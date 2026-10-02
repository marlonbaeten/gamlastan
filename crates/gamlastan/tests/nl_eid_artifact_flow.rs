//! End-to-end tests for the Dutch eID SAML (DV ↔ RD) profile.
//!
//! An RD-signed SOAP `ArtifactResponse` → `Response` → `Assertion` chain is
//! built and signed here with dedicated test keys, exactly as a Routeringsdienst
//! emits it (RD signatures on the ArtifactResponse and the Assertion, an
//! `EncryptedID` for the acting subject wrapped to the DV encryption key,
//! `KeyName`-only KeyInfo), and driven through `process_artifact_response`.
//! Only the mTLS back-channel that would deliver these bytes is left out.

use base64::Engine;
use chrono::{Duration, Utc};

use gamlastan::crypto::keys::loader;
use gamlastan::crypto::{KeyUsage, KeysManager, SamlEncryptor, SamlSigner, SamlVerifier};
use gamlastan::profiles::nl_eid::{
    build_dv_metadata, constants, parse_rd_metadata, sign_element_xml, sign_message_xml,
    signed_artifact_resolve, signed_authn_request, signed_logout_request, validate_logout_response,
    ArtifactResponseParams, AuthnOutcome, DvDecryptionKeys, DvMetadataOptions, IdentifierType,
    LevelOfAssurance, NlEidAuthnOptions, NlEidConfig, NlEidError, PublishedCertificate, RdMetadata,
};
use gamlastan::security::replay::InMemoryReplayCache;

const RD_SIGNING_CERT: &str = include_str!("fixtures/nl_eid/rd-signing-cert.pem");
const RD_SIGNING_KEY: &str = include_str!("fixtures/nl_eid/rd-signing-key.pem");
const DV_SIGNING_CERT: &str = include_str!("fixtures/nl_eid/dv-signing-cert.pem");
const DV_SIGNING_KEY: &str = include_str!("fixtures/nl_eid/dv-signing-key.pem");
const DV_ENCRYPTION_CERT: &str = include_str!("fixtures/nl_eid/dv-encryption-cert.pem");
const DV_ENCRYPTION_KEY: &str = include_str!("fixtures/nl_eid/dv-encryption-key.pem");
const DV_ENCRYPTION_2_CERT: &str = include_str!("fixtures/nl_eid/dv-encryption-2-cert.pem");
const DV_ENCRYPTION_2_KEY: &str = include_str!("fixtures/nl_eid/dv-encryption-2-key.pem");

const DV: &str = "urn:nl-eid-gdi:1.0:DV:00000001234567890000:entities:9001";
const RD: &str = "urn:nl-eid-gdi:1.0:RD:00000004000000149000:entities:9002";
const AD: &str = "urn:nl-eid-gdi:1.0:AD:00000004166909913000:entities:9002";
const ACS: &str = "https://dv.example.nl/saml/acs";
const SLS: &str = "https://dv.example.nl/saml/slo";
const SERVICE_UUID: &str = "f847dc11-ac24-47b2-84a8-a057440ce56d";
const RESOLVE_ID: &str = "_resolve1";
const AUTHN_ID: &str = "_authn1";
const BSN: &str = "900070341";

const SAML: &str = constants::NS_SAML_ASSERTION;
const SAMLP: &str = constants::NS_SAML_PROTOCOL;
const XENC: &str = constants::NS_XENC;
const DS: &str = constants::NS_DS;

// ── Key material ────────────────────────────────────────────────────────────

fn cert_der_b64(cert_pem: &str) -> String {
    cert_pem
        .lines()
        .filter(|l| !l.starts_with("-----"))
        .map(str::trim)
        .collect()
}

fn signer(key_pem: &str) -> SamlSigner {
    let mut key = loader::load_pem_auto(key_pem.as_bytes(), None).expect("load private key");
    key.usage = KeyUsage::Sign;
    let mut km = KeysManager::new();
    km.add_key(key);
    SamlSigner::new(km)
}

fn published(cert_pem: &str) -> PublishedCertificate {
    PublishedCertificate::from_pem(cert_pem).expect("certificate")
}

/// RD metadata (§8.5) naming the RD signing certificate, as the DV would have
/// verified and pinned it out of band.
fn rd_metadata_xml(signing_cert_pem: &str) -> String {
    let key_info = published(signing_cert_pem).key_info_xml();
    format!(
        r#"<md:EntityDescriptor xmlns:md="{}" entityID="{RD}" ID="_rdmeta" cacheDuration="PT24H">
  <md:IDPSSODescriptor WantAuthnRequestsSigned="true" protocolSupportEnumeration="{SAMLP}">
    <md:KeyDescriptor use="signing">{key_info}</md:KeyDescriptor>
    <md:ArtifactResolutionService Binding="{}" Location="https://rd.example/ars" index="0"/>
    <md:SingleLogoutService Binding="{}" Location="https://rd.example/slo"/>
    <md:SingleSignOnService Binding="{}" Location="https://rd.example/sso"/>
  </md:IDPSSODescriptor>
</md:EntityDescriptor>"#,
        constants::NS_MD,
        constants::BINDING_SOAP,
        constants::BINDING_HTTP_POST,
        constants::BINDING_HTTP_POST,
    )
}

fn rd_metadata() -> RdMetadata {
    parse_rd_metadata(&rd_metadata_xml(RD_SIGNING_CERT)).expect("RD metadata")
}

fn rd_verifier() -> SamlVerifier {
    rd_metadata().verifier().expect("verifier")
}

fn dv_keys() -> DvDecryptionKeys {
    DvDecryptionKeys::from_private_key_pems([DV_ENCRYPTION_KEY.as_bytes()]).expect("DV keys")
}

fn cfg() -> NlEidConfig {
    NlEidConfig::service_provider(DV, SERVICE_UUID, ACS, RD, LevelOfAssurance::Low)
        .with_single_logout_url(SLS)
}

fn params<'a>(cache: &'a InMemoryReplayCache) -> ArtifactResponseParams<'a> {
    ArtifactResponseParams {
        expected_artifact_resolve_id: RESOLVE_ID,
        expected_authn_request_id: AUTHN_ID,
        replay_cache: cache,
        relay_state: None,
        now: Utc::now(),
    }
}

// ── Message construction (the RD side) ──────────────────────────────────────

fn ts(offset: Duration) -> String {
    (Utc::now() + offset)
        .format("%Y-%m-%dT%H:%M:%SZ")
        .to_string()
}

/// An `EncryptedID` carrying `name_id_xml`, wrapped to `cert_pem` for
/// `recipient` with the inline-`EncryptedKey` layout (AES-256-CBC data,
/// RSA-OAEP key transport, §9.3).
fn encrypted_id_inline(cert_pem: &str, recipient: &str, name_id_xml: &str) -> String {
    let cert = published(cert_pem);
    let key_name = &cert.key_name;
    let template = format!(
        r#"<saml:EncryptedID xmlns:saml="{SAML}" xmlns:xenc="{XENC}" xmlns:ds="{DS}"><xenc:EncryptedData Type="http://www.w3.org/2001/04/xmlenc#Element"><xenc:EncryptionMethod Algorithm="{}"/><ds:KeyInfo><xenc:EncryptedKey Recipient="{recipient}"><xenc:EncryptionMethod Algorithm="{}"/><ds:KeyInfo><ds:KeyName>{key_name}</ds:KeyName></ds:KeyInfo><xenc:CipherData><xenc:CipherValue></xenc:CipherValue></xenc:CipherData></xenc:EncryptedKey></ds:KeyInfo><xenc:CipherData><xenc:CipherValue></xenc:CipherValue></xenc:CipherData></xenc:EncryptedData></saml:EncryptedID>"#,
        constants::ENC_AES256_CBC,
        constants::KEYTRANSPORT_RSA_OAEP_MGF1P,
    );
    let recipient_key = loader::load_x509_cert_pem(cert_pem.as_bytes())
        .expect("recipient cert")
        .with_name(key_name.clone());
    let mut km = KeysManager::new();
    km.add_key(recipient_key);
    SamlEncryptor::new(km)
        .encrypt(&template, name_id_xml.as_bytes())
        .expect("encrypt NameID")
}

/// Rewrite an inline-layout `EncryptedID` into the layout TVS actually emits:
/// the `EncryptedKey` as a sibling of `EncryptedData`, referenced through a
/// `ds:RetrievalMethod`, with `Id` attributes and a `ReferenceList`.
fn to_retrieval_layout(inline: &str, suffix: &str) -> String {
    let ek_start = inline.find("<xenc:EncryptedKey").expect("EncryptedKey");
    let ek_end = inline
        .find("</xenc:EncryptedKey>")
        .expect("EncryptedKey end")
        + "</xenc:EncryptedKey>".len();
    let encrypted_key = &inline[ek_start..ek_end];
    let data_id = format!("_data{suffix}");
    let key_id = format!("_key{suffix}");
    let without_key = format!("{}{}", &inline[..ek_start], &inline[ek_end..]);
    let retrieval = format!(
        r##"<ds:RetrievalMethod Type="http://www.w3.org/2001/04/xmlenc#EncryptedKey" URI="#{key_id}"/>"##
    );
    let with_retrieval = without_key
        .replacen(
            r#"<xenc:EncryptedData Type="#,
            &format!(r#"<xenc:EncryptedData Id="{data_id}" Type="#),
            1,
        )
        .replacen(
            "<ds:KeyInfo></ds:KeyInfo>",
            &format!("<ds:KeyInfo>{retrieval}</ds:KeyInfo>"),
            1,
        );
    assert!(
        with_retrieval.contains("RetrievalMethod"),
        "{with_retrieval}"
    );
    let sibling_key = encrypted_key
        .replacen(
            "<xenc:EncryptedKey ",
            &format!(r#"<xenc:EncryptedKey Id="{key_id}" "#),
            1,
        )
        .replacen(
            "</xenc:EncryptedKey>",
            &format!(
                r##"<xenc:ReferenceList><xenc:DataReference URI="#{data_id}"/></xenc:ReferenceList></xenc:EncryptedKey>"##
            ),
            1,
        );
    with_retrieval.replacen(
        "</saml:EncryptedID>",
        &format!("{sibling_key}</saml:EncryptedID>"),
        1,
    )
}

fn bsn_name_id(value: &str) -> String {
    format!(
        r#"<saml:NameID xmlns:saml="{SAML}" Format="{}" NameQualifier="{}">{value}</saml:NameID>"#,
        constants::NAMEID_PERSISTENT,
        constants::ID_TYPE_LEGACY_BSN
    )
}

enum Outcome {
    Success,
    Cancelled,
    Failed,
}

/// Every knob a test varies; `Default` is a successful login for `cfg()`.
struct Wire {
    resolve_id: &'static str,
    response_in_response_to: &'static str,
    assertion_in_response_to: &'static str,
    outcome: Outcome,
    /// Status of the ArtifactResponse itself (§7.6.1); `false` = RequestDenied,
    /// no Response.
    artifact_resolved: bool,
    rd_signing_key: &'static str,
    /// The KeyName written into the RD signatures' KeyInfo.
    rd_key_name: Option<String>,
    sign_assertion: bool,
    audience: &'static str,
    loa: &'static str,
    service_uuid: &'static str,
    /// The acting-subject EncryptedID XML; `None` omits the attribute.
    acting_subject: Option<String>,
    /// An extra Response child (e.g. an EncryptedAssertion).
    response_extra: String,
    /// Shift of every timestamp relative to now.
    time_offset: Duration,
    /// Declare the SAML namespaces on the SOAP envelope rather than on the
    /// ArtifactResponse, so the signed element inherits them.
    namespaces_on_envelope: bool,
}

impl Default for Wire {
    fn default() -> Self {
        Self {
            resolve_id: RESOLVE_ID,
            response_in_response_to: AUTHN_ID,
            assertion_in_response_to: AUTHN_ID,
            outcome: Outcome::Success,
            artifact_resolved: true,
            rd_signing_key: RD_SIGNING_KEY,
            rd_key_name: None,
            sign_assertion: true,
            audience: DV,
            loa: constants::LOA_SUBSTANTIAL_EIDAS,
            service_uuid: SERVICE_UUID,
            acting_subject: Some(encrypted_id_inline(
                DV_ENCRYPTION_CERT,
                DV,
                &bsn_name_id(BSN),
            )),
            response_extra: String::new(),
            time_offset: Duration::zero(),
            namespaces_on_envelope: false,
        }
    }
}

fn status_xml(outcome: &Outcome) -> String {
    match outcome {
        Outcome::Success => format!(
            r#"<samlp:Status><samlp:StatusCode Value="{}"/></samlp:Status>"#,
            constants::STATUS_SUCCESS
        ),
        Outcome::Cancelled => format!(
            r#"<samlp:Status><samlp:StatusCode Value="{}"><samlp:StatusCode Value="{}"/></samlp:StatusCode><samlp:StatusMessage>{}</samlp:StatusMessage></samlp:Status>"#,
            constants::STATUS_RESPONDER,
            constants::STATUS_AUTHN_FAILED,
            constants::STATUS_MESSAGE_CANCELLED
        ),
        Outcome::Failed => format!(
            r#"<samlp:Status><samlp:StatusCode Value="{}"><samlp:StatusCode Value="{}"/></samlp:StatusCode><samlp:StatusMessage>Level of assurance not supported</samlp:StatusMessage></samlp:Status>"#,
            constants::STATUS_RESPONDER,
            constants::STATUS_REQUEST_UNSUPPORTED
        ),
    }
}

/// The RD signature template as TVS emits it: `KeyInfo` with a `KeyName` only.
fn rd_signature_template(id: &str, key_name: &str) -> String {
    format!(
        r##"<dsig:Signature xmlns:dsig="{DS}"><dsig:SignedInfo><dsig:CanonicalizationMethod Algorithm="{}"/><dsig:SignatureMethod Algorithm="{}"/><dsig:Reference URI="#{id}"><dsig:Transforms><dsig:Transform Algorithm="{}"/><dsig:Transform Algorithm="{}"/></dsig:Transforms><dsig:DigestMethod Algorithm="{}"/><dsig:DigestValue></dsig:DigestValue></dsig:Reference></dsig:SignedInfo><dsig:SignatureValue></dsig:SignatureValue><dsig:KeyInfo><dsig:KeyName>{key_name}</dsig:KeyName></dsig:KeyInfo></dsig:Signature>"##,
        constants::C14N_EXCLUSIVE,
        constants::SIG_RSA_SHA256,
        constants::TRANSFORM_ENVELOPED_SIGNATURE,
        constants::C14N_EXCLUSIVE,
        constants::DIGEST_SHA256,
    )
}

/// Sign `xml` as the RD: the template goes right after the first
/// `</saml:Issuer>` of the element carrying `id`.
fn rd_sign(xml: &str, id: &str, wire: &Wire) -> String {
    let key_name = wire
        .rd_key_name
        .clone()
        .unwrap_or_else(|| published(RD_SIGNING_CERT).key_name);
    let template = rd_signature_template(id, &key_name);
    let marker = format!(r#"ID="{id}""#);
    let elem_at = xml.find(&marker).expect("element with id");
    let issuer_end =
        xml[elem_at..].find("</saml:Issuer>").expect("issuer") + "</saml:Issuer>".len();
    let at = elem_at + issuer_end;
    let with_template = format!("{}{}{}", &xml[..at], template, &xml[at..]);
    signer(wire.rd_signing_key)
        .sign_enveloped(&with_template)
        .expect("RD signs")
}

fn assertion_xml(wire: &Wire) -> String {
    let issued = ts(wire.time_offset);
    let scd_expiry = ts(wire.time_offset + Duration::minutes(2));
    let not_before = ts(wire.time_offset - Duration::minutes(2));
    let not_on_or_after = ts(wire.time_offset + Duration::minutes(2));
    let acting = wire
        .acting_subject
        .as_ref()
        .map(|enc| {
            format!(
                r#"<saml:Attribute Name="{}"><saml:AttributeValue>{enc}</saml:AttributeValue></saml:Attribute>"#,
                constants::ATTR_ACTING_SUBJECT_ID
            )
        })
        .unwrap_or_default();
    format!(
        r#"<saml:Assertion ID="_assertion1" Version="2.0" IssueInstant="{issued}"><saml:Issuer>{RD}</saml:Issuer><saml:Subject><saml:NameID>64b0d194095940008ffa142b12444c01</saml:NameID><saml:SubjectConfirmation Method="{}"><saml:SubjectConfirmationData InResponseTo="{}" NotOnOrAfter="{scd_expiry}" Recipient="{ACS}"/></saml:SubjectConfirmation></saml:Subject><saml:Conditions NotBefore="{not_before}" NotOnOrAfter="{not_on_or_after}"><saml:AudienceRestriction><saml:Audience>{}</saml:Audience></saml:AudienceRestriction></saml:Conditions><saml:Advice><saml:Assertion ID="_ad1" Version="2.0" IssueInstant="{issued}"><saml:Issuer>{AD}</saml:Issuer><saml:Subject><saml:NameID Format="{}">ad-transient</saml:NameID></saml:Subject><saml:AuthnStatement AuthnInstant="{issued}"><saml:AuthnContext><saml:AuthnContextClassRef>{}</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement></saml:Assertion></saml:Advice><saml:AuthnStatement AuthnInstant="{issued}"><saml:AuthnContext><saml:AuthnContextClassRef>{}</saml:AuthnContextClassRef><saml:AuthenticatingAuthority>{AD}</saml:AuthenticatingAuthority></saml:AuthnContext></saml:AuthnStatement><saml:AttributeStatement>{acting}<saml:Attribute Name="{}"><saml:AttributeValue>{}</saml:AttributeValue></saml:Attribute></saml:AttributeStatement></saml:Assertion>"#,
        constants::CM_BEARER,
        wire.assertion_in_response_to,
        wire.audience,
        constants::NAMEID_TRANSIENT,
        wire.loa,
        wire.loa,
        constants::ATTR_SERVICE_UUID,
        wire.service_uuid,
    )
}

/// The complete SOAP body the back-channel returns for `wire`.
fn soap_artifact_response(wire: &Wire) -> String {
    let issued = ts(wire.time_offset);
    let response = if wire.artifact_resolved {
        let assertion = match wire.outcome {
            Outcome::Success => assertion_xml(wire),
            Outcome::Cancelled | Outcome::Failed => String::new(),
        };
        format!(
            r#"<samlp:Response ID="_response1" Version="2.0" IssueInstant="{issued}" Destination="{ACS}" InResponseTo="{}"><saml:Issuer>{RD}</saml:Issuer>{}{}{assertion}</samlp:Response>"#,
            wire.response_in_response_to,
            status_xml(&wire.outcome),
            wire.response_extra,
        )
    } else {
        String::new()
    };
    let art_status = if wire.artifact_resolved {
        status_xml(&Outcome::Success)
    } else {
        format!(
            r#"<samlp:Status><samlp:StatusCode Value="{}"><samlp:StatusCode Value="{}"/></samlp:StatusCode></samlp:Status>"#,
            constants::STATUS_REQUESTER,
            constants::STATUS_REQUEST_DENIED
        )
    };
    let unsigned = format!(
        r#"<samlp:ArtifactResponse xmlns:samlp="{SAMLP}" xmlns:saml="{SAML}" ID="_artifactresponse1" Version="2.0" IssueInstant="{issued}" InResponseTo="{}"><saml:Issuer>{RD}</saml:Issuer>{art_status}{response}</samlp:ArtifactResponse>"#,
        wire.resolve_id
    );

    // The RD signs the assertion first, then the enveloping ArtifactResponse.
    let mut signed = unsigned;
    if wire.sign_assertion && matches!(wire.outcome, Outcome::Success) && wire.artifact_resolved {
        signed = rd_sign(&signed, "_assertion1", wire);
    }
    signed = rd_sign(&signed, "_artifactresponse1", wire);

    if wire.namespaces_on_envelope {
        // Exclusive c14n renders visibly used namespaces on the apex element,
        // so moving the declarations to the envelope leaves the digest intact.
        let decls = format!(r#" xmlns:samlp="{SAMLP}" xmlns:saml="{SAML}""#);
        let stripped = signed.replacen(&decls, "", 1);
        assert_ne!(stripped, signed);
        format!(
            r#"<soapenv:Envelope xmlns:soapenv="{}"{decls}><soapenv:Body>{stripped}</soapenv:Body></soapenv:Envelope>"#,
            constants::NS_SOAP11
        )
    } else {
        gamlastan::bindings::soap::soap_envelope_wrap(&signed, None)
    }
}

fn run(wire: &Wire) -> Result<AuthnOutcome, NlEidError> {
    run_with(&cfg(), wire, &dv_keys())
}

fn run_with(
    cfg: &NlEidConfig,
    wire: &Wire,
    keys: &DvDecryptionKeys,
) -> Result<AuthnOutcome, NlEidError> {
    let cache = InMemoryReplayCache::new();
    gamlastan::profiles::nl_eid::process_artifact_response(
        cfg,
        &soap_artifact_response(wire),
        &rd_verifier(),
        keys,
        &params(&cache),
    )
}

fn authenticated(
    result: Result<AuthnOutcome, NlEidError>,
) -> gamlastan::profiles::nl_eid::NlEidAuthnResult {
    match result {
        Ok(AuthnOutcome::Authenticated(r)) => *r,
        other => panic!("expected an authenticated outcome, got {other:?}"),
    }
}

// ── The happy path ──────────────────────────────────────────────────────────

#[test]
fn a_valid_artifact_response_authenticates_the_subject() {
    let result = authenticated(run(&Wire::default()));
    assert_eq!(result.acting_subject.expose_value(), BSN);
    assert_eq!(
        result.acting_subject.identifier_type(),
        IdentifierType::LegacyBsn
    );
    assert!(result.legal_subject.is_none());
    assert_eq!(result.transient_name_id, "64b0d194095940008ffa142b12444c01");
    assert_eq!(result.level_of_assurance, LevelOfAssurance::Substantial);
    assert_eq!(result.authenticating_authorities, vec![AD.to_string()]);
    assert_eq!(result.service_uuid, SERVICE_UUID);
    assert_eq!(
        result.rd_signing_key_name,
        published(RD_SIGNING_CERT).key_name
    );
    assert_eq!(result.authn.idp_entity_id, RD);
    assert_eq!(result.authn.assertion_id, "_assertion1");
    assert_eq!(result.authn.response_id, "_response1");
    // The debug form of the result never shows the BSN.
    assert!(!format!("{result:?}").contains(BSN));
}

#[test]
fn namespaces_declared_on_the_soap_envelope_still_verify() {
    let wire = Wire {
        namespaces_on_envelope: true,
        ..Wire::default()
    };
    let result = authenticated(run(&wire));
    assert_eq!(result.acting_subject.expose_value(), BSN);
}

#[test]
fn the_tvs_retrieval_method_layout_decrypts() {
    let inline = encrypted_id_inline(DV_ENCRYPTION_CERT, DV, &bsn_name_id(BSN));
    let wire = Wire {
        acting_subject: Some(to_retrieval_layout(&inline, "-1")),
        ..Wire::default()
    };
    let result = authenticated(run(&wire));
    assert_eq!(result.acting_subject.expose_value(), BSN);
}

#[test]
fn keys_wrapped_for_another_recipient_are_ignored() {
    // Two EncryptedIDs for the attribute (one per recipient, §7.6.3.4), the
    // foreign one first and wrapped to a key we do not hold.
    let foreign = encrypted_id_inline(
        DV_ENCRYPTION_2_CERT,
        "urn:nl-eid-gdi:1.0:DV:00000000000000000001:entities:0001",
        &bsn_name_id("000000000"),
    );
    let ours = encrypted_id_inline(DV_ENCRYPTION_CERT, DV, &bsn_name_id(BSN));
    let attribute_values = format!("{foreign}</saml:AttributeValue><saml:AttributeValue>{ours}");
    let wire = Wire {
        acting_subject: Some(attribute_values),
        ..Wire::default()
    };
    let result = authenticated(run(&wire));
    assert_eq!(result.acting_subject.expose_value(), BSN);
}

#[test]
fn a_message_wrapped_to_the_rollover_key_decrypts_with_the_second_key() {
    let wire = Wire {
        acting_subject: Some(encrypted_id_inline(
            DV_ENCRYPTION_2_CERT,
            DV,
            &bsn_name_id(BSN),
        )),
        ..Wire::default()
    };
    // Only the first key: fails.
    assert!(matches!(run(&wire), Err(NlEidError::Decryption { .. })));
    // Both keys, old one first: decrypts.
    let keys = DvDecryptionKeys::from_private_key_pems([
        DV_ENCRYPTION_KEY.as_bytes(),
        DV_ENCRYPTION_2_KEY.as_bytes(),
    ])
    .unwrap();
    let result = authenticated(run_with(&cfg(), &wire, &keys));
    assert_eq!(result.acting_subject.expose_value(), BSN);
}

#[test]
fn an_unsigned_assertion_is_accepted_only_when_configured() {
    let wire = Wire {
        sign_assertion: false,
        ..Wire::default()
    };
    assert!(matches!(
        run(&wire),
        Err(NlEidError::MissingSignature("Assertion"))
    ));
    let mut lenient = cfg();
    lenient.require_assertion_signature = false;
    let result = authenticated(run_with(&lenient, &wire, &dv_keys()));
    assert_eq!(result.acting_subject.expose_value(), BSN);
}

// ── RD answers that are not a login ─────────────────────────────────────────

#[test]
fn a_cancelled_login_is_reported_as_cancelled() {
    let outcome = run(&Wire {
        outcome: Outcome::Cancelled,
        ..Wire::default()
    })
    .unwrap();
    match outcome {
        AuthnOutcome::Cancelled { status } => {
            assert_eq!(
                status.status_message.as_deref(),
                Some(constants::STATUS_MESSAGE_CANCELLED)
            );
        }
        other => panic!("expected Cancelled, got {other:?}"),
    }
}

#[test]
fn an_rd_error_status_is_reported_as_failed() {
    let outcome = run(&Wire {
        outcome: Outcome::Failed,
        ..Wire::default()
    })
    .unwrap();
    assert!(matches!(outcome, AuthnOutcome::Failed { .. }));
}

#[test]
fn a_denied_artifact_resolution_is_an_error() {
    assert!(matches!(
        run(&Wire {
            artifact_resolved: false,
            ..Wire::default()
        }),
        Err(NlEidError::ArtifactResolutionFailed(_))
    ));
}

// ── Correlation and trust failures ──────────────────────────────────────────

#[test]
fn an_artifact_response_for_another_resolve_is_rejected() {
    assert!(matches!(
        run(&Wire {
            resolve_id: "_someoneelses",
            ..Wire::default()
        }),
        Err(NlEidError::InResponseToMismatch {
            element: "ArtifactResponse",
            ..
        })
    ));
}

#[test]
fn a_response_to_another_flow_is_rejected() {
    assert!(matches!(
        run(&Wire {
            response_in_response_to: "_theirs",
            ..Wire::default()
        }),
        Err(NlEidError::InResponseToMismatch {
            element: "Response",
            ..
        })
    ));
}

#[test]
fn an_assertion_spliced_from_another_flow_is_rejected() {
    // The Response names our request, the assertion's bearer confirmation
    // another one: the shared validator's InResponseTo check fails.
    let err = run(&Wire {
        assertion_in_response_to: "_theirs",
        ..Wire::default()
    })
    .unwrap_err();
    assert!(matches!(err, NlEidError::Profile(_)), "{err}");
    assert!(err.to_string().contains("InResponseTo"), "{err}");
}

#[test]
fn a_signature_by_a_key_outside_the_rd_metadata_is_rejected() {
    // Unknown KeyName: refused before any cryptography.
    let err = run(&Wire {
        rd_signing_key: DV_SIGNING_KEY,
        rd_key_name: Some(published(DV_SIGNING_CERT).key_name),
        ..Wire::default()
    })
    .unwrap_err();
    assert!(matches!(err, NlEidError::UnknownSigningKey(_)), "{err}");

    // The RD's KeyName, but a signature by another key: cryptographic failure.
    let err = run(&Wire {
        rd_signing_key: DV_SIGNING_KEY,
        ..Wire::default()
    })
    .unwrap_err();
    assert!(matches!(err, NlEidError::InvalidSignature { .. }), "{err}");
}

#[test]
fn a_signed_element_wrapped_in_a_forged_artifact_response_is_rejected() {
    // The genuine, RD-signed ArtifactResponse is moved into an Extensions
    // element of a forged outer ArtifactResponse that reuses its signature.
    let genuine = soap_artifact_response(&Wire::default());
    let inner_start = genuine.find("<samlp:ArtifactResponse").unwrap();
    let inner_end =
        genuine.rfind("</samlp:ArtifactResponse>").unwrap() + "</samlp:ArtifactResponse>".len();
    let inner = &genuine[inner_start..inner_end];
    let sig_start = inner.find("<dsig:Signature").unwrap();
    let sig_end = inner.find("</dsig:Signature>").unwrap() + "</dsig:Signature>".len();
    let signature = &inner[sig_start..sig_end];
    let now = ts(Duration::zero());
    let forged = format!(
        r#"<samlp:ArtifactResponse xmlns:samlp="{SAMLP}" xmlns:saml="{SAML}" ID="_forged" Version="2.0" IssueInstant="{now}" InResponseTo="{RESOLVE_ID}"><saml:Issuer>{RD}</saml:Issuer>{signature}<samlp:Extensions>{inner}</samlp:Extensions><samlp:Status><samlp:StatusCode Value="{}"/></samlp:Status></samlp:ArtifactResponse>"#,
        constants::STATUS_SUCCESS
    );
    let cache = InMemoryReplayCache::new();
    let err = gamlastan::profiles::nl_eid::process_artifact_response(
        &cfg(),
        &gamlastan::bindings::soap::soap_envelope_wrap(&forged, None),
        &rd_verifier(),
        &dv_keys(),
        &params(&cache),
    )
    .unwrap_err();
    assert!(
        matches!(
            err,
            NlEidError::InvalidSignature { .. }
                | NlEidError::SignatureNotBoundToElement(_)
                | NlEidError::AmbiguousSignature(_)
        ),
        "{err}"
    );
}

#[test]
fn an_assertion_for_another_dv_is_rejected() {
    let err = run(&Wire {
        audience: "urn:nl-eid-gdi:1.0:DV:00000000000000000001:entities:0001",
        ..Wire::default()
    })
    .unwrap_err();
    assert!(matches!(err, NlEidError::Profile(_)), "{err}");
    assert!(err.to_string().contains("udience"), "{err}");
}

#[test]
fn a_level_of_assurance_below_the_minimum_is_rejected_and_a_higher_one_accepted() {
    assert!(matches!(
        run(&Wire {
            loa: constants::LOA_BASIC,
            ..Wire::default()
        }),
        Err(NlEidError::LevelOfAssuranceTooLow { .. })
    ));
    assert!(matches!(
        run(&Wire {
            loa: "urn:bogus:loa",
            ..Wire::default()
        }),
        Err(NlEidError::UnknownLevelOfAssurance(_))
    ));
    let result = authenticated(run(&Wire {
        loa: constants::LOA_HIGH,
        ..Wire::default()
    }));
    assert_eq!(result.level_of_assurance, LevelOfAssurance::High);
}

#[test]
fn a_service_uuid_for_another_service_is_rejected() {
    assert!(matches!(
        run(&Wire {
            service_uuid: "00000000-0000-0000-0000-000000000000",
            ..Wire::default()
        }),
        Err(NlEidError::ServiceUuidMismatch { .. })
    ));
}

#[test]
fn an_encrypted_id_without_a_key_for_us_is_rejected() {
    assert!(matches!(
        run(&Wire {
            acting_subject: Some(encrypted_id_inline(
                DV_ENCRYPTION_CERT,
                "urn:nl-eid-gdi:1.0:DV:00000000000000000001:entities:0001",
                &bsn_name_id(BSN)
            )),
            ..Wire::default()
        }),
        Err(NlEidError::NoEncryptedKeyForRecipient { .. })
    ));
    assert!(matches!(
        run(&Wire {
            acting_subject: None,
            ..Wire::default()
        }),
        Err(NlEidError::MissingActingSubjectId)
    ));
}

#[test]
fn a_decrypted_name_id_of_the_wrong_shape_is_rejected() {
    let transient = format!(
        r#"<saml:NameID xmlns:saml="{SAML}" Format="{}" NameQualifier="{}">{BSN}</saml:NameID>"#,
        constants::NAMEID_TRANSIENT,
        constants::ID_TYPE_LEGACY_BSN
    );
    assert!(matches!(
        run(&Wire {
            acting_subject: Some(encrypted_id_inline(DV_ENCRYPTION_CERT, DV, &transient)),
            ..Wire::default()
        }),
        Err(NlEidError::InvalidDecryptedNameId { .. })
    ));
}

#[test]
fn an_encrypted_assertion_is_forbidden() {
    assert!(matches!(
        run(&Wire {
            response_extra: format!(
                r#"<saml:EncryptedAssertion><xenc:EncryptedData xmlns:xenc="{XENC}"><xenc:EncryptionMethod Algorithm="{}"/><xenc:CipherData><xenc:CipherValue>AA==</xenc:CipherValue></xenc:CipherData></xenc:EncryptedData></saml:EncryptedAssertion>"#,
                constants::ENC_AES256_CBC
            ),
            ..Wire::default()
        }),
        Err(NlEidError::EncryptedAssertionForbidden)
    ));
}

#[test]
fn stale_messages_are_rejected() {
    assert!(matches!(
        run(&Wire {
            time_offset: -Duration::minutes(20),
            ..Wire::default()
        }),
        Err(NlEidError::StaleMessage { .. })
    ));
    assert!(matches!(
        run(&Wire {
            time_offset: Duration::hours(1),
            ..Wire::default()
        }),
        Err(NlEidError::StaleMessage { .. })
    ));
}

#[test]
fn a_replayed_assertion_is_rejected() {
    let cache = InMemoryReplayCache::new();
    let body = soap_artifact_response(&Wire::default());
    let first = gamlastan::profiles::nl_eid::process_artifact_response(
        &cfg(),
        &body,
        &rd_verifier(),
        &dv_keys(),
        &params(&cache),
    );
    assert!(first.unwrap().is_authenticated());
    let second = gamlastan::profiles::nl_eid::process_artifact_response(
        &cfg(),
        &body,
        &rd_verifier(),
        &dv_keys(),
        &params(&cache),
    )
    .unwrap_err();
    assert!(second.to_string().contains("replayed"), "{second}");
}

#[test]
fn a_weak_algorithm_anywhere_is_rejected_before_verification() {
    let body = soap_artifact_response(&Wire::default()).replacen(
        constants::DIGEST_SHA256,
        constants::DIGEST_SHA1,
        1,
    );
    let cache = InMemoryReplayCache::new();
    let err = gamlastan::profiles::nl_eid::process_artifact_response(
        &cfg(),
        &body,
        &rd_verifier(),
        &dv_keys(),
        &params(&cache),
    )
    .unwrap_err();
    assert!(
        matches!(err, NlEidError::DisallowedAlgorithm { kind: "digest", .. }),
        "{err}"
    );
}

#[test]
fn garbage_from_the_back_channel_is_rejected() {
    let cache = InMemoryReplayCache::new();
    for body in ["502 Bad Gateway", "<html><body>proxy error</body></html>"] {
        let err = gamlastan::profiles::nl_eid::process_artifact_response(
            &cfg(),
            body,
            &rd_verifier(),
            &dv_keys(),
            &params(&cache),
        )
        .unwrap_err();
        assert!(matches!(err, NlEidError::MalformedMessage(_)), "{err}");
    }
}

// ── DV-side messages and metadata ───────────────────────────────────────────

fn dv_verifier() -> SamlVerifier {
    let mut key = loader::load_pem_auto(DV_SIGNING_CERT.as_bytes(), None).expect("DV cert");
    key.usage = KeyUsage::Verify;
    let mut km = KeysManager::new();
    km.add_key(key);
    km.add_trusted_cert(
        base64::engine::general_purpose::STANDARD
            .decode(cert_der_b64(DV_SIGNING_CERT))
            .unwrap(),
    );
    SamlVerifier::new(km).with_algorithm_policy(constants::algorithm_policy())
}

#[test]
fn the_signed_authn_request_and_artifact_resolve_verify_against_the_dv_certificate() {
    let signer = signer(DV_SIGNING_KEY);
    let cert = cert_der_b64(DV_SIGNING_CERT);
    let rd = rd_metadata();

    let request = signed_authn_request(
        &cfg(),
        &NlEidAuthnOptions::to(&rd.sso_url, 0),
        &signer,
        &cert,
    )
    .unwrap();
    assert!(request.xml.contains(&format!(r#"ID="{}""#, request.id)));
    assert!(request.xml.contains("<ds:Signature"));
    let result = dv_verifier().verify_enveloped(&request.xml).unwrap();
    assert!(result.is_valid(), "{result:?}");
    // The signature sits after the Issuer and before the Extensions.
    let issuer = request.xml.find("</saml:Issuer>").unwrap();
    let sig = request.xml.find("<ds:Signature").unwrap();
    let ext = request.xml.find("<samlp:Extensions").unwrap();
    assert!(issuer < sig && sig < ext, "{}", request.xml);

    let resolve = signed_artifact_resolve(
        &cfg(),
        "AAQAAMh48/1oXIM+sDo7Dh2qMp1HM4IF5DaRNmDj6auzddOYoLXh0LA5NA==",
        &rd.artifact_resolution_url,
        &signer,
        &cert,
    )
    .unwrap();
    assert!(dv_verifier()
        .verify_enveloped(&resolve.xml)
        .unwrap()
        .is_valid());
    let envelope = gamlastan::bindings::soap::soap_envelope_wrap(&resolve.xml, None);
    assert!(envelope.contains("ArtifactResolve"));

    let logout =
        signed_logout_request(&cfg(), "transient-1", &rd.single_logout_url, &signer, &cert)
            .unwrap();
    assert!(dv_verifier()
        .verify_enveloped(&logout.xml)
        .unwrap()
        .is_valid());
}

#[test]
fn the_dv_metadata_is_signed_and_round_trips() {
    let mut opts = DvMetadataOptions::from_config(&cfg(), "Kiesraad");
    opts.signing_certificates = vec![published(DV_SIGNING_CERT)];
    opts.encryption_certificates = vec![
        published(DV_ENCRYPTION_CERT),
        published(DV_ENCRYPTION_2_CERT),
    ];
    let xml = build_dv_metadata(
        &opts,
        &signer(DV_SIGNING_KEY),
        &cert_der_b64(DV_SIGNING_CERT),
    )
    .unwrap();
    let result = dv_verifier().verify_enveloped(&xml).unwrap();
    assert!(result.is_valid(), "{result:?}");
    // The signature is the first child of the EntityDescriptor.
    let root_end = xml.find('>').unwrap();
    assert!(
        xml[root_end..]
            .trim_start_matches('>')
            .starts_with("<ds:Signature"),
        "{xml}"
    );
    assert!(xml.contains(&published(DV_ENCRYPTION_2_CERT).key_name));
}

#[test]
fn a_logout_response_from_the_rd_validates() {
    let in_response_to = "_logout1";
    let now = ts(Duration::zero());
    let unsigned = format!(
        r#"<samlp:LogoutResponse xmlns:samlp="{SAMLP}" xmlns:saml="{SAML}" ID="_lr1" Version="2.0" IssueInstant="{now}" Destination="{SLS}" InResponseTo="{in_response_to}"><saml:Issuer>{RD}</saml:Issuer><samlp:Status><samlp:StatusCode Value="{}"/></samlp:Status></samlp:LogoutResponse>"#,
        constants::STATUS_SUCCESS
    );
    let signed = rd_sign(&unsigned, "_lr1", &Wire::default());
    let outcome =
        validate_logout_response(&cfg(), &signed, &rd_verifier(), in_response_to, Utc::now())
            .unwrap();
    assert!(outcome.is_success());
    assert_eq!(outcome.in_response_to, in_response_to);

    // Wrong correlation and wrong destination are rejected.
    assert!(matches!(
        validate_logout_response(&cfg(), &signed, &rd_verifier(), "_other", Utc::now()),
        Err(NlEidError::InResponseToMismatch { .. })
    ));
    let mut other_sls = cfg();
    other_sls.single_logout_url = Some("https://dv.example.nl/elsewhere".to_string());
    assert!(matches!(
        validate_logout_response(
            &other_sls,
            &signed,
            &rd_verifier(),
            in_response_to,
            Utc::now()
        ),
        Err(NlEidError::DestinationMismatch { .. })
    ));
    // A tampered response fails the signature.
    let tampered = signed.replacen(SLS, "https://attacker.example/slo", 1);
    assert!(matches!(
        validate_logout_response(
            &cfg(),
            &tampered,
            &rd_verifier(),
            in_response_to,
            Utc::now()
        ),
        Err(NlEidError::InvalidSignature { .. })
    ));
}

#[test]
fn sign_element_xml_places_an_assertion_signature_after_the_issuer() {
    let assertion = assertion_xml(&Wire::default()).replacen(
        "<saml:Assertion ",
        &format!(r#"<saml:Assertion xmlns:saml="{SAML}" "#),
        1,
    );
    let signed = sign_element_xml(
        &assertion,
        SAML,
        "Assertion",
        "_assertion1",
        &signer(RD_SIGNING_KEY),
        &cert_der_b64(RD_SIGNING_CERT),
    )
    .unwrap();
    let issuer = signed.find("</saml:Issuer>").unwrap();
    let sig = signed.find("<ds:Signature").unwrap();
    let subject = signed.find("<saml:Subject>").unwrap();
    assert!(issuer < sig && sig < subject);
    assert!(rd_verifier().verify_enveloped(&signed).unwrap().is_valid());
    // The same helper refuses an element that is not there.
    assert!(sign_message_xml(
        &assertion,
        "Response",
        "_assertion1",
        &signer(RD_SIGNING_KEY),
        "AA=="
    )
    .is_err());
}
