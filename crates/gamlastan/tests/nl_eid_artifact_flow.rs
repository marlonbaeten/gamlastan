//! End-to-end tests for the Dutch eID SAML (DV ↔ RD) profile.
//!
//! An RD-signed SOAP `ArtifactResponse` → `Response` → `Assertion` chain is
//! built here from the typed protocol structs through `profiles::nl_eid::rd`
//! and signed with dedicated test keys, exactly as a Routeringsdienst emits it
//! (RD signatures on the ArtifactResponse and the Assertion, an `EncryptedID`
//! for the acting subject wrapped to the DV encryption key, `KeyName`-only
//! KeyInfo), and driven through `process_artifact_response`. Only the mTLS
//! back-channel that would deliver these bytes is left out.

use base64::Engine;
use chrono::{Duration, Utc};

use gamlastan::core::assertion::name_id::NameId;
use gamlastan::core::assertion::types::{Assertion, EncryptedAssertion};
use gamlastan::core::identifiers::SamlVersion;
use gamlastan::core::protocol::logout::LogoutResponse;
use gamlastan::core::protocol::response::Response;
use gamlastan::core::protocol::status::Status;
use gamlastan::crypto::keys::loader;
use gamlastan::crypto::{KeyUsage, KeysManager, SamlSigner, SamlVerifier};
use gamlastan::profiles::nl_eid::rd::{
    cancel_status, create_artifact_response, create_artifact_response_error, create_error_response,
    create_response, encrypt_subject_id, encrypted_id_attribute_value, request_denied_status,
    request_unsupported_status, sign_rd_element_xml, sign_rd_metadata_xml,
    signed_artifact_response_xml, RdResponseOptions, RdSubject,
};
use gamlastan::profiles::nl_eid::{
    build_dv_metadata, constants, parse_rd_metadata, sign_element_xml, signed_artifact_resolve,
    signed_authn_request, signed_logout_request, validate_logout_response, ArtifactResponseParams,
    AuthnOutcome, DvDecryptionKeys, DvMetadataOptions, IdentifierType, LevelOfAssurance,
    NlEidAuthnOptions, NlEidConfig, NlEidError, PublishedCertificate, RdMetadata,
};
use gamlastan::profiles::sso::web_browser::ResponseTimes;
use gamlastan::security::replay::InMemoryReplayCache;
use gamlastan::xml::serialize::SamlSerialize;

const RD_SIGNING_CERT: &str = include_str!("fixtures/nl_eid/rd-signing-cert.pem");
const RD_SIGNING_KEY: &str = include_str!("fixtures/nl_eid/rd-signing-key.pem");
const DV_SIGNING_CERT: &str = include_str!("fixtures/nl_eid/dv-signing-cert.pem");
const DV_SIGNING_KEY: &str = include_str!("fixtures/nl_eid/dv-signing-key.pem");
const DV_ENCRYPTION_CERT: &str = include_str!("fixtures/nl_eid/dv-encryption-cert.pem");
const DV_ENCRYPTION_KEY: &str = include_str!("fixtures/nl_eid/dv-encryption-key.pem");
const DV_ENCRYPTION_2_CERT: &str = include_str!("fixtures/nl_eid/dv-encryption-2-cert.pem");
const DV_ENCRYPTION_2_KEY: &str = include_str!("fixtures/nl_eid/dv-encryption-2-key.pem");

const DV: &str = "urn:nl-eid-gdi:1.0:DV:00000001234567890000:entities:9001";
const OTHER_DV: &str = "urn:nl-eid-gdi:1.0:DV:00000000000000000001:entities:0001";
const RD: &str = "urn:nl-eid-gdi:1.0:RD:00000004000000149000:entities:9002";
const AD: &str = "urn:nl-eid-gdi:1.0:AD:00000004166909913000:entities:9002";
const ACS: &str = "https://dv.example.nl/saml/acs";
const SLS: &str = "https://dv.example.nl/saml/slo";
const SERVICE_UUID: &str = "f847dc11-ac24-47b2-84a8-a057440ce56d";
const RESOLVE_ID: &str = "_resolve1";
const AUTHN_ID: &str = "_authn1";
const RESPONSE_ID: &str = "_response1";
const ASSERTION_ID: &str = "_assertion1";
const TRANSIENT_ID: &str = "64b0d194095940008ffa142b12444c01";
const BSN: &str = "900070341";

const SAML: &str = constants::NS_SAML_ASSERTION;
const SAMLP: &str = constants::NS_SAML_PROTOCOL;
const XENC: &str = constants::NS_XENC;

// ── Key material ────────────────────────────────────────────────────────────

fn cert_der_b64(cert_pem: &str) -> String {
    cert_pem
        .lines()
        .filter(|l| !l.starts_with("-----"))
        .map(str::trim)
        .collect()
}

fn cert_der(cert_pem: &str) -> Vec<u8> {
    base64::engine::general_purpose::STANDARD
        .decode(cert_der_b64(cert_pem))
        .expect("certificate DER")
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

fn rd_key_name() -> String {
    published(RD_SIGNING_CERT).key_name
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

/// A §7.6.3.4.4 persistent `NameID` carrying a legacy BSN.
fn bsn_name_id(value: &str) -> NameId {
    NameId {
        value: value.to_string(),
        format: Some(constants::NAMEID_PERSISTENT.to_string()),
        name_qualifier: Some(constants::ID_TYPE_LEGACY_BSN.to_string()),
        sp_name_qualifier: None,
        sp_provided_id: None,
    }
}

/// An `EncryptedID` carrying `name_id`, wrapped to `cert_pem` for `recipient`
/// with the inline-`EncryptedKey` layout (AES-256-CBC data, RSA-OAEP key
/// transport, §9.3).
fn encrypted_id(cert_pem: &str, recipient: &str, name_id: &NameId) -> String {
    let cert = published(cert_pem);
    encrypt_subject_id(name_id, recipient, &cert_der(cert_pem), &cert.key_name)
        .expect("encrypt NameID")
}

/// Rewrite an inline-layout `EncryptedID` into the layout TVS actually emits
/// on the wire: the `EncryptedKey` as a sibling of `EncryptedData`, referenced
/// through a `ds:RetrievalMethod`, with `Id` attributes and a `ReferenceList`.
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
    /// The AuthnContextClassRef; `None` is the eIDAS spelling of Substantial.
    loa: Option<&'static str>,
    service_uuid: &'static str,
    /// The `ActingSubjectID` attribute values (one `EncryptedID` XML each);
    /// empty omits the attribute.
    acting_subject: Vec<String>,
    /// Add an `EncryptedAssertion` to the Response.
    encrypted_assertion: bool,
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
            loa: None,
            service_uuid: SERVICE_UUID,
            acting_subject: vec![encrypted_id(DV_ENCRYPTION_CERT, DV, &bsn_name_id(BSN))],
            encrypted_assertion: false,
            time_offset: Duration::zero(),
            namespaces_on_envelope: false,
        }
    }
}

/// The AD's own assertion as the RD places it in `<saml:Advice>` (§7.6.3):
/// evidence only, not consumed.
fn ad_advice_assertion(times: ResponseTimes) -> Assertion {
    let opts = RdResponseOptions::new(
        AD,
        RD,
        "https://rd.example/acs",
        "_rd-to-ad",
        SERVICE_UUID,
        LevelOfAssurance::Substantial,
        RdSubject::new(
            "ad-transient",
            r#"<saml:EncryptedID xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"/>"#,
        ),
    );
    let mut assertion = create_response(&opts, times).assertions.remove(0);
    assertion.id = "_ad1".to_string();
    assertion
}

/// The typed `Response` for `wire`.
fn response_for(wire: &Wire) -> Response {
    let now = Utc::now() + wire.time_offset;
    let times = ResponseTimes::at(now);
    match wire.outcome {
        Outcome::Cancelled => {
            create_error_response(RD, wire.response_in_response_to, ACS, cancel_status(), now)
        }
        Outcome::Failed => create_error_response(
            RD,
            wire.response_in_response_to,
            ACS,
            request_unsupported_status("Level of assurance not supported"),
            now,
        ),
        Outcome::Success => {
            let mut opts = RdResponseOptions::new(
                RD,
                wire.audience,
                ACS,
                wire.response_in_response_to,
                wire.service_uuid,
                LevelOfAssurance::Substantial,
                RdSubject::new(
                    TRANSIENT_ID,
                    wire.acting_subject.first().cloned().unwrap_or_default(),
                ),
            );
            opts.authenticating_authorities = vec![AD.to_string()];
            opts.advice = vec![ad_advice_assertion(times)];
            let mut response = create_response(&opts, times);
            response.base.id = RESPONSE_ID.to_string();

            let assertion = &mut response.assertions[0];
            assertion.id = ASSERTION_ID.to_string();
            assertion.has_signature = wire.sign_assertion;
            let scd = assertion.subject.as_mut().unwrap().subject_confirmations[0]
                .subject_confirmation_data
                .as_mut()
                .unwrap();
            scd.in_response_to = Some(wire.assertion_in_response_to.to_string());
            if let Some(loa) = wire.loa {
                assertion.authn_statements[0]
                    .authn_context
                    .authn_context_class_ref = Some(loa.to_string());
            }
            let attributes = &mut assertion.attribute_statements[0].attributes;
            if wire.acting_subject.is_empty() {
                attributes.retain(|a| a.name != constants::ATTR_ACTING_SUBJECT_ID);
            } else {
                attributes[0].values = wire
                    .acting_subject
                    .iter()
                    .map(|xml| encrypted_id_attribute_value(xml))
                    .collect();
            }

            if wire.encrypted_assertion {
                let raw = format!(
                    r#"<saml:EncryptedAssertion xmlns:saml="{SAML}"><xenc:EncryptedData xmlns:xenc="{XENC}"><xenc:EncryptionMethod Algorithm="{}"/><xenc:CipherData><xenc:CipherValue>AA==</xenc:CipherValue></xenc:CipherData></xenc:EncryptedData></saml:EncryptedAssertion>"#,
                    constants::ENC_AES256_CBC
                );
                response.encrypted_assertions.push(EncryptedAssertion {
                    raw: raw.into_bytes(),
                });
            }
            response
        }
    }
}

/// The complete SOAP body the back-channel returns for `wire`.
fn soap_artifact_response(wire: &Wire) -> String {
    let mut artifact_response = if wire.artifact_resolved {
        create_artifact_response(RD, wire.resolve_id, &response_for(wire)).expect("wrap")
    } else {
        create_artifact_response_error(RD, wire.resolve_id, request_denied_status())
    };
    artifact_response.id = "_artifactresponse1".to_string();
    artifact_response.issue_instant = Utc::now() + wire.time_offset;

    // The RD signs the assertion first, then the enveloping ArtifactResponse.
    let sign_assertion =
        wire.sign_assertion && wire.artifact_resolved && matches!(wire.outcome, Outcome::Success);
    let key_name = wire.rd_key_name.clone().unwrap_or_else(rd_key_name);
    let signed = signed_artifact_response_xml(
        &artifact_response,
        sign_assertion.then_some(ASSERTION_ID),
        &signer(wire.rd_signing_key),
        &key_name,
    )
    .expect("RD signs");

    if wire.namespaces_on_envelope {
        // Exclusive c14n renders visibly used namespaces on the apex element,
        // so moving the declarations to the envelope leaves the digest intact.
        let decls = format!(r#" xmlns:samlp="{SAMLP}" xmlns:saml="{SAML}""#);
        let stripped = signed.replacen(&decls, "", 1);
        assert_ne!(stripped, signed, "{signed}");
        format!(
            r#"<soapenv:Envelope xmlns:soapenv="{}"{decls}><soapenv:Body>{stripped}</soapenv:Body></soapenv:Envelope>"#,
            constants::NS_SOAP11
        )
    } else {
        gamlastan::bindings::soap::soap_envelope_wrap(&signed, None)
    }
}

fn process(
    cfg: &NlEidConfig,
    body: &str,
    keys: &DvDecryptionKeys,
    cache: &InMemoryReplayCache,
) -> Result<AuthnOutcome, NlEidError> {
    gamlastan::profiles::nl_eid::process_artifact_response(
        cfg,
        body,
        &rd_verifier(),
        keys,
        &params(cache),
    )
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
    process(cfg, &soap_artifact_response(wire), keys, &cache)
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
    assert_eq!(result.transient_name_id, TRANSIENT_ID);
    assert_eq!(result.level_of_assurance, LevelOfAssurance::Substantial);
    assert_eq!(result.authenticating_authorities, vec![AD.to_string()]);
    assert_eq!(result.service_uuid, SERVICE_UUID);
    assert_eq!(result.rd_signing_key_name, rd_key_name());
    assert_eq!(result.authn.idp_entity_id, RD);
    assert_eq!(result.authn.assertion_id, ASSERTION_ID);
    assert_eq!(result.authn.response_id, RESPONSE_ID);
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
    let inline = encrypted_id(DV_ENCRYPTION_CERT, DV, &bsn_name_id(BSN));
    let wire = Wire {
        acting_subject: vec![to_retrieval_layout(&inline, "-1")],
        ..Wire::default()
    };
    let result = authenticated(run(&wire));
    assert_eq!(result.acting_subject.expose_value(), BSN);
}

#[test]
fn a_legal_subject_is_decrypted_alongside_the_acting_subject() {
    let mut response = response_for(&Wire::default());
    let legal = encrypted_id(DV_ENCRYPTION_CERT, DV, &bsn_name_id("000000012"));
    let attributes = &mut response.assertions[0].attribute_statements[0].attributes;
    attributes.insert(
        1,
        gamlastan::core::assertion::attribute::Attribute {
            name: constants::ATTR_LEGAL_SUBJECT_ID.to_string(),
            name_format: None,
            friendly_name: None,
            values: vec![encrypted_id_attribute_value(&legal)],
        },
    );
    let art = create_artifact_response(RD, RESOLVE_ID, &response).unwrap();
    let signed = signed_artifact_response_xml(
        &art,
        Some(ASSERTION_ID),
        &signer(RD_SIGNING_KEY),
        &rd_key_name(),
    )
    .unwrap();
    let cache = InMemoryReplayCache::new();
    let body = gamlastan::bindings::soap::soap_envelope_wrap(&signed, None);
    let result = authenticated(process(&cfg(), &body, &dv_keys(), &cache));
    assert_eq!(result.acting_subject.expose_value(), BSN);
    assert_eq!(
        result.legal_subject.as_ref().unwrap().expose_value(),
        "000000012"
    );
}

#[test]
fn keys_wrapped_for_another_recipient_are_ignored() {
    // Two EncryptedIDs for the attribute (one per recipient, §7.6.3.4), the
    // foreign one first and wrapped to a key we do not hold.
    let foreign = encrypted_id(DV_ENCRYPTION_2_CERT, OTHER_DV, &bsn_name_id("000000000"));
    let ours = encrypted_id(DV_ENCRYPTION_CERT, DV, &bsn_name_id(BSN));
    let wire = Wire {
        acting_subject: vec![foreign, ours],
        ..Wire::default()
    };
    let result = authenticated(run(&wire));
    assert_eq!(result.acting_subject.expose_value(), BSN);
}

#[test]
fn a_message_wrapped_to_the_rollover_key_decrypts_with_the_second_key() {
    let wire = Wire {
        acting_subject: vec![encrypted_id(DV_ENCRYPTION_2_CERT, DV, &bsn_name_id(BSN))],
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
    let sig_start = inner.find("<ds:Signature").unwrap();
    let sig_end = inner.find("</ds:Signature>").unwrap() + "</ds:Signature>".len();
    let signature = &inner[sig_start..sig_end];
    let now = Utc::now().format("%Y-%m-%dT%H:%M:%SZ");
    let forged = format!(
        r#"<samlp:ArtifactResponse xmlns:samlp="{SAMLP}" xmlns:saml="{SAML}" ID="_forged" Version="2.0" IssueInstant="{now}" InResponseTo="{RESOLVE_ID}"><saml:Issuer>{RD}</saml:Issuer>{signature}<samlp:Extensions>{inner}</samlp:Extensions><samlp:Status><samlp:StatusCode Value="{}"/></samlp:Status></samlp:ArtifactResponse>"#,
        constants::STATUS_SUCCESS
    );
    let cache = InMemoryReplayCache::new();
    let err = process(
        &cfg(),
        &gamlastan::bindings::soap::soap_envelope_wrap(&forged, None),
        &dv_keys(),
        &cache,
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
        audience: OTHER_DV,
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
            loa: Some(constants::LOA_BASIC),
            ..Wire::default()
        }),
        Err(NlEidError::LevelOfAssuranceTooLow { .. })
    ));
    assert!(matches!(
        run(&Wire {
            loa: Some("urn:bogus:loa"),
            ..Wire::default()
        }),
        Err(NlEidError::UnknownLevelOfAssurance(_))
    ));
    let result = authenticated(run(&Wire {
        loa: Some(constants::LOA_HIGH),
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
            acting_subject: vec![encrypted_id(
                DV_ENCRYPTION_CERT,
                OTHER_DV,
                &bsn_name_id(BSN)
            )],
            ..Wire::default()
        }),
        Err(NlEidError::NoEncryptedKeyForRecipient { .. })
    ));
    assert!(matches!(
        run(&Wire {
            acting_subject: vec![],
            ..Wire::default()
        }),
        Err(NlEidError::MissingActingSubjectId)
    ));
}

#[test]
fn a_decrypted_name_id_of_the_wrong_shape_is_rejected() {
    let transient = NameId {
        format: Some(constants::NAMEID_TRANSIENT.to_string()),
        ..bsn_name_id(BSN)
    };
    assert!(matches!(
        run(&Wire {
            acting_subject: vec![encrypted_id(DV_ENCRYPTION_CERT, DV, &transient)],
            ..Wire::default()
        }),
        Err(NlEidError::InvalidDecryptedNameId { .. })
    ));
}

#[test]
fn an_encrypted_assertion_is_forbidden() {
    assert!(matches!(
        run(&Wire {
            encrypted_assertion: true,
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
    let first = process(&cfg(), &body, &dv_keys(), &cache);
    assert!(first.unwrap().is_authenticated());
    let second = process(&cfg(), &body, &dv_keys(), &cache).unwrap_err();
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
    let err = process(&cfg(), &body, &dv_keys(), &cache).unwrap_err();
    assert!(
        matches!(err, NlEidError::DisallowedAlgorithm { kind: "digest", .. }),
        "{err}"
    );
}

#[test]
fn garbage_from_the_back_channel_is_rejected() {
    let cache = InMemoryReplayCache::new();
    for body in ["502 Bad Gateway", "<html><body>proxy error</body></html>"] {
        let err = process(&cfg(), body, &dv_keys(), &cache).unwrap_err();
        assert!(matches!(err, NlEidError::MalformedMessage(_)), "{err}");
    }
}

// ── DV-side messages and metadata ───────────────────────────────────────────

fn dv_verifier() -> SamlVerifier {
    let mut key = loader::load_pem_auto(DV_SIGNING_CERT.as_bytes(), None).expect("DV cert");
    key.usage = KeyUsage::Verify;
    let mut km = KeysManager::new();
    km.add_key(key);
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
fn rd_metadata_is_trust_filtered_and_its_signature_verified() {
    // The RD signs its metadata with a key it also publishes in it. The DV
    // keeps only the keys its deployment trusts and then verifies the document
    // against exactly those.
    let unsigned = rd_metadata_xml(RD_SIGNING_CERT);
    let signed = sign_rd_metadata_xml(
        &unsigned,
        "_rdmeta",
        &signer(RD_SIGNING_KEY),
        &rd_key_name(),
    )
    .unwrap();
    let mut rd = parse_rd_metadata(&signed).unwrap();
    assert_eq!(rd.signing_keys.len(), 1);
    assert_eq!(rd.verify_signature(&signed).unwrap(), rd_key_name());

    // A tampered document fails.
    let tampered = signed.replacen("https://rd.example/ars", "https://evil.example/ars", 1);
    assert!(matches!(
        rd.verify_signature(&tampered),
        Err(NlEidError::InvalidSignature { .. })
    ));
    // The unsigned document fails.
    assert!(matches!(
        rd.verify_signature(&unsigned),
        Err(NlEidError::MissingSignature("EntityDescriptor"))
    ));
    // A deployment trust filter that rejects the key leaves nothing to verify
    // with, and the filter itself fails closed.
    assert!(matches!(
        rd.retain_signing_keys(|key| key.cert_der != cert_der(RD_SIGNING_CERT)),
        Err(NlEidError::Metadata(_))
    ));

    // A document published with one key but signed by another the DV does not
    // hold is refused before any cryptography: the KeyName is unknown.
    let foreign = sign_rd_metadata_xml(
        &unsigned,
        "_rdmeta",
        &signer(DV_SIGNING_KEY),
        &published(DV_SIGNING_CERT).key_name,
    )
    .unwrap();
    let rd = parse_rd_metadata(&foreign).unwrap();
    assert!(matches!(
        rd.verify_signature(&foreign),
        Err(NlEidError::UnknownSigningKey(_))
    ));
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
    let doc = gamlastan::xml::parse_secure_metadata(&xml).unwrap();
    let root = doc.document_element().unwrap();
    let first_child = doc
        .children_iter(root)
        .find(|c| doc.element(*c).is_some())
        .unwrap();
    assert!(doc
        .element(first_child)
        .unwrap()
        .matches_name_ns(constants::NS_DS, "Signature"));
    assert!(xml.contains(&published(DV_ENCRYPTION_2_CERT).key_name));
}

#[test]
fn a_logout_response_from_the_rd_validates() {
    let in_response_to = "_logout1";
    let response = LogoutResponse {
        id: "_lr1".to_string(),
        version: SamlVersion::V2_0,
        issue_instant: Utc::now(),
        destination: Some(SLS.to_string()),
        consent: None,
        issuer: Some(gamlastan::core::assertion::issuer::Issuer::entity(RD)),
        has_signature: true,
        in_response_to: Some(in_response_to.to_string()),
        status: Status::success(),
    };
    let signed = sign_rd_element_xml(
        &response.to_xml_string().unwrap(),
        SAMLP,
        "LogoutResponse",
        "_lr1",
        &signer(RD_SIGNING_KEY),
        &rd_key_name(),
    )
    .unwrap();
    let outcome = validate_logout_response(
        &cfg(),
        &signed,
        &rd_verifier(),
        Some(in_response_to),
        Utc::now(),
    )
    .unwrap();
    assert!(outcome.is_success());
    assert_eq!(outcome.in_response_to, in_response_to);
    assert_eq!(outcome.rd_signing_key_name, rd_key_name());
    // Without an expectation the caller correlates afterwards.
    let outcome =
        validate_logout_response(&cfg(), &signed, &rd_verifier(), None, Utc::now()).unwrap();
    assert_eq!(outcome.in_response_to, in_response_to);

    // Wrong correlation and wrong destination are rejected.
    assert!(matches!(
        validate_logout_response(&cfg(), &signed, &rd_verifier(), Some("_other"), Utc::now()),
        Err(NlEidError::InResponseToMismatch { .. })
    ));
    let mut other_sls = cfg();
    other_sls.single_logout_url = Some("https://dv.example.nl/elsewhere".to_string());
    assert!(matches!(
        validate_logout_response(
            &other_sls,
            &signed,
            &rd_verifier(),
            Some(in_response_to),
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
            Some(in_response_to),
            Utc::now()
        ),
        Err(NlEidError::InvalidSignature { .. })
    ));
    // An unsigned response is refused.
    assert!(matches!(
        validate_logout_response(
            &cfg(),
            &response.to_xml_string().unwrap(),
            &rd_verifier(),
            Some(in_response_to),
            Utc::now()
        ),
        Err(NlEidError::MissingSignature("LogoutResponse"))
    ));
}

#[test]
fn sign_element_xml_places_an_assertion_signature_after_the_issuer() {
    let assertion = response_for(&Wire::default()).assertions.remove(0);
    let signed = sign_element_xml(
        &assertion.to_xml_string().unwrap(),
        SAML,
        "Assertion",
        ASSERTION_ID,
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
    assert!(sign_element_xml(
        &assertion.to_xml_string().unwrap(),
        SAML,
        "Assertion",
        "_not-there",
        &signer(RD_SIGNING_KEY),
        &cert_der_b64(RD_SIGNING_CERT),
    )
    .is_err());
}
