// RD-side message construction (§7.6, §7.8), the counterpart of
// `profiles::swedenconnect::idp`.
//
// gamlastan is the DV in an eID deployment; this module exists so that an RD
// mock, a conformance test or this crate's own test suite can produce the
// messages a Routeringsdienst sends from the typed protocol structs, instead
// of hand-written XML: a §7.6.3 `Assertion` inside a §7.6.2 `Response`, an
// §7.6.1 `ArtifactResponse` around it, the §7.8 statuses, `EncryptedID`
// identifiers wrapped for a recipient, and the RD signatures with a
// `<ds:KeyName>`-only `<ds:KeyInfo>` (§9.2).

use chrono::{DateTime, TimeDelta, Utc};

use crate::core::assertion::attribute::{Attribute, AttributeStatement, AttributeValue};
use crate::core::assertion::authn::{AuthnContext, AuthnStatement};
use crate::core::assertion::conditions::{AudienceRestriction, Conditions};
use crate::core::assertion::issuer::Issuer;
use crate::core::assertion::name_id::{NameId, NameIdOrEncryptedId};
use crate::core::assertion::subject::{Subject, SubjectConfirmation, SubjectConfirmationData};
use crate::core::assertion::types::{Advice, Assertion};
use crate::core::identifiers::{SamlId, SamlVersion};
use crate::core::protocol::artifact::ArtifactResponse;
use crate::core::protocol::response::{Response, ResponseBase};
use crate::core::protocol::status::Status;
use crate::crypto::keys::loader;
use crate::crypto::{KeysManager, SamlEncryptor, SamlSigner};
use crate::profiles::sso::idp as idp_profile;
use crate::profiles::sso::web_browser::ResponseTimes;
use crate::xml::serialize::SamlSerialize;
use crate::xml::XmlWriter;

use super::authn_context::LevelOfAssurance;
use super::constants;
use super::error::NlEidError;

/// The subject of a successful RD `Assertion` (§7.6.3.1, §7.6.3.4).
#[derive(Debug, Clone)]
pub struct RdSubject {
    /// The Subject TransientID.
    pub transient_name_id: String,
    /// The `ActingSubjectID` `<saml:EncryptedID>` XML (see [`encrypt_subject_id`]).
    pub acting_subject_id_xml: String,
    /// The `LegalSubjectID` `<saml:EncryptedID>` XML, for representation.
    pub legal_subject_id_xml: Option<String>,
}

impl RdSubject {
    /// A subject acting for themselves.
    pub fn new(
        transient_name_id: impl Into<String>,
        acting_subject_id_xml: impl Into<String>,
    ) -> Self {
        Self {
            transient_name_id: transient_name_id.into(),
            acting_subject_id_xml: acting_subject_id_xml.into(),
            legal_subject_id_xml: None,
        }
    }

    /// Add the `LegalSubjectID` of the represented party.
    pub fn representing(mut self, legal_subject_id_xml: impl Into<String>) -> Self {
        self.legal_subject_id_xml = Some(legal_subject_id_xml.into());
        self
    }
}

/// Inputs for a successful RD `Response` (§7.6.2, §7.6.3).
#[derive(Debug, Clone)]
pub struct RdResponseOptions {
    /// The RD `entityID` (Issuer of the Response and the Assertion).
    pub rd_entity_id: String,
    /// The DV `entityID` (the `<saml:Audience>`).
    pub dv_entity_id: String,
    /// The DV ACS URL (`@Destination` and bearer `@Recipient`).
    pub acs_url: String,
    /// The `AuthnRequest` `@ID` being answered.
    pub in_response_to: String,
    /// The `ServiceUUID` attribute value.
    pub service_uuid: String,
    /// The delivered Level of Assurance (emitted in its eIDAS spelling).
    pub level_of_assurance: LevelOfAssurance,
    /// `<saml:AuthenticatingAuthority>` entity IDs (the AD, and the BVD).
    pub authenticating_authorities: Vec<String>,
    /// The authenticated subject and its encrypted identifiers.
    pub subject: RdSubject,
    /// Validity window of the assertion and the bearer confirmation, in
    /// seconds from the issue instant (§7.6.3.3: initially two minutes).
    pub assertion_lifetime_seconds: u64,
    /// The AD / BVD assertions placed in `<saml:Advice>` (§7.6.3).
    pub advice: Vec<Assertion>,
}

impl RdResponseOptions {
    /// Options with a two-minute validity window and no advice.
    pub fn new(
        rd_entity_id: impl Into<String>,
        dv_entity_id: impl Into<String>,
        acs_url: impl Into<String>,
        in_response_to: impl Into<String>,
        service_uuid: impl Into<String>,
        level_of_assurance: LevelOfAssurance,
        subject: RdSubject,
    ) -> Self {
        Self {
            rd_entity_id: rd_entity_id.into(),
            dv_entity_id: dv_entity_id.into(),
            acs_url: acs_url.into(),
            in_response_to: in_response_to.into(),
            service_uuid: service_uuid.into(),
            level_of_assurance,
            authenticating_authorities: Vec::new(),
            subject,
            assertion_lifetime_seconds: constants::SUBJECT_CONFIRMATION_WINDOW_SECONDS,
            advice: Vec::new(),
        }
    }
}

/// An `<saml:AttributeValue>` holding `encrypted_id_xml` (a serialized
/// `<saml:EncryptedID>`, see [`encrypt_subject_id`]), as the §7.6.3.4
/// identifier attributes carry their values. `AttributeValue::Xml` holds the
/// complete `AttributeValue` element.
pub fn encrypted_id_attribute_value(encrypted_id_xml: &str) -> AttributeValue {
    let mut w = XmlWriter::with_capacity(encrypted_id_xml.len() + 64);
    w.start_element("saml:AttributeValue", &[]);
    w.raw(encrypted_id_xml);
    w.end_element("saml:AttributeValue");
    AttributeValue::Xml(w.into_string().into_bytes())
}

fn encrypted_id_attribute(name: &str, encrypted_id_xml: &str) -> Attribute {
    Attribute {
        name: name.to_string(),
        name_format: None,
        friendly_name: None,
        values: vec![encrypted_id_attribute_value(encrypted_id_xml)],
    }
}

/// Build the typed success `Response` with its one §7.6.3 `Assertion`
/// (cleartext; sign it with [`signed_artifact_response_xml`] once wrapped).
pub fn create_response(opts: &RdResponseOptions, times: ResponseTimes) -> Response {
    let lifetime =
        TimeDelta::try_seconds(i64::try_from(opts.assertion_lifetime_seconds).unwrap_or(i64::MAX))
            .unwrap_or(TimeDelta::MAX);
    let not_on_or_after = times
        .issue_instant
        .checked_add_signed(lifetime)
        .unwrap_or(DateTime::<Utc>::MAX_UTC);
    let not_before = times
        .issue_instant
        .checked_sub_signed(lifetime)
        .unwrap_or(DateTime::<Utc>::MIN_UTC);

    let mut attributes = vec![encrypted_id_attribute(
        constants::ATTR_ACTING_SUBJECT_ID,
        &opts.subject.acting_subject_id_xml,
    )];
    if let Some(legal) = &opts.subject.legal_subject_id_xml {
        attributes.push(encrypted_id_attribute(
            constants::ATTR_LEGAL_SUBJECT_ID,
            legal,
        ));
    }
    attributes.push(Attribute {
        name: constants::ATTR_SERVICE_UUID.to_string(),
        name_format: None,
        friendly_name: None,
        values: vec![AttributeValue::String(opts.service_uuid.clone())],
    });

    let assertion = Assertion {
        id: SamlId::generate().as_str().to_string(),
        version: SamlVersion::V2_0,
        issue_instant: times.issue_instant,
        issuer: Issuer::entity(&opts.rd_entity_id),
        has_signature: false,
        subject: Some(Subject {
            name_id: Some(NameIdOrEncryptedId::NameId(NameId {
                value: opts.subject.transient_name_id.clone(),
                format: Some(constants::NAMEID_TRANSIENT.to_string()),
                name_qualifier: None,
                sp_name_qualifier: None,
                sp_provided_id: None,
            })),
            subject_confirmations: vec![SubjectConfirmation {
                method: constants::CM_BEARER.to_string(),
                name_id: None,
                subject_confirmation_data: Some(SubjectConfirmationData {
                    not_before: None,
                    not_on_or_after: Some(not_on_or_after),
                    recipient: Some(opts.acs_url.clone()),
                    in_response_to: Some(opts.in_response_to.clone()),
                    address: None,
                    key_info_x509_certs: vec![],
                }),
            }],
        }),
        conditions: Some(Conditions {
            not_before: Some(not_before),
            not_on_or_after: Some(not_on_or_after),
            audience_restrictions: vec![AudienceRestriction {
                audiences: vec![opts.dv_entity_id.clone()],
            }],
            one_time_use: false,
            proxy_restriction: None,
        }),
        advice: if opts.advice.is_empty() {
            None
        } else {
            Some(Advice {
                assertion_id_refs: vec![],
                assertion_uri_refs: vec![],
                assertions: opts.advice.clone(),
                encrypted_assertions: vec![],
            })
        },
        authn_statements: vec![AuthnStatement {
            authn_instant: times.authn_instant,
            session_index: None,
            session_not_on_or_after: None,
            subject_locality: None,
            authn_context: AuthnContext {
                authn_context_class_ref: Some(opts.level_of_assurance.as_eidas_uri().to_string()),
                authn_context_decl_ref: None,
                authenticating_authorities: opts.authenticating_authorities.clone(),
            },
        }],
        authz_decision_statements: vec![],
        attribute_statements: vec![AttributeStatement { attributes }],
    };

    Response {
        base: ResponseBase {
            id: SamlId::generate().as_str().to_string(),
            version: SamlVersion::V2_0,
            issue_instant: times.issue_instant,
            destination: Some(opts.acs_url.clone()),
            consent: None,
            issuer: Some(Issuer::entity(&opts.rd_entity_id)),
            has_signature: false,
            in_response_to: Some(opts.in_response_to.clone()),
            status: Status::success(),
        },
        assertions: vec![assertion],
        encrypted_assertions: vec![],
    }
}

/// Build an error `Response` (no assertion) with the given §7.8 status.
pub fn create_error_response(
    rd_entity_id: &str,
    in_response_to: &str,
    acs_url: &str,
    status: Status,
    now: DateTime<Utc>,
) -> Response {
    idp_profile::create_error_response(rd_entity_id, Some(in_response_to), acs_url, status, now)
}

/// §7.8.3: the user cancelled (`Responder` / `AuthnFailed`, with the
/// mandatory message).
pub fn cancel_status() -> Status {
    Status::with_sub_status(
        constants::STATUS_RESPONDER,
        constants::STATUS_AUTHN_FAILED,
        Some(constants::STATUS_MESSAGE_CANCELLED.to_string()),
    )
}

/// §7.8.5: a recoverable incorrect message (`Responder` / `RequestUnsupported`
/// with a description).
pub fn request_unsupported_status(message: impl Into<String>) -> Status {
    Status::with_sub_status(
        constants::STATUS_RESPONDER,
        constants::STATUS_REQUEST_UNSUPPORTED,
        Some(message.into()),
    )
}

/// §7.8.2: the minimum Level of Assurance cannot be met.
pub fn no_authn_context_status() -> Status {
    Status::with_sub_status(
        constants::STATUS_RESPONDER,
        constants::STATUS_NO_AUTHN_CONTEXT,
        Some("Level of assurance not supported".to_string()),
    )
}

/// §7.8.2: the responder refuses the exchange (e.g. an unverifiable signature).
pub fn request_denied_status() -> Status {
    Status::with_sub_status(
        constants::STATUS_REQUESTER,
        constants::STATUS_REQUEST_DENIED,
        None,
    )
}

/// Wrap a `Response` in a §7.6.1 `ArtifactResponse` answering the
/// `ArtifactResolve` `in_response_to`. The Response is carried serialized, as
/// the `ArtifactResponse` type does.
pub fn create_artifact_response(
    rd_entity_id: &str,
    in_response_to: &str,
    response: &Response,
) -> Result<ArtifactResponse, NlEidError> {
    let message = response.to_xml_string()?.into_bytes();
    Ok(ArtifactResponse {
        id: SamlId::generate().as_str().to_string(),
        version: SamlVersion::V2_0,
        issue_instant: Utc::now(),
        destination: None,
        consent: None,
        issuer: Some(Issuer::entity(rd_entity_id)),
        has_signature: false,
        in_response_to: Some(in_response_to.to_string()),
        status: Status::success(),
        message: Some(message),
    })
}

/// An `ArtifactResponse` reporting that the artifact could not be resolved
/// (§7.6.1): no `Response` inside.
pub fn create_artifact_response_error(
    rd_entity_id: &str,
    in_response_to: &str,
    status: Status,
) -> ArtifactResponse {
    ArtifactResponse {
        id: SamlId::generate().as_str().to_string(),
        version: SamlVersion::V2_0,
        issue_instant: Utc::now(),
        destination: None,
        consent: None,
        issuer: Some(Issuer::entity(rd_entity_id)),
        has_signature: false,
        in_response_to: Some(in_response_to.to_string()),
        status,
        message: None,
    }
}

/// Encrypt a §7.6.3.4.4 `NameID` into a `<saml:EncryptedID>` for
/// `recipient_entity_id` (§7.6.3.4 `@Recipient`), using AES-256-CBC with the
/// content key transported by RSA-OAEP to `recipient_cert_der` (§9.3) and
/// named `key_name` in the `EncryptedKey`'s `<ds:KeyInfo>`.
pub fn encrypt_subject_id(
    name_id: &NameId,
    recipient_entity_id: &str,
    recipient_cert_der: &[u8],
    key_name: &str,
) -> Result<String, NlEidError> {
    let mut w = XmlWriter::with_capacity(1024);
    w.start_element(
        "saml:EncryptedID",
        &[
            ("xmlns:saml", constants::NS_SAML_ASSERTION),
            ("xmlns:xenc", constants::NS_XENC),
            ("xmlns:ds", constants::NS_DS),
        ],
    );
    w.start_element(
        "xenc:EncryptedData",
        &[("Type", "http://www.w3.org/2001/04/xmlenc#Element")],
    );
    w.empty_element(
        "xenc:EncryptionMethod",
        &[("Algorithm", constants::ENC_AES256_CBC)],
    );
    w.start_element("ds:KeyInfo", &[]);
    w.start_element("xenc:EncryptedKey", &[("Recipient", recipient_entity_id)]);
    w.empty_element(
        "xenc:EncryptionMethod",
        &[("Algorithm", constants::KEYTRANSPORT_RSA_OAEP_MGF1P)],
    );
    w.start_element("ds:KeyInfo", &[]);
    w.start_element("ds:KeyName", &[]);
    w.text(key_name);
    w.end_element("ds:KeyName");
    w.end_element("ds:KeyInfo");
    w.start_element("xenc:CipherData", &[]);
    w.start_element("xenc:CipherValue", &[]);
    w.end_element("xenc:CipherValue");
    w.end_element("xenc:CipherData");
    w.end_element("xenc:EncryptedKey");
    w.end_element("ds:KeyInfo");
    w.start_element("xenc:CipherData", &[]);
    w.start_element("xenc:CipherValue", &[]);
    w.end_element("xenc:CipherValue");
    w.end_element("xenc:CipherData");
    w.end_element("xenc:EncryptedData");
    w.end_element("saml:EncryptedID");
    let template = w.into_string();

    let recipient = loader::load_x509_cert_der(recipient_cert_der)
        .map_err(crate::crypto::CryptoError::BergshamraError)?
        .with_name(key_name);
    let mut km = KeysManager::new();
    km.add_key(recipient);
    let plaintext = name_id.to_xml_string()?;
    Ok(SamlEncryptor::new(km).encrypt(&template, plaintext.as_bytes())?)
}

/// The enveloped-signature template an RD uses (§9.1, §9.2): exclusive c14n,
/// RSA-SHA256 (or `signature_method_uri`), SHA-256 digest, and a
/// `<ds:KeyInfo>` carrying only the `<ds:KeyName>`.
pub fn rd_signature_template(
    reference_id: &str,
    key_name: &str,
    signature_method_uri: &str,
) -> String {
    let mut w = XmlWriter::with_capacity(768);
    w.start_element("ds:Signature", &[("xmlns:ds", constants::NS_DS)]);
    w.start_element("ds:SignedInfo", &[]);
    w.empty_element(
        "ds:CanonicalizationMethod",
        &[("Algorithm", constants::C14N_EXCLUSIVE)],
    );
    w.empty_element("ds:SignatureMethod", &[("Algorithm", signature_method_uri)]);
    let uri = format!("#{reference_id}");
    w.start_element("ds:Reference", &[("URI", uri.as_str())]);
    w.start_element("ds:Transforms", &[]);
    w.empty_element(
        "ds:Transform",
        &[("Algorithm", constants::TRANSFORM_ENVELOPED_SIGNATURE)],
    );
    w.empty_element("ds:Transform", &[("Algorithm", constants::C14N_EXCLUSIVE)]);
    w.end_element("ds:Transforms");
    w.empty_element(
        "ds:DigestMethod",
        &[("Algorithm", constants::DIGEST_SHA256)],
    );
    w.start_element("ds:DigestValue", &[]);
    w.end_element("ds:DigestValue");
    w.end_element("ds:Reference");
    w.end_element("ds:SignedInfo");
    w.start_element("ds:SignatureValue", &[]);
    w.end_element("ds:SignatureValue");
    w.start_element("ds:KeyInfo", &[]);
    w.start_element("ds:KeyName", &[]);
    w.text(key_name);
    w.end_element("ds:KeyName");
    w.end_element("ds:KeyInfo");
    w.end_element("ds:Signature");
    w.into_string()
}

/// Sign the `{element_ns}element_local` element with `@ID` `id` inside `xml`
/// as the RD: the [`rd_signature_template`] is placed after the element's
/// `<saml:Issuer>` and signed with `signer`.
pub fn sign_rd_element_xml(
    xml: &str,
    element_ns: &str,
    element_local: &str,
    id: &str,
    signer: &SamlSigner,
    key_name: &str,
) -> Result<String, NlEidError> {
    let method = signer.signature_method_uri()?;
    if !constants::is_allowed_signature_algorithm(method) {
        return Err(NlEidError::DisallowedAlgorithm {
            kind: "signature",
            uri: method.to_string(),
        });
    }
    let template = rd_signature_template(id, key_name, method);
    let with_template =
        idp_profile::insert_signature_after_issuer(xml, element_ns, element_local, id, &template)?;
    Ok(signer.sign_enveloped(&with_template)?)
}

/// Sign an RD metadata document (`<md:EntityDescriptor ID="id">`) as the RD
/// does (§8.2): the [`rd_signature_template`] with a `KeyName`-only `KeyInfo`
/// becomes the first child of the document element.
pub fn sign_rd_metadata_xml(
    xml: &str,
    id: &str,
    signer: &SamlSigner,
    key_name: &str,
) -> Result<String, NlEidError> {
    let method = signer.signature_method_uri()?;
    if !constants::is_allowed_signature_algorithm(method) {
        return Err(NlEidError::DisallowedAlgorithm {
            kind: "signature",
            uri: method.to_string(),
        });
    }
    let template = rd_signature_template(id, key_name, method);
    let with_template = super::xmlutil::insert_signature_as_first_child(xml, &template)?;
    Ok(signer.sign_enveloped(&with_template)?)
}

/// Serialize an `ArtifactResponse` and sign it as the RD does: first the
/// `Assertion` with `@ID` `assertion_id` (if any, §7.6.3), then the enveloping
/// `ArtifactResponse` (§7.6.1), so the outer signature covers the inner one.
pub fn signed_artifact_response_xml(
    artifact_response: &ArtifactResponse,
    assertion_id: Option<&str>,
    signer: &SamlSigner,
    key_name: &str,
) -> Result<String, NlEidError> {
    let mut xml = artifact_response.to_xml_string()?;
    if let Some(assertion_id) = assertion_id {
        xml = sign_rd_element_xml(
            &xml,
            constants::NS_SAML_ASSERTION,
            "Assertion",
            assertion_id,
            signer,
            key_name,
        )?;
    }
    sign_rd_element_xml(
        &xml,
        constants::NS_SAML_PROTOCOL,
        "ArtifactResponse",
        &artifact_response.id,
        signer,
        key_name,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const RD: &str = "urn:nl-eid-gdi:1.0:RD:00000004000000149000:entities:9002";
    const DV: &str = "urn:nl-eid-gdi:1.0:DV:00000001234567890000:entities:9001";

    fn opts() -> RdResponseOptions {
        RdResponseOptions::new(
            RD,
            DV,
            "https://dv.example.nl/saml/acs",
            "_authn1",
            "f847dc11-ac24-47b2-84a8-a057440ce56d",
            LevelOfAssurance::Substantial,
            RdSubject::new(
                "transient-1",
                r#"<saml:EncryptedID xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"/>"#,
            ),
        )
    }

    #[test]
    fn test_create_response_shape() {
        let now = Utc::now();
        let response = create_response(&opts(), ResponseTimes::at(now));
        assert!(response.base.status.is_success());
        assert_eq!(response.base.in_response_to.as_deref(), Some("_authn1"));
        let assertion = &response.assertions[0];
        assert_eq!(assertion.issuer.value, RD);
        assert_eq!(assertion.authn_statements.len(), 1);
        assert_eq!(
            assertion.authn_statements[0]
                .authn_context
                .authn_context_class_ref
                .as_deref(),
            Some(constants::LOA_SUBSTANTIAL_EIDAS)
        );
        let attrs = &assertion.attribute_statements[0].attributes;
        assert_eq!(attrs[0].name, constants::ATTR_ACTING_SUBJECT_ID);
        assert_eq!(attrs[1].name, constants::ATTR_SERVICE_UUID);
        let conditions = assertion.conditions.as_ref().unwrap();
        assert!(conditions.not_before.is_some() && conditions.not_on_or_after.is_some());
        assert!(assertion.advice.is_none());

        // Serializes with the EncryptedID embedded verbatim, inside an
        // AttributeValue.
        let xml = response.to_xml_string().unwrap();
        assert!(
            xml.contains("<saml:AttributeValue><saml:EncryptedID"),
            "{xml}"
        );
        assert!(xml.contains(constants::ATTR_SERVICE_UUID));
    }

    #[test]
    fn test_statuses_and_error_responses() {
        assert!(super::super::response::is_cancellation_status(
            &cancel_status()
        ));
        assert_eq!(
            request_denied_status().status_code.value,
            constants::STATUS_REQUESTER
        );
        assert_eq!(
            no_authn_context_status()
                .status_code
                .sub_status
                .unwrap()
                .value,
            constants::STATUS_NO_AUTHN_CONTEXT
        );
        let err = create_error_response(
            RD,
            "_authn1",
            "https://dv.example.nl/saml/acs",
            request_unsupported_status("Level of assurance not supported"),
            Utc::now(),
        );
        assert!(err.assertions.is_empty());
        assert!(!err.base.status.is_success());
    }

    #[test]
    fn test_artifact_response_carries_serialized_response() {
        let response = create_response(&opts(), ResponseTimes::at(Utc::now()));
        let art = create_artifact_response(RD, "_resolve1", &response).unwrap();
        assert_eq!(art.in_response_to.as_deref(), Some("_resolve1"));
        let xml = art.to_xml_string().unwrap();
        assert!(xml.contains("<samlp:Response"), "{xml}");
        assert!(xml.contains("<saml:Assertion"), "{xml}");
        let denied = create_artifact_response_error(RD, "_resolve1", request_denied_status());
        assert!(denied.message.is_none());
        assert!(!denied.status.is_success());
    }

    #[test]
    fn test_rd_signature_template_is_key_name_only() {
        let t = rd_signature_template("_x", "abc", constants::SIG_RSA_SHA256);
        assert!(t.contains("<ds:KeyName>abc</ds:KeyName>"));
        assert!(!t.contains("X509"));
        assert!(t.contains(r##"URI="#_x""##));
        assert!(crate::xml::parse_secure(&t).is_ok());
    }
}
