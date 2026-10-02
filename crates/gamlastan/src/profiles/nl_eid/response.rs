// DV-side processing of the resolved `ArtifactResponse` (§7.6).
//
// The RD answers an `ArtifactResolve` over the SOAP back-channel with
//
//     <samlp:ArtifactResponse>          RD-signed (§7.6.1)
//       <samlp:Response>                SHOULD NOT be signed (§7.6.2)
//         <saml:Assertion>              RD-signed (§7.6.3)
//           … <saml:EncryptedID> …      identifiers encrypted to the DV (§7.6.3.4)
//           <saml:Advice>               AD / BVD evidence, never consumed
//
// Everything is navigated on one parsed document. A sub-element whose
// signature must be verified or whose content must be decrypted is
// re-serialized as a standalone document (with its inherited namespace
// declarations) only for that purpose; claims are always read from the tree.

use chrono::{DateTime, Utc};
use zeroize::Zeroizing;

use crate::core::assertion::name_id::{NameIdOrEncryptedId, NameIdRef};
use crate::core::assertion::types::Assertion;
use crate::core::protocol::artifact::{ArtifactResponse, ArtifactResponseRef};
use crate::core::protocol::response::{Response, ResponseRef};
use crate::core::protocol::status::Status;
use crate::crypto::keys::loader;
use crate::crypto::{KeyUsage, KeysManager, SamlDecryptor, SamlVerifier};
use crate::profiles::error::ProfileError;
use crate::profiles::sso::web_browser::{self, AuthnResult};
use crate::security::replay::ReplayCache;
use crate::security::validation::{AssertionValidator, ValidationParams};
use crate::xml::deserialize::SamlDeserialize;
use crate::xml::uppsala::{Document, NodeId};

use super::authn_context::{validate_level_of_assurance, LevelOfAssurance};
use super::config::NlEidConfig;
use super::constants;
use super::error::NlEidError;
use super::xmlutil;

// ── Inputs ──────────────────────────────────────────────────────────────────

/// Correlation inputs for [`process_artifact_response`].
pub struct ArtifactResponseParams<'a> {
    /// The `@ID` of the `ArtifactResolve` this DV sent; the ArtifactResponse
    /// `@InResponseTo` MUST equal it (§7.6.1).
    pub expected_artifact_resolve_id: &'a str,

    /// The `@ID` of the `AuthnRequest` this browser's flow started; the
    /// Response `@InResponseTo` and the bearer `SubjectConfirmationData
    /// @InResponseTo` MUST equal it (§7.6.2, §7.6.3.3, §7.6.3.5 rule 4).
    ///
    /// Matching is done here; *consuming* the pending request ID so a replay
    /// is refused (§9.7) stays with the embedding application, whose store
    /// may be shared across instances. Consume it only after this function
    /// returns an [`AuthnOutcome`].
    pub expected_authn_request_id: &'a str,

    /// Assertion-ID replay cache (§9.7). Required: the specification mandates
    /// replay protection.
    pub replay_cache: &'a dyn ReplayCache,

    /// The `RelayState` returned with the artifact, if the DV used one (§9.8:
    /// the RD returns it unverified, so the DV checks its content and length).
    pub relay_state: Option<&'a str>,

    /// The current time (injectable for testing).
    pub now: DateTime<Utc>,
}

/// The DV's private decryption keys, one [`SamlDecryptor`] per key.
///
/// The RD wraps the content-encryption key once per encryption certificate
/// the DV publishes (§7.6.3.4.4), so during certificate rollover a message may
/// decrypt with the second key only. The XML Encryption backend uses the first
/// RSA private key of its key manager, hence one decryptor per key, tried in
/// order.
#[derive(Default)]
pub struct DvDecryptionKeys {
    decryptors: Vec<SamlDecryptor>,
}

impl DvDecryptionKeys {
    /// No keys. Add some with [`push`](Self::push) or
    /// [`add_private_key_pem`](Self::add_private_key_pem).
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a ready-made decryptor (for HSM-backed or pre-configured keys).
    pub fn push(&mut self, decryptor: SamlDecryptor) {
        self.decryptors.push(decryptor);
    }

    /// Add a PEM-encoded RSA private key (PKCS#8 or PKCS#1, unencrypted or
    /// with `password`).
    pub fn add_private_key_pem(
        &mut self,
        private_key_pem: &[u8],
        password: Option<&str>,
    ) -> Result<(), NlEidError> {
        let mut key = loader::load_pem_auto(private_key_pem, password)
            .map_err(crate::crypto::CryptoError::BergshamraError)?;
        key.usage = KeyUsage::Decrypt;
        let mut km = KeysManager::new();
        km.add_key(key);
        self.decryptors.push(SamlDecryptor::new(km));
        Ok(())
    }

    /// Build from PEM-encoded private keys.
    pub fn from_private_key_pems<'a, I>(pems: I) -> Result<Self, NlEidError>
    where
        I: IntoIterator<Item = &'a [u8]>,
    {
        let mut keys = Self::new();
        for pem in pems {
            keys.add_private_key_pem(pem, None)?;
        }
        Ok(keys)
    }

    /// Number of configured keys.
    pub fn len(&self) -> usize {
        self.decryptors.len()
    }

    /// Whether no key is configured.
    pub fn is_empty(&self) -> bool {
        self.decryptors.is_empty()
    }

    /// Decrypt an `EncryptedID` document with the first key that succeeds.
    fn decrypt(&self, encrypted_xml: &str) -> Result<Zeroizing<String>, String> {
        if self.decryptors.is_empty() {
            return Err("no decryption keys configured".to_string());
        }
        let mut last = String::new();
        for decryptor in &self.decryptors {
            match decryptor.decrypt(encrypted_xml) {
                Ok(plaintext) => return Ok(Zeroizing::new(plaintext)),
                Err(e) => last = e.to_string(),
            }
        }
        Err(last)
    }
}

// ── Outputs ─────────────────────────────────────────────────────────────────

/// The §10.1 identifier type a decrypted `EncryptedID` declares.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IdentifierType {
    /// A BSN, 9 digits with leading zeros.
    LegacyBsn,
    /// An encrypted (polymorphic) BSN.
    Bsn,
    /// An encrypted pseudonym.
    Pseudonym,
}

impl IdentifierType {
    /// Parse a `@NameQualifier`.
    pub fn from_uri(uri: &str) -> Option<Self> {
        match uri {
            constants::ID_TYPE_LEGACY_BSN => Some(Self::LegacyBsn),
            constants::ID_TYPE_BSN => Some(Self::Bsn),
            constants::ID_TYPE_PSEUDONYM => Some(Self::Pseudonym),
            _ => None,
        }
    }

    /// The `@NameQualifier` URI.
    pub fn as_uri(self) -> &'static str {
        match self {
            Self::LegacyBsn => constants::ID_TYPE_LEGACY_BSN,
            Self::Bsn => constants::ID_TYPE_BSN,
            Self::Pseudonym => constants::ID_TYPE_PSEUDONYM,
        }
    }
}

/// A decrypted subject identifier (BSN or pseudonym): personal data.
///
/// The value is zeroized when dropped and never appears in `Debug` output;
/// read it with [`expose_value`](Self::expose_value).
#[derive(Clone)]
pub struct SubjectId {
    value: Zeroizing<String>,
    identifier_type: IdentifierType,
}

impl SubjectId {
    /// The identifier type declared by the `@NameQualifier`.
    pub fn identifier_type(&self) -> IdentifierType {
        self.identifier_type
    }

    /// The identifier itself. Handle as personal data.
    pub fn expose_value(&self) -> &str {
        &self.value
    }
}

impl std::fmt::Debug for SubjectId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SubjectId")
            .field("identifier_type", &self.identifier_type)
            .field("value_len", &self.value.len())
            .finish_non_exhaustive()
    }
}

/// A successful, fully validated eID authentication.
#[derive(Debug, Clone)]
pub struct NlEidAuthnResult {
    /// The underlying Web Browser SSO result (issuer, session, authn context,
    /// raw attributes). Attribute values of the identifier attributes are
    /// ciphertext; the decrypted identities are the fields below.
    pub authn: AuthnResult,
    /// The Subject TransientID `<saml:NameID>`, needed for a later
    /// `LogoutRequest` (§7.7.1).
    pub transient_name_id: String,
    /// The delivered Level of Assurance (≥ the configured minimum).
    pub level_of_assurance: LevelOfAssurance,
    /// The `<saml:AuthenticatingAuthority>` entity IDs (the AD, and the BVD
    /// for representation).
    pub authenticating_authorities: Vec<String>,
    /// The `ServiceUUID` attribute (equal to the configured one).
    pub service_uuid: String,
    /// The authenticated subject (`ActingSubjectID`).
    pub acting_subject: SubjectId,
    /// The represented party (`LegalSubjectID`), present for representation.
    pub legal_subject: Option<SubjectId>,
    /// The `<ds:KeyName>` of the RD key that signed the ArtifactResponse.
    pub rd_signing_key_name: String,
}

/// What a well-formed, RD-signed answer to this browser's flow said.
///
/// A protocol or trust violation is an [`NlEidError`] instead; these three
/// variants are all genuine RD answers to the DV's own `AuthnRequest`, which
/// is why the embedding application may end its local session on the failure
/// variants (§9.9) but must not do so for an error.
#[derive(Debug)]
pub enum AuthnOutcome {
    /// Every check passed; the user is authenticated.
    Authenticated(Box<NlEidAuthnResult>),
    /// The user cancelled at the AD/BVD (§7.8.3): `Responder` / `AuthnFailed`.
    /// The RD includes the message "Authentication cancelled"; the same status
    /// pair is also sent for failed credentials, so `status` is kept.
    Cancelled {
        /// The Response status.
        status: Status,
    },
    /// Any other non-success Response status (§7.8).
    Failed {
        /// The Response status.
        status: Status,
    },
}

impl AuthnOutcome {
    /// Whether this outcome authenticated the user.
    pub fn is_authenticated(&self) -> bool {
        matches!(self, AuthnOutcome::Authenticated(_))
    }
}

/// Whether a non-success Response status denotes a user cancellation (§7.8.3).
pub fn is_cancellation_status(status: &Status) -> bool {
    if status.status_code.value != constants::STATUS_RESPONDER {
        return false;
    }
    let authn_failed = status
        .status_code
        .sub_status
        .as_ref()
        .is_some_and(|s| s.value == constants::STATUS_AUTHN_FAILED);
    let message = status
        .status_message
        .as_deref()
        .is_some_and(|m| m.trim() == constants::STATUS_MESSAGE_CANCELLED);
    authn_failed || message
}

// ── Entry point ─────────────────────────────────────────────────────────────

/// Verify and process the back-channel answer to an `ArtifactResolve` (§7.6).
///
/// `body` is the raw SOAP 1.1 response body (a `<soap:Envelope>` carrying
/// exactly one `<samlp:ArtifactResponse>`), or a bare `<samlp:ArtifactResponse>`
/// document. `verifier` MUST hold only the RD signing keys from its verified
/// metadata, each named by its `<ds:KeyName>` (see
/// [`super::metadata::RdMetadata::keys_manager`]); `keys` are the DV's
/// decryption keys.
///
/// The chain is validated in this order, failing closed at the first violation:
///
/// 1. §9.1 / §9.3 algorithm allow-lists over the whole document.
/// 2. The RD signature enveloping the `ArtifactResponse`: single, first,
///    `KeyName`-selected (§9.2), cryptographically valid, bound to the
///    consumed element's `@ID`.
/// 3. §7.6.1: `Version`, `Issuer` = RD, `InResponseTo` = the ArtifactResolve,
///    fresh `IssueInstant`, `Status` = `Success`, exactly one `Response`.
/// 4. §7.6.2: `Version`, `Issuer` = RD, `Destination` = the DV ACS,
///    `InResponseTo` = the AuthnRequest, fresh `IssueInstant`, no
///    `EncryptedAssertion`; a Response signature, if present, is verified and
///    bound too. A non-success status with no assertion yields
///    [`AuthnOutcome::Cancelled`] / [`AuthnOutcome::Failed`].
/// 5. §7.6.3: exactly one `Assertion`; its RD signature is verified and bound
///    (required unless [`NlEidConfig::require_assertion_signature`] is off);
///    the shared [`AssertionValidator`] runs the Web Browser SSO checks
///    (bearer confirmation, Recipient, InResponseTo, NotOnOrAfter, no
///    NotBefore, Conditions window, AudienceRestriction, replay, AuthnStatement);
///    then the eID rules: TransientID Subject, mandatory `Conditions/@NotBefore`,
///    fresh `AuthnInstant`, Level of Assurance ≥ minimum (§7.6.3.2), exactly one
///    `AttributeStatement` with the registered `ServiceUUID`, and the
///    `ActingSubjectID` / `LegalSubjectID` `EncryptedID`s decrypted with the key
///    addressed to this DV (§7.6.3.4) into §7.6.3.4.4-shaped `NameID`s.
///
/// Claims are read only from the outer RD assertion, never from the
/// `<saml:Advice>` evidence (§9.1: nested signatures are evidence, not trust).
pub fn process_artifact_response(
    cfg: &NlEidConfig,
    body: &str,
    verifier: &SamlVerifier,
    keys: &DvDecryptionKeys,
    params: &ArtifactResponseParams<'_>,
) -> Result<AuthnOutcome, NlEidError> {
    cfg.validate()?;

    let art_xml = extract_artifact_response_xml(body)?;
    let doc = crate::xml::parse_secure(&art_xml)?;
    let root = doc
        .document_element()
        .ok_or_else(|| NlEidError::MalformedMessage("empty document".to_string()))?;
    if !xmlutil::is_element(&doc, root, constants::NS_SAML_PROTOCOL, "ArtifactResponse") {
        return Err(NlEidError::MalformedMessage(
            "back-channel body is not a samlp:ArtifactResponse".to_string(),
        ));
    }

    // 1. Algorithms, before any cryptography.
    xmlutil::validate_algorithms(&doc, root, Some(&cfg.entity_id))?;

    // 2. The enveloping RD signature, bound to the ArtifactResponse.
    let envelope_signature =
        xmlutil::verify_enveloping_signature(&doc, root, &art_xml, verifier, "ArtifactResponse")?;
    let mut signed_ids = envelope_signature.signed_ids.clone();

    // 3. ArtifactResponse envelope.
    let artifact_response = ArtifactResponseRef::from_xml(&doc, root)?.to_owned();
    check_artifact_response(cfg, &artifact_response, params)?;
    let response_nodes =
        xmlutil::element_children(&doc, root, constants::NS_SAML_PROTOCOL, "Response");
    if response_nodes.len() != 1 {
        return Err(NlEidError::ResponseCount(response_nodes.len()));
    }
    let response_node = response_nodes[0];

    // 4. Response envelope.
    let response = ResponseRef::from_xml(&doc, response_node)?.to_owned();
    check_response(cfg, &response, params)?;
    let response_signature_verified = if response.base.has_signature {
        let xml = xmlutil::self_contained_xml(&doc, response_node);
        let verified =
            xmlutil::verify_enveloping_signature(&doc, response_node, &xml, verifier, "Response")?;
        signed_ids.extend(verified.signed_ids);
        Some(true)
    } else {
        None
    };
    if !response.base.status.is_success() {
        if !response.assertions.is_empty() {
            return Err(NlEidError::AssertionCount {
                success: false,
                found: response.assertions.len(),
            });
        }
        let status = response.base.status.clone();
        return Ok(if is_cancellation_status(&status) {
            AuthnOutcome::Cancelled { status }
        } else {
            AuthnOutcome::Failed { status }
        });
    }

    // 5. The assertion.
    let assertion_nodes = xmlutil::element_children(
        &doc,
        response_node,
        constants::NS_SAML_ASSERTION,
        "Assertion",
    );
    if response.assertions.len() != 1 || assertion_nodes.len() != 1 {
        return Err(NlEidError::AssertionCount {
            success: true,
            found: response.assertions.len().max(assertion_nodes.len()),
        });
    }
    let assertion_node = assertion_nodes[0];
    let assertion = &response.assertions[0];
    if assertion.has_signature {
        let xml = xmlutil::self_contained_xml(&doc, assertion_node);
        let verified = xmlutil::verify_enveloping_signature(
            &doc,
            assertion_node,
            &xml,
            verifier,
            "Assertion",
        )?;
        signed_ids.extend(verified.signed_ids);
    } else if cfg.require_assertion_signature {
        return Err(NlEidError::MissingSignature("Assertion"));
    }

    run_shared_validator(
        cfg,
        &response,
        params,
        response_signature_verified,
        &signed_ids,
    )?;
    let (transient_name_id, level_of_assurance) = check_assertion(cfg, assertion, params)?;
    let attributes = extract_identity_attributes(cfg, &doc, assertion_node, keys)?;

    let authn_stmt = &assertion.authn_statements[0];
    let authn = AuthnResult {
        name_id: transient_name_id.clone(),
        name_id_format: Some(constants::NAMEID_TRANSIENT.to_string()),
        name_qualifier: None,
        sp_name_qualifier: None,
        session_index: authn_stmt.session_index.clone(),
        session_not_on_or_after: authn_stmt.session_not_on_or_after,
        authn_instant: authn_stmt.authn_instant,
        authn_context_class_ref: authn_stmt.authn_context.authn_context_class_ref.clone(),
        authn_context_decl_ref: authn_stmt.authn_context.authn_context_decl_ref.clone(),
        authenticating_authorities: authn_stmt.authn_context.authenticating_authorities.clone(),
        attributes: web_browser::extract_attributes(&assertion.attribute_statements),
        idp_entity_id: assertion.issuer.value.clone(),
        assertion_id: assertion.id.clone(),
        response_id: response.base.id.clone(),
    };

    Ok(AuthnOutcome::Authenticated(Box::new(NlEidAuthnResult {
        authenticating_authorities: authn.authenticating_authorities.clone(),
        authn,
        transient_name_id,
        level_of_assurance,
        service_uuid: attributes.service_uuid,
        acting_subject: attributes.acting_subject,
        legal_subject: attributes.legal_subject,
        rd_signing_key_name: envelope_signature.key_name,
    })))
}

// ── Steps ───────────────────────────────────────────────────────────────────

/// The `<samlp:ArtifactResponse>` of a SOAP body as a standalone document
/// (§7.6: one SOAP 1.1 `Envelope`, one `Body`, one SAML element), or `body`
/// itself when it already is a bare SAML document.
fn extract_artifact_response_xml(body: &str) -> Result<String, NlEidError> {
    let doc = crate::xml::parse_secure(body).map_err(|e| {
        NlEidError::MalformedMessage(format!("back-channel body is not well-formed XML: {e}"))
    })?;
    let root = doc
        .document_element()
        .ok_or_else(|| NlEidError::MalformedMessage("empty document".to_string()))?;
    if !xmlutil::is_element(&doc, root, constants::NS_SOAP11, "Envelope") {
        return Ok(body.to_string());
    }
    let bodies = xmlutil::element_children(&doc, root, constants::NS_SOAP11, "Body");
    let [soap_body] = bodies[..] else {
        return Err(NlEidError::MalformedMessage(format!(
            "SOAP envelope carries {} Body elements",
            bodies.len()
        )));
    };
    let children: Vec<NodeId> = doc
        .children_iter(soap_body)
        .filter(|c| doc.element(*c).is_some())
        .collect();
    let [saml] = children[..] else {
        return Err(NlEidError::MalformedMessage(format!(
            "SOAP Body carries {} element children (exactly one SAML element expected)",
            children.len()
        )));
    };
    if xmlutil::is_element(&doc, saml, constants::NS_SOAP11, "Fault") {
        let detail = doc.text_content_deep(saml);
        return Err(NlEidError::MalformedMessage(format!(
            "SOAP Fault: {}",
            detail.split_whitespace().collect::<Vec<_>>().join(" ")
        )));
    }
    Ok(xmlutil::self_contained_xml(&doc, saml))
}

fn check_issuer(
    issuer: Option<&str>,
    expected: &str,
    element: &'static str,
) -> Result<(), NlEidError> {
    let received = issuer
        .map(str::trim)
        .ok_or(NlEidError::MissingIssuer(element))?;
    if received != expected {
        return Err(NlEidError::IssuerMismatch {
            element,
            received: received.to_string(),
            expected: expected.to_string(),
        });
    }
    Ok(())
}

fn check_in_response_to(
    received: Option<&str>,
    expected: &str,
    element: &'static str,
) -> Result<(), NlEidError> {
    if received != Some(expected) {
        return Err(NlEidError::InResponseToMismatch {
            element,
            received: received.map(str::to_string),
            expected: expected.to_string(),
        });
    }
    Ok(())
}

/// §7.6.1.
fn check_artifact_response(
    cfg: &NlEidConfig,
    art: &ArtifactResponse,
    params: &ArtifactResponseParams<'_>,
) -> Result<(), NlEidError> {
    if !art.version.is_v2_0() {
        return Err(NlEidError::MalformedMessage(
            "ArtifactResponse Version is not 2.0".to_string(),
        ));
    }
    check_issuer(
        art.issuer.as_ref().map(|i| i.value.as_str()),
        &cfg.rd_entity_id,
        "ArtifactResponse",
    )?;
    check_in_response_to(
        art.in_response_to.as_deref(),
        params.expected_artifact_resolve_id,
        "ArtifactResponse",
    )?;
    xmlutil::check_freshness(
        art.issue_instant,
        params.now,
        cfg.effective_clock_skew(),
        cfg.message_freshness_seconds,
        "ArtifactResponse @IssueInstant",
    )?;
    if !art.status.is_success() {
        return Err(NlEidError::ArtifactResolutionFailed(art.status.clone()));
    }
    Ok(())
}

/// §7.6.2 (everything except the status, which decides the outcome).
fn check_response(
    cfg: &NlEidConfig,
    response: &Response,
    params: &ArtifactResponseParams<'_>,
) -> Result<(), NlEidError> {
    if !response.base.version.is_v2_0() {
        return Err(NlEidError::MalformedMessage(
            "Response Version is not 2.0".to_string(),
        ));
    }
    check_issuer(
        response.base.issuer.as_ref().map(|i| i.value.as_str()),
        &cfg.rd_entity_id,
        "Response",
    )?;
    if response.base.destination.as_deref() != Some(cfg.acs_url.as_str()) {
        return Err(NlEidError::DestinationMismatch {
            received: response.base.destination.clone(),
            expected: cfg.acs_url.clone(),
        });
    }
    check_in_response_to(
        response.base.in_response_to.as_deref(),
        params.expected_authn_request_id,
        "Response",
    )?;
    xmlutil::check_freshness(
        response.base.issue_instant,
        params.now,
        cfg.effective_clock_skew(),
        cfg.message_freshness_seconds,
        "Response @IssueInstant",
    )?;
    if !response.encrypted_assertions.is_empty() {
        return Err(NlEidError::EncryptedAssertionForbidden);
    }
    Ok(())
}

/// The shared Web Browser SSO checklist, with the signature facts established
/// above threaded in.
fn run_shared_validator(
    cfg: &NlEidConfig,
    response: &Response,
    params: &ArtifactResponseParams<'_>,
    response_signature_verified: Option<bool>,
    signed_ids: &[String],
) -> Result<(), NlEidError> {
    let security = cfg.security_config();
    let validator = AssertionValidator::new(&security).with_replay_cache(params.replay_cache);
    let ids: Vec<&str> = signed_ids.iter().map(String::as_str).collect();
    let validation = validator.validate_response(
        response,
        &ValidationParams {
            received_url: &cfg.acs_url,
            expected_idp_entity_id: &cfg.rd_entity_id,
            sp_entity_id: &cfg.entity_id,
            acs_url: &cfg.acs_url,
            expected_request_id: Some(params.expected_authn_request_id),
            client_address: None,
            relay_state: params.relay_state,
            response_signature_xml: None,
            response_signature_verified,
            verified_signed_ids: &ids,
            current_proxy_depth: 0,
            now: params.now,
        },
    );
    if validation.is_valid() {
        return Ok(());
    }
    let errors: Vec<String> = validation
        .failures()
        .iter()
        .map(|c| {
            format!(
                "{}: {}",
                c.check_name,
                c.detail.as_deref().unwrap_or("failed")
            )
        })
        .collect();
    Err(NlEidError::Profile(ProfileError::AssertionValidation(
        errors.join("; "),
    )))
}

/// The eID-specific assertion rules (§7.6.3) on the typed assertion. Returns
/// the TransientID and the delivered Level of Assurance.
fn check_assertion(
    cfg: &NlEidConfig,
    assertion: &Assertion,
    params: &ArtifactResponseParams<'_>,
) -> Result<(String, LevelOfAssurance), NlEidError> {
    if assertion.authn_statements.len() != 1 {
        return Err(NlEidError::AuthnStatementCount(
            assertion.authn_statements.len(),
        ));
    }
    if assertion.attribute_statements.len() != 1 {
        return Err(NlEidError::AttributeStatementCount(
            assertion.attribute_statements.len(),
        ));
    }

    // §7.6.3: the Subject NameID is a TransientID. The Format MAY be omitted
    // (SAML core defaults it to "unspecified" and the TVS pre-production RD
    // does omit it); a present Format MUST be transient.
    let subject = assertion
        .subject
        .as_ref()
        .ok_or(NlEidError::MissingRequired("Subject"))?;
    let transient_name_id = match &subject.name_id {
        Some(NameIdOrEncryptedId::NameId(nid)) => {
            if let Some(format) = nid.format.as_deref() {
                if format != constants::NAMEID_TRANSIENT {
                    return Err(NlEidError::InvalidSubjectNameId(format!(
                        "Format {format:?} is not the transient format"
                    )));
                }
            }
            let value = nid.value.trim();
            if value.is_empty() {
                return Err(NlEidError::InvalidSubjectNameId(
                    "NameID value is empty".to_string(),
                ));
            }
            value.to_string()
        }
        Some(NameIdOrEncryptedId::EncryptedId(_)) => {
            return Err(NlEidError::InvalidSubjectNameId(
                "Subject carries an EncryptedID; the TransientID is in cleartext".to_string(),
            ))
        }
        None => return Err(NlEidError::MissingRequired("Subject/NameID")),
    };

    // §7.6.3: Conditions with both NotBefore and NotOnOrAfter are mandatory
    // (the shared validator requires NotOnOrAfter and the audience).
    let conditions = assertion
        .conditions
        .as_ref()
        .ok_or(NlEidError::MissingRequired("Conditions"))?;
    if conditions.not_before.is_none() {
        return Err(NlEidError::MissingRequired("Conditions/@NotBefore"));
    }
    if conditions.not_on_or_after.is_none() {
        return Err(NlEidError::MissingRequired("Conditions/@NotOnOrAfter"));
    }

    let authn_stmt = &assertion.authn_statements[0];
    xmlutil::check_freshness(
        authn_stmt.authn_instant,
        params.now,
        cfg.effective_clock_skew(),
        cfg.message_freshness_seconds,
        "AuthnStatement @AuthnInstant",
    )?;
    let level = validate_level_of_assurance(
        authn_stmt.authn_context.authn_context_class_ref.as_deref(),
        cfg.minimum_loa,
    )?;

    Ok((transient_name_id, level))
}

struct IdentityAttributes {
    service_uuid: String,
    acting_subject: SubjectId,
    legal_subject: Option<SubjectId>,
}

/// §7.6.3.4: read the `AttributeStatement` of the outer assertion from the
/// parsed tree (so the `EncryptedID` elements can be re-serialized intact),
/// bind the `ServiceUUID`, and decrypt the identifier attributes.
fn extract_identity_attributes(
    cfg: &NlEidConfig,
    doc: &Document<'_>,
    assertion_node: NodeId,
    keys: &DvDecryptionKeys,
) -> Result<IdentityAttributes, NlEidError> {
    let statements = xmlutil::element_children(
        doc,
        assertion_node,
        constants::NS_SAML_ASSERTION,
        "AttributeStatement",
    );
    let [statement] = statements[..] else {
        return Err(NlEidError::AttributeStatementCount(statements.len()));
    };
    let attributes =
        xmlutil::element_children(doc, statement, constants::NS_SAML_ASSERTION, "Attribute");
    let find = |name: &str| -> Vec<NodeId> {
        attributes
            .iter()
            .copied()
            .filter(|a| doc.get_attribute(*a, "Name") == Some(name))
            .collect()
    };

    let service_uuid = find(constants::ATTR_SERVICE_UUID)
        .first()
        .and_then(|a| {
            xmlutil::element_child(doc, *a, constants::NS_SAML_ASSERTION, "AttributeValue")
        })
        .and_then(|v| xmlutil::text_only(doc, v))
        .filter(|s| !s.is_empty());
    match service_uuid.as_deref() {
        Some(u) if u == cfg.service_uuid => {}
        received => {
            return Err(NlEidError::ServiceUuidMismatch {
                received: received.map(str::to_string),
                expected: cfg.service_uuid.clone(),
            })
        }
    }

    let acting_nodes = find(constants::ATTR_ACTING_SUBJECT_ID);
    let acting_subject = match acting_nodes[..] {
        [] => return Err(NlEidError::MissingActingSubjectId),
        [node] => decrypt_subject_attribute(cfg, doc, node, "ActingSubjectID", keys)?,
        _ => return Err(NlEidError::TooManySubjectIds("ActingSubjectID")),
    };
    let legal_nodes = find(constants::ATTR_LEGAL_SUBJECT_ID);
    let legal_subject = match legal_nodes[..] {
        [] => None,
        [node] => Some(decrypt_subject_attribute(
            cfg,
            doc,
            node,
            "LegalSubjectID",
            keys,
        )?),
        _ => return Err(NlEidError::TooManySubjectIds("LegalSubjectID")),
    };

    Ok(IdentityAttributes {
        service_uuid: cfg.service_uuid.clone(),
        acting_subject,
        legal_subject,
    })
}

/// All `<xenc:EncryptedKey>` elements below `node`.
fn encrypted_keys(doc: &Document<'_>, node: NodeId) -> Vec<NodeId> {
    xmlutil::descendant_elements(doc, node)
        .into_iter()
        .filter(|n| xmlutil::is_element(doc, *n, constants::NS_XENC, "EncryptedKey"))
        .collect()
}

/// Decrypt the one `<saml:EncryptedID>` of `attribute_node` that is addressed
/// to this DV (§7.6.3.4 `@Recipient`) into a §7.6.3.4.4 `NameID`.
fn decrypt_subject_attribute(
    cfg: &NlEidConfig,
    doc: &Document<'_>,
    attribute_node: NodeId,
    attribute: &'static str,
    keys: &DvDecryptionKeys,
) -> Result<SubjectId, NlEidError> {
    let encrypted_ids: Vec<NodeId> = xmlutil::element_children(
        doc,
        attribute_node,
        constants::NS_SAML_ASSERTION,
        "AttributeValue",
    )
    .into_iter()
    .filter_map(|v| xmlutil::element_child(doc, v, constants::NS_SAML_ASSERTION, "EncryptedID"))
    .collect();
    if encrypted_ids.is_empty() {
        return Err(NlEidError::MalformedMessage(format!(
            "{attribute} carries no EncryptedID"
        )));
    }

    // Select the EncryptedID(s) wrapped for us; the others SHOULD be ignored.
    let mut recipients: Vec<String> = Vec::new();
    let mut ours: Vec<NodeId> = Vec::new();
    for enc_id in &encrypted_ids {
        let mut addressed_to_us = false;
        for key in encrypted_keys(doc, *enc_id) {
            let recipient = doc.get_attribute(key, "Recipient");
            recipients.push(recipient.unwrap_or("<absent>").to_string());
            if recipient == Some(cfg.entity_id.as_str()) {
                addressed_to_us = true;
            }
        }
        if addressed_to_us {
            ours.push(*enc_id);
        }
    }
    let enc_id = match ours[..] {
        [] => {
            return Err(NlEidError::NoEncryptedKeyForRecipient {
                attribute,
                recipients,
            })
        }
        [one] => one,
        _ => return Err(NlEidError::TooManySubjectIds(attribute)),
    };

    let pruned = pruned_encrypted_id_xml(doc, enc_id, &cfg.entity_id)?;
    let plaintext = keys
        .decrypt(&pruned)
        .map_err(|reason| NlEidError::Decryption { attribute, reason })?;
    decrypted_name_id(&plaintext, attribute)
}

/// The `EncryptedID` as a standalone document with every `<xenc:EncryptedKey>`
/// not addressed to `recipient` removed, together with any
/// `<ds:RetrievalMethod>` pointing at a removed key. Decryption then can only
/// use our own wrapped key (§7.6.3.4: keys for other recipients are ignored).
fn pruned_encrypted_id_xml(
    doc: &Document<'_>,
    enc_id: NodeId,
    recipient: &str,
) -> Result<String, NlEidError> {
    let xml = xmlutil::self_contained_xml(doc, enc_id);
    let standalone = crate::xml::parse_secure(&xml)?;
    let root = standalone
        .document_element()
        .ok_or_else(|| NlEidError::MalformedMessage("EncryptedID is empty".to_string()))?;

    let mut removed_ids: Vec<String> = Vec::new();
    let mut cuts: Vec<std::ops::Range<usize>> = Vec::new();
    for key in encrypted_keys(&standalone, root) {
        if standalone.get_attribute(key, "Recipient") == Some(recipient) {
            continue;
        }
        if let Some(id) = standalone.get_attribute(key, "Id") {
            removed_ids.push(id.to_string());
        }
        if let Some(range) = standalone.node_range(key) {
            cuts.push(range);
        }
    }
    for rm in xmlutil::descendant_elements(&standalone, root)
        .into_iter()
        .filter(|n| xmlutil::is_element(&standalone, *n, constants::NS_DS, "RetrievalMethod"))
    {
        let target = standalone
            .get_attribute(rm, "URI")
            .and_then(|u| u.strip_prefix('#'));
        if target.is_some_and(|t| removed_ids.iter().any(|r| r == t)) {
            if let Some(range) = standalone.node_range(rm) {
                cuts.push(range);
            }
        }
    }
    cuts.sort_by_key(|cut| std::cmp::Reverse(cut.start));
    let mut out = xml.clone();
    let mut last_start = usize::MAX;
    for cut in cuts {
        if cut.end > last_start {
            continue; // nested inside an already removed range
        }
        out.replace_range(cut.clone(), "");
        last_start = cut.start;
    }
    Ok(out)
}

/// §7.6.3.4.4: the decrypted plaintext MUST be a `<saml:NameID>` with the
/// persistent format, a §10.1 `@NameQualifier`, no `SPNameQualifier` /
/// `SPProvidedID`, and a non-empty value.
fn decrypted_name_id(plaintext: &str, attribute: &'static str) -> Result<SubjectId, NlEidError> {
    let invalid = |reason: &str| NlEidError::InvalidDecryptedNameId {
        attribute,
        reason: reason.to_string(),
    };
    let doc = crate::xml::parse_secure(plaintext)
        .map_err(|_| invalid("plaintext is not well-formed XML"))?;
    let root = doc
        .document_element()
        .ok_or_else(|| invalid("plaintext is empty"))?;
    let name_id_node = if xmlutil::is_element(&doc, root, constants::NS_SAML_ASSERTION, "NameID") {
        root
    } else {
        xmlutil::descendant_elements(&doc, root)
            .into_iter()
            .find(|n| xmlutil::is_element(&doc, *n, constants::NS_SAML_ASSERTION, "NameID"))
            .ok_or_else(|| invalid("plaintext does not contain a saml:NameID"))?
    };
    let name_id = NameIdRef::from_xml(&doc, name_id_node)
        .map_err(|e| invalid(&format!("cannot read NameID: {e}")))?;

    if name_id.format != Some(constants::NAMEID_PERSISTENT) {
        return Err(invalid(&format!(
            "Format must be {}, got {:?}",
            constants::NAMEID_PERSISTENT,
            name_id.format
        )));
    }
    let qualifier = name_id
        .name_qualifier
        .map(str::trim)
        .filter(|q| !q.is_empty())
        .ok_or_else(|| invalid("NameQualifier (the identifier type) is missing"))?;
    let identifier_type = IdentifierType::from_uri(qualifier).ok_or_else(|| {
        invalid(&format!(
            "NameQualifier {qualifier:?} is not a §10.1 identifier type"
        ))
    })?;
    if name_id.sp_name_qualifier.is_some() {
        return Err(invalid("SPNameQualifier must not be used"));
    }
    if name_id.sp_provided_id.is_some() {
        return Err(invalid("SPProvidedID must not be used"));
    }
    let value = name_id.value.trim();
    if value.is_empty() {
        return Err(invalid("value is empty"));
    }
    Ok(SubjectId {
        value: Zeroizing::new(value.to_string()),
        identifier_type,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const DV: &str = "urn:nl-eid-gdi:1.0:DV:00000001234567890000:entities:9001";

    #[test]
    fn test_subject_id_debug_is_redacted() {
        let id = SubjectId {
            value: Zeroizing::new("900070341".to_string()),
            identifier_type: IdentifierType::LegacyBsn,
        };
        let dbg = format!("{id:?}");
        assert!(!dbg.contains("900070341"), "{dbg}");
        assert!(dbg.contains("LegacyBsn"));
        assert_eq!(id.expose_value(), "900070341");
    }

    #[test]
    fn test_identifier_type_round_trip() {
        for t in [
            IdentifierType::LegacyBsn,
            IdentifierType::Bsn,
            IdentifierType::Pseudonym,
        ] {
            assert_eq!(IdentifierType::from_uri(t.as_uri()), Some(t));
        }
        assert!(IdentifierType::from_uri("urn:nl-eid-gdi:1.0:id:Other").is_none());
    }

    #[test]
    fn test_cancellation_status() {
        let cancelled = Status::with_sub_status(
            constants::STATUS_RESPONDER,
            constants::STATUS_AUTHN_FAILED,
            Some(constants::STATUS_MESSAGE_CANCELLED.to_string()),
        );
        assert!(is_cancellation_status(&cancelled));
        let denied = Status::with_sub_status(
            constants::STATUS_REQUESTER,
            constants::STATUS_REQUEST_DENIED,
            None,
        );
        assert!(!is_cancellation_status(&denied));
        let responder_other = Status::with_sub_status(
            constants::STATUS_RESPONDER,
            constants::STATUS_REQUEST_UNSUPPORTED,
            Some("Level of assurance not supported".to_string()),
        );
        assert!(!is_cancellation_status(&responder_other));
    }

    #[test]
    fn test_decrypted_name_id_shape() {
        let ok = format!(
            r#"<saml:NameID xmlns:saml="{}" Format="{}" NameQualifier="{}"> 900070341 </saml:NameID>"#,
            constants::NS_SAML_ASSERTION,
            constants::NAMEID_PERSISTENT,
            constants::ID_TYPE_LEGACY_BSN
        );
        let id = decrypted_name_id(&ok, "ActingSubjectID").unwrap();
        assert_eq!(id.expose_value(), "900070341");
        assert_eq!(id.identifier_type(), IdentifierType::LegacyBsn);

        // Wrapped in an EncryptedID (the backend replaces EncryptedData in place).
        let wrapped = format!(
            r#"<saml:EncryptedID xmlns:saml="{}">{ok}</saml:EncryptedID>"#,
            constants::NS_SAML_ASSERTION
        );
        assert!(decrypted_name_id(&wrapped, "ActingSubjectID").is_ok());

        let bad_cases = [
            ok.replace(constants::NAMEID_PERSISTENT, constants::NAMEID_TRANSIENT),
            ok.replace(
                &format!(r#" NameQualifier="{}""#, constants::ID_TYPE_LEGACY_BSN),
                "",
            ),
            ok.replace(constants::ID_TYPE_LEGACY_BSN, "urn:nl-eid-gdi:1.0:id:Other"),
            ok.replace("Format=", r#"SPNameQualifier="x" Format="#),
            ok.replace("Format=", r#"SPProvidedID="x" Format="#),
            ok.replace(" 900070341 ", "  "),
            format!(
                r#"<NameID xmlns="urn:attacker" Format="{}" NameQualifier="{}">1</NameID>"#,
                constants::NAMEID_PERSISTENT,
                constants::ID_TYPE_LEGACY_BSN
            ),
            "not xml".to_string(),
        ];
        for bad in bad_cases {
            assert!(
                matches!(
                    decrypted_name_id(&bad, "ActingSubjectID"),
                    Err(NlEidError::InvalidDecryptedNameId { .. })
                ),
                "{bad}"
            );
        }
    }

    #[test]
    fn test_pruned_encrypted_id_removes_foreign_keys() {
        let xenc = constants::NS_XENC;
        let ds = constants::NS_DS;
        let saml = constants::NS_SAML_ASSERTION;
        let xml = format!(
            r##"<saml:EncryptedID xmlns:saml="{saml}"><xenc:EncryptedData xmlns:xenc="{xenc}" Id="d1"><xenc:EncryptionMethod Algorithm="{}"/><ds:KeyInfo xmlns:ds="{ds}"><ds:RetrievalMethod Type="http://www.w3.org/2001/04/xmlenc#EncryptedKey" URI="#k-other"/><ds:RetrievalMethod Type="http://www.w3.org/2001/04/xmlenc#EncryptedKey" URI="#k-ours"/></ds:KeyInfo><xenc:CipherData><xenc:CipherValue>AA==</xenc:CipherValue></xenc:CipherData></xenc:EncryptedData><xenc:EncryptedKey xmlns:xenc="{xenc}" Id="k-other" Recipient="urn:other"><xenc:CipherData><xenc:CipherValue>BB==</xenc:CipherValue></xenc:CipherData></xenc:EncryptedKey><xenc:EncryptedKey xmlns:xenc="{xenc}" Id="k-ours" Recipient="{DV}"><xenc:CipherData><xenc:CipherValue>CC==</xenc:CipherValue></xenc:CipherData></xenc:EncryptedKey></saml:EncryptedID>"##,
            constants::ENC_AES256_CBC
        );
        let doc = crate::xml::parse_secure(&xml).unwrap();
        let root = doc.document_element().unwrap();
        let pruned = pruned_encrypted_id_xml(&doc, root, DV).unwrap();
        assert!(!pruned.contains("k-other"), "{pruned}");
        assert!(!pruned.contains("urn:other"), "{pruned}");
        assert!(pruned.contains("k-ours"), "{pruned}");
        assert!(pruned.contains("CC=="), "{pruned}");
        // Still well-formed with exactly one EncryptedKey.
        let p = crate::xml::parse_secure(&pruned).unwrap();
        let r = p.document_element().unwrap();
        assert_eq!(encrypted_keys(&p, r).len(), 1);
    }

    #[test]
    fn test_extract_artifact_response_xml_from_soap() {
        let samlp = constants::NS_SAML_PROTOCOL;
        let soap = constants::NS_SOAP11;
        let env = format!(
            r#"<soapenv:Envelope xmlns:soapenv="{soap}" xmlns:samlp="{samlp}"><soapenv:Body><samlp:ArtifactResponse ID="_a" Version="2.0" IssueInstant="2024-01-01T00:00:00Z"><samlp:Status><samlp:StatusCode Value="{}"/></samlp:Status></samlp:ArtifactResponse></soapenv:Body></soapenv:Envelope>"#,
            constants::STATUS_SUCCESS
        );
        let xml = extract_artifact_response_xml(&env).unwrap();
        assert!(xml.starts_with("<samlp:ArtifactResponse"));
        let doc = crate::xml::parse_secure(&xml).unwrap();
        assert!(xmlutil::is_element(
            &doc,
            doc.document_element().unwrap(),
            samlp,
            "ArtifactResponse"
        ));

        // Bare documents pass through; non-XML and multi-child bodies fail.
        assert_eq!(extract_artifact_response_xml(&xml).unwrap(), xml);
        assert!(extract_artifact_response_xml("502 Bad Gateway").is_err());
        let two = format!(
            r#"<soapenv:Envelope xmlns:soapenv="{soap}" xmlns:samlp="{samlp}"><soapenv:Body><samlp:ArtifactResponse ID="_a"/><samlp:ArtifactResponse ID="_b"/></soapenv:Body></soapenv:Envelope>"#
        );
        assert!(matches!(
            extract_artifact_response_xml(&two),
            Err(NlEidError::MalformedMessage(_))
        ));
        let fault = format!(
            r#"<soapenv:Envelope xmlns:soapenv="{soap}"><soapenv:Body><soapenv:Fault><faultcode>soapenv:Server</faultcode><faultstring>boom</faultstring></soapenv:Fault></soapenv:Body></soapenv:Envelope>"#
        );
        let err = extract_artifact_response_xml(&fault).unwrap_err();
        assert!(err.to_string().contains("SOAP Fault"), "{err}");
    }
}
