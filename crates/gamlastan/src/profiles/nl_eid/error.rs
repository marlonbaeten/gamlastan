// Errors specific to the Dutch eID SAML interface profile.

use crate::core::protocol::status::Status;
use crate::profiles::error::ProfileError;

use super::constants;

/// Errors raised by eID SAML profile processing.
///
/// Every variant is a protocol violation, a trust failure, or a configuration
/// error. A *well-formed* failed authentication (user cancelled, RD/AD error
/// status) is **not** an error: it is reported as a
/// [`super::response::AuthnOutcome`] variant so the embedding application can
/// show the right page (§7.8.3 / §9.9).
#[derive(Debug)]
pub enum NlEidError {
    /// The clock skew configured exceeds [`constants::MAX_CLOCK_SKEW_SECONDS`].
    ClockSkewTooLarge(u64),

    /// A configuration value is missing or inconsistent (e.g. an empty
    /// `entityID`, or an SLO URL required for logout that was not configured).
    Config(String),

    /// The AuthnRequest options violate §7.3 (e.g. both an ACS URL and an ACS
    /// index, or both `AttributeConsumingServiceIndex` and `Extensions`).
    InvalidRequestOptions(String),

    /// The back-channel body was not a SOAP 1.1 envelope carrying exactly one
    /// `<samlp:ArtifactResponse>`, or was not SAML XML at all.
    MalformedMessage(String),

    /// A message uses an algorithm outside the §9.1 / §9.3 allow-lists.
    DisallowedAlgorithm {
        /// The algorithm usage being checked ("signature", "digest",
        /// "canonicalization", "transform", "block encryption", "key transport").
        kind: &'static str,
        /// The offending algorithm URI.
        uri: String,
    },

    /// The element the DV consumes carries no enveloped `<ds:Signature>` where
    /// §7.6.1 / §7.6.3 / §7.7.2 require one.
    MissingSignature(&'static str),

    /// The enveloped signature is not the first `<ds:Signature>` of the signed
    /// element, or the element carries more than one direct `<ds:Signature>`
    /// child. Both are XML Signature Wrapping shapes.
    AmbiguousSignature(&'static str),

    /// The signature's `<ds:KeyInfo>` does not name a key from the RD's verified
    /// metadata with a `<ds:KeyName>` (§9.2).
    UnknownSigningKey(String),

    /// Cryptographic signature verification failed.
    InvalidSignature {
        /// Which element's signature failed.
        element: &'static str,
        /// The verifier's reason.
        reason: String,
    },

    /// A valid signature was found but none of its verified XML-DSig references
    /// covered the consumed element (XML Signature Wrapping defence, ADR 0028).
    SignatureNotBoundToElement(&'static str),

    /// The `<saml:Issuer>` of a message did not identify the configured RD.
    IssuerMismatch {
        /// Which element carried the issuer.
        element: &'static str,
        /// The issuer value received.
        received: String,
        /// The RD `entityID` expected.
        expected: String,
    },

    /// A message is missing its mandatory `<saml:Issuer>`.
    MissingIssuer(&'static str),

    /// `@InResponseTo` is absent or does not match the request it must answer
    /// (§7.6.1, §7.6.2, §7.6.3.3, §7.7.2).
    InResponseToMismatch {
        /// Which element carried (or lacked) the attribute.
        element: &'static str,
        /// The received value, if any.
        received: Option<String>,
        /// The request ID expected.
        expected: String,
    },

    /// The `@Destination` of the Response / LogoutResponse is not the DV endpoint
    /// it was delivered to (§7.6.2, §7.7.2).
    DestinationMismatch {
        /// The received value, if any.
        received: Option<String>,
        /// The DV endpoint expected.
        expected: String,
    },

    /// An `@IssueInstant` / `@AuthnInstant` is older than the configured
    /// freshness window or lies in the future beyond the clock skew.
    StaleMessage {
        /// Which instant failed.
        element: &'static str,
        /// A human-readable detail.
        detail: String,
    },

    /// The ArtifactResponse status was not `Success` (§7.6.1): the artifact
    /// could not be resolved (unknown, expired, already used, or denied).
    ArtifactResolutionFailed(Status),

    /// The ArtifactResponse reported `Success` but carried no `<samlp:Response>`
    /// (§7.6.1 / SAML-bindings §3.6.6: the artifact was already spent or the
    /// requester is not authorized), or carried more than one.
    ResponseCount(usize),

    /// A `<samlp:Response>` carried an `<saml:EncryptedAssertion>`, which §7.6.2
    /// forbids.
    EncryptedAssertionForbidden,

    /// A successful Response did not carry exactly one `<saml:Assertion>`, or a
    /// failed Response carried one (§7.6.2).
    AssertionCount {
        /// Whether the Response status was `Success`.
        success: bool,
        /// The number of assertions found.
        found: usize,
    },

    /// An element the specification gives cardinality 1 is absent.
    MissingRequired(&'static str),

    /// The assertion did not carry exactly one `<saml:AuthnStatement>`.
    AuthnStatementCount(usize),

    /// A successful assertion did not carry exactly one
    /// `<saml:AttributeStatement>` (§7.6.3).
    AttributeStatementCount(usize),

    /// The Subject `<saml:NameID>` is missing, empty, or not a TransientID
    /// (§7.6.3).
    InvalidSubjectNameId(String),

    /// The assertion carried no `<saml:AuthnContextClassRef>` (§7.6.3).
    MissingAuthnContextClassRef,

    /// The `<saml:AuthnContextClassRef>` is not a §10.3 Level of Assurance URI.
    UnknownLevelOfAssurance(String),

    /// The delivered Level of Assurance is below the DV minimum (§7.6.3.2).
    LevelOfAssuranceTooLow {
        /// The URI delivered by the RD.
        received: String,
        /// The minimum the DV is registered for.
        minimum: &'static str,
    },

    /// The `ServiceUUID` attribute is missing or does not match the DV's
    /// registered service (§7.6.3.4).
    ServiceUuidMismatch {
        /// The received value, if any.
        received: Option<String>,
        /// The configured ServiceUUID.
        expected: String,
    },

    /// The mandatory `ActingSubjectID` attribute is missing (§7.6.3.4).
    MissingActingSubjectId,

    /// An eID identifier attribute carried more `<saml:AttributeValue>`
    /// elements with an `EncryptedID` than the profile supports.
    TooManySubjectIds(&'static str),

    /// An `<saml:EncryptedID>` carried no `<xenc:EncryptedKey>` addressed to this
    /// DV in its `@Recipient` (§7.6.3.4).
    NoEncryptedKeyForRecipient {
        /// The attribute the EncryptedID belongs to.
        attribute: &'static str,
        /// The recipients that were present.
        recipients: Vec<String>,
    },

    /// Decryption of an `<saml:EncryptedID>` failed with every configured key.
    Decryption {
        /// The attribute the EncryptedID belongs to.
        attribute: &'static str,
        /// The last decryption error.
        reason: String,
    },

    /// A decrypted `<saml:EncryptedID>` did not contain a `<saml:NameID>` with
    /// the §7.6.3.4.4 shape (persistent format, a §10.1 `@NameQualifier`, no
    /// `SPNameQualifier` / `SPProvidedID`, non-empty value).
    InvalidDecryptedNameId {
        /// The attribute the EncryptedID belongs to.
        attribute: &'static str,
        /// What was wrong.
        reason: String,
    },

    /// The ArtifactResponse `@InResponseTo` / Response `@InResponseTo` and the
    /// assertion's bearer `@InResponseTo` disagree: an assertion spliced into a
    /// Response for another flow.
    InResponseToDisagreement {
        /// The Response-level value.
        response: String,
        /// The assertion-level value.
        assertion: String,
    },

    /// The RD metadata lacks a mandatory element (§8.5), or declares an
    /// endpoint with a binding the specification does not allow.
    Metadata(String),

    /// An error from the underlying Web Browser SSO / assertion validation.
    Profile(ProfileError),

    /// A cryptographic error (verification, decryption).
    Crypto(crate::crypto::CryptoError),

    /// An XML parsing/serialization error.
    Xml(crate::xml::XmlError),
}

impl NlEidError {
    /// Map this error to the SAML `<samlp:Status>` a participant should return
    /// per §7.8.5 / §7.8.6: structural and trust failures are non-recoverable
    /// (`Requester` / `RequestUnsupported`); an unsatisfiable Level of
    /// Assurance maps to `Responder` / `NoAuthnContext`.
    pub fn to_status(&self) -> Status {
        match self {
            NlEidError::LevelOfAssuranceTooLow { .. }
            | NlEidError::UnknownLevelOfAssurance(_)
            | NlEidError::MissingAuthnContextClassRef => Status::with_sub_status(
                constants::STATUS_RESPONDER,
                constants::STATUS_NO_AUTHN_CONTEXT,
                Some(self.to_string()),
            ),
            NlEidError::ArtifactResolutionFailed(status) => status.clone(),
            _ => Status::with_sub_status(
                constants::STATUS_REQUESTER,
                constants::STATUS_REQUEST_UNSUPPORTED,
                Some(self.to_string()),
            ),
        }
    }
}

impl std::fmt::Display for NlEidError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NlEidError::ClockSkewTooLarge(s) => write!(
                f,
                "clock skew {s}s exceeds the profile maximum of {}s",
                constants::MAX_CLOCK_SKEW_SECONDS
            ),
            NlEidError::Config(m) => write!(f, "configuration error: {m}"),
            NlEidError::InvalidRequestOptions(m) => write!(f, "invalid AuthnRequest options: {m}"),
            NlEidError::MalformedMessage(m) => write!(f, "malformed message: {m}"),
            NlEidError::DisallowedAlgorithm { kind, uri } => {
                write!(f, "message uses disallowed {kind} algorithm {uri:?}")
            }
            NlEidError::MissingSignature(e) => write!(f, "{e} carries no enveloped Signature"),
            NlEidError::AmbiguousSignature(e) => write!(
                f,
                "{e} signature is not the single, first Signature of the signed element \
                 (possible XML Signature Wrapping)"
            ),
            NlEidError::UnknownSigningKey(m) => {
                write!(f, "signature KeyInfo does not name a trusted RD key: {m}")
            }
            NlEidError::InvalidSignature { element, reason } => {
                write!(f, "{element} signature verification failed: {reason}")
            }
            NlEidError::SignatureNotBoundToElement(e) => write!(
                f,
                "verified signature does not reference the consumed {e} (XML Signature Wrapping)"
            ),
            NlEidError::IssuerMismatch {
                element,
                received,
                expected,
            } => write!(
                f,
                "{element} Issuer {received:?} does not match the RD {expected:?}"
            ),
            NlEidError::MissingIssuer(e) => write!(f, "{e} is missing its Issuer"),
            NlEidError::InResponseToMismatch {
                element,
                received,
                expected,
            } => write!(
                f,
                "{element} InResponseTo {received:?} does not match expected {expected:?}"
            ),
            NlEidError::DestinationMismatch { received, expected } => write!(
                f,
                "Destination {received:?} does not match this endpoint {expected:?}"
            ),
            NlEidError::StaleMessage { element, detail } => {
                write!(f, "{element} is not fresh: {detail}")
            }
            NlEidError::ArtifactResolutionFailed(status) => write!(
                f,
                "artifact resolution failed with status {} / {}{}",
                status.status_code.value,
                status
                    .status_code
                    .sub_status
                    .as_ref()
                    .map(|s| s.value.as_str())
                    .unwrap_or("-"),
                status
                    .status_message
                    .as_deref()
                    .map(|m| format!(": {m}"))
                    .unwrap_or_default()
            ),
            NlEidError::ResponseCount(0) => write!(
                f,
                "ArtifactResponse reports Success but carries no Response (artifact expired, \
                 already resolved, or requester not authorized)"
            ),
            NlEidError::ResponseCount(n) => {
                write!(f, "ArtifactResponse carries {n} Response elements")
            }
            NlEidError::EncryptedAssertionForbidden => {
                write!(f, "Response carries an EncryptedAssertion (forbidden by §7.6.2)")
            }
            NlEidError::AssertionCount { success, found } => write!(
                f,
                "Response with status success={success} carries {found} Assertion element(s)"
            ),
            NlEidError::MissingRequired(what) => write!(f, "missing the required {what}"),
            NlEidError::AuthnStatementCount(n) => {
                write!(f, "expected exactly one AuthnStatement, found {n}")
            }
            NlEidError::AttributeStatementCount(n) => {
                write!(f, "expected exactly one AttributeStatement, found {n}")
            }
            NlEidError::InvalidSubjectNameId(m) => write!(f, "invalid Subject NameID: {m}"),
            NlEidError::MissingAuthnContextClassRef => {
                write!(f, "assertion is missing an AuthnContextClassRef")
            }
            NlEidError::UnknownLevelOfAssurance(u) => {
                write!(f, "AuthnContextClassRef {u:?} is not a known Level of Assurance")
            }
            NlEidError::LevelOfAssuranceTooLow { received, minimum } => write!(
                f,
                "delivered Level of Assurance {received:?} is below the minimum {minimum}"
            ),
            NlEidError::ServiceUuidMismatch { received, expected } => write!(
                f,
                "ServiceUUID {received:?} does not match the registered service {expected:?}"
            ),
            NlEidError::MissingActingSubjectId => {
                write!(f, "assertion carries no ActingSubjectID attribute")
            }
            NlEidError::TooManySubjectIds(a) => {
                write!(f, "{a} carries more EncryptedID values than supported")
            }
            NlEidError::NoEncryptedKeyForRecipient {
                attribute,
                recipients,
            } => write!(
                f,
                "{attribute} has no EncryptedKey addressed to this DV (recipients: {recipients:?})"
            ),
            NlEidError::Decryption { attribute, reason } => {
                write!(f, "{attribute} could not be decrypted: {reason}")
            }
            NlEidError::InvalidDecryptedNameId { attribute, reason } => {
                write!(f, "{attribute} decrypted NameID is invalid: {reason}")
            }
            NlEidError::InResponseToDisagreement {
                response,
                assertion,
            } => write!(
                f,
                "Response InResponseTo {response:?} and assertion InResponseTo {assertion:?} disagree"
            ),
            NlEidError::Metadata(m) => write!(f, "metadata error: {m}"),
            NlEidError::Profile(e) => write!(f, "profile error: {e}"),
            NlEidError::Crypto(e) => write!(f, "crypto error: {e}"),
            NlEidError::Xml(e) => write!(f, "XML error: {e}"),
        }
    }
}

impl std::error::Error for NlEidError {}

impl From<ProfileError> for NlEidError {
    fn from(e: ProfileError) -> Self {
        NlEidError::Profile(e)
    }
}

impl From<crate::crypto::CryptoError> for NlEidError {
    fn from(e: crate::crypto::CryptoError) -> Self {
        NlEidError::Crypto(e)
    }
}

impl From<crate::xml::XmlError> for NlEidError {
    fn from(e: crate::xml::XmlError) -> Self {
        NlEidError::Xml(e)
    }
}

impl From<uppsala::XmlError> for NlEidError {
    fn from(e: uppsala::XmlError) -> Self {
        NlEidError::Xml(crate::xml::XmlError::ParseError(e))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_status_mapping() {
        let loa = NlEidError::LevelOfAssuranceTooLow {
            received: "x".into(),
            minimum: constants::LOA_LOW,
        }
        .to_status();
        assert_eq!(loa.status_code.value, constants::STATUS_RESPONDER);
        assert_eq!(
            loa.status_code.sub_status.unwrap().value,
            constants::STATUS_NO_AUTHN_CONTEXT
        );

        let other = NlEidError::MissingIssuer("Response").to_status();
        assert_eq!(other.status_code.value, constants::STATUS_REQUESTER);
        assert_eq!(
            other.status_code.sub_status.unwrap().value,
            constants::STATUS_REQUEST_UNSUPPORTED
        );
    }
}
