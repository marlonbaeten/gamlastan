// SP-initiated Single Logout: validation of the RD `LogoutResponse` (§7.7.2).
//
// The request side lives in `request::build_logout_request`. Only SP-initiated
// logout exists in the eID framework (§3.1.1.1), so there is no
// `LogoutRequest` to process on the DV side.

use chrono::{DateTime, Utc};

use crate::core::protocol::logout::LogoutResponseRef;
use crate::core::protocol::status::Status;
use crate::crypto::SamlVerifier;
use crate::xml::deserialize::SamlDeserialize;

use super::config::NlEidConfig;
use super::constants;
use super::error::NlEidError;
use super::xmlutil;

/// The correlation fields of a structurally valid, RD-signed `LogoutResponse`.
#[derive(Debug, Clone)]
pub struct LogoutResponseOutcome {
    /// The `@InResponseTo`: the `LogoutRequest` this answers. The caller
    /// consumes it from its pending-request store (once).
    pub in_response_to: String,
    /// The reported status.
    pub status: Status,
    /// The `<ds:KeyName>` of the RD key that signed the response.
    pub rd_signing_key_name: String,
}

impl LogoutResponseOutcome {
    /// Whether the RD reported `Success`.
    pub fn is_success(&self) -> bool {
        self.status.is_success()
    }
}

/// Validate the decoded (HTTP-POST `SAMLResponse`) `LogoutResponse` XML per
/// §7.7.2: root `samlp:LogoutResponse`, §9.1 algorithms, the enveloping RD
/// signature (single, first, `KeyName`-selected, bound to the element),
/// `Version` 2.0, fresh `IssueInstant`, `Issuer` = RD, `Destination` = the DV
/// `SingleLogoutService` URL, and `InResponseTo` = `expected_in_response_to`.
///
/// A failure status is not an error: the outcome reports it. The local
/// session is already gone by the time this runs, so the caller logs the
/// result and redirects regardless.
pub fn validate_logout_response(
    cfg: &NlEidConfig,
    xml: &str,
    verifier: &SamlVerifier,
    expected_in_response_to: &str,
    now: DateTime<Utc>,
) -> Result<LogoutResponseOutcome, NlEidError> {
    cfg.validate()?;
    let sls_url = cfg
        .single_logout_url
        .as_deref()
        .ok_or_else(|| NlEidError::Config("single_logout_url is not configured".to_string()))?;

    let doc = crate::xml::parse_secure(xml)?;
    let root = doc
        .document_element()
        .ok_or_else(|| NlEidError::MalformedMessage("empty document".to_string()))?;
    if !xmlutil::is_element(&doc, root, constants::NS_SAML_PROTOCOL, "LogoutResponse") {
        return Err(NlEidError::MalformedMessage(
            "message is not a samlp:LogoutResponse".to_string(),
        ));
    }
    xmlutil::validate_algorithms(&doc, root, None)?;
    let signature =
        xmlutil::verify_enveloping_signature(&doc, root, xml, verifier, "LogoutResponse")?;

    let response = LogoutResponseRef::from_xml(&doc, root)?.to_owned();
    if !response.version.is_v2_0() {
        return Err(NlEidError::MalformedMessage(
            "LogoutResponse Version is not 2.0".to_string(),
        ));
    }
    xmlutil::check_freshness(
        response.issue_instant,
        now,
        cfg.effective_clock_skew(),
        cfg.message_freshness_seconds,
        "LogoutResponse @IssueInstant",
    )?;
    let issuer = response
        .issuer
        .as_ref()
        .map(|i| i.value.trim())
        .ok_or(NlEidError::MissingIssuer("LogoutResponse"))?;
    if issuer != cfg.rd_entity_id {
        return Err(NlEidError::IssuerMismatch {
            element: "LogoutResponse",
            received: issuer.to_string(),
            expected: cfg.rd_entity_id.clone(),
        });
    }
    if response.destination.as_deref() != Some(sls_url) {
        return Err(NlEidError::DestinationMismatch {
            received: response.destination.clone(),
            expected: sls_url.to_string(),
        });
    }
    let in_response_to = match response.in_response_to.as_deref() {
        Some(irt) if irt == expected_in_response_to => irt.to_string(),
        received => {
            return Err(NlEidError::InResponseToMismatch {
                element: "LogoutResponse",
                received: received.map(str::to_string),
                expected: expected_in_response_to.to_string(),
            })
        }
    };

    Ok(LogoutResponseOutcome {
        in_response_to,
        status: response.status,
        rd_signing_key_name: signature.key_name,
    })
}
