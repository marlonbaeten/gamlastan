// Deployment configuration for a Dienstverlener (DV, Service Provider).

use crate::security::config::SecurityConfig;

use super::authn_context::LevelOfAssurance;
use super::constants;
use super::error::NlEidError;

/// Deployment configuration for a DV connecting directly to a Routeringsdienst
/// (RD) under the eID SAML v4.4 interface specification.
///
/// The configuration captures what the DV registered during onboarding (its
/// `entityID`, `ServiceUUID`, endpoints and minimum Level of Assurance) plus
/// the RD it trusts. Construct it with [`NlEidConfig::service_provider`] and
/// adjust the public fields as needed.
#[derive(Debug, Clone)]
pub struct NlEidConfig {
    /// This DV's `entityID` (§10.2 format for production participants).
    pub entity_id: String,

    /// The `ServiceUUID` of the service definition in the RD service catalogue
    /// (§7.3.1.1). Sent in every `AuthnRequest`, published in the metadata, and
    /// required to come back unchanged in the assertion (§7.6.3.4).
    pub service_uuid: String,

    /// The DV's `AssertionConsumerService` URL (HTTP-Artifact binding). The
    /// Response `@Destination` and the bearer `@Recipient` MUST equal it.
    pub acs_url: String,

    /// The DV's `SingleLogoutService` URL (HTTP-POST binding), if the DV takes
    /// part in SSO and therefore supports logout (§3.1.1.1, §8.3).
    pub single_logout_url: Option<String>,

    /// The RD's `entityID`, taken from its verified metadata (§8.5). Every
    /// `<saml:Issuer>` the DV receives MUST equal it.
    pub rd_entity_id: String,

    /// The minimum Level of Assurance registered for the service (§7.6.3.2).
    /// Requested with `Comparison="minimum"`; a delivered level below it is
    /// rejected, equal or higher is accepted.
    pub minimum_loa: LevelOfAssurance,

    /// The `IntendedAudience` placed in the `AuthnRequest` extension (§7.3).
    /// For a DV this is its own `entityID`; `None` means "same as `entity_id`".
    pub intended_audience: Option<String>,

    /// Clock skew tolerance in seconds, applied to every instant. Clamped to
    /// [`constants::MAX_CLOCK_SKEW_SECONDS`].
    pub clock_skew_seconds: u64,

    /// How old an envelope `@IssueInstant` or `@AuthnInstant` may be (seconds).
    /// Also the maximum assertion age fed to the shared validator.
    pub message_freshness_seconds: u64,

    /// Whether the RD's own `<ds:Signature>` on the `<saml:Assertion>` is
    /// required (§7.6.3 gives it cardinality 1 and the DV metadata declares
    /// `WantAssertionsSigned="true"`). When present it is always verified and
    /// bound to the consumed assertion; set this to `false` to accept an
    /// unsigned assertion on the strength of the enveloping ArtifactResponse
    /// signature alone (the behaviour of some reference implementations).
    pub require_assertion_signature: bool,
}

impl NlEidConfig {
    /// Create a configuration for a DV talking to the RD `rd_entity_id`.
    pub fn service_provider(
        entity_id: impl Into<String>,
        service_uuid: impl Into<String>,
        acs_url: impl Into<String>,
        rd_entity_id: impl Into<String>,
        minimum_loa: LevelOfAssurance,
    ) -> Self {
        Self {
            entity_id: entity_id.into(),
            service_uuid: service_uuid.into(),
            acs_url: acs_url.into(),
            single_logout_url: None,
            rd_entity_id: rd_entity_id.into(),
            minimum_loa,
            intended_audience: None,
            clock_skew_seconds: constants::DEFAULT_CLOCK_SKEW_SECONDS,
            message_freshness_seconds: constants::DEFAULT_MESSAGE_FRESHNESS_SECONDS,
            require_assertion_signature: true,
        }
    }

    /// Set the `SingleLogoutService` URL (builder style).
    pub fn with_single_logout_url(mut self, url: impl Into<String>) -> Self {
        self.single_logout_url = Some(url.into());
        self
    }

    /// The `IntendedAudience` to send: the explicit value, else the DV itself.
    pub fn intended_audience(&self) -> &str {
        self.intended_audience.as_deref().unwrap_or(&self.entity_id)
    }

    /// Validate the configuration against the profile's hard requirements.
    pub fn validate(&self) -> Result<(), NlEidError> {
        if self.entity_id.trim().is_empty() {
            return Err(NlEidError::Config("entity_id is empty".to_string()));
        }
        if self.service_uuid.trim().is_empty() {
            return Err(NlEidError::Config("service_uuid is empty".to_string()));
        }
        if self.acs_url.trim().is_empty() {
            return Err(NlEidError::Config("acs_url is empty".to_string()));
        }
        if self.rd_entity_id.trim().is_empty() {
            return Err(NlEidError::Config("rd_entity_id is empty".to_string()));
        }
        if self.clock_skew_seconds > constants::MAX_CLOCK_SKEW_SECONDS {
            return Err(NlEidError::ClockSkewTooLarge(self.clock_skew_seconds));
        }
        Ok(())
    }

    /// The effective clock skew, clamped to the profile maximum.
    pub fn effective_clock_skew(&self) -> u64 {
        self.clock_skew_seconds
            .min(constants::MAX_CLOCK_SKEW_SECONDS)
    }

    /// Build the [`SecurityConfig`] for the shared assertion validator:
    ///
    /// - clock skew clamped to ≤ 60 s,
    /// - the `<samlp:Response>` is **not** required to be signed: its
    ///   authenticity comes from the RD signature on the enveloping
    ///   `<samlp:ArtifactResponse>` (§7.6.2 says a Response signature SHOULD NOT
    ///   be used),
    /// - the assertion signature requirement follows
    ///   [`require_assertion_signature`](Self::require_assertion_signature),
    /// - assertions arrive in cleartext (only the identifiers are encrypted, so
    ///   `EncryptedAssertion` is forbidden rather than required, §7.6.2),
    /// - Destination and Recipient MUST be verified (§7.6.2, §7.6.3.5),
    /// - unsolicited responses are never accepted (the artifact flow is always
    ///   solicited).
    pub fn security_config(&self) -> SecurityConfig {
        SecurityConfig {
            clock_skew_seconds: self.effective_clock_skew(),
            require_signed_assertions: self.require_assertion_signature,
            require_signed_responses: false,
            require_encrypted_assertions: false,
            max_assertion_age_seconds: self.message_freshness_seconds,
            reject_signatures_with_ds_object: true,
            enforce_persistent_id_uniqueness: false,
            sanitize_relay_state: true,
            require_integrity_with_cbc: true,
            verify_destination: true,
            verify_recipient: true,
            check_client_address: false,
            allow_unsolicited_responses: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> NlEidConfig {
        NlEidConfig::service_provider(
            "urn:nl-eid-gdi:1.0:DV:00000001234567890000:entities:9001",
            "f847dc11-ac24-47b2-84a8-a057440ce56d",
            "https://dv.example.nl/saml/acs",
            "urn:nl-eid-gdi:1.0:RD:00000004000000149000:entities:9002",
            LevelOfAssurance::Low,
        )
    }

    #[test]
    fn test_defaults() {
        let c = cfg();
        assert!(c.validate().is_ok());
        assert_eq!(c.intended_audience(), c.entity_id);
        assert!(c.require_assertion_signature);
        assert_eq!(c.clock_skew_seconds, constants::DEFAULT_CLOCK_SKEW_SECONDS);
        assert!(c.single_logout_url.is_none());
    }

    #[test]
    fn test_security_config_shape() {
        let sec = cfg().security_config();
        assert!(!sec.require_signed_responses);
        assert!(sec.require_signed_assertions);
        assert!(!sec.require_encrypted_assertions);
        assert!(sec.verify_destination);
        assert!(sec.verify_recipient);
        assert!(!sec.allow_unsolicited_responses);
        assert_eq!(
            sec.clock_skew_seconds,
            constants::DEFAULT_CLOCK_SKEW_SECONDS
        );
    }

    #[test]
    fn test_clock_skew_is_clamped() {
        let mut c = cfg();
        c.clock_skew_seconds = 600;
        assert!(matches!(
            c.validate(),
            Err(NlEidError::ClockSkewTooLarge(600))
        ));
        assert_eq!(
            c.security_config().clock_skew_seconds,
            constants::MAX_CLOCK_SKEW_SECONDS
        );
    }

    #[test]
    fn test_validate_rejects_empty_fields() {
        let mut c = cfg();
        c.service_uuid = String::new();
        assert!(matches!(c.validate(), Err(NlEidError::Config(_))));
    }
}
