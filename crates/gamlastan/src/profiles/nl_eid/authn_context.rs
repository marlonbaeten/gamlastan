// Level of Assurance handling (§7.6.3.2, §9.6, §10.3).
//
// The eID framework orders its assurance levels and requires a DV to accept
// any authentication at *or above* the minimum level registered for the
// service, so the `AuthnRequest` uses `Comparison="minimum"` and the response
// check is an ordered comparison rather than the exact match of other
// deployment profiles.

use crate::core::protocol::request::{AuthnContextComparison, RequestedAuthnContext};

use super::constants;
use super::error::NlEidError;

/// A Level of Assurance of the eID framework (§10.3), ordered by increasing
/// assurance so `>=` implements the §7.6.3.2 minimum rule directly.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum LevelOfAssurance {
    /// Basis (DigiD Basis, eTD 2).
    Basic,
    /// Midden / eIDAS low (DigiD Midden, eTD 2+).
    Low,
    /// Substantieel / eIDAS substantial (DigiD Substantieel, eTD 3).
    Substantial,
    /// Hoog / eIDAS high (DigiD Hoog, eTD 4).
    High,
}

impl LevelOfAssurance {
    /// Parse an `AuthnContextClassRef` URI per the §10.3 table. Each level has
    /// two accepted spellings: the SAML `ac:classes` URN and the eID / eIDAS
    /// URL the RD emits. Returns `None` for any URI not in the table.
    pub fn from_uri(uri: &str) -> Option<Self> {
        match uri {
            constants::LOA_BASIC | constants::LOA_BASIC_EID => Some(Self::Basic),
            constants::LOA_LOW | constants::LOA_LOW_EIDAS => Some(Self::Low),
            constants::LOA_SUBSTANTIAL | constants::LOA_SUBSTANTIAL_EIDAS => {
                Some(Self::Substantial)
            }
            constants::LOA_HIGH | constants::LOA_HIGH_EIDAS => Some(Self::High),
            _ => None,
        }
    }

    /// The URI used to *request* this level in an outgoing `AuthnRequest`: the
    /// SAML `ac:classes` spelling of the §10.3 table. Round-trips through
    /// [`Self::from_uri`].
    pub fn as_request_uri(self) -> &'static str {
        match self {
            Self::Basic => constants::LOA_BASIC,
            Self::Low => constants::LOA_LOW,
            Self::Substantial => constants::LOA_SUBSTANTIAL,
            Self::High => constants::LOA_HIGH,
        }
    }

    /// The eIDAS / eID URL spelling of this level.
    pub fn as_eidas_uri(self) -> &'static str {
        match self {
            Self::Basic => constants::LOA_BASIC_EID,
            Self::Low => constants::LOA_LOW_EIDAS,
            Self::Substantial => constants::LOA_SUBSTANTIAL_EIDAS,
            Self::High => constants::LOA_HIGH_EIDAS,
        }
    }
}

/// Build the `<samlp:RequestedAuthnContext Comparison="minimum">` for the DV's
/// minimum level (§7.6.3.2 / TVS Checklist Testen T6): the RD may authenticate
/// at this level or higher, never lower.
pub fn requested_authn_context(minimum: LevelOfAssurance) -> RequestedAuthnContext {
    RequestedAuthnContext {
        authn_context_class_refs: vec![minimum.as_request_uri().to_string()],
        authn_context_decl_refs: vec![],
        comparison: AuthnContextComparison::Minimum,
    }
}

/// Validate the `AuthnContextClassRef` delivered in an assertion against the
/// DV minimum (§7.6.3.2): the value MUST be present, MUST be a §10.3 URI, and
/// MUST denote a level equal to or higher than `minimum`.
pub fn validate_level_of_assurance(
    received: Option<&str>,
    minimum: LevelOfAssurance,
) -> Result<LevelOfAssurance, NlEidError> {
    let received = received
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or(NlEidError::MissingAuthnContextClassRef)?;
    let level = LevelOfAssurance::from_uri(received)
        .ok_or_else(|| NlEidError::UnknownLevelOfAssurance(received.to_string()))?;
    if level >= minimum {
        Ok(level)
    } else {
        Err(NlEidError::LevelOfAssuranceTooLow {
            received: received.to_string(),
            minimum: minimum.as_request_uri(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_from_uri_maps_every_spelling() {
        let cases = [
            (constants::LOA_BASIC, LevelOfAssurance::Basic),
            (constants::LOA_BASIC_EID, LevelOfAssurance::Basic),
            (constants::LOA_LOW, LevelOfAssurance::Low),
            (constants::LOA_LOW_EIDAS, LevelOfAssurance::Low),
            (constants::LOA_SUBSTANTIAL, LevelOfAssurance::Substantial),
            (
                constants::LOA_SUBSTANTIAL_EIDAS,
                LevelOfAssurance::Substantial,
            ),
            (constants::LOA_HIGH, LevelOfAssurance::High),
            (constants::LOA_HIGH_EIDAS, LevelOfAssurance::High),
        ];
        for (uri, level) in cases {
            assert_eq!(LevelOfAssurance::from_uri(uri), Some(level), "{uri}");
        }
        // An invented spelling is not a level.
        assert_eq!(
            LevelOfAssurance::from_uri("http://eID.logius.nl/LoA/substantial"),
            None
        );
    }

    #[test]
    fn test_request_uri_round_trips() {
        for level in [
            LevelOfAssurance::Basic,
            LevelOfAssurance::Low,
            LevelOfAssurance::Substantial,
            LevelOfAssurance::High,
        ] {
            assert_eq!(
                LevelOfAssurance::from_uri(level.as_request_uri()),
                Some(level)
            );
            assert_eq!(
                LevelOfAssurance::from_uri(level.as_eidas_uri()),
                Some(level)
            );
        }
    }

    #[test]
    fn test_ordering_implements_minimum_rule() {
        assert!(LevelOfAssurance::High > LevelOfAssurance::Substantial);
        assert!(LevelOfAssurance::Substantial > LevelOfAssurance::Low);
        assert!(LevelOfAssurance::Low > LevelOfAssurance::Basic);
    }

    #[test]
    fn test_requested_authn_context_is_minimum() {
        let rac = requested_authn_context(LevelOfAssurance::Low);
        assert_eq!(rac.comparison, AuthnContextComparison::Minimum);
        assert_eq!(rac.authn_context_class_refs, vec![constants::LOA_LOW]);
    }

    #[test]
    fn test_validate_accepts_equal_and_higher() {
        let min = LevelOfAssurance::Low;
        assert_eq!(
            validate_level_of_assurance(Some(constants::LOA_LOW_EIDAS), min).unwrap(),
            LevelOfAssurance::Low
        );
        assert_eq!(
            validate_level_of_assurance(Some(constants::LOA_HIGH), min).unwrap(),
            LevelOfAssurance::High
        );
        // Whitespace around the URI (pretty-printed RD output) is tolerated.
        assert!(validate_level_of_assurance(
            Some(&format!("\n  {}\n  ", constants::LOA_SUBSTANTIAL_EIDAS)),
            min
        )
        .is_ok());
    }

    #[test]
    fn test_validate_rejects_lower_unknown_and_missing() {
        let min = LevelOfAssurance::Low;
        assert!(matches!(
            validate_level_of_assurance(Some(constants::LOA_BASIC), min),
            Err(NlEidError::LevelOfAssuranceTooLow { .. })
        ));
        assert!(matches!(
            validate_level_of_assurance(Some("urn:bogus"), min),
            Err(NlEidError::UnknownLevelOfAssurance(_))
        ));
        assert!(matches!(
            validate_level_of_assurance(None, min),
            Err(NlEidError::MissingAuthnContextClassRef)
        ));
        assert!(matches!(
            validate_level_of_assurance(Some("   "), min),
            Err(NlEidError::MissingAuthnContextClassRef)
        ));
    }
}
