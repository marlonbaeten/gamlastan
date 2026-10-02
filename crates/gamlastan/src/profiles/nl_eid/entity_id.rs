// eID entity identifiers (§10.2).
//
// Every participant is identified as
// `urn:nl-eid-gdi:1.0:<ROLE>:<OIN>:entities:<index>`, where the OIN is the
// Dutch government organisation number carried in the participant's
// PKIoverheid certificates and the four-digit index distinguishes endpoints
// of one organisation (9000–9999 are reserved for test systems).

use std::fmt;

use super::constants;

/// A participant role (§4.1, §10.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ParticipantRole {
    /// Authenticatiedienst: the Identity Provider (DigiD, eHerkenning, eIDAS).
    AuthenticationService,
    /// Dienstverlener: the Service Provider.
    ServiceProvider,
    /// Bevoegdheidsverklaringsdienst: issues representation assertions.
    AuthorizationService,
    /// Leverancier Clusteraansluiting: a cluster connection provider.
    ClusterConnectionProvider,
    /// Routeringsdienst: the routing service (TVS) the DV talks to.
    RoutingService,
}

impl ParticipantRole {
    /// The `<ROLE>` token used in an entity identifier.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::AuthenticationService => "AD",
            Self::ServiceProvider => "DV",
            Self::AuthorizationService => "BVD",
            Self::ClusterConnectionProvider => "LC",
            Self::RoutingService => "RD",
        }
    }

    /// Parse a `<ROLE>` token.
    pub fn from_str_token(token: &str) -> Option<Self> {
        match token {
            "AD" => Some(Self::AuthenticationService),
            "DV" => Some(Self::ServiceProvider),
            "BVD" => Some(Self::AuthorizationService),
            "LC" => Some(Self::ClusterConnectionProvider),
            "RD" => Some(Self::RoutingService),
            _ => None,
        }
    }
}

/// A parsed §10.2 entity identifier.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct EidEntityId {
    /// The participant role.
    pub role: ParticipantRole,
    /// The organisation number (OIN), as written (20 digits in practice).
    pub oin: String,
    /// The endpoint index (0000–9999).
    pub index: u16,
}

impl EidEntityId {
    /// Construct an identifier.
    pub fn new(role: ParticipantRole, oin: impl Into<String>, index: u16) -> Self {
        Self {
            role,
            oin: oin.into(),
            index,
        }
    }

    /// Parse `urn:nl-eid-gdi:1.0:<ROLE>:<OIN>:entities:<index>`.
    ///
    /// Returns `None` when the value does not follow the §10.2 format. Note that
    /// an RD may legitimately use a different `entityID` scheme in some
    /// environments (the TVS mock uses URLs), so callers compare entity IDs as
    /// opaque strings and use this parser only for configuration validation.
    pub fn parse(entity_id: &str) -> Option<Self> {
        let rest = entity_id.strip_prefix(constants::EID_URN_BASE)?;
        let rest = rest.strip_prefix(':')?;
        let mut parts = rest.split(':');
        let role = ParticipantRole::from_str_token(parts.next()?)?;
        let oin = parts.next()?;
        if oin.is_empty() || !oin.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        if parts.next()? != "entities" {
            return None;
        }
        let index = parts.next()?;
        if index.len() != 4 || !index.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        if parts.next().is_some() {
            return None;
        }
        let index: u16 = index.parse().ok()?;
        Some(Self {
            role,
            oin: oin.to_string(),
            index,
        })
    }

    /// Whether the index lies in the range reserved for test systems (§10.2).
    pub fn is_test_system(&self) -> bool {
        self.index >= constants::ENTITY_INDEX_TEST_START
    }
}

impl fmt::Display for EidEntityId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}:{}:{}:entities:{:04}",
            constants::EID_URN_BASE,
            self.role.as_str(),
            self.oin,
            self.index
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_and_display_round_trip() {
        let id = "urn:nl-eid-gdi:1.0:RD:00000004000000149000:entities:9002";
        let parsed = EidEntityId::parse(id).unwrap();
        assert_eq!(parsed.role, ParticipantRole::RoutingService);
        assert_eq!(parsed.oin, "00000004000000149000");
        assert_eq!(parsed.index, 9002);
        assert!(parsed.is_test_system());
        assert_eq!(parsed.to_string(), id);

        let prod = EidEntityId::new(ParticipantRole::ServiceProvider, "00000001234567890000", 1);
        assert!(!prod.is_test_system());
        assert_eq!(
            prod.to_string(),
            "urn:nl-eid-gdi:1.0:DV:00000001234567890000:entities:0001"
        );
    }

    #[test]
    fn test_parse_rejects_malformed() {
        for bad in [
            "https://rd.example/metadata",
            "urn:nl-eid-gdi:1.0:XX:00000004000000149000:entities:9002",
            "urn:nl-eid-gdi:1.0:RD:abc:entities:9002",
            "urn:nl-eid-gdi:1.0:RD:00000004000000149000:entity:9002",
            "urn:nl-eid-gdi:1.0:RD:00000004000000149000:entities:12",
            "urn:nl-eid-gdi:1.0:RD:00000004000000149000:entities:9002:extra",
            "urn:nl-eid-gdi:1.0:RD::entities:9002",
        ] {
            assert!(EidEntityId::parse(bad).is_none(), "{bad}");
        }
    }
}
