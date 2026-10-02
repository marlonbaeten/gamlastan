// Constants for the Dutch eID SAML interface specification
// ("Koppelvlakspecificatie eID SAML v4.4", Logius).
//
// Identifiers are taken from:
// - §3.1.1 (bindings), §7 (messages), §7.8 (status codes), §8 (metadata),
//   §9.1 / §9.3 (algorithms), §10 (type definitions).
//
// Section references in this module point at the eID SAML v4.4 specification
// unless marked otherwise.

// ── XML namespaces ──────────────────────────────────────────────────────────

/// SAML 2.0 assertion namespace.
pub const NS_SAML_ASSERTION: &str = "urn:oasis:names:tc:SAML:2.0:assertion";
/// SAML 2.0 protocol namespace.
pub const NS_SAML_PROTOCOL: &str = "urn:oasis:names:tc:SAML:2.0:protocol";
/// SAML 2.0 metadata namespace.
pub const NS_MD: &str = "urn:oasis:names:tc:SAML:2.0:metadata";
/// XML Digital Signature namespace.
pub const NS_DS: &str = "http://www.w3.org/2000/09/xmldsig#";
/// XML Encryption 1.0 namespace.
pub const NS_XENC: &str = "http://www.w3.org/2001/04/xmlenc#";
/// XML Encryption 1.1 namespace.
pub const NS_XENC11: &str = "http://www.w3.org/2009/xmlenc11#";
/// SOAP 1.1 envelope namespace (§7.5 / §7.6: the back-channel binding).
pub const NS_SOAP11: &str = "http://schemas.xmlsoap.org/soap/envelope/";
/// XML Schema instance namespace (`xsi:type` on metadata attribute values).
pub const NS_XSI: &str = "http://www.w3.org/2001/XMLSchema-instance";
/// XML Schema namespace.
pub const NS_XS: &str = "http://www.w3.org/2001/XMLSchema";

// ── Bindings (§3.1.1) ───────────────────────────────────────────────────────

/// HTTP-POST binding: AuthnRequest → RD, LogoutRequest/LogoutResponse.
pub const BINDING_HTTP_POST: &str = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST";
/// HTTP-Artifact binding: the RD delivers an artifact to the DV ACS.
pub const BINDING_HTTP_ARTIFACT: &str = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact";
/// SOAP binding: ArtifactResolve / ArtifactResponse over the mTLS back-channel.
pub const BINDING_SOAP: &str = "urn:oasis:names:tc:SAML:2.0:bindings:SOAP";

// ── Name identifier formats (§7.6.3, §7.6.3.4.4) ────────────────────────────

/// The Subject `<saml:NameID>` of the RD assertion MUST be a TransientID.
pub const NAMEID_TRANSIENT: &str = "urn:oasis:names:tc:SAML:2.0:nameid-format:transient";
/// A decrypted `<saml:EncryptedID>` NameID MUST use the persistent format.
pub const NAMEID_PERSISTENT: &str = "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent";

// ── Subject confirmation (§7.6.3.3) ─────────────────────────────────────────

/// The only permitted SubjectConfirmation method.
pub const CM_BEARER: &str = "urn:oasis:names:tc:SAML:2.0:cm:bearer";

// ── eID attributes (§7.3, §7.6.3.4) ─────────────────────────────────────────

/// Base URN of the eID naming scheme (§10.2 and the 4.4 final errata).
pub const EID_URN_BASE: &str = "urn:nl-eid-gdi:1.0";
/// AuthnRequest extension attribute: the DV the authentication is for.
pub const ATTR_INTENDED_AUDIENCE: &str = "urn:nl-eid-gdi:1.0:IntendedAudience";
/// AuthnRequest extension attribute / assertion attribute / metadata
/// `RequestedAttribute`: the service definition in the RD service catalogue.
pub const ATTR_SERVICE_UUID: &str = "urn:nl-eid-gdi:1.0:ServiceUUID";
/// Assertion attribute carrying the authenticated subject as an `EncryptedID`.
pub const ATTR_ACTING_SUBJECT_ID: &str = "urn:nl-eid-gdi:1.0:ActingSubjectID";
/// Assertion attribute carrying the represented party as an `EncryptedID`
/// (representation only).
pub const ATTR_LEGAL_SUBJECT_ID: &str = "urn:nl-eid-gdi:1.0:LegalSubjectID";

// ── Identifier types (§10.1) ────────────────────────────────────────────────

/// BSN, 9 digits with leading zeros (`@NameQualifier` of a decrypted NameID).
pub const ID_TYPE_LEGACY_BSN: &str = "urn:nl-eid-gdi:1.0:id:legacy-BSN";
/// Encrypted identity (polymorphic BSN).
pub const ID_TYPE_BSN: &str = "urn:nl-eid-gdi:1.0:id:BSN";
/// Encrypted pseudonym.
pub const ID_TYPE_PSEUDONYM: &str = "urn:nl-eid-gdi:1.0:id:Pseudonym";

/// Every identifier type a decrypted `EncryptedID` may declare (§10.1).
pub const IDENTIFIER_TYPES: &[&str] = &[ID_TYPE_LEGACY_BSN, ID_TYPE_BSN, ID_TYPE_PSEUDONYM];

// ── Levels of Assurance (§10.3) ─────────────────────────────────────────────

/// Basis: `PasswordProtectedTransport` (the SAML `ac:classes` spelling).
pub const LOA_BASIC: &str = "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport";
/// Basis: the eID spelling.
pub const LOA_BASIC_EID: &str = "http://eID.logius.nl/LoA/basic";
/// Midden / eIDAS low: `MobileTwoFactorContract`.
pub const LOA_LOW: &str = "urn:oasis:names:tc:SAML:2.0:ac:classes:MobileTwoFactorContract";
/// Midden / eIDAS low: the eIDAS spelling.
pub const LOA_LOW_EIDAS: &str = "http://eidas.europa.eu/LoA/low";
/// Substantieel / eIDAS substantial: `Smartcard`.
pub const LOA_SUBSTANTIAL: &str = "urn:oasis:names:tc:SAML:2.0:ac:classes:Smartcard";
/// Substantieel / eIDAS substantial: the eIDAS spelling.
pub const LOA_SUBSTANTIAL_EIDAS: &str = "http://eidas.europa.eu/LoA/substantial";
/// Hoog / eIDAS high: `SmartcardPKI`.
pub const LOA_HIGH: &str = "urn:oasis:names:tc:SAML:2.0:ac:classes:SmartcardPKI";
/// Hoog / eIDAS high: the eIDAS spelling.
pub const LOA_HIGH_EIDAS: &str = "http://eidas.europa.eu/LoA/high";

// ── Status codes (§7.8) ─────────────────────────────────────────────────────

/// Top-level status: success.
pub const STATUS_SUCCESS: &str = "urn:oasis:names:tc:SAML:2.0:status:Success";
/// Top-level status: error caused by the requester.
pub const STATUS_REQUESTER: &str = "urn:oasis:names:tc:SAML:2.0:status:Requester";
/// Top-level status: error caused by the responder.
pub const STATUS_RESPONDER: &str = "urn:oasis:names:tc:SAML:2.0:status:Responder";
/// Second-level status: the user could not be authenticated (also used for a
/// cancellation, §7.8.3).
pub const STATUS_AUTHN_FAILED: &str = "urn:oasis:names:tc:SAML:2.0:status:AuthnFailed";
/// Second-level status: the minimum LoA for the service cannot be met.
pub const STATUS_NO_AUTHN_CONTEXT: &str = "urn:oasis:names:tc:SAML:2.0:status:NoAuthnContext";
/// Second-level status: understood but unsupported request (§7.8.5, §7.8.6).
pub const STATUS_REQUEST_UNSUPPORTED: &str =
    "urn:oasis:names:tc:SAML:2.0:status:RequestUnsupported";
/// Second-level status: the responder refuses the exchange (e.g. a signature
/// could not be verified).
pub const STATUS_REQUEST_DENIED: &str = "urn:oasis:names:tc:SAML:2.0:status:RequestDenied";
/// Second-level status: no `IDPList` entry is supported by the RD.
pub const STATUS_NO_SUPPORTED_IDP: &str = "urn:oasis:names:tc:SAML:2.0:status:NoSupportedIDP";

/// The exact `<samlp:StatusMessage>` an RD MUST send on a user cancellation
/// (§7.8.3), together with `Responder` / `AuthnFailed`.
pub const STATUS_MESSAGE_CANCELLED: &str = "Authentication cancelled";

// ── Entity identifiers (§10.2) ──────────────────────────────────────────────

/// The first index reserved for test systems (`9000`–`9999`, §10.2).
pub const ENTITY_INDEX_TEST_START: u16 = 9000;
/// The last index available to production systems.
pub const ENTITY_INDEX_PRODUCTION_END: u16 = 8999;

// ── Protocol limits ─────────────────────────────────────────────────────────

/// Maximum RelayState length in characters (§9.8).
pub const MAX_RELAY_STATE_CHARS: usize = 80;
/// An RD stores an artifact for at most this long (§7.1 step 5).
pub const ARTIFACT_LIFETIME_SECONDS: u64 = 15 * 60;
/// Initial bearer `SubjectConfirmationData/@NotOnOrAfter` window (§7.6.3.3).
pub const SUBJECT_CONFIRMATION_WINDOW_SECONDS: u64 = 120;
/// A DV session MUST end after at most this much inactivity (§9.7).
pub const MAX_SESSION_INACTIVITY_SECONDS: u64 = 30 * 60;

/// Default clock skew accepted on every instant (§9.5 advises NTP; this is the
/// allowance used by the TVS reference deployments).
pub const DEFAULT_CLOCK_SKEW_SECONDS: u64 = 30;
/// The largest clock skew [`super::config::NlEidConfig`] accepts.
pub const MAX_CLOCK_SKEW_SECONDS: u64 = 60;
/// Default upper bound on how old an envelope `@IssueInstant` /
/// `@AuthnInstant` may be. The specification bounds the assertion through its
/// `<saml:Conditions>` only, so this is the library's own ceiling for the
/// ArtifactResponse / Response envelopes, which carry no conditions at all.
pub const DEFAULT_MESSAGE_FRESHNESS_SECONDS: u64 = 300;

// ── Cryptographic algorithms (§9.1, §9.3) ───────────────────────────────────

/// Exclusive canonicalization without comments (mandatory, §9.1).
pub const C14N_EXCLUSIVE: &str = "http://www.w3.org/2001/10/xml-exc-c14n#";
/// The enveloped-signature transform (mandatory, §9.1).
pub const TRANSFORM_ENVELOPED_SIGNATURE: &str =
    "http://www.w3.org/2000/09/xmldsig#enveloped-signature";

/// RSA-SHA256 signature method (minimum, §9.1).
pub const SIG_RSA_SHA256: &str = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
/// RSA-SHA384 signature method.
pub const SIG_RSA_SHA384: &str = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384";
/// RSA-SHA512 signature method.
pub const SIG_RSA_SHA512: &str = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512";

/// SHA-256 digest (minimum, §9.1).
pub const DIGEST_SHA256: &str = "http://www.w3.org/2001/04/xmlenc#sha256";
/// SHA-384 digest as the specification spells it.
pub const DIGEST_SHA384: &str = "http://www.w3.org/2001/04/xmldsig-more#sha384";
/// SHA-512 digest as the specification spells it (`xmldsig-more`).
pub const DIGEST_SHA512_DSIG_MORE: &str = "http://www.w3.org/2001/04/xmldsig-more#sha512";
/// SHA-512 digest as registered by the W3C (`xmlenc`).
pub const DIGEST_SHA512: &str = "http://www.w3.org/2001/04/xmlenc#sha512";
/// SHA-1 digest: no longer supported by eID SAML 4.x (§9.1), except inside the
/// RSA-OAEP padding function.
pub const DIGEST_SHA1: &str = "http://www.w3.org/2000/09/xmldsig#sha1";

/// Block encryption: AES-256-CBC (the only permitted data cipher, §9.3).
pub const ENC_AES256_CBC: &str = "http://www.w3.org/2001/04/xmlenc#aes256-cbc";
/// Key transport: RSA-OAEP with MGF1 (XML Encryption 1.0 URI, §9.3).
pub const KEYTRANSPORT_RSA_OAEP_MGF1P: &str = "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p";
/// Key transport: RSA-OAEP (XML Encryption 1.1 URI, §9.3).
pub const KEYTRANSPORT_RSA_OAEP: &str = "http://www.w3.org/2009/xmlenc11#rsa-oaep";
/// Key transport: RSA PKCS#1 v1.5 — not permitted (§9.3 requires OAEP).
pub const KEYTRANSPORT_RSA_1_5: &str = "http://www.w3.org/2001/04/xmlenc#rsa-1_5";

/// Signature algorithms permitted by §9.1 ("Only RSA is supported", SHA-256
/// or stronger).
pub const ALLOWED_SIGNATURE_ALGORITHMS: &[&str] = &[SIG_RSA_SHA256, SIG_RSA_SHA384, SIG_RSA_SHA512];

/// Digest algorithms permitted by §9.1. Both spellings of SHA-512 are accepted:
/// the specification lists the `xmldsig-more` URI while the W3C registry uses
/// `xmlenc`; the algorithm is identical.
pub const ALLOWED_DIGEST_ALGORITHMS: &[&str] = &[
    DIGEST_SHA256,
    DIGEST_SHA384,
    DIGEST_SHA512_DSIG_MORE,
    DIGEST_SHA512,
];

/// Block-encryption algorithms permitted by §9.3.
pub const ALLOWED_BLOCK_ENCRYPTION_ALGORITHMS: &[&str] = &[ENC_AES256_CBC];

/// Key-transport algorithms permitted by §9.3.
pub const ALLOWED_KEY_TRANSPORT_ALGORITHMS: &[&str] =
    &[KEYTRANSPORT_RSA_OAEP_MGF1P, KEYTRANSPORT_RSA_OAEP];

/// Returns `true` if `uri` is a signature algorithm permitted by §9.1.
pub fn is_allowed_signature_algorithm(uri: &str) -> bool {
    ALLOWED_SIGNATURE_ALGORITHMS.contains(&uri)
}

/// Returns `true` if `uri` is a digest algorithm permitted by §9.1.
pub fn is_allowed_digest_algorithm(uri: &str) -> bool {
    ALLOWED_DIGEST_ALGORITHMS.contains(&uri)
}

/// Returns `true` if `uri` is a block-encryption algorithm permitted by §9.3.
pub fn is_allowed_block_encryption_algorithm(uri: &str) -> bool {
    ALLOWED_BLOCK_ENCRYPTION_ALGORITHMS.contains(&uri)
}

/// Returns `true` if `uri` is a key-transport algorithm permitted by §9.3.
pub fn is_allowed_key_transport_algorithm(uri: &str) -> bool {
    ALLOWED_KEY_TRANSPORT_ALGORITHMS.contains(&uri)
}

/// The signature/digest allow-list of §9.1 as a verifier policy.
pub fn algorithm_policy() -> crate::crypto::AlgorithmPolicy {
    crate::crypto::AlgorithmPolicy::allow_only(
        ALLOWED_SIGNATURE_ALGORITHMS.iter().copied(),
        ALLOWED_DIGEST_ALGORITHMS.iter().copied(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_algorithm_allow_lists() {
        assert!(is_allowed_signature_algorithm(SIG_RSA_SHA256));
        assert!(!is_allowed_signature_algorithm(
            "http://www.w3.org/2000/09/xmldsig#rsa-sha1"
        ));
        // ECDSA is not permitted: "Only RSA is supported" (§9.1).
        assert!(!is_allowed_signature_algorithm(
            "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256"
        ));
        assert!(is_allowed_digest_algorithm(DIGEST_SHA256));
        assert!(is_allowed_digest_algorithm(DIGEST_SHA512));
        assert!(is_allowed_digest_algorithm(DIGEST_SHA512_DSIG_MORE));
        assert!(!is_allowed_digest_algorithm(DIGEST_SHA1));
        assert!(is_allowed_block_encryption_algorithm(ENC_AES256_CBC));
        assert!(!is_allowed_block_encryption_algorithm(
            "http://www.w3.org/2001/04/xmlenc#aes128-cbc"
        ));
        assert!(is_allowed_key_transport_algorithm(KEYTRANSPORT_RSA_OAEP));
        assert!(!is_allowed_key_transport_algorithm(KEYTRANSPORT_RSA_1_5));
    }

    #[test]
    fn test_policy_matches_allow_lists() {
        let policy = algorithm_policy();
        assert!(policy.allows_signature_algorithm(SIG_RSA_SHA512));
        assert!(!policy
            .allows_signature_algorithm("http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256"));
        assert!(!policy.allows_digest_algorithm(DIGEST_SHA1));
    }
}
