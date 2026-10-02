//! # Dutch eID SAML interface (Koppelvlakspecificatie eID SAML v4.4)
//!
//! An implementation of the Dienstverlener (DV, Service Provider) side of the
//! [Koppelvlakspecificatie eID SAML v4.4](https://tvs.dictu.nl/documentatie-en-links/koppelvlakspecificatie)
//! (Logius), the interface between a service provider and a Routeringsdienst
//! (RD) such as TVS, which routes to the Dutch authentication services (DigiD,
//! eHerkenning, eIDAS). It is layered on the SAML V2.0 Web Browser SSO and
//! Artifact Resolution profiles that live in [`crate::profiles::sso`] and
//! [`crate::profiles::artifact_resolution`].
//!
//! The specification is a *restriction and extension* of Web Browser SSO with
//! an unusual message flow: the `AuthnRequest` goes out over HTTP-POST, the RD
//! answers with an **artifact** (HTTP-Artifact), and the DV resolves it over a
//! mutually authenticated SOAP back-channel into an RD-signed
//! `ArtifactResponse` → `Response` → `Assertion` chain whose identifiers
//! (BSN / pseudonym) are the only encrypted parts. This module provides:
//!
//! - [`constants`] — namespaces, bindings, eID attribute names, §10.1
//!   identifier types, §10.3 Levels of Assurance, §7.8 status codes and the
//!   §9.1 / §9.3 algorithm allow-lists.
//! - [`config::NlEidConfig`] — the DV deployment configuration, yielding a
//!   profile-correct [`crate::security::config::SecurityConfig`].
//! - [`authn_context`] — the ordered [`authn_context::LevelOfAssurance`], the
//!   `Comparison="minimum"` `RequestedAuthnContext`, and the §7.6.3.2 check.
//! - [`entity_id`] — the §10.2 `urn:nl-eid-gdi:1.0:<ROLE>:<OIN>:entities:<index>`
//!   identifier format.
//! - [`request`] — `AuthnRequest` (§7.3), `ArtifactResolve` (§7.5) and
//!   `LogoutRequest` (§7.7.1) construction and enveloped signing.
//! - [`response`] — processing of the resolved `ArtifactResponse` (§7.6):
//!   signature verification bound to the consumed elements, the §7.6.3.5
//!   processing rules, Level-of-Assurance and `ServiceUUID` binding, and
//!   `EncryptedID` decryption into zeroized [`response::SubjectId`]s.
//! - [`metadata`] — the DV SP metadata document (§8.3) and a reader for the RD
//!   IdP metadata (§8.5) that yields the endpoints and a `KeysManager` keyed by
//!   `<ds:KeyName>`.
//! - [`logout`] — `LogoutResponse` validation (§7.7.2).
//!
//! ## Scope
//!
//! The DV role is covered in full. The Leverancier Clusteraansluiting (LC,
//! cluster connection provider, §6.3 / §8.4) role is not modelled; the
//! `IntendedAudience` is configurable so an LC can be layered on later. The
//! parts of a DV deployment that are *not* SAML — the PKIoverheid chain and
//! OIN checks on the RD metadata certificates (§9.1, §9.2), the mutual-TLS
//! back-channel transport (§9.4), the pending-request store that is consumed
//! on a successful login (§9.7), and the browser flow binding — are left to the
//! embedding application, which supplies verified trust material through
//! [`crate::crypto::SamlVerifier`] / [`crate::crypto::SamlDecryptor`].

pub mod authn_context;
pub mod config;
pub mod constants;
pub mod entity_id;
pub mod error;
pub mod logout;
pub mod metadata;
pub mod request;
pub mod response;
mod xmlutil;

pub use authn_context::{requested_authn_context, validate_level_of_assurance, LevelOfAssurance};
pub use config::NlEidConfig;
pub use entity_id::{EidEntityId, ParticipantRole};
pub use error::NlEidError;
pub use logout::{validate_logout_response, LogoutResponseOutcome};
pub use metadata::{
    build_dv_metadata, key_name_for_certificate, parse_rd_metadata, DvMetadataOptions,
    PublishedCertificate, RdMetadata, RdSigningKey,
};
pub use request::{
    build_artifact_resolve, build_authn_request, build_logout_request, check_artifact_param,
    sign_element_xml, sign_message_xml, signed_artifact_resolve, signed_authn_request,
    signed_logout_request, AcsTarget, NlEidAuthnOptions, ServiceReference, SignedMessage,
};
pub use response::{
    process_artifact_response, ArtifactResponseParams, AuthnOutcome, DvDecryptionKeys,
    IdentifierType, NlEidAuthnResult, SubjectId,
};
