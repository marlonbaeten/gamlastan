// DV-side message construction: AuthnRequest (§7.3), ArtifactResolve (§7.5)
// and LogoutRequest (§7.7.1), plus the enveloped-signing helper every one of
// them needs (§7.3 / §7.5 / §7.7.1: "Signature, cardinality 1").
//
// The builders return gamlastan's typed protocol structs; `sign_message_xml`
// turns a serialized message into its signed form by splicing an
// `<ds:Signature>` template after `<saml:Issuer>` (the schema position) and
// signing with `SamlSigner`.

use chrono::Utc;

use crate::core::assertion::issuer::Issuer;
use crate::core::assertion::name_id::{NameId, NameIdOrEncryptedId};
use crate::core::identifiers::{SamlId, SamlVersion};
use crate::core::protocol::artifact::ArtifactResolve;
use crate::core::protocol::logout::LogoutRequest;
use crate::core::protocol::request::{AuthnRequest, Scoping};
use crate::crypto::SamlSigner;
use crate::profiles::sso::sp as sp_profile;
use crate::profiles::sso::web_browser::AuthnRequestOptions as BaseAuthnRequestOptions;
use crate::xml::serialize::SamlSerialize;
use crate::xml::XmlWriter;

use super::authn_context::requested_authn_context;
use super::config::NlEidConfig;
use super::constants;
use super::error::NlEidError;

/// Where the RD should deliver the artifact (§7.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AcsTarget {
    /// `@AssertionConsumerServiceIndex`: refers to an `AssertionConsumerService`
    /// in the DV's registered metadata. This is what §7.3 mandates.
    Index(u16),
    /// `@AssertionConsumerServiceURL` (with `ProtocolBinding` HTTP-Artifact).
    /// §7.3 says the URL "MUST NOT be included"; some RD test environments
    /// accept it for a DV whose metadata is not registered. Never use it
    /// against a production RD.
    Url(String),
}

/// How the AuthnRequest references the service definition (§7.3.1.1).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum ServiceReference {
    /// A `<samlp:Extensions>` block carrying the `IntendedAudience` and
    /// `ServiceUUID` attributes. Allowed for a DV, mandatory for an LC.
    #[default]
    Extensions,
    /// `@AttributeConsumingServiceIndex`, pointing at an
    /// `AttributeConsumingService` in the DV metadata that carries the
    /// `ServiceUUID`. Only a DV may use this.
    AttributeConsumingServiceIndex(u16),
}

/// Options for building an eID `AuthnRequest`.
#[derive(Debug, Clone)]
pub struct NlEidAuthnOptions {
    /// The RD `SingleSignOnService` (HTTP-POST) URL; becomes `@Destination`,
    /// which MUST match the RD metadata (§7.3).
    pub destination: String,

    /// Where the RD delivers the artifact.
    pub acs: AcsTarget,

    /// How the service definition is referenced. Defaults to `Extensions`.
    pub service_reference: ServiceReference,

    /// `@ForceAuthn`. Defaults to `true`: an existing SSO session at the AD MUST
    /// NOT be reused, so every login is a fresh authentication (§7.7).
    pub force_authn: bool,

    /// `<samlp:Scoping>/<samlp:IDPList>` entries: the AD and/or BVD `entityID`s
    /// pre-selected at the DV (§6.4, §7.3). At least one AD when non-empty.
    pub preselected_providers: Vec<String>,

    /// `<samlp:Scoping>/<samlp:RequesterID>` entries: BVD `entityID`s that make
    /// representation mandatory (§7.3).
    pub required_authorization_services: Vec<String>,

    /// `@ProviderName`, reserved for eIDAS outbound; SHOULD NOT be used
    /// otherwise (§7.3).
    pub provider_name: Option<String>,
}

impl NlEidAuthnOptions {
    /// Options for a request to `destination`, delivering the artifact to the
    /// DV's metadata ACS `index`, with `ForceAuthn="true"` and an `Extensions`
    /// service reference.
    pub fn to(destination: impl Into<String>, acs_index: u16) -> Self {
        Self {
            destination: destination.into(),
            acs: AcsTarget::Index(acs_index),
            service_reference: ServiceReference::Extensions,
            force_authn: true,
            preselected_providers: Vec::new(),
            required_authorization_services: Vec::new(),
            provider_name: None,
        }
    }
}

/// Build the `<samlp:Extensions>` block of §7.3: an `IntendedAudience` and a
/// `ServiceUUID` attribute. The block is namespace self-contained.
pub fn extensions_xml(intended_audience: &str, service_uuid: &str) -> String {
    let mut w = XmlWriter::with_capacity(512);
    w.start_element(
        "samlp:Extensions",
        &[
            ("xmlns:samlp", constants::NS_SAML_PROTOCOL),
            ("xmlns:saml", constants::NS_SAML_ASSERTION),
        ],
    );
    for (name, value) in [
        (constants::ATTR_INTENDED_AUDIENCE, intended_audience),
        (constants::ATTR_SERVICE_UUID, service_uuid),
    ] {
        w.start_element("saml:Attribute", &[("Name", name)]);
        w.start_element("saml:AttributeValue", &[]);
        w.text(value);
        w.end_element("saml:AttributeValue");
        w.end_element("saml:Attribute");
    }
    w.end_element("samlp:Extensions");
    w.into_string()
}

/// Build a §7.3 conformant `AuthnRequest` (unsigned; see [`sign_message_xml`]).
///
/// Applies the §7.3 constraints: `@Destination` present, `@ForceAuthn`
/// explicit, exactly one of `Extensions` / `AttributeConsumingServiceIndex`,
/// `RequestedAuthnContext Comparison="minimum"` for the configured minimum LoA,
/// no `NameIDPolicy` (not part of the specification), and the optional
/// `Scoping` for AD/BVD pre-selection.
pub fn build_authn_request(
    cfg: &NlEidConfig,
    opts: &NlEidAuthnOptions,
) -> Result<AuthnRequest, NlEidError> {
    cfg.validate()?;
    if opts.destination.trim().is_empty() {
        return Err(NlEidError::InvalidRequestOptions(
            "Destination (the RD SingleSignOnService URL) is required".to_string(),
        ));
    }
    if let AcsTarget::Url(url) = &opts.acs {
        if url.trim().is_empty() {
            return Err(NlEidError::InvalidRequestOptions(
                "AssertionConsumerServiceURL is empty".to_string(),
            ));
        }
    }

    let (acs_url, acs_index, protocol_binding) = match &opts.acs {
        AcsTarget::Index(i) => (None, Some(*i), None),
        AcsTarget::Url(u) => (
            Some(u.clone()),
            None,
            Some(constants::BINDING_HTTP_ARTIFACT.to_string()),
        ),
    };
    let (extensions, attribute_consuming_service_index) = match &opts.service_reference {
        ServiceReference::Extensions => (
            Some(extensions_xml(cfg.intended_audience(), &cfg.service_uuid)),
            None,
        ),
        ServiceReference::AttributeConsumingServiceIndex(i) => (None, Some(*i)),
    };

    let mut request = sp_profile::create_authn_request(&BaseAuthnRequestOptions {
        sp_entity_id: cfg.entity_id.clone(),
        acs_url,
        acs_index,
        protocol_binding,
        force_authn: Some(opts.force_authn),
        is_passive: None,
        name_id_format: None,
        allow_create: false,
        sp_name_qualifier: None,
        authn_context_class_refs: vec![cfg.minimum_loa.as_request_uri().to_string()],
        authn_context_comparison: Some(
            crate::core::protocol::request::AuthnContextComparison::Minimum,
        ),
        provider_name: opts.provider_name.clone(),
        destination: Some(opts.destination.clone()),
        proxy_count: None,
        requester_ids: opts.required_authorization_services.clone(),
        attribute_consuming_service_index,
        extensions,
    })?;

    // Defensive: the comparison is the whole point of §7.6.3.2.
    request.requested_authn_context = Some(requested_authn_context(cfg.minimum_loa));

    if !opts.preselected_providers.is_empty() {
        let mut scoping = request.scoping.take().unwrap_or(Scoping {
            proxy_count: None,
            idp_list: vec![],
            requester_ids: opts.required_authorization_services.clone(),
        });
        scoping.idp_list = opts.preselected_providers.clone();
        request.scoping = Some(scoping);
    }

    Ok(request)
}

/// Build a §7.5 `ArtifactResolve` for `artifact` (the `SAMLart` query parameter,
/// see [`check_artifact_param`]), addressed to the RD
/// `ArtifactResolutionService` at `ars_url`.
pub fn build_artifact_resolve(
    cfg: &NlEidConfig,
    artifact: &str,
    ars_url: &str,
) -> Result<ArtifactResolve, NlEidError> {
    cfg.validate()?;
    let artifact = check_artifact_param(artifact)?;
    Ok(ArtifactResolve {
        id: SamlId::generate().as_str().to_string(),
        version: SamlVersion::V2_0,
        issue_instant: Utc::now(),
        destination: Some(ars_url.to_string()),
        consent: None,
        issuer: Some(Issuer::entity(&cfg.entity_id)),
        has_signature: false,
        artifact: artifact.to_string(),
    })
}

/// Maximum accepted length of a `SAMLart` value. A SAML type-4 artifact is 60
/// base64 characters; the bound only keeps an attacker-controlled query
/// parameter from being signed into an `ArtifactResolve` unbounded.
pub const MAX_ARTIFACT_CHARS: usize = 512;

/// Validate the raw `SAMLart` query parameter (§7.4) before it is signed into
/// an `ArtifactResolve`: non-empty, bounded, and base64 text (standard or URL
/// alphabet). The value itself is opaque to the DV.
pub fn check_artifact_param(artifact: &str) -> Result<&str, NlEidError> {
    if artifact.is_empty() || artifact.len() > MAX_ARTIFACT_CHARS {
        return Err(NlEidError::MalformedMessage(format!(
            "SAMLart is empty or longer than {MAX_ARTIFACT_CHARS} characters"
        )));
    }
    if !artifact
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'=' | b'-' | b'_'))
    {
        return Err(NlEidError::MalformedMessage(
            "SAMLart is not base64 text".to_string(),
        ));
    }
    Ok(artifact)
}

/// Build a §7.7.1 `LogoutRequest` carrying the TransientID `<saml:NameID>` from
/// the Subject of the original assertion, addressed to the RD
/// `SingleLogoutService` at `destination`.
///
/// Only the elements of the §7.7.1 table are emitted: no `SessionIndex`,
/// `NotOnOrAfter` or `Reason` (§7.2 rule 3).
pub fn build_logout_request(
    cfg: &NlEidConfig,
    transient_name_id: &str,
    destination: &str,
) -> Result<LogoutRequest, NlEidError> {
    cfg.validate()?;
    if transient_name_id.trim().is_empty() {
        return Err(NlEidError::InvalidRequestOptions(
            "the TransientID NameID is empty".to_string(),
        ));
    }
    Ok(LogoutRequest {
        id: SamlId::generate().as_str().to_string(),
        version: SamlVersion::V2_0,
        issue_instant: Utc::now(),
        destination: Some(destination.to_string()),
        consent: None,
        issuer: Some(Issuer::entity(&cfg.entity_id)),
        has_signature: false,
        not_on_or_after: None,
        reason: None,
        name_id: NameIdOrEncryptedId::NameId(NameId {
            value: transient_name_id.to_string(),
            format: Some(constants::NAMEID_TRANSIENT.to_string()),
            name_qualifier: None,
            sp_name_qualifier: None,
            sp_provided_id: None,
        }),
        session_indexes: vec![],
    })
}

/// A serialized, signed message and the `@ID` the caller must remember to
/// correlate the answer (§7.6.1 `InResponseTo`, §7.6.2/§7.6.3.3, §7.7.2).
#[derive(Debug, Clone)]
pub struct SignedMessage {
    /// The message `@ID`.
    pub id: String,
    /// The signed XML document.
    pub xml: String,
}

/// Sign a serialized SAML protocol message with an enveloped RSA-SHA256 /
/// SHA-256 / exclusive-c14n signature (§9.1) whose `<ds:KeyInfo>` carries the
/// DV signing certificate (`cert_der_b64`, §9.2).
///
/// `element_local` is the protocol element being signed (`AuthnRequest`,
/// `ArtifactResolve`, `LogoutRequest`) and `id` its `@ID`; the template is
/// spliced directly after the element's `<saml:Issuer>`.
pub fn sign_message_xml(
    xml: &str,
    element_local: &str,
    id: &str,
    signer: &SamlSigner,
    cert_der_b64: &str,
) -> Result<String, NlEidError> {
    sign_element_xml(
        xml,
        constants::NS_SAML_PROTOCOL,
        element_local,
        id,
        signer,
        cert_der_b64,
    )
}

/// Like [`sign_message_xml`] for an element in an arbitrary namespace (e.g. a
/// `saml:Assertion` when building RD-side test messages). The template is
/// spliced after the element's `<saml:Issuer>`.
pub fn sign_element_xml(
    xml: &str,
    element_ns: &str,
    element_local: &str,
    id: &str,
    signer: &SamlSigner,
    cert_der_b64: &str,
) -> Result<String, NlEidError> {
    let method = signer.signature_method_uri()?;
    if !constants::is_allowed_signature_algorithm(method) {
        return Err(NlEidError::DisallowedAlgorithm {
            kind: "signature",
            uri: method.to_string(),
        });
    }
    let template = crate::profiles::sso::idp::signature_template(id, cert_der_b64, method);
    let with_template = crate::profiles::sso::idp::insert_signature_after_issuer(
        xml,
        element_ns,
        element_local,
        id,
        &template,
    )?;
    Ok(signer.sign_enveloped(&with_template)?)
}

/// Build, serialize and sign an `AuthnRequest` in one step.
pub fn signed_authn_request(
    cfg: &NlEidConfig,
    opts: &NlEidAuthnOptions,
    signer: &SamlSigner,
    cert_der_b64: &str,
) -> Result<SignedMessage, NlEidError> {
    let request = build_authn_request(cfg, opts)?;
    let xml = request.to_xml_string()?;
    let xml = sign_message_xml(&xml, "AuthnRequest", &request.base.id, signer, cert_der_b64)?;
    Ok(SignedMessage {
        id: request.base.id,
        xml,
    })
}

/// Build, serialize and sign an `ArtifactResolve` in one step. Wrap the result
/// with [`crate::bindings::soap::soap_envelope_wrap`] for the back-channel.
pub fn signed_artifact_resolve(
    cfg: &NlEidConfig,
    artifact: &str,
    ars_url: &str,
    signer: &SamlSigner,
    cert_der_b64: &str,
) -> Result<SignedMessage, NlEidError> {
    let resolve = build_artifact_resolve(cfg, artifact, ars_url)?;
    let xml = resolve.to_xml_string()?;
    let xml = sign_message_xml(&xml, "ArtifactResolve", &resolve.id, signer, cert_der_b64)?;
    Ok(SignedMessage {
        id: resolve.id,
        xml,
    })
}

/// Build, serialize and sign a `LogoutRequest` in one step.
pub fn signed_logout_request(
    cfg: &NlEidConfig,
    transient_name_id: &str,
    destination: &str,
    signer: &SamlSigner,
    cert_der_b64: &str,
) -> Result<SignedMessage, NlEidError> {
    let request = build_logout_request(cfg, transient_name_id, destination)?;
    let xml = request.to_xml_string()?;
    let xml = sign_message_xml(&xml, "LogoutRequest", &request.id, signer, cert_der_b64)?;
    Ok(SignedMessage {
        id: request.id,
        xml,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::protocol::request::AuthnContextComparison;
    use crate::profiles::nl_eid::authn_context::LevelOfAssurance;

    const DV: &str = "urn:nl-eid-gdi:1.0:DV:00000001234567890000:entities:9001";
    const RD: &str = "urn:nl-eid-gdi:1.0:RD:00000004000000149000:entities:9002";
    const UUID: &str = "f847dc11-ac24-47b2-84a8-a057440ce56d";

    fn cfg() -> NlEidConfig {
        NlEidConfig::service_provider(
            DV,
            UUID,
            "https://dv.example.nl/saml/acs",
            RD,
            LevelOfAssurance::Low,
        )
    }

    #[test]
    fn test_basic_request_shape() {
        let req = build_authn_request(&cfg(), &NlEidAuthnOptions::to("https://rd.example/sso", 0))
            .unwrap();
        assert_eq!(req.base.issuer.as_ref().unwrap().value, DV);
        assert_eq!(
            req.base.destination.as_deref(),
            Some("https://rd.example/sso")
        );
        assert_eq!(req.force_authn, Some(true));
        assert_eq!(req.assertion_consumer_service_index, Some(0));
        assert!(req.assertion_consumer_service_url.is_none());
        assert!(req.protocol_binding.is_none());
        assert!(req.name_id_policy.is_none(), "NameIDPolicy is not in §7.3");
        assert!(req.attribute_consuming_service_index.is_none());
        assert!(req.scoping.is_none());
        let rac = req.requested_authn_context.as_ref().unwrap();
        assert_eq!(rac.comparison, AuthnContextComparison::Minimum);
        assert_eq!(rac.authn_context_class_refs, vec![constants::LOA_LOW]);
        let ext = req.extensions.as_deref().unwrap();
        assert!(ext.contains(constants::ATTR_INTENDED_AUDIENCE));
        assert!(ext.contains(constants::ATTR_SERVICE_UUID));
        assert!(ext.contains(DV));
        assert!(ext.contains(UUID));

        // Serializes with Extensions after Issuer and before RequestedAuthnContext.
        let xml = req.to_xml_string().unwrap();
        let issuer = xml.find("</saml:Issuer>").unwrap();
        let ext_at = xml.find("<samlp:Extensions").unwrap();
        let rac_at = xml.find("<samlp:RequestedAuthnContext").unwrap();
        assert!(issuer < ext_at && ext_at < rac_at, "{xml}");
        assert!(xml.contains(r#"Comparison="minimum""#));
    }

    #[test]
    fn test_acs_url_variant_and_attribute_consuming_service() {
        let mut opts = NlEidAuthnOptions::to("https://rd.example/sso", 0);
        opts.acs = AcsTarget::Url("https://dv.example.nl/saml/acs".into());
        opts.service_reference = ServiceReference::AttributeConsumingServiceIndex(0);
        let req = build_authn_request(&cfg(), &opts).unwrap();
        assert!(req.assertion_consumer_service_index.is_none());
        assert_eq!(
            req.assertion_consumer_service_url.as_deref(),
            Some("https://dv.example.nl/saml/acs")
        );
        assert_eq!(
            req.protocol_binding.as_deref(),
            Some(constants::BINDING_HTTP_ARTIFACT)
        );
        assert!(
            req.extensions.is_none(),
            "exactly one of Extensions / ACS index"
        );
        assert_eq!(req.attribute_consuming_service_index, Some(0));
    }

    #[test]
    fn test_scoping() {
        let mut opts = NlEidAuthnOptions::to("https://rd.example/sso", 0);
        opts.preselected_providers = vec!["urn:nl-eid-gdi:1.0:AD:1:entities:0001".into()];
        opts.required_authorization_services =
            vec!["urn:nl-eid-gdi:1.0:BVD:2:entities:0001".into()];
        let req = build_authn_request(&cfg(), &opts).unwrap();
        let scoping = req.scoping.unwrap();
        assert_eq!(scoping.idp_list.len(), 1);
        assert_eq!(scoping.requester_ids.len(), 1);
        assert!(scoping.proxy_count.is_none());
    }

    #[test]
    fn test_rejects_missing_destination() {
        let mut opts = NlEidAuthnOptions::to("", 0);
        assert!(matches!(
            build_authn_request(&cfg(), &opts),
            Err(NlEidError::InvalidRequestOptions(_))
        ));
        opts.destination = "https://rd.example/sso".into();
        opts.acs = AcsTarget::Url(String::new());
        assert!(build_authn_request(&cfg(), &opts).is_err());
    }

    #[test]
    fn test_intended_audience_override() {
        let mut c = cfg();
        c.intended_audience = Some("urn:nl-eid-gdi:1.0:DV:9:entities:0002".into());
        let req =
            build_authn_request(&c, &NlEidAuthnOptions::to("https://rd.example/sso", 0)).unwrap();
        assert!(req
            .extensions
            .as_deref()
            .unwrap()
            .contains("urn:nl-eid-gdi:1.0:DV:9:entities:0002"));
    }

    #[test]
    fn test_extensions_xml_escapes() {
        let xml = extensions_xml("a&b", "<uuid>");
        assert!(xml.contains("a&amp;b"));
        assert!(xml.contains("&lt;uuid&gt;"));
        assert!(crate::xml::parse_secure(&xml).is_ok());
    }

    #[test]
    fn test_artifact_resolve() {
        let r = build_artifact_resolve(
            &cfg(),
            "AAQAAMh48/1oXIM+sDo7Dh2qMp1HM4IF5DaRNmDj6auzddOYoLXh0LA5NA==",
            "https://rd.example/ars",
        )
        .unwrap();
        assert_eq!(r.destination.as_deref(), Some("https://rd.example/ars"));
        assert_eq!(r.issuer.as_ref().unwrap().value, DV);
        assert!(r.to_xml_string().unwrap().contains("samlp:Artifact"));

        assert!(build_artifact_resolve(&cfg(), "", "https://rd.example/ars").is_err());
        assert!(build_artifact_resolve(&cfg(), "not base64!", "https://rd.example/ars").is_err());
        assert!(
            build_artifact_resolve(&cfg(), &"A".repeat(600), "https://rd.example/ars").is_err()
        );
    }

    #[test]
    fn test_logout_request() {
        let r = build_logout_request(&cfg(), "transient-1", "https://rd.example/slo").unwrap();
        assert!(r.not_on_or_after.is_none());
        assert!(r.reason.is_none());
        assert!(r.session_indexes.is_empty());
        match r.name_id {
            NameIdOrEncryptedId::NameId(n) => {
                assert_eq!(n.value, "transient-1");
                assert_eq!(n.format.as_deref(), Some(constants::NAMEID_TRANSIENT));
            }
            _ => panic!("plain NameID expected"),
        }
        assert!(build_logout_request(&cfg(), "  ", "https://rd.example/slo").is_err());
    }
}
