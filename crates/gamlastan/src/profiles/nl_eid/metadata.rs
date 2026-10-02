// Metadata (§8): the DV SP metadata document (§8.3) and a reader for the RD
// IdP metadata (§8.5).
//
// Keys are identified by `<ds:KeyName>` throughout the eID framework (§9.2):
// an RD signature names its key, and the DV must find that name among the
// `<md:KeyDescriptor>`s of the RD's *verified* metadata. The TVS convention
// is the lowercase hex SHA-1 fingerprint of the certificate; the DV publishes
// its own keys the same way.

use base64::Engine;
use chrono::{DateTime, Utc};

use crate::core::assertion::attribute::{Attribute, AttributeValue};
use crate::crypto::keys::loader;
use crate::crypto::{KeyUsage, KeysManager, SamlSigner, SamlVerifier};
use crate::metadata::types::endpoint::{Endpoint, IndexedEndpoint};
use crate::metadata::types::entity_descriptor::{
    EntityDescriptor, EntityDescriptorRef, EntityRoles,
};
use crate::metadata::types::idp::IdpSsoDescriptor;
use crate::metadata::types::key_descriptor::KeyDescriptor;
use crate::metadata::types::localized::LocalizedName;
use crate::metadata::types::role_descriptor::{RoleDescriptorBase, SsoDescriptorBase};
use crate::metadata::types::sp::{AttributeConsumingService, RequestedAttribute, SpSsoDescriptor};
use crate::xml::deserialize::parse_saml;
use crate::xml::serialize::SamlSerialize;
use crate::xml::XmlWriter;

use super::config::NlEidConfig;
use super::constants;
use super::error::NlEidError;
use super::xmlutil;

// ── Key naming ──────────────────────────────────────────────────────────────

/// The `<ds:KeyName>` for a certificate: the lowercase hex SHA-1 fingerprint
/// of its DER encoding (the TVS / eID convention; §8.3 "the name which
/// identifies the key").
pub fn key_name_for_certificate(cert_der: &[u8]) -> String {
    crate::crypto::digest::sha1(cert_der)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// A certificate as published in a `<md:KeyDescriptor>`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublishedCertificate {
    /// The `<ds:KeyName>`.
    pub key_name: String,
    /// The base64 DER certificate (`<ds:X509Certificate>` content).
    pub cert_der_b64: String,
}

impl PublishedCertificate {
    /// From a DER certificate, named by its SHA-1 fingerprint.
    pub fn from_der(cert_der: &[u8]) -> Self {
        Self {
            key_name: key_name_for_certificate(cert_der),
            cert_der_b64: base64::engine::general_purpose::STANDARD.encode(cert_der),
        }
    }

    /// From a PEM certificate, named by its SHA-1 fingerprint.
    pub fn from_pem(cert_pem: &str) -> Result<Self, NlEidError> {
        let key = loader::load_x509_cert_pem(cert_pem.as_bytes())
            .map_err(crate::crypto::CryptoError::BergshamraError)?;
        let der = key.x509_chain.first().ok_or_else(|| {
            NlEidError::Config("PEM did not yield an X.509 certificate".to_string())
        })?;
        Ok(Self::from_der(der))
    }

    /// The `<ds:KeyInfo>` carrying this certificate's `KeyName` and `X509Data`
    /// (§8.3: both are required).
    pub fn key_info_xml(&self) -> String {
        let mut w = XmlWriter::with_capacity(256 + self.cert_der_b64.len());
        w.start_element("ds:KeyInfo", &[("xmlns:ds", constants::NS_DS)]);
        w.start_element("ds:KeyName", &[]);
        w.text(&self.key_name);
        w.end_element("ds:KeyName");
        w.start_element("ds:X509Data", &[]);
        w.start_element("ds:X509Certificate", &[]);
        w.text(&self.cert_der_b64);
        w.end_element("ds:X509Certificate");
        w.end_element("ds:X509Data");
        w.end_element("ds:KeyInfo");
        w.into_string()
    }
}

// ── DV metadata (§8.3) ──────────────────────────────────────────────────────

/// Inputs for the DV SP metadata document (§8.3).
#[derive(Debug, Clone)]
pub struct DvMetadataOptions {
    /// The DV `entityID`.
    pub entity_id: String,
    /// The document `@ID` the signature references. Generated when `None`.
    pub id: Option<String>,
    /// The `AssertionConsumerService` URL (HTTP-Artifact binding, index 0,
    /// default).
    pub acs_url: String,
    /// The `SingleLogoutService` URL (HTTP-POST binding), required when the DV
    /// supports SSO.
    pub single_logout_url: Option<String>,
    /// The `<md:ServiceName>` shown for the service.
    pub service_name: String,
    /// `xml:lang` of the service name. Defaults to `nl-NL`.
    pub service_name_lang: String,
    /// The `ServiceUUID` published as the `RequestedAttribute` of the
    /// `AttributeConsumingService` (index 0, default).
    pub service_uuid: String,
    /// `use="signing"` certificates: the SAML signing certificate(s) and, per
    /// §8.3, the mTLS client certificate when it differs. At least one.
    pub signing_certificates: Vec<PublishedCertificate>,
    /// `use="encryption"` certificates (at least one; a second for rollover).
    pub encryption_certificates: Vec<PublishedCertificate>,
    /// `@cacheDuration` (ISO 8601 duration). Defaults to `PT24H`. Either this
    /// or `valid_until` MUST be present.
    pub cache_duration: Option<String>,
    /// `@validUntil`.
    pub valid_until: Option<DateTime<Utc>>,
}

impl DvMetadataOptions {
    /// Options derived from a [`NlEidConfig`], with `PT24H` caching and no
    /// certificates yet.
    pub fn from_config(cfg: &NlEidConfig, service_name: impl Into<String>) -> Self {
        Self {
            entity_id: cfg.entity_id.clone(),
            id: None,
            acs_url: cfg.acs_url.clone(),
            single_logout_url: cfg.single_logout_url.clone(),
            service_name: service_name.into(),
            service_name_lang: "nl-NL".to_string(),
            service_uuid: cfg.service_uuid.clone(),
            signing_certificates: Vec::new(),
            encryption_certificates: Vec::new(),
            cache_duration: Some("PT24H".to_string()),
            valid_until: None,
        }
    }

    fn validate(&self) -> Result<(), NlEidError> {
        if self.entity_id.trim().is_empty() {
            return Err(NlEidError::Config(
                "metadata entity_id is empty".to_string(),
            ));
        }
        if self.acs_url.trim().is_empty() {
            return Err(NlEidError::Config("metadata acs_url is empty".to_string()));
        }
        if self.service_name.trim().is_empty() {
            return Err(NlEidError::Config(
                "metadata service_name is empty".to_string(),
            ));
        }
        if self.service_uuid.trim().is_empty() {
            return Err(NlEidError::Config(
                "metadata service_uuid is empty".to_string(),
            ));
        }
        if self.signing_certificates.is_empty() {
            return Err(NlEidError::Config(
                "§8.3 requires at least one use=\"signing\" KeyDescriptor".to_string(),
            ));
        }
        if self.encryption_certificates.is_empty() {
            return Err(NlEidError::Config(
                "§8.3 requires at least one use=\"encryption\" KeyDescriptor".to_string(),
            ));
        }
        if self.cache_duration.is_none() && self.valid_until.is_none() {
            return Err(NlEidError::Config(
                "§8.3 requires validUntil or cacheDuration".to_string(),
            ));
        }
        Ok(())
    }
}

/// Build the typed DV `EntityDescriptor` of §8.3 (unsigned).
pub fn build_dv_entity_descriptor(
    opts: &DvMetadataOptions,
) -> Result<EntityDescriptor, NlEidError> {
    opts.validate()?;
    let id = opts.id.clone().unwrap_or_else(|| {
        crate::core::identifiers::SamlId::generate()
            .as_str()
            .to_string()
    });

    let mut key_descriptors: Vec<KeyDescriptor> = opts
        .signing_certificates
        .iter()
        .map(|c| KeyDescriptor::signing(c.key_info_xml()))
        .collect();
    key_descriptors.extend(
        opts.encryption_certificates
            .iter()
            .map(|c| KeyDescriptor::encryption(c.key_info_xml())),
    );

    let single_logout_services = opts
        .single_logout_url
        .iter()
        .map(|url| Endpoint {
            binding: constants::BINDING_HTTP_POST.to_string(),
            location: url.clone(),
            response_location: None,
        })
        .collect();

    let sp = SpSsoDescriptor {
        sso_base: SsoDescriptorBase {
            base: RoleDescriptorBase {
                id: None,
                valid_until: None,
                cache_duration: None,
                protocol_support_enumeration: vec![constants::NS_SAML_PROTOCOL.to_string()],
                error_url: None,
                extensions: None,
                key_descriptors,
                organization: None,
                contact_persons: vec![],
            },
            artifact_resolution_services: vec![],
            single_logout_services,
            manage_name_id_services: vec![],
            name_id_formats: vec![],
        },
        authn_requests_signed: Some(true),
        want_assertions_signed: Some(true),
        assertion_consumer_services: vec![IndexedEndpoint {
            endpoint: Endpoint {
                binding: constants::BINDING_HTTP_ARTIFACT.to_string(),
                location: opts.acs_url.clone(),
                response_location: None,
            },
            index: 0,
            is_default: Some(true),
        }],
        attribute_consuming_services: vec![AttributeConsumingService {
            index: 0,
            is_default: Some(true),
            service_names: vec![LocalizedName {
                lang: opts.service_name_lang.clone(),
                value: opts.service_name.clone(),
            }],
            service_descriptions: vec![],
            requested_attributes: vec![RequestedAttribute {
                attribute: Attribute {
                    name: constants::ATTR_SERVICE_UUID.to_string(),
                    name_format: None,
                    friendly_name: None,
                    values: vec![AttributeValue::String(opts.service_uuid.clone())],
                },
                is_required: None,
            }],
        }],
    };

    Ok(EntityDescriptor {
        entity_id: opts.entity_id.clone(),
        id: Some(id),
        valid_until: opts.valid_until,
        cache_duration: opts.cache_duration.clone(),
        has_signature: false,
        extensions: None,
        roles: EntityRoles::Roles {
            idp_sso: vec![],
            sp_sso: vec![sp],
            authn_authority: vec![],
            attr_authority: vec![],
            pdp: vec![],
        },
        organization: None,
        contact_persons: vec![],
        additional_metadata_locations: vec![],
    })
}

/// Build and sign the DV metadata document (§8.3: enveloped signature over the
/// `EntityDescriptor`, referenced by its `@ID`, `<ds:KeyInfo>` carrying the
/// signing certificate `cert_der_b64`).
pub fn build_dv_metadata(
    opts: &DvMetadataOptions,
    signer: &SamlSigner,
    cert_der_b64: &str,
) -> Result<String, NlEidError> {
    let descriptor = build_dv_entity_descriptor(opts)?;
    let id = descriptor
        .id
        .clone()
        .ok_or_else(|| NlEidError::Config("metadata ID missing".to_string()))?;
    let xml = descriptor.to_xml_string()?;
    let method = signer.signature_method_uri()?;
    if !constants::is_allowed_signature_algorithm(method) {
        return Err(NlEidError::DisallowedAlgorithm {
            kind: "signature",
            uri: method.to_string(),
        });
    }
    let template = crate::profiles::sso::idp::signature_template(&id, cert_der_b64, method);
    let with_template = xmlutil::insert_signature_as_first_child(&xml, &template)?;
    Ok(signer.sign_enveloped(&with_template)?)
}

// ── RD metadata (§8.5) ──────────────────────────────────────────────────────

/// An RD signing certificate from its metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RdSigningKey {
    /// The `<ds:KeyName>` the RD uses in its signatures. Taken from the
    /// `<md:KeyDescriptor>`; when the descriptor carries none, the SHA-1
    /// fingerprint convention is assumed.
    pub key_name: String,
    /// Whether `key_name` was present in the metadata (as opposed to derived).
    pub key_name_declared: bool,
    /// The DER certificate.
    pub cert_der: Vec<u8>,
}

/// The parts of the RD IdP metadata (§8.5) a DV needs.
///
/// Produced by [`parse_rd_metadata`] / [`RdMetadata::from_entity_descriptor`].
/// **This reader does not establish trust in the document**: the metadata
/// signature, the PKIoverheid chain and the OIN of the signing certificates
/// (§9.1, §9.2) and the pinning of the endpoint hosts are the embedding
/// application's job before this structure is used.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RdMetadata {
    /// The RD `entityID`.
    pub entity_id: String,
    /// `SingleSignOnService` with the HTTP-POST binding (the only one §8.5
    /// allows).
    pub sso_url: String,
    /// `ArtifactResolutionService` with the SOAP binding: the default one, or
    /// the lowest index.
    pub artifact_resolution_url: String,
    /// The `@index` of [`artifact_resolution_url`](Self::artifact_resolution_url).
    pub artifact_resolution_index: u16,
    /// `SingleLogoutService` with the HTTP-POST binding.
    pub single_logout_url: String,
    /// The `use="signing"` (or unspecified-use) certificates.
    pub signing_keys: Vec<RdSigningKey>,
    /// `@validUntil` (entity or role level).
    pub valid_until: Option<DateTime<Utc>>,
    /// `@cacheDuration` (entity or role level).
    pub cache_duration: Option<String>,
}

impl RdMetadata {
    /// Read the §8.5 fields from a parsed `EntityDescriptor`, enforcing its
    /// mandatory elements: one `IDPSSODescriptor` with
    /// `WantAuthnRequestsSigned="true"`, `validUntil` or `cacheDuration`, at
    /// least one signing certificate, an HTTP-POST SSO endpoint, a SOAP
    /// artifact-resolution endpoint and an HTTP-POST logout endpoint.
    pub fn from_entity_descriptor(ed: &EntityDescriptor) -> Result<Self, NlEidError> {
        let entity_id = ed.entity_id.trim();
        if entity_id.is_empty() {
            return Err(NlEidError::Metadata("entityID is empty".to_string()));
        }
        let idp = single_idp_descriptor(ed)?;
        if idp.want_authn_requests_signed != Some(true) {
            return Err(NlEidError::Metadata(
                "IDPSSODescriptor must declare WantAuthnRequestsSigned=\"true\"".to_string(),
            ));
        }
        let valid_until = ed.valid_until.or(idp.sso_base.base.valid_until);
        let cache_duration = ed
            .cache_duration
            .clone()
            .or_else(|| idp.sso_base.base.cache_duration.clone());
        if valid_until.is_none() && cache_duration.is_none() {
            return Err(NlEidError::Metadata(
                "either validUntil or cacheDuration must be present".to_string(),
            ));
        }

        let sso_url = idp
            .single_sign_on_services
            .iter()
            .find(|e| e.binding == constants::BINDING_HTTP_POST)
            .map(|e| e.location.clone())
            .ok_or_else(|| {
                NlEidError::Metadata(
                    "no SingleSignOnService with the HTTP-POST binding".to_string(),
                )
            })?;
        let ars = select_artifact_resolution_service(&idp.sso_base.artifact_resolution_services)?;
        let single_logout_url = idp
            .sso_base
            .single_logout_services
            .iter()
            .find(|e| e.binding == constants::BINDING_HTTP_POST)
            .map(|e| e.location.clone())
            .ok_or_else(|| {
                NlEidError::Metadata(
                    "no SingleLogoutService with the HTTP-POST binding".to_string(),
                )
            })?;

        let mut signing_keys = Vec::new();
        for kd in &idp.sso_base.base.key_descriptors {
            if !kd.can_sign() {
                continue;
            }
            let declared_name = key_name_from_key_info(&kd.key_info_xml);
            let certs = kd.x509_certificates_der();
            if certs.is_empty() {
                return Err(NlEidError::Metadata(
                    "a signing KeyDescriptor carries no X509Certificate".to_string(),
                ));
            }
            for cert_der in certs {
                let (key_name, key_name_declared) = match &declared_name {
                    Some(n) => (n.clone(), true),
                    None => (key_name_for_certificate(&cert_der), false),
                };
                signing_keys.push(RdSigningKey {
                    key_name,
                    key_name_declared,
                    cert_der,
                });
            }
        }
        if signing_keys.is_empty() {
            return Err(NlEidError::Metadata(
                "no signing KeyDescriptor with a certificate".to_string(),
            ));
        }

        Ok(Self {
            entity_id: entity_id.to_string(),
            sso_url,
            artifact_resolution_url: ars.endpoint.location.clone(),
            artifact_resolution_index: ars.index,
            single_logout_url,
            signing_keys,
            valid_until,
            cache_duration,
        })
    }

    /// Whether `validUntil`, when present, lies in the future at `now` (§8.2:
    /// expired metadata MUST NOT be used).
    pub fn is_valid_at(&self, now: DateTime<Utc>) -> bool {
        self.valid_until.is_none_or(|vu| vu > now)
    }

    /// A `KeysManager` holding exactly the RD signing certificates, each as a
    /// verification key named by its `<ds:KeyName>` and as a trust anchor, so
    /// `<ds:KeyInfo>/<ds:KeyName>` in RD signatures resolves to the right key
    /// (§9.2) and nothing else verifies.
    pub fn keys_manager(&self) -> Result<KeysManager, NlEidError> {
        let mut km = KeysManager::new();
        for key in &self.signing_keys {
            let mut k = loader::load_x509_cert_der(&key.cert_der)
                .map_err(crate::crypto::CryptoError::BergshamraError)?
                .with_name(key.key_name.clone());
            k.usage = KeyUsage::Verify;
            km.add_key(k);
            km.add_trusted_cert(key.cert_der.clone());
        }
        Ok(km)
    }

    /// A [`SamlVerifier`] over [`keys_manager`](Self::keys_manager) with the
    /// §9.1 algorithm policy and gamlastan's secure defaults (trusted keys only,
    /// strict reference positions, E91).
    pub fn verifier(&self) -> Result<SamlVerifier, NlEidError> {
        Ok(SamlVerifier::new(self.keys_manager()?)
            .with_algorithm_policy(constants::algorithm_policy()))
    }
}

fn single_idp_descriptor(ed: &EntityDescriptor) -> Result<&IdpSsoDescriptor, NlEidError> {
    match &ed.roles {
        EntityRoles::Roles { idp_sso, .. } => match idp_sso.as_slice() {
            [idp] => Ok(idp),
            other => Err(NlEidError::Metadata(format!(
                "expected exactly one IDPSSODescriptor, found {}",
                other.len()
            ))),
        },
        EntityRoles::Affiliation(_) => Err(NlEidError::Metadata(
            "RD metadata is an AffiliationDescriptor".to_string(),
        )),
    }
}

fn select_artifact_resolution_service(
    services: &[IndexedEndpoint],
) -> Result<&IndexedEndpoint, NlEidError> {
    let soap: Vec<&IndexedEndpoint> = services
        .iter()
        .filter(|e| e.endpoint.binding == constants::BINDING_SOAP)
        .collect();
    if soap.is_empty() {
        return Err(NlEidError::Metadata(
            "no ArtifactResolutionService with the SOAP binding".to_string(),
        ));
    }
    let mut seen = std::collections::HashSet::new();
    for e in &soap {
        if !seen.insert(e.index) {
            return Err(NlEidError::Metadata(format!(
                "ArtifactResolutionService index {} is not unique",
                e.index
            )));
        }
    }
    Ok(soap
        .iter()
        .find(|e| e.is_default == Some(true))
        .or_else(|| soap.iter().min_by_key(|e| e.index))
        .copied()
        .expect("non-empty"))
}

/// The `<ds:KeyName>` inside a raw `<ds:KeyInfo>` fragment, if any. The
/// fragment may rely on an `xmlns:ds` declared on an ancestor, so the
/// conventional prefix is pre-declared on a wrapper.
fn key_name_from_key_info(key_info_xml: &str) -> Option<String> {
    if key_info_xml.trim().is_empty() {
        return None;
    }
    let wrapped = format!(
        r#"<w xmlns:ds="{}" xmlns:dsig="{}" xmlns:md="{}">{key_info_xml}</w>"#,
        constants::NS_DS,
        constants::NS_DS,
        constants::NS_MD
    );
    let doc = crate::xml::parse_secure_metadata(&wrapped).ok()?;
    let root = doc.document_element()?;
    let key_info = xmlutil::element_child(&doc, root, constants::NS_DS, "KeyInfo")?;
    let key_name = xmlutil::element_child(&doc, key_info, constants::NS_DS, "KeyName")?;
    xmlutil::text_only(&doc, key_name).filter(|s| !s.is_empty())
}

/// Parse an RD IdP metadata document (§8.5) into [`RdMetadata`].
///
/// The signature on the document is **not** verified here; see [`RdMetadata`].
pub fn parse_rd_metadata(xml: &str) -> Result<RdMetadata, NlEidError> {
    let doc = crate::xml::parse_secure_metadata(xml)?;
    let ed = parse_saml::<EntityDescriptorRef<'_>>(&doc)?.to_owned();
    RdMetadata::from_entity_descriptor(&ed)
}

#[cfg(test)]
mod tests {
    use super::*;

    const RD: &str = "urn:nl-eid-gdi:1.0:RD:00000004000000149000:entities:9002";
    // A tiny self-signed test certificate is not available without a fixture;
    // the DER here is a deterministic stand-in only used for naming/encoding.
    const FAKE_DER: &[u8] = b"not really a certificate";

    fn rd_metadata_xml(key_info: &str, extra_attrs: &str, slo: bool) -> String {
        let slo = if slo {
            format!(
                r#"<md:SingleLogoutService Binding="{}" Location="https://rd.example/slo"/>"#,
                constants::BINDING_HTTP_POST
            )
        } else {
            String::new()
        };
        format!(
            r#"<md:EntityDescriptor xmlns:md="{}" xmlns:ds="{}" entityID="{RD}" ID="_rd" {extra_attrs}>
  <md:IDPSSODescriptor WantAuthnRequestsSigned="true" protocolSupportEnumeration="{}">
    <md:KeyDescriptor use="signing">{key_info}</md:KeyDescriptor>
    <md:ArtifactResolutionService Binding="{}" Location="https://rd.example/ars2" index="1"/>
    <md:ArtifactResolutionService Binding="{}" Location="https://rd.example/ars" index="0"/>
    {slo}
    <md:SingleSignOnService Binding="{}" Location="https://rd.example/sso-redirect"/>
    <md:SingleSignOnService Binding="{}" Location="https://rd.example/sso"/>
  </md:IDPSSODescriptor>
</md:EntityDescriptor>"#,
            constants::NS_MD,
            constants::NS_DS,
            constants::NS_SAML_PROTOCOL,
            constants::BINDING_SOAP,
            constants::BINDING_SOAP,
            "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
            constants::BINDING_HTTP_POST,
        )
    }

    #[test]
    fn test_key_name_is_lowercase_sha1_hex() {
        let name = key_name_for_certificate(b"hello");
        assert_eq!(name, "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d");
        let published = PublishedCertificate::from_der(FAKE_DER);
        assert_eq!(published.key_name, key_name_for_certificate(FAKE_DER));
        assert_eq!(
            published.cert_der_b64,
            base64::engine::general_purpose::STANDARD.encode(FAKE_DER)
        );
        let ki = published.key_info_xml();
        assert!(ki.contains("<ds:KeyName>"));
        assert!(ki.contains("<ds:X509Certificate>"));
        assert_eq!(
            key_name_from_key_info(&ki).as_deref(),
            Some(published.key_name.as_str())
        );
    }

    #[test]
    fn test_dv_metadata_shape() {
        let cfg = NlEidConfig::service_provider(
            "urn:nl-eid-gdi:1.0:DV:00000001234567890000:entities:9001",
            "f847dc11-ac24-47b2-84a8-a057440ce56d",
            "https://dv.example.nl/saml/acs",
            RD,
            super::super::authn_context::LevelOfAssurance::Low,
        )
        .with_single_logout_url("https://dv.example.nl/saml/slo");
        let mut opts = DvMetadataOptions::from_config(&cfg, "Kiesraad");
        assert!(matches!(
            build_dv_entity_descriptor(&opts),
            Err(NlEidError::Config(_))
        ));
        opts.signing_certificates = vec![PublishedCertificate::from_der(FAKE_DER)];
        opts.encryption_certificates = vec![PublishedCertificate::from_der(b"enc cert")];
        let ed = build_dv_entity_descriptor(&opts).unwrap();
        let xml = ed.to_xml_string().unwrap();
        assert!(xml.contains(r#"AuthnRequestsSigned="true""#));
        assert!(xml.contains(r#"WantAssertionsSigned="true""#));
        assert!(xml.contains(r#"cacheDuration="PT24H""#));
        assert!(xml.contains(constants::BINDING_HTTP_ARTIFACT));
        assert!(xml.contains(r#"index="0""#));
        assert!(xml.contains(r#"isDefault="true""#));
        assert!(xml.contains("https://dv.example.nl/saml/slo"));
        assert!(xml.contains(constants::ATTR_SERVICE_UUID));
        assert!(xml.contains("f847dc11-ac24-47b2-84a8-a057440ce56d"));
        assert!(xml.contains(r#"use="signing""#));
        assert!(xml.contains(r#"use="encryption""#));
        assert!(xml.contains("Kiesraad"));
        // Round-trips through the metadata parser.
        let doc = crate::xml::parse_secure_metadata(&xml).unwrap();
        let parsed = parse_saml::<EntityDescriptorRef<'_>>(&doc)
            .unwrap()
            .to_owned();
        assert_eq!(parsed.entity_id, cfg.entity_id);
        assert_eq!(parsed.cache_duration.as_deref(), Some("PT24H"));
    }

    #[test]
    fn test_rd_metadata_reader_selects_endpoints_and_keys() {
        let ki = PublishedCertificate::from_der(FAKE_DER).key_info_xml();
        // The fake DER is not a parseable certificate, so the reader's
        // certificate extraction yields nothing: use a KeyInfo whose cert is
        // the real test fixture instead.
        let _ = ki;
        let cert_pem = include_str!("../../../tests/fixtures/enc-cert.pem");
        let published = PublishedCertificate::from_pem(cert_pem).unwrap();
        let xml = rd_metadata_xml(&published.key_info_xml(), r#"cacheDuration="PT1H""#, true);
        let rd = parse_rd_metadata(&xml).unwrap();
        assert_eq!(rd.entity_id, RD);
        assert_eq!(rd.sso_url, "https://rd.example/sso");
        assert_eq!(rd.artifact_resolution_url, "https://rd.example/ars");
        assert_eq!(rd.artifact_resolution_index, 0);
        assert_eq!(rd.single_logout_url, "https://rd.example/slo");
        assert_eq!(rd.signing_keys.len(), 1);
        assert_eq!(rd.signing_keys[0].key_name, published.key_name);
        assert!(rd.signing_keys[0].key_name_declared);
        assert!(rd.is_valid_at(Utc::now()));
        let km = rd.keys_manager().unwrap();
        assert!(km.find_by_name(&published.key_name).is_some());
        assert!(rd.verifier().is_ok());
    }

    #[test]
    fn test_rd_metadata_reader_enforces_mandatory_parts() {
        let cert_pem = include_str!("../../../tests/fixtures/enc-cert.pem");
        let published = PublishedCertificate::from_pem(cert_pem).unwrap();
        let ki = published.key_info_xml();
        // No validUntil / cacheDuration.
        assert!(matches!(
            parse_rd_metadata(&rd_metadata_xml(&ki, "", true)),
            Err(NlEidError::Metadata(_))
        ));
        // No logout endpoint.
        assert!(matches!(
            parse_rd_metadata(&rd_metadata_xml(&ki, r#"cacheDuration="PT1H""#, false)),
            Err(NlEidError::Metadata(_))
        ));
        // WantAuthnRequestsSigned missing.
        let xml = rd_metadata_xml(&ki, r#"cacheDuration="PT1H""#, true)
            .replace(r#"WantAuthnRequestsSigned="true" "#, "");
        assert!(matches!(
            parse_rd_metadata(&xml),
            Err(NlEidError::Metadata(_))
        ));
        // KeyName absent: derived from the certificate, flagged as such.
        let no_name = ki.replace(
            &format!("<ds:KeyName>{}</ds:KeyName>", published.key_name),
            "",
        );
        let rd =
            parse_rd_metadata(&rd_metadata_xml(&no_name, r#"cacheDuration="PT1H""#, true)).unwrap();
        assert_eq!(rd.signing_keys[0].key_name, published.key_name);
        assert!(!rd.signing_keys[0].key_name_declared);
        // Expired validUntil is reported by is_valid_at.
        let rd = parse_rd_metadata(&rd_metadata_xml(
            &ki,
            r#"validUntil="2020-01-01T00:00:00Z""#,
            true,
        ))
        .unwrap();
        assert!(!rd.is_valid_at(Utc::now()));
    }
}
