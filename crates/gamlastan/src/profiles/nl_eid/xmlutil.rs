// Shared helpers for the eID SAML profile: signature binding on top of
// `SamlVerifier`, the §9.1 / §9.3 algorithm scan, freshness bounds, and the
// few uppsala document operations the profile needs beyond the typed model.
//
// SAML messages are read through the typed deserializers (`parse_saml`,
// `SamlDeserialize::from_xml`); the document tree is only consulted where the
// typed model cannot carry the information — which `<ds:Signature>` belongs to
// which element, the `<ds:KeyName>` of a signature, and the `<saml:EncryptedID>`
// elements that must be handed to the decryptor as standalone documents.

use chrono::{DateTime, TimeDelta, Utc};

use crate::crypto::{SamlVerifier, VerifyResult};
use crate::xml::uppsala::{Document, NodeId};

use super::constants;
use super::error::NlEidError;

// ── Document access ─────────────────────────────────────────────────────────

/// Whether `node` is the element `{ns}local`.
pub(crate) fn is_element(doc: &Document<'_>, node: NodeId, ns: &str, local: &str) -> bool {
    doc.element(node)
        .is_some_and(|e| e.matches_name_ns(ns, local))
}

/// The trimmed text of an element that holds text only.
pub(crate) fn element_text(doc: &Document<'_>, node: NodeId) -> Option<String> {
    doc.element_text(node).map(|t| t.trim().to_string())
}

/// Descendant elements of `node` named `{ns}local`, in document order.
pub(crate) fn descendant_elements(
    doc: &Document<'_>,
    node: NodeId,
    ns: &str,
    local: &str,
) -> Vec<NodeId> {
    doc.descendants(node)
        .into_iter()
        .filter(|n| is_element(doc, *n, ns, local))
        .collect()
}

/// A deep copy of the subtree at `node` as its own document, so it can be
/// serialized namespace-complete or edited without touching the received
/// message (see [`crate::xml::helpers::node_to_self_contained_xml`]).
pub(crate) fn standalone_document(
    doc: &Document<'_>,
    node: NodeId,
) -> Result<Document<'static>, NlEidError> {
    let mut standalone: Document<'static> = Document::new();
    let copied = standalone
        .import_subtree(doc, node)
        .ok_or_else(|| NlEidError::MalformedMessage("cannot copy XML subtree".to_string()))?;
    let root = standalone.root();
    standalone.append_child(root, copied);
    Ok(standalone)
}

/// Insert `template` (a serialized `<ds:Signature>` template) as the first
/// child of the document element of `xml`, through the document tree. Used
/// for metadata, where the signature precedes every other child of
/// `<md:EntityDescriptor>`.
pub(crate) fn insert_signature_as_first_child(
    xml: &str,
    template: &str,
) -> Result<String, NlEidError> {
    let mut doc = crate::xml::parse_secure_metadata(xml)?;
    let root = doc
        .document_element()
        .ok_or_else(|| NlEidError::MalformedMessage("document has no root element".to_string()))?;
    let template_doc = crate::xml::parse_secure_metadata(template)?;
    let template_root = template_doc.document_element().ok_or_else(|| {
        NlEidError::MalformedMessage("signature template has no root element".to_string())
    })?;
    let signature = doc
        .import_subtree(&template_doc, template_root)
        .ok_or_else(|| {
            NlEidError::MalformedMessage("cannot copy signature template".to_string())
        })?;
    match doc.children_iter(root).find(|c| doc.element(*c).is_some()) {
        Some(first) => doc.insert_before(root, signature, first),
        None => doc.append_child(root, signature),
    }
    Ok(doc.to_xml())
}

// ── Signatures ──────────────────────────────────────────────────────────────

/// Every `<ds:Signature>` of a received document, with the verifier's verdict
/// for each. `SamlVerifier::verify_all_enveloped` reports the signatures in
/// document order; so does the element enumeration, which is what aligns the
/// two. Signatures the profile does not consume (the AD's signature inside
/// `<saml:Advice>`, §9.1) are allowed to be invalid against the RD keys.
pub(crate) struct DocumentSignatures {
    nodes: Vec<NodeId>,
    results: Vec<VerifyResult>,
}

/// Verify every signature in `xml` (the exact bytes `doc` was parsed from).
pub(crate) fn verify_document_signatures(
    doc: &Document<'_>,
    xml: &str,
    verifier: &SamlVerifier,
    element: &'static str,
) -> Result<DocumentSignatures, NlEidError> {
    let nodes = doc.get_elements_by_tag_name_ns(constants::NS_DS, "Signature");
    let results = match verifier.verify_all_enveloped(xml) {
        Ok(results) => results,
        Err(crate::crypto::CryptoError::BergshamraError(
            bergshamra_core::Error::MissingElement(e),
        )) if e == "Signature" => return Err(NlEidError::MissingSignature(element)),
        Err(e) => {
            return Err(NlEidError::InvalidSignature {
                element,
                reason: e.to_string(),
            })
        }
    };
    if results.len() != nodes.len() {
        return Err(NlEidError::MalformedMessage(format!(
            "the verifier reported {} signatures but the document holds {}",
            results.len(),
            nodes.len()
        )));
    }
    Ok(DocumentSignatures { nodes, results })
}

/// What a verified enveloping signature established for an element.
#[derive(Debug, Clone)]
pub(crate) struct VerifiedSignature {
    /// The `<ds:KeyName>` the signature carried (and the key that verified it).
    pub key_name: String,
    /// SAML object IDs covered by the verified XML-DSig references.
    pub signed_ids: Vec<String>,
}

/// Require `element_node` to carry exactly one enveloping `<ds:Signature>`
/// child that verified, names an RD key by `<ds:KeyName>` (§9.2), and
/// references the element's own `@ID` (ADR 0028).
pub(crate) fn require_signed_element(
    doc: &Document<'_>,
    signatures: &DocumentSignatures,
    element_node: NodeId,
    element: &'static str,
    verifier: &SamlVerifier,
) -> Result<VerifiedSignature, NlEidError> {
    let direct = doc.child_elements_by_name_ns(element_node, constants::NS_DS, "Signature");
    let [signature] = direct[..] else {
        return Err(if direct.is_empty() {
            NlEidError::MissingSignature(element)
        } else {
            NlEidError::AmbiguousSignature(element)
        });
    };
    let index = signatures
        .nodes
        .iter()
        .position(|n| *n == signature)
        .ok_or_else(|| {
            NlEidError::MalformedMessage(format!("{element} signature was not verified"))
        })?;
    let key_name = require_known_key_name(doc, signature, verifier)?;
    let id = doc.get_attribute(element_node, "ID").ok_or_else(|| {
        NlEidError::MalformedMessage(format!(
            "{element} has no ID attribute to bind the signature to"
        ))
    })?;
    let signed_ids = bind_verified_references(&signatures.results[index], id, element)?;
    Ok(VerifiedSignature {
        key_name,
        signed_ids,
    })
}

/// The `<ds:KeyInfo>/<ds:KeyName>` of a signature, if present.
pub(crate) fn signature_key_name(doc: &Document<'_>, signature: NodeId) -> Option<String> {
    let key_info = doc.first_child_element_by_name_ns(signature, constants::NS_DS, "KeyInfo")?;
    let key_name = doc.first_child_element_by_name_ns(key_info, constants::NS_DS, "KeyName")?;
    element_text(doc, key_name).filter(|s| !s.is_empty())
}

/// §9.2: an RD signature MUST carry a `<ds:KeyName>` that corresponds to a
/// `<ds:KeyName>` in a `<md:KeyDescriptor>` of the RD's verified metadata. The
/// verifier's key manager holds the RD keys under exactly those names (see
/// [`super::metadata::RdMetadata::keys_manager`]).
pub(crate) fn require_known_key_name(
    doc: &Document<'_>,
    signature: NodeId,
    verifier: &SamlVerifier,
) -> Result<String, NlEidError> {
    let name = signature_key_name(doc, signature)
        .ok_or_else(|| NlEidError::UnknownSigningKey("KeyInfo has no KeyName".to_string()))?;
    if verifier.keys_manager().find_by_name(&name).is_none() {
        return Err(NlEidError::UnknownSigningKey(format!(
            "KeyName {name:?} is not a key from the RD metadata"
        )));
    }
    Ok(name)
}

/// Convert a verification result into the SAML object IDs it covers and fail
/// closed unless `consumed_id` is one of them.
pub(crate) fn bind_verified_references(
    result: &VerifyResult,
    consumed_id: &str,
    element: &'static str,
) -> Result<Vec<String>, NlEidError> {
    match result {
        VerifyResult::Invalid { reason } => Err(NlEidError::InvalidSignature {
            element,
            reason: reason.clone(),
        }),
        VerifyResult::Valid { references, .. } => {
            if !result.all_reference_digests_verified() {
                return Err(NlEidError::InvalidSignature {
                    element,
                    reason: "not every signed reference digest was verified locally".to_string(),
                });
            }
            let mut ids: Vec<String> = Vec::new();
            for reference in references {
                let id = if reference.uri.is_empty() {
                    Some(consumed_id)
                } else {
                    reference.uri.strip_prefix('#')
                };
                if let Some(id) = id {
                    if !ids.iter().any(|existing| existing == id) {
                        ids.push(id.to_string());
                    }
                }
            }
            if !ids.iter().any(|i| i == consumed_id) {
                return Err(NlEidError::SignatureNotBoundToElement(element));
            }
            Ok(ids)
        }
    }
}

// ── Time ────────────────────────────────────────────────────────────────────

fn seconds(s: u64) -> TimeDelta {
    TimeDelta::try_seconds(i64::try_from(s).unwrap_or(i64::MAX)).unwrap_or(TimeDelta::MAX)
}

/// Bound an `@IssueInstant` / `@AuthnInstant` on both sides: at most
/// `max_age_seconds` (plus skew) in the past and at most `skew_seconds` in the
/// future.
pub(crate) fn check_freshness(
    instant: DateTime<Utc>,
    now: DateTime<Utc>,
    skew_seconds: u64,
    max_age_seconds: u64,
    element: &'static str,
) -> Result<(), NlEidError> {
    let out_of_range = || NlEidError::StaleMessage {
        element,
        detail: format!("instant {instant} is outside the usable range"),
    };
    let skew = seconds(skew_seconds);
    let stale_after = instant
        .checked_add_signed(seconds(max_age_seconds))
        .and_then(|t| t.checked_add_signed(skew))
        .ok_or_else(out_of_range)?;
    let not_before = instant.checked_sub_signed(skew).ok_or_else(out_of_range)?;
    if stale_after < now {
        return Err(NlEidError::StaleMessage {
            element,
            detail: format!("issued at {instant}, older than {max_age_seconds}s (now {now})"),
        });
    }
    if not_before > now {
        return Err(NlEidError::StaleMessage {
            element,
            detail: format!("issued at {instant}, which is in the future (now {now})"),
        });
    }
    Ok(())
}

// ── §9.1 / §9.3 algorithm allow-list ────────────────────────────────────────

#[derive(Clone, Copy, Default)]
struct AlgorithmContext {
    in_encrypted_key: bool,
    in_encrypted_data: bool,
    in_reference: bool,
}

/// Validate that every signature, digest, canonicalization, transform and
/// encryption algorithm declared at or below `node` is one the specification
/// permits (§9.1, §9.3).
///
/// The scan covers the whole received document, including the `<saml:Advice>`
/// evidence assertions, before any cryptography: §9.1 binds every participant.
/// The one exception is an `<xenc:EncryptedKey>` wrapped for another recipient
/// (`@Recipient` present and different from `own_recipient`): §7.6.3.4 says
/// those SHOULD be ignored, so their key-transport algorithm is not ours to
/// judge and the subtree is skipped.
pub(crate) fn validate_algorithms(
    doc: &Document<'_>,
    node: NodeId,
    own_recipient: Option<&str>,
) -> Result<(), NlEidError> {
    validate_algorithms_recursive(doc, node, AlgorithmContext::default(), own_recipient)
}

fn disallowed(kind: &'static str, uri: &str) -> NlEidError {
    NlEidError::DisallowedAlgorithm {
        kind,
        uri: uri.to_string(),
    }
}

fn algorithm_attr<'a>(
    doc: &'a Document<'a>,
    node: NodeId,
    element: &str,
) -> Result<&'a str, NlEidError> {
    doc.get_attribute(node, "Algorithm")
        .ok_or_else(|| NlEidError::MalformedMessage(format!("{element} is missing Algorithm")))
}

fn validate_algorithms_recursive<'a>(
    doc: &'a Document<'a>,
    node: NodeId,
    ctx: AlgorithmContext,
    own_recipient: Option<&str>,
) -> Result<(), NlEidError> {
    let mut next = ctx;
    if let Some(elem) = doc.element(node) {
        let ns = elem.name.namespace_uri.as_deref();
        let local: &str = elem.name.local_name.as_ref();
        if matches!(ns, Some(constants::NS_XENC) | Some(constants::NS_XENC11)) {
            match local {
                "EncryptedKey" => {
                    if let (Some(own), Some(recipient)) =
                        (own_recipient, elem.get_attribute("Recipient"))
                    {
                        if recipient != own {
                            return Ok(());
                        }
                    }
                    next.in_encrypted_key = true;
                }
                "EncryptedData" => next.in_encrypted_data = true,
                "EncryptionMethod" => {
                    let uri = algorithm_attr(doc, node, "EncryptionMethod")?;
                    if ctx.in_encrypted_key {
                        if !constants::is_allowed_key_transport_algorithm(uri) {
                            return Err(disallowed("key transport", uri));
                        }
                    } else if ctx.in_encrypted_data
                        && !constants::is_allowed_block_encryption_algorithm(uri)
                    {
                        return Err(disallowed("block encryption", uri));
                    }
                }
                _ => {}
            }
        } else if ns == Some(constants::NS_DS) {
            match local {
                "Reference" => next.in_reference = true,
                "SignatureMethod" => {
                    let uri = algorithm_attr(doc, node, "SignatureMethod")?;
                    if !constants::is_allowed_signature_algorithm(uri) {
                        return Err(disallowed("signature", uri));
                    }
                }
                "CanonicalizationMethod" => {
                    let uri = algorithm_attr(doc, node, "CanonicalizationMethod")?;
                    if uri != constants::C14N_EXCLUSIVE {
                        return Err(disallowed("canonicalization", uri));
                    }
                }
                "DigestMethod" => {
                    let uri = algorithm_attr(doc, node, "DigestMethod")?;
                    // Inside an EncryptedKey the digest parameterises RSA-OAEP,
                    // where §9.1 still allows the SHA-1 padding function.
                    let allowed = constants::is_allowed_digest_algorithm(uri)
                        || (ctx.in_encrypted_key && uri == constants::DIGEST_SHA1);
                    if !allowed {
                        return Err(disallowed("digest", uri));
                    }
                }
                "Transform" if ctx.in_reference => {
                    let uri = algorithm_attr(doc, node, "Transform")?;
                    if uri != constants::TRANSFORM_ENVELOPED_SIGNATURE
                        && uri != constants::C14N_EXCLUSIVE
                    {
                        return Err(disallowed("transform", uri));
                    }
                }
                "Transforms" if ctx.in_reference => check_transform_list(doc, node)?,
                _ => {}
            }
        }
    }
    for child in doc.children_iter(node) {
        if doc.element(child).is_some() {
            validate_algorithms_recursive(doc, child, next, own_recipient)?;
        }
    }
    Ok(())
}

/// §9.1: a Reference applies the enveloped-signature transform exactly once
/// and at most one exclusive-c14n transform, which (yielding octets) comes last.
fn check_transform_list(doc: &Document<'_>, transforms: NodeId) -> Result<(), NlEidError> {
    let uris: Vec<&str> = doc
        .child_elements_by_name_ns(transforms, constants::NS_DS, "Transform")
        .into_iter()
        .map(|t| algorithm_attr(doc, t, "Transform"))
        .collect::<Result<_, _>>()?;
    let enveloped = uris
        .iter()
        .filter(|u| **u == constants::TRANSFORM_ENVELOPED_SIGNATURE)
        .count();
    let c14n = uris
        .iter()
        .filter(|u| **u == constants::C14N_EXCLUSIVE)
        .count();
    if enveloped != 1 {
        return Err(NlEidError::MalformedMessage(format!(
            "signature Reference applies the enveloped-signature transform {enveloped} times (§9.1 requires exactly one)"
        )));
    }
    if c14n > 1 || (c14n == 1 && uris.last() != Some(&constants::C14N_EXCLUSIVE)) {
        return Err(NlEidError::MalformedMessage(
            "signature Reference canonicalization transform must be the single, last transform"
                .to_string(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMLP: &str = constants::NS_SAML_PROTOCOL;
    const DS: &str = constants::NS_DS;

    fn sig(id: &str) -> String {
        format!(
            r##"<ds:Signature xmlns:ds="{DS}"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="{}"/><ds:SignatureMethod Algorithm="{}"/><ds:Reference URI="#{id}"><ds:Transforms><ds:Transform Algorithm="{}"/><ds:Transform Algorithm="{}"/></ds:Transforms><ds:DigestMethod Algorithm="{}"/><ds:DigestValue>AA==</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>AA==</ds:SignatureValue><ds:KeyInfo><ds:KeyName>k1</ds:KeyName></ds:KeyInfo></ds:Signature>"##,
            constants::C14N_EXCLUSIVE,
            constants::SIG_RSA_SHA256,
            constants::TRANSFORM_ENVELOPED_SIGNATURE,
            constants::C14N_EXCLUSIVE,
            constants::DIGEST_SHA256,
        )
    }

    #[test]
    fn test_standalone_document_declares_inherited_namespaces() {
        let xml = format!(
            r#"<soap:Envelope xmlns:soap="{}" xmlns:saml="{}"><soap:Body><samlp:ArtifactResponse xmlns:samlp="{SAMLP}" ID="_a"><saml:Issuer>rd</saml:Issuer></samlp:ArtifactResponse></soap:Body></soap:Envelope>"#,
            constants::NS_SOAP11,
            constants::NS_SAML_ASSERTION
        );
        let doc = crate::xml::parse_secure(&xml).unwrap();
        let root = doc.document_element().unwrap();
        let body = doc
            .first_child_element_by_name_ns(root, constants::NS_SOAP11, "Body")
            .unwrap();
        let art = doc
            .first_child_element_by_name_ns(body, SAMLP, "ArtifactResponse")
            .unwrap();
        let standalone = standalone_document(&doc, art).unwrap().to_xml();
        assert!(
            standalone.starts_with("<samlp:ArtifactResponse"),
            "{standalone}"
        );
        let doc2 = crate::xml::parse_secure(&standalone).unwrap();
        let root2 = doc2.document_element().unwrap();
        assert!(is_element(&doc2, root2, SAMLP, "ArtifactResponse"));
        assert!(
            doc2.first_child_element_by_name_ns(root2, constants::NS_SAML_ASSERTION, "Issuer")
                .is_some(),
            "{standalone}"
        );
    }

    #[test]
    fn test_signature_key_name() {
        let xml = format!(
            r#"<samlp:ArtifactResponse xmlns:samlp="{SAMLP}" ID="_a">{}</samlp:ArtifactResponse>"#,
            sig("_a")
        );
        let doc = crate::xml::parse_secure(&xml).unwrap();
        let root = doc.document_element().unwrap();
        let s = doc.child_elements_by_name_ns(root, DS, "Signature")[0];
        assert_eq!(signature_key_name(&doc, s).as_deref(), Some("k1"));
    }

    #[test]
    fn test_require_signed_element_structure() {
        use crate::crypto::KeysManager;
        let verifier = SamlVerifier::new(KeysManager::new());
        let fake = |n: usize| DocumentSignatures {
            nodes: Vec::new(),
            results: (0..n)
                .map(|_| VerifyResult::Invalid {
                    reason: "unused".to_string(),
                })
                .collect(),
        };
        // No signature.
        let xml = format!(r#"<samlp:ArtifactResponse xmlns:samlp="{SAMLP}" ID="_a"/>"#);
        let doc = crate::xml::parse_secure(&xml).unwrap();
        let root = doc.document_element().unwrap();
        assert!(matches!(
            require_signed_element(&doc, &fake(0), root, "ArtifactResponse", &verifier),
            Err(NlEidError::MissingSignature(_))
        ));
        // Two direct signatures.
        let xml = format!(
            r#"<samlp:ArtifactResponse xmlns:samlp="{SAMLP}" ID="_a">{}{}</samlp:ArtifactResponse>"#,
            sig("_a"),
            sig("_a")
        );
        let doc = crate::xml::parse_secure(&xml).unwrap();
        let root = doc.document_element().unwrap();
        assert!(matches!(
            require_signed_element(&doc, &fake(2), root, "ArtifactResponse", &verifier),
            Err(NlEidError::AmbiguousSignature(_))
        ));
    }

    #[test]
    fn test_bind_verified_references() {
        // A real enveloped signature over `<samlp:ArtifactResponse ID="_a">`,
        // verified against its own certificate, so the result carries the
        // reference `#_a`.
        let key_pem = include_str!("../../../tests/fixtures/enc-key.pem");
        let cert_pem = include_str!("../../../tests/fixtures/enc-cert.pem");
        let mut key = crate::crypto::keys::loader::load_pem_auto(key_pem.as_bytes(), None).unwrap();
        key.usage = crate::crypto::KeyUsage::Sign;
        let mut signing = crate::crypto::KeysManager::new();
        signing.add_key(key);
        let template = sig("_a")
            .replace(
                "<ds:DigestValue>AA==</ds:DigestValue>",
                "<ds:DigestValue></ds:DigestValue>",
            )
            .replace(
                "<ds:SignatureValue>AA==</ds:SignatureValue>",
                "<ds:SignatureValue></ds:SignatureValue>",
            );
        let unsigned = format!(
            r#"<samlp:ArtifactResponse xmlns:samlp="{SAMLP}" ID="_a">{template}</samlp:ArtifactResponse>"#
        );
        let signed = crate::crypto::SamlSigner::new(signing)
            .sign_enveloped(&unsigned)
            .unwrap();

        let mut cert = crate::crypto::keys::loader::load_pem_auto(cert_pem.as_bytes(), None)
            .unwrap()
            .with_name("k1");
        cert.usage = crate::crypto::KeyUsage::Verify;
        let mut verifying = crate::crypto::KeysManager::new();
        let cert_der = cert.x509_chain.first().cloned().unwrap();
        verifying.add_key(cert);
        verifying.add_trusted_cert(cert_der);
        let result = SamlVerifier::new(verifying)
            .verify_enveloped(&signed)
            .unwrap();
        assert!(result.is_valid(), "{result:?}");

        assert_eq!(
            bind_verified_references(&result, "_a", "X").unwrap(),
            vec!["_a".to_string()]
        );
        assert!(matches!(
            bind_verified_references(&result, "_other", "X"),
            Err(NlEidError::SignatureNotBoundToElement("X"))
        ));
        assert!(matches!(
            bind_verified_references(
                &VerifyResult::Invalid {
                    reason: "bad".to_string()
                },
                "_a",
                "X"
            ),
            Err(NlEidError::InvalidSignature { .. })
        ));
    }

    #[test]
    fn test_validate_algorithms_accepts_spec_set_and_rejects_others() {
        let ok = format!(
            r#"<samlp:ArtifactResponse xmlns:samlp="{SAMLP}" ID="_a">{}</samlp:ArtifactResponse>"#,
            sig("_a")
        );
        let doc = crate::xml::parse_secure(&ok).unwrap();
        assert!(validate_algorithms(&doc, doc.document_element().unwrap(), None).is_ok());

        for (from, to, kind) in [
            (
                constants::SIG_RSA_SHA256.to_string(),
                "http://www.w3.org/2000/09/xmldsig#rsa-sha1".to_string(),
                "signature",
            ),
            (
                constants::SIG_RSA_SHA256.to_string(),
                "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256".to_string(),
                "signature",
            ),
            (
                constants::DIGEST_SHA256.to_string(),
                constants::DIGEST_SHA1.to_string(),
                "digest",
            ),
            (
                format!(
                    r#"CanonicalizationMethod Algorithm="{}""#,
                    constants::C14N_EXCLUSIVE
                ),
                r#"CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#WithComments""#.to_string(),
                "canonicalization",
            ),
            (
                format!(
                    r#"Transform Algorithm="{}"/><ds:Transform Algorithm="{}""#,
                    constants::TRANSFORM_ENVELOPED_SIGNATURE,
                    constants::C14N_EXCLUSIVE
                ),
                format!(
                    r#"Transform Algorithm="{}"/><ds:Transform Algorithm="http://www.w3.org/TR/1999/REC-xpath-19991116""#,
                    constants::TRANSFORM_ENVELOPED_SIGNATURE
                ),
                "transform",
            ),
        ] {
            let bad = ok.replacen(&from, &to, 1);
            assert_ne!(bad, ok, "replacement {from} must apply");
            let doc = crate::xml::parse_secure(&bad).unwrap();
            let err = validate_algorithms(&doc, doc.document_element().unwrap(), None).unwrap_err();
            assert!(
                matches!(&err, NlEidError::DisallowedAlgorithm { kind: k, .. } if *k == kind),
                "{kind}: {err}"
            );
        }
    }

    #[test]
    fn test_validate_algorithms_encryption() {
        let xenc = constants::NS_XENC;
        let enc = |data: &str, key: &str, oaep_digest: &str| {
            format!(
                r#"<r xmlns:xenc="{xenc}" xmlns:ds="{DS}"><xenc:EncryptedData><xenc:EncryptionMethod Algorithm="{data}"/><ds:KeyInfo><xenc:EncryptedKey><xenc:EncryptionMethod Algorithm="{key}"><ds:DigestMethod Algorithm="{oaep_digest}"/></xenc:EncryptionMethod></xenc:EncryptedKey></ds:KeyInfo></xenc:EncryptedData></r>"#
            )
        };
        let check = |xml: String| {
            let doc = crate::xml::parse_secure(&xml).unwrap();
            validate_algorithms(&doc, doc.document_element().unwrap(), None)
        };
        assert!(check(enc(
            constants::ENC_AES256_CBC,
            constants::KEYTRANSPORT_RSA_OAEP_MGF1P,
            constants::DIGEST_SHA1
        ))
        .is_ok());
        assert!(matches!(
            check(enc(
                "http://www.w3.org/2001/04/xmlenc#aes128-cbc",
                constants::KEYTRANSPORT_RSA_OAEP_MGF1P,
                constants::DIGEST_SHA256
            )),
            Err(NlEidError::DisallowedAlgorithm {
                kind: "block encryption",
                ..
            })
        ));
        assert!(matches!(
            check(enc(
                constants::ENC_AES256_CBC,
                constants::KEYTRANSPORT_RSA_1_5,
                constants::DIGEST_SHA256
            )),
            Err(NlEidError::DisallowedAlgorithm {
                kind: "key transport",
                ..
            })
        ));
    }

    #[test]
    fn test_validate_algorithms_ignores_other_recipients_keys() {
        let xenc = constants::NS_XENC;
        let xml = format!(
            r#"<r xmlns:xenc="{xenc}"><xenc:EncryptedData><xenc:EncryptionMethod Algorithm="{}"/></xenc:EncryptedData><xenc:EncryptedKey Recipient="urn:other"><xenc:EncryptionMethod Algorithm="{}"/></xenc:EncryptedKey><xenc:EncryptedKey Recipient="urn:me"><xenc:EncryptionMethod Algorithm="{}"/></xenc:EncryptedKey></r>"#,
            constants::ENC_AES256_CBC,
            constants::KEYTRANSPORT_RSA_1_5,
            constants::KEYTRANSPORT_RSA_OAEP_MGF1P,
        );
        let doc = crate::xml::parse_secure(&xml).unwrap();
        let root = doc.document_element().unwrap();
        assert!(validate_algorithms(&doc, root, Some("urn:me")).is_ok());
        assert!(validate_algorithms(&doc, root, None).is_err());
        let swapped = xml
            .replace(constants::KEYTRANSPORT_RSA_1_5, "TMP")
            .replace(
                constants::KEYTRANSPORT_RSA_OAEP_MGF1P,
                constants::KEYTRANSPORT_RSA_1_5,
            )
            .replace("TMP", constants::KEYTRANSPORT_RSA_OAEP_MGF1P);
        let doc = crate::xml::parse_secure(&swapped).unwrap();
        assert!(
            validate_algorithms(&doc, doc.document_element().unwrap(), Some("urn:me")).is_err()
        );
    }

    #[test]
    fn test_transform_list_shape() {
        let base = format!(
            r#"<samlp:ArtifactResponse xmlns:samlp="{SAMLP}" ID="_a">{}</samlp:ArtifactResponse>"#,
            sig("_a")
        );
        let swapped = base.replacen(
            &format!(
                r#"<ds:Transform Algorithm="{}"/><ds:Transform Algorithm="{}"/>"#,
                constants::TRANSFORM_ENVELOPED_SIGNATURE,
                constants::C14N_EXCLUSIVE
            ),
            &format!(
                r#"<ds:Transform Algorithm="{}"/><ds:Transform Algorithm="{}"/>"#,
                constants::C14N_EXCLUSIVE,
                constants::TRANSFORM_ENVELOPED_SIGNATURE
            ),
            1,
        );
        assert_ne!(swapped, base);
        let doc = crate::xml::parse_secure(&swapped).unwrap();
        assert!(matches!(
            validate_algorithms(&doc, doc.document_element().unwrap(), None),
            Err(NlEidError::MalformedMessage(_))
        ));
        let no_env = base.replacen(
            &format!(
                r#"<ds:Transform Algorithm="{}"/>"#,
                constants::TRANSFORM_ENVELOPED_SIGNATURE
            ),
            "",
            1,
        );
        let doc = crate::xml::parse_secure(&no_env).unwrap();
        assert!(matches!(
            validate_algorithms(&doc, doc.document_element().unwrap(), None),
            Err(NlEidError::MalformedMessage(_))
        ));
    }

    #[test]
    fn test_check_freshness_bounds() {
        let now = Utc::now();
        assert!(check_freshness(now - TimeDelta::seconds(10), now, 30, 300, "x").is_ok());
        assert!(check_freshness(now + TimeDelta::seconds(10), now, 30, 300, "x").is_ok());
        assert!(matches!(
            check_freshness(now - TimeDelta::seconds(400), now, 30, 300, "x"),
            Err(NlEidError::StaleMessage { .. })
        ));
        assert!(matches!(
            check_freshness(now + TimeDelta::hours(1), now, 30, 300, "x"),
            Err(NlEidError::StaleMessage { .. })
        ));
        assert!(check_freshness(DateTime::<Utc>::MAX_UTC, now, 30, 300, "x").is_err());
        assert!(check_freshness(DateTime::<Utc>::MIN_UTC, now, 30, 300, "x").is_err());
    }

    #[test]
    fn test_insert_signature_as_first_child() {
        let xml = r#"<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="a>b" ID="_m"><md:SPSSODescriptor/></md:EntityDescriptor>"#;
        let out = insert_signature_as_first_child(
            xml,
            r#"<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"/>"#,
        )
        .unwrap();
        let doc = crate::xml::parse_secure_metadata(&out).unwrap();
        let root = doc.document_element().unwrap();
        let children: Vec<NodeId> = doc
            .children_iter(root)
            .filter(|c| doc.element(*c).is_some())
            .collect();
        assert_eq!(children.len(), 2, "{out}");
        assert!(is_element(&doc, children[0], DS, "Signature"));
        assert!(is_element(
            &doc,
            children[1],
            "urn:oasis:names:tc:SAML:2.0:metadata",
            "SPSSODescriptor"
        ));
        assert_eq!(doc.get_attribute(root, "entityID"), Some("a>b"));
    }
}
