// XML navigation, signature-binding and algorithm helpers shared by the eID
// SAML profile modules.
//
// Everything here operates on a single parsed `uppsala::Document`: the
// ArtifactResponse → Response → Assertion chain is navigated on one tree, and
// a signed sub-element is re-serialized with `Document::node_to_xml` (which
// carries the ancestor namespace bindings) only when it has to be handed to
// the verifier or decryptor as a standalone document.

use chrono::{DateTime, TimeDelta, Utc};

use crate::crypto::{SamlVerifier, VerifyResult};
use crate::xml::uppsala::{Document, NodeId, NodeKind};

use super::constants;
use super::error::NlEidError;

// ── Navigation ──────────────────────────────────────────────────────────────

/// Whether `node` is the element `{ns}local`.
pub(crate) fn is_element(doc: &Document<'_>, node: NodeId, ns: &str, local: &str) -> bool {
    doc.element(node)
        .is_some_and(|e| e.matches_name_ns(ns, local))
}

/// Direct element children of `node` named `{ns}local`, in document order.
pub(crate) fn element_children(
    doc: &Document<'_>,
    node: NodeId,
    ns: &str,
    local: &str,
) -> Vec<NodeId> {
    doc.children_iter(node)
        .filter(|c| is_element(doc, *c, ns, local))
        .collect()
}

/// The first direct element child of `node` named `{ns}local`.
pub(crate) fn element_child(
    doc: &Document<'_>,
    node: NodeId,
    ns: &str,
    local: &str,
) -> Option<NodeId> {
    doc.children_iter(node)
        .find(|c| is_element(doc, *c, ns, local))
}

/// Every element in the subtree below `node` (excluding `node`), document order.
pub(crate) fn descendant_elements(doc: &Document<'_>, node: NodeId) -> Vec<NodeId> {
    doc.descendants(node)
        .into_iter()
        .filter(|n| doc.element(*n).is_some())
        .collect()
}

/// The text content of an element that must hold *only* text: `None` when the
/// element has element children. Text and CDATA runs are concatenated (so a
/// comment splitting a value cannot truncate it) and trimmed.
pub(crate) fn text_only(doc: &Document<'_>, node: NodeId) -> Option<String> {
    let mut out = String::new();
    for child in doc.children_iter(node) {
        match doc.node_kind(child) {
            Some(NodeKind::Text(t)) | Some(NodeKind::CData(t)) => out.push_str(t),
            Some(NodeKind::Element(_)) => return None,
            _ => {}
        }
    }
    Some(out.trim().to_string())
}

/// The value of the attribute that names an element for a `#id` reference.
pub(crate) fn element_id<'a>(doc: &'a Document<'a>, node: NodeId) -> Option<&'a str> {
    doc.get_attribute(node, "ID")
}

/// Serialize the subtree rooted at `node` as a standalone document.
///
/// `Document::node_to_xml` emits only the namespace declarations the element
/// itself carries; prefixes bound on an ancestor (the usual shape of an RD
/// message, where `saml`/`samlp` are declared on the `ArtifactResponse` or even
/// the SOAP envelope) would be left dangling. Every inherited binding that the
/// element does not redeclare is therefore added to its start tag. Exclusive
/// canonicalization ignores namespace declarations that are not visibly
/// utilized, so the extra declarations cannot change a signature digest.
pub(crate) fn self_contained_xml(doc: &Document<'_>, node: NodeId) -> String {
    let fragment = doc.node_to_xml(node);
    let Some(elem) = doc.element(node) else {
        return fragment;
    };
    let mut seen: Vec<&str> = elem
        .namespace_declarations
        .iter()
        .map(|(p, _)| p.as_ref())
        .collect();
    let mut inherited: Vec<(&str, &str)> = Vec::new();
    let mut cur = doc.parent(node);
    while let Some(p) = cur {
        if let Some(e) = doc.element(p) {
            for (prefix, uri) in &e.namespace_declarations {
                let prefix: &str = prefix.as_ref();
                if prefix == "xml" || prefix == "xmlns" || seen.contains(&prefix) {
                    continue;
                }
                seen.push(prefix);
                inherited.push((prefix, uri.as_ref()));
            }
        }
        cur = doc.parent(p);
    }
    if inherited.is_empty() || !fragment.starts_with('<') {
        return fragment;
    }
    let name_end = fragment[1..]
        .find(|c: char| c.is_whitespace() || c == '>' || c == '/')
        .map(|i| i + 1)
        .unwrap_or(fragment.len());
    let mut decls = String::new();
    for (prefix, uri) in inherited {
        use bergshamra_c14n::escape::escape_attr;
        if prefix.is_empty() {
            decls.push_str(&format!(" xmlns=\"{}\"", escape_attr(uri)));
        } else {
            decls.push_str(&format!(" xmlns:{prefix}=\"{}\"", escape_attr(uri)));
        }
    }
    format!(
        "{}{}{}",
        &fragment[..name_end],
        decls,
        &fragment[name_end..]
    )
}

// ── Signatures ──────────────────────────────────────────────────────────────

/// Locate the single *enveloping* `<ds:Signature>` of `element_node`: it MUST
/// be a direct child, there MUST be exactly one such child, and it MUST be the
/// first `<ds:Signature>` in the element's subtree in document order.
///
/// The verifier processes the first signature it encounters, so a nested
/// signature placed earlier (a genuine RD signature wrapped inside a forged
/// outer element) would be the one verified while the structural checks look
/// at the enveloping one. Genuine eID messages always place the enveloping
/// signature first (`Issuer` → `Signature` → …), so this only rejects wrapped
/// documents.
pub(crate) fn enveloping_signature(
    doc: &Document<'_>,
    element_node: NodeId,
    element: &'static str,
) -> Result<NodeId, NlEidError> {
    let direct = element_children(doc, element_node, constants::NS_DS, "Signature");
    let [sig] = direct[..] else {
        return Err(if direct.is_empty() {
            NlEidError::MissingSignature(element)
        } else {
            NlEidError::AmbiguousSignature(element)
        });
    };
    let first_in_subtree = descendant_elements(doc, element_node)
        .into_iter()
        .find(|n| is_element(doc, *n, constants::NS_DS, "Signature"));
    if first_in_subtree != Some(sig) {
        return Err(NlEidError::AmbiguousSignature(element));
    }
    Ok(sig)
}

/// The `<ds:KeyInfo>/<ds:KeyName>` of a signature, if present.
pub(crate) fn signature_key_name(doc: &Document<'_>, sig: NodeId) -> Option<String> {
    let key_info = element_child(doc, sig, constants::NS_DS, "KeyInfo")?;
    let key_name = element_child(doc, key_info, constants::NS_DS, "KeyName")?;
    text_only(doc, key_name).filter(|s| !s.is_empty())
}

/// §9.2: an RD signature MUST carry a `<ds:KeyName>` that corresponds to a
/// `<ds:KeyName>` in a `<md:KeyDescriptor>` of the RD's verified metadata. The
/// verifier's key manager is expected to hold the RD keys under exactly those
/// names (see [`super::metadata::RdMetadata::keys_manager`]).
pub(crate) fn require_known_key_name(
    doc: &Document<'_>,
    sig: NodeId,
    verifier: &SamlVerifier,
) -> Result<String, NlEidError> {
    let name = signature_key_name(doc, sig)
        .ok_or_else(|| NlEidError::UnknownSigningKey("KeyInfo has no KeyName".to_string()))?;
    if verifier.keys_manager().find_by_name(&name).is_none() {
        return Err(NlEidError::UnknownSigningKey(format!(
            "KeyName {name:?} is not a key from the RD metadata"
        )));
    }
    Ok(name)
}

/// What a successfully verified enveloping signature established.
#[derive(Debug, Clone)]
pub(crate) struct VerifiedSignature {
    /// The `<ds:KeyName>` the signature carried (and the key that verified it).
    pub key_name: String,
    /// SAML object IDs covered by the verified XML-DSig references.
    pub signed_ids: Vec<String>,
}

/// Verify the enveloping signature of `element_node` (whose standalone XML is
/// `element_xml`) and bind it to the element's `@ID` (ADR 0028).
///
/// Steps: structural check ([`enveloping_signature`]), §9.2 `KeyName` check,
/// cryptographic verification with `verifier` (trusted keys only, strict
/// reference positions, E91), every reference digest locally verified, and the
/// verified references MUST include `element_node` itself (an empty URI or
/// `#<ID>`).
pub(crate) fn verify_enveloping_signature(
    doc: &Document<'_>,
    element_node: NodeId,
    element_xml: &str,
    verifier: &SamlVerifier,
    element: &'static str,
) -> Result<VerifiedSignature, NlEidError> {
    let sig = enveloping_signature(doc, element_node, element)?;
    let key_name = require_known_key_name(doc, sig, verifier)?;
    let id = element_id(doc, element_node).ok_or_else(|| {
        NlEidError::MalformedMessage(format!(
            "{element} has no ID attribute to bind the signature to"
        ))
    })?;

    let result = match verifier.verify_enveloped(element_xml) {
        Ok(r) => r,
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
    let signed_ids = bind_verified_references(&result, id, element)?;
    Ok(VerifiedSignature {
        key_name,
        signed_ids,
    })
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

/// Bound an `@IssueInstant` / `@AuthnInstant` on both sides: it may be at most
/// `max_age_seconds` (plus skew) in the past and at most `skew_seconds` in the
/// future.
pub(crate) fn check_freshness(
    instant: DateTime<Utc>,
    now: DateTime<Utc>,
    skew_seconds: u64,
    max_age_seconds: u64,
    element: &'static str,
) -> Result<(), NlEidError> {
    let skew = seconds(skew_seconds);
    let stale_after = instant
        .checked_add_signed(seconds(max_age_seconds))
        .and_then(|t| t.checked_add_signed(skew))
        .ok_or_else(|| NlEidError::StaleMessage {
            element,
            detail: format!("instant {instant} is outside the usable range"),
        })?;
    let not_before = instant
        .checked_sub_signed(skew)
        .ok_or_else(|| NlEidError::StaleMessage {
            element,
            detail: format!("instant {instant} is outside the usable range"),
        })?;
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
/// encryption algorithm declared anywhere below (and including) `node` is one
/// the specification permits (§9.1, §9.3).
///
/// This runs over the whole received document, including the `<saml:Advice>`
/// evidence assertions, before any cryptographic processing: §9.1 binds every
/// participant, and a weak algorithm anywhere in the message is a reason to
/// reject it rather than to reason about which parts it affects. The one
/// exception is an `<xenc:EncryptedKey>` wrapped for another recipient
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
                "Transforms" if ctx.in_reference => {
                    check_transform_list(doc, node)?;
                }
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

/// §9.1: a Reference applies the enveloped-signature transform exactly once and
/// at most one exclusive-c14n transform, which (yielding octets) comes last.
fn check_transform_list(doc: &Document<'_>, transforms: NodeId) -> Result<(), NlEidError> {
    let uris: Vec<&str> = element_children(doc, transforms, constants::NS_DS, "Transform")
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

// ── Signing helpers ─────────────────────────────────────────────────────────

/// Insert `template` into `xml` as the first child of its document element.
/// Used for metadata, where `<ds:Signature>` precedes every other child of
/// `<md:EntityDescriptor>`.
pub(crate) fn insert_signature_as_first_child(
    xml: &str,
    template: &str,
) -> Result<String, NlEidError> {
    let doc = crate::xml::parse_secure_metadata(xml)?;
    let root = doc
        .document_element()
        .ok_or_else(|| NlEidError::MalformedMessage("document has no root element".to_string()))?;
    let range = doc
        .node_range(root)
        .ok_or_else(|| NlEidError::MalformedMessage("root has no source range".to_string()))?;
    // The start tag ends at the first '>' of the root element's source that is
    // not inside an attribute value; the parser already guaranteed the start
    // tag is well-formed, so locate it by scanning quotes.
    let src = &xml[range.clone()];
    let mut in_quote: Option<u8> = None;
    let mut end_of_start_tag = None;
    for (i, b) in src.bytes().enumerate() {
        match (in_quote, b) {
            (None, b'"') | (None, b'\'') => in_quote = Some(b),
            (Some(q), c) if c == q => in_quote = None,
            (None, b'>') => {
                end_of_start_tag = Some(range.start + i + 1);
                break;
            }
            _ => {}
        }
    }
    let at = end_of_start_tag.ok_or_else(|| {
        NlEidError::MalformedMessage("cannot locate the end of the root start tag".to_string())
    })?;
    if src.ends_with("/>") && at == range.end {
        return Err(NlEidError::MalformedMessage(
            "cannot place a signature inside an empty root element".to_string(),
        ));
    }
    Ok(format!("{}{}{}", &xml[..at], template, &xml[at..]))
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
    fn test_text_only_concatenates_and_rejects_elements() {
        // (A comment splitting element text is rejected by the parser itself,
        // so the concatenation path only ever joins text with CDATA.)
        let doc = crate::xml::parse_secure_metadata(
            r#"<a xmlns="urn:x"><b> one two </b><d><e/></d><f/></a>"#,
        )
        .unwrap();
        let root = doc.document_element().unwrap();
        let b = element_child(&doc, root, "urn:x", "b").unwrap();
        let d = element_child(&doc, root, "urn:x", "d").unwrap();
        let f = element_child(&doc, root, "urn:x", "f").unwrap();
        assert_eq!(text_only(&doc, b).as_deref(), Some("one two"));
        assert!(text_only(&doc, d).is_none());
        assert_eq!(text_only(&doc, f).as_deref(), Some(""));
    }

    #[test]
    fn test_self_contained_xml_adds_inherited_declarations() {
        let xml = format!(
            r#"<soap:Envelope xmlns:soap="{}" xmlns:saml="{}"><soap:Body><samlp:ArtifactResponse xmlns:samlp="{SAMLP}" ID="_a"><saml:Issuer>rd</saml:Issuer></samlp:ArtifactResponse></soap:Body></soap:Envelope>"#,
            constants::NS_SOAP11,
            constants::NS_SAML_ASSERTION
        );
        let doc = crate::xml::parse_secure(&xml).unwrap();
        let root = doc.document_element().unwrap();
        let body = element_child(&doc, root, constants::NS_SOAP11, "Body").unwrap();
        let art = element_child(&doc, body, SAMLP, "ArtifactResponse").unwrap();
        let standalone = self_contained_xml(&doc, art);
        assert!(
            standalone.starts_with("<samlp:ArtifactResponse"),
            "{standalone}"
        );
        // Re-parses on its own, with the Issuer still in the SAML namespace.
        let doc2 = crate::xml::parse_secure(&standalone).unwrap();
        let root2 = doc2.document_element().unwrap();
        assert!(is_element(&doc2, root2, SAMLP, "ArtifactResponse"));
        assert!(
            element_child(&doc2, root2, constants::NS_SAML_ASSERTION, "Issuer").is_some(),
            "{standalone}"
        );
        // An element that declares everything itself is returned unchanged.
        let plain = crate::xml::parse_secure(&standalone).unwrap();
        let n = plain.document_element().unwrap();
        assert_eq!(self_contained_xml(&plain, n), plain.node_to_xml(n));
    }

    #[test]
    fn test_enveloping_signature_requires_single_first_direct_child() {
        let good = format!(
            r#"<samlp:ArtifactResponse xmlns:samlp="{SAMLP}" ID="_a">{}<samlp:Status/><samlp:Response>{}</samlp:Response></samlp:ArtifactResponse>"#,
            sig("_a"),
            sig("_r")
        );
        let doc = crate::xml::parse_secure(&good).unwrap();
        let root = doc.document_element().unwrap();
        assert!(enveloping_signature(&doc, root, "ArtifactResponse").is_ok());

        // A nested signature placed before the enveloping one is wrapping.
        let wrapped = format!(
            r#"<samlp:ArtifactResponse xmlns:samlp="{SAMLP}" ID="_a"><samlp:Response>{}</samlp:Response>{}</samlp:ArtifactResponse>"#,
            sig("_r"),
            sig("_a")
        );
        let doc = crate::xml::parse_secure(&wrapped).unwrap();
        let root = doc.document_element().unwrap();
        assert!(matches!(
            enveloping_signature(&doc, root, "ArtifactResponse"),
            Err(NlEidError::AmbiguousSignature(_))
        ));

        // Two direct signatures are ambiguous; none is missing.
        let two = format!(
            r#"<samlp:ArtifactResponse xmlns:samlp="{SAMLP}" ID="_a">{}{}</samlp:ArtifactResponse>"#,
            sig("_a"),
            sig("_a")
        );
        let doc = crate::xml::parse_secure(&two).unwrap();
        let root = doc.document_element().unwrap();
        assert!(matches!(
            enveloping_signature(&doc, root, "ArtifactResponse"),
            Err(NlEidError::AmbiguousSignature(_))
        ));
        let none = format!(r#"<samlp:ArtifactResponse xmlns:samlp="{SAMLP}" ID="_a"/>"#);
        let doc = crate::xml::parse_secure(&none).unwrap();
        let root = doc.document_element().unwrap();
        assert!(matches!(
            enveloping_signature(&doc, root, "ArtifactResponse"),
            Err(NlEidError::MissingSignature(_))
        ));
    }

    #[test]
    fn test_signature_key_name() {
        let xml = format!(
            r#"<samlp:ArtifactResponse xmlns:samlp="{SAMLP}" ID="_a">{}</samlp:ArtifactResponse>"#,
            sig("_a")
        );
        let doc = crate::xml::parse_secure(&xml).unwrap();
        let root = doc.document_element().unwrap();
        let s = enveloping_signature(&doc, root, "ArtifactResponse").unwrap();
        assert_eq!(signature_key_name(&doc, s).as_deref(), Some("k1"));
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
                constants::SIG_RSA_SHA256,
                "http://www.w3.org/2000/09/xmldsig#rsa-sha1",
                "signature",
            ),
            (
                constants::SIG_RSA_SHA256,
                "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256",
                "signature",
            ),
            (constants::DIGEST_SHA256, constants::DIGEST_SHA1, "digest"),
            (
                &format!(
                    r#"CanonicalizationMethod Algorithm="{}""#,
                    constants::C14N_EXCLUSIVE
                ),
                r#"CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#WithComments""#,
                "canonicalization",
            ),
            (
                &format!(
                    r#"Transform Algorithm="{}"/><ds:Transform Algorithm="{}""#,
                    constants::TRANSFORM_ENVELOPED_SIGNATURE,
                    constants::C14N_EXCLUSIVE
                ),
                &format!(
                    r#"Transform Algorithm="{}"/><ds:Transform Algorithm="http://www.w3.org/TR/1999/REC-xpath-19991116""#,
                    constants::TRANSFORM_ENVELOPED_SIGNATURE
                ),
                "transform",
            ),
        ] {
            let bad = ok.replacen(from, to, 1);
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
        let parse_check = |xml: String| {
            let doc = crate::xml::parse_secure(&xml).unwrap();
            validate_algorithms(&doc, doc.document_element().unwrap(), None)
        };
        assert!(parse_check(enc(
            constants::ENC_AES256_CBC,
            constants::KEYTRANSPORT_RSA_OAEP_MGF1P,
            constants::DIGEST_SHA1
        ))
        .is_ok());
        assert!(matches!(
            parse_check(enc(
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
            parse_check(enc(
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
        // A foreign key with a weak transport does not fail the message ...
        assert!(validate_algorithms(&doc, root, Some("urn:me")).is_ok());
        // ... but without a recipient to compare against every key counts.
        assert!(validate_algorithms(&doc, root, None).is_err());
        // And our own key using rsa-1_5 is rejected.
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
        // c14n before enveloped: rejected.
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
        // Only c14n, no enveloped transform: rejected.
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
        // The edges of chrono's range must be rejected, never panicked on.
        assert!(check_freshness(DateTime::<Utc>::MAX_UTC, now, 30, 300, "x").is_err());
        assert!(check_freshness(DateTime::<Utc>::MIN_UTC, now, 30, 300, "x").is_err());
    }

    #[test]
    fn test_insert_signature_as_first_child() {
        let xml = r#"<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="a>b" ID="_m"><md:SPSSODescriptor/></md:EntityDescriptor>"#;
        let out = insert_signature_as_first_child(xml, "<S/>").unwrap();
        assert!(
            out.contains(r#"ID="_m"><S/><md:SPSSODescriptor/>"#),
            "{out}"
        );
        assert!(insert_signature_as_first_child(
            r#"<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"/>"#,
            "<S/>"
        )
        .is_err());
    }
}
