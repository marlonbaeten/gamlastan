# ADR 0045 — Dutch eID SAML interface (DV ↔ Routeringsdienst) as a layered profile module

- **Status:** Accepted
- **Date:** 2026-10-02
- **Deciders:** gamlastan maintainers
- **Spec:** [Koppelvlakspecificatie eID SAML v4.4](https://tvs.dictu.nl/documentatie-en-links/koppelvlakspecificatie) (Logius, 16 September 2020, final)
- **Implementation:** `crates/gamlastan/src/profiles/nl_eid/`

## Context

Dutch public-sector service providers (Dienstverleners, DVs) authenticate
citizens through a Routeringsdienst (RD) such as TVS, which routes to DigiD,
eHerkenning and eIDAS. The DV ↔ RD interface is the "Koppelvlakspecificatie
eID SAML v4.4", a restriction and extension of SAML V2.0 Web Browser SSO with
a message flow that differs from every profile gamlastan ships today:

- the `AuthnRequest` is sent over HTTP-POST and carries an `<samlp:Extensions>`
  block with an `IntendedAudience` and a `ServiceUUID` attribute (§7.3);
- the RD answers with an **artifact** (HTTP-Artifact); the DV resolves it over
  a mutually authenticated SOAP back-channel (§7.5, §9.4);
- the resolved message is an RD-signed `ArtifactResponse` → unsigned
  `Response` → RD-signed `Assertion` chain, in **cleartext**: only the
  identifiers (BSN, pseudonym) travel as `<saml:EncryptedID>` attribute values,
  with one `<xenc:EncryptedKey>` per recipient selected by `@Recipient`
  (§7.6, §7.6.3.4);
- assurance levels are ordered and requested with `Comparison="minimum"`
  (§7.6.3.2), keys are selected by `<ds:KeyName>` against verified metadata
  (§9.2), and the algorithm set is RSA-only with SHA-256 or stronger (§9.1).

An existing production DV implementation (the Kiesraad `e-ks` auth-service)
implements this interface against a private XML toolkit. The intent is to move
the protocol handling into gamlastan so that deployment keeps only what is not
SAML: PKIoverheid chain and OIN validation of RD certificates, the mTLS
transport, its pending-request store and browser-flow binding.

## Decision

Implement the interface as a **self-contained `profiles::nl_eid` module**,
following the structure ADR 0001 set for Sweden Connect: constants and a
deployment configuration that yields a `SecurityConfig`, request builders over
`profiles::sso::sp`, a response processor that drives the shared
`AssertionValidator` directly and adds the profile's own rules, metadata
helpers, and a profile error type with a SAML status mapping.

| File | Spec | Responsibility |
| --- | --- | --- |
| `constants.rs` | §3.1.1, §7.3, §7.6.3.4, §7.8, §9.1, §9.3, §10 | Namespaces, bindings, eID attribute names, identifier types, LoA URIs, status codes, algorithm allow-lists |
| `config.rs` | §7.6.2, §7.6.3, §9.5 | `NlEidConfig` → profile-correct `SecurityConfig` |
| `authn_context.rs` | §7.6.3.2, §10.3 | Ordered `LevelOfAssurance`, `Comparison="minimum"`, the ≥-minimum check |
| `entity_id.rs` | §10.2 | `urn:nl-eid-gdi:1.0:<ROLE>:<OIN>:entities:<index>` |
| `request.rs` | §7.3, §7.5, §7.7.1 | `AuthnRequest`, `ArtifactResolve`, `LogoutRequest`, enveloped signing |
| `response.rs` | §7.6, §7.6.3.5, §9.2, §9.3 | `process_artifact_response` and `AuthnOutcome` |
| `metadata.rs` | §8.3, §8.5 | DV metadata document; RD metadata reader and `KeyName`-keyed `KeysManager` |
| `logout.rs` | §7.7.2 | `LogoutResponse` validation |
| `rd.rs` | §7.6, §7.8, §9.2, §9.3 | RD-side message construction from the typed structs (the counterpart of `swedenconnect::idp`) |
| `xmlutil.rs` | — | Signature binding on top of `SamlVerifier`, §9 algorithm scan, freshness bounds, the few uppsala document operations the typed model cannot cover |

The module name is `nl_eid` (after the identifier scheme `urn:nl-eid-gdi`)
rather than the RD product name, so a deployment against another RD
implementation needs no rename.

## Consequences and the decisions inside the decision

### 1. Typed model first; the document tree only where the model is blind

As in the Sweden Connect profile, messages are read through the crate's
deserializers (`parse_saml`, `SamlDeserialize::from_xml`) and written through
its serializers and `XmlWriter`; no profile code splices namespace
declarations, cuts byte ranges or scans start tags. The document tree
(`uppsala`) is consulted for exactly three things the typed model cannot
carry: which `<ds:Signature>` element belongs to which SAML element, the
`<ds:KeyName>` of a signature, and the `<saml:EncryptedID>` elements that must
reach the decryptor byte-exact.

A subtree that has to leave the received document (an `EncryptedID`, or the
SAML element inside a SOAP `Body`) is copied with `Document::import_subtree`
into a fresh document and serialized from there. `node_to_xml` on the original
treats ancestor namespace bindings as in scope and omits them, which leaves a
dangling prefix when an RD declares `saml`/`samlp` on the `ArtifactResponse` or
the SOAP envelope; the writer of a fresh document synthesizes every declaration
the copied subtree needs. `xml::helpers::node_to_self_contained_xml` exposes
this, and `bindings::soap::soap_envelope_unwrap` now uses it too, which fixes
the same latent gap in its `body_xml`. Exclusive canonicalization ignores
declarations that are not visibly utilized, so the moved declarations cannot
change a digest; the integration test signs with the declarations on the
element and verifies with them moved to the envelope.

### 2. One verification pass over the received bytes; every consumed signature single, `KeyName`-selected and bound

The received `ArtifactResponse` document is verified once with
`SamlVerifier::verify_all_enveloped`, over the exact bytes it was parsed from.
The verifier reports one result per `<ds:Signature>` in document order, which
is the same order in which the tree enumerates them, so each verdict is
attached to its `<ds:Signature>` element and through that to the element it is
a child of. For each element the profile consumes (`ArtifactResponse`,
`Assertion`, and a `Response` that unexpectedly carries a signature) it then
requires exactly one direct `<ds:Signature>` child, a `<ds:KeyInfo>/<ds:KeyName>`
that names a key in the verifier's `KeysManager` (§9.2; bergshamra would fall
back to the first trusted key), and verified references that cover the
element's `@ID` (ADR 0028). Signatures the profile does not consume, such as
the AD's signature on the `<saml:Advice>` evidence assertion (§9.1), may be
invalid against the RD keys: they are never looked at. Nothing is
re-serialized for verification, so the bytes the RD signed are the bytes the
verifier sees.

### 3. Assertion signature required by default, configurable

§7.6.3 gives the assertion `Signature` cardinality 1 and the DV metadata
declares `WantAssertionsSigned="true"`, so `require_assertion_signature`
defaults to `true`. Some reference implementations rely on the enveloping
`ArtifactResponse` signature alone and treat inner signatures as evidence; the
flag can be switched off for them. When present the assertion signature is
always verified and bound, never ignored.

### 4. Identifiers are decrypted from a pruned `EncryptedID`

An `EncryptedID` may carry one `<xenc:EncryptedKey>` per recipient and per
published encryption certificate, referenced either inline or through a
`<ds:RetrievalMethod>`. The profile selects the `EncryptedID` whose
`EncryptedKey/@Recipient` is this DV, copies it into a standalone document,
detaches every other recipient's `EncryptedKey` (and the `RetrievalMethod`s
pointing at them) from that copy with the DOM, and only then serializes and
decrypts, so the backend can never pick a foreign key. The §9.1 / §9.3 algorithm scan also skips `EncryptedKey`s wrapped for
other recipients, as §7.6.3.4 says they SHOULD be ignored. The XML Encryption
backend uses the first RSA private key of its key manager, so
`DvDecryptionKeys` holds one `SamlDecryptor` per DV encryption key and tries
them in order (certificate rollover, §7.6.3.4.4).

### 5. Decrypted identifiers are zeroized and never printed

`SubjectId` wraps the BSN / pseudonym in `zeroize::Zeroizing<String>`; `Debug`
prints only the identifier type and the value length. This adds `zeroize` as a
direct dependency (it was already in the lock file transitively). Plaintext
copies the XML parser keeps while reading the decrypted `NameID` are
best-effort only.

### 6. Failed logins are outcomes, not errors

A well-formed, RD-signed answer to the DV's own `AuthnRequest` that reports a
non-success status is returned as `AuthnOutcome::Cancelled` (`Responder` /
`AuthnFailed`, §7.8.3) or `AuthnOutcome::Failed`, with the full `Status`. Every
structural, correlation or trust violation is an `NlEidError`. The distinction
lets the embedding application end its local session on a genuine failed login
(§9.9) while a cross-site GET with a garbage artifact cannot log a user out.

### 7. What stays outside the library

Recorded so the profile's boundary is unambiguous:

- **Trust in the RD metadata** — `parse_rd_metadata` reads endpoints and
  signing keys; verifying the metadata signature, the PKIoverheid chain and
  the OIN in the certificate subject (§9.1, §9.2), and pinning the endpoint
  hosts, remain with the deployment.
- **Transport** — the mutual-TLS SOAP back-channel (§9.4) and the HTTP-POST
  auto-submit page.
- **Pending-request store** — the profile matches `InResponseTo` against the
  request IDs the caller supplies; consuming them once (§9.7) and binding the
  browser to its flow stay with the application.
- **The LC role** (§6.3, §8.4) — not modelled; `IntendedAudience` is
  configurable so an LC layer can be added without an API break.
- **The RD role** — gamlastan is the DV here. `nl_eid::rd` builds the RD's
  messages from the typed structs so RD mocks and this crate's tests do not
  hand-write XML, but it is not an RD implementation: artifact issuance and
  the RD's own validation of DV requests are out of scope.

## Validation

- `cargo fmt --all -- --check`, `cargo clippy -p gamlastan --all-targets -- -D warnings` — clean.
- `cargo test -p gamlastan` — the module's unit tests plus
  `tests/nl_eid_artifact_flow.rs`, which builds RD-signed SOAP
  `ArtifactResponse`s through `nl_eid::rd` with dedicated test keys
  (`tests/fixtures/nl_eid/`) and covers: the happy path, SAML namespaces
  declared on the SOAP envelope, the TVS `RetrievalMethod` + sibling
  `EncryptedKey` layout, a `LegalSubjectID`, keys for another recipient,
  encryption-key rollover, the assertion-signature policy,
  cancellation and RD error statuses, a denied artifact resolution, wrong
  `InResponseTo` at every level, an unknown and a mismatched RD key, a
  signature-wrapping attempt, a foreign audience, LoA below the minimum and
  unknown, `ServiceUUID` mismatch, missing/foreign `EncryptedKey`, a
  non-persistent decrypted `NameID`, a forbidden `EncryptedAssertion`, stale
  and future timestamps, assertion replay, a SHA-1 digest, non-SAML bodies,
  and the signed `AuthnRequest` / `ArtifactResolve` / `LogoutRequest` / DV
  metadata and `LogoutResponse` validation.

## Alternatives considered

- **Re-serialize each signed sub-element and verify it alone with
  `verify_enveloped`.** This was the first implementation. Rejected in favour
  of one `verify_all_enveloped` pass over the received bytes with per-element
  binding: it needed the profile to splice inherited namespace declarations
  into the re-serialized element by hand, the kind of custom XML handling
  the module exists to retire, and it verified bytes the RD never signed.
- **Fail the message when any signature in it is invalid.** Rejected: the
  `<saml:Advice>` carries the AD's assertion with its own signature by a key
  the DV does not trust. Only the signatures of consumed elements are
  required to verify.
- **Return the decrypted identifiers as plain `String`s.** Rejected in favour
  of a zeroizing, redacting type; the one dependency is small and already in
  the tree.
- **Name the module after the RD (`tvs`).** Rejected: the specification is
  the interface, the RD is one implementation of it.
- **A separate crate.** Deferred for the same reasons as ADR 0001.
