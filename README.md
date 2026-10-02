# gamlastan

A comprehensive Rust SAML 2.0 library built on zero-copy XML parsing. The
library implements the full SAML 2.0 specification with errata corrections and
passes the Italian SPID (Sistema Pubblico di Identita Digitale) conformance
test suite (263/263 tests).

The plan is to become Rust equivalent of
[pysaml2](https://https://github.com/IdentityPython/pysaml2) project. We will
not be 100% compatible, but will try to close the gap. We thank the amazing
maintainers of the `pysaml2` project for maintaining the stack for the community.

The workspace requires Rust 1.88 or later.

## Workspace Structure

| Crate | Description |
|-------|-------------|
| `gamlastan` | Core SAML 2.0 library: types, XML, crypto, metadata, bindings, security, profiles |
| `gamlastan-actix` | actix-web integration (extractors, responders, handlers, middleware) |
| `gamlastan-mdq` | Metadata Query Protocol (MDQ) client: fetch entity metadata on demand, verify, and cache |

The `gamlastan` crate contains the following modules:

| Module | Description |
|--------|-------------|
| `core` | Core SAML 2.0 types (Issuer, NameID, Assertions, StatusCode, Conditions, etc.) |
| `xml` | XML serialization/deserialization via [uppsala](https://github.com/kushaldas/uppsala) |
| `crypto` | Cryptographic operations (signing, verification) via [bergshamra](https://github.com/kushaldas/bergshamra) |
| `metadata` | SAML metadata types, SPID extensions, caching, and validation |
| `bindings` | HTTP Redirect, POST, Artifact, SOAP, PAOS bindings and RelayState handling |
| `security` | 35-check assertion validator, replay cache, clock skew handling |
| `profiles` | Web Browser SSO (SP + IdP), SLO, ECP, artifact resolution, name ID management, Sweden Connect and Dutch eID deployment profiles |

## Deployment Profiles

In addition to the core SAML 2.0 profiles, gamlastan ships national deployment
profiles that layer restrictions and extensions on Web Browser SSO:

| Profile | Module | Description |
|---------|--------|-------------|
| Italian SPID | (built into `core`, `metadata`, `security`) | Italian public digital identity system; validated by the SPID conformance suite (see below) |
| Sweden Connect | `profiles::swedenconnect` | [Deployment Profile for the Swedish eID Framework](https://docs.swedenconnect.se/technical-framework/latest/02_-_Deployment_Profile_for_the_Swedish_eID_Framework.html) (Sweden Connect / DIGG) |
| Dutch eID | `profiles::nl_eid` | [Koppelvlakspecificatie eID SAML v4.4](https://tvs.dictu.nl/documentatie-en-links/koppelvlakspecificatie) (Logius): the Dienstverlener ↔ Routeringsdienst (TVS) interface to DigiD / eHerkenning / eIDAS |

The `swedenconnect` module implements the Swedish eID Framework as a restriction
and extension of Web Browser SSO, covering:

- **Levels of Assurance** -- the `LevelOfAssurance` enum, exact-comparison
  `RequestedAuthnContext` building, and the section 6.3.4 LoA matching check.
- **Deployment configuration** -- `SwedenConnectConfig` yields a profile-correct
  `SecurityConfig` (<= 1 minute clock skew, signed + encrypted responses,
  Destination/Recipient checks).
- **Metadata extensions** -- `mdui:UIInfo`, `mdattr:EntityAttributes` (entity
  categories + assurance certification), `shibmd:Scope`, and
  `idpdisc:DiscoveryResponse`.
- **Principal selection** -- the `psc:PrincipalSelection` request extension and
  `psc:RequestedPrincipalSelection` metadata extension.
- **Authentication for Signature** -- the `csig:SignMessage` and `sap:SADRequest`
  request extensions (section 7).
- **SP-side request/response** -- AuthnRequest construction (section 5) and
  Response processing: decrypt, signature verification, LoA match, structural
  checks (section 6).
- **IdP-side responses** -- Response and error construction (sections 6 and 6.4).

The ordinary Web Browser SSO profile is fully covered. Holder-of-key is supported
at the metadata/constant and `SubjectConfirmation`-method level; the mutual-TLS
transport requirement is a deployment concern outside the library. The DSS/SAP
`SignRequest`/`SignResponse` envelope and SAD verification are out of scope.

The `nl_eid` module implements the Dienstverlener (DV, Service Provider) side
of the Dutch eID SAML interface, whose flow is HTTP-POST `AuthnRequest` →
HTTP-Artifact → SOAP `ArtifactResolve` → RD-signed `ArtifactResponse` with
cleartext assertions and encrypted identifiers only:

- **Levels of Assurance** -- the ordered `LevelOfAssurance` enum, the
  `Comparison="minimum"` `RequestedAuthnContext`, and the section 7.6.3.2
  "equal or higher" check.
- **Deployment configuration** -- `NlEidConfig` (entityID, ServiceUUID, ACS,
  RD entityID, minimum LoA) yields a profile-correct `SecurityConfig`.
- **Requests** -- `AuthnRequest` with the `IntendedAudience` / `ServiceUUID`
  extension and AD/BVD pre-selection (section 7.3), `ArtifactResolve`
  (section 7.5), `LogoutRequest` (section 7.7.1), and enveloped RSA-SHA256
  signing of each.
- **Response processing** -- `process_artifact_response` verifies the RD
  signatures (single, first, `KeyName`-selected, bound to the consumed
  element), enforces sections 7.6.1–7.6.3.5, the section 9 algorithm
  allow-lists, the Level of Assurance and `ServiceUUID`, and decrypts the
  `ActingSubjectID` / `LegalSubjectID` `EncryptedID`s addressed to this DV
  into zeroized `SubjectId`s. Cancelled and failed logins are outcomes, not
  errors.
- **Metadata** -- the DV SP metadata document (section 8.3) with
  `KeyName`-named certificates, and a reader for the RD metadata (section 8.5)
  that yields the endpoints and a `KeysManager` keyed by `KeyName`.
- **Logout** -- `LogoutResponse` validation (section 7.7.2).
- **RD-side builders** -- `nl_eid::rd` builds the messages a Routeringsdienst
  sends (`Response` with the section 7.6.3 `Assertion`, `ArtifactResponse`,
  the section 7.8 statuses, `EncryptedID` identifiers, `KeyName`-only RD
  signatures) from the typed protocol structs, for RD mocks and tests.

Like the Sweden Connect profile, the module works on the typed model (the
crate's deserializers, serializers and `XmlWriter`) and uses the document tree
only for what the typed model cannot carry: which `ds:Signature` belongs to
which element, and the `EncryptedID` elements handed to the decryptor.

The DV role is complete; the cluster-connection-provider (LC) role is not
modelled. Trust in the RD metadata document (PKIoverheid chain, OIN), the
mutual-TLS back-channel and the pending-request store stay with the deployment.

## Security

gamlastan is built to fail closed against the SAML attack classes catalogued in
[`samlattacks.md`](samlattacks.md). The enforced controls — signature binding
against XML Signature Wrapping, request correlation, ready-handler trust
boundaries, and fail-closed key extraction and input validation — are documented
in [`docs/security-hardening.md`](docs/security-hardening.md), with the rationale
for each decision captured in the [Architecture Decision Records](docs/adr/).

## License

BSD-2-Clause
