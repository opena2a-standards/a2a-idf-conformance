# A2A-IDF Conformance Suite

Canonical conformance suite for the **A2A-IDF** (Agent-to-Agent Identity Framework) specification proposed in [a2aproject/A2A#1496](https://github.com/a2aproject/A2A/pull/1496).

Implementations of A2A-IDF run the fixtures in this repository to verify byte-match interoperability against the reference vectors. The suite is intentionally narrow: it covers the identity-framework layer (verification levels, attestation array shape, delegation chain envelopes, message-signing wire format) and composes with adjacent conformance suites for the wire signature layer ([#1829](https://github.com/a2aproject/A2A/issues/1829)), identity-claim envelope layer ([#1786](https://github.com/a2aproject/A2A/issues/1786) CTEF), and delegation/continuity layer ([#1575](https://github.com/a2aproject/A2A/issues/1575) APS).

## Status

Active construction. The directory structure is fixed; fixtures land incrementally in coordination with the A2A-IDF specification cycle ([#1496](https://github.com/a2aproject/A2A/pull/1496)) and the broader four-layer alignment.

**Shipped:**

- [`vectors/rfc8032-7-1.json`](./vectors/rfc8032-7-1.json) — canonical RFC 8032 §7.1 Test 1 Ed25519 keypair (PEM SPKI, raw hex, multibase, JWK).
- [`fixtures/composition/aim-did-rfc9421/signature-alone.json`](./fixtures/composition/aim-did-rfc9421/signature-alone.json) — byte-matches [Envoys signature/v1 §13 Vector 1](https://envoys.me/specs/signature/v1) with the `keyid` URL resolving to a W3C DID Document (Ed25519VerificationKey2020 + publicKeyMultibase) instead of the Envoys compact form. This is the core interop claim of A2A-IDF §6: dual-shape keyid resolution does not change the signature bytes.
- [`scripts/verify.mjs`](./scripts/verify.mjs) and [`scripts/verify.py`](./scripts/verify.py) — reference verifiers. Node stdlib `crypto` and Python `cryptography` only; no dependency on any A2A-IDF implementation library.

| Layer | Spec | Suite |
|---|---|---|
| Wire signature (per-message RFC 9421 + Ed25519) | [#1829](https://github.com/a2aproject/A2A/issues/1829) | [`envoys-rfc9421/`](https://github.com/aeoess/aps-conformance-suite) (external) |
| **Identity framework (verification levels, attestations, delegation chains)** | **[#1496](https://github.com/a2aproject/A2A/pull/1496)** | **this repo** |
| Identity claims (CTEF) | [#1786](https://github.com/a2aproject/A2A/issues/1786) | external |
| Delegation and continuity (APS) | [#1575](https://github.com/a2aproject/A2A/issues/1575) | external |

## Layout

```
fixtures/
  levels/          Verification-level fixtures (Level 0 self-asserted, Level 1 domain-verified, Level 2 organization-verified)
  composition/     Multi-layer composition fixtures (A2A-IDF wrap of #1829 wire signatures, with DID Document or compact-form key resolution)
vectors/           Pinned test vectors (Ed25519 keypairs per RFC 8032 §7.1, request/response byte sequences)
scripts/           Reference verifiers and fixture builders (Node.js, Python)
```

## Composition fixtures

The first composition fixture under construction is `fixtures/composition/aim-did-rfc9421/`, which exercises:

- **L1:** [#1829](https://github.com/a2aproject/A2A/issues/1829) wire signature (Ed25519 over RFC 9421 components `("@method" "@path" "content-digest")` with `created` / `nonce` / `keyid`)
- **L2:** [#1496](https://github.com/a2aproject/A2A/pull/1496) identity-framework wrap (A2A-IDF extension under `metadata`)
- **Key resolution:** W3C DID Document with `Ed25519VerificationKey2020` and `publicKeyMultibase`

Three shapes per fixture, pinned to the RFC 8032 §7.1 keypair:

1. Signature alone
2. Signature wrapped in a bilateral receipt envelope
3. Signature wrapped in a 3-link delegation chain

These shapes parallel the `envoys-rfc9421/` fixtures hosted in `aeoess/aps-conformance-suite` so that any verifier passing both suites can demonstrate cross-implementation byte-match.

## Reference implementation

[**AIM**](https://github.com/opena2a-org) is the canonical reference implementation of A2A-IDF and ships Ed25519 message signing, JCS canonicalization, and W3C DID Document resolution today. AIM does not have a privileged position in the specification — any conforming implementation may serve as the basis for cross-validation — but its production deployment is the source of the test vectors in this suite.

## Contributing

Pull requests welcome. Conformance vectors must be reproducible from the documented inputs (keypair, body, parameters) and must pass the verifier in `scripts/`. Implementation-specific fixtures (Envoys, APS, CTEF, AIP, Hippo) belong in their respective home repositories; this suite is for A2A-IDF-layer vectors and cross-layer composition.

Coordination thread: [a2aproject/A2A#1496](https://github.com/a2aproject/A2A/pull/1496).

## License

Apache License 2.0. See [LICENSE](./LICENSE).
