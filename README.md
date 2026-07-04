# A2A-IDF Conformance Suite

Canonical conformance suite for the **A2A-IDF** (Agent-to-Agent Identity Framework) specification proposed in [a2aproject/A2A#1496](https://github.com/a2aproject/A2A/pull/1496).

Implementations of A2A-IDF run the fixtures in this repository to verify byte-match interoperability against the reference vectors. The suite is intentionally narrow: it covers the identity-framework layer (verification levels, attestation array shape, delegation chain envelopes, message-signing wire format) and composes with adjacent conformance suites for the wire signature layer ([#1829](https://github.com/a2aproject/A2A/issues/1829)), identity-claim envelope layer ([#1786](https://github.com/a2aproject/A2A/issues/1786) CTEF), and delegation/continuity layer ([#1575](https://github.com/a2aproject/A2A/issues/1575) APS).

## Status

Byte-pinned and CI-enforced. Every fixture is pinned in [`MANIFEST.sha256`](./MANIFEST.sha256) and reproducible from its documented inputs by [`scripts/generate-fixtures.mjs`](./scripts/generate-fixtures.mjs); CI regenerates the set on every push and fails on any byte drift. New fixtures land incrementally in coordination with the A2A-IDF specification cycle ([#1496](https://github.com/a2aproject/A2A/pull/1496)) and the broader four-layer alignment.

**Shipped (13 fixtures):**

- [`fixtures/composition/aim-did-rfc9421/`](./fixtures/composition/aim-did-rfc9421/): three positive fixtures that byte-match [Envoys signature/v1 §14 Vectors 1-3](https://envoys.me/specs/signature/v1) with the `keyid` URL resolving to a W3C DID Document (Ed25519VerificationKey2020 + publicKeyMultibase) instead of the Envoys compact form — the core interop claim of A2A-IDF §6: dual-shape keyid resolution does not change the signature bytes. Plus three negative fixtures (tampered signature, substituted key, tampered body) that a conforming verifier MUST reject.
- [`fixtures/levels/`](./fixtures/levels/): seven fixtures for A2A-IDF §1 verification levels — Level 0 SELF_ASSERTED, Level 1 DOMAIN_VERIFIED (pinned `_a2a-identity` DNS TXT record, key fingerprint binding), Level 2 ORGANIZATION_VERIFIED (registry attestation signed over the RFC 8785 JCS form), each with negative fixtures for the level's characteristic failure.
- [`vectors/rfc8032-7-1.json`](./vectors/rfc8032-7-1.json) and [`vectors/rfc8032-7-1-test2.json`](./vectors/rfc8032-7-1-test2.json): RFC 8032 §7.1 Test 1 (agent) and Test 2 (registry issuer) Ed25519 keypairs in every encoded form the fixtures use.
- [`scripts/verify.mjs`](./scripts/verify.mjs) and [`scripts/verify.py`](./scripts/verify.py): reference verifiers. Node stdlib `crypto` and Python `cryptography` only; no dependency on any A2A-IDF implementation library. A [parity gate](./scripts/parity/parity.py) asserts both implementations agree per fixture on gate, verdict, and reject category.
- [`conformance.json`](./conformance.json): machine-readable profile mapping every tested requirement to its fixture and pinned outcome, derived from the fixtures themselves (CI fails if stale).

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
vectors/           Pinned test vectors (Ed25519 keypairs per RFC 8032 §7.1)
scripts/           Reference verifiers, parity gate, deterministic fixture generator, profile generator
MANIFEST.sha256    SHA-256 byte-pin over every fixture and vector (generator-emitted, CI-verified)
conformance.json   Machine-readable conformance profile (derived from the fixtures, CI-verified)
COSIGNERS.md       Second-party cosignature registry over MANIFEST.sha256
```

## Composition fixtures

The first composition fixture set is `fixtures/composition/aim-did-rfc9421/`, which exercises:

- **L1:** [#1829](https://github.com/a2aproject/A2A/issues/1829) wire signature (Ed25519 over RFC 9421 components `("@method" "@path" "content-digest")` with `created` / `nonce` / `keyid`)
- **L2:** [#1496](https://github.com/a2aproject/A2A/pull/1496) identity-framework wrap (A2A-IDF extension under `metadata`)
- **Key resolution:** W3C DID Document with `Ed25519VerificationKey2020` and `publicKeyMultibase`

Three shapes per fixture, pinned to the RFC 8032 §7.1 keypair:

1. Signature alone
2. Signature wrapped in a bilateral receipt envelope
3. Signature wrapped in a 3-link delegation chain

These shapes parallel the `envoys-rfc9421/` fixtures hosted in `aeoess/aps-conformance-suite` so that any verifier passing both suites can demonstrate cross-implementation byte-match.

## Reference implementation

[**AIM**](https://github.com/opena2a-org) is the canonical reference implementation of A2A-IDF and ships Ed25519 message signing, JCS canonicalization, and W3C DID Document resolution today. AIM does not have a privileged position in the specification (any conforming implementation may serve as the basis for cross-validation), but its production deployment is the source of the test vectors in this suite.

## Contributing

Pull requests welcome.

### Two kinds of fixtures, two homes

| Fixture kind | Example | Lives in |
|---|---|---|
| **Implementation-only.** A wire-format implementation's own conformance vectors. | Envoys §14 Vectors 1-3 in `envoys-rfc9421/`; APS continuity vectors; CTEF envelope vectors. | The implementation's home repository. |
| **Cross-layer composition.** An implementation's wire signature combined with A2A-IDF §6 identity-framework resolution (compact-form or DID Document), proving the signature bytes are unchanged across resolution shapes. | `aim-did-rfc9421/signature-alone.json` (Envoys §14 Vector 1 wrapped with a W3C DID Document). | **This repo**, under `fixtures/composition/<impl>-<wire-spec>/`. |

If your PR wraps an existing wire-signature implementation in A2A-IDF §6 resolution to demonstrate dual-shape interoperability, it belongs here. If your PR pins your implementation's own primary vectors, those belong in your home repository and can be referenced from a composition fixture here.

### Requirements

1. **Generated, not hand-edited.** Fixtures are owned by [`scripts/generate-fixtures.mjs`](./scripts/generate-fixtures.mjs): add your fixture's generation code there and run it to emit the fixture and refresh `MANIFEST.sha256`. CI regenerates the whole set and fails on any byte difference, so a hand-edited fixture cannot merge. Snapshot-only fixtures (signatures committed without enough information to regenerate them) are not accepted.
2. **Passes both reference verifiers and the parity gate.** `node scripts/verify.mjs fixtures` and `python3 scripts/verify.py fixtures` must both report `0 fail`, and `python3 scripts/parity/parity.py` must report PARITY: PASS.
3. **Matches the schema** for its family: [`fixtures/composition/SCHEMA.md`](./fixtures/composition/SCHEMA.md) for composition fixtures, [`fixtures/levels/README.md`](./fixtures/levels/README.md) for verification-level fixtures.

Coordination thread: [a2aproject/A2A#1496](https://github.com/a2aproject/A2A/pull/1496).

## License

Apache License 2.0. See [LICENSE](./LICENSE).
