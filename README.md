# A2A-IDF Conformance Suite

Canonical conformance suite for the **A2A-IDF** (Agent-to-Agent Identity Framework) specification proposed in [a2aproject/A2A#1496](https://github.com/a2aproject/A2A/pull/1496).

Implementations of A2A-IDF run the fixtures in this repository to verify byte-match interoperability against the reference vectors, and compare their verdicts with the pinned outcomes and the reference verifiers through the parity gate (see [Testing an implementation](#testing-an-implementation)). The suite is intentionally narrow: it covers the identity-framework layer (verification levels, attestation array shape, message-signing wire format, delegation chain and bilateral receipt envelope shapes (unverified)) and composes with adjacent conformance suites for the wire signature layer ([#1829](https://github.com/a2aproject/A2A/issues/1829)) and the delegation/continuity layer ([#1575](https://github.com/a2aproject/A2A/issues/1575) APS). The identity-claim envelope layer ([#1786](https://github.com/a2aproject/A2A/issues/1786) CTEF) is adjacent but not yet composed: no fixture, schema or verifier code in this repository exercises a CTEF envelope, and a composition fixture depends on the upstream envelope decision.

## Status

Byte-pinned and CI-enforced. Every fixture is pinned in [`MANIFEST.sha256`](./MANIFEST.sha256); generator-owned fixtures are reproducible from their documented inputs by [`scripts/generate-fixtures.mjs`](./scripts/generate-fixtures.mjs), and externally contributed snapshot fixtures (regenerated in their source implementation, noted per directory) are preserved and pinned by the same run. CI regenerates the set on every push to `main` and every pull request, and fails on any byte drift. New fixtures land incrementally in coordination with the A2A-IDF specification cycle ([#1496](https://github.com/a2aproject/A2A/pull/1496)) and the broader four-layer alignment.

**Shipped (41 fixtures):**

- [`fixtures/composition/aim-did-rfc9421/`](./fixtures/composition/aim-did-rfc9421/): three positive fixtures that byte-match [Envoys signature/v1 §14 Vectors 1-3](https://envoys.me/specs/signature/v1) with the `keyid` URL resolving to a W3C DID Document (Ed25519VerificationKey2020 + publicKeyMultibase) instead of the Envoys compact form — the core interop claim of A2A-IDF §6: dual-shape keyid resolution does not change the signature bytes. Plus four negative fixtures (tampered signature, substituted key, tampered body, and a signature that verifies but is not the declared Envoys vector) that a conforming verifier MUST reject, one that pins a `null` signature tag as an absent tag, and a pair that pins the Envoys §4.3 tag rule: an absent tag is accepted as `a2a-message`, and a correctly signed request with any other tag is rejected (`TAG_MISMATCH`). One more fixture carries a foreign tag and an altered signature and pins that the tag rule runs before signature verification.
- [`fixtures/composition/hippo-rfc9421/`](./fixtures/composition/hippo-rfc9421/): two snapshot fixtures contributed from [lawcontinue/hippo-auth](https://github.com/lawcontinue/hippo-auth), an independent Ed25519 + RFC 9421 implementation — §4.3 `tag=a2a-message` present and absent (absent ≡ `a2a-message` back-compat; both reference verifiers enforce the rule, and the rejection of any other tag is pinned in `aim-did-rfc9421/signature-tag-foreign.json`). Second-implementation evidence for the wire layer; signatures verified by both reference verifiers in this suite.
- [`fixtures/levels/`](./fixtures/levels/): twenty-eight fixtures for A2A-IDF §1 verification levels — Level 0 SELF_ASSERTED, Level 1 DOMAIN_VERIFIED (pinned `_a2a-identity` DNS TXT record, key fingerprint binding, and the [provider domain](./fixtures/levels/README.md#provider-domain) derived from `provider.url` as the WHATWG URL parser reports it: an internationalized host, a percent-encoded host, a backslash in the authority, a UTS #46 ignored code point, a numeric IPv4 form, a URL without a host and a URL that does not parse), Level 2 ORGANIZATION_VERIFIED (registry attestation signed over the RFC 8785 JCS form), plus two Level 2 attestations that pin RFC 8785 §3.2.3 property ordering by UTF-16 code unit (one against code-point order, with a key outside the BMP alongside one in U+E000-U+FFFF, and one against numeric and case-insensitive order, with ASCII keys) and five fixtures with a malformed field (a `null` agentId, an `attestations` value that is not an array, a `provider.url` that is not a string, a string `issuer`, an array `verifiedAt`). Every one of the nine reject categories has a single-defect negative fixture, and two multi-defect fixtures pin the documented [check order](./fixtures/levels/README.md#check-order-cross-implementation-contract).
- [`vectors/rfc8032-7-1.json`](./vectors/rfc8032-7-1.json) and [`vectors/rfc8032-7-1-test2.json`](./vectors/rfc8032-7-1-test2.json): RFC 8032 §7.1 Test 1 (agent) and Test 2 (registry issuer) Ed25519 keypairs in every encoded form the fixtures use.
- [`scripts/verify.mjs`](./scripts/verify.mjs) and [`scripts/verify.py`](./scripts/verify.py): reference verifiers. Node stdlib `crypto` and Python `cryptography` only; no dependency on any A2A-IDF implementation library. A [parity gate](./scripts/parity/parity.py) asserts both implementations agree per fixture on gate, verdict, and reject category.
- [`conformance.json`](./conformance.json): machine-readable profile mapping every tested requirement to its fixture and pinned outcome, derived from the fixtures themselves (CI fails if stale).

| Layer | Spec | Suite |
|---|---|---|
| Wire signature (per-message RFC 9421 + Ed25519) | [#1829](https://github.com/a2aproject/A2A/issues/1829) | [`envoys-rfc9421/`](https://github.com/aeoess/aps-conformance-suite) (external) |
| **Identity framework (verification levels, attestations, delegation chain envelope shapes (unverified))** | **[#1496](https://github.com/a2aproject/A2A/pull/1496)** | **this repo** |
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

## Testing an implementation

Wrap your implementation in a command that takes a fixtures directory, evaluates every `*.json` fixture under it, and prints the reference verifier output format (`PASS|FAIL|ERROR <path>`, then `observed: ACCEPT` or `observed: REJECT[CATEGORY]`). Then add it to the parity gate:

```bash
python3 scripts/parity/parity.py --verifier mylib="node ../mylib/conformance.js"
```

The gate runs it beside both reference verifiers and reports `PARITY: PASS` only when every implementation agrees on every fixture and matches the outcome pinned in the fixture. The full input and output contract is in [`scripts/README.md`](./scripts/README.md#testing-another-implementation).

## Composition fixtures

The first composition fixture set is `fixtures/composition/aim-did-rfc9421/`, which exercises:

- **L1:** [#1829](https://github.com/a2aproject/A2A/issues/1829) wire signature (Ed25519 over RFC 9421 components `("@method" "@path" "content-digest")` with `created` / `nonce` / `keyid`)
- **L2:** [#1496](https://github.com/a2aproject/A2A/pull/1496) identity-framework layer: A2A-IDF §6 keyid resolution (DID Document), pinned in each fixture's `keyidResolution` member
- **Key resolution:** W3C DID Document with `Ed25519VerificationKey2020` and `publicKeyMultibase`

Three shapes per fixture, pinned to the RFC 8032 §7.1 keypair:

1. Signature alone
2. Signature wrapped in a bilateral receipt envelope
3. Signature wrapped in a 3-link delegation chain

The reference verifiers check the wire signature in all three shapes. The envelopes are pinned as data only: the chain links and the receipt carry no signatures, and neither verifier reads the `envelope` block, so a chain whose scope widens or whose expiry increases is still accepted. Envelope verification is listed under `notCovered` in [`conformance.json`](./conformance.json).

These shapes parallel the `envoys-rfc9421/` fixtures hosted in `aeoess/aps-conformance-suite` so that any verifier passing both suites can demonstrate cross-implementation byte-match.

## Reference implementation

[**AIM**](https://github.com/opena2a-org) is the canonical reference implementation of A2A-IDF and ships Ed25519 message signing, JCS canonicalization, and W3C DID Document resolution today. AIM does not have a privileged position in the specification: any conforming implementation may serve as the basis for cross-validation.

The test vectors in this suite are not taken from AIM or from any deployment. The keypairs in [`vectors/`](./vectors/) are the RFC 8032 §7.1 Test 1 and Test 2 seeds, and every generator-owned fixture is derived from those two seeds and the templates in [`scripts/generate-fixtures.mjs`](./scripts/generate-fixtures.mjs). The generator also asserts that the `aim-did-rfc9421/` composition signatures byte-match [Envoys signature/v1 §14 Vectors 1-3](https://envoys.me/specs/signature/v1). The two `hippo-rfc9421/` fixtures are snapshots produced by the [hippo-auth](https://github.com/lawcontinue/hippo-auth) signing path and pinned as contributed.

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
