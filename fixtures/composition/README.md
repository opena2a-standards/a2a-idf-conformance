# Composition fixtures

Multi-layer fixtures that exercise A2A-IDF in combination with adjacent layers (wire signature, identity claims, delegation/continuity).

## Shipped fixtures

### `aim-did-rfc9421/`

A2A-IDF identity-framework wrap of an [#1829](https://github.com/a2aproject/A2A/issues/1829) wire signature, with the `keyid` URL resolving to a W3C DID Document (`Ed25519VerificationKey2020` + `publicKeyMultibase`).

Three positive shapes per the [aps-conformance-suite](https://github.com/aeoess/aps-conformance-suite) composition convention:

- `signature-alone.json` — per-message signature, no enclosing envelope
- `bilateral-receipt.json` — signature wrapped in an APS bilateral receipt
- `delegation-chain-3link.json` — signature wrapped in a 3-link APS delegation chain

All three pin to the RFC 8032 §7.1 keypair so verifiers running both suites produce byte-identical results for the signature-alone case.

Plus three negative fixtures a conforming verifier MUST reject: `signature-tampered.json` (signature bytes altered in flight), `key-substituted.json` (DID Document serves a different valid Ed25519 key than the one that signed), and `body-tampered.json` (body modified and Content-Digest recomputed, signature not re-produced). See [`aim-did-rfc9421/README.md`](./aim-did-rfc9421/README.md) for the full table.

## Planned fixtures

### `envoys-rfc9421-cross-validate/` (planned)

Direct cross-validation against [`envoys-rfc9421/`](https://github.com/aeoess/aps-conformance-suite) fixtures. A2A-IDF verifiers MUST produce the same accept/reject decisions on these inputs as the Envoys reference verifier.

### `erc-8004-bridge/` (proposed, blocked on upstream)

Cross-layer composition between A2A-IDF (off-chain identity framework) and [ERC-8004](https://eips.ethereum.org/EIPS/eip-8004) (Ethereum on-chain Identity Registry). An Identity Registry entry's token URI resolves to an agent registration file; the proposed fixture set would pin both the on-chain entry hash and an off-chain A2A-IDF DID Document's wire signature.

Not scheduled. ERC-8004 is `status: Draft` on the EIP track (checked 2026-08-19 against [`ethereum/ERCs`](https://github.com/ethereum/ERCs/blob/master/ERCS/erc-8004.md)) and defines no conformance test cases, so there is no upstream shape to conform to yet. A second open question is our own byte-pin gate: fixtures are emitted by a deterministic generator and CI fails on any diff, so a bridge fixture would need a pinned chain-state snapshot (fixed block number plus committed response body) rather than a live RPC read at generation time.

Tracked in [#5](https://github.com/opena2a-standards/a2a-idf-conformance/issues/5), which stays open. Revisit when ERC-8004 leaves Draft, or when we decide to pin a specific revision and accept the churn.

## Fixture format

The normative fixture schema — required fields, supported `keyidResolution` shapes, the exact signature-base format, and the `rejectCategory` values used by negative fixtures — is documented in [`SCHEMA.md`](./SCHEMA.md). Verifiers in [`../../scripts/`](../../scripts/) consume these fixtures and emit `PASS` / `FAIL` per fixture; fixtures themselves are emitted by the deterministic generator ([`../../scripts/generate-fixtures.mjs`](../../scripts/generate-fixtures.mjs)) and byte-pinned in [`../../MANIFEST.sha256`](../../MANIFEST.sha256).
