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

### `erc-8004-bridge/` (planned, pending spec-author input)

Cross-layer composition between A2A-IDF (off-chain identity framework) and [ERC-8004](https://eips.ethereum.org/EIPS/eip-8004) (Ethereum on-chain IdentityRegistry). An ERC-8004 IdentityRegistry entry's `tokenURI` resolves to an A2A-IDF DID Document, with both the on-chain entry hash and the off-chain DID Document's wire signature byte-stable.

First fixture set scopes to the identity composition surface only. TEE / zkTLS attestation envelopes (ERC-8004 ValidationRegistry) defer to a second fixture set gated on the OM World Intent Schema verifier-map question.

Verifier tooling for this directory is scoped: an ethers-based reader for `IdentityRegistry.tokenURI` lives inside the bridge directory and does not change the top-level Node stdlib `crypto` / Python `cryptography` verifier dependencies.

Fixture refs pin both the EIP draft revision (`version` = EIP git SHA or revision date) and the canonical content (`specSha256`), matching the version-pinning discipline used in `aim-did-rfc9421/` for Envoys v1.4.0 → v1.5.1.

Tracked in [#5](https://github.com/opena2a-org/a2a-idf-conformance/issues/5). Spec-author input invited from [@MarcoMetaMask](https://github.com/MarcoMetaMask) and [@dcrapis](https://github.com/dcrapis) on the canonical shape (which `IdentityRegistry` fields enter the cross-layer hash, which are informational, how `tokenURI → DID Document` resolution composes) before the contributor PR lands.

## Fixture format

The normative fixture schema — required fields, supported `keyidResolution` shapes, the exact signature-base format, and the `rejectCategory` values used by negative fixtures — is documented in [`SCHEMA.md`](./SCHEMA.md). Verifiers in [`../../scripts/`](../../scripts/) consume these fixtures and emit `PASS` / `FAIL` per fixture; fixtures themselves are emitted by the deterministic generator ([`../../scripts/generate-fixtures.mjs`](../../scripts/generate-fixtures.mjs)) and byte-pinned in [`../../MANIFEST.sha256`](../../MANIFEST.sha256).
