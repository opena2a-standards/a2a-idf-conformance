# Composition fixtures

Multi-layer fixtures that exercise A2A-IDF in combination with adjacent layers (wire signature, identity claims, delegation/continuity).

## Planned fixtures

### `aim-did-rfc9421/` (in progress)

A2A-IDF identity-framework wrap of an [#1829](https://github.com/a2aproject/A2A/issues/1829) wire signature, with the `keyid` URL resolving to a W3C DID Document (`Ed25519VerificationKey2020` + `publicKeyMultibase`).

Three shapes per the [aps-conformance-suite](https://github.com/aeoess/aps-conformance-suite) composition convention:

- `signature-alone.json` — per-message signature, no enclosing envelope
- `bilateral-receipt.json` — signature wrapped in an APS bilateral receipt
- `delegation-chain-3link.json` — signature wrapped in a 3-link APS delegation chain

All three pin to the RFC 8032 §7.1 keypair so verifiers running both suites produce byte-identical results for the signature-alone case.

### `envoys-rfc9421-cross-validate/` (planned)

Direct cross-validation against [`envoys-rfc9421/`](https://github.com/aeoess/aps-conformance-suite) fixtures. A2A-IDF verifiers MUST produce the same accept/reject decisions on these inputs as the Envoys reference verifier.

### `erc-8004-bridge/` (planned, pending spec-author input)

Cross-layer composition between A2A-IDF (off-chain identity framework) and [ERC-8004](https://eips.ethereum.org/EIPS/eip-8004) (Ethereum on-chain IdentityRegistry). An ERC-8004 IdentityRegistry entry's `tokenURI` resolves to an A2A-IDF DID Document, with both the on-chain entry hash and the off-chain DID Document's wire signature byte-stable.

First fixture set scopes to the identity composition surface only. TEE / zkTLS attestation envelopes (ERC-8004 ValidationRegistry) defer to a second fixture set gated on the OM World Intent Schema verifier-map question.

Verifier tooling for this directory is scoped: an ethers-based reader for `IdentityRegistry.tokenURI` lives inside the bridge directory and does not change the top-level Node stdlib `crypto` / Python `cryptography` verifier dependencies.

Fixture refs pin both the EIP draft revision (`version` = EIP git SHA or revision date) and the canonical content (`specSha256`), matching the version-pinning discipline used in `aim-did-rfc9421/` for Envoys v1.4.0 → v1.5.1.

Tracked in [#5](https://github.com/opena2a-org/a2a-idf-conformance/issues/5). Spec-author input invited from [@MarcoMetaMask](https://github.com/MarcoMetaMask) and [@dcrapis](https://github.com/dcrapis) on the canonical shape (which `IdentityRegistry` fields enter the cross-layer hash, which are informational, how `tokenURI → DID Document` resolution composes) before the contributor PR lands.

## Fixture format

Each fixture is a JSON file with the following top-level fields:

```json
{
  "name": "...",
  "description": "...",
  "spec": ["A2A-IDF #1496", "RFC 9421", "..."],
  "keypair": {
    "source": "RFC 8032 §7.1",
    "publicKeyMultibase": "...",
    "privateKey": "<test vector only — never use in production>"
  },
  "input": { "method": "...", "path": "...", "headers": {...}, "body": "..." },
  "expected": {
    "signatureBase": "...",
    "signature": "...",
    "verifyResult": "ACCEPT" | "REJECT",
    "rejectReason": "..."
  }
}
```

Verifiers in `scripts/` consume these and emit `pass` / `fail` per fixture.
