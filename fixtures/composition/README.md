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
