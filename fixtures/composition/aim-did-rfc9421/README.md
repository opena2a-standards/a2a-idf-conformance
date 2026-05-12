# aim-did-rfc9421/

A2A-IDF identity-framework composition fixtures. Each fixture exercises:

- **Wire layer:** [Envoys signature/v1](https://envoys.me/specs/signature/v1) (RFC 9421 + Ed25519, components `("@method" "@path" "content-digest")` with `created` / `nonce` / `keyid`).
- **Framework layer:** [A2A-IDF #1496](https://github.com/a2aproject/A2A/pull/1496) §6 dual-shape keyid resolution. These fixtures pin the `application/did+json` branch (W3C DID Document with `Ed25519VerificationKey2020` + `publicKeyMultibase`). The compact-form branch is covered by [`envoys-rfc9421/`](https://github.com/aeoess/aps-conformance-suite) in `aeoess/aps-conformance-suite`.
- **Keypair:** RFC 8032 §7.1 Test 1, shared with the Envoys §13 reproducible vectors.

## Shapes

| Fixture | Status | Envelope |
|---|---|---|
| [`signature-alone.json`](./signature-alone.json) | shipped | none — bare RFC 9421 over GET `/api/health` |
| `bilateral-receipt.json` | planned | APS bilateral receipt wraps the signature |
| `delegation-chain-3link.json` | planned | 3-link APS delegation chain wraps the signature |

## Cross-suite parity

The `signature-alone` fixture's `expected.signature` is byte-identical to Envoys §13 Vector 1 by construction: substituting the DID Document for the compact-form key document at the keyid URL does not change the signature base (RFC 9421 base depends only on signed components + parameters, not on the keyid document body). A verifier implementing A2A-IDF §6 dual-shape resolution can interoperate with Envoys-signed traffic without re-keying or re-signing.

This is the core interop claim of A2A-IDF §6 and is what the rest of the suite builds on.

## Verifying

```bash
node ../../scripts/verify.mjs ./signature-alone.json
python ../../scripts/verify.py ./signature-alone.json
```

Both reference verifiers produce `PASS` on this fixture and reject any tampered variant.
