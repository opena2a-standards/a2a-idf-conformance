# aim-did-rfc9421/

A2A-IDF identity-framework composition fixtures. Each fixture exercises:

- **Wire layer:** [Envoys signature/v1](https://envoys.me/specs/signature/v1) (RFC 9421 + Ed25519, components `("@method" "@path" "content-digest")` with `created` / `nonce` / `keyid`).
- **Framework layer:** [A2A-IDF #1496](https://github.com/a2aproject/A2A/pull/1496) §6 dual-shape keyid resolution. These fixtures pin the `application/did+json` branch (W3C DID Document with `Ed25519VerificationKey2020` + `publicKeyMultibase`). The compact-form branch is covered by [`envoys-rfc9421/`](https://github.com/aeoess/aps-conformance-suite) in `aeoess/aps-conformance-suite`.
- **Keypair:** RFC 8032 §7.1 Test 1, shared with the Envoys §14 (v1.5.1) reproducible vectors.

## Shapes

| Fixture | Expected | Wire vector | Envelope |
|---|---|---|---|
| [`signature-alone.json`](./signature-alone.json) | ACCEPT | Envoys §14 Vector 1 (GET `/api/health`, empty body) | none |
| [`bilateral-receipt.json`](./bilateral-receipt.json) | ACCEPT | Envoys §14 Vector 2 (POST `/api/task`, JSON body) | APS bilateral receipt v1 (initiator wire signature plus responder receipt acknowledgment over JCS-canonical payload) |
| [`delegation-chain-3link.json`](./delegation-chain-3link.json) | ACCEPT | Envoys §14 Vector 3 (POST `/api/echo`, `{}` body) | APS delegation chain v1 (3 links: 1 root plus 2 derived; scope monotonic narrow; expiry monotonic non-increase; `previousSignature` binding) |
| [`signature-tampered.json`](./signature-tampered.json) | REJECT[SIGNATURE_INVALID] | Vector 1 with altered signature bytes | none |
| [`key-substituted.json`](./key-substituted.json) | REJECT[SIGNATURE_INVALID] | Vector 1 signature, DID Document serving the RFC 8032 §7.1 Test 2 key instead | none |
| [`body-tampered.json`](./body-tampered.json) | REJECT[SIGNATURE_INVALID] | Vector 2 signature over a body later modified (Content-Digest recomputed, no re-sign) | none |

The negatives each pin exactly one defect against a fixture that is otherwise valid, so a verifier that rejects for the wrong reason still fails the suite (the reject must occur at the Ed25519 verification of the resolved key, not at fixture-integrity stages).

## Cross-suite parity

Each positive fixture's `expected.signature` is byte-identical to the corresponding Envoys §14 vector by construction. Substituting the DID Document for the compact-form key document at the keyid URL does not change the signature base. RFC 9421 base depends only on signed components plus parameters, not on the keyid document body. A verifier implementing A2A-IDF §6 dual-shape resolution can interoperate with Envoys-signed traffic without re-keying or re-signing, regardless of framework-layer envelope.

This is the core interop claim of A2A-IDF §6 and is what every fixture in this set demonstrates against a different envelope shape.

## Envelope verification scope

The reference verifiers in [`../../scripts/`](../../scripts/) check the wire layer for every fixture:

- Recompute `Content-Digest` from `input.body`
- Reconstruct the RFC 9421 signature base
- Resolve the keyid per A2A-IDF §6 (this fixture set pins the `application/did+json` branch)
- Verify the Ed25519 signature against the resolved public key
- Cross-suite byte-match check against the declared Envoys §14 vector

Deeper envelope verification (responder signature for `bilateral-receipt`, per-link signatures and chain-rule enforcement for `delegation-chain-3link`) is a planned extension of the reference verifiers. The current fixtures pin the envelope shapes and invariants so consumers can build envelope verifiers against a known-good wire layer.

## Verifying

```bash
node ../../scripts/verify.mjs .
python3 ../../scripts/verify.py .
```

Both reference verifiers produce `PASS` on every fixture: the positives verify (`observed: ACCEPT`) and the negatives are rejected for the pinned reason (`observed: REJECT[SIGNATURE_INVALID]`).
