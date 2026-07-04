# Test vectors

Pinned cryptographic vectors used across the suite. Vectors live here once,
fixtures reference them by relative path (`keypairRef`). Like the fixtures,
vector files are emitted by [`scripts/generate-fixtures.mjs`](../scripts/generate-fixtures.mjs)
(every encoded form is derived from the RFC 8032 seed) and byte-pinned in
[`MANIFEST.sha256`](../MANIFEST.sha256).

## Keypairs

### `rfc8032-7-1.json`

The Ed25519 keypair from [RFC 8032 §7.1 Test 1](https://datatracker.ietf.org/doc/html/rfc8032#section-7.1),
in raw hex/base64, PEM (SPKI / PKCS#8), multibase, and JWK forms. This is the
agent signing key in every fixture, and the same keypair used by
[aps-conformance-suite](https://github.com/aeoess/aps-conformance-suite)
composition fixtures and the [Envoys spec §14](https://envoys.me/specs/signature/v1)
reproducible vectors, so any A2A-IDF verifier passing this suite produces
byte-identical signatures with the wire-format layer.

### `rfc8032-7-1-test2.json`

The Ed25519 keypair from RFC 8032 §7.1 Test 2. Two roles:

- the trust-registry **issuer key** signing the Level 2 organization
  attestations in [`fixtures/levels/`](../fixtures/levels/)
- the **substituted key** in the
  [`key-substituted.json`](../fixtures/composition/aim-did-rfc9421/key-substituted.json)
  negative fixture

Both keypairs are published in RFC 8032 itself and are for cross-implementation
verification only. They MUST NOT be used to sign anything in any production
deployment.
