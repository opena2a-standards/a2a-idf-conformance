# Test vectors

Pinned cryptographic vectors used across the suite. Vectors live here once, fixtures reference them by name.

## Keypairs

### `rfc8032-7-1.json` (planned)

The Ed25519 keypair from [RFC 8032 §7.1 Test 1](https://datatracker.ietf.org/doc/html/rfc8032#section-7.1). This is the same keypair used by [aps-conformance-suite](https://github.com/aeoess/aps-conformance-suite) composition fixtures and the [Envoys spec §13](https://envoys.me/specs/signature/v1) reproducible vectors, so any A2A-IDF verifier passing this suite produces byte-identical signatures with the wire-format layer.

```
secretKey:   9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60
publicKey:   d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a
```

These are test-only keys published in RFC 8032 itself. They MUST NOT be used in any production deployment.

## Body fixtures

### `simple-message-send.json` (planned)

A canonical `message/send` JSON-RPC body used as the input to the signature-alone composition fixture. Single text part, no attachments, no streaming.

### `delegation-context.json` (planned)

A `message/send` body carrying a 3-link delegation chain in `metadata.a2a:delegationChain`. Used by `delegation-chain-3link.json` composition fixtures.
