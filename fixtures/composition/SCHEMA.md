# Composition fixture schema

This document describes the JSON schema that every fixture under `fixtures/composition/` must conform to. Both reference verifiers (`scripts/verify.mjs`, `scripts/verify.py`) read this shape directly; a fixture that doesn't match this schema cannot be verified.

The canonical reference fixture is [`aim-did-rfc9421/signature-alone.json`](./aim-did-rfc9421/signature-alone.json).

## Top-level shape

```jsonc
{
  "$schema": "https://a2a-idf.opena2a.org/schemas/fixture-composition-v1.json",
  "name": "<dir>/<filename-without-extension>",
  "description": "...",
  "spec": [ /* spec citations, see below */ ],

  "input":            { /* what was signed */ },
  "signatureParams":  { /* RFC 9421 signature parameters */ },
  "keyidResolution":  { /* how the keyid URL resolves to a public key */ },

  "expected": {
    "contentDigest":    "sha-256=:...:",
    "signatureBase":    "...",
    "signatureInput":   "sig1=(...);keyid=\"...\";created=...;nonce=\"...\"",
    "signature":        "sig1=:<base64>:",
    "signatureBase64":  "<base64>",
    "verifyResult":     "ACCEPT"
  },

  "crossSuiteEquivalence": { /* optional, see below */ }
}
```

## `input`

| Field | Required | Notes |
|---|---|---|
| `method` | yes | HTTP method, uppercase (`GET`, `POST`, ...). |
| `path` | yes | Request path including leading `/`. |
| `body` | yes | Request body. Empty string for `GET`. |
| `bodyEncoding` | no | `utf-8` (default) or `base64`. Use `base64` for binary bodies. |

The verifier rehashes `body` using the algorithm declared in `expected.contentDigest` (see below) and rejects the fixture if the recomputed digest doesn't match. **Placeholder bodies (`"<see other repo>"`) are not allowed** because they make the fixture unverifiable.

## `signatureParams`

```jsonc
{
  "components": ["@method", "@path", "content-digest"],
  "keyid":   "https://example.com/agents/.../keys/k1",
  "created": 1714000000,
  "nonce":   "AAECAwQFBgcICQoLDA0ODw",
  "tag":     "a2a-message"        // optional
}
```

**Component identifiers** are restricted to the RFC 9421 derived-component subset supported by the verifier:

- `@method`: request method
- `@path`: request path
- `content-digest`: RFC 9530 `Content-Digest` header

**`created`, `nonce`, `keyid`, and `tag` are signature parameters, not components.** They appear only in the `@signature-params` line of the signature base. Listing them in `components` produces an `unsupported component` error from the verifier and is invalid per RFC 9421 §2.3.

The verifier serializes parameters in the order `keyid; created; nonce; tag`. Fixtures must use the same order to byte-match `expected.signatureInput` and `expected.signatureBase`.

## `keyidResolution`

How the verifier obtains the public key referenced by `keyid`. Two shapes are supported.

### Compact form

```jsonc
{
  "shape": "compact",
  "publicKeyPem": "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEA...\n-----END PUBLIC KEY-----\n"
}
```

Use when the `keyid` URL would return a bare Ed25519 SPKI PEM in the production deployment. This is the Envoys §6 compact form.

### DID Document form

```jsonc
{
  "shape": "did-json",
  "contentType": "application/did+json",
  "document": {
    "@context": ["https://www.w3.org/ns/did/v1", "https://w3id.org/security/suites/ed25519-2020/v1"],
    "id": "did:web:example.com:agents:test",
    "verificationMethod": [{
      "id": "did:web:example.com:agents:test#key-1",
      "type": "Ed25519VerificationKey2020",
      "controller": "did:web:example.com:agents:test",
      "publicKeyMultibase": "z6Mk..."
    }],
    "assertionMethod": ["did:web:example.com:agents:test#key-1"]
  }
}
```

Use when the `keyid` URL would return a W3C DID Document at `application/did+json`. The verifier picks the verification method referenced by `assertionMethod` if present, else the first entry. Supports `publicKeyMultibase` (Ed25519VerificationKey2020) and `publicKeyJwk` (OKP/Ed25519).

**`keypair`, `publicKeyBase64`, and ad-hoc fields are not supported.** Use one of the two shapes above.

## `expected`

| Field | Required | Notes |
|---|---|---|
| `contentDigest` | yes | RFC 9530 Content-Digest of `input.body`. Algorithm prefix `sha-256=:` or `sha-512=:`. The verifier recomputes this from the body and rejects on mismatch. |
| `signatureBase` | yes | The exact bytes the signer signed. Format per RFC 9421 §2.5: quoted component identifiers, parameters only in `@signature-params`. See below for the precise format. |
| `signatureInput` | yes | RFC 9421 `Signature-Input` header value for label `sig1`. |
| `signature` | yes | RFC 9421 `Signature` header value: `sig1=:<base64>:`. |
| `signatureBase64` | yes | The base64 signature, naked (no `sig1=:` wrapping). Used by `crossSuiteEquivalence` byte-match checks. |
| `verifyResult` | no | `ACCEPT` (default) or `REJECT`. Use `REJECT` for negative-path fixtures asserting that a particular malformation must be rejected. |

### Exact `signatureBase` format

```
"@method": <UPPERCASE METHOD>
"@path": <PATH>
"content-digest": <DIGEST-WITH-ALG-PREFIX>
"@signature-params": (<QUOTED COMPONENT LIST>);keyid="<KEYID>";created=<CREATED>;nonce="<NONCE>"[;tag="<TAG>"]
```

Each component identifier is wrapped in double quotes, followed by `: `, followed by the value. Parameters are semicolon-separated, in the order `keyid; created; nonce; tag` (tag optional).

## `crossSuiteEquivalence` (optional)

Declare a byte-match relationship with another conformance suite's published vector:

```jsonc
{
  "envoys": {
    "vector": "§13 Vector 1",
    "expectedSignatureBase64": "XUpjUHt36N...",
    "byteIdentical": true,
    "note": "..."
  }
}
```

When `byteIdentical: true`, the verifier asserts that `expected.signatureBase64` matches `expectedSignatureBase64` exactly. This is the core interop claim of A2A-IDF §6: dual-shape `keyid` resolution does not change the signed bytes.

## Reproducibility checklist

Before opening a PR:

- [ ] `node scripts/verify.mjs <fixture.json>` returns `PASS`
- [ ] `python3 scripts/verify.py <fixture.json>` returns `PASS`
- [ ] The keypair is either RFC 8032 §7.1 (referenced via `keypairRef`) or an independent test keypair whose private key is documented in the source repo
- [ ] The body is the real bytes that produce the embedded content-digest, not a placeholder
- [ ] If wrapping an existing wire-signature implementation's vector, `crossSuiteEquivalence` declares the byte-match claim explicitly
