# Composition fixture schema

This document describes the JSON schema that every fixture under `fixtures/composition/` must conform to. The machine-readable form is [`schemas/fixture-composition-v1.json`](../../schemas/fixture-composition-v1.json), whose `$id` is the `$schema` URL each fixture declares. Both reference verifiers (`scripts/verify.mjs`, `scripts/verify.py`) check every fixture against it before any other stage: a fixture missing a required field, or carrying a value of the wrong type or outside an allowed set, fails at stage `schema`.

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

  "crossSuiteEquivalence": { /* optional, see below */ },
  "envelope":              { /* optional, see below */ }
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

A JSON number does not record how it was written, so `created` is written as JavaScript writes the number it holds: `1714000000.0` and `1714000000` are both written `created=1714000000`, in both reference verifiers.

A `tag` of JSON `null` is treated as an absent tag: it is omitted from the signature base and the Signature-Input header, never serialized as `tag="null"`.

**Tag rule (Envoys signature/v1 §4.3).** A verifier accepts a `tag` of `a2a-message` and treats an absent (or `null`) tag as `a2a-message` for back-compat. Any other tag value marks a signature produced for a different application: the verifier rejects it with `TAG_MISMATCH`, even when the signature verifies. The tag is an application requirement on the signature parameters (RFC 9421 §3.2.1), checked after the signature base and Signature-Input are reconstructed and before key resolution and Ed25519 verification. Pinned by the pair `aim-did-rfc9421/signature-tag-absent.json` (ACCEPT) and `aim-did-rfc9421/signature-tag-foreign.json` (REJECT[TAG_MISMATCH]). The place of the rule before Ed25519 verification is pinned by `aim-did-rfc9421/signature-tag-foreign-tampered.json`, which carries a foreign tag and an altered signature and is REJECT[TAG_MISMATCH], not REJECT[SIGNATURE_INVALID].

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
| `signatureBase64` | yes | The base64 signature, naked (no `sig1=:` wrapping). Informational: verifiers MUST NOT use it for the `crossSuiteEquivalence` byte-match, which compares the bytes parsed from `signature`. The `cross-suite-mismatch` negative fixture sets it to a value that differs from `signature` to catch a verifier that does. |
| `verifyResult` | no | `ACCEPT` (default) or `REJECT`. Use `REJECT` for negative-path fixtures asserting that a particular malformation must be rejected. |
| `rejectCategory` | REJECT fixtures | Machine-readable reject category the verifier must observe. At the wire layer three categories are modeled. `TAG_MISMATCH`: the signature carries a `tag` other than `a2a-message` (see the tag rule above). `SIGNATURE_INVALID`: tampered signature bytes, a substituted key, and a tampered body (content-digest is a signed component) all surface as an Ed25519 verification failure against the resolved key. `CROSS_SUITE_MISMATCH`: the signature verifies, but the fixture declares `crossSuiteEquivalence.envoys.byteIdentical: true` and the verified signature bytes are not the pinned vector (see below). A negative fixture must be valid at every stage before its pinned check (digest, base, Signature-Input, then the tag rule, then key extraction), so a verifier that rejects for the wrong reason fails the fixture. `signature-tag-foreign.json` carries a signature that verifies, so a verifier that ignores the tag accepts it and fails. `signature-tag-foreign-tampered.json` is the one fixture with a second defect after its pinned check (an altered signature), so a verifier that checks the signature before the tag reports `SIGNATURE_INVALID` and fails. The envelope adds eight categories, described under [`envelope`](#envelope-optional): `DEPTH_EXCEEDED`, `CHAIN_BROKEN`, `LINK_SIGNATURE_INVALID`, `SCOPE_WIDENED`, `EXPIRY_EXTENDED` and `REQUEST_OUT_OF_SCOPE` for a delegation chain, and `RECEIPT_SIGNATURE_INVALID` and `RECEIPT_MISMATCH` for a bilateral receipt. A negative envelope fixture carries a request that the wire layer accepts. |

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
    "vector": "§14 Vector 1",
    "expectedSignatureBase64": "XUpjUHt36N...",
    "byteIdentical": true,
    "note": "..."
  }
}
```

When `byteIdentical: true` and the signature verifies, the verifier base64-encodes the signature bytes it parsed from `expected.signature` (the bytes it just verified) and asserts that they match `expectedSignatureBase64` exactly; otherwise it rejects with `CROSS_SUITE_MISMATCH`. It never reads `expected.signatureBase64` for this check. `byteIdentical: true` without an `expectedSignatureBase64` that is a non-empty string is a malformed fixture: both verifiers report it as `FAIL` at stage `cross-suite-equivalence` rather than skipping the comparison. A `crossSuiteEquivalence` or `crossSuiteEquivalence.envoys` value that is present but is not a JSON object (a string, an array, `null`) is malformed too: both verifiers report it as `FAIL` at stage `schema`, before any other check, rather than reading it as an absent block. This is the core interop claim of A2A-IDF §6: dual-shape `keyid` resolution does not change the signed bytes.

## `envelope` (optional)

A fixture may wrap its request in an [APS](https://github.com/a2aproject/A2A/issues/1575) envelope: a delegation chain (`"type": "aps-delegation-chain-v1"`, A2A-IDF §7) or a bilateral receipt (`"type": "aps-bilateral-receipt-v1"`, A2A-IDF §8). Both reference verifiers check the envelope after the wire layer has accepted the request, so a wire-layer reject is the verdict whatever the envelope holds.

Every envelope carries `keyidResolutions`, an object from each keyid the envelope needs a key for to its resolution, in either shape described under [`keyidResolution`](#keyidresolution). `signatureParams.keyid` resolves through the fixture's own `keyidResolution` only, and an entry for it in `keyidResolutions` fails the fixture at stage `envelope`. An envelope signature is an Ed25519 signature in base64 (RFC 4648 §4, padded) over the UTF-8 bytes of the RFC 8785 JCS form of the payload it signs; text that is not exactly the base64 encoding of 64 bytes does not verify. A member the checks cannot read fails the fixture at stage `envelope`, as an unusable key fails it at stage `public-key-extraction`.

### Delegation chain

```jsonc
{
  "type": "aps-delegation-chain-v1",
  "depth": 3,                // the number of links
  "maxDepth": 4,             // the most links the verifier accepts
  "links": [
    {
      "index": 0,
      "type": "root",        // "derived" for every link after the first
      "issuerKeyid": "https://envoys.me/agents/test@rfc8032-vec1.example",
      "subjectKeyid": "did:web:counterparty.example:agents:delegate-level-1",
      "scope": ["POST /api/echo", "POST /api/health", "GET /api/health"],
      "issuedAt": "2026-05-01T00:00:00Z",
      "expiresAt": "2026-12-31T00:00:00Z",
      "signature": "<base64>"
      // a derived link also carries "previousSignatureRef": "links[<i-1>].signature"
    }
  ],
  "keyidResolutions": { "did:web:counterparty.example:agents:delegate-level-1": { "shape": "did-json", ... } }
}
```

The issuer of a link signs the JCS form of `{type, issuerKeyid, subjectKeyid, scope, issuedAt, expiresAt}`, plus, for a derived link, `previousSignature`: the `signature` of the link before it. A scope entry names a request as its method, a space and its path. The checks run in this order, and the first that fails decides:

1. The chain can be read, or the fixture fails at stage `envelope`: `links` is not empty and `depth` is its length, and each link in turn is an object whose `index` is its position and whose `type` is `root` for the first link and `derived` after it, with a non-empty string `issuerKeyid` and `subjectKeyid`, a `scope` array of strings, an `issuedAt` and an `expiresAt` of the form `YYYY-MM-DDTHH:MM:SSZ`, a `previousSignatureRef` of `links[<i-1>].signature` on a derived link, a string `signature`, no lone surrogate, and an `issuerKeyid` that resolves to a key.
2. `DEPTH_EXCEEDED`: the chain has more links than `maxDepth`.
3. For each link from the root: `CHAIN_BROKEN` when a derived link's `issuerKeyid` is not the `subjectKeyid` of the link before it, `LINK_SIGNATURE_INVALID` when the link's signature does not verify with its issuer's key, `SCOPE_WIDENED` when a derived link's `scope` holds an entry that the scope before it does not, and `EXPIRY_EXTENDED` when a derived link's `expiresAt` is later than the one before it.
4. `CHAIN_BROKEN`: the `subjectKeyid` of the last link is not `signatureParams.keyid`, the key that signed the request.
5. `REQUEST_OUT_OF_SCOPE`: the `scope` of the last link does not hold the request, its method in upper case, a space and its path.

### Bilateral receipt

```jsonc
{
  "type": "aps-bilateral-receipt-v1",
  "request": { "initiatorKeyid": "https://envoys.me/agents/test@rfc8032-vec1.example", ... },
  "response": {
    "responderKeyid": "did:web:counterparty.example:agents:receipt-test",
    "respondedAt": "2026-05-13T13:31:02Z",
    "status": "ACCEPTED",
    "receiptPayloadJcs": {
      "initiatorSignatureBase64": "<the signature of the request>",
      "initiatorKeyid": "https://envoys.me/agents/test@rfc8032-vec1.example",
      "respondedAt": "2026-05-13T13:31:02Z",
      "responderKeyid": "did:web:counterparty.example:agents:receipt-test",
      "status": "ACCEPTED"
    },
    "responderSignatureBase64": "<base64>"
  },
  "keyidResolutions": { "did:web:counterparty.example:agents:receipt-test": { "shape": "did-json", ... } }
}
```

The responder signs the JCS form of `receiptPayloadJcs` with the key of its `responderKeyid`. The checks run in this order:

1. The receipt can be read, or the fixture fails at stage `envelope`: the five members of `receiptPayloadJcs` shown above are strings, `receiptPayloadJcs` holds only strings, arrays and objects and no lone surrogate, and its `responderKeyid` resolves to a key.
2. `RECEIPT_SIGNATURE_INVALID`: `responderSignatureBase64` does not verify over `receiptPayloadJcs`.
3. `RECEIPT_MISMATCH`, in this order: `receiptPayloadJcs.initiatorSignatureBase64` is not the base64 of the signature bytes the wire layer verified; `receiptPayloadJcs.initiatorKeyid`, then `request.initiatorKeyid`, is not `signatureParams.keyid`; `response.responderKeyid`, `response.respondedAt` or `response.status` differs from the member of that name in `receiptPayloadJcs`.

The schema stage checks the members it can: an `envelope` that is present is an object with a `type` named above and an object `keyidResolutions`; a delegation chain has integer `depth` and `maxDepth` and an array `links`, and a bilateral receipt has a `request` with a string `initiatorKeyid` and a `response` with the string `responderKeyid`, `respondedAt`, `status` and `responderSignatureBase64` and the object `receiptPayloadJcs`.

Neither verifier compares `issuedAt`, `expiresAt` or `respondedAt` with a clock: the fixtures pin no verification time, and `conformance.json` lists that under `notCovered`.

## Reproducibility checklist

Before opening a PR:

- [ ] The fixture is emitted by `scripts/generate-fixtures.mjs` (add your generation code there and rerun it — CI reruns the generator and fails when a fixture it writes differs from the committed file, so a pull request that edits a generated fixture by hand fails CI and is not merged)
- [ ] `node scripts/verify.mjs <fixture.json>` returns `PASS`
- [ ] `python3 scripts/verify.py <fixture.json>` returns `PASS`
- [ ] The keypair is either RFC 8032 §7.1 (referenced via `keypairRef`) or an independent test keypair whose private key is documented in the source repo
- [ ] The body is the real bytes that produce the embedded content-digest, not a placeholder
- [ ] If wrapping an existing wire-signature implementation's vector, `crossSuiteEquivalence` declares the byte-match claim explicitly

## Known cross-suite variations

Some fixture-level details vary across cross-suite composition without affecting byte-match validation. Documented variations:

- **`did:web` id form.** The `aim-did-rfc9421` fixtures use the URL-encoded form `did:web:envoys.me:agents:test%40rfc8032-vec1.example`. Envoys §6 vec-6 uses the keyid URL directly. Both forms are conformant per A2A-IDF §6.1 and produce the same wire signature, because the keyid document body does not enter the signature base.
