# aim-did-rfc9421/

A2A-IDF identity-framework composition fixtures. Each fixture exercises:

- **Wire layer:** [Envoys signature/v1](https://envoys.me/specs/signature/v1) (RFC 9421 + Ed25519, components `("@method" "@path" "content-digest")` with `created` / `nonce` / `keyid`).
- **Framework layer:** [A2A-IDF #1496](https://github.com/a2aproject/A2A/pull/1496) §6 dual-shape keyid resolution. These fixtures pin the `application/did+json` branch (W3C DID Document with `Ed25519VerificationKey2020` + `publicKeyMultibase`). The compact-form branch is covered by [`envoys-rfc9421/`](https://github.com/aeoess/aps-conformance-suite) in `aeoess/aps-conformance-suite`.
- **Keypair:** RFC 8032 §7.1 Test 1, shared with the Envoys §14 (v1.5.1) reproducible vectors. The envelopes also use RFC 8032 §7.1 Test 2, the key of the `counterparty.example` agents that sign delegation links and receipts.

## Shapes

| Fixture | Expected | Wire vector | Envelope |
|---|---|---|---|
| [`signature-alone.json`](./signature-alone.json) | ACCEPT | Envoys §14 Vector 1 (GET `/api/health`, empty body) | none |
| [`bilateral-receipt.json`](./bilateral-receipt.json) | ACCEPT | Envoys §14 Vector 2 (POST `/api/task`, JSON body) | APS bilateral receipt v1: the responder's Ed25519 signature over the JCS receipt payload, which names the initiator's wire signature |
| [`delegation-chain-3link.json`](./delegation-chain-3link.json) | ACCEPT | Envoys §14 Vector 3 (POST `/api/echo`, `{}` body) | APS delegation chain v1: 3 signed links (1 root plus 2 derived), each derived link bound to the signature of the link before it, each scope a subset of the one before it and no expiry later than the one before it; the last link delegates to the wire keyid with scope `POST /api/echo` |
| [`signature-tampered.json`](./signature-tampered.json) | REJECT[SIGNATURE_INVALID] | Vector 1 with altered signature bytes | none |
| [`key-substituted.json`](./key-substituted.json) | REJECT[SIGNATURE_INVALID] | Vector 1 signature, DID Document serving the RFC 8032 §7.1 Test 2 key instead | none |
| [`body-tampered.json`](./body-tampered.json) | REJECT[SIGNATURE_INVALID] | Vector 2 signature over a body later modified (Content-Digest recomputed, no re-sign) | none |
| [`cross-suite-mismatch.json`](./cross-suite-mismatch.json) | REJECT[CROSS_SUITE_MISMATCH] | Vector 1 request signed by the RFC 8032 §7.1 Test 2 key, DID Document serving that key; declares byte-identity with Vector 1 and `expected.signatureBase64` carries the Vector 1 bytes | none |
| [`signature-tag-null.json`](./signature-tag-null.json) | ACCEPT | Envoys §14 Vector 1 with `signatureParams.tag` set to `null` (a null tag is an absent tag; signature byte-identical to Vector 1) | none |
| [`signature-tag-absent.json`](./signature-tag-absent.json) | ACCEPT | Envoys §14 Vector 1 with no tag: Envoys §4.3 back-compat, an absent tag is treated as `a2a-message` | none |
| [`signature-tag-foreign.json`](./signature-tag-foreign.json) | REJECT[TAG_MISMATCH] | Vector 1 request signed by the correct key with `tag="not-a2a-message"`: the signature verifies, but the tag names another application | none |
| [`signature-tag-foreign-tampered.json`](./signature-tag-foreign-tampered.json) | REJECT[TAG_MISMATCH] | The `signature-tag-foreign` request with its signature bytes altered: two defects, and the tag rule is the one that runs first | none |
| [`delegation-chain-depth-exceeded.json`](./delegation-chain-depth-exceeded.json) | REJECT[DEPTH_EXCEEDED] | Vector 3 | The `delegation-chain-3link` chain with `maxDepth` 2 |
| [`delegation-chain-issuer-not-delegate.json`](./delegation-chain-issuer-not-delegate.json) | REJECT[CHAIN_BROKEN] | Vector 3 | The last link issued by `delegate-level-3`, which is not the subject of the link before it, and signed by that issuer |
| [`delegation-chain-leaf-not-signer.json`](./delegation-chain-leaf-not-signer.json) | REJECT[CHAIN_BROKEN] | Vector 3 | The last link delegates to `delegate-level-3` instead of the wire keyid, signed by its issuer |
| [`delegation-chain-root-tampered.json`](./delegation-chain-root-tampered.json) | REJECT[LINK_SIGNATURE_INVALID] | Vector 3 | `DELETE /api/everything` added to the root scope after the root was signed |
| [`delegation-chain-link-tampered.json`](./delegation-chain-link-tampered.json) | REJECT[LINK_SIGNATURE_INVALID] | Vector 3 | The `expiresAt` of link 1 moved from `2026-09-30T00:00:00Z` to `2026-08-31T00:00:00Z` after the link was signed |
| [`delegation-chain-link-replaced.json`](./delegation-chain-link-replaced.json) | REJECT[LINK_SIGNATURE_INVALID] | Vector 3 | Link 1 replaced by another link its issuer signed; link 2 is bound to the signature of the link it replaced, so link 2 no longer verifies |
| [`delegation-chain-scope-widened.json`](./delegation-chain-scope-widened.json) | REJECT[SCOPE_WIDENED] | Vector 3 | `DELETE /api/everything` added to the scope of the last link, signed by its issuer |
| [`delegation-chain-expiry-extended.json`](./delegation-chain-expiry-extended.json) | REJECT[EXPIRY_EXTENDED] | Vector 3 | The last link expires at `2099-01-01T00:00:00Z`, after the link before it, signed by its issuer |
| [`delegation-chain-request-out-of-scope.json`](./delegation-chain-request-out-of-scope.json) | REJECT[REQUEST_OUT_OF_SCOPE] | Vector 3 | The scope of the last link narrowed to `POST /api/health`, which does not grant the request, signed by its issuer |
| [`bilateral-receipt-signature-tampered.json`](./bilateral-receipt-signature-tampered.json) | REJECT[RECEIPT_SIGNATURE_INVALID] | Vector 2 | The responder signature bytes altered |
| [`bilateral-receipt-other-request.json`](./bilateral-receipt-other-request.json) | REJECT[RECEIPT_MISMATCH] | Vector 2 | A receipt the responder signed for the Envoys §14 Vector 1 request |
| [`bilateral-receipt-status-mismatch.json`](./bilateral-receipt-status-mismatch.json) | REJECT[RECEIPT_MISMATCH] | Vector 2 | A signed payload with status `REJECTED` beside a `response.status` of `ACCEPTED` |

Every negative but `signature-tag-foreign-tampered` pins exactly one defect against a fixture that is otherwise valid, so a verifier that rejects for the wrong reason still fails the suite. The `SIGNATURE_INVALID` rejects must occur at the Ed25519 verification of the resolved key and the `cross-suite-mismatch` reject at the cross-suite byte-match of the verified signature, not at fixture-integrity stages. The `TAG_MISMATCH` reject must come from the Envoys §4.3 tag rule, which runs before key resolution: the signature of `signature-tag-foreign` verifies, so a verifier that ignores the tag accepts it and fails. The `signature-tag-absent` / `signature-tag-foreign` pair differs only in the tag, so it separates an absent tag (accepted as `a2a-message`) from any other value. `signature-tag-foreign-tampered` carries two defects, a foreign tag and an altered signature, to pin the order: a verifier that checks the signature before the tag reports `SIGNATURE_INVALID` and fails it. Each envelope negative carries the wire request of its positive fixture unchanged, which verifies, so its reject must come from the envelope checks and a verifier that skips the envelope accepts it and fails. The two `CHAIN_BROKEN` fixtures pin the two places a chain can break: between two links, and between the last link and the key that signed the request. The three `LINK_SIGNATURE_INVALID` fixtures pin the signature of the root link, of a middle link, and of the link after a replaced one.

## Cross-suite parity

Each positive fixture's `expected.signature` is byte-identical to the corresponding Envoys §14 vector by construction. Substituting the DID Document for the compact-form key document at the keyid URL does not change the signature base. RFC 9421 base depends only on signed components plus parameters, not on the keyid document body. A verifier implementing A2A-IDF §6 dual-shape resolution can interoperate with Envoys-signed traffic without re-keying or re-signing, regardless of framework-layer envelope.

This is the core interop claim of A2A-IDF §6 and is what every fixture in this set demonstrates against a different envelope shape.

## Envelope verification scope

The reference verifiers in [`../../../scripts/`](../../../scripts/) check the wire layer for every fixture:

- Recompute `Content-Digest` from `input.body`
- Reconstruct the RFC 9421 signature base
- Apply the Envoys §4.3 tag rule (`a2a-message` or absent accepted, any other tag rejected as `TAG_MISMATCH`)
- Resolve the keyid per A2A-IDF §6 (this fixture set pins the `application/did+json` branch)
- Verify the Ed25519 signature against the resolved public key
- Cross-suite byte-match of the verified signature bytes (parsed from the `Signature` header) against the declared Envoys §14 vector

When the wire layer accepts the request, they check the envelope:

- **Delegation chain:** the number of links against `maxDepth`; then, for each link from the root, that its issuer is the subject of the link before it, its issuer's Ed25519 signature over the JCS form of the link payload (a derived link's payload includes `previousSignature`, the signature of the link before it), that its scope is a subset of the scope before it, and that its `expiresAt` is not later than the one before it; then that the last link delegates to the wire keyid with a scope that grants the request.
- **Bilateral receipt:** the responder's Ed25519 signature over the JCS form of `receiptPayloadJcs`; that the payload's `initiatorSignatureBase64` is the signature the wire layer verified and its `initiatorKeyid`, like `request.initiatorKeyid`, is the wire keyid; and that `response.responderKeyid`, `respondedAt` and `status` equal the members of the same name in the signed payload.

The root link is signed with the Test 1 key, as the wire keyid issues it. The issuers of the derived links and the responder are `did:web:counterparty.example:agents:*` keyids, which resolve through `envelope.keyidResolutions` to the Test 2 key (`counterpartyKeypairRef`). Neither verifier compares a timestamp with a clock. The envelope members and the check order are in [`SCHEMA.md`](../SCHEMA.md#envelope-optional).

## Verifying

```bash
node ../../../scripts/verify.mjs .
python3 ../../../scripts/verify.py .
```

Both reference verifiers produce `PASS` on every fixture: the positives verify (`observed: ACCEPT`) and the negatives are rejected for the pinned reason (`observed: REJECT[SIGNATURE_INVALID]`, `observed: REJECT[TAG_MISMATCH]` for `signature-tag-foreign.json` and `signature-tag-foreign-tampered.json`, `observed: REJECT[CROSS_SUITE_MISMATCH]` for `cross-suite-mismatch.json`, or the envelope category in the table above for each envelope negative).
