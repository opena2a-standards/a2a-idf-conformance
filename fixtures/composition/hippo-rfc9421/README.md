# hippo-rfc9421/

Composition fixtures from [lawcontinue/hippo-auth](https://github.com/lawcontinue/hippo-auth) — an independent Ed25519 + RFC 9421 signing implementation for A2A messages.

## Fixtures

| File | Description | Coverage |
|------|-------------|----------|
| `signature-alone-tag.json` | POST with §4.3 `tag=a2a-message` | Explicit tag parameter |
| `signature-alone-no-tag.json` | GET without tag parameter | §4.3 back-compat: absent ≡ `a2a-message` |

## Keypair

These fixtures use an independent Ed25519 test keypair (not RFC 8032 §7.1). The public key is embedded in each fixture via `keyidResolution` (compact shape, PEM SPKI). The private key is available in the [hippo-auth repository](https://github.com/lawcontinue/hippo-auth) for vector regeneration.

## Cross-suite notes

- These are **snapshot fixtures** — signatures are pre-generated and pinned. They demonstrate byte-match correctness of the Hippo implementation against the RFC 9421 signature base construction.
- The `tag` parameter coverage (present/absent) directly exercises the Envoys v1.5 §4.3 mechanism discussed in [A2A #1829](https://github.com/a2aproject/A2A/issues/1829).
- Signature base conforms to RFC 9421 §2.5: only `@method`, `@path`, `content-digest` are covered components. `created`, `nonce`, `keyid` appear exclusively as `@signature-params` parameters per §2.3.

## Verification

Run the canonical verifier from this suite:
```bash
node scripts/verify.mjs fixtures/composition/hippo-rfc9421/*.json
```
