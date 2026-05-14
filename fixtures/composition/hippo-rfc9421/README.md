# hippo-rfc9421/

Composition fixtures from [lawcontinue/hippo-auth](https://github.com/lawcontinue/hippo-auth) — an independent Ed25519 + RFC 9421 signing implementation for A2A messages.

## Fixtures

| File | Description | Coverage |
|------|-------------|----------|
| `signature-alone-tag.json` | POST with §4.3 `tag=a2a-message` | Explicit tag parameter |
| `signature-alone-no-tag.json` | GET without tag parameter | §4.3 back-compat: absent ≡ `a2a-message` |
| `signature-alone-sha512.json` | POST ≥4096 bytes with SHA-512 | §4.2 SHA-512 auto-promote |

## Keypair

These fixtures use an independent Ed25519 test keypair (not RFC 8032 §7.1). The public key is embedded in each fixture. The private key is available in the [hippo-auth repository](https://github.com/lawcontinue/hippo-auth) for vector regeneration.

## Cross-suite notes

- These are **snapshot fixtures** — signatures are pre-generated and pinned. They demonstrate byte-match correctness of the Hippo implementation against the RFC 9421 signature base construction.
- The `tag` parameter coverage (present/absent) directly exercises the Envoys v1.5 §4.3 mechanism discussed in [A2A #1829](https://github.com/a2aproject/A2A/issues/1829).
- The SHA-512 fixture exercises the §4.2 auto-promote threshold at ≥4096 bytes.

## Verification

Run `hippo-auth` test suite:
```bash
git clone https://github.com/lawcontinue/hippo-auth
cd hippo-auth && pytest
```

All 3 vectors are verified in the [byte-match report](https://github.com/lawcontinue/hippo-auth/blob/main/fixtures/hippo-rfc9421/byte-match-report.json).
