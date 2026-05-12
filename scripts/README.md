# Reference verifiers and fixture builders

Reference tooling for producing and consuming A2A-IDF conformance fixtures.

## Shipped

- [`verify.mjs`](./verify.mjs) — Node.js verifier. Pure Node stdlib (`node:crypto`), no third-party dependencies. Reconstructs the RFC 9421 signature base, extracts the public key per A2A-IDF §6 dual-shape keyid resolution (`application/did+json` → DID Document with `Ed25519VerificationKey2020` + `publicKeyMultibase` or `JsonWebKey2020` JWK; else compact-form PEM SPKI), and verifies the Ed25519 signature.
- [`verify.py`](./verify.py) — Python verifier. Single dependency: the [`cryptography`](https://pypi.org/project/cryptography/) package. Same interface as the Node verifier; same accept/reject decisions on every fixture.

## Planned

- `build-fixture.mjs` — Producer that takes inputs (keypair, body, parameters) and emits a fixture JSON with the computed signature for use in cross-validation against external suites.

## Install

The Node verifier needs no install — it runs on stock Node ≥ 18:

```bash
node ./verify.mjs ../fixtures/composition/aim-did-rfc9421/signature-alone.json
```

The Python verifier needs `cryptography`:

```bash
python3 -m pip install cryptography  # or use your system package manager
python3 ./verify.py ../fixtures/composition/aim-did-rfc9421/signature-alone.json
```

## Output

Each verifier prints one line per fixture:

```
PASS  /abs/path/to/fixture.json
```

On failure, the line is `FAIL` followed by `stage:` (which validation step failed) and `reason:` (the specific mismatch). Exit code is 0 if every fixture met its expected verifyResult, else 1. Tampered signatures produce `FAIL  stage:  ed25519-verify  reason: verify result REJECT != expected ACCEPT` in both verifiers.

## Cross-implementation guarantee

Both verifiers are wire-compatible with the [`envoys-rfc9421/`](https://github.com/aeoess/aps-conformance-suite) verifier on the signature-alone case (same keypair, same RFC 9421 components → byte-identical signature bytes). This is enforced by the fixture's `crossSuiteEquivalence.envoys` block: the verifier checks that `expected.signatureBase64` matches the value pinned to the corresponding Envoys §13 vector.

## Why no implementation-library dependency

The conformance suite must not depend on any A2A-IDF SDK (including `@opena2a/a2a-idf`). Doing so would make the suite a self-verifier rather than an independent oracle. Both reference verifiers use only the platform's primitive cryptography (`node:crypto` / `cryptography`) and ~120 lines of inline RFC 9421 + multibase logic each.
