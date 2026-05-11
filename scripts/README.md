# Reference verifiers and fixture builders

Reference tooling for producing and consuming A2A-IDF conformance fixtures.

## Planned

- `verify.mjs` — Node.js verifier that consumes a fixture JSON, reconstructs the RFC 9421 signature base, verifies the Ed25519 signature against the published `publicKeyMultibase`, and reports `pass` / `fail`.
- `verify.py` — Python verifier with the same interface.
- `build-fixture.mjs` — Producer that takes inputs (keypair, body, parameters) and emits a fixture JSON with the computed signature for use in cross-validation against external suites.

Both verifiers will be wire-compatible with the [`envoys-rfc9421/`](https://github.com/aeoess/aps-conformance-suite) verifier on the signature-alone case (same keypair, same RFC 9421 components → same signature bytes).
