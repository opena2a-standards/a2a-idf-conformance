# Reference verifiers and suite tooling

Reference tooling for producing and consuming A2A-IDF conformance fixtures.

## Shipped

- [`verify.mjs`](./verify.mjs) — Node.js verifier. Pure Node stdlib (`node:crypto`), no third-party dependencies. For composition fixtures it reconstructs the RFC 9421 signature base, extracts the public key per A2A-IDF §6 dual-shape keyid resolution (`application/did+json` → DID Document with `Ed25519VerificationKey2020` + `publicKeyMultibase` or `JsonWebKey2020` JWK; else compact-form PEM SPKI), and verifies the Ed25519 signature. For level fixtures it evaluates the A2A-IDF §1 identity declaration (shape, DNS TXT binding, registry attestation over the RFC 8785 JCS form, validity window).
- [`verify.py`](./verify.py) — Python verifier. Single dependency: the [`cryptography`](https://pypi.org/project/cryptography/) package. Same interface, same check order, and same accept/reject/category decisions as the Node verifier on every fixture.
- [`generate-fixtures.mjs`](./generate-fixtures.mjs) — deterministic fixture generator. Regenerates every file under `fixtures/` and `vectors/` plus `MANIFEST.sha256` from the RFC 8032 §7.1 seeds and the templates in the script. Self-checks that the composition signatures byte-match the pinned Envoys §14 vectors. CI runs it and fails on any diff, so committed fixtures cannot drift from their documented inputs.
- [`parity/parity.py`](./parity/parity.py) — cross-implementation parity gate. Runs both verifiers over the fixture set and fails on any disagreement in gate status, verdict, or reject category.
- [`conformance_profile.py`](./conformance_profile.py) — generates (or `--check`s) `conformance.json`, the machine-readable profile derived from the fixtures. `--check` also fails when a coverage claim in the top-level `README.md` names an envelope that `notCovered` still lists, unless the claim marks it "(unverified)".
- [`check-doc-links.mjs`](./check-doc-links.mjs) — documentation path check. Fails when a relative link in a tracked Markdown file, or the script path of a `node` / `python3` command in one of its code blocks, does not resolve. Command script paths may be relative to the Markdown file's directory or to the repo root. Run `node scripts/check-doc-links.mjs` from anywhere in the repo.

## Install

The Node tooling needs no install — it runs on stock Node ≥ 18:

```bash
node scripts/verify.mjs fixtures
```

The Python verifier needs `cryptography`:

```bash
python3 -m pip install cryptography  # or use your system package manager
python3 scripts/verify.py fixtures
```

Both verifiers accept fixture files or directories (walked recursively for `*.json`).

## Output

Each verifier prints one block per fixture:

```
PASS  /abs/path/to/fixture.json
      observed: ACCEPT
```

Negative fixtures PASS when the observed rejection matches the pinned expectation:

```
PASS  /abs/path/to/signature-tampered.json
      observed: REJECT[SIGNATURE_INVALID]
```

On failure, the line is `FAIL` followed by `stage:` (which validation step failed) and `reason:` (the specific mismatch). The final line is `summary: N pass, M fail (T fixtures)`. Exit code is 0 if every fixture met its expected verdict (and reject category, when pinned), else 1. The parity gate parses the `observed:` lines to assert cross-implementation agreement.

## Cross-implementation guarantee

Both verifiers are wire-compatible with the [`envoys-rfc9421/`](https://github.com/aeoess/aps-conformance-suite) verifier on the signature-alone case (same keypair, same RFC 9421 components → byte-identical signature bytes). This is enforced twice: the generator asserts the recomputed signatures equal the Envoys §14 pins at generation time, and each fixture's `crossSuiteEquivalence.envoys` block makes the verifier check that the signature bytes it verified (parsed from `expected.signature`) match the pinned vector value, rejecting with `CROSS_SUITE_MISMATCH` when they do not. The `cross-suite-mismatch` negative fixture pins that check: its Signature header carries a different key's valid signature while `expected.signatureBase64` still carries the Envoys bytes.

## Why no implementation-library dependency

The conformance suite must not depend on any A2A-IDF SDK (including `@opena2a/a2a-idf`). Doing so would make the suite a self-verifier rather than an independent oracle. Both reference verifiers use only the platform's primitive cryptography (`node:crypto` / `cryptography`) plus inline RFC 9421, multibase, and minimal-JCS logic.
