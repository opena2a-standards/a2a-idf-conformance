# Reference verifiers and suite tooling

Reference tooling for producing and consuming A2A-IDF conformance fixtures. The detail is on these pages:

- [Install and run](../docs/install.md): Node and Python setup, the pipx command that needs no clone, and how the package is built.
- [Reference verifiers](../docs/verifiers.md): what the two verifiers check, the arguments they read, and the output contract (per-fixture blocks, reasons, summary line, exit codes).
- [Testing another implementation](../docs/testing-another-implementation.md): the interface an implementation provides to join the parity gate, and what the gate reports.
- [Contributor tools](../docs/contributor-tools.md): the fixture generator, the conformance profile script and the documentation path check.
- [Tests for the tooling](../docs/tooling-tests.md): the two test commands, and what each test file covers.

## Shipped

- [`verify.mjs`](./verify.mjs): the Node.js verifier. It uses only the Node standard library (`node:crypto`).
- [`verify.py`](./verify.py): the Python verifier. Its one dependency is the [`cryptography`](https://pypi.org/project/cryptography/) package. It has the same interface and check order as the Node verifier, and makes the same accept/reject/category decisions on every fixture.
- [`generate-fixtures.mjs`](./generate-fixtures.mjs): the deterministic fixture generator. It rewrites the fixtures and vectors it owns from the RFC 8032 §7.1 seeds and the templates in the script, then writes `MANIFEST.sha256`. It leaves the two snapshot fixtures in [`fixtures/composition/hippo-rfc9421/`](../fixtures/composition/hippo-rfc9421/) as found and pins them as found.
- [`parity/parity.py`](./parity/parity.py): the cross-implementation parity gate. It runs both verifiers, plus any implementation added with `--verifier NAME=COMMAND`, over the fixture set. It fails on any disagreement in gate status, verdict or reject category, and on any observed outcome that differs from the fixture's pinned outcome.
- [`conformance_profile.py`](./conformance_profile.py): writes `conformance.json`, the machine-readable profile derived from the fixtures, or checks it with `--check`.
- [`check-doc-links.mjs`](./check-doc-links.mjs): checks that the relative links and command script paths of the tracked Markdown files resolve.
- [`test/`](./test/) and the `test_*.py` files in [`parity/`](./parity/): regression tests for the tooling above.

[`docs/captures/parity.txt`](../docs/captures/parity.txt) holds what the parity gate prints for the committed fixture set. It is the full output behind the trimmed excerpt in the top-level `README.md`. [`docs/captures/parity.json`](../docs/captures/parity.json) holds the `--json` report of the same run. Refresh both from the repository root:

```bash
python3 scripts/parity/parity.py --json docs/captures/parity.json > docs/captures/parity.txt
```

## Install

The Node tooling needs no install. It runs on stock Node ≥ 18:

```bash
node scripts/verify.mjs fixtures
```

The Python verifier needs `cryptography`. From the repository root, install it into a virtual environment:

```bash
python3 -m venv .venv
. .venv/bin/activate
python3 -m pip install cryptography
python3 scripts/verify.py fixtures
```

[Install and run](../docs/install.md) covers a Python marked as externally managed (PEP 668), Windows, the pipx command that needs no clone, and how the package is built.

## Testing another implementation

An A2A-IDF implementation joins the parity gate with `--verifier NAME=COMMAND`:

```bash
python3 scripts/parity/parity.py --verifier mylib="node ../mylib/conformance.js" --json parity-report.json
```

The gate runs COMMAND with the absolute path of `fixtures/` as its last argument. The command prints one block per fixture in the [reference verifier output format](../docs/verifiers.md#output), and exits 0 when every fixture is `PASS`. [Testing another implementation](../docs/testing-another-implementation.md) gives the whole interface and what the gate reports.

## Cross-implementation guarantee

Both verifiers are wire-compatible with the [`envoys-rfc9421/`](https://github.com/aeoess/aps-conformance-suite) verifier on the signature-alone case: the same keypair and the same RFC 9421 components give byte-identical signature bytes. This is enforced twice:

- The generator asserts that the recomputed signatures equal the Envoys §14 pins at generation time.
- Each fixture's `crossSuiteEquivalence.envoys` block makes the verifier check that the signature bytes it verified (parsed from `expected.signature`) match the pinned vector value. It rejects with `CROSS_SUITE_MISMATCH` when they do not.

The `cross-suite-mismatch` negative fixture pins that check. Its Signature header carries a different key's valid signature, while `expected.signatureBase64` still carries the Envoys bytes.

## Why no implementation-library dependency

The conformance suite must not depend on any A2A-IDF SDK (including `@opena2a/a2a-idf`). Doing so would make the suite a self-verifier rather than an independent oracle. Both reference verifiers use only the platform's primitive cryptography (`node:crypto` / `cryptography`) plus inline RFC 9421, multibase, and minimal-JCS logic.
