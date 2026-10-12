# Reference verifiers and suite tooling

Reference tooling for producing and consuming A2A-IDF conformance fixtures.

## Shipped

- [`verify.mjs`](./verify.mjs) — Node.js verifier. Pure Node stdlib (`node:crypto`), no third-party dependencies. For composition fixtures it reconstructs the RFC 9421 signature base, applies the Envoys §4.3 tag rule (`a2a-message` or an absent tag accepted, any other tag rejected as `TAG_MISMATCH`), extracts the public key per A2A-IDF §6 dual-shape keyid resolution (`application/did+json` → DID Document with `Ed25519VerificationKey2020` + `publicKeyMultibase` or `JsonWebKey2020` JWK; else compact-form PEM SPKI), and verifies the Ed25519 signature. For level fixtures it evaluates the A2A-IDF §1 identity declaration (shape, DNS TXT binding, registry attestation over the RFC 8785 JCS form, validity window).
- [`verify.py`](./verify.py) — Python verifier. Single dependency: the [`cryptography`](https://pypi.org/project/cryptography/) package. Same interface, same check order, and same accept/reject/category decisions as the Node verifier on every fixture. It derives the provider domain of a Level 1 card with its own implementation of the WHATWG URL host rules; what that implementation approximates is listed under [Provider domain](../fixtures/levels/README.md#provider-domain).
- [`generate-fixtures.mjs`](./generate-fixtures.mjs) — deterministic fixture generator. Regenerates every file under `fixtures/` and `vectors/` plus `MANIFEST.sha256` from the RFC 8032 §7.1 seeds and the templates in the script. Self-checks that the composition signatures byte-match the pinned Envoys §14 vectors. CI runs it and fails on any diff, so committed fixtures cannot drift from their documented inputs.
- [`parity/parity.py`](./parity/parity.py) — cross-implementation parity gate. Runs both verifiers, plus any implementation added with `--verifier NAME=COMMAND`, over the fixture set and fails on any disagreement in gate status, verdict, or reject category, or on any observed outcome that differs from the fixture's pinned outcome. See [Testing another implementation](#testing-another-implementation).
- [`conformance_profile.py`](./conformance_profile.py) — generates (or `--check`s) `conformance.json`, the machine-readable profile derived from the fixtures. `--check` also fails when a coverage claim in the top-level `README.md` names an envelope that `notCovered` still lists, unless the claim marks it "(unverified)", when `README.md` or `fixtures/composition/README.md` says the suite composes with an adjacent layer (wire signature, identity claims, delegation/continuity) that no fixture under `fixtures/composition/` carries a `spec` entry for, and when the "at present" fixture count in the `COSIGNERS.md` baseline row differs from the number of fixtures. A fixture that is not valid JSON or not a JSON object, or that lacks a field the profile is derived from (`name` and `description`, strings; `spec`, an array; `expected`, an object) or has one of another JSON type, is reported in one line naming the file and every such field, with exit code 1, in both modes.
- [`check-doc-links.mjs`](./check-doc-links.mjs) — documentation path check. Fails when a relative link in a tracked Markdown file, or the script path of a `node` / `python3` command in one of its code blocks (including a command chained after `&&`, `||`, `;` or `|`), does not resolve. Command script paths may be relative to the Markdown file's directory or to the repo root, after any `cd <dir>` or `cd -- <dir>` earlier on the same line (a redirection on the `cd` is set aside, whether written as its own word, as in `cd fixtures 2>/dev/null`, or against the directory, as in `cd fixtures>/dev/null`). In a code block labelled as shell (`bash`, `sh`, `zsh`, `ksh`, `shell`, `console`, `shell-session`, `sh-session`, in any letter case), a `cd` inside a subshell, as in `(cd <dir> && node ...)`, applies up to the closing parenthesis; other blocks do not split at parentheses, so in them a `cd` that opens a subshell, `(cd <dir>` or `$(cd <dir>`, is one the check cannot resolve (put such a line in a shell-labelled block to have it checked). A `cd` the check cannot resolve (an option such as `-P`, a variable, `~`, `-`, a `<placeholder>` such as `<your-clone>`, more than one operand, a path longer than 4096 characters, or any `cd` past the 32nd on one line) skips the commands it would move. It also fails when a file that a `cosign sign-blob` command writes is ignored by git in the `.sigstore/<org>/` directory the same code block says to commit it under. In a code block, text from an unquoted `#` that starts a word is a comment: the command script paths and cosign output flags in it are not read, the `.sigstore/<org>/` directory is. Run `node scripts/check-doc-links.mjs` from the repository root; from another directory, adjust the script path (for example `node ../../scripts/check-doc-links.mjs` from `fixtures/levels/`). The result does not depend on the working directory. Needs a git checkout: it reads the list of tracked Markdown files from `git ls-files`.
- [`test/`](./test/) — regression tests for the tooling above, on scratch copies and fixture variants that cannot be committed under `fixtures/`. Run `node --test scripts/test/*.test.mjs` from the repository root (needs `git`, and `python3` with `cryptography`).

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

On failure, the line is `FAIL` followed by `stage:` (which validation step failed) and `reason:` (the specific mismatch).

When a verifier cannot evaluate a fixture at all, the line is `ERROR` followed by the error (the Python verifier prints its message; the Node verifier prints its message when it comes from a failed system call, such as opening a fixture path that does not exist or a file without read permission, and its stack trace otherwise), with no `observed:` line:

```
ERROR /abs/path/to/fixture.json
      value type outside the fixture JCS domain: int
```

`ERROR` means the verifier raised instead of reaching a verdict: unreadable JSON, a composition fixture missing a required block, or an attestation value outside the minimal JCS domain (numbers, booleans, null). A malformed level-fixture field is not an `ERROR`: it resolves to `REJECT[SHAPE_INVALID]`. That includes a lone surrogate in an organization attestation, which cannot enter the JCS form the attestation is signed over. An `ERROR` counts as a fail.

The final line is `summary: N pass, M fail (T fixtures)`. Exit code is 0 if every fixture met its expected verdict (and reject category, when pinned), else 1. The parity gate parses the `PASS`/`FAIL`/`ERROR` lines and the `observed:` lines to assert cross-implementation agreement; an `ERROR` in one verifier and a verdict in the other is reported as a divergence.

## Testing another implementation

An A2A-IDF implementation joins the parity gate with `--verifier NAME=COMMAND` (repeatable). It is then run beside the two reference verifiers and compared with them and with the outcome pinned in each fixture:

```bash
python3 scripts/parity/parity.py --verifier mylib="node ../mylib/conformance.js" --json parity-report.json
```

The interface an implementation provides:

- **Invocation.** COMMAND is split with shell-style quoting (no shell is invoked) and run from the directory `parity.py` is called from, with the absolute path of this repository's `fixtures/` directory appended as its last argument. The implementation walks that directory recursively for `*.json` and evaluates every fixture.
- **Output.** On stdout, one block per fixture in the format shown under [Output](#output): a line `PASS <path>`, `FAIL <path>` or `ERROR <path>`, then, for `PASS` and `FAIL`, an indented line `observed: ACCEPT` or `observed: REJECT[CATEGORY]` (`CATEGORY` in upper case, letters and underscores, as in `rejectCategory`). `<path>` is the fixture path it was given (absolute), or any path whose last `fixtures` directory component is followed by the path under `fixtures/` (`fixtures/levels/x.json` and `/any/checkout/fixtures/levels/x.json` both name `levels/x.json`; `my-fixtures/levels/x.json` does not, because `my-fixtures` is a different directory name). Other lines are ignored.
- **Gate status.** `PASS` when the observed outcome matches the fixture's `expected` block (`verifyResult`, and `rejectCategory` when present), `FAIL` when it does not, `ERROR` when the implementation could not reach a verdict.
- **Exit code.** 0 when every fixture is `PASS`, non-zero otherwise.

The gate reports `PARITY: FAIL` and exits 1 when any verifier exits non-zero or cannot be started, misses a fixture or reports one that does not exist, disagrees with another verifier on gate status, verdict or reject category, or observes an outcome other than the one pinned in the fixture. The pinned check reads each fixture's `expected` block directly, so an implementation that prints `PASS` next to the wrong verdict still fails. A name already in use (`node`, `python`, or an earlier `--verifier`) is a usage error, exit 2. A fixture whose `expected` block is not a JSON object pins nothing, so the gate reports it as a divergence too.

## Tests for the tooling

```bash
python3 -m unittest discover -s scripts/parity -p 'test_*.py'
node --test scripts/test/*.test.mjs
```

- [`parity/test_parity.py`](./parity/test_parity.py) — the parity gate: output parsing, the `--verifier` option, the pinned-outcome check.
- [`parity/test_verifier_agreement.py`](./parity/test_verifier_agreement.py) — both reference verifiers on inputs no fixture pins: further spellings of each provider-domain rule, and lone surrogates.
- [`parity/test_doc_links.py`](./parity/test_doc_links.py) — the `.sigstore/<org>/` check of `check-doc-links.mjs`.
- [`test/`](./test/) — the path checks of `check-doc-links.mjs`, the `COSIGNERS.md` baseline count check of `conformance_profile.py --check`, and unpinned byte-identity claims in both verifiers.

Run both commands from the repository root. They need Node, git and the Python `cryptography` package. Several tests run a copy of the suite in a temporary directory, so none of them writes to `fixtures/`.

## Cross-implementation guarantee

Both verifiers are wire-compatible with the [`envoys-rfc9421/`](https://github.com/aeoess/aps-conformance-suite) verifier on the signature-alone case (same keypair, same RFC 9421 components → byte-identical signature bytes). This is enforced twice: the generator asserts the recomputed signatures equal the Envoys §14 pins at generation time, and each fixture's `crossSuiteEquivalence.envoys` block makes the verifier check that the signature bytes it verified (parsed from `expected.signature`) match the pinned vector value, rejecting with `CROSS_SUITE_MISMATCH` when they do not. The `cross-suite-mismatch` negative fixture pins that check: its Signature header carries a different key's valid signature while `expected.signatureBase64` still carries the Envoys bytes.

## Why no implementation-library dependency

The conformance suite must not depend on any A2A-IDF SDK (including `@opena2a/a2a-idf`). Doing so would make the suite a self-verifier rather than an independent oracle. Both reference verifiers use only the platform's primitive cryptography (`node:crypto` / `cryptography`) plus inline RFC 9421, multibase, and minimal-JCS logic.
