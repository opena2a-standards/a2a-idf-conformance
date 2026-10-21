# Tests for the tooling

Part of [Reference verifiers and suite tooling](../scripts/README.md).

Run both commands from the repository root:

```bash
python3 -m unittest discover -s scripts/parity -p 'test_*.py'
node --test scripts/test/*.test.mjs
```

They need Node, git, `bash`, and `python3` with the `cryptography` package and the `venv` module, and the entry point tests also need network access to PyPI. Several tests run a copy of the suite in a temporary directory, so none of them writes to `fixtures/`. The tests use scratch copies and fixture variants that cannot be committed under `fixtures/`.

## Python tests (`scripts/parity/`)

- [`test_parity.py`](../scripts/parity/test_parity.py): the parity gate. It covers output parsing, the `--verifier` option, the `--json` report file (and the notice for a repeated `--json`), the pinned-outcome check, and the usage error for an abbreviated option.
- [`test_verifier_agreement.py`](../scripts/parity/test_verifier_agreement.py): both reference verifiers on inputs no fixture pins. These are further spellings of each provider-domain rule, lone surrogates, members nested deeper than `json.loads` reads, and an integer of more digits than Python's `int()` converts.
- [`test_doc_links.py`](../scripts/parity/test_doc_links.py): the `.sigstore/<org>/` check of `check-doc-links.mjs`.
- [`test_captures.py`](../scripts/parity/test_captures.py): the captured parity gate run.
  - The top-level `README.md` labels its excerpt with a link to `docs/captures/parity.txt`.
  - Each run of lines between the excerpt's `...` lines appears in that file as consecutive lines and in the same order.
  - `docs/captures/parity.txt` and `docs/captures/parity.json` equal what a fresh run of the gate prints and writes.
- [`test_fixture_schema.py`](../scripts/parity/test_fixture_schema.py): the `schema` stage of both verifiers. It removes each required field (and alters typed or enumerated ones) in copies of committed fixtures. It asserts that both verifiers fail them at stage `schema` while the unmodified copies pass. When the `jsonschema` package is installed, it also checks the cases with a full JSON Schema validator.
- [`test_entry_point.py`](../scripts/parity/test_entry_point.py): the published entry point.
  - The top-level README's first command is `pipx run --spec git+https://github.com/opena2a-standards/a2a-idf-conformance a2a-idf-conformance`, and `pyproject.toml` declares the console script it names.
  - The wheel built from the checkout carries each path listed in `MANIFEST.sha256` with the bytes the manifest pins, the two schemas, `verify.mjs`, `verify.py` and `parity.py`. It carries no other script, and no `__pycache__`.
  - The installed console script, run from another directory, prints `docs/captures/parity.txt` and writes nothing into that directory. It takes `--json` and `--verifier`, whose command runs from the calling directory, and exits 1 on a divergence. Its `--help` usage line and its error line for an unknown option (exit 2) name `a2a-idf-conformance` as the program.
  - Its `--version`, `-V` and `version` print `a2a-idf-conformance` and the version in the wheel's METADATA. Its `--help` in an 80-column terminal gives the URL of the output format unbroken.
  - `python3 -m a2a_idf_conformance` from the checkout prints the same capture without an install. It names `<interpreter> -m a2a_idf_conformance` as the program in those two lines, `<interpreter>` being the file name of the Python that runs it. It prints the version in `pyproject.toml` for those three arguments, and gives the same URL.
  - `project_version()` reads the version from the `[project]` table only.
  - `pyproject.toml` lists `readme` under `project.dynamic` and names `hatch_build.py` as the metadata hook.
  - `absolute_links()` in that hook rewrites a relative link to `blob/main/<path>` for a file and `tree/main/<path>` for a directory. It keeps a fragment, a title and angle brackets. It leaves an absolute link, a same-page fragment and a link inside a fenced code block as they are. It rewrites a path that is not in the checkout without failing.
  - After the rewrite, every link of the top-level `README.md` is absolute, and each one into this repository names a file or directory of the checkout. The built wheel's METADATA carries that rewritten text as its `text/markdown` description.
  - The sdist that `python3 -m build --sdist` writes rebuilds a wheel whose files, apart from the `WHEEL` and `RECORD` metadata entries, are the same byte for byte.
  - The wheel's METADATA and the sdist's PKG-INFO carry `Metadata-Version: 2.4`, and `twine check --strict` passes on both.

  The wheel is built and installed into a scratch virtual environment, which downloads the build backend, `build`, `twine` and `cryptography` from PyPI.

## Node tests (`scripts/test/`)

- [`verify.test.mjs`](../scripts/test/verify.test.mjs): both verifiers, on:
  - unpinned byte-identity claims, the wording of reasons that quote a fixture value, and how `created` is written in the signature base;
  - keys that cannot be extracted, text outside the armor of a compact-form `publicKeyPem`, and the base64 text and encryption headers within it;
  - control characters and a backslash before `u` in a quoted value;
  - symlinks, sockets and FIFOs met during the walk, paths that cannot be read, listed or searched, and a fixture that is not JSON text;
  - the options they read, an empty argument, the error count of the summary line, and `verify.py` without the `cryptography` package;
  - the envelope checks.
- [`check-doc-links.test.mjs`](../scripts/test/check-doc-links.test.mjs): the path checks of `check-doc-links.mjs`.
- [`conformance-profile.test.mjs`](../scripts/test/conformance-profile.test.mjs): `conformance_profile.py`. It covers the `COSIGNERS.md` baseline count check of `--check`, its checks of composition and envelope claims, the one-line report of a fixture the script cannot profile, and UTF-8 reading and writing in other locales.
- [`tool-usage.test.mjs`](../scripts/test/tool-usage.test.mjs): the command lines of the three [contributor tools](./contributor-tools.md). `--help` and `-h` print the usage and write nothing. Any other argument, except `--check` for the profile script, is a usage error, exit 2, that writes nothing.
- [`generator-claims.test.mjs`](../scripts/test/generator-claims.test.mjs): the fixture generator rewrites the pinned files other than the two `hippo-rfc9421/` snapshot fixtures, and pins those two as found. Its entry in `scripts/README.md`, its section in `docs/contributor-tools.md`, its header comment and the Status paragraph of `docs/coverage.md` name the snapshot directory. No tracked Markdown file or comment in the generator matches the check's patterns for saying that the generator, or the CI step that reruns it, covers every pinned file. No pinned file carries a raw control character other than the line feed, or a raw soft hyphen.
- [`merge-claims.test.mjs`](../scripts/test/merge-claims.test.mjs): the tracked Markdown files do not describe a failing CI run as keeping a pull request out of `main`. The repository's settings for `main` decide that, not CI.
- [`install-docs.test.mjs`](../scripts/test/install-docs.test.mjs): the install commands in `scripts/README.md`, `docs/install.md`, the top-level `README.md` and `COSIGNERS.md`. It runs them in a scratch directory to check that `pip install` runs inside the virtual environment the commands create. It also checks that each statement of what the tooling tests need names `bash` and the `venv` module.
