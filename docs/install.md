# Install and run the tooling

Part of [Reference verifiers and suite tooling](../scripts/README.md).

## Node

The Node tooling needs no install. It runs on stock Node ≥ 18:

```bash
node scripts/verify.mjs fixtures
```

## Python

The Python verifier needs the [`cryptography`](https://pypi.org/project/cryptography/) package. From the repository root, install it into a virtual environment:

```bash
python3 -m venv .venv
. .venv/bin/activate
python3 -m pip install cryptography
python3 scripts/verify.py fixtures
```

A Python marked as externally managed (PEP 668), such as Homebrew Python or the system Python of Debian and Ubuntu, refuses `pip install` outside a virtual environment with `error: externally-managed-environment`.

- The `.venv` directory is ignored by git.
- Activate it again in each new shell before running the Python tooling. On Windows, activate it with `.venv\Scripts\activate`.
- On Debian and Ubuntu, `python3 -m venv` needs the `python3-venv` package.
- To use the system Python instead, install `cryptography` with your system package manager.

Without `cryptography`, `verify.py` prints one line on stderr and exits 2:

```
verify.py needs the cryptography package: python3 -m pip install cryptography (see scripts/README.md#install)
```

It reads its arguments first, so `--help` and a usage error do not need the package.

## Without a clone

The top-level README's first command runs the parity gate without a clone:

```bash
pipx run --spec git+https://github.com/opena2a-standards/a2a-idf-conformance a2a-idf-conformance
```

pipx builds the package that [`pyproject.toml`](../pyproject.toml) defines from this repository. It installs the package with `cryptography` into a virtual environment of its own. Then it runs the package's console script, `a2a-idf-conformance` ([`src/a2a_idf_conformance/__init__.py`](../src/a2a_idf_conformance/__init__.py)).

The console script runs `parity.py` from the copy of the suite that the wheel carries under `a2a_idf_conformance/suite/`. That copy keeps the repository's layout: `fixtures/`, `schemas/`, `vectors/`, `MANIFEST.sha256`, `verify.mjs`, `verify.py` and `parity/parity.py`. The generator, the profile script and the link check are not in the wheel. They run from a checkout.

The console script takes the options of `parity.py` (`--json`, `--verifier`). Like `parity.py`, it needs `node` on the `PATH` for the Node verifier. Its usage and error lines name `a2a-idf-conformance`, not `parity.py`.

It also takes `--version` (`-V`, or the word `version` on its own). That option prints `a2a-idf-conformance` and the version that `pyproject.toml` declares, read from the installed package's metadata. `parity.py` run as a script has no such option.

In a checkout, `python3 -m a2a_idf_conformance` with `src/` on `PYTHONPATH` runs the gate of the checkout without an install. Its usage and error lines name the interpreter and the package, as in `python3.14 -m a2a_idf_conformance`. Its `--version` reads the version from the checkout's `pyproject.toml`.

## How the package is built

The package's description is the top-level `README.md` with each relative link rewritten to the file on GitHub. A file becomes `blob/main/<path>` and a directory `tree/main/<path>`, and the fragment is kept. The build hook [`hatch_build.py`](../hatch_build.py) does the rewrite. `pyproject.toml` names it as hatchling's custom metadata hook, with `readme` listed under `project.dynamic`.

The rewrite is needed because PyPI renders a description with `readme_renderer`, which leaves a relative link as it is. A link such as `./docs/coverage.md` would otherwise point under pypi.org, where there is no such page. `README.md` itself keeps its relative links. GitHub resolves them against the branch a reader is on, and [`check-doc-links.mjs`](../scripts/check-doc-links.mjs) checks them in the checkout.

A link inside a fenced code block is not rewritten. A link whose path is not in the checkout is rewritten all the same: the hook fails no build over a link. [`parity/test_entry_point.py`](../scripts/parity/test_entry_point.py) checks that each rewritten path of `README.md` names a file or directory of the checkout.

Both the wheel and the sdist write core metadata version 2.4 (`core-metadata-version` under each target in `pyproject.toml`). That version carries every field the package sets. twine 6.2.0, unlike twine 7.0.0, refuses the 2.5 that hatchling 1.32 writes by default as not a valid metadata version.
