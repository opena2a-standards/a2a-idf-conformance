"""Entry point of the A2A-IDF conformance suite as an installed package.

`pyproject.toml` declares the console script `a2a-idf-conformance`, which calls
:func:`main`, so that

    pipx run --spec git+https://github.com/opena2a-standards/a2a-idf-conformance a2a-idf-conformance

runs the parity gate without a clone: pipx builds the package from the
repository, installs it with `cryptography`, the Python verifier's one
dependency, into a virtual environment of its own, and runs the script.

The wheel carries the suite under `a2a_idf_conformance/suite/` in the
repository's own layout (`fixtures/`, `schemas/`, `vectors/`,
`MANIFEST.sha256`, `scripts/verify.mjs`, `scripts/verify.py` and
`scripts/parity/parity.py`; see the `force-include` table in
`pyproject.toml`), and :func:`main` runs the gate from that copy. In a
checkout nothing is installed and no `suite/` directory exists next to this
file, so `python3 -m a2a_idf_conformance` with `src/` on `PYTHONPATH` runs the
gate of the checkout itself.

The gate takes its options (`--json`, `--verifier`) from the command line as
when it is run as `python3 scripts/parity/parity.py`, and the process exits
with the gate's exit code.
"""
from __future__ import annotations

import runpy
from pathlib import Path

_PACKAGE_DIR = Path(__file__).resolve().parent

# Filled by the wheel build (`force-include` in pyproject.toml); absent in a checkout.
INSTALLED_SUITE = _PACKAGE_DIR / "suite"

# src/a2a_idf_conformance/ -> src/ -> the repository root.
CHECKOUT_ROOT = _PACKAGE_DIR.parent.parent


def suite_root() -> Path:
    """The directory holding `fixtures/` and `scripts/parity/parity.py`: the copy
    installed with the package when there is one, else the checkout this file is in."""
    return INSTALLED_SUITE if INSTALLED_SUITE.is_dir() else CHECKOUT_ROOT


def main() -> None:
    """Run the parity gate with the arguments on the command line.

    The gate ends with `sys.exit`, so the `SystemExit` it raises carries its
    exit code out of this function to the interpreter."""
    gate = suite_root() / "scripts" / "parity" / "parity.py"
    runpy.run_path(str(gate), run_name="__main__")
