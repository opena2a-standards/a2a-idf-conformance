"""`python3 -m a2a_idf_conformance`: the same as the `a2a-idf-conformance` console script.

The usage and error lines name the interpreter and this package, as in
`python3.14 -m a2a_idf_conformance`: the name argparse gives a package run
with `-m` from Python 3.14 on. It is given here because before 3.14 argparse
names the file in `sys.argv[0]`, which `-m` sets to this one, `__main__.py`."""
import sys
from pathlib import Path

from a2a_idf_conformance import main

main(f"{Path(sys.executable).name} -m a2a_idf_conformance")
