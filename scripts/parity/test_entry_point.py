#!/usr/bin/env python3
"""Tests for the published entry point of the suite.

Run from the repository root:
    python3 -m unittest discover -s scripts/parity -p 'test_*.py'

The README's first command,

    pipx run --spec git+https://github.com/opena2a-standards/a2a-idf-conformance a2a-idf-conformance

builds the package that `pyproject.toml` defines from the repository, installs
it with `cryptography` into a virtual environment of its own and runs its
console script, which runs the parity gate from the copy of the suite inside
the package. These tests build the wheel from this checkout and install it into
a scratch virtual environment, so besides Node they need `python3` with the
`venv` module and network access to PyPI, for the build backend and
`cryptography`.
"""
from __future__ import annotations

import hashlib
import json
import os
import shlex
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:  # Python before 3.11
    tomllib = None

HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parent.parent
README = REPO_ROOT / "README.md"
PYPROJECT = REPO_ROOT / "pyproject.toml"
MANIFEST = REPO_ROOT / "MANIFEST.sha256"
CAPTURE_TXT = REPO_ROOT / "docs" / "captures" / "parity.txt"

PACKAGE = "a2a_idf_conformance"
SCRIPT = "a2a-idf-conformance"
REPOSITORY = "https://github.com/opena2a-standards/a2a-idf-conformance"
ENTRY_POINT = f"pipx run --spec git+{REPOSITORY} {SCRIPT}"
# Where the wheel carries the suite, in the repository's layout.
SUITE = f"{PACKAGE}/suite/"
SUITE_SCRIPTS = ("scripts/verify.mjs", "scripts/verify.py", "scripts/parity/parity.py")

BIN = "Scripts" if os.name == "nt" else "bin"
EXE = ".exe" if os.name == "nt" else ""

# A stand-in implementation under test for `--verifier`. It echoes each
# fixture's pinned outcome in the reference output format; in `lie` mode it
# observes the wrong verdict on one fixture, which the gate must report. The
# gate appends the absolute fixtures path as the command's last argument.
STUB = r'''
import json
import sys
from pathlib import Path

mode, root = sys.argv[1], Path(sys.argv[-1])
for path in sorted(root.rglob("*.json")):
    expected = json.loads(path.read_text())["expected"]
    category = expected.get("rejectCategory")
    observed = f"REJECT[{category}]" if category else expected.get("verifyResult", "ACCEPT")
    if mode == "lie" and path.name == "level-0-self-asserted.json":
        observed = "REJECT[SHAPE_INVALID]"
    print(f"PASS  {path}")
    print(f"      observed: {observed}")
'''


def first_bash_block(text: str) -> list[str]:
    """The lines of the first fenced `bash` block of a Markdown file."""
    lines = text.split("\n")
    start = next(i for i, line in enumerate(lines) if line.rstrip() == "```bash")
    end = next(i for i in range(start + 1, len(lines)) if lines[i].rstrip() == "```")
    return lines[start + 1 : end]


def manifest_entries() -> list[tuple[str, str]]:
    """(sha256, path) for each line of MANIFEST.sha256."""
    entries = []
    for line in MANIFEST.read_text(encoding="utf-8").splitlines():
        if line.strip():
            sha, path = line.split(None, 1)
            entries.append((sha, path.strip()))
    return entries


def run(cmd: list[str], **kwargs) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, timeout=600, **kwargs)


def checked(proc: subprocess.CompletedProcess, what: str) -> subprocess.CompletedProcess:
    if proc.returncode != 0:
        raise RuntimeError(f"{what} exited {proc.returncode}\n{proc.stdout}{proc.stderr}")
    return proc


class ReadmeAndMetadataTests(unittest.TestCase):
    def test_readme_first_command_is_the_entry_point(self):
        self.assertEqual(first_bash_block(README.read_text(encoding="utf-8")), [ENTRY_POINT])

    @unittest.skipIf(tomllib is None, "reading pyproject.toml needs tomllib (Python 3.11)")
    def test_pyproject_declares_the_console_script_the_readme_runs(self):
        project = tomllib.loads(PYPROJECT.read_text(encoding="utf-8"))["project"]
        self.assertEqual(project["scripts"], {SCRIPT: f"{PACKAGE}:main"})
        self.assertEqual(project["urls"]["Repository"], REPOSITORY)
        self.assertIn("cryptography", " ".join(project["dependencies"]))


class InstalledPackageTests(unittest.TestCase):
    """Builds the wheel from this checkout once, installs it into a scratch
    virtual environment, and exercises the installed copy."""

    @classmethod
    def setUpClass(cls):
        cls._scratch = tempfile.TemporaryDirectory()
        scratch = Path(cls._scratch.name)
        venv = scratch / "venv"
        checked(run([sys.executable, "-m", "venv", str(venv)]), "python3 -m venv")
        cls.python = venv / BIN / ("python" + EXE)
        pip = [str(cls.python), "-m", "pip", "--disable-pip-version-check", "-q"]
        dist = scratch / "dist"
        checked(run([*pip, "wheel", "--no-deps", "--wheel-dir", str(dist), str(REPO_ROOT)]), "pip wheel")
        wheels = sorted(dist.glob("*.whl"))
        if len(wheels) != 1:
            raise RuntimeError(f"expected one wheel, found {wheels}")
        cls.wheel = wheels[0]
        checked(run([*pip, "install", str(cls.wheel)]), "pip install")
        cls.script = venv / BIN / (SCRIPT + EXE)

    @classmethod
    def tearDownClass(cls):
        cls._scratch.cleanup()

    def test_wheel_carries_the_pinned_suite(self):
        with zipfile.ZipFile(self.wheel) as wheel:
            names = set(wheel.namelist())
            entries = manifest_entries()
            self.assertTrue(entries, "MANIFEST.sha256 is empty")
            for sha, path in entries:
                name = SUITE + path
                self.assertIn(name, names)
                self.assertEqual(hashlib.sha256(wheel.read(name)).hexdigest(), sha, name)
        self.assertIn(SUITE + "MANIFEST.sha256", names)
        schemas = sorted(p.name for p in (REPO_ROOT / "schemas").glob("*.json"))
        self.assertTrue(schemas)
        for schema in schemas:
            self.assertIn(f"{SUITE}schemas/{schema}", names)
        # The verifiers and the gate, and no other script: the generator, the
        # profile script and the link check run from a checkout.
        self.assertEqual(
            {n for n in names if n.startswith(SUITE + "scripts/")},
            {SUITE + path for path in SUITE_SCRIPTS},
        )
        self.assertEqual([n for n in names if "__pycache__" in n], [])

    def test_suite_root_is_the_installed_copy(self):
        proc = checked(
            run([str(self.python), "-c", f"import {PACKAGE} as m; print(m.suite_root())"]),
            "suite_root()",
        )
        root = Path(proc.stdout.strip())
        self.assertEqual((root.parent.name, root.name), (PACKAGE, "suite"))
        self.assertTrue((root / "fixtures").is_dir())

    def test_console_script_prints_the_captured_run_from_another_directory(self):
        with tempfile.TemporaryDirectory() as cwd:
            proc = run([str(self.script)], cwd=cwd)
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            self.assertEqual(proc.stdout, CAPTURE_TXT.read_text(encoding="utf-8"))
            self.assertEqual(os.listdir(cwd), [], "the gate wrote into the calling directory")

    def test_console_script_takes_the_gate_options(self):
        fixtures = sum(1 for _, path in manifest_entries() if path.startswith("fixtures/"))
        with tempfile.TemporaryDirectory() as cwd:
            Path(cwd, "stub.py").write_text(STUB, encoding="utf-8")
            # `stub.py` is relative: the command runs from the calling directory.
            stub = f"stub={shlex.quote(sys.executable)} stub.py"
            proc = run([str(self.script), "--json", "report.json", "--verifier", stub + " ok"], cwd=cwd)
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            self.assertEqual(proc.stdout.split("\n")[0], f"parity: {fixtures} fixtures x 3 verifiers")
            self.assertIn("\nPARITY: PASS", proc.stdout)
            report = json.loads(Path(cwd, "report.json").read_text(encoding="utf-8"))
            self.assertTrue(report["agree"])
            self.assertEqual(sorted(report["exitCodes"]), ["node", "python", "stub"])

            proc = run([str(self.script), "--verifier", stub + " lie"], cwd=cwd)
            self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
            self.assertIn("\nPARITY: FAIL", proc.stdout)
            self.assertIn("levels/level-0-self-asserted.json: verdict divergence", proc.stdout)


class CheckoutTests(unittest.TestCase):
    def test_module_runs_the_gate_of_the_checkout_without_an_install(self):
        src = str(REPO_ROOT / "src")
        env = dict(os.environ)
        env["PYTHONPATH"] = os.pathsep.join(p for p in (src, env.get("PYTHONPATH")) if p)
        with tempfile.TemporaryDirectory() as cwd:
            proc = run([sys.executable, "-m", PACKAGE], cwd=cwd, env=env)
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            self.assertEqual(proc.stdout, CAPTURE_TXT.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
