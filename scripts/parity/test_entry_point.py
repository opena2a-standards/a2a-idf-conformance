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
`venv` module and network access to PyPI, for the build backend, `build`,
`twine` and `cryptography`.

The package's description is `README.md` with its relative links made absolute
by the metadata hook in `hatch_build.py`, which the tests here exercise
directly and through the wheel's METADATA.
"""
from __future__ import annotations

import email
import hashlib
import importlib.util
import json
import os
import re
import shlex
import subprocess
import sys
import tarfile
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
HATCH_BUILD = REPO_ROOT / "hatch_build.py"
# Where a relative link of README.md points after the hook's rewrite.
BLOB = f"{REPOSITORY}/blob/main/"
TREE = f"{REPOSITORY}/tree/main/"
# The core metadata version both artifacts write (`core-metadata-version` in
# pyproject.toml). It carries every field the package sets, and twine 6.2.0
# replaces packaging's list of valid metadata versions with one that ends at
# 2.4, so it refuses a 2.5 artifact as not a valid metadata version.
METADATA_VERSION = "2.4"

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


def load_hatch_build():
    """The metadata hook module, imported from its path: it is a build script,
    not a package."""
    spec = importlib.util.spec_from_file_location("hatch_build", HATCH_BUILD)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


# `](target` with an optional `<`: the targets of a Markdown text's inline
# links, read independently of the hook's own pattern.
LINK_TARGET = re.compile(r"\]\(\s*<?([^)\s>]+)")
URL_SCHEME = re.compile(r"[a-z][a-z0-9+.-]*:", re.IGNORECASE)


def link_targets(markdown: str) -> list[str]:
    return LINK_TARGET.findall(markdown)


def relative_targets(markdown: str) -> list[str]:
    """The link targets with no URL scheme that are not same-page fragments."""
    return [t for t in link_targets(markdown) if not URL_SCHEME.match(t) and not t.startswith("#")]


def wheel_metadata(path: Path):
    """The parsed METADATA of a wheel; its payload is the description."""
    with zipfile.ZipFile(path) as wheel:
        name = next(n for n in wheel.namelist() if n.endswith(".dist-info/METADATA"))
        return email.message_from_string(wheel.read(name).decode("utf-8"))


def sdist_metadata(path: Path):
    """The parsed PKG-INFO of an sdist, at `<name>-<version>/PKG-INFO`."""
    with tarfile.open(path) as sdist:
        name = next(n for n in sdist.getnames() if n.count("/") == 1 and n.endswith("/PKG-INFO"))
        return email.message_from_bytes(sdist.extractfile(name).read())


def wheel_files(path: Path) -> dict[str, str]:
    """{entry: sha256} for each file of a wheel other than the `WHEEL` entry,
    which records the builder's version, and `RECORD`, which records the
    hashes."""
    with zipfile.ZipFile(path) as wheel:
        return {
            name: hashlib.sha256(wheel.read(name)).hexdigest()
            for name in wheel.namelist()
            if not name.endswith((".dist-info/WHEEL", ".dist-info/RECORD"))
        }


class ReadmeAndMetadataTests(unittest.TestCase):
    def test_readme_first_command_is_the_entry_point(self):
        self.assertEqual(first_bash_block(README.read_text(encoding="utf-8")), [ENTRY_POINT])

    @unittest.skipIf(tomllib is None, "reading pyproject.toml needs tomllib (Python 3.11)")
    def test_pyproject_declares_the_console_script_the_readme_runs(self):
        project = tomllib.loads(PYPROJECT.read_text(encoding="utf-8"))["project"]
        self.assertEqual(project["scripts"], {SCRIPT: f"{PACKAGE}:main"})
        self.assertEqual(project["urls"]["Repository"], REPOSITORY)
        self.assertIn("cryptography", " ".join(project["dependencies"]))

    @unittest.skipIf(tomllib is None, "reading pyproject.toml needs tomllib (Python 3.11)")
    def test_pyproject_has_the_readme_hook_set_the_description(self):
        config = tomllib.loads(PYPROJECT.read_text(encoding="utf-8"))
        self.assertEqual(config["project"]["dynamic"], ["readme"])
        self.assertNotIn("readme", config["project"])
        self.assertEqual(config["tool"]["hatch"]["metadata"]["hooks"], {"custom": {"path": "hatch_build.py"}})
        self.assertTrue(HATCH_BUILD.is_file())


class ReadmeLinkRewriteTests(unittest.TestCase):
    """`absolute_links()` in hatch_build.py, which the build runs on README.md
    to set the package's description."""

    @classmethod
    def setUpClass(cls):
        cls.hook = load_hatch_build()

    def rewrite(self, markdown: str) -> str:
        return self.hook.absolute_links(markdown, REPO_ROOT, REPOSITORY)

    def test_relative_link_points_at_the_file_or_directory_on_github(self):
        cases = {
            "[c](./docs/coverage.md#status)": f"[c]({BLOB}docs/coverage.md#status)",
            "[v](./vectors/)": f"[v]({TREE}vectors/)",
            "[s](scripts/README.md)": f"[s]({BLOB}scripts/README.md)",
            '[l](./LICENSE "License")': f'[l]({BLOB}LICENSE "License")',
            "[l](<./LICENSE>)": f"[l](<{BLOB}LICENSE>)",
            # Not in the checkout: rewritten all the same, the build goes on.
            "[x](./no-such-file.md)": f"[x]({BLOB}no-such-file.md)",
        }
        for source, expected in cases.items():
            with self.subTest(source=source):
                self.assertEqual(self.rewrite(source), expected)

    def test_absolute_links_fragments_and_fenced_code_are_left_as_they_are(self):
        kept = [
            "[a](https://example.com/docs/coverage.md) [b](#status) [m](mailto:maintainers@example.com)",
            "```",
            "[c](./docs/coverage.md)",
            "```",
            "~~~bash",
            "echo '[d](./docs/coverage.md)'",
            "~~~",
        ]
        text = "\n".join([*kept, "[e](./docs/coverage.md)"])
        self.assertEqual(self.rewrite(text), "\n".join([*kept, f"[e]({BLOB}docs/coverage.md)"]))

    def test_every_readme_link_is_absolute_and_in_the_checkout_after_the_rewrite(self):
        readme = README.read_text(encoding="utf-8")
        self.assertTrue(relative_targets(readme), "README.md has no relative link to rewrite")
        rewritten = self.rewrite(readme)
        self.assertEqual(relative_targets(rewritten), [])
        self.assertEqual(len(link_targets(rewritten)), len(link_targets(readme)))
        for target in link_targets(rewritten):
            if not target.startswith(REPOSITORY + "/"):
                continue
            with self.subTest(target=target):
                kind, _, rest = target[len(REPOSITORY) + 1 :].partition("/")
                self.assertIn(kind, ("blob", "tree"))
                self.assertTrue(rest.startswith("main/"), target)
                path = REPO_ROOT / rest[len("main/") :].partition("#")[0]
                self.assertTrue(path.is_dir() if kind == "tree" else path.is_file(), target)


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
        dist = scratch / "dist"
        checked(run([*cls.pip(), "wheel", "--no-deps", "--wheel-dir", str(dist), str(REPO_ROOT)]), "pip wheel")
        wheels = sorted(dist.glob("*.whl"))
        if len(wheels) != 1:
            raise RuntimeError(f"expected one wheel, found {wheels}")
        cls.wheel = wheels[0]
        checked(run([*cls.pip(), "install", str(cls.wheel)]), "pip install")
        cls.script = venv / BIN / (SCRIPT + EXE)
        cls._sdist = None

    @classmethod
    def tearDownClass(cls):
        cls._scratch.cleanup()

    @classmethod
    def pip(cls) -> list[str]:
        return [str(cls.python), "-m", "pip", "--disable-pip-version-check", "-q"]

    @classmethod
    def sdist(cls) -> Path:
        """The sdist that `python3 -m build --sdist` writes from this checkout,
        built on first use with the `build` and `hatchling` the scratch
        environment installs from PyPI."""
        if cls._sdist is None:
            checked(run([*cls.pip(), "install", "build", "hatchling>=1.27"]), "pip install build hatchling")
            sdists = Path(cls._scratch.name) / "sdist"
            checked(
                run([str(cls.python), "-m", "build", "--sdist", "--no-isolation", "--outdir", str(sdists), str(REPO_ROOT)]),
                "python -m build --sdist",
            )
            archives = sorted(sdists.glob("*.tar.gz"))
            if len(archives) != 1:
                raise RuntimeError(f"expected one sdist, found {archives}")
            cls._sdist = archives[0]
        return cls._sdist

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

    def test_wheel_description_is_the_readme_with_absolute_links(self):
        metadata = wheel_metadata(self.wheel)
        self.assertEqual(metadata["Description-Content-Type"], "text/markdown")
        description = metadata.get_payload()
        readme = README.read_text(encoding="utf-8")
        expected = load_hatch_build().absolute_links(readme, REPO_ROOT, REPOSITORY)
        self.assertEqual(description.strip(), expected.strip())
        self.assertEqual(relative_targets(description), [])
        self.assertIn(f"]({BLOB}docs/coverage.md#status)", description)

    def test_sdist_rebuilds_the_wheel(self):
        """`python3 -m build` builds the sdist first and the wheel from the
        sdist, and a release uploads both, so the sdist must carry what the
        wheel build reads: the suite, README.md and hatch_build.py."""
        rebuilt = Path(self._scratch.name) / "rebuilt"
        checked(
            run([*self.pip(), "wheel", "--no-deps", "--no-build-isolation", "--wheel-dir", str(rebuilt), str(self.sdist())]),
            "pip wheel from the sdist",
        )
        wheels = sorted(rebuilt.glob("*.whl"))
        self.assertEqual(len(wheels), 1, wheels)
        self.assertEqual(wheel_files(wheels[0]), wheel_files(self.wheel))

    def test_artifacts_write_core_metadata_version_2_4(self):
        """hatchling 1.32 moved its default to Metadata-Version 2.5. Both
        targets in pyproject.toml set 2.4, which carries every field the
        package writes, so the artifacts do not depend on which hatchling the
        build resolves, and twine 6.2.0, which refuses a 2.5 artifact,
        accepts them."""
        self.assertEqual(wheel_metadata(self.wheel)["Metadata-Version"], METADATA_VERSION)
        self.assertEqual(sdist_metadata(self.sdist())["Metadata-Version"], METADATA_VERSION)

    def test_artifacts_pass_twine_check(self):
        """`twine check --strict` parses each artifact's metadata and renders
        its description as PyPI does; a release runs it before the upload."""
        checked(run([*self.pip(), "install", "twine"]), "pip install twine")
        proc = run([str(self.python), "-m", "twine", "check", "--strict", str(self.wheel), str(self.sdist())])
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertEqual(proc.stdout.count("PASSED"), 2, proc.stdout)

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
