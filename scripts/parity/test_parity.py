#!/usr/bin/env python3
"""Tests for the parity gate's implementation-under-test interface.

Run from the repository root:
    python3 -m unittest discover -s scripts/parity -p 'test_*.py'

The end-to-end cases run the two reference verifiers, so they need Node and
the Python `cryptography` package, like the parity gate itself.
"""
from __future__ import annotations

import json
import shlex
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
PARITY = HERE / "parity.py"
FIXTURES_DIR = HERE.parent.parent / "fixtures"
sys.path.insert(0, str(HERE))

import parity  # noqa: E402

# A stand-in implementation under test. It echoes each fixture's pinned
# outcome in the reference output format. In `lie` mode it reports PASS for
# every fixture but observes the wrong verdict on one, which the gate must
# catch from the pinned outcome and from the reference verifiers.
STUB = r'''
import json
import sys
from pathlib import Path

mode, root = sys.argv[1], Path(sys.argv[2])
if not root.is_absolute():
    sys.exit(3)
for path in sorted(root.rglob("*.json")):
    expected = json.loads(path.read_text())["expected"]
    category = expected.get("rejectCategory")
    observed = f"REJECT[{category}]" if category else expected.get("verifyResult", "ACCEPT")
    if mode == "lie" and path.name == "level-0-self-asserted.json":
        observed = "REJECT[SHAPE_INVALID]"
    print(f"PASS  {path}")
    print(f"      observed: {observed}")
print("summary: stub")
'''


def run_parity(*args: str, cwd: Path) -> tuple[subprocess.CompletedProcess, dict | None]:
    report = cwd / "parity-report.json"
    if report.exists():
        report.unlink()
    proc = subprocess.run(
        [sys.executable, str(PARITY), "--json", str(report), *args],
        cwd=cwd,
        capture_output=True,
        text=True,
    )
    data = json.loads(report.read_text()) if report.exists() else None
    return proc, data


class ParseTests(unittest.TestCase):
    def test_fixture_key_accepts_absolute_and_repo_relative_paths(self):
        self.assertEqual(parity.fixture_key("/a/b/fixtures/levels/x.json"), "levels/x.json")
        self.assertEqual(parity.fixture_key("fixtures/levels/x.json"), "levels/x.json")

    def test_block_path_may_contain_spaces(self):
        records = parity.parse_output(
            "PASS  /home/u/my checkout/fixtures/levels/x.json\n"
            "      observed: REJECT[SHAPE_INVALID]\n"
        )
        self.assertEqual(
            records,
            {"levels/x.json": {"gate": "PASS", "verdict": "REJECT", "category": "SHAPE_INVALID"}},
        )

    def test_verifier_spec_is_split_without_a_shell(self):
        self.assertEqual(
            parity.parse_verifier_spec("impl=./run 'a b' --flag"),
            ("impl", ["./run", "a b", "--flag"]),
        )


class VerifierOptionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._tmp = tempfile.TemporaryDirectory()
        cls.tmp = Path(cls._tmp.name)
        (cls.tmp / "stub.py").write_text(STUB)
        cls.fixture_files = sorted(
            p.relative_to(FIXTURES_DIR).as_posix() for p in FIXTURES_DIR.rglob("*.json")
        )

    @classmethod
    def tearDownClass(cls):
        cls._tmp.cleanup()

    def stub_spec(self, mode: str, script: str = "stub.py") -> str:
        return "stub=" + shlex.join([sys.executable, script, mode])

    def test_help_documents_the_option(self):
        proc = subprocess.run(
            [sys.executable, str(PARITY), "--help"], capture_output=True, text=True
        )
        self.assertEqual(proc.returncode, 0)
        self.assertIn("--verifier NAME=COMMAND", proc.stdout)

    def test_conforming_implementation_is_compared_and_passes(self):
        # Relative script path: COMMAND runs from the caller's directory.
        proc, report = run_parity("--verifier", self.stub_spec("conform"), cwd=self.tmp)
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn("x 3 verifiers", proc.stdout)
        self.assertTrue(report["agree"])
        self.assertEqual(report["exitCodes"]["stub"], 0)
        self.assertEqual(sorted(report["fixtures"]), self.fixture_files)
        for fx, row in report["fixtures"].items():
            observed = row["stub"]["verdict"]
            if row["stub"]["category"]:
                observed += f"[{row['stub']['category']}]"
            self.assertEqual(observed, report["pinned"][fx], fx)

    def test_divergent_implementation_fails_even_when_it_reports_pass(self):
        proc, report = run_parity("--verifier", self.stub_spec("lie"), cwd=self.tmp)
        self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
        self.assertFalse(report["agree"])
        fx = "levels/level-0-self-asserted.json"
        self.assertIn(
            f"{fx}: stub observed REJECT[SHAPE_INVALID], pinned outcome is ACCEPT",
            report["divergences"],
        )
        self.assertTrue(
            any(d.startswith(f"{fx}: verdict divergence") for d in report["divergences"])
        )

    def test_command_that_cannot_start_is_a_divergence(self):
        missing = str(self.tmp / "no-such-verifier")
        proc, report = run_parity("--verifier", f"stub={missing}", cwd=self.tmp)
        self.assertEqual(proc.returncode, 1)
        self.assertIn("stub verifier exited 127 (expected 0)", report["divergences"])

    def test_malformed_specs_are_usage_errors(self):
        for spec in ("no-equals-sign", "=cmd", "stub=", "node=./other"):
            with self.subTest(spec=spec):
                proc, report = run_parity("--verifier", spec, cwd=self.tmp)
                self.assertEqual(proc.returncode, 2, proc.stderr)
                self.assertIsNone(report)


if __name__ == "__main__":
    unittest.main()
