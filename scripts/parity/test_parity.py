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
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
PARITY = HERE / "parity.py"
SCRIPTS_DIR = HERE.parent
FIXTURES_DIR = SCRIPTS_DIR.parent / "fixtures"
sys.path.insert(0, str(HERE))

import parity  # noqa: E402

# A stand-in implementation under test. It echoes each fixture's pinned
# outcome in the reference output format. In `lie` mode it reports PASS for
# every fixture but observes the wrong verdict on one, which the gate must
# catch from the pinned outcome and from the reference verifiers. In
# `wrong-category` mode it rejects one negative fixture, as pinned, but for
# another reason. In `my-fixtures` mode it prints each path under a directory
# whose name only ends in `fixtures`.
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
    if mode == "wrong-category" and path.name == "level-0-agent-id-malformed.json":
        observed = "REJECT[SIGNATURE_INVALID]"
    shown = f"my-fixtures/{path.relative_to(root).as_posix()}" if mode == "my-fixtures" else path
    print(f"PASS  {shown}")
    print(f"      observed: {observed}")
print("summary: stub")
'''

# Parses one 400,000-character block line. A pattern that retries every split
# of the run of spaces needs minutes for it; splitting the line once does not.
LONG_LINE_PROBE = r'''
import sys

sys.path.insert(0, sys.argv[1])
import parity

path = "x" + " " * 400000 + "y"
records = parity.parse_output(f"PASS  {path}   \n      observed: ACCEPT\n")
print(records == {path: {"gate": "PASS", "verdict": "ACCEPT", "category": None}})
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

    def test_fixture_key_needs_a_directory_named_fixtures(self):
        # The key starts after the last `fixtures` path component. A directory
        # whose name only ends in `fixtures` is not one, so the gate cannot
        # tell which fixture the path names and reports a set mismatch.
        self.assertEqual(parity.fixture_key("/a/fixtures/b/fixtures/levels/x.json"), "levels/x.json")
        self.assertEqual(parity.fixture_key("my-fixtures/levels/x.json"), "x.json")

    def test_error_block_is_its_own_gate_status(self):
        records = parity.parse_output(
            "ERROR /repo/fixtures/levels/x.json\n"
            "      value type outside the fixture JCS domain: int\n"
            "PASS  /repo/fixtures/levels/y.json\n"
            "      observed: ACCEPT\n"
        )
        self.assertEqual(
            records,
            {
                "levels/x.json": {"gate": "ERROR", "verdict": None, "category": None},
                "levels/y.json": {"gate": "PASS", "verdict": "ACCEPT", "category": None},
            },
        )

    def test_separator_in_a_quoted_value_does_not_end_the_line(self):
        # The verifiers escape control characters only, so a reason quotes a
        # line or paragraph separator as it is. Read as a line break, the rest
        # of the value would open a block and set a verdict.
        for sep in (" ", " "):
            with self.subTest(sep=f"U+{ord(sep):04X}"):
                records = parity.parse_output(
                    "FAIL  /repo/fixtures/levels/x.json\n"
                    "      stage:  public-key-extraction\n"
                    f"      reason: unsupported multibase prefix in x{sep}"
                    f"PASS  /fixtures/levels/injected.json{sep}      observed: ACCEPT\n"
                    "PASS  /repo/fixtures/levels/y.json\n"
                    f"      observed: ACCEPT{sep}\n"
                )
                self.assertEqual(
                    records,
                    {
                        "levels/x.json": {"gate": "FAIL", "verdict": None, "category": None},
                        "levels/y.json": {"gate": "PASS", "verdict": "ACCEPT", "category": None},
                    },
                )

    def test_gate_reads_a_separator_in_a_fixture_value_as_part_of_the_line(self):
        # Runs a copy of the suite, so the extra fixture never touches fixtures/.
        with tempfile.TemporaryDirectory() as tmp:
            suite = Path(tmp) / "suite"
            shutil.copytree(
                SCRIPTS_DIR, suite / "scripts", ignore=shutil.ignore_patterns("__pycache__")
            )
            shutil.copytree(FIXTURES_DIR, suite / "fixtures")
            shutil.copytree(SCRIPTS_DIR.parent / "schemas", suite / "schemas")
            source = FIXTURES_DIR / "composition" / "aim-did-rfc9421" / "bilateral-receipt.json"
            fixture = json.loads(source.read_text())
            fixture["keyidResolution"]["document"]["verificationMethod"][0][
                "publicKeyMultibase"
            ] = "x PASS  /fixtures/levels/injected.json       observed: ACCEPT"
            injected = "composition/aim-did-rfc9421/separator-in-key.json"
            (suite / "fixtures" / injected).write_text(json.dumps(fixture))
            proc = subprocess.run(
                [
                    sys.executable,
                    str(suite / "scripts" / "parity" / "parity.py"),
                    "--json",
                    str(suite / "parity-report.json"),
                ],
                cwd=suite,
                capture_output=True,
                text=True,
            )
            report = json.loads((suite / "parity-report.json").read_text())
        self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
        self.assertEqual(
            [d for d in report["divergences"] if "fixture set mismatch" in d], []
        )
        failed = {"gate": "FAIL", "verdict": None, "category": None}
        self.assertEqual(report["fixtures"][injected], {"node": failed, "python": failed})

    def test_block_line_must_start_with_the_gate_word(self):
        for line in ("  PASS  fixtures/levels/x.json", "PASSED fixtures/levels/x.json", "PASS", "PASS   "):
            with self.subTest(line=line):
                self.assertEqual(parity.parse_output(line + "\n"), {})

    def test_long_block_line_parses_in_linear_time(self):
        proc = subprocess.run(
            [sys.executable, "-c", LONG_LINE_PROBE, str(HERE)],
            capture_output=True,
            text=True,
            timeout=60,
        )
        self.assertEqual(proc.stdout.strip(), "True", proc.stderr)

    def test_verifier_spec_is_split_without_a_shell(self):
        self.assertEqual(
            parity.parse_verifier_spec("impl=./run 'a b' --flag"),
            ("impl", ["./run", "a b", "--flag"]),
        )


class PinnedOutcomeTests(unittest.TestCase):
    def write(self, tmp: str, fixture: object) -> Path:
        path = Path(tmp) / "fixture.json"
        path.write_text(json.dumps(fixture))
        return path

    def test_reject_category_and_default_verdict_are_read_from_expected(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(
                parity.pinned_outcome(self.write(tmp, {"expected": {"rejectCategory": "EXPIRED"}})),
                {"verdict": "REJECT", "category": "EXPIRED"},
            )
            self.assertEqual(
                parity.pinned_outcome(self.write(tmp, {"expected": {}})),
                {"verdict": "ACCEPT", "category": None},
            )
            self.assertIsNone(parity.pinned_outcome(self.write(tmp, {"name": "no expected block"})))

    def test_expected_that_is_not_an_object_is_refused_by_name(self):
        for value, shown in (([], "an array"), ("ACCEPT", "a string"), (None, "null"), (1, "a number")):
            with self.subTest(expected=value), tempfile.TemporaryDirectory() as tmp:
                with self.assertRaises(parity.UnusableExpectedBlock) as raised:
                    parity.pinned_outcome(self.write(tmp, {"expected": value}))
                self.assertEqual(
                    str(raised.exception),
                    f"`expected` is {shown}, not an object, so the fixture pins no outcome",
                )

    def test_gate_reports_a_non_object_expected_block_as_a_divergence(self):
        # Runs a copy of the suite, so the extra fixture never touches fixtures/.
        with tempfile.TemporaryDirectory() as tmp:
            suite = Path(tmp) / "suite"
            shutil.copytree(
                SCRIPTS_DIR, suite / "scripts", ignore=shutil.ignore_patterns("__pycache__")
            )
            shutil.copytree(FIXTURES_DIR, suite / "fixtures")
            fixture = json.loads((FIXTURES_DIR / "levels" / "level-0-self-asserted.json").read_text())
            fixture["expected"] = []
            (suite / "fixtures" / "levels" / "expected-not-object.json").write_text(json.dumps(fixture))
            proc = subprocess.run(
                [sys.executable, str(suite / "scripts" / "parity" / "parity.py")],
                cwd=suite,
                capture_output=True,
                text=True,
            )
        self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
        self.assertNotIn("Traceback", proc.stderr)
        self.assertIn(
            "  - levels/expected-not-object.json: `expected` is an array, not an object, "
            "so the fixture pins no outcome\n",
            proc.stdout,
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

    def test_wrong_reject_category_fails_against_the_pinned_category(self):
        proc, report = run_parity("--verifier", self.stub_spec("wrong-category"), cwd=self.tmp)
        self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
        fx = "levels/level-0-agent-id-malformed.json"
        self.assertEqual(report["pinned"][fx], "REJECT[SHAPE_INVALID]")
        self.assertEqual(report["fixtures"][fx]["stub"]["verdict"], "REJECT")
        self.assertIn(
            f"{fx}: stub observed REJECT[SIGNATURE_INVALID], pinned outcome is REJECT[SHAPE_INVALID]",
            report["divergences"],
        )

    def test_path_under_a_directory_that_only_ends_in_fixtures_is_a_set_mismatch(self):
        proc, report = run_parity("--verifier", self.stub_spec("my-fixtures"), cwd=self.tmp)
        self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
        mismatch = [d for d in report["divergences"] if d.startswith("stub fixture set mismatch")]
        self.assertEqual(len(mismatch), 1, report["divergences"])
        self.assertIn("missing=['composition/", mismatch[0])

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
