#!/usr/bin/env python3
"""Tests for the parity gate's implementation-under-test interface.

Run from the repository root:
    python3 -m unittest discover -s scripts/parity -p 'test_*.py'

The end-to-end cases run the two reference verifiers, so they need Node and
the Python `cryptography` package, like the parity gate itself.
"""
from __future__ import annotations

import json
import os
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

# An implementation under test that prints 25 ERROR blocks on stdout and 400
# numbered lines on stderr, then exits 1.
NOISY_STUB = r'''
import sys

for i in range(25):
    print(f"ERROR {sys.argv[1]}/levels/e{i:02}.json")
    print(f"      reason {i}")
for i in range(400):
    print(f"stderr line {i:03}", file=sys.stderr)
sys.exit(1)
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
    # The gate opens the report file once the arguments are read, so a run
    # that ends at a usage error leaves no file.
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
                "levels/x.json": {
                    "gate": "ERROR",
                    "verdict": None,
                    "category": None,
                    "reason": "value type outside the fixture JCS domain: int",
                },
                "levels/y.json": {"gate": "PASS", "verdict": "ACCEPT", "category": None},
            },
        )

    def test_error_block_without_an_indented_line_has_no_reason(self):
        records = parity.parse_output(
            "ERROR /repo/fixtures/levels/x.json\n"
            "summary: 0 pass, 1 fail (1 fixtures)\n"
        )
        self.assertEqual(
            records,
            {"levels/x.json": {"gate": "ERROR", "verdict": None, "category": None, "reason": None}},
        )

    def test_fixture_text_in_a_node_stack_trace_does_not_open_a_line(self):
        # An error message can quote fixture text, line feeds included. Printed
        # a line at a time, the trace would put `observed: ACCEPT` and a block
        # line on lines of their own, giving the ERROR a verdict and the gate a
        # record for a fixture that does not exist. verify.mjs writes a component
        # value it does not support into its own `unsupported component` error,
        # so that case does not rest on the wording of a Node error message, as
        # the JSON.parse case does.
        injected = "\n      observed: ACCEPT\nPASS  /fixtures/levels/injected.json\n      observed: ACCEPT"
        source = FIXTURES_DIR / "composition" / "aim-did-rfc9421" / "bilateral-receipt.json"
        component = json.loads(source.read_text())
        component["signatureParams"]["components"].append(f"x{injected}")
        # Each case: the fixture bytes, text the trace must quote, and how the
        # reason the gate keeps from the ERROR block begins.
        cases = {
            "composition/split-trace.json": (
                json.dumps(component).encode(),
                "Error: unsupported component: x\\u000a      observed: ACCEPT\\u000aPASS  ",
                "Error: unsupported component: x",
            ),
            "levels/split-trace.json": (b"[\nobserved: ACCEPT", "SyntaxError", "SyntaxError"),
        }
        for key, (text, quoted, reason_start) in cases.items():
            with self.subTest(fixture=key), tempfile.TemporaryDirectory() as tmp:
                fixture = Path(tmp) / "fixtures" / key
                fixture.parent.mkdir(parents=True)
                fixture.write_bytes(text)
                proc = subprocess.run(
                    ["node", str(SCRIPTS_DIR / "verify.mjs"), str(fixture)],
                    capture_output=True,
                    text=True,
                )
                self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
                records = parity.parse_output(proc.stdout)
                reason = (records.get(key) or {}).get("reason") or ""
                self.assertTrue(reason.startswith(reason_start), proc.stdout)
                self.assertEqual(
                    records,
                    {key: {"gate": "ERROR", "verdict": None, "category": None, "reason": reason}},
                    proc.stdout,
                )
                self.assertIn(quoted, proc.stdout)

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

    def test_command_that_cannot_start_is_not_also_listed_as_missing_every_fixture(self):
        missing = str(self.tmp / "no-such-verifier")
        proc, report = run_parity("--verifier", f"stub={missing}", cwd=self.tmp)
        self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
        self.assertEqual(report["divergences"], ["stub verifier exited 127 (expected 0)"])
        self.assertIn("[parity] stub verifier could not start: ", proc.stderr)
        # A command that starts, exits 0 and reports no fixture keeps the line,
        # since nothing else reports it.
        silent = "stub=" + shlex.join([sys.executable, "-c", "pass"])
        proc, report = run_parity("--verifier", silent, cwd=self.tmp)
        self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
        self.assertEqual(
            report["divergences"],
            [f"stub fixture set mismatch: missing={self.fixture_files} extra=[]"],
        )

    def test_malformed_specs_are_usage_errors(self):
        for spec in ("no-equals-sign", "=cmd", "stub=", "node=./other"):
            with self.subTest(spec=spec):
                proc, report = run_parity("--verifier", spec, cwd=self.tmp)
                self.assertEqual(proc.returncode, 2, proc.stderr)
                self.assertIsNone(report)


class JsonReportPathTests(unittest.TestCase):
    """A `--json` path that cannot be written is refused before any verifier runs."""

    def assert_refused(self, path: Path, shown: str) -> None:
        with self.assertRaises(OSError) as raised:
            open(path, "w", encoding="utf-8")
        proc = subprocess.run(
            [sys.executable, str(PARITY), "--json", str(path)], capture_output=True, text=True
        )
        self.assertEqual(proc.returncode, 2, proc.stdout + proc.stderr)
        self.assertNotIn("Traceback", proc.stderr)
        # The gate did not run: not even its `parity:` line was printed.
        self.assertEqual(proc.stdout, "")
        last = proc.stderr.rstrip("\n").split("\n")[-1]
        self.assertTrue(last.startswith("parity.py: error: argument --json:"), proc.stderr)
        self.assertIn(shown, last)
        self.assertIn(raised.exception.strerror, last)

    def test_path_in_a_missing_directory_is_a_usage_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            missing = Path(tmp) / "missing"
            self.assert_refused(missing / "r.json", "missing/r.json")
            self.assertFalse(missing.exists())

    def test_directory_is_a_usage_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.assert_refused(Path(tmp), tmp)


# Longer than the report of the committed fixture set, so a report written
# after this text, or over its start, leaves a file json.loads() refuses.
PREVIOUS_REPORT = "previous report\n" * 10000


class JsonReportContentTests(unittest.TestCase):
    """The `--json` file changes only when the report is written in its place."""

    def test_help_and_usage_errors_leave_the_path_as_it_was(self):
        for args, code in (
            (["--help"], 0),
            (["-h"], 0),
            (["--no-such-option"], 2),
            (["--verifier", "no-equals-sign"], 2),
            (["--verifier", "node=./other"], 2),
        ):
            with self.subTest(args=args), tempfile.TemporaryDirectory() as tmp:
                existing, missing = Path(tmp) / "existing.json", Path(tmp) / "missing.json"
                existing.write_text(PREVIOUS_REPORT)
                for path in (existing, missing):
                    proc = subprocess.run(
                        [sys.executable, str(PARITY), "--json", str(path), *args],
                        capture_output=True,
                        text=True,
                    )
                    self.assertEqual(proc.returncode, code, proc.stdout + proc.stderr)
                    self.assertTrue((proc.stdout if code == 0 else proc.stderr).startswith("usage:"))
                self.assertEqual(existing.read_text(), PREVIOUS_REPORT)
                self.assertFalse(missing.exists())

    def test_run_that_writes_no_report_keeps_an_existing_file(self):
        # A copy of the gate over an empty fixtures/ directory stops at
        # "no fixtures found", before any verifier runs.
        with tempfile.TemporaryDirectory() as tmp:
            gate = Path(tmp) / "suite" / "scripts" / "parity" / "parity.py"
            gate.parent.mkdir(parents=True)
            shutil.copy(PARITY, gate)
            (Path(tmp) / "suite" / "fixtures").mkdir()
            existing, created = Path(tmp) / "existing.json", Path(tmp) / "created.json"
            existing.write_text(PREVIOUS_REPORT)
            for path in (existing, created):
                proc = subprocess.run(
                    [sys.executable, str(gate), "--json", str(path)], capture_output=True, text=True
                )
                self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
                self.assertEqual(proc.stderr, "[parity] no fixtures found\n")
            self.assertEqual(existing.read_text(), PREVIOUS_REPORT)
            self.assertEqual(created.read_text(), "")

    def test_report_replaces_the_content_of_the_last_json_path(self):
        with tempfile.TemporaryDirectory() as tmp:
            first, second = Path(tmp) / "first.json", Path(tmp) / "second.json"
            for path in (first, second):
                path.write_text(PREVIOUS_REPORT)
            proc = subprocess.run(
                [sys.executable, str(PARITY), "--json", str(first), "--json", str(second)],
                capture_output=True,
                text=True,
            )
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            self.assertEqual(first.read_text(), PREVIOUS_REPORT)
            self.assertTrue(json.loads(second.read_text())["agree"])

    def test_report_to_a_pipe_is_written_without_truncating_it(self):
        read_end, write_end = os.pipe()
        with open(read_end, encoding="utf-8") as reader:
            parity.write_report(open(write_end, "a", encoding="utf-8"), "report\n")
            self.assertEqual(reader.read(), "report\n")


class ErrorReasonTests(unittest.TestCase):
    """What the gate shows when a verifier reports ERROR or exits non-zero."""

    @unittest.skipIf(
        not hasattr(os, "geteuid") or os.geteuid() == 0,
        "a file of mode 000 is unreadable only to a POSIX user other than root",
    )
    def test_unreadable_fixture_is_reported_with_each_verifier_reason(self):
        # Runs a copy of the suite, so the mode change never touches fixtures/.
        key = "levels/level-0-self-asserted.json"
        with tempfile.TemporaryDirectory() as tmp:
            # The verifiers print fixture paths with symbolic links resolved.
            suite = Path(tmp).resolve() / "suite"
            shutil.copytree(
                SCRIPTS_DIR, suite / "scripts", ignore=shutil.ignore_patterns("__pycache__")
            )
            shutil.copytree(FIXTURES_DIR, suite / "fixtures")
            shutil.copytree(SCRIPTS_DIR.parent / "schemas", suite / "schemas")
            fixture = suite / "fixtures" / key
            fixture.chmod(0o000)
            try:
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
            finally:
                # Restored so that the temporary directory can be removed.
                fixture.chmod(0o644)
            report = json.loads((suite / "parity-report.json").read_text())
        self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
        stderr_lines = proc.stderr.split("\n")
        for name in ("node", "python"):
            with self.subTest(verifier=name):
                prefix = f"  - {key}: {name} ERROR: "
                bullets = [line for line in proc.stdout.split("\n") if line.startswith(prefix)]
                self.assertEqual(len(bullets), 1, proc.stdout)
                self.assertIn("permission denied", bullets[0][len(prefix):].lower())
                self.assertIn(bullets[0][len("  - "):], report["divergences"])
                self.assertTrue(report["fixtures"][key][name]["reason"])
                self.assertIn(f"[parity] {name} ERROR blocks:", stderr_lines)
        self.assertIn(f"ERROR {fixture}", stderr_lines)
        # Each ERROR block is echoed whole, so no line under its header is cut.
        self.assertTrue(proc.stderr.endswith("\n"), proc.stderr)
        header = None
        for line in stderr_lines[:-1]:
            if line.startswith("[parity]"):
                header = line
            elif header is not None and header.endswith(" ERROR blocks:"):
                self.assertTrue(line.startswith(("ERROR ", " " * 6)), f"{line!r} under {header!r}")

    def test_verifier_that_prints_no_error_block_has_its_stdout_echoed(self):
        # It exits non-zero with a diagnostic outside the block format and
        # nothing on stderr.
        with tempfile.TemporaryDirectory() as tmp:
            stub = Path(tmp) / "boom.py"
            stub.write_text('print("boom")\nraise SystemExit(3)\n')
            proc, report = run_parity(
                "--verifier", "stub=" + shlex.join([sys.executable, str(stub)]), cwd=Path(tmp)
            )
        self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
        self.assertIn("[parity] stub stdout (last lines):\nboom\n", proc.stderr)
        self.assertIn("stub verifier exited 3 (expected 0)", report["divergences"])

    def test_twenty_error_blocks_are_echoed_and_the_stderr_tail_starts_at_a_line(self):
        with tempfile.TemporaryDirectory() as tmp:
            stub = Path(tmp) / "noisy.py"
            stub.write_text(NOISY_STUB)
            proc, _ = run_parity(
                "--verifier", "stub=" + shlex.join([sys.executable, str(stub)]), cwd=Path(tmp)
            )
        self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
        lines = proc.stderr.split("\n")
        start = lines.index("[parity] stub ERROR blocks:") + 1
        blocks = []
        for i in range(20):
            blocks += [f"ERROR {FIXTURES_DIR}/levels/e{i:02}.json", f"      reason {i}"]
        self.assertEqual(lines[start : start + 41], [*blocks, "[parity] ... and 5 more"])
        start = lines.index("[parity] stub stderr (last lines):") + 1
        self.assertEqual(lines[-1], "", proc.stderr)
        tail = lines[start:-1]
        self.assertTrue(0 < len(tail) < 400, proc.stderr)
        self.assertEqual(tail, [f"stderr line {i:03}" for i in range(400 - len(tail), 400)])
        self.assertLessEqual(len("\n".join(tail).encode()), 2000)

    def test_echoed_tail_is_the_lines_that_start_within_the_window(self):
        size = parity.ECHO_TAIL_BYTES
        self.assertEqual(parity.last_lines("a\nb\n\n"), "a\nb")
        # The window starts at the start of a line, so that line is kept.
        lines = "x" * (size // 2 - 1) + "\n" + "y" * (size // 2)
        self.assertEqual(parity.last_lines(f"cut\n{lines}\n"), lines)
        # One byte more, and the first of those lines starts before the window.
        self.assertEqual(parity.last_lines(f"cut\nx{lines}\n"), "y" * (size // 2))
        # A last line longer than the window is cut to it.
        self.assertEqual(parity.last_lines("z" * (size + 5)), "z" * size)


class CommandLineTests(unittest.TestCase):
    """Options the gate refuses as usage errors, exit 2, before it runs a verifier."""

    def run_gate(self, *args: str) -> tuple[subprocess.CompletedProcess, list[str]]:
        """Run the gate from a scratch directory; return the process and the
        names of the files it left there."""
        with tempfile.TemporaryDirectory() as cwd:
            proc = subprocess.run(
                [sys.executable, str(PARITY), *args], cwd=cwd, capture_output=True, text=True
            )
            return proc, sorted(os.listdir(cwd))

    def test_abbreviated_option_is_a_usage_error(self):
        # Taken as `--json` and `--verifier`, these would run the gate.
        for args in (["--jso", "report.json"], ["--v", "x=true"]):
            with self.subTest(args=args):
                proc, written = self.run_gate(*args)
                self.assertEqual(proc.returncode, 2, proc.stdout + proc.stderr)
                self.assertEqual(
                    proc.stderr.splitlines()[-1],
                    f"parity.py: error: unrecognized arguments: {' '.join(args)}",
                )
                self.assertEqual(written, [])


if __name__ == "__main__":
    unittest.main()
