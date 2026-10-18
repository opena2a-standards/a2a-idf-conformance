#!/usr/bin/env python3
"""Tests for the captured parity gate run that the top-level README quotes.

Run from the repository root:
    python3 -m unittest discover -s scripts/parity -p 'test_*.py'

`docs/captures/parity.txt` is what `python3 scripts/parity/parity.py` prints
for the committed fixture set, and `docs/captures/parity.json` is the `--json`
report of the same run. The README shows a trimmed excerpt, labelled with its
first command (the published entry point, which runs the same gate from the
installed copy of the suite), and links the full output. After a change to the
gate's output, refresh both files from the repository root with:

    python3 scripts/parity/parity.py --json docs/captures/parity.json > docs/captures/parity.txt

The fresh-run case runs the two reference verifiers, so it needs Node and the
Python `cryptography` package, like the parity gate itself.
"""
from __future__ import annotations

import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
PARITY = HERE / "parity.py"
REPO_ROOT = HERE.parent.parent
README = REPO_ROOT / "README.md"
CAPTURE_TXT = REPO_ROOT / "docs" / "captures" / "parity.txt"
CAPTURE_JSON = REPO_ROOT / "docs" / "captures" / "parity.json"

COMMAND = "python3 scripts/parity/parity.py"
# The README's first command. It runs the same gate from the installed copy of
# the suite, so it prints the same lines (test_entry_point.py checks that).
ENTRY_POINT = "pipx run --spec git+https://github.com/opena2a-standards/a2a-idf-conformance a2a-idf-conformance"
LABEL = f"What `{ENTRY_POINT}` prints, trimmed ([full output](./docs/captures/parity.txt)):"
ELISION = "..."
REFRESH = f"{COMMAND} --json docs/captures/parity.json > docs/captures/parity.txt"


def readme_excerpt() -> list[str]:
    """The lines of the fenced block that follows the capture label."""
    lines = README.read_text(encoding="utf-8").splitlines()
    start = lines.index(LABEL)
    opening = next(i for i in range(start + 1, len(lines)) if lines[i].startswith("```"))
    closing = next(i for i in range(opening + 1, len(lines)) if lines[i].startswith("```"))
    return lines[opening + 1 : closing]


def runs_between_elisions(excerpt: list[str]) -> list[list[str]]:
    """Split the excerpt at its `...` lines into the runs of lines it quotes."""
    runs: list[list[str]] = [[]]
    for line in excerpt:
        if line == ELISION:
            runs.append([])
        else:
            runs[-1].append(line)
    return [run for run in runs if run]


def find_run(capture: list[str], run: list[str], start: int) -> int:
    """Index in `capture`, at or after `start`, where `run` appears as
    consecutive lines, or -1."""
    for i in range(start, len(capture) - len(run) + 1):
        if capture[i : i + len(run)] == run:
            return i
    return -1


class ReadmeCaptureTests(unittest.TestCase):
    def test_readme_label_names_the_command_and_links_the_full_output(self):
        lines = README.read_text(encoding="utf-8").splitlines()
        self.assertTrue(LABEL in lines, f"README.md has no line {LABEL!r}")

    def test_capture_files_exist_where_the_label_links(self):
        self.assertTrue(CAPTURE_TXT.is_file(), f"missing {CAPTURE_TXT.relative_to(REPO_ROOT)}")
        self.assertTrue(CAPTURE_JSON.is_file(), f"missing {CAPTURE_JSON.relative_to(REPO_ROOT)}")

    def test_readme_excerpt_is_taken_from_the_capture_in_order(self):
        capture = CAPTURE_TXT.read_text(encoding="utf-8").splitlines()
        runs = runs_between_elisions(readme_excerpt())
        self.assertTrue(runs, "the README excerpt quotes no lines")
        position = 0
        for run in runs:
            found = find_run(capture, run, position)
            self.assertNotEqual(
                found, -1, f"README excerpt lines not found, in order, in the capture: {run!r}"
            )
            position = found + len(run)


class RunMatchingTests(unittest.TestCase):
    """The helpers that read the excerpt, on inputs written here."""

    def test_an_edited_line_is_not_found(self):
        capture = ["a", "b  node=PASS:ACCEPT", "c"]
        self.assertEqual(find_run(capture, ["b  node=PASS:REJECT"], 0), -1)

    def test_lines_quoted_together_must_be_consecutive_in_the_capture(self):
        capture = ["a", "b", "c"]
        self.assertEqual(find_run(capture, ["a", "c"], 0), -1)
        self.assertEqual(find_run(capture, ["b", "c"], 0), 1)

    def test_elision_lines_split_the_excerpt_into_runs(self):
        self.assertEqual(
            runs_between_elisions(["...", "a", "...", "b", "", "c"]), [["a"], ["b", "", "c"]]
        )


class FreshRunTests(unittest.TestCase):
    def test_captures_equal_a_fresh_run_of_the_gate(self):
        with tempfile.TemporaryDirectory() as tmp:
            report = Path(tmp) / "parity.json"
            proc = subprocess.run(
                [sys.executable, str(PARITY), "--json", str(report)],
                cwd=REPO_ROOT,
                capture_output=True,
                text=True,
                timeout=300,
            )
            hint = f"refresh with: {REFRESH}"
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            self.assertEqual(proc.stdout, CAPTURE_TXT.read_text(encoding="utf-8"), hint)
            self.assertEqual(report.read_text(encoding="utf-8"), CAPTURE_JSON.read_text(encoding="utf-8"), hint)


if __name__ == "__main__":
    unittest.main()
