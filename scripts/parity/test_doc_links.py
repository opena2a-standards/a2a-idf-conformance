#!/usr/bin/env python3
"""Tests for scripts/check-doc-links.mjs: the `.sigstore/<org>/` check.

Run from the repository root with the other tooling tests:
    python3 -m unittest discover -s scripts/parity -p 'test_*.py'

The script checks the tracked Markdown of the repository it sits in, so each
case runs a copy of it inside a throwaway git repository. Needs Node and git.
"""
from __future__ import annotations

import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parent.parent / "check-doc-links.mjs"

# A cosigning recipe whose code block names the directory to commit under.
RECIPE = """\
# Cosigning

```bash
cosign sign-blob MANIFEST.sha256 \\
    --output-signature MANIFEST.sha256.sig \\
    --output-certificate MANIFEST.sha256.crt

# Open a PR that adds both files under {directory}
```
"""


def run_check(files: dict[str, str], timeout: int = 120) -> subprocess.CompletedProcess:
    with tempfile.TemporaryDirectory() as tmp:
        repo = Path(tmp)
        (repo / "scripts").mkdir()
        shutil.copy(SCRIPT, repo / "scripts" / SCRIPT.name)
        for name, text in files.items():
            (repo / name).write_text(text)
        for command in (["git", "init", "-q"], ["git", "add", "--", *files]):
            subprocess.run(command, cwd=repo, check=True, capture_output=True)
        return subprocess.run(
            ["node", str(repo / "scripts" / SCRIPT.name)],
            cwd=repo,
            capture_output=True,
            text=True,
            timeout=timeout,
        )


class SigstoreDirectoryTests(unittest.TestCase):
    def test_ignored_cosign_output_is_reported_under_the_named_directory(self):
        proc = run_check(
            {"COSIGNERS.md": RECIPE.format(directory=".sigstore/<your-org>/"), ".gitignore": "*.crt\n"}
        )
        self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
        self.assertIn(
            "cosign output MANIFEST.sha256.crt -> .sigstore/example-org/MANIFEST.sha256.crt "
            "is ignored by git (.gitignore:1:*.crt)",
            proc.stdout,
        )
        self.assertIn("summary: 2 paths checked, 1 broken", proc.stdout)

    def test_re_included_cosign_output_passes(self):
        proc = run_check(
            {
                "COSIGNERS.md": RECIPE.format(directory=".sigstore/<your-org>/"),
                ".gitignore": "*.crt\n!.sigstore/**/*.crt\n",
            }
        )
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn("summary: 2 paths checked, 0 broken", proc.stdout)

    def test_directory_is_found_in_every_position_a_recipe_writes_it(self):
        # (text in the code block, directory the outputs are checked under)
        for written, directory in (
            (".sigstore/acme/", ".sigstore/acme/"),
            ("`.sigstore/acme/`", ".sigstore/acme/"),
            ("'.sigstore/acme/'", ".sigstore/acme/"),
            ('".sigstore/acme/"', ".sigstore/acme/"),
            ("(.sigstore/acme/)", ".sigstore/acme/"),
            (".sigstore/acme/2026/", ".sigstore/acme/2026/"),
            (".sigstore/<org>/<year>/", ".sigstore/example-org/example-org/"),
            ("x.sigstore/skipped/ then `.sigstore/acme/`", ".sigstore/acme/"),
        ):
            with self.subTest(written=written):
                proc = run_check(
                    {"COSIGNERS.md": RECIPE.format(directory=written), ".gitignore": "*.crt\n"}
                )
                self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
                self.assertIn(f"-> {directory}MANIFEST.sha256.crt is ignored by git", proc.stdout)

    def test_block_that_names_no_directory_is_not_checked(self):
        for written in ("the repository root", ".sigstore/acme", "x.sigstore/acme/", ".sigstore/acme/file.crt"):
            with self.subTest(written=written):
                proc = run_check(
                    {"COSIGNERS.md": RECIPE.format(directory=written), ".gitignore": "*.crt\n"}
                )
                self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
                self.assertIn("summary: 0 paths checked, 0 broken", proc.stdout)

    def test_long_code_block_lines_are_scanned_in_linear_time(self):
        # Two megabyte-long lines with no space in them. A pattern that retries
        # every `.sigstore/` start, or every `<`, against the rest of the line
        # takes hours on these; one pass per line takes milliseconds.
        many_starts = "(.sigstore/" * 200_000 + "x"
        many_placeholders = ".sigstore/" + "<" * 2_000_000 + "/"
        doc = f"# Long lines\n\n```\n{many_starts}\n{many_placeholders}\n```\n"
        proc = run_check({"LONG.md": doc}, timeout=60)
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn("summary: 0 paths checked, 0 broken", proc.stdout)


if __name__ == "__main__":
    unittest.main()
