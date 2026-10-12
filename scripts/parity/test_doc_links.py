#!/usr/bin/env python3
"""Tests for scripts/check-doc-links.mjs: the `.sigstore/<org>/` check.

Run from the repository root with the other tooling tests:
    python3 -m unittest discover -s scripts/parity -p 'test_*.py'

The script checks the tracked Markdown of the repository it sits in, so each
case runs a copy of it inside a throwaway git repository. Needs Node and git.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

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


def git_env(root: Path) -> dict[str, str]:
    """Keep git inside the scratch directory: no repository above it, and no
    GIT_DIR, work tree or index inherited from the caller."""
    env = {k: v for k, v in os.environ.items() if k not in ("GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE")}
    env["GIT_CEILING_DIRECTORIES"] = str(root.parent)
    return env


def run_check(files: dict[str, str], timeout: int = 120) -> subprocess.CompletedProcess:
    with tempfile.TemporaryDirectory() as tmp:
        repo = Path(tmp)
        env = git_env(repo)
        (repo / "scripts").mkdir()
        shutil.copy(SCRIPT, repo / "scripts" / SCRIPT.name)
        for name, text in files.items():
            (repo / name).write_text(text)
        for command in (["git", "init", "-q"], ["git", "add", "--", *files]):
            subprocess.run(command, cwd=repo, env=env, check=True, capture_output=True)
        return subprocess.run(
            ["node", str(repo / "scripts" / SCRIPT.name)],
            cwd=repo,
            env=env,
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

    def test_output_flags_in_a_comment_are_not_read(self):
        # The directory is read from the comment line; an output flag after an
        # unquoted `#` is not part of the command, and a `\` in a comment does
        # not continue it. Only MANIFEST.sha256.crt is checked.
        for command in (
            "cosign sign-blob MANIFEST.sha256 --output-certificate MANIFEST.sha256.crt"
            " # was: --output-signature MANIFEST.sha256.key",
            "cosign sign-blob MANIFEST.sha256 --output-certificate MANIFEST.sha256.crt # signs \\\n"
            "    --output-signature MANIFEST.sha256.key",
        ):
            with self.subTest(command=command):
                doc = f"# Cosigning\n\n```bash\n{command}\n# commit both under .sigstore/<your-org>/\n```\n"
                proc = run_check({"COSIGNERS.md": doc, ".gitignore": "*.key\n"})
                self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
                self.assertIn("summary: 1 paths checked, 0 broken", proc.stdout)

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


class GitEnvironmentTests(unittest.TestCase):
    def test_caller_git_variables_do_not_reach_the_scratch_repository(self):
        # A caller inside a git hook or worktree can carry these variables. The
        # scratch repository must not be created at, or staged into, theirs.
        with tempfile.TemporaryDirectory() as other:
            git_dir = Path(other) / "caller.git"
            index = Path(other) / "caller-index"
            caller = {"GIT_DIR": str(git_dir), "GIT_INDEX_FILE": str(index), "GIT_WORK_TREE": other}
            with mock.patch.dict(os.environ, caller):
                proc = run_check(
                    {"COSIGNERS.md": RECIPE.format(directory=".sigstore/acme/"), ".gitignore": "*.crt\n"}
                )
            self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
            self.assertIn("-> .sigstore/acme/MANIFEST.sha256.crt is ignored by git", proc.stdout)
            self.assertFalse(git_dir.exists(), "git init wrote the caller's GIT_DIR")
            self.assertFalse(index.exists(), "git add wrote the caller's GIT_INDEX_FILE")


if __name__ == "__main__":
    unittest.main()
