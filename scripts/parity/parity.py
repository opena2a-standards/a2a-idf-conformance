#!/usr/bin/env python3
"""Cross-implementation parity gate.

Runs every reference verifier in this repository, plus any implementation
named with `--verifier`, over the byte-pinned fixture set and asserts that all
implementations agree per fixture on:

  1. gate status   -- PASS/FAIL against the fixture's pinned `expected` block,
                      or ERROR when the verifier raised instead of deciding
  2. verdict       -- ACCEPT vs REJECT
  3. reject category (when REJECT)

and that every implementation's observed verdict (and reject category, when
pinned) matches the outcome pinned in the fixture itself. The pinned check
reads the fixture directly, so it does not rely on an implementation's own
PASS/FAIL report. The gate fails if any verifier skips a fixture the others
saw, disagrees on gate, verdict or category, departs from the pinned outcome,
or exits non-zero. It also fails when a fixture's `expected` block is not a
JSON object, since such a fixture pins nothing.

Usage:
    python3 scripts/parity/parity.py [--json parity-report.json]
                                     [--verifier NAME=COMMAND ...]

`--verifier` adds an implementation under test. COMMAND is split with
shell-style quoting (no shell is invoked), run from the current directory, and
given the absolute path of the fixtures/ directory as its last argument. It
must print the same per-fixture blocks as the reference verifiers; the
interface is documented in scripts/README.md.

Exit codes: 0 = all implementations agree, 1 = divergence or verifier error,
2 = usage error.
"""
from __future__ import annotations

import argparse
import json
import re
import shlex
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
FIXTURES_DIR = REPO_ROOT / "fixtures"

VERIFIERS = {
    "node": {
        "cwd": REPO_ROOT,
        "cmd": ["node", "scripts/verify.mjs", "fixtures"],
    },
    "python": {
        "cwd": REPO_ROOT,
        "cmd": [sys.executable, "scripts/verify.py", "fixtures"],
    },
}

# `PASS  <path>`, `FAIL  <path>` or `ERROR <path>` opens a per-fixture block.
# ERROR (the verifier raised instead of reaching a verdict) is recorded as its
# own gate status, so it is reported as a divergence, never as a missing fixture.
BLOCK_GATES = ("PASS", "FAIL", "ERROR")
# `observed: ACCEPT` or `observed: REJECT[CATEGORY]`
OBSERVED_RE = re.compile(r"^\s*observed:\s+(ACCEPT|REJECT\[([A-Z_]+)\])")
VERIFIER_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")


def parse_block_line(line: str) -> tuple[str, str] | None:
    """(gate, path) when `line` opens a per-fixture block, else None.

    The path runs to the end of the line, so a checkout path with spaces
    parses. The line is split once, which stays linear in its length: this is
    the output of a command named with `--verifier`, and a pattern that
    retries every split of a long run of spaces takes quadratic time on it."""
    parts = line.split(None, 1)
    if len(parts) < 2 or parts[0] not in BLOCK_GATES or not line.startswith(parts[0]):
        return None
    return parts[0], parts[1].rstrip()


def fixture_key(path_str: str) -> str:
    """Stable per-fixture key: the path relative to the fixtures/ root.

    Verifiers print absolute paths or paths relative to the repository root;
    fixtures are nested (composition/…, levels/…), so basenames alone would
    be ambiguous."""
    marker = "/fixtures/"
    rooted = path_str if path_str.startswith("/") else "/" + path_str
    idx = rooted.rfind(marker)
    if idx >= 0:
        return rooted[idx + len(marker):]
    return Path(path_str).name


def parse_verifier_spec(spec: str) -> tuple[str, list[str]]:
    """argparse type for `--verifier NAME=COMMAND`."""
    name, sep, command = spec.partition("=")
    name = name.strip()
    if not sep or not VERIFIER_NAME_RE.match(name):
        raise argparse.ArgumentTypeError(
            f"expected NAME=COMMAND with NAME of letters, digits, '.', '_' or '-', got {spec!r}"
        )
    try:
        argv = shlex.split(command)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"cannot parse COMMAND in {spec!r}: {exc}") from exc
    if not argv:
        raise argparse.ArgumentTypeError(f"empty COMMAND in {spec!r}")
    return name, argv


def parse_output(stdout: str) -> dict[str, dict]:
    """Parse verifier stdout into {fixture_key: {gate, verdict, category}}.

    Lines are split at line feeds only, as the verifiers write them. A reason
    can quote a fixture value as it is, and str.splitlines() would also break
    a line at a separator in it (U+2028, U+2029), which the verifiers do not
    escape, so the rest of the value would be read as block lines."""
    records: dict[str, dict] = {}
    current: str | None = None
    for line in stdout.split("\n"):
        block = parse_block_line(line)
        if block:
            gate, path = block
            current = fixture_key(path)
            records[current] = {"gate": gate, "verdict": None, "category": None}
            continue
        if current is None:
            continue
        om = OBSERVED_RE.match(line)
        if om:
            if om.group(1) == "ACCEPT":
                records[current]["verdict"] = "ACCEPT"
            else:
                records[current]["verdict"] = "REJECT"
                records[current]["category"] = om.group(2)
    return records


def run_verifier(name: str, spec: dict) -> tuple[int, dict[str, dict]]:
    """Run one verifier; return (exit_code, {fixture_key: record})."""
    try:
        proc = subprocess.run(
            spec["cmd"], cwd=spec["cwd"], capture_output=True, text=True
        )
    except OSError as exc:
        sys.stderr.write(f"[parity] {name} verifier could not start: {exc}\n")
        return 127, {}
    records = parse_output(proc.stdout)
    if proc.returncode != 0:
        sys.stderr.write(f"[parity] {name} verifier exited {proc.returncode}\n")
        sys.stderr.write(proc.stdout[-2000:] + proc.stderr[-2000:] + "\n")
    return proc.returncode, records


JSON_TYPE_NAMES = {
    list: "an array",
    str: "a string",
    bool: "a boolean",
    int: "a number",
    float: "a number",
    type(None): "null",
}


class UnusableExpectedBlock(ValueError):
    """A fixture's `expected` member is present but is not a JSON object."""


def pinned_outcome(path: Path) -> dict | None:
    """The fixture's pinned outcome, read the same way conformance_profile.py
    derives it. None when the fixture is not readable JSON with an `expected`
    block; the verifiers report that fixture as ERROR. Raises
    UnusableExpectedBlock when `expected` is not an object: it pins nothing,
    while a verifier can still report PASS for the fixture."""
    try:
        expected = json.loads(path.read_text())["expected"]
    except (OSError, ValueError, KeyError, TypeError):
        return None
    if not isinstance(expected, dict):
        raise UnusableExpectedBlock(
            f"`expected` is {JSON_TYPE_NAMES[type(expected)]}, not an object, "
            "so the fixture pins no outcome"
        )
    category = expected.get("rejectCategory")
    verdict = "REJECT" if category else expected.get("verifyResult", "ACCEPT")
    return {"verdict": verdict, "category": category}


def outcome_str(record: dict | None) -> str:
    if record is None or record["verdict"] is None:
        return "NONE"
    if record["category"]:
        return f"{record['verdict']}[{record['category']}]"
    return record["verdict"]


def main(prog: str | None = None) -> int:
    """Run the gate with the arguments on the command line; return its exit code.

    `prog` is the program name the usage and error lines give. None leaves
    argparse's default, `parity.py` when this file is run as a script."""
    ap = argparse.ArgumentParser(
        prog=prog,
        description="Run the reference verifiers and any implementation under test over the "
        "fixture set; fail on any disagreement with each other or with the pinned outcomes."
    )
    ap.add_argument("--json", metavar="PATH", help="write a JSON parity report")
    ap.add_argument(
        "--verifier",
        metavar="NAME=COMMAND",
        action="append",
        default=[],
        type=parse_verifier_spec,
        help="add an implementation under test (repeatable). COMMAND runs from the current "
        "directory with the absolute fixtures/ path appended as its last argument and must "
        "print the reference verifier output format (see scripts/README.md)",
    )
    args = ap.parse_args()

    verifiers = dict(VERIFIERS)
    for name, argv in args.verifier:
        if name in verifiers:
            ap.error(f"--verifier: name {name!r} is already in use")
        verifiers[name] = {"cwd": None, "cmd": [*argv, str(FIXTURES_DIR)]}

    fixture_files = sorted(
        p.relative_to(FIXTURES_DIR).as_posix() for p in FIXTURES_DIR.rglob("*.json")
    )
    if not fixture_files:
        sys.stderr.write("[parity] no fixtures found\n")
        return 1
    divergences: list[str] = []
    pinned: dict[str, dict | None] = {}
    for fx in fixture_files:
        try:
            pinned[fx] = pinned_outcome(FIXTURES_DIR / fx)
        except UnusableExpectedBlock as exc:
            pinned[fx] = None
            divergences.append(f"{fx}: {exc}")

    results: dict[str, dict[str, dict]] = {}
    exit_codes: dict[str, int] = {}
    for name, spec in verifiers.items():
        code, records = run_verifier(name, spec)
        exit_codes[name] = code
        results[name] = records

    for name, code in exit_codes.items():
        if code != 0:
            divergences.append(f"{name} verifier exited {code} (expected 0)")

    for name, records in results.items():
        seen = sorted(records)
        if seen != fixture_files:
            missing = set(fixture_files) - set(seen)
            extra = set(seen) - set(fixture_files)
            divergences.append(
                f"{name} fixture set mismatch: missing={sorted(missing)} extra={sorted(extra)}"
            )

    names = list(verifiers)
    table: dict[str, dict] = {}
    for fx in fixture_files:
        row = {n: results[n].get(fx) for n in names}
        table[fx] = row
        present = [n for n in names if row[n] is not None]
        for field in ("gate", "verdict", "category"):
            vals = {n: row[n][field] for n in present}
            if len(set(vals.values())) > 1:
                divergences.append(f"{fx}: {field} divergence {vals}")
        pin = pinned[fx]
        if pin is None:
            continue
        for n in present:
            r = row[n]
            if r["verdict"] != pin["verdict"] or (
                pin["category"] and r["category"] != pin["category"]
            ):
                divergences.append(
                    f"{fx}: {n} observed {outcome_str(r)}, pinned outcome is {outcome_str(pin)}"
                )

    print(f"parity: {len(fixture_files)} fixtures x {len(names)} verifiers")
    for fx, row in table.items():
        cells = []
        for n in names:
            r = row[n]
            if r is None:
                cells.append(f"{n}=MISSING")
            else:
                v = r["verdict"] or "?"
                cat = f"[{r['category']}]" if r["category"] else ""
                cells.append(f"{n}={r['gate']}:{v}{cat}")
        print(f"  {fx:60s} {'  '.join(cells)}")

    if args.json:
        Path(args.json).write_text(
            json.dumps(
                {
                    "fixtures": table,
                    "pinned": {fx: outcome_str(pin) for fx, pin in pinned.items()},
                    "exitCodes": exit_codes,
                    "divergences": divergences,
                    "agree": not divergences,
                },
                indent=2,
                sort_keys=True,
            )
            + "\n"
        )

    if divergences:
        print("\nPARITY: FAIL")
        for d in divergences:
            print(f"  - {d}")
        return 1
    print(
        "\nPARITY: PASS (all implementations agree on gate, verdict, and category, "
        "and match the pinned outcomes)"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
