#!/usr/bin/env python3
"""Generate (or verify) the machine-readable conformance profile.

`conformance.json` maps every requirement this suite tests to the fixture
that tests it and the pinned expected outcome. The requirement entries are
DERIVED from the fixtures themselves (each fixture carries its spec
references and expected block), so the profile cannot drift from the fixture
set: regeneration is deterministic and CI verifies the committed file matches.

Usage:
    python3 scripts/conformance_profile.py            # (re)write conformance.json
    python3 scripts/conformance_profile.py --check    # exit 1 if committed file is stale
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
OUT = REPO_ROOT / "conformance.json"

# --- suite metadata (hand-maintained; everything under `requirements` is derived) ---
SUITE = {
    "$schema": "https://specs.opena2a.org/schemas/conformance-profile-v1.json",
    "suite": "a2a-idf-conformance",
    "spec": {
        "id": "A2A-IDF",
        "name": "Agent-to-Agent Identity Framework",
        "version": "1.0.0-draft",
        "ref": "https://github.com/a2aproject/A2A/pull/1496",
    },
    "fixtureManifest": "MANIFEST.sha256",
    "verifiers": [
        {
            "language": "node",
            "path": "scripts/verify.mjs",
            "coverage": "full: composition (RFC 9421 wire layer + §6 dual-shape keyid resolution) and levels (§1 SELF_ASSERTED / DOMAIN_VERIFIED / ORGANIZATION_VERIFIED)",
        },
        {
            "language": "python",
            "path": "scripts/verify.py",
            "coverage": "full: same fixture families and check order as the Node verifier",
        },
    ],
    "notCovered": [
        {
            "specSection": "§1 DNS Verification — live DNS resolution and DNSSEC validation",
            "reason": "fixtures pin the TXT record content; live resolution is deployment behavior, not byte-stable",
        },
        {
            "specSection": "§7 Delegation chains — per-link signatures and chain-rule enforcement",
            "reason": "envelope shapes pinned in fixtures; deeper verification lands once APS delegation schemas stabilize",
        },
        {
            "specSection": "§8 Bilateral receipts — responder signature over the JCS receipt payload",
            "reason": "same APS schema-stability dependency as delegation chains",
        },
        {
            "specSection": "v1.1 Vouching attestations",
            "reason": "spec cycle not started; fixture shape depends on the CTEF envelope decision",
        },
        {
            "specSection": "v1.2 Revocation log",
            "reason": "byte-stability requires pinned tree-state fixtures; deferred with the spec cycle",
        },
    ],
}


# Coverage claims in README.md and docs/coverage.md must not outrun
# `notCovered`. While one of these sections is listed there, any line of those
# documents that states this repository's coverage and names the envelope must
# mark it "(unverified)". Removing the notCovered entry (once the verifiers
# check the envelope) lifts the requirement.
UNVERIFIED_ENVELOPES = {
    "§7 Delegation chains": "delegation chain",
    "§8 Bilateral receipts": "bilateral receipt",
}
README_CLAIM_DOCS = ("README.md", "docs/coverage.md")
README_CLAIM_MARKERS = ("it covers", "this repo")


def readme_claim_errors() -> list[str]:
    open_sections = [entry["specSection"] for entry in SUITE["notCovered"]]
    errors = []
    for doc in README_CLAIM_DOCS:
        lines = (REPO_ROOT / doc).read_text(encoding="utf-8").splitlines()
        for section, term in UNVERIFIED_ENVELOPES.items():
            if not any(s.startswith(section) for s in open_sections):
                continue
            for number, line in enumerate(lines, start=1):
                low = line.lower()
                if not any(marker in low for marker in README_CLAIM_MARKERS):
                    continue
                if term in low and "(unverified)" not in low:
                    errors.append(
                        f"{doc}:{number} claims {term} coverage, but notCovered lists "
                        f"'{section}'; mark it \"(unverified)\""
                    )
    return errors


# Composition claims must not outrun the fixtures. An adjacent layer counts as
# composed once a fixture under fixtures/composition/ carries a `spec` entry
# for it: the layer's a2aproject/A2A issue as `ref`, or one of the ids below.
# Until then, a sentence in these documents that says the suite composes with
# adjacent layers must not name the layer; state it in a sentence of its own
# as not yet composed.
A2A_ISSUE = "https://github.com/a2aproject/A2A/issues/"
ADJACENT_LAYERS = {
    # issue: (layer, fixture spec ids, pattern that names the layer in prose)
    "1829": ("wire signature", ("RFC 9421", "Envoys signature/v1"), r"wire[- ]signature"),
    "1786": ("identity claims (CTEF)", ("CTEF",), r"ctef|identity[- ]claims?"),
    "1575": ("delegation and continuity (APS)", ("APS",), r"aps|delegation(?:/| and )continuity"),
}
COMPOSITION_CLAIM_DOCS = ("README.md", "docs/coverage.md", "fixtures/composition/README.md")
COMPOSITION_CLAIM_MARKERS = ("composes with", "in combination with")


def composed_layers(requirements: list[dict]) -> set[str]:
    """The adjacent layers the composition fixtures compose, read from the
    requirement entries built from them, so each fixture is parsed once."""
    composed = set()
    for requirement in requirements:
        if requirement["fixtureType"] != "composition":
            continue
        for entry in requirement["specRefs"]:
            # A spec entry that is not a JSON object names no layer.
            if not isinstance(entry, dict):
                continue
            for issue, (_, spec_ids, _) in ADJACENT_LAYERS.items():
                if entry.get("ref") == A2A_ISSUE + issue or entry.get("id") in spec_ids:
                    composed.add(issue)
    return composed


def composition_claim_errors(requirements: list[dict]) -> list[str]:
    composed = composed_layers(requirements)
    errors = []
    for doc in COMPOSITION_CLAIM_DOCS:
        lines = (REPO_ROOT / doc).read_text(encoding="utf-8").splitlines()
        for number, line in enumerate(lines, start=1):
            for sentence in re.split(r"(?<=[.!?])\s+", line.lower()):
                if not any(marker in sentence for marker in COMPOSITION_CLAIM_MARKERS):
                    continue
                for issue, (layer, _, pattern) in ADJACENT_LAYERS.items():
                    if issue in composed:
                        continue
                    if re.search(rf"#{issue}\b|\b(?:{pattern})\b", sentence):
                        errors.append(
                            f"{doc}:{number} says the suite composes with the {layer} layer "
                            f"(a2aproject/A2A#{issue}), but no fixture under fixtures/composition/ "
                            f"carries a spec entry for it; state the layer as not yet composed"
                        )
    return errors


# The CI baseline row in COSIGNERS.md states the verifier summary as the fixture
# count at the current commit ("N at present", once per verifier cell). It must
# equal the number of fixtures, so adding a fixture cannot leave it stale.
COSIGNERS_BASELINE_ROW = "| opena2a-org (self-cosigned baseline, CI) |"
AT_PRESENT = re.compile(r"\b(\d+) at present\b")


def cosigners_baseline_errors(fixture_count: int) -> list[str]:
    lines = (REPO_ROOT / "COSIGNERS.md").read_text(encoding="utf-8").splitlines()
    rows = [(n, line) for n, line in enumerate(lines, start=1) if line.startswith(COSIGNERS_BASELINE_ROW)]
    if len(rows) != 1:
        return [f"COSIGNERS.md: expected one baseline row starting '{COSIGNERS_BASELINE_ROW}', found {len(rows)}"]
    number, line = rows[0]
    counts = [int(c) for c in AT_PRESENT.findall(line)]
    if len(counts) != 2:
        return [
            f"COSIGNERS.md:{number} baseline row must state the fixture count as "
            f"\"{fixture_count} at present\" in both verifier cells"
        ]
    return [
        f"COSIGNERS.md:{number} baseline row states {count} at present, but fixtures/ "
        f"holds {fixture_count} fixtures; update the row"
        for count in counts
        if count != fixture_count
    ]


def fixture_type(rel: Path) -> str:
    top = rel.parts[0]
    return {"composition": "composition", "levels": "level"}.get(top, top)


# Every requirement entry is derived from these fixture fields, so a fixture
# without one, or with one of another JSON type, cannot be profiled.
REQUIRED_FIXTURE_FIELDS = {
    "name": (str, "a string"),
    "description": (str, "a string"),
    "spec": (list, "a JSON array"),
    "expected": (dict, "a JSON object"),
}


class FixtureError(Exception):
    """A fixture cannot be profiled; one line per fixture. It is not valid JSON
    (bytes that are not UTF-8, a syntax error, or one of the constants NaN,
    Infinity and -Infinity, which the json module accepts unless told not to),
    is past a limit of this script (nesting too deep for the json module, an
    integer of more digits than Python converts), is not a JSON object, lacks a
    field the profile is derived from or has one of the wrong type, or holds a
    value in such a field that cannot be written to the profile."""


def reject_constant(name: str) -> None:
    raise FixtureError(f"is not valid JSON ({name} is not a JSON value)")


def parse_int(digits: str) -> int:
    try:
        return int(digits)
    except ValueError:
        # The only way the digits of a JSON integer fail to convert.
        raise FixtureError(
            f"holds an integer of more than {sys.get_int_max_str_digits()} digits, which Python "
            "does not convert; this is a limit of this script, not a JSON error"
        ) from None


def read_fixture(path: Path) -> object:
    try:
        return json.loads(
            path.read_text(encoding="utf-8"), parse_constant=reject_constant, parse_int=parse_int
        )
    except ValueError as err:
        # JSONDecodeError, or UnicodeDecodeError for bytes that are not UTF-8.
        raise FixtureError(f"is not valid JSON ({err})") from None
    except RecursionError:
        raise FixtureError(
            "is nested too deeply for Python's json module to read; this is a limit of this "
            "script, not a JSON error"
        ) from None


def encode(value: object) -> bytes:
    """`value` as the bytes conformance.json holds for it. Raises instead of
    writing text that is not JSON (a float that is not finite) or not UTF-8."""
    return (json.dumps(value, indent=2, ensure_ascii=False, allow_nan=False) + "\n").encode("utf-8")


def fixture_field_error(fx: object) -> str | None:
    """The one-line reason a fixture cannot be profiled, or None: every missing
    field and every field of the wrong type, so one run names them all."""
    if not isinstance(fx, dict):
        return "is not a JSON object"
    missing = [f'"{field}"' for field in REQUIRED_FIXTURE_FIELDS if field not in fx]
    problems = []
    if missing:
        problems.append(f"missing required field{'s' if len(missing) > 1 else ''} " + ", ".join(missing))
    problems += [
        f'required field "{field}" is not {label}'
        for field, (kind, label) in REQUIRED_FIXTURE_FIELDS.items()
        if field in fx and not isinstance(fx[field], kind)
    ]
    return "; ".join(problems) or None


def requirement_entry(rel: Path, fx: dict) -> dict:
    """The requirement entry derived from one fixture, known to be writable."""
    try:
        expected = fx["expected"]
        outcome = expected.get("verifyResult", "ACCEPT")
        if expected.get("rejectCategory"):
            outcome = f"REJECT[{expected['rejectCategory']}]"
        entry = {
            "fixture": f"fixtures/{rel.as_posix()}",
            "name": fx["name"],
            "fixtureType": fixture_type(rel),
            "level": "MUST",
            "specRefs": fx["spec"],
            "expected": outcome,
            "description": fx["description"],
        }
        # Encoded as deeply nested as it is in the profile, so an entry that
        # encodes here encodes there, and a failure names its fixture.
        encode({"requirements": [entry]})
    except RecursionError:
        raise FixtureError(
            'cannot be written to the profile: "spec" or "expected" is nested too deeply for '
            "Python's json module; this is a limit of this script, not a JSON error"
        ) from None
    except UnicodeEncodeError as err:
        raise FixtureError(
            'cannot be written to the profile: "name", "description", "spec" or "expected" holds '
            f"a lone surrogate (\\u{ord(err.object[err.start]):04x}), which UTF-8 cannot encode"
        ) from None
    except ValueError:
        raise FixtureError(
            'cannot be written to the profile: "spec" or "expected" holds a number too large for '
            "a Python float; this is a limit of this script, not a JSON error"
        ) from None
    return entry


def build() -> dict:
    requirements = []
    errors = []
    fixtures_root = REPO_ROOT / "fixtures"
    for path in sorted(fixtures_root.rglob("*.json")):
        rel = path.relative_to(fixtures_root)
        try:
            fx = read_fixture(path)
            error = fixture_field_error(fx)
            if error is not None:
                raise FixtureError(error)
            requirements.append(requirement_entry(rel, fx))
        except FixtureError as err:
            errors.append(f"fixtures/{rel.as_posix()}: {err}")
    if errors:
        raise FixtureError("\n".join(errors))
    profile = dict(SUITE)
    profile["requirements"] = requirements
    return profile


def main() -> int:
    try:
        profile = build()
    except FixtureError as err:
        print(err)
        return 1
    # The whole profile is encoded before conformance.json is opened, so a
    # profile that cannot be encoded leaves the file as it was.
    rendered = encode(profile)
    if "--check" in sys.argv:
        if not OUT.exists():
            print("conformance.json missing; run scripts/conformance_profile.py")
            return 1
        # Bytes, not text in the locale's encoding. A checkout that converts
        # line endings to CRLF is still current.
        if OUT.read_bytes().replace(b"\r\n", b"\n") != rendered:
            print("conformance.json is stale; run scripts/conformance_profile.py")
            return 1
        errors = (
            readme_claim_errors()
            + composition_claim_errors(profile["requirements"])
            + cosigners_baseline_errors(len(profile["requirements"]))
        )
        if errors:
            print("\n".join(errors))
            return 1
        print("conformance.json is current")
        return 0
    OUT.write_bytes(rendered)
    print(f"wrote conformance.json ({len(profile['requirements'])} requirements)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
