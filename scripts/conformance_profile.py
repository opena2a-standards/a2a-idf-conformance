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


def fixture_type(rel: Path) -> str:
    top = rel.parts[0]
    return {"composition": "composition", "levels": "level"}.get(top, top)


def build() -> dict:
    requirements = []
    fixtures_root = REPO_ROOT / "fixtures"
    for path in sorted(fixtures_root.rglob("*.json")):
        rel = path.relative_to(fixtures_root)
        fx = json.loads(path.read_text())
        expected = fx["expected"]
        outcome = expected.get("verifyResult", "ACCEPT")
        if expected.get("rejectCategory"):
            outcome = f"REJECT[{expected['rejectCategory']}]"
        requirements.append(
            {
                "fixture": f"fixtures/{rel.as_posix()}",
                "name": fx["name"],
                "fixtureType": fixture_type(rel),
                "level": "MUST",
                "specRefs": fx["spec"],
                "expected": outcome,
                "description": fx["description"],
            }
        )
    profile = dict(SUITE)
    profile["requirements"] = requirements
    return profile


def main() -> int:
    rendered = json.dumps(build(), indent=2, ensure_ascii=False) + "\n"
    if "--check" in sys.argv:
        if not OUT.exists():
            print("conformance.json missing; run scripts/conformance_profile.py")
            return 1
        if OUT.read_text() != rendered:
            print("conformance.json is stale; run scripts/conformance_profile.py")
            return 1
        print("conformance.json is current")
        return 0
    OUT.write_text(rendered)
    print(f"wrote conformance.json ({len(build()['requirements'])} requirements)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
