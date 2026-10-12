#!/usr/bin/env python3
"""The two reference verifiers must agree on inputs that no fixture pins.

Run from the repository root with the other tooling tests:
    python3 -m unittest discover -s scripts/parity -p 'test_*.py'

Each case is a level fixture written to a temporary directory. Both verifiers
run over that directory once, and each case states the outcome both must
observe. The fixtures under fixtures/ pin what every implementation must do;
these cases keep verify.py in step with verify.mjs on inputs that are not
published as fixtures, either because several spellings exercise one rule or
because not every JSON parser loads the input at all (a lone surrogate).

Needs Node and the Python `cryptography` package, like the parity gate.
"""
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any, NamedTuple

HERE = Path(__file__).resolve().parent
SCRIPTS_DIR = HERE.parent
LEVELS_DIR = SCRIPTS_DIR.parent / "fixtures" / "levels"
sys.path.insert(0, str(HERE))

import parity  # noqa: E402

VERIFIERS = {
    "node": ["node", str(SCRIPTS_DIR / "verify.mjs")],
    "python": [sys.executable, str(SCRIPTS_DIR / "verify.py")],
}


class Case(NamedTuple):
    name: str
    fixture: dict
    observed: str | None  # "ACCEPT" or "REJECT[CATEGORY]"; None for a FAIL at stage schema
    pinned: str | None = None  # written to `expected`; defaults to `observed`
    nested: str | None = None  # JSON text written in place of the string NESTED
    expected: dict | None = None  # written to `expected` as is, in place of `pinned`


# A placeholder for a value too deeply nested for json.dumps to write; the
# Case's `nested` text replaces it in the written fixture.
NESTED = "nested-value-placeholder"

# Deeper than a recursive walk of the attestation reached in either verifier
# (verify.mjs overflowed its call stack at 3,000 levels, verify.py exceeded its
# recursion limit at 900), and deeper than json.loads parses on the CPython
# builds measured (fewer than 1,000 levels on 3.11.14, fewer than 1,500 on
# 3.12.2, fewer than 10,000 on 3.12.12 and 3.13.12, 116,174 on 3.14.3 on macOS,
# where the limit is the C stack), so these cases also hold verify.py to
# reading a fixture without recursion, as JSON.parse in verify.mjs does.
DEPTH = 200_000


def identity_params(fixture: dict) -> dict:
    return fixture["agentCard"]["capabilities"]["extensions"][0]["params"]


def provider_url(url: Any, domain: str = "example.com") -> dict:
    """The valid Level 1 fixture served from `url`, with the attestation domain,
    the agentId domain and the DNS record name all naming `domain`."""
    fixture = json.loads((LEVELS_DIR / "level-1-domain-verified.json").read_text())
    fixture["agentCard"]["provider"]["url"] = url
    params = identity_params(fixture)
    params["agentId"] = f"urn:a2a:agent:{domain}:financial-advisor:v2"
    params["attestations"][0]["domain"] = domain
    fixture["evidence"]["dnsTxt"]["recordName"] = f"_a2a-identity.{domain}"
    return fixture


def attestation_domain(domain: str) -> dict:
    fixture = provider_url("https://example.com")
    identity_params(fixture)["attestations"][0]["domain"] = domain
    return fixture


def organization(**changes: Any) -> dict:
    """The valid Level 2 fixture with members of its attestation replaced or
    added after signing. A key of the form `subject.organization` reaches into
    a nested object."""
    fixture = json.loads((LEVELS_DIR / "level-2-organization-verified.json").read_text())
    attestation = identity_params(fixture)["attestations"][0]
    for key, value in changes.items():
        target = attestation
        *parents, leaf = key.split(".")
        for parent in parents:
            target = target[parent]
        target[leaf] = value
    return fixture


CASES = [
    # In a special scheme a backslash ends the authority, as a slash does.
    Case("backslash-before-at", provider_url("https://evil.example\\@example.com"), "REJECT[DOMAIN_MISMATCH]"),
    Case("backslash-before-at-real-host", provider_url("https://evil.example\\@example.com", "evil.example"), "ACCEPT"),
    Case("backslash-in-host", provider_url("https://exa\\mple.com"), "REJECT[DOMAIN_MISMATCH]"),
    Case("backslash-in-host-real-host", provider_url("https://exa\\mple.com", "exa"), "ACCEPT"),
    Case("backslashes-for-slashes", provider_url("https:\\\\example.com\\card"), "ACCEPT"),
    Case("no-slashes-after-scheme", provider_url("https:example.com"), "ACCEPT"),
    # UTS #46 ignored code points are dropped from a domain.
    Case("soft-hyphen", provider_url("https://exam\u00adple.com"), "ACCEPT"),
    Case("zero-width-space", provider_url("https://exa\u200bmple.com"), "ACCEPT"),
    # A host that ends in a number is an IPv4 address.
    Case("ipv4-hexadecimal", provider_url("https://0x7f.0.0.1", "127.0.0.1"), "ACCEPT"),
    Case("ipv4-two-parts", provider_url("https://127.1", "127.0.0.1"), "ACCEPT"),
    Case("ipv4-one-number", provider_url("https://2130706433", "127.0.0.1"), "ACCEPT"),
    Case("ipv4-octal", provider_url("https://0177.0.0.1", "127.0.0.1"), "ACCEPT"),
    Case("ipv4-as-written", provider_url("https://0x7f.0.0.1", "0x7f.0.0.1"), "REJECT[DOMAIN_MISMATCH]"),
    Case("ipv4-five-parts", provider_url("https://1.2.3.4.5", "1.2.3.4.5"), "REJECT[SHAPE_INVALID]"),
    Case("ipv4-part-out-of-range", provider_url("https://256.0.0.1", "256.0.0.1"), "REJECT[SHAPE_INVALID]"),
    # Port and credentials are not part of the host, and an invalid port fails the URL.
    Case("port", provider_url("https://example.com:8443/card"), "ACCEPT"),
    Case("port-out-of-range", provider_url("https://example.com:99999"), "REJECT[SHAPE_INVALID]"),
    Case("port-not-a-number", provider_url("https://example.com:8o"), "REJECT[SHAPE_INVALID]"),
    # A port may carry leading zeros; only its value must be at most 65535.
    Case("port-zero-padded", provider_url("https://example.com:" + "0" * 4298 + "443"), "ACCEPT"),
    Case(
        "port-zero-padded-out-of-range",
        provider_url("https://example.com:" + "0" * 4300 + "99999"),
        "REJECT[SHAPE_INVALID]",
    ),
    Case("username", provider_url("https://someone@example.com"), "ACCEPT"),
    Case("username-without-host", provider_url("https://someone@"), "REJECT[SHAPE_INVALID]"),
    Case("trailing-dot-is-kept", provider_url("https://example.com."), "REJECT[DOMAIN_MISMATCH]"),
    # Other schemes: an opaque host keeps its case, file://localhost has no host.
    Case("opaque-host-keeps-case", provider_url("a2a://Example.COM", "Example.COM"), "ACCEPT"),
    Case("opaque-host-is-not-lowercased", provider_url("a2a://Example.COM"), "REJECT[DOMAIN_MISMATCH]"),
    Case("file-localhost", provider_url("file://localhost/card", "localhost"), "REJECT[SHAPE_INVALID]"),
    # Input that cannot be a domain.
    Case("lone-surrogate-in-host", provider_url("https://exa\udc00mple.com"), "REJECT[SHAPE_INVALID]"),
    Case("undecodable-percent-byte", provider_url("https://%ff.example"), "REJECT[SHAPE_INVALID]"),
    Case("url-is-an-array", provider_url(["https://example.com"]), "REJECT[SHAPE_INVALID]"),
    # A lone surrogate in the attestation is a shape reject, wherever it sits.
    Case("lone-surrogate-in-string", organization(**{"subject.organization": "Ex\udc00"}), "REJECT[SHAPE_INVALID]"),
    Case("lone-surrogate-in-property-name", organization(**{"note\ud800": "x"}), "REJECT[SHAPE_INVALID]"),
    Case("lone-surrogate-in-array", organization(tags=["a", "b\udfff"]), "REJECT[SHAPE_INVALID]"),
    Case("surrogate-pair-is-well-formed", organization(**{"subject.organization": "Ex\U0001f600"}), "REJECT[SIGNATURE_INVALID]"),
    # A member added after signing is a signature reject at any nesting depth.
    Case(
        "deeply-nested-array-member",
        organization(deep=NESTED),
        "REJECT[SIGNATURE_INVALID]",
        nested="[" * DEPTH + "]" * DEPTH,
    ),
    Case(
        "deeply-nested-object-member",
        organization(deep=NESTED),
        "REJECT[SIGNATURE_INVALID]",
        nested='{"a":' * DEPTH + '"x"' + "}" * DEPTH,
    ),
    Case(
        "lone-surrogate-deeply-nested",
        organization(deep=NESTED),
        "REJECT[SHAPE_INVALID]",
        nested="[" * DEPTH + '"\\udc00"' + "]" * DEPTH,
    ),
    # A schema reason names an array by its JSON type, so a deeply nested
    # expected.verifyResult fails at stage schema in both verifiers.
    Case(
        "deeply-nested-verify-result",
        organization(),
        None,
        nested="[" * DEPTH + "]" * DEPTH,
        expected={"verifyResult": NESTED},
    ),
    # A reject reason that quotes a lone surrogate is still printed as FAIL, not ERROR.
    Case("lone-surrogate-in-reason", attestation_domain("example.com\udc00"), "REJECT[DOMAIN_MISMATCH]", pinned="ACCEPT"),
]


def expected_block(outcome: str) -> dict:
    if outcome == "ACCEPT":
        return {"verifyResult": "ACCEPT"}
    return {"verifyResult": "REJECT", "rejectCategory": outcome[len("REJECT[") : -1]}


def record(case: Case) -> dict:
    if case.observed is None:
        return {"gate": "FAIL", "verdict": None, "category": None}
    block = expected_block(case.observed)
    return {
        "gate": "PASS" if case.pinned in (None, case.observed) else "FAIL",
        "verdict": block["verifyResult"],
        "category": block.get("rejectCategory"),
    }


class VerifierAgreementTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._tmp = tempfile.TemporaryDirectory()
        # parity.fixture_key() keys a path on its last `fixtures` directory.
        root = Path(cls._tmp.name) / "fixtures"
        root.mkdir()
        for case in CASES:
            case.fixture["expected"] = case.expected or expected_block(case.pinned or case.observed)
            text = json.dumps(case.fixture)
            if case.nested is not None:
                text = text.replace(json.dumps(NESTED), case.nested)
            (root / f"{case.name}.json").write_text(text)
        cls.records = {}
        cls.output = {}
        for verifier, command in VERIFIERS.items():
            proc = subprocess.run(
                [*command, str(root)], capture_output=True, encoding="utf-8", errors="replace"
            )
            cls.records[verifier] = parity.parse_output(proc.stdout)
            cls.output[verifier] = proc.stdout + proc.stderr

    @classmethod
    def tearDownClass(cls):
        cls._tmp.cleanup()

    def test_case_names_are_unique(self):
        self.assertEqual(len({case.name for case in CASES}), len(CASES))

    def test_every_case_is_reported_by_both_verifiers(self):
        names = sorted(f"{case.name}.json" for case in CASES)
        for verifier in VERIFIERS:
            with self.subTest(verifier=verifier):
                self.assertEqual(sorted(self.records[verifier]), names, self.output[verifier])

    def test_both_verifiers_observe_the_stated_outcome(self):
        for case in CASES:
            for verifier in VERIFIERS:
                with self.subTest(case=case.name, verifier=verifier):
                    self.assertEqual(self.records[verifier].get(f"{case.name}.json"), record(case))


if __name__ == "__main__":
    unittest.main()
