#!/usr/bin/env python3
"""Both reference verifiers enforce the committed fixture schemas.

Each case copies a committed fixture into a temporary directory and removes
or alters one field. Both verifiers then run once over that directory. A case
passes when each verifier reports FAIL at stage `schema` with a reason that
names the field. Unmodified copies of the same fixtures are controls and must
PASS, so a failure can only come from the mutation.

Usage:  python3 -m unittest discover -s scripts/parity -p 'test_*.py'
Needs `node` on PATH and the `cryptography` package (for verify.py). When the
`jsonschema` package is installed, every case is also checked against the
committed schemas with a full Draft 2020-12 validator.
"""
from __future__ import annotations

import copy
import json
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
FIXTURES = REPO_ROOT / "fixtures"
SCHEMAS = REPO_ROOT / "schemas"

COMPOSITION = "composition/aim-did-rfc9421/signature-alone.json"
COMPOSITION_COMPACT = "composition/hippo-rfc9421/signature-alone-tag.json"
COMPOSITION_REJECT = "composition/aim-did-rfc9421/signature-tampered.json"
COMPOSITION_TAG_NULL = "composition/aim-did-rfc9421/signature-tag-null.json"
COMPOSITION_TAG_FOREIGN = "composition/aim-did-rfc9421/signature-tag-foreign.json"
LEVEL = "levels/level-1-domain-verified.json"
LEVEL_REJECT = "levels/level-1-kid-mismatch.json"

# The keywords both verifiers implement. A schema keyword outside this set
# (or the annotations) would be documented but silently unenforced.
ENFORCED_KEYWORDS = {"type", "const", "enum", "required", "properties", "allOf", "if", "then"}
ANNOTATION_KEYWORDS = {"$schema", "$id", "title", "description", "default"}


def _missing(base: str, field: str) -> tuple[str, list, str]:
    return base, [("del", field)], f"missing required field {field}"


# (base fixture, mutations, substring the verifier's reason must contain)
CASES: list[tuple[str, list, str]] = [
    # Required fields marked "yes" in fixtures/composition/SCHEMA.md, plus the
    # top-level members its shape lists without "optional".
    *[
        _missing(COMPOSITION, f)
        for f in (
            "$schema",
            "name",
            "description",
            "spec",
            "input",
            "signatureParams",
            "keyidResolution",
            "expected",
            "input.method",
            "input.path",
            "input.body",
            "signatureParams.components",
            "signatureParams.keyid",
            "signatureParams.created",
            "signatureParams.nonce",
            "keyidResolution.shape",
            "keyidResolution.document",
            "expected.contentDigest",
            "expected.signatureBase",
            "expected.signatureInput",
            "expected.signature",
            "expected.signatureBase64",
        )
    ],
    _missing(COMPOSITION_COMPACT, "keyidResolution.publicKeyPem"),
    _missing(COMPOSITION_COMPACT, "expected.signatureBase64"),
    _missing(COMPOSITION_REJECT, "expected.rejectCategory"),
    # The reproduction from the issue: five required fields removed at once.
    (
        COMPOSITION_COMPACT,
        [("del", f) for f in ("$schema", "name", "description", "spec", "expected.signatureBase64")],
        "missing required field $schema",
    ),
    (
        COMPOSITION,
        [("set", "signatureParams.created", "1714000000")],
        "signatureParams.created is present but is not a JSON integer",
    ),
    # A null tag is an absent tag (SCHEMA.md); any other non-string is not.
    (
        COMPOSITION_TAG_NULL,
        [("set", "signatureParams.tag", 7)],
        "signatureParams.tag is present but is not a JSON string or null",
    ),
    (
        COMPOSITION_TAG_FOREIGN,
        [("set", "expected.rejectCategory", "TAG_INVALID")],
        'expected.rejectCategory: "TAG_INVALID" is not one of',
    ),
    (
        COMPOSITION,
        [("set", "crossSuiteEquivalence", None)],
        "crossSuiteEquivalence is present but is not a JSON object",
    ),
    (
        COMPOSITION,
        [("set", "crossSuiteEquivalence.envoys", [])],
        "crossSuiteEquivalence.envoys is present but is not a JSON object",
    ),
    (COMPOSITION, [("set", "keyidResolution.shape", "keypair")], 'keyidResolution.shape: "keypair" is not one of'),
    (COMPOSITION, [("set", "expected.verifyResult", "MAYBE")], 'expected.verifyResult: "MAYBE" is not one of'),
    (COMPOSITION, [("set", "$schema", "https://example.invalid/fixture.json")], "$schema: expected"),
    # Level fixtures: the envelope is checked, the agentCard under evaluation is not.
    *[
        _missing(LEVEL, f)
        for f in ("$schema", "name", "description", "spec", "level", "agentCard", "expected")
    ],
    _missing(LEVEL_REJECT, "expected.rejectCategory"),
    (LEVEL, [("set", "level", 3)], "level: 3 is not one of"),
    (LEVEL, [("set", "level", True)], "level is present but is not a JSON integer"),
    (LEVEL, [("set", "$schema", "https://example.invalid/fixture.json")], "$schema: expected"),
    # An array or an object is named by its JSON type, in the same words in both verifiers.
    (
        LEVEL,
        [("set", "expected.verifyResult", ["ACCEPT"])],
        'expected.verifyResult: a JSON array is not one of "ACCEPT", "REJECT"',
    ),
    (
        LEVEL,
        [("set", "$schema", {"$id": "https://a2a-idf.opena2a.org/schemas/fixture-level-v1.json"})],
        '$schema: expected "https://a2a-idf.opena2a.org/schemas/fixture-level-v1.json", got a JSON object',
    ),
]

CONTROLS = sorted({base for base, _, _ in CASES})

BLOCK_RE = re.compile(r"^(PASS|FAIL|ERROR)\s+(.+)$")


def _mutate(fixture: dict, mutations: list) -> dict:
    out = copy.deepcopy(fixture)
    for op, dotted, *value in mutations:
        *parents, leaf = dotted.split(".")
        target = out
        for key in parents:
            target = target[key]
        if op == "del":
            del target[leaf]
        else:
            target[leaf] = value[0]
    return out


def _run(cmd: list[str], directory: Path) -> dict[str, dict]:
    proc = subprocess.run([*cmd, str(directory)], cwd=REPO_ROOT, capture_output=True, text=True)
    results: dict[str, dict] = {}
    current = None
    for line in proc.stdout.splitlines():
        m = BLOCK_RE.match(line)
        if m:
            current = Path(m.group(2)).name
            results[current] = {"status": m.group(1), "stage": None, "reason": None}
            continue
        stripped = line.strip()
        if current is not None and stripped.startswith("stage:"):
            results[current]["stage"] = stripped[len("stage:"):].strip()
        elif current is not None and stripped.startswith("reason:"):
            results[current]["reason"] = stripped[len("reason:"):].strip()
    return results


def _case_file(index: int, mutations: list) -> str:
    slug = re.sub(r"[^A-Za-z0-9.-]+", "-", "-".join(f"{op}-{path}" for op, path, *_ in mutations))
    return f"case-{index:02d}-{slug.strip('-')}.json"


def _control_file(base: str) -> str:
    return "control-" + base.replace("/", "-")


class FixtureSchemaTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls._tmp = tempfile.TemporaryDirectory()
        directory = Path(cls._tmp.name)
        cls.documents: dict[str, tuple[str, dict]] = {}
        for base in CONTROLS:
            fixture = json.loads((FIXTURES / base).read_text(encoding="utf-8"))
            cls.documents[_control_file(base)] = (base, fixture)
        for index, (base, mutations, _) in enumerate(CASES):
            fixture = json.loads((FIXTURES / base).read_text(encoding="utf-8"))
            cls.documents[_case_file(index, mutations)] = (base, _mutate(fixture, mutations))
        for name, (_, document) in cls.documents.items():
            (directory / name).write_text(json.dumps(document, indent=2), encoding="utf-8")
        cls.results = {
            "node": _run(["node", "scripts/verify.mjs"], directory),
            "python": _run([sys.executable, "scripts/verify.py"], directory),
        }

    @classmethod
    def tearDownClass(cls) -> None:
        cls._tmp.cleanup()

    def test_controls_pass(self) -> None:
        for verifier, results in self.results.items():
            for base in CONTROLS:
                with self.subTest(verifier=verifier, fixture=base):
                    self.assertEqual(results.get(_control_file(base), {}).get("status"), "PASS")

    def test_schema_violations_fail_at_schema_stage(self) -> None:
        for verifier, results in self.results.items():
            for index, (base, mutations, reason) in enumerate(CASES):
                name = _case_file(index, mutations)
                with self.subTest(verifier=verifier, case=name):
                    got = results.get(name)
                    self.assertIsNotNone(got, f"{verifier} did not report {name}")
                    self.assertEqual(got["status"], "FAIL", got)
                    self.assertEqual(got["stage"], "schema", got)
                    self.assertIn(reason, got["reason"] or "")

    def test_schemas_use_only_enforced_keywords(self) -> None:
        def walk(node: dict, where: str) -> None:
            unknown = set(node) - ENFORCED_KEYWORDS - ANNOTATION_KEYWORDS
            self.assertEqual(unknown, set(), f"{where} uses keywords the verifiers do not enforce")
            for key, sub in node.get("properties", {}).items():
                walk(sub, f"{where}.properties.{key}")
            for i, sub in enumerate(node.get("allOf", [])):
                walk(sub, f"{where}.allOf[{i}]")
            for key in ("if", "then"):
                if key in node:
                    walk(node[key], f"{where}.{key}")

        for path in sorted(SCHEMAS.glob("*.json")):
            walk(json.loads(path.read_text(encoding="utf-8")), path.name)

    def test_every_fixture_names_a_committed_schema(self) -> None:
        ids = {
            json.loads(p.read_text(encoding="utf-8"))["$id"] for p in SCHEMAS.glob("*.json")
        }
        for path in sorted(FIXTURES.rglob("*.json")):
            with self.subTest(fixture=str(path.relative_to(FIXTURES))):
                self.assertIn(json.loads(path.read_text(encoding="utf-8")).get("$schema"), ids)

    def test_full_validator_agrees(self) -> None:
        try:
            import jsonschema
        except ImportError:
            self.skipTest("jsonschema is not installed")
        by_family = {}
        for p in SCHEMAS.glob("*.json"):
            schema = json.loads(p.read_text(encoding="utf-8"))
            jsonschema.Draft202012Validator.check_schema(schema)
            by_family[schema["$id"]] = jsonschema.Draft202012Validator(schema)
        for name, (base, document) in self.documents.items():
            base_schema = json.loads((FIXTURES / base).read_text(encoding="utf-8"))["$schema"]
            errors = list(by_family[base_schema].iter_errors(document))
            with self.subTest(document=name):
                if name.startswith("control-"):
                    self.assertEqual(errors, [])
                else:
                    self.assertNotEqual(errors, [])


if __name__ == "__main__":
    unittest.main()
