// Regression tests for `scripts/conformance_profile.py` (`--check`, and
// regeneration where a test says so), run on a scratch copy of the files it
// reads so the committed tree is never modified.
//
// Usage:  node --test scripts/test/*.test.mjs

import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { cpSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const REPO = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..");

function scratchCopy(t) {
  const root = mkdtempSync(join(tmpdir(), "profile-"));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  for (const rel of ["scripts/conformance_profile.py", "README.md", "COSIGNERS.md", "conformance.json", "fixtures"]) {
    cpSync(join(REPO, rel), join(root, rel), { recursive: true });
  }
  return root;
}

function run(root, ...args) {
  return spawnSync("python3", [join(root, "scripts", "conformance_profile.py"), ...args], {
    encoding: "utf8",
  });
}

function check(root) {
  return run(root, "--check");
}

function fixtureCount(root) {
  return JSON.parse(readFileSync(join(root, "conformance.json"), "utf8")).requirements.length;
}

function editFile(root, rel, edit) {
  const path = join(root, rel);
  const before = readFileSync(path, "utf8");
  const after = edit(before);
  assert.notEqual(after, before, `the edit must change ${rel}`);
  writeFileSync(path, after);
}

function editCosigners(root, edit) {
  editFile(root, "COSIGNERS.md", edit);
}

test("--check passes on an unmodified copy", (t) => {
  const result = check(scratchCopy(t));
  assert.equal(result.status, 0, result.stdout + result.stderr);
});

test("--check fails when the COSIGNERS.md baseline count differs from the fixture count", (t) => {
  const root = scratchCopy(t);
  const n = fixtureCount(root);
  editCosigners(root, (text) => text.replaceAll(`${n} at present`, `${n - 1} at present`));
  const result = check(root);
  assert.equal(result.status, 1, result.stdout + result.stderr);
  assert.match(result.stdout, new RegExp(`^COSIGNERS\\.md:\\d+ .*${n - 1}.*${n}`, "m"));
});

test("--check fails when the COSIGNERS.md baseline row does not state the count", (t) => {
  const root = scratchCopy(t);
  const n = fixtureCount(root);
  editCosigners(root, (text) => text.replaceAll(`; ${n} at present`, ""));
  const result = check(root);
  assert.equal(result.status, 1, result.stdout + result.stderr);
  assert.match(result.stdout, /^COSIGNERS\.md:\d+ /m);
});

// The edited sentence already names the wire signature and delegation layers,
// which fixtures compose, so the one line reported is the layer that none does.
test("--check fails when README.md says the suite composes with a layer no fixture composes", (t) => {
  const root = scratchCopy(t);
  editFile(root, "README.md", (text) =>
    text.replace("composes with ", "composes with the identity-claim envelope layer (#1786 CTEF) and "),
  );
  const result = check(root);
  assert.equal(result.status, 1, result.stdout + result.stderr);
  const lines = result.stdout.trim().split("\n");
  assert.equal(lines.length, 1, result.stdout);
  assert.match(
    lines[0],
    /^README\.md:\d+ says the suite composes with the identity claims \(CTEF\) layer \(a2aproject\/A2A#1786\), but no fixture /,
  );
});

// Rewrites a fixture's text by changing its parsed JSON in place.
const editJson = (mutate) => (text) => {
  const fixture = JSON.parse(text);
  mutate(fixture);
  return JSON.stringify(fixture, null, 2) + "\n";
};

// Each case rewrites one fixture and names the line the profile must print for it.
const FIELD_CASES = [
  ...["name", "description", "spec", "expected"].map((field) => [
    `without "${field}"`,
    editJson((fx) => delete fx[field]),
    `missing required field "${field}"`,
  ]),
  [
    "without several required fields",
    editJson((fx) => {
      delete fx.name;
      delete fx.expected;
    }),
    'missing required fields "name", "expected"',
  ],
  ['with "expected": null', editJson((fx) => (fx.expected = null)), 'required field "expected" is not a JSON object'],
  ['with "description": []', editJson((fx) => (fx.description = [])), 'required field "description" is not a string'],
  [
    "with several required fields of the wrong type",
    editJson((fx) => {
      fx.name = 7;
      fx.spec = "A2A-IDF §1";
    }),
    'required field "name" is not a string; required field "spec" is not a JSON array',
  ],
  [
    "with a missing field and a field of the wrong type",
    editJson((fx) => {
      delete fx.name;
      fx.spec = {};
    }),
    'missing required field "name"; required field "spec" is not a JSON array',
  ],
  ["that is not a JSON object", (text) => `[${text.trimEnd()}]\n`, "is not a JSON object"],
  ["that is not valid JSON", () => '{"name": ', "is not valid JSON (Expecting value: line 1 column 10 (char 9))"],
];

for (const [label, args] of [["--check", ["--check"]], ["regeneration", []]]) {
  for (const [fixtureLabel, edit, message] of FIELD_CASES) {
    test(`${label} names a fixture ${fixtureLabel} in one line`, (t) => {
      const root = scratchCopy(t);
      const rel = "fixtures/levels/level-0-self-asserted.json";
      editFile(root, rel, edit);
      const profile = readFileSync(join(root, "conformance.json"), "utf8");
      const result = run(root, ...args);
      assert.equal(result.status, 1, result.stdout + result.stderr);
      assert.equal(result.stderr, "");
      assert.equal(result.stdout, `${rel}: ${message}\n`);
      assert.equal(readFileSync(join(root, "conformance.json"), "utf8"), profile);
    });
  }
}
