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
  for (const rel of ["scripts/conformance_profile.py", "README.md", "docs/coverage.md", "COSIGNERS.md", "conformance.json", "fixtures"]) {
    cpSync(join(REPO, rel), join(root, rel), { recursive: true });
  }
  return root;
}

function runIn(root, env, ...args) {
  return spawnSync("python3", [join(root, "scripts", "conformance_profile.py"), ...args], {
    encoding: "utf8",
    env: { ...process.env, ...env },
  });
}

function run(root, ...args) {
  return runIn(root, {}, ...args);
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

// docs/coverage.md states the CTEF layer as not yet composed, in a sentence of
// its own; the edit turns that sentence into a claim that the suite composes it.
test("--check fails when docs/coverage.md says the suite composes with a layer no fixture composes", (t) => {
  const root = scratchCopy(t);
  editFile(root, "docs/coverage.md", (text) =>
    text.replace("is adjacent but not yet composed", "is one the suite composes with"),
  );
  const result = check(root);
  assert.equal(result.status, 1, result.stdout + result.stderr);
  const lines = result.stdout.trim().split("\n");
  assert.equal(lines.length, 1, result.stdout);
  assert.match(
    lines[0],
    /^docs\/coverage\.md:\d+ says the suite composes with the identity claims \(CTEF\) layer \(a2aproject\/A2A#1786\), but no fixture /,
  );
});

// The layer table in docs/coverage.md states this repository's coverage of the
// delegation chain envelope, which notCovered lists.
test("--check fails when docs/coverage.md claims an envelope notCovered lists without \"(unverified)\"", (t) => {
  const root = scratchCopy(t);
  editFile(root, "docs/coverage.md", (text) =>
    text.replace("delegation chain envelope shapes (unverified)", "delegation chain envelope shapes"),
  );
  const result = check(root);
  assert.equal(result.status, 1, result.stdout + result.stderr);
  const lines = result.stdout.trim().split("\n");
  assert.equal(lines.length, 1, result.stdout);
  assert.match(
    lines[0],
    /^docs\/coverage\.md:\d+ claims delegation chain coverage, but notCovered lists '§7 Delegation chains/,
  );
});

// Rewrites a fixture's text by changing its parsed JSON in place.
const editJson = (mutate) => (text) => {
  const fixture = JSON.parse(text);
  mutate(fixture);
  return JSON.stringify(fixture, null, 2) + "\n";
};

// Rewrites a fixture's text by adding a JSON value as the first entry of "spec".
const firstInSpec = (value) => (text) => text.replace('"spec": [', `"spec": [${value}, `);

// A fixture whose "name" holds the byte 0xff, which is not UTF-8 in any position.
const NOT_UTF8 = Buffer.from('{"name": "\xff"}', "latin1");
const NOT_UTF8_ERROR = "'utf-8' codec can't decode byte 0xff in position 10: invalid start byte";

const SCRIPT_LIMIT = "this is a limit of this script, not a JSON error";

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
  ["that is not UTF-8", () => NOT_UTF8, `is not valid JSON (${NOT_UTF8_ERROR})`],
  // Python's json module reads these three as numbers unless told not to.
  ...["NaN", "Infinity", "-Infinity"].map((constant) => [
    `that holds ${constant}`,
    firstInSpec(constant),
    `is not valid JSON (${constant} is not a JSON value)`,
  ]),
  // Valid JSON that the script cannot read, or cannot write to the profile.
  // 4300 digits is Python's default limit on converting an integer.
  [
    "that holds an integer of 5,000 digits",
    (text) => text.replace("{", `{"x": ${"7".repeat(5000)},`),
    `holds an integer of more than 4300 digits, which Python does not convert; ${SCRIPT_LIMIT}`,
  ],
  // In a member the profile does not use: a Python that reads it writes the
  // profile it had, so the test fails without writing a very large file.
  [
    "nested 200,000 deep",
    (text) => text.replace("{", `{"x": ${"[".repeat(200_000)}${"]".repeat(200_000)},`),
    `is nested too deeply for Python's json module to read; ${SCRIPT_LIMIT}`,
  ],
  [
    'with a number too large for a float in "spec"',
    firstInSpec("1e400"),
    `cannot be written to the profile: "spec" or "expected" holds a number too large for a Python float; ${SCRIPT_LIMIT}`,
  ],
  [
    'with a lone surrogate in "name"',
    editJson((fx) => (fx.name = "\ud800")),
    'cannot be written to the profile: "name", "description", "spec" or "expected" holds a lone surrogate (\\ud800), which UTF-8 cannot encode',
  ],
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

// How deep the json module reads and writes differs between Python versions.
// A fixture nested 2,000 deep in "spec" is reported in one line where either
// is too deep, and profiled where neither is. No version ends in a traceback.
test('a fixture nested 2,000 deep in "spec" is reported in one line, or profiled', (t) => {
  const root = scratchCopy(t);
  const rel = "fixtures/levels/level-0-self-asserted.json";
  editFile(root, rel, firstInSpec("[".repeat(2000) + "]".repeat(2000)));
  const profile = readFileSync(join(root, "conformance.json"), "utf8");
  const checked = check(root);
  assert.equal(checked.stderr, "");
  assert.equal(checked.status, 1, checked.stdout);
  const written = run(root);
  assert.equal(written.stderr, "");
  if (written.status === 0) {
    assert.equal(checked.stdout, "conformance.json is stale; run scripts/conformance_profile.py\n");
    assert.match(written.stdout, /^wrote conformance\.json \(\d+ requirements\)\n$/);
    const again = check(root);
    assert.equal(again.status, 0, again.stdout + again.stderr);
    return;
  }
  assert.equal(written.status, 1, written.stdout);
  const cause = `(?:is nested too deeply for Python's json module to read|cannot be written to the profile: "spec" or "expected" is nested too deeply for Python's json module)`;
  assert.match(checked.stdout, new RegExp(`^${rel}: ${cause}; ${SCRIPT_LIMIT}\n$`));
  assert.equal(written.stdout, checked.stdout);
  assert.equal(readFileSync(join(root, "conformance.json"), "utf8"), profile);
});

// The composition claim check reads the `spec` entries of composition fixtures.
test("--check passes over composition fixture spec entries that are not JSON objects", (t) => {
  const root = scratchCopy(t);
  editFile(
    root,
    "fixtures/composition/aim-did-rfc9421/signature-alone.json",
    editJson((fx) => (fx.spec = ["A2A-IDF section 1", null, 7, ["RFC 9421"]])),
  );
  const written = run(root);
  assert.equal(written.status, 0, written.stdout + written.stderr);
  const result = check(root);
  assert.equal(result.stderr, "");
  assert.equal(result.status, 0, result.stdout);
  assert.equal(result.stdout, "conformance.json is current\n");
});

// Fixtures, documents and the profile are UTF-8 whatever the locale. Python
// falls back to its default for a locale the platform does not have, and the
// assertions hold there as well.
for (const [label, locale] of [["an ASCII", "C"], ["an ISO 8859-1", "en_US.ISO8859-1"]]) {
  test(`reads and writes UTF-8 in ${label} locale`, (t) => {
    const env = { LC_ALL: locale, PYTHONUTF8: "0", PYTHONCOERCECLOCALE: "0" };
    const root = scratchCopy(t);
    const profile = readFileSync(join(root, "conformance.json"));
    const current = runIn(root, env, "--check");
    assert.equal(current.status, 0, current.stdout + current.stderr);
    const written = runIn(root, env);
    assert.equal(written.status, 0, written.stdout + written.stderr);
    assert.ok(readFileSync(join(root, "conformance.json")).equals(profile), "regeneration changed conformance.json");

    const rel = "fixtures/levels/level-0-self-asserted.json";
    editFile(root, rel, () => NOT_UTF8);
    for (const args of [["--check"], []]) {
      const result = runIn(root, env, ...args);
      assert.equal(result.status, 1, result.stdout + result.stderr);
      assert.equal(result.stderr, "");
      assert.equal(result.stdout, `${rel}: is not valid JSON (${NOT_UTF8_ERROR})\n`);
      assert.ok(readFileSync(join(root, "conformance.json")).equals(profile), "a failed run changed conformance.json");
    }
  });
}
