// Regression tests for the two reference verifiers on fixture variants that
// cannot live under fixtures/ (a malformed fixture fails the suite run). Each
// variant is a copy of a committed fixture, mutated and written to a scratch
// directory. The Python verifier needs the `cryptography` package.
//
// Usage:  node --test scripts/test/*.test.mjs

import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const REPO = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..");
const VERIFIERS = {
  node: [process.execPath, join(REPO, "scripts", "verify.mjs")],
  python: ["python3", join(REPO, "scripts", "verify.py")],
};

function writeVariant(t, source, mutate) {
  const dir = mkdtempSync(join(tmpdir(), "verify-"));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const fixture = JSON.parse(readFileSync(join(REPO, source), "utf8"));
  mutate(fixture);
  const path = join(dir, "variant.json");
  writeFileSync(path, JSON.stringify(fixture, null, 2) + "\n");
  return path;
}

function runVerifier([command, ...args], path) {
  return spawnSync(command, [...args, path], { encoding: "utf8" });
}

// A copy of the cross-suite-mismatch fixture that pins ACCEPT, so a verifier
// that skips the crossSuiteEquivalence block passes it.
function writeAcceptVariant(t, mutate) {
  return writeVariant(t, "fixtures/composition/aim-did-rfc9421/cross-suite-mismatch.json", (fx) => {
    mutate(fx);
    fx.expected.verifyResult = "ACCEPT";
    delete fx.expected.rejectCategory;
  });
}

for (const [label, pin] of [["no", undefined], ["an empty", ""], ["a non-string", 5]]) {
  test(`byteIdentical: true with ${label} expectedSignatureBase64 is a fixture error`, (t) => {
    const path = writeAcceptVariant(t, (fx) => {
      if (pin === undefined) delete fx.crossSuiteEquivalence.envoys.expectedSignatureBase64;
      else fx.crossSuiteEquivalence.envoys.expectedSignatureBase64 = pin;
    });
    for (const [name, argv] of Object.entries(VERIFIERS)) {
      const result = runVerifier(argv, path);
      assert.equal(result.status, 1, `${name}: ${result.stdout}${result.stderr}`);
      assert.match(result.stdout, /^FAIL {2}/m, name);
      assert.match(result.stdout, /stage: +cross-suite-equivalence/, name);
      assert.match(result.stdout, /reason: .*expectedSignatureBase64 is missing, empty or not a string$/m, name);
      assert.doesNotMatch(result.stdout, /observed: ACCEPT/, name);
    }
  });
}

// A block that is present but is not a JSON object must not be read as an
// absent one. The two verifiers print the same lines; only the path on the
// first line differs, because each resolves it in its own way.
for (const [label, field, mutate] of [
  ["a string envoys", "crossSuiteEquivalence.envoys", (fx) => (fx.crossSuiteEquivalence.envoys = "not-an-object")],
  ["an array envoys", "crossSuiteEquivalence.envoys", (fx) => (fx.crossSuiteEquivalence.envoys = [{ byteIdentical: true }])],
  ["a null envoys", "crossSuiteEquivalence.envoys", (fx) => (fx.crossSuiteEquivalence.envoys = null)],
  ["a string crossSuiteEquivalence", "crossSuiteEquivalence", (fx) => (fx.crossSuiteEquivalence = "not-an-object")],
  ["an array crossSuiteEquivalence", "crossSuiteEquivalence", (fx) => (fx.crossSuiteEquivalence = [{ envoys: {} }])],
  ["a null crossSuiteEquivalence", "crossSuiteEquivalence", (fx) => (fx.crossSuiteEquivalence = null)],
  // The schema check runs before any other check: with the body tampered as
  // well, the content-digest check would otherwise fail first.
  [
    "a null envoys and a tampered body",
    "crossSuiteEquivalence.envoys",
    (fx) => {
      fx.crossSuiteEquivalence.envoys = null;
      fx.input.body = `${fx.input.body ?? ""}tampered`;
    },
  ],
]) {
  test(`${label} fails at the schema stage in both verifiers`, (t) => {
    const path = writeAcceptVariant(t, mutate);
    const outcomes = {};
    for (const [name, argv] of Object.entries(VERIFIERS)) {
      const result = runVerifier(argv, path);
      assert.equal(result.status, 1, `${name}: ${result.stdout}${result.stderr}`);
      outcomes[name] = result.stdout.replace(/^(\w+) .*$/m, "$1");
    }
    assert.equal(
      outcomes.node,
      ["FAIL", "      stage:  schema", `      reason: ${field} is present but is not a JSON object`, "summary: 0 pass, 1 fail (1 fixtures)", ""].join("\n"),
    );
    assert.equal(outcomes.python, outcomes.node);
  });
}

// A fixture path that does not exist is an ERROR fixture with a summary line,
// not an uncaught exception. The message wording is each runtime's own.
test("a fixture path that does not exist is reported as ERROR by both verifiers", (t) => {
  const dir = mkdtempSync(join(tmpdir(), "verify-"));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const path = join(dir, "missing.json");
  for (const [name, argv] of Object.entries(VERIFIERS)) {
    const result = runVerifier(argv, path);
    assert.equal(result.status, 1, `${name}: ${result.stdout}${result.stderr}`);
    assert.equal(result.stderr, "", name);
    const lines = result.stdout.split("\n");
    assert.match(lines[0], /^ERROR .*missing\.json$/, name);
    assert.match(lines[1], /^ {6}.*no such file or directory.*missing\.json/i, name);
    assert.deepEqual(lines.slice(2), ["summary: 0 pass, 1 fail (1 fixtures)", ""], name);
  }
});
