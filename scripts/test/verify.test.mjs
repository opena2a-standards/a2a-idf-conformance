// Regression tests for the two reference verifiers on fixture variants that
// cannot live under fixtures/ (a malformed fixture fails the suite run). Each
// variant is a copy of a committed fixture, mutated and written to a scratch
// directory. The Python verifier needs the `cryptography` package.
//
// Usage:  node --test scripts/test/*.test.mjs

import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import {
  chmodSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  realpathSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
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

// A path that cannot be stat'ed or read, or a directory that cannot be listed,
// is an ERROR entry whose message names it, and the run goes on to the summary
// line: never an uncaught exception, and never a run that skips the entry and
// exits 0. `errors` lists each expected ERROR entry as [path, message pattern].
const SYMLINK_LOOP = /too many (levels of )?symbolic links/i;
const NO_PERMISSION = /permission denied/i;

function assertErrorEntries(name, result, dir, errors, summary) {
  assert.equal(result.status, 1, `${name}: ${result.stdout}${result.stderr}`);
  assert.equal(result.stderr, "", name);
  const lines = result.stdout.split("\n");
  for (const [path, message] of errors) {
    const at = lines.indexOf(`ERROR ${join(dir, path)}`);
    assert.notEqual(at, -1, `${name}: no ERROR line for ${path}\n${result.stdout}`);
    assert.match(lines[at + 1], message, name);
    assert.ok(lines[at + 1].includes(join(dir, path)), `${name}: ${lines[at + 1]}`);
  }
  assert.deepEqual(lines.slice(-2), [summary, ""], name);
}

// A scratch directory holding `valid.json`, a copy of a fixture both verifiers
// pass, so each case shows the walk going on past the entry it cannot read. The
// directory is given without symlinks, so both verifiers print the paths
// written here.
function scratchFixtureDir(t) {
  const dir = realpathSync(mkdtempSync(join(tmpdir(), "verify-")));
  const locked = [];
  t.after(() => {
    for (const path of locked) chmodSync(path, 0o755);
    rmSync(dir, { recursive: true, force: true });
  });
  writeFileSync(join(dir, "valid.json"), readFileSync(join(REPO, "fixtures/levels/level-0-self-asserted.json")));
  return { dir, lock: (path) => (locked.push(path), chmodSync(path, 0o000)) };
}

test("a symlink loop is reported as ERROR by both verifiers", { skip: process.platform === "win32" }, (t) => {
  const { dir } = scratchFixtureDir(t);
  symlinkSync("loop-b.json", join(dir, "loop-a.json"));
  symlinkSync("loop-a.json", join(dir, "loop-b.json"));
  // Not a fixture name, so the walk passes over it in both verifiers.
  symlinkSync("loop-c", join(dir, "loop-c"));
  for (const [name, argv] of Object.entries(VERIFIERS)) {
    assertErrorEntries(
      `${name} (named)`,
      runVerifier(argv, join(dir, "loop-a.json")),
      dir,
      [["loop-a.json", SYMLINK_LOOP]],
      "summary: 0 pass, 1 fail (1 fixtures)",
    );
    assertErrorEntries(
      `${name} (walked)`,
      runVerifier(argv, dir),
      dir,
      [
        ["loop-a.json", SYMLINK_LOOP],
        ["loop-b.json", SYMLINK_LOOP],
      ],
      "summary: 1 pass, 2 fail (3 fixtures)",
    );
  }
});

test(
  "a directory that cannot be listed is reported as ERROR by both verifiers",
  { skip: process.platform === "win32" || process.getuid?.() === 0 },
  (t) => {
    const { dir, lock } = scratchFixtureDir(t);
    mkdirSync(join(dir, "locked"));
    lock(join(dir, "locked"));
    for (const [name, argv] of Object.entries(VERIFIERS)) {
      assertErrorEntries(
        `${name} (named)`,
        runVerifier(argv, join(dir, "locked")),
        dir,
        [["locked", NO_PERMISSION]],
        "summary: 0 pass, 1 fail (1 fixtures)",
      );
      assertErrorEntries(
        `${name} (walked)`,
        runVerifier(argv, dir),
        dir,
        [["locked", NO_PERMISSION]],
        "summary: 1 pass, 1 fail (2 fixtures)",
      );
    }
  },
);
