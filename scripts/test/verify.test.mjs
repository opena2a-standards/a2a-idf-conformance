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

// NaN, Infinity and -Infinity are not JSON. JSON.parse raises on them, and
// Python's json module reads them as numbers unless told not to, which would
// make verify.py reach a verdict where verify.mjs reports ERROR.
for (const constant of ["NaN", "Infinity", "-Infinity"]) {
  test(`a fixture holding ${constant} is reported as ERROR by both verifiers`, (t) => {
    const dir = mkdtempSync(join(tmpdir(), "verify-"));
    t.after(() => rmSync(dir, { recursive: true, force: true }));
    const source = readFileSync(join(REPO, "fixtures/levels/level-0-self-asserted.json"), "utf8");
    const text = source.replace('"spec": [', `"spec": [${constant}, `);
    assert.notEqual(text, source);
    const path = join(dir, "variant.json");
    writeFileSync(path, text);
    for (const [name, argv] of Object.entries(VERIFIERS)) {
      const result = runVerifier(argv, path);
      assert.equal(result.status, 1, `${name}: ${result.stdout}${result.stderr}`);
      assert.equal(result.stderr, "", name);
      const lines = result.stdout.split("\n");
      assert.match(lines[0], /^ERROR .*variant\.json$/, name);
      assert.doesNotMatch(result.stdout, /observed:/, name);
      assert.deepEqual(lines.slice(-2), ["summary: 0 pass, 1 fail (1 fixtures)", ""], name);
    }
  });
}

// Runs both verifiers once over a scratch directory holding `variants`, an
// object of file name to fixture text, and returns each verifier's output as
// { file name: [status, ...the lines printed under it] }, so the two are
// compared whatever order each walks the directory in.
function runOverVariants(t, variants) {
  const dir = mkdtempSync(join(tmpdir(), "verify-"));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  for (const [name, text] of Object.entries(variants)) writeFileSync(join(dir, name), text);
  const blocks = {};
  for (const [verifier, argv] of Object.entries(VERIFIERS)) {
    const result = runVerifier(argv, dir);
    assert.equal(result.stderr, "", verifier);
    blocks[verifier] = {};
    let current = null;
    for (const line of result.stdout.split("\n")) {
      const status = line.match(/^(PASS|FAIL|ERROR) .*\/([^/]+)$/);
      if (status) {
        current = blocks[verifier][status[2]] = [status[1]];
      } else if (current !== null && line.startsWith("      ")) {
        current.push(line.trim());
      }
    }
  }
  return blocks;
}

// The text of a fixture after `mutate`. When `literal` is given, `mutate` sets
// one member to PLACEHOLDER and the placeholder is replaced by `literal`, JSON
// text that JSON.stringify does not write (1.0, 1e400, an integer of 5,000
// digits).
const PLACEHOLDER = "literal-placeholder";

function literalVariant(source, mutate, literal) {
  const fixture = JSON.parse(readFileSync(join(REPO, source), "utf8"));
  mutate(fixture);
  const text = JSON.stringify(fixture);
  if (literal === undefined) return text;
  const replaced = text.replace(JSON.stringify(PLACEHOLDER), () => literal);
  assert.notEqual(replaced, text);
  return replaced;
}

// A reject reason quotes a string as it is and names any other value by its
// JSON type, in the same words in both verifiers. Each runtime's own text for
// such a value differed (an empty string and [] for an empty array, undefined
// and None for a missing member), and on a deeply nested value one verifier
// raised where the other reached a verdict. The variants pin ACCEPT, so the
// reason is printed.
const VALUE_KINDS = [
  ["array", "[[]]", "a JSON array"],
  ["object", '{"a":{}}', "a JSON object"],
  ["integer", "5", "a JSON integer"],
  ["number", "0.5", "a JSON number"],
  ["infinite", "1e400", "a JSON number"],
  ["boolean", "true", "a JSON boolean"],
  ["null", "null", "a JSON null"],
  ["string", '"PLATINUM"', "PLATINUM"],
  ["missing", undefined, "(missing)"],
];
const identityParams = (fx) => fx.agentCard.capabilities.extensions[0].params;

for (const [label, member, holder, category, reason] of [
  ["an identityLevel", "identityLevel", identityParams, "SHAPE_INVALID", (text) => `unknown identityLevel: ${text}`],
  [
    "an agentId",
    "agentId",
    identityParams,
    "SHAPE_INVALID",
    (text) => `agentId is not a urn:a2a:agent:{domain}:{agent-name}:{version} URN: ${text}`,
  ],
  [
    "an attestation domain",
    "domain",
    (fx) => identityParams(fx).attestations[0],
    "DOMAIN_MISMATCH",
    (text) => `attestation domain ${text} != provider domain example.com`,
  ],
]) {
  test(`a reject reason words ${label} that is not a string the same way in both verifiers`, (t) => {
    const variants = {};
    const expected = {};
    for (const [kind, literal, text] of VALUE_KINDS) {
      // An agentId that is missing is not declared, which is another check's reject.
      if (member === "agentId" && literal === undefined) continue;
      variants[`${kind}.json`] = literalVariant(
        "fixtures/levels/level-1-domain-verified.json",
        (fx) => {
          if (literal === undefined) delete holder(fx)[member];
          else holder(fx)[member] = PLACEHOLDER;
        },
        literal,
      );
      expected[`${kind}.json`] = [
        "FAIL",
        `observed: REJECT[${category}]`,
        "stage:  verdict",
        `reason: verify result REJECT[${category}] != expected ACCEPT (${reason(text)})`,
      ];
    }
    const blocks = runOverVariants(t, variants);
    assert.deepEqual(blocks.node, expected);
    assert.deepEqual(blocks.python, blocks.node);
  });
}

// The CROSS_SUITE_MISMATCH reason of a composition fixture quotes
// crossSuiteEquivalence.envoys.vector, which the schema does not type, in the
// same way. Each runtime's own text for a vector that is not a string differed
// (1e-7 and 1e-07, 1 and 1.0, an empty string and [] for an empty array,
// undefined and None for a missing vector), and converting a deeply nested one
// to text raised: Array.prototype.toString in verify.mjs on an array nested
// 5,000 levels, repr() in verify.py on an array or an object nested 200,000.
// The fixture pins REJECT, so each copy pins ACCEPT for the reason to be
// printed.
const DEPTH = 200_000;

test("the cross-suite mismatch reason words a vector that is not a string the same way in both verifiers", (t) => {
  const variants = {};
  const expected = {};
  for (const [kind, literal, text] of [
    ...VALUE_KINDS,
    ["empty-array", "[]", "a JSON array"],
    ["float-one", "1.0", "a JSON integer"],
    ["negative-zero", "-0.0", "a JSON integer"],
    ["twenty-digits", "12345678901234567890", "a JSON integer"],
    ["small-fraction", "1e-7", "a JSON number"],
    ["integer-of-5000-digits", "7".repeat(5000), "a JSON number"],
    ["deeply-nested-array", "[".repeat(DEPTH) + "]".repeat(DEPTH), "a JSON array"],
    ["deeply-nested-object", '{"a":'.repeat(DEPTH) + "{}" + "}".repeat(DEPTH), "a JSON object"],
  ]) {
    variants[`${kind}.json`] = literalVariant(
      "fixtures/composition/aim-did-rfc9421/cross-suite-mismatch.json",
      (fx) => {
        fx.expected.verifyResult = "ACCEPT";
        delete fx.expected.rejectCategory;
        if (literal === undefined) delete fx.crossSuiteEquivalence.envoys.vector;
        else fx.crossSuiteEquivalence.envoys.vector = PLACEHOLDER;
      },
      literal,
    );
    expected[`${kind}.json`] = [
      "FAIL",
      "observed: REJECT[CROSS_SUITE_MISMATCH]",
      "stage:  verdict",
      `reason: verify result REJECT[CROSS_SUITE_MISMATCH] != expected ACCEPT (verified signature does not byte-match Envoys ${text})`,
    ];
  }
  const blocks = runOverVariants(t, variants);
  assert.deepEqual(blocks.node, expected);
  assert.deepEqual(blocks.python, blocks.node);
});

// A schema reason writes a number as text only when it is a safe integer, which
// both runtimes write the same way, and names any other number by its JSON
// type. JSON.stringify and json.dumps wrote 1 and 1.0, null and Infinity, 0 and
// -0.0, 1e-7 and 1e-07, 12345678901234567000 and 12345678901234567890. An
// integer beyond the range of a double is an infinite number in both verifiers,
// so neither calls it a JSON integer.
test("a schema reason words a number the same way in both verifiers", (t) => {
  const variants = {};
  const expected = {};
  for (const [name, literal, text] of [
    ["float-one", "1.0", "1"],
    ["negative-zero", "-0.0", "0"],
    ["largest-safe-integer", "9007199254740991", "9007199254740991"],
    ["smallest-safe-integer", "-9007199254740991", "-9007199254740991"],
    ["past-safe-integers", "9007199254740993", "a JSON integer"],
    ["twenty-digits", "12345678901234567890", "a JSON integer"],
    ["small-fraction", "1e-7", "a JSON number"],
    ["float-overflow", "1e400", "a JSON number"],
    ["integer-of-400-digits", "7".repeat(400), "a JSON number"],
    ["integer-of-5000-digits", "7".repeat(5000), "a JSON number"],
    ["negative-integer-of-5000-digits", `-${"7".repeat(5000)}`, "a JSON number"],
  ]) {
    variants[`${name}.json`] = literalVariant(
      "fixtures/levels/level-0-self-asserted.json",
      (fx) => (fx.expected.verifyResult = PLACEHOLDER),
      literal,
    );
    expected[`${name}.json`] = [
      "FAIL",
      "stage:  schema",
      `reason: expected.verifyResult: ${text} is not one of "ACCEPT", "REJECT"`,
    ];
  }
  // As `level`, an integer beyond the range of a double is not a JSON integer.
  for (const digits of [400, 5000]) {
    variants[`level-of-${digits}-digits.json`] = literalVariant(
      "fixtures/levels/level-0-self-asserted.json",
      (fx) => (fx.level = PLACEHOLDER),
      "7".repeat(digits),
    );
    expected[`level-of-${digits}-digits.json`] = [
      "FAIL",
      "stage:  schema",
      "reason: level is present but is not a JSON integer",
    ];
  }
  const blocks = runOverVariants(t, variants);
  assert.deepEqual(blocks.node, expected);
  assert.deepEqual(blocks.python, blocks.node);
});

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

// The walk does not follow a symlink to a directory, so both verifiers list the
// same fixtures: verify.mjs followed one, listing the fixtures under it a second
// time and once more per level through a link to a parent directory. A symlink
// to a file is a fixture, and a directory named on the command line is walked
// when it is a symlink.
test("a symlink to a directory is not followed during the walk by either verifier", { skip: process.platform === "win32" }, (t) => {
  const { dir } = scratchFixtureDir(t);
  mkdirSync(join(dir, "real"));
  writeFileSync(join(dir, "real", "a.json"), readFileSync(join(dir, "valid.json")));
  symlinkSync("real", join(dir, "alias"));
  symlinkSync(".", join(dir, "parent"));
  // A fixture name does not make a symlink to a directory a fixture.
  symlinkSync("real", join(dir, "directory.json"));
  symlinkSync(join("real", "a.json"), join(dir, "file.json"));
  const passed = (result) =>
    result.stdout.split("\n").filter((line) => line.startsWith("PASS  ")).map((line) => line.slice(6)).sort();
  for (const [name, argv] of Object.entries(VERIFIERS)) {
    const walked = runVerifier(argv, dir);
    assert.equal(walked.status, 0, `${name}: ${walked.stdout}${walked.stderr}`);
    assert.deepEqual(passed(walked), ["file.json", join("real", "a.json"), "valid.json"].map((path) => join(dir, path)), name);
    assert.deepEqual(walked.stdout.split("\n").slice(-2), ["summary: 3 pass, 0 fail (3 fixtures)", ""], name);
    const named = runVerifier(argv, join(dir, "alias"));
    assert.equal(named.status, 0, `${name}: ${named.stdout}${named.stderr}`);
    assert.deepEqual(passed(named), [join(dir, "alias", "a.json")], name);
    assert.deepEqual(named.stdout.split("\n").slice(-2), ["summary: 1 pass, 0 fail (1 fixtures)", ""], name);
  }
});

// A symlink to a directory is the only `*.json` entry the walk of verify.mjs
// passes over. An entry of another kind that cannot be read as a file (here a
// Unix socket) is listed and reported as ERROR, not skipped by a run that then
// exits 0. verify.py passes over a socket, so it is not run here. The socket
// is bound by a relative name from inside the directory, because a socket
// address holds about 100 bytes.
test("verify.mjs reports a socket named *.json met during the walk as ERROR", { skip: process.platform === "win32" }, (t) => {
  const { dir } = scratchFixtureDir(t);
  const bound = spawnSync(
    VERIFIERS.python[0],
    ["-c", "import socket; socket.socket(socket.AF_UNIX).bind('socket.json')"],
    { cwd: dir, encoding: "utf8" },
  );
  assert.equal(bound.status, 0, bound.stderr);
  assertErrorEntries(
    "node",
    runVerifier(VERIFIERS.node, dir),
    dir,
    [["socket.json", /\bopen\b/]],
    "summary: 1 pass, 1 fail (2 fixtures)",
  );
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
