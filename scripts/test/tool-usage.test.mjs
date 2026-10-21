// Regression tests for the command lines of the contributor tools:
// scripts/conformance_profile.py, scripts/generate-fixtures.mjs and
// scripts/check-doc-links.mjs. Each read no argument at all, so `--help`
// regenerated conformance.json or the fixtures, or ran the link check, and a
// mistyped option did the same. Now --help and -h print the usage and exit 0,
// any other argument (any argument other than --check, for the profile script)
// is a usage error, exit 2, and neither writes a file. Each tool runs on a
// scratch copy, so a tool that ignored its arguments would write there.
//
// Usage:  node --test scripts/test/*.test.mjs

import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { cpSync, existsSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const REPO = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..");

function scratch(t, files) {
  const root = mkdtempSync(join(tmpdir(), "tool-usage-"));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  for (const rel of files) cpSync(join(REPO, rel), join(root, rel), { recursive: true });
  return root;
}

// Every file and directory under `root`, as paths relative to it.
function listing(root, dir = "") {
  return readdirSync(join(root, dir), { withFileTypes: true })
    .flatMap((entry) => {
      const rel = join(dir, entry.name);
      return entry.isDirectory() ? [rel, ...listing(root, rel)] : [rel];
    })
    .sort();
}

const HELP_OPTIONS = ["--help", "-h"];

// --- conformance_profile.py ----------------------------------------------------

const PROFILE = "scripts/conformance_profile.py";
const PROFILE_USAGE = "usage: conformance_profile.py [-h] [--check]";

// The files the profile script reads, with conformance.json removed, so a run
// that writes the profile creates it.
function profileCopy(t) {
  const root = scratch(t, [PROFILE, "README.md", "docs/coverage.md", "COSIGNERS.md", "fixtures"]);
  assert.ok(!existsSync(join(root, "conformance.json")));
  return root;
}

function runProfile(root, ...args) {
  return spawnSync("python3", [join(root, PROFILE), ...args], { encoding: "utf8" });
}

for (const option of HELP_OPTIONS) {
  test(`conformance_profile.py ${option} prints the usage and writes nothing`, (t) => {
    const root = profileCopy(t);
    const result = runProfile(root, option);
    assert.equal(result.status, 0, result.stdout + result.stderr);
    assert.equal(result.stderr, "");
    assert.ok(result.stdout.startsWith(`${PROFILE_USAGE}\n`), result.stdout);
    assert.match(result.stdout, /^ {2}--check /m);
    assert.doesNotMatch(result.stdout, /^wrote /m);
    assert.ok(!existsSync(join(root, "conformance.json")), "conformance.json was written");
  });
}

test("conformance_profile.py refuses an argument other than --check, exit 2, and writes nothing", (t) => {
  const root = profileCopy(t);
  // `--che` would be taken for `--check` if abbreviations were allowed.
  for (const args of [["--bogus"], ["extra"], ["--che"], ["--check", "--bogus"]]) {
    const result = runProfile(root, ...args);
    assert.equal(result.status, 2, `${args}: ${result.stdout}${result.stderr}`);
    assert.equal(result.stdout, "", `${args}`);
    assert.deepEqual(
      result.stderr.split("\n"),
      [PROFILE_USAGE, `conformance_profile.py: error: unrecognized arguments: ${args.at(-1)}`, ""],
      `${args}`,
    );
    assert.ok(!existsSync(join(root, "conformance.json")), `${args}: conformance.json was written`);
  }
});

test("conformance_profile.py with no argument still writes the profile, and --check still checks it", (t) => {
  const root = profileCopy(t);
  const wrote = runProfile(root);
  assert.equal(wrote.status, 0, wrote.stdout + wrote.stderr);
  assert.match(wrote.stdout, /^wrote conformance\.json \(\d+ requirements\)\n$/);
  assert.deepEqual(readFileSync(join(root, "conformance.json")), readFileSync(join(REPO, "conformance.json")));
  const checked = runProfile(root, "--check");
  assert.equal(checked.status, 0, checked.stdout + checked.stderr);
  assert.equal(checked.stdout, "conformance.json is current\n");
});

// --- generate-fixtures.mjs -----------------------------------------------------

const GENERATOR = "scripts/generate-fixtures.mjs";
const GENERATOR_USAGE = "usage: node generate-fixtures.mjs";
// What a copy holding the generator alone lists.
const GENERATOR_ONLY = ["scripts", join("scripts", "generate-fixtures.mjs")];

function runGenerator(root, ...args) {
  return spawnSync(process.execPath, [join(root, GENERATOR), ...args], { encoding: "utf8" });
}

// The copy holds the generator alone, so any file it writes shows in the listing.
for (const option of HELP_OPTIONS) {
  test(`generate-fixtures.mjs ${option} prints the usage and writes nothing`, (t) => {
    const root = scratch(t, [GENERATOR]);
    const result = runGenerator(root, option);
    assert.equal(result.status, 0, result.stdout + result.stderr);
    assert.equal(result.stderr, "");
    assert.ok(result.stdout.startsWith(`${GENERATOR_USAGE}\n`), result.stdout);
    assert.doesNotMatch(result.stdout, /^wrote /m);
    assert.deepEqual(listing(root), GENERATOR_ONLY);
  });
}

test("generate-fixtures.mjs refuses any other argument, exit 2, and writes nothing", (t) => {
  const root = scratch(t, [GENERATOR]);
  for (const [arg, line] of [
    ["--bogus", "generate-fixtures.mjs: unknown option: --bogus"],
    ["fixtures", "generate-fixtures.mjs: unexpected argument: fixtures"],
    // Printed as verify.mjs prints an unknown option, its control characters escaped.
    ["-\u001b[2J", "generate-fixtures.mjs: unknown option: -\\u001b[2J"],
  ]) {
    const result = runGenerator(root, arg);
    assert.equal(result.status, 2, `${line}: ${result.stdout}${result.stderr}`);
    assert.equal(result.stdout, "", line);
    assert.equal(result.stderr, `${GENERATOR_USAGE}\n${line}\n`);
  }
  assert.deepEqual(listing(root), GENERATOR_ONLY);
});

// --- check-doc-links.mjs -------------------------------------------------------

const LINK_CHECK = "scripts/check-doc-links.mjs";
const LINK_CHECK_USAGE = "usage: node check-doc-links.mjs";

// A git checkout whose one Markdown file has a broken link, so a run that
// checks it prints a FAIL line and a summary line and exits 1.
function linkCheckCopy(t) {
  const root = scratch(t, [LINK_CHECK]);
  writeFileSync(join(root, "README.md"), "# Demo\n\n[missing](./missing.md)\n");
  const env = { ...process.env, GIT_CEILING_DIRECTORIES: dirname(root) };
  for (const name of ["GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE"]) delete env[name];
  execFileSync("git", ["-c", "init.defaultBranch=main", "init", "-q"], { cwd: root, env });
  execFileSync("git", ["add", "--", "README.md"], { cwd: root, env });
  return { root, env };
}

function runLinkCheck({ root, env }, ...args) {
  return spawnSync(process.execPath, [join(root, LINK_CHECK), ...args], { cwd: root, encoding: "utf8", env });
}

for (const option of HELP_OPTIONS) {
  test(`check-doc-links.mjs ${option} prints the usage without running the check`, (t) => {
    const copy = linkCheckCopy(t);
    const result = runLinkCheck(copy, option);
    assert.equal(result.status, 0, result.stdout + result.stderr);
    assert.equal(result.stderr, "");
    assert.ok(result.stdout.startsWith(`${LINK_CHECK_USAGE}\n`), result.stdout);
    assert.doesNotMatch(result.stdout, /^(FAIL|summary:)/m);
  });
}

test("check-doc-links.mjs refuses any other argument, exit 2, without running the check", (t) => {
  const copy = linkCheckCopy(t);
  for (const [arg, line] of [
    ["--bogus", "check-doc-links.mjs: unknown option: --bogus"],
    ["README.md", "check-doc-links.mjs: unexpected argument: README.md"],
  ]) {
    const result = runLinkCheck(copy, arg);
    assert.equal(result.status, 2, `${line}: ${result.stdout}${result.stderr}`);
    assert.equal(result.stdout, "", line);
    assert.equal(result.stderr, `${LINK_CHECK_USAGE}\n${line}\n`);
  }
  // With no argument the check runs and finds the broken link.
  const result = runLinkCheck(copy);
  assert.equal(result.status, 1, result.stdout + result.stderr);
  assert.match(result.stdout, /^summary: 1 paths checked, 1 broken$/m);
});
