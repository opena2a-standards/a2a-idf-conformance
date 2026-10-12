// Regression tests for scripts/check-doc-links.mjs. Each test copies the script
// into a scratch directory, so the scratch directory is the repo root it checks.
//
// Usage:  node --test scripts/test/*.test.mjs

import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync, spawn, spawnSync } from "node:child_process";
import { once } from "node:events";
import { cpSync, mkdirSync, mkdtempSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const SCRIPT = resolve(dirname(fileURLToPath(import.meta.url)), "..", "check-doc-links.mjs");

// Keep git inside the scratch directory: no repository above it, and no
// GIT_DIR or work tree inherited from the caller.
function gitEnv(root) {
  const env = { ...process.env, GIT_CEILING_DIRECTORIES: dirname(root) };
  for (const name of ["GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE"]) delete env[name];
  return env;
}

function scratchRepo(t, files, { git = true, parent = tmpdir() } = {}) {
  const root = mkdtempSync(join(parent, "doc-links-"));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  mkdirSync(join(root, "scripts"));
  cpSync(SCRIPT, join(root, "scripts", "check-doc-links.mjs"));
  for (const [rel, content] of Object.entries(files)) {
    mkdirSync(dirname(join(root, rel)), { recursive: true });
    writeFileSync(join(root, rel), content);
  }
  if (git) {
    const opts = { cwd: root, env: gitEnv(root) };
    execFileSync("git", ["-c", "init.defaultBranch=main", "init", "-q"], opts);
    execFileSync("git", ["add", "--", ...Object.keys(files)], opts);
  }
  return root;
}

function runCheck(root, { timeout = 10_000, maxBuffer = 1024 * 1024 } = {}) {
  return spawnSync(process.execPath, [join(root, "scripts", "check-doc-links.mjs")], {
    cwd: root,
    encoding: "utf8",
    timeout,
    maxBuffer,
    env: gitEnv(root),
  });
}

// A relative directory, without a trailing `/`, that a `cd` in a scratch repo
// resolves to a path of `length` characters. The check resolves a `cd` against
// the real path of the directory it sits in.
function dirOfLength(root, length) {
  const n = length - realpathSync(root).length - 1;
  const steps = Math.floor((n - 1) / 2);
  return "d/".repeat(steps) + "e".repeat(n - 2 * steps);
}

test("checks the script path of a command chained after &&, ;, || or |", (t) => {
  const root = scratchRepo(t, {
    "fixtures/levels/README.md": "# Levels\n",
    "README.md": [
      "# Demo",
      "",
      "```bash",
      "cd fixtures/levels && node ../../scripts/nope.mjs .",
      "cd fixtures/levels && node ../../scripts/check-doc-links.mjs",
      "true; python3 scripts/missing.py fixtures",
      "echo ok | node scripts/check-doc-links.mjs || node scripts/fallback.mjs",
      "```",
      "",
    ].join("\n"),
  });
  const result = runCheck(root);
  assert.equal(result.status, 1, result.stdout + result.stderr);
  assert.match(result.stdout, /^FAIL {2}README\.md:4 {2}command script \.\.\/\.\.\/scripts\/nope\.mjs /m);
  assert.match(result.stdout, /^FAIL {2}README\.md:6 {2}command script scripts\/missing\.py /m);
  assert.match(result.stdout, /^FAIL {2}README\.md:7 {2}command script scripts\/fallback\.mjs /m);
  assert.doesNotMatch(result.stdout, /README\.md:5 /);
  assert.match(result.stdout, /^summary: 5 paths checked, 3 broken$/m);
});

test("follows cd -- <dir> and a cd inside a subshell, until the subshell closes", (t) => {
  const root = scratchRepo(t, {
    "fixtures/levels/README.md": "# Levels\n",
    "README.md": [
      "# Demo",
      "",
      "```bash",
      "cd -- fixtures/levels && node ../../scripts/check-doc-links.mjs",
      "cd -- fixtures/levels && node ../../scripts/nope.mjs",
      "(cd fixtures/levels && node ../../scripts/check-doc-links.mjs)",
      "(cd fixtures/levels && node ../../scripts/gone.mjs)",
      "$ ( cd fixtures/levels && node ../../scripts/check-doc-links.mjs ) && node scripts/check-doc-links.mjs",
      "OUT=$(cd fixtures/levels && node ../../scripts/check-doc-links.mjs) && node scripts/lost.mjs",
      "```",
      "",
    ].join("\n"),
  });
  const result = runCheck(root);
  assert.equal(result.status, 1, result.stdout + result.stderr);
  assert.match(result.stdout, /^FAIL {2}README\.md:5 {2}command script \.\.\/\.\.\/scripts\/nope\.mjs \(not found from fixtures\/levels\/\)$/m);
  assert.match(result.stdout, /^FAIL {2}README\.md:7 {2}command script \.\.\/\.\.\/scripts\/gone\.mjs \(not found from fixtures\/levels\/\)$/m);
  assert.match(result.stdout, /^FAIL {2}README\.md:9 {2}command script scripts\/lost\.mjs \(not found from the repo root\)$/m);
  assert.match(result.stdout, /^summary: 8 paths checked, 3 broken$/m);
});

test("does not guess the directory of a cd it cannot resolve", (t) => {
  const root = scratchRepo(t, {
    "fixtures/levels/README.md": "# Levels\n",
    "README.md": [
      "# Demo",
      "",
      "```bash",
      "cd -P fixtures/levels && node ../../scripts/check-doc-links.mjs",
      'cd "$(dirname "$0")" && node ../scripts/check-doc-links.mjs',
      "cd -- && node scripts/elsewhere.mjs",
      '(cd "$DIR" && node elsewhere.mjs); node scripts/nope.mjs',
      "cd <your-clone> && node scripts/elsewhere.mjs",
      "cd fixtures/<level> && node ../../scripts/elsewhere.mjs",
      "```",
      "",
    ].join("\n"),
  });
  const result = runCheck(root);
  assert.equal(result.status, 1, result.stdout + result.stderr);
  assert.match(result.stdout, /^FAIL {2}README\.md:7 {2}command script scripts\/nope\.mjs /m);
  assert.match(result.stdout, /^summary: 1 paths checked, 1 broken$/m);
});

test("follows a cd that carries a redirection or a trailing comment, not one with a second operand", (t) => {
  const root = scratchRepo(t, {
    "fixtures/levels/README.md": "# Levels\n",
    "README.md": [
      "# Demo",
      "",
      "```bash",
      "cd fixtures/levels 2>/dev/null && node ../../scripts/nope.mjs",
      "cd fixtures/levels > /dev/null 2>&1 && node ../../scripts/check-doc-links.mjs",
      "cd fixtures/levels # the level fixtures",
      "cd 2>/dev/null -- fixtures/levels && node ../../scripts/gone.mjs",
      "cd fixtures/levels extra && node ../../scripts/elsewhere.mjs",
      "cd fixtures/levels 2> && node ../../scripts/elsewhere.mjs",
      "cd fixtures/levels>/dev/null && node ../../scripts/lost.mjs",
      "cd fixtures/levels&>/dev/null && node ../../scripts/check-doc-links.mjs",
      "cd fixtures/levels> /dev/null && node ../../scripts/check-doc-links.mjs",
      "cd fixtures/levels <input && node ../../scripts/check-doc-links.mjs",
      "```",
      "",
    ].join("\n"),
  });
  const result = runCheck(root);
  assert.equal(result.status, 1, result.stdout + result.stderr);
  assert.match(result.stdout, /^FAIL {2}README\.md:4 {2}command script \.\.\/\.\.\/scripts\/nope\.mjs \(not found from fixtures\/levels\/\)$/m);
  assert.match(result.stdout, /^FAIL {2}README\.md:7 {2}command script \.\.\/\.\.\/scripts\/gone\.mjs \(not found from fixtures\/levels\/\)$/m);
  assert.match(result.stdout, /^FAIL {2}README\.md:10 {2}command script \.\.\/\.\.\/scripts\/lost\.mjs \(not found from fixtures\/levels\/\)$/m);
  assert.doesNotMatch(result.stdout, /elsewhere/);
  assert.match(result.stdout, /^summary: 7 paths checked, 3 broken$/m);
});

test("outside a shell block, does not resolve a cd that opens a subshell", (t) => {
  const root = scratchRepo(t, {
    "fixtures/levels/README.md": "# Levels\n",
    "README.md": [
      "# Demo",
      "",
      "```",
      "(cd fixtures/levels && node ../../scripts/check-doc-links.mjs .)",
      "(cd fixtures/levels && node ../../scripts/nope.mjs .)",
      "$ ( cd fixtures/levels && node ../../scripts/nope.mjs . )",
      "OUT=$(cd fixtures/levels && node ../../scripts/nope.mjs .) && node scripts/nope.mjs .",
      "node scripts/before.mjs; (cd fixtures/levels && node ../../scripts/nope.mjs .)",
      "```",
      "",
      "```text",
      "(cd fixtures/levels && node ../../scripts/check-doc-links.mjs .)",
      "```",
      "",
    ].join("\n"),
  });
  const result = runCheck(root);
  assert.equal(result.status, 1, result.stdout + result.stderr);
  assert.doesNotMatch(result.stdout, /check-doc-links\.mjs|nope\.mjs/);
  assert.match(result.stdout, /^FAIL {2}README\.md:8 {2}command script scripts\/before\.mjs \(not found from the repo root\)$/m);
  assert.match(result.stdout, /^summary: 1 paths checked, 1 broken$/m);
});

test("splits at parentheses in shell blocks only, and does not read a comment", (t) => {
  const root = scratchRepo(t, {
    "README.md": [
      "# Demo",
      "",
      "```js",
      "console.log(node scripts/nope.mjs)",
      "```",
      "",
      "```",
      "case $x in a) node scripts/nope.mjs ;; esac",
      "# (node scripts/nope.mjs)",
      "```",
      "",
      "```bash",
      "# (node scripts/nope.mjs)",
      "node scripts/check-doc-links.mjs # ; node scripts/nope.mjs",
      "echo '#' && node scripts/quoted.mjs",
      "echo a#b; node scripts/word.mjs",
      "(node scripts/check-doc-links.mjs)",
      "echo \\ #x ; node scripts/escaped-space.mjs",
      "echo ' # ' ; node scripts/single-quoted.mjs",
      'echo "a\\" # b" ; node scripts/double-quoted.mjs',
      "echo \\' # ; node scripts/nope.mjs",
      "echo x;# y ; node scripts/nope.mjs",
      "```",
      "",
    ].join("\n"),
  });
  const result = runCheck(root);
  assert.equal(result.status, 1, result.stdout + result.stderr);
  assert.doesNotMatch(result.stdout, /nope\.mjs/);
  assert.match(result.stdout, /^FAIL {2}README\.md:15 {2}command script scripts\/quoted\.mjs /m);
  assert.match(result.stdout, /^FAIL {2}README\.md:16 {2}command script scripts\/word\.mjs /m);
  assert.match(result.stdout, /^FAIL {2}README\.md:18 {2}command script scripts\/escaped-space\.mjs /m);
  assert.match(result.stdout, /^FAIL {2}README\.md:19 {2}command script scripts\/single-quoted\.mjs /m);
  assert.match(result.stdout, /^FAIL {2}README\.md:20 {2}command script scripts\/double-quoted\.mjs /m);
  assert.match(result.stdout, /^summary: 7 paths checked, 5 broken$/m);
});

test("splits at parentheses in a block labelled with any shell name, in any letter case", (t) => {
  const labels = ["bash", "sh", "zsh", "ksh", "shell", "console", "shell-session", "sh-session", "Bash", "SH"];
  const root = scratchRepo(t, {
    "README.md": [
      "# Demo",
      "",
      ...labels.flatMap((label) => ["```" + label, `(node scripts/${label}.mjs)`, "```", ""]),
      "```text",
      "(node scripts/text.mjs)",
      "```",
      "",
    ].join("\n"),
  });
  const result = runCheck(root);
  assert.equal(result.status, 1, result.stdout + result.stderr);
  for (const label of labels) {
    assert.match(result.stdout, new RegExp(`^FAIL {2}README\\.md:\\d+ {2}command script scripts/${label}\\.mjs `, "m"));
  }
  assert.doesNotMatch(result.stdout, /text\.mjs/);
  assert.match(result.stdout, new RegExp(`^summary: ${labels.length} paths checked, ${labels.length} broken$`, "m"));
});

test("follows a cd to a directory of up to 4096 characters, not longer", (t) => {
  const root = scratchRepo(t, { "README.md": "# Demo\n" });
  writeFileSync(
    join(root, "README.md"),
    [
      "# Demo",
      "",
      "```bash",
      `cd ${dirOfLength(root, 4096)} && node scripts/nope.mjs`,
      `cd ${dirOfLength(root, 4097)} && node scripts/gone.mjs`,
      "```",
      "",
    ].join("\n"),
  );
  const result = runCheck(root);
  assert.equal(result.status, 1, result.stdout + result.stderr);
  assert.match(result.stdout, /^FAIL {2}README\.md:4 {2}command script scripts\/nope\.mjs /m);
  assert.doesNotMatch(result.stdout, /gone\.mjs/);
  assert.match(result.stdout, /^summary: 1 paths checked, 1 broken$/m);
});

test("reports every broken path when one file has a very large number of them", (t) => {
  const root = scratchRepo(t, {
    "README.md": ["# Demo", "", "```bash", "node a.mjs; ".repeat(200_000), "```", ""].join("\n"),
  });
  const result = runCheck(root, { timeout: 60_000, maxBuffer: 64 * 1024 * 1024 });
  assert.equal(result.error, undefined, String(result.error));
  assert.equal(result.status, 1, result.stderr);
  assert.equal(result.stderr, "");
  assert.equal(result.stdout.match(/^FAIL {2}README\.md:4 {2}command script a\.mjs /gm)?.length, 200_000);
  assert.match(result.stdout, /^summary: 200000 paths checked, 200000 broken$/m);
});

// Output to a pipe is written asynchronously, so a process that ends itself
// with process.exit() drops the FAIL lines still queued, and the summary line.
test("prints every FAIL line and the summary when its output goes to a pipe", async (t) => {
  const root = scratchRepo(t, { "README.md": "# Demo\n" });
  writeFileSync(
    join(root, "README.md"),
    ["# Demo", "", "```bash", `cd ${dirOfLength(root, 4000)}; ${"node a.mjs; ".repeat(200)}`, "```", ""].join("\n"),
  );
  const child = spawn(process.execPath, [join(root, "scripts", "check-doc-links.mjs")], {
    cwd: root,
    env: gitEnv(root),
  });
  let stdout = "";
  child.stdout.setEncoding("utf8").on("data", (chunk) => (stdout += chunk));
  const [status] = await once(child, "close");
  assert.equal(status, 1);
  assert.equal(stdout.match(/^FAIL {2}README\.md:4 {2}command script a\.mjs /gm)?.length, 200);
  assert.match(stdout, /^summary: 200 paths checked, 200 broken$/m);
});

// Without the bounds, each of the first three lines below takes seconds to
// minutes: every `cd` resolves a path that grows with the line, and open
// subshells keep them all. The last two pin the number of `cd` steps followed.
test("bounds the cd steps followed on a long line", (t) => {
  const root = scratchRepo(t, {
    "README.md": [
      "# Demo",
      "",
      "```bash",
      `${"cd a; ".repeat(35_000)}node scripts/nope.mjs`,
      `${"(cd a && ".repeat(25_000)}node scripts/nope.mjs`,
      `cd ${"d/".repeat(100_000)}; ${"node a.mjs; ".repeat(20_000)}`,
      `${"cd a; ".repeat(32)}node ${"../".repeat(32)}scripts/check-doc-links.mjs`,
      `${"cd a; ".repeat(33)}node ${"../".repeat(33)}scripts/check-doc-links.mjs`,
      "```",
      "",
    ].join("\n"),
  });
  const started = Date.now();
  const result = runCheck(root, { timeout: 3_000 });
  assert.equal(result.error, undefined, `link check did not finish within 3 s (${Date.now() - started} ms)`);
  assert.equal(result.status, 0, result.stdout + result.stderr);
  assert.match(result.stdout, /^summary: 1 paths checked, 0 broken$/m);
});

test("scans a long line of link-like text in linear time", (t) => {
  const root = scratchRepo(t, {
    "README.md": ["# Demo", "", "[a](".repeat(40_000), "", "[".repeat(80_000), "", "[ok](./README.md)", ""].join("\n"),
  });
  const started = Date.now();
  const result = runCheck(root, { timeout: 3_000 });
  assert.equal(result.error, undefined, `link check did not finish within 3 s (${Date.now() - started} ms)`);
  assert.equal(result.status, 0, result.stdout + result.stderr);
  assert.match(result.stdout, /^summary: 1 paths checked, 0 broken$/m);
});

test("reports a link with a stray percent sign instead of throwing", (t) => {
  const root = scratchRepo(t, { "README.md": "# Demo\n\nSee [x](./100%.md).\n" });
  const result = runCheck(root);
  assert.equal(result.status, 1, result.stdout + result.stderr);
  assert.match(result.stdout, /^FAIL {2}README\.md:3 {2}link \.\/100%\.md \(malformed percent-encoding/m);
  assert.equal(result.stderr, "");
  assert.match(result.stdout, /^summary: 1 paths checked, 1 broken$/m);
});

test("outside a git checkout prints one line naming the cause", (t) => {
  const root = scratchRepo(t, { "README.md": "# Demo\n" }, { git: false });
  const result = runCheck(root);
  assert.equal(result.status, 1, result.stdout + result.stderr);
  const output = (result.stdout + result.stderr).trim().split("\n");
  assert.equal(output.length, 1, output.join("\n"));
  assert.match(output[0], /^error: git ls-files failed .*not a git repository/);
});

test("a repository above the scratch directory is not reached", (t) => {
  // The scratch directory has no repository of its own and sits inside one.
  // Without GIT_CEILING_DIRECTORIES, git finds the one above and the check
  // passes over its empty index instead of failing.
  const outer = mkdtempSync(join(tmpdir(), "doc-links-outer-"));
  t.after(() => rmSync(outer, { recursive: true, force: true }));
  execFileSync("git", ["init", "-q"], { cwd: outer, env: gitEnv(outer) });
  const root = scratchRepo(t, { "README.md": "# Demo\n" }, { git: false, parent: outer });
  const result = runCheck(root);
  assert.equal(result.status, 1, result.stdout + result.stderr);
  assert.match(result.stderr, /^error: git ls-files failed .*not a git repository/);
});
