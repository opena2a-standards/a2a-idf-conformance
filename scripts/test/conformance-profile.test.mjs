// Regression tests for `scripts/conformance_profile.py --check`, run on a
// scratch copy of the files it reads so the committed tree is never modified.
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

function check(root) {
  return spawnSync("python3", [join(root, "scripts", "conformance_profile.py"), "--check"], {
    encoding: "utf8",
  });
}

function fixtureCount(root) {
  return JSON.parse(readFileSync(join(root, "conformance.json"), "utf8")).requirements.length;
}

function editCosigners(root, edit) {
  const path = join(root, "COSIGNERS.md");
  const before = readFileSync(path, "utf8");
  const after = edit(before);
  assert.notEqual(after, before, "the edit must change COSIGNERS.md");
  writeFileSync(path, after);
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
