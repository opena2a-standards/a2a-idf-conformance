// Regression test for what the Markdown files say about merging. CI fails a
// pull request that edits a generated fixture by hand (the conformance job
// reruns the generator, then runs `git diff --exit-code`), but whether a pull
// request whose CI fails can still be merged is set by the repository's rules
// for main (branch protection or a ruleset), which are settings outside this
// tree. So no tracked Markdown file says that a pull request, or a fixture in
// one, cannot merge. If main comes to require the check, this test changes
// with the documents.
//
// Usage:  node --test scripts/test/*.test.mjs

import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const REPO = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..");

// "cannot merge", "can't be merged", "cannot land", "blocks the merge",
// "prevented from merging" and the like.
const MERGE_BLOCK =
  /\b(?:cannot|can not|can['’]t)\s+(?:be\s+)?(?:merged?|land(?:ed)?)\b|\b(?:block|prevent)(?:s|ed)?\s+(?:(?:the|a|its)\s+)?merg(?:e|es|ing)\b|\b(?:blocked|prevented)\s+from\s+merging\b/i;

test("no tracked Markdown file says that something cannot merge", () => {
  const files = execFileSync("git", ["ls-files", "-z", "--", "*.md"], { cwd: REPO, encoding: "utf8" })
    .split("\0")
    .filter(Boolean);
  assert.ok(files.length > 0, "git ls-files lists no Markdown file");
  const claims = [];
  for (const rel of files) {
    readFileSync(join(REPO, rel), "utf8").split("\n").forEach((line, index) => {
      const match = line.match(MERGE_BLOCK);
      if (match) claims.push(`${rel}:${index + 1}: "${match[0]}"`);
    });
  }
  assert.deepEqual(
    claims,
    [],
    `whether a pull request can be merged is set by the repository's rules for main, not by CI; say what CI does instead:\n${claims.join("\n")}`,
  );
});
