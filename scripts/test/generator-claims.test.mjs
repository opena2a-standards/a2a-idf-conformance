// Regression tests for what the documentation says scripts/generate-fixtures.mjs
// writes. The generator rewrites the fixtures and vectors in its FILES map,
// then writes MANIFEST.sha256 from the JSON files under fixtures/ and vectors/
// as it finds them. The two hippo-rfc9421 snapshot fixtures are not in FILES,
// so the generator pins them as found, and CI's byte-pin step (the generator,
// then `git diff --exit-code`) passes when one of them changes and
// MANIFEST.sha256 is refreshed with it. So no passage says that the generator
// rewrites every file or that CI fails on any byte change, and the passages
// that say what the generator writes name the snapshot fixtures it leaves as
// found.
//
// Usage:  node --test scripts/test/*.test.mjs

import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { appendFileSync, cpSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const REPO = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..");
const GENERATOR = "scripts/generate-fixtures.mjs";

// The pinned files the documentation names as the ones the generator leaves
// as found. If the generator comes to write one of them, or another pinned
// file it does not write is added, the passages change with this list.
const SNAPSHOT_DIR = "fixtures/composition/hippo-rfc9421/";
const SNAPSHOTS = [`${SNAPSHOT_DIR}signature-alone-no-tag.json`, `${SNAPSHOT_DIR}signature-alone-tag.json`];

// "regenerates every file", "rewrites all fixtures", "regenerates the whole
// set", "fails on any diff", "fails on any byte drift" and the like.
const WHOLE_SET_CLAIM = new RegExp(
  [
    String.raw`\b(?:re)?(?:generates?|writes?|emits?)\s+(?:every|all|each)\s+(?:of\s+the\s+)?(?:files?|fixtures?)\b`,
    String.raw`\bregenerates?\s+(?:the\s+)?(?:whole\s+|full\s+|entire\s+)?set\b`,
    String.raw`\bfails?\s+on\s+any\s+(?:byte\s+)?(?:diff|drift|difference|change)s?\b`,
  ].join("|"),
  "gi",
);

// MANIFEST.sha256 as a map from path to hash, in file order.
function manifest(text) {
  return new Map(
    text
      .split("\n")
      .filter(Boolean)
      .map((line) => {
        const match = /^([0-9a-f]{64}) {2}(\S.*)$/.exec(line);
        assert.ok(match, `not a MANIFEST.sha256 line: ${JSON.stringify(line)}`);
        return [match[2], match[1]];
      }),
  );
}

test("the generator rewrites the files it owns and pins the snapshot fixtures as found", (t) => {
  const root = mkdtempSync(join(tmpdir(), "generator-claims-"));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  for (const rel of [GENERATOR, "fixtures", "vectors", "MANIFEST.sha256"]) {
    cpSync(join(REPO, rel), join(root, rel), { recursive: true });
  }
  // One more line feed at the end of every pinned file: a file the generator
  // writes loses it, a file it leaves as found keeps it.
  const found = new Map();
  for (const rel of manifest(readFileSync(join(REPO, "MANIFEST.sha256"), "utf8")).keys()) {
    appendFileSync(join(root, rel), "\n");
    found.set(rel, readFileSync(join(root, rel)));
  }

  const run = spawnSync(process.execPath, [join(root, GENERATOR)], { encoding: "utf8" });
  assert.equal(run.status, 0, run.stderr);

  const pins = manifest(readFileSync(join(root, "MANIFEST.sha256"), "utf8"));
  assert.deepEqual([...pins.keys()], [...found.keys()], "the generator pinned another set of files");
  const asFound = [...found].filter(([rel, bytes]) => readFileSync(join(root, rel)).equals(bytes)).map(([rel]) => rel);
  assert.deepEqual(
    asFound,
    SNAPSHOTS,
    `the documentation names ${SNAPSHOTS.join(" and ")} as the pinned files the generator leaves as found; ` +
      `change scripts/README.md, docs/coverage.md, the header of ${GENERATOR} and this list together`,
  );
  for (const rel of asFound) {
    const hash = createHash("sha256").update(found.get(rel)).digest("hex");
    assert.equal(pins.get(rel), hash, `MANIFEST.sha256 does not pin ${rel} as found`);
  }
});

test("no passage says that the generator rewrites every file or that CI fails on any byte change", () => {
  const files = execFileSync("git", ["ls-files", "-z", "--", "*.md"], { cwd: REPO, encoding: "utf8" })
    .split("\0")
    .filter(Boolean);
  assert.ok(files.length > 0, "git ls-files lists no Markdown file");
  const lines = [];
  for (const rel of files) {
    readFileSync(join(REPO, rel), "utf8").split("\n").forEach((line, index) => lines.push([rel, index + 1, line]));
  }
  readFileSync(join(REPO, GENERATOR), "utf8").split("\n").forEach((line, index) => {
    if (line.trimStart().startsWith("//")) lines.push([GENERATOR, index + 1, line]);
  });
  const claims = lines.flatMap(([rel, number, line]) =>
    [...line.matchAll(WHOLE_SET_CLAIM)].map((match) => `${rel}:${number}: "${match[0]}"`),
  );
  assert.deepEqual(
    claims,
    [],
    `the generator leaves ${SNAPSHOTS.join(" and ")} as found and pins them as found, so the byte-pin step passes ` +
      `when one of them changes and MANIFEST.sha256 is refreshed with it; say which files it writes instead:\n` +
      claims.join("\n"),
  );
});

// The passages that say what the generator writes: its entry in
// scripts/README.md, its header comment, and the Status paragraph of
// docs/coverage.md.
function passages() {
  const readme = readFileSync(join(REPO, "scripts", "README.md"), "utf8").split("\n");
  const generator = readFileSync(join(REPO, GENERATOR), "utf8").split("\n");
  const coverage = readFileSync(join(REPO, "docs", "coverage.md"), "utf8").split("\n");
  const status = coverage.indexOf("## Status");
  return [
    ["scripts/README.md", readme.find((line) => line.startsWith("- [`generate-fixtures.mjs`](./generate-fixtures.mjs)"))],
    [GENERATOR, generator.slice(0, generator.findIndex((line) => !line.startsWith("#!") && !line.startsWith("//"))).join("\n")],
    ["docs/coverage.md", status < 0 ? undefined : coverage.slice(status + 1).join("\n").trim().split("\n\n")[0]],
  ];
}

test("the passages that say what the generator writes name the snapshot fixtures it leaves as found", () => {
  for (const [rel, text] of passages()) {
    assert.ok(text, `${rel}: the passage that says what the generator writes was not found`);
    assert.ok(
      text.includes(SNAPSHOT_DIR),
      `${rel} does not name ${SNAPSHOT_DIR}, whose snapshot fixtures MANIFEST.sha256 pins and the generator ` +
        `does not write:\n${text}`,
    );
  }
});
