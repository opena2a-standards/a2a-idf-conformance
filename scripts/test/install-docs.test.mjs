// Regression tests for the install commands in README.md, scripts/README.md
// and COSIGNERS.md.
// A Python marked as externally managed (PEP 668) refuses `pip install`
// outside a virtual environment, so each documented `pip install` line must
// run with `python3` resolving to a virtual environment the block created.
//
// Usage:  node --test scripts/test/*.test.mjs

import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, realpathSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";

const REPO = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..");

// The lines of each fenced `bash` block in a Markdown file.
function bashBlocks(text) {
  const blocks = [];
  let current = null;
  for (const line of text.split("\n")) {
    if (current === null) {
      if (/^```bash\s*$/.test(line)) current = [];
    } else if (/^```\s*$/.test(line)) {
      blocks.push(current);
      current = null;
    } else {
      current.push(line);
    }
  }
  return blocks;
}

for (const rel of ["README.md", "scripts/README.md", "COSIGNERS.md"]) {
  test(`${rel}: each pip install line runs inside a virtual environment the block creates`, (t) => {
    const blocks = bashBlocks(readFileSync(join(REPO, rel), "utf8"))
      .map((lines) => ({ lines, pip: lines.findIndex((line) => /^python3 -m pip install\b/.test(line)) }))
      .filter((block) => block.pip !== -1);
    assert.ok(blocks.length > 0, `${rel} has no bash block with a pip install line`);

    for (const { lines, pip } of blocks) {
      const scratch = realpathSync(mkdtempSync(join(tmpdir(), "install-docs-")));
      t.after(() => rmSync(scratch, { recursive: true, force: true }));
      // The scratch directory stands in for the clone, so the clone and cd
      // lines are not run; every other line before the pip line is.
      const setup = lines.slice(0, pip).filter((line) => !/^(git clone|cd)\s/.test(line));
      const script = ["set -e", ...setup, "python3 -c 'import os, sys; print(os.path.realpath(sys.prefix))'"].join("\n");
      const result = spawnSync("bash", ["-c", script], { cwd: scratch, encoding: "utf8", timeout: 120_000 });
      assert.equal(result.status, 0, `${rel}: setup lines failed\n${result.stdout}${result.stderr}`);
      const prefix = result.stdout.trim().split("\n").pop();
      assert.ok(
        prefix.startsWith(scratch + sep),
        `${rel}: python3 before "${lines[pip]}" resolves to ${prefix}, not a virtual environment under the block's directory`,
      );
    }
  });
}
