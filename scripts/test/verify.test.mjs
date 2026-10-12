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

for (const [label, pin] of [["no", undefined], ["an empty", ""]]) {
  test(`byteIdentical: true with ${label} expectedSignatureBase64 is a fixture error`, (t) => {
    const path = writeVariant(t, "fixtures/composition/aim-did-rfc9421/cross-suite-mismatch.json", (fx) => {
      if (pin === undefined) delete fx.crossSuiteEquivalence.envoys.expectedSignatureBase64;
      else fx.crossSuiteEquivalence.envoys.expectedSignatureBase64 = pin;
      fx.expected.verifyResult = "ACCEPT";
      delete fx.expected.rejectCategory;
    });
    for (const [name, argv] of Object.entries(VERIFIERS)) {
      const result = runVerifier(argv, path);
      assert.equal(result.status, 1, `${name}: ${result.stdout}${result.stderr}`);
      assert.match(result.stdout, /^FAIL {2}/m, name);
      assert.match(result.stdout, /stage: +cross-suite-equivalence/, name);
      assert.doesNotMatch(result.stdout, /observed: ACCEPT/, name);
    }
  });
}
