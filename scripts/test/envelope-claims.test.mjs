// Regression test for what the documentation says an envelope ACCEPT does not
// establish. No check decides whether the issuer of a chain's root link may
// grant the scope it grants, or who may sign a bilateral receipt: the root
// issuerKeyid and the responderKeyid only have to resolve to a key, and
// signatureParams.keyid resolves to the key that signed the request. So both
// reference verifiers accept a chain the request signer issues to itself and a
// receipt the request signer signs. The section of
// fixtures/composition/SCHEMA.md that README.md and docs/coverage.md link, and
// an entry of notCovered in conformance.json, say so. If a verifier comes to
// check the root issuer or the responder, this test changes with the documents.
//
// Usage:  node --test scripts/test/*.test.mjs

import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createPrivateKey, sign } from "node:crypto";
import { mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, posix, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const REPO = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..");
const VERIFIERS = {
  node: [process.execPath, join(REPO, "scripts", "verify.mjs")],
  python: ["python3", join(REPO, "scripts", "verify.py")],
};
const COMPOSITION = "fixtures/composition";
const CHAIN = `${COMPOSITION}/aim-did-rfc9421/delegation-chain-3link.json`;
const RECEIPT = `${COMPOSITION}/aim-did-rfc9421/bilateral-receipt.json`;
const SCHEMA_DOC = `${COMPOSITION}/SCHEMA.md`;
const HEADING = "## What an envelope verdict does not establish";
// GitHub's anchor for HEADING.
const FRAGMENT = "what-an-envelope-verdict-does-not-establish";
const NOT_COVERED =
  "§7 and §8 envelopes — the authority of a chain's root issuer and the identity of a receipt's responder";

const readJson = (rel) => JSON.parse(readFileSync(join(REPO, rel), "utf8"));

// The key that signs every request, the RFC 8032 Test 1 key.
const signerKey = createPrivateKey({ key: readJson("vectors/rfc8032-7-1.json").private.privateKeyJwk, format: "jwk" });

// The JCS form of a value made of strings, arrays and objects: the members of
// an object in the order of their names' UTF-16 code units, which
// Array.prototype.sort() gives, and each string as JSON.stringify writes it.
function jcs(value) {
  if (Array.isArray(value)) return `[${value.map(jcs).join(",")}]`;
  if (typeof value === "object") {
    return `{${Object.keys(value)
      .sort()
      .map((name) => `${JSON.stringify(name)}:${jcs(value[name])}`)
      .join(",")}}`;
  }
  return JSON.stringify(value);
}

const signedBySigner = (payload) => sign(null, Buffer.from(jcs(payload), "utf8"), signerKey).toString("base64");

// delegation-chain-3link.json with its links replaced by one root link whose
// issuer and subject are both signatureParams.keyid, signed with the key that
// signed the request, and without the keyidResolutions entries that only the
// replaced links named. The fixture pins ACCEPT.
function selfIssuedChain({ scope = ["DELETE /api/everything", "POST /api/echo"], maxDepth } = {}) {
  const fx = readJson(CHAIN);
  const keyid = fx.signatureParams.keyid;
  const root = fx.envelope.links[0];
  const payload = {
    type: "root",
    issuerKeyid: keyid,
    subjectKeyid: keyid,
    scope,
    issuedAt: root.issuedAt,
    expiresAt: root.expiresAt,
  };
  fx.envelope.links = [{ index: 0, ...payload, signature: signedBySigner(payload) }];
  fx.envelope.depth = 1;
  if (maxDepth !== undefined) fx.envelope.maxDepth = maxDepth;
  fx.envelope.keyidResolutions = {};
  return fx;
}

// bilateral-receipt.json with signatureParams.keyid as its responder, in the
// signed payload and beside it, and the payload signed with the key that
// signed the request. The fixture pins ACCEPT.
function selfSignedReceipt() {
  const fx = readJson(RECEIPT);
  const { response } = fx.envelope;
  response.responderKeyid = fx.signatureParams.keyid;
  response.receiptPayloadJcs.responderKeyid = fx.signatureParams.keyid;
  response.responderSignatureBase64 = signedBySigner(response.receiptPayloadJcs);
  return fx;
}

// Runs both verifiers once over a scratch directory holding `variants`, an
// object of file name to fixture, and returns each verifier's output as
// { file name: [status, ...the lines printed under it] }.
function runOverVariants(t, variants) {
  const dir = mkdtempSync(join(tmpdir(), "envelope-claims-"));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  for (const [name, fixture] of Object.entries(variants)) {
    writeFileSync(join(dir, name), JSON.stringify(fixture, null, 2) + "\n");
  }
  const blocks = {};
  for (const [verifier, [command, ...args]] of Object.entries(VERIFIERS)) {
    const result = spawnSync(command, [...args, dir], { encoding: "utf8" });
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

// The self-issued chain is accepted when its scope holds the request and
// maxDepth is at least 1, with a scope that also grants DELETE /api/everything.
// The two rejects show that those two conditions decide.
test("both verifiers accept a chain the request signer issues to itself and a receipt it signs", (t) => {
  const accepted = ["PASS", "observed: ACCEPT"];
  const rejected = (category) => ["FAIL", `observed: REJECT[${category}]`];
  const blocks = runOverVariants(t, {
    "chain.json": selfIssuedChain(),
    "chain-max-depth-1.json": selfIssuedChain({ maxDepth: 1 }),
    "chain-max-depth-0.json": selfIssuedChain({ maxDepth: 0 }),
    "chain-request-out-of-scope.json": selfIssuedChain({ scope: ["DELETE /api/everything"] }),
    "receipt.json": selfSignedReceipt(),
  });
  const verdicts = Object.fromEntries(Object.entries(blocks.node).map(([name, block]) => [name, block.slice(0, 2)]));
  assert.deepEqual(verdicts, {
    "chain.json": accepted,
    "chain-max-depth-1.json": accepted,
    "chain-max-depth-0.json": rejected("DEPTH_EXCEEDED"),
    "chain-request-out-of-scope.json": rejected("REQUEST_OUT_OF_SCOPE"),
    "receipt.json": accepted,
  });
  assert.deepEqual(blocks.python, blocks.node);
});

// SCHEMA.md says that the root issuer of each chain fixture is
// signatureParams.keyid, so a root trust policy that accepts it leaves the
// pinned outcomes to the checks the fixtures pin.
test("every chain fixture roots at the request signer", () => {
  const chains = [];
  for (const dir of readdirSync(join(REPO, COMPOSITION), { withFileTypes: true })) {
    if (!dir.isDirectory()) continue;
    for (const name of readdirSync(join(REPO, COMPOSITION, dir.name)).filter((n) => n.endsWith(".json"))) {
      const rel = `${COMPOSITION}/${dir.name}/${name}`;
      const fx = readJson(rel);
      if (fx.envelope?.type !== "aps-delegation-chain-v1") continue;
      chains.push(rel);
      assert.equal(fx.envelope.links[0].issuerKeyid, fx.signatureParams.keyid, rel);
    }
  }
  assert.ok(chains.includes(CHAIN), `no chain fixture found at ${CHAIN}: ${chains.join(", ")}`);
});

test("SCHEMA.md, notCovered, README.md and docs/coverage.md state what an envelope ACCEPT does not establish", () => {
  const lines = readFileSync(join(REPO, SCHEMA_DOC), "utf8").split("\n");
  const start = lines.indexOf(HEADING);
  assert.notEqual(start, -1, `${SCHEMA_DOC} has no line "${HEADING}"`);
  const end = lines.findIndex((line, i) => i > start && line.startsWith("## "));
  const section = lines.slice(start, end === -1 ? undefined : end).join("\n");
  for (const term of ["`issuerKeyid`", "`responderKeyid`", "`signatureParams.keyid`", "delegation-chain-3link.json", "`notCovered`"]) {
    assert.ok(section.includes(term), `the section "${HEADING}" of ${SCHEMA_DOC} does not name ${term}`);
  }

  const entries = readJson("conformance.json").notCovered.map((entry) => entry.specSection);
  assert.ok(entries.includes(NOT_COVERED), `notCovered in conformance.json has no entry "${NOT_COVERED}"`);

  for (const doc of ["README.md", "docs/coverage.md"]) {
    const links = [...readFileSync(join(REPO, doc), "utf8").matchAll(/\]\(([^)\s]+)\)/g)].filter(([, target]) => {
      const [path, fragment] = target.split("#");
      return fragment === FRAGMENT && posix.join(posix.dirname(doc), path) === SCHEMA_DOC;
    });
    assert.ok(links.length > 0, `${doc} does not link ${SCHEMA_DOC}#${FRAGMENT}`);
  }
});
