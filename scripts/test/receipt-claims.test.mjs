// Regression tests for what the documents say an ACCEPT of a bilateral receipt
// does not establish. Both reference verifiers resolve the responder's keyid to
// a key and compare the receipt with the request, but no check compares the
// responder's keyid, or the key it resolves to, with the request's: a receipt
// whose responder keyid is signatureParams.keyid, signed with the request's
// key, is accepted, and so is one whose responder keyid is a second keyid that
// resolves to the request's key. The section "Bilateral receipt" of
// fixtures/composition/SCHEMA.md says so, conformance.json lists it under
// notCovered, and README.md and docs/coverage.md link that section. If a
// verifier comes to refuse such a receipt, or a fixture comes to pin an
// outcome for one, the documents change with these tests.
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
const RECEIPT = "fixtures/composition/aim-did-rfc9421/bilateral-receipt.json";
const RECEIPT_ENVELOPE = "aps-bilateral-receipt-v1";
const SCHEMA_DOC = "fixtures/composition/SCHEMA.md";
const SECTION = "Bilateral receipt";
// GitHub's anchor for the heading SECTION.
const ANCHOR = "bilateral-receipt";
// GitHub's anchor for a heading line: its text in lower case, without the
// characters other than letters, digits, spaces, hyphens and underscores, with
// each space a hyphen. A later heading with the same anchor gets "-1" added,
// so a link to ANCHOR reaches only the first.
const anchorOf = (line) =>
  line
    .replace(/^#+ /, "")
    .toLowerCase()
    .replace(/[^\p{L}\p{N} _-]/gu, "")
    .replace(/ /g, "-");
const NOT_SHOWN = "a party other than the request signer received or acknowledged the request";
const NOT_COVERED = {
  specSection:
    "§7 and §8 envelopes — the authority of a chain's root issuer and the identity of a receipt's responder",
  reason:
    "the fixtures pin no trust policy and no expected responder, and an issuerKeyid or responderKeyid only has to resolve to a key, so an ACCEPT does not show that a party other than the request signer granted the scope or received the request",
};
const CHANGE_TOGETHER = `change the section "${SECTION}" of ${SCHEMA_DOC}, the notCovered entry and these tests together`;

const readJson = (rel) => JSON.parse(readFileSync(join(REPO, rel), "utf8"));

// A copy of the committed receipt whose responder keyid is `responderKeyid`,
// with `keyidResolutions` as its envelope.keyidResolutions. It is signed again
// with the request's key, the RFC 8032 Test 1 key. The payload holds only
// strings, so its JCS form is its members sorted by UTF-16 code units, which
// Array.prototype.sort() does, each written by JSON.stringify.
function selfAcknowledgedReceipt(responderKeyid, keyidResolutions) {
  const fixture = readJson(RECEIPT);
  const { response } = fixture.envelope;
  response.responderKeyid = responderKeyid;
  response.receiptPayloadJcs.responderKeyid = responderKeyid;
  const vector = readJson("vectors/rfc8032-7-1.json");
  const requestKey = createPrivateKey({ key: vector.private.privateKeyJwk, format: "jwk" });
  const payload = response.receiptPayloadJcs;
  const members = Object.keys(payload).sort();
  const jcs = `{${members.map((k) => `${JSON.stringify(k)}:${JSON.stringify(payload[k])}`).join(",")}}`;
  response.responderSignatureBase64 = sign(null, Buffer.from(jcs, "utf8"), requestKey).toString("base64");
  fixture.envelope.keyidResolutions = keyidResolutions;
  return JSON.stringify(fixture, null, 2) + "\n";
}

test("both verifiers accept a receipt whose responder is the request signer", (t) => {
  const dir = mkdtempSync(join(tmpdir(), "receipt-claims-"));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const source = readJson(RECEIPT);
  const secondKeyid = "did:web:envoys.me:agents:second-keyid";
  const variants = {
    // The request's keyid resolves through keyidResolution, so
    // keyidResolutions holds no entry for it.
    "responder-is-request-keyid.json": selfAcknowledgedReceipt(source.signatureParams.keyid, {}),
    // A second keyid whose entry is a copy of the request's keyidResolution.
    "responder-keyid-resolves-to-request-key.json": selfAcknowledgedReceipt(secondKeyid, {
      [secondKeyid]: source.keyidResolution,
    }),
  };
  for (const [name, text] of Object.entries(variants)) writeFileSync(join(dir, name), text);
  for (const [verifier, [command, ...args]] of Object.entries(VERIFIERS)) {
    const result = spawnSync(command, [...args, dir], { encoding: "utf8" });
    const output = `${verifier}: ${result.stdout}${result.stderr}`;
    for (const name of Object.keys(variants)) {
      assert.match(
        result.stdout,
        new RegExp(`^PASS {2}.*/${name.replace(/\./g, "\\.")}\\n {6}observed: ACCEPT$`, "m"),
        `${output}\n${CHANGE_TOGETHER}`,
      );
    }
    assert.match(result.stdout, /^summary: 2 pass, 0 fail, 0 error \(2 fixtures\)$/m, output);
    assert.equal(result.status, 0, output);
  }
});

// The comparison is by keyid, and by the responder's entry in keyidResolutions
// against a copy of the request's keyidResolution.
test("no fixture's receipt names the request's keyid as its responder or resolves its responder through a copy of the request's keyidResolution", () => {
  const root = join(REPO, "fixtures");
  const receipts = readdirSync(root, { recursive: true })
    .filter((name) => name.endsWith(".json"))
    .map((name) => [`fixtures/${name}`, JSON.parse(readFileSync(join(root, name), "utf8"))])
    .filter(([, fixture]) => fixture.envelope?.type === RECEIPT_ENVELOPE);
  assert.ok(receipts.length > 0, "no fixture under fixtures/ carries a bilateral receipt");
  for (const [rel, fixture] of receipts) {
    const { response, keyidResolutions } = fixture.envelope;
    for (const [field, keyid] of [
      ["envelope.response.responderKeyid", response.responderKeyid],
      ["envelope.response.receiptPayloadJcs.responderKeyid", response.receiptPayloadJcs.responderKeyid],
    ]) {
      const pinned = `so a fixture pins an outcome for a receipt whose responder is the request signer; ${CHANGE_TOGETHER}`;
      assert.notEqual(keyid, fixture.signatureParams.keyid, `${rel}: ${field} is signatureParams.keyid, ${pinned}`);
      assert.notDeepEqual(
        keyidResolutions[keyid],
        fixture.keyidResolution,
        `${rel}: the keyidResolutions entry for ${field} is a copy of keyidResolution, ${pinned}`,
      );
    }
  }
});

test("SCHEMA.md, conformance.json, README.md and docs/coverage.md say what that ACCEPT does not establish", () => {
  const schema = readFileSync(join(REPO, SCHEMA_DOC), "utf8").split("\n");
  const start = schema.findIndex((line) => /^#{2,3} /.test(line) && line.replace(/^#+ /, "") === SECTION);
  assert.notEqual(start, -1, `${SCHEMA_DOC} has no section "${SECTION}"`);
  assert.deepEqual(
    schema.filter((line) => /^#{1,6} /.test(line) && anchorOf(line) === ANCHOR),
    [schema[start]],
    `${SCHEMA_DOC} has more than one heading with the anchor #${ANCHOR}, so the links reach only the first`,
  );
  const end = schema.findIndex((line, index) => index > start && /^#{1,3} /.test(line));
  const section = schema.slice(start + 1, end === -1 ? undefined : end).join("\n");
  for (const statement of [
    "only has to resolve to a key",
    "two keyids may resolve to one key",
    `does not show that ${NOT_SHOWN}`,
    "No fixture pins an outcome for a receipt whose responder is the request signer",
  ]) {
    assert.ok(section.includes(statement), `the section "${SECTION}" of ${SCHEMA_DOC} does not say "${statement}"`);
  }

  const { notCovered } = readJson("conformance.json");
  assert.deepEqual(
    notCovered.find((entry) => entry.specSection === NOT_COVERED.specSection),
    NOT_COVERED,
    "conformance.json notCovered does not list the identity of a receipt's responder",
  );

  // Each document says it in a sentence that links the section.
  for (const doc of ["README.md", "docs/coverage.md"]) {
    const target = `${posix.relative(posix.dirname(doc), SCHEMA_DOC)}#${ANCHOR}`;
    const sentences = readFileSync(join(REPO, doc), "utf8")
      .split("\n")
      .flatMap((line) => line.split(/(?<=[.!?])\s+/))
      .filter((sentence) => sentence.includes(`](${target})`) || sentence.includes(`](./${target})`));
    assert.ok(
      sentences.some((sentence) => sentence.includes(NOT_SHOWN)),
      `${doc} has no sentence that links ${target} and says "${NOT_SHOWN}"`,
    );
  }
});
