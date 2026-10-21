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
import { createPrivateKey, createPublicKey, sign } from "node:crypto";
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

// Copies of the committed receipt whose responder is the request signer, by
// file name. The responder keyid is signatureParams.keyid or a second keyid,
// and each entry for the second keyid holds the request's key in another form.
function selfAcknowledgedReceipts() {
  const source = readJson(RECEIPT);
  const secondKeyid = "did:web:envoys.me:agents:second-keyid";
  // The request's DID document gives its key as publicKeyMultibase, then as
  // publicKeyJwk; the counterparty's gives its own key as publicKeyMultibase.
  const [multibaseMethod, jwkMethod] = source.keyidResolution.document.verificationMethod;
  const [counterpartyMethod] =
    source.envelope.keyidResolutions[source.envelope.response.responderKeyid].document.verificationMethod;
  const didJson = (verificationMethod, assertionMethod) => ({
    shape: "did-json",
    document: { verificationMethod, assertionMethod },
  });
  const withSecondKeyid = (keyidResolution) =>
    selfAcknowledgedReceipt(secondKeyid, { [secondKeyid]: keyidResolution });
  return {
    // The request's keyid resolves through keyidResolution, so
    // keyidResolutions holds no entry for it.
    "responder-is-request-keyid.json": selfAcknowledgedReceipt(source.signatureParams.keyid, {}),
    // A second keyid whose entry is a copy of the request's keyidResolution.
    "responder-keyid-resolves-to-request-key.json": withSecondKeyid(source.keyidResolution),
    // A compact-form entry: the request's key as an SPKI PEM.
    "responder-keyid-resolves-to-request-key-compact.json": withSecondKeyid({
      shape: "compact",
      publicKeyPem: readJson("vectors/rfc8032-7-1.json").public.pemSpki,
    }),
    // A DID document whose one verificationMethod gives the key as publicKeyJwk.
    "responder-keyid-resolves-to-request-key-jwk.json": withSecondKeyid(didJson([jwkMethod])),
    // A DID document whose first verificationMethod holds the counterparty's
    // key and whose assertionMethod names the second, the request's key.
    "responder-keyid-resolves-to-request-key-assertion-method.json": withSecondKeyid(
      didJson([counterpartyMethod, multibaseMethod], [multibaseMethod.id]),
    ),
  };
}

const ED25519_SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");
const BASE58BTC = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
// The form in which public.pemSpki of vectors/rfc8032-7-1.json holds a key: a
// BEGIN PUBLIC KEY line, one line of base64 text and an END PUBLIC KEY line,
// each ending in a line feed.
const PEM = /^-----BEGIN PUBLIC KEY-----\n([A-Za-z0-9+/]+={0,2})\n-----END PUBLIC KEY-----\n$/;

// The bytes that base58btc text encodes: a zero byte for each leading "1",
// then the text read as a number in base 58, big-endian.
function base58btc(text) {
  let value = 0n;
  for (const char of text) {
    const digit = BASE58BTC.indexOf(char);
    if (digit < 0) throw new Error(`publicKeyMultibase holds ${JSON.stringify(char)}, which is not base58btc`);
    value = value * 58n + BigInt(digit);
  }
  const hex = value === 0n ? "" : value.toString(16);
  const zeros = text.length - text.replace(/^1+/, "").length;
  return Buffer.concat([Buffer.alloc(zeros), Buffer.from(hex.length % 2 ? `0${hex}` : hex, "hex")]);
}

// The 32 bytes of the Ed25519 public key a keyidResolution holds, read by the
// rules both verifiers follow. In a did-json document the key is that of the
// verificationMethod named by the first assertionMethod entry that is a string
// or an object with a string id, else that of the first verificationMethod,
// read from publicKeyMultibase when that is a string and else from
// publicKeyJwk. A compact-form publicKeyPem is read only in the form PEM
// matches. Any other keyidResolution throws, so a key this test cannot read
// fails it.
function rawPublicKey(kr) {
  if (kr?.shape === "compact") {
    const text = typeof kr.publicKeyPem === "string" ? PEM.exec(kr.publicKeyPem)?.[1] : undefined;
    const der = Buffer.from(text ?? "", "base64");
    if (
      text === undefined ||
      der.toString("base64") !== text ||
      der.length !== ED25519_SPKI_PREFIX.length + 32 ||
      !der.subarray(0, ED25519_SPKI_PREFIX.length).equals(ED25519_SPKI_PREFIX)
    ) {
      throw new Error(
        "a compact-form publicKeyPem is not an Ed25519 SPKI PEM in the form of public.pemSpki in vectors/rfc8032-7-1.json",
      );
    }
    return der.subarray(ED25519_SPKI_PREFIX.length);
  }
  if (kr?.shape !== "did-json") throw new Error("a keyidResolution is not a compact or did-json keyidResolution");
  const methods = kr.document?.verificationMethod;
  if (!Array.isArray(methods) || methods.length === 0) {
    throw new Error("a did-json keyidResolution has no verificationMethod entries");
  }
  const assertionMethod = Array.isArray(kr.document.assertionMethod) ? kr.document.assertionMethod : [];
  const preferredId = assertionMethod
    .map((entry) => (typeof entry === "string" ? entry : entry?.id))
    .find((id) => typeof id === "string");
  const method = methods.find((m) => preferredId !== undefined && m?.id === preferredId) ?? methods[0];
  if (typeof method?.publicKeyMultibase === "string") {
    const { publicKeyMultibase } = method;
    const bytes = publicKeyMultibase.startsWith("z") ? base58btc(publicKeyMultibase.slice(1)) : Buffer.alloc(0);
    if (bytes.length !== 34 || bytes[0] !== 0xed || bytes[1] !== 0x01) {
      throw new Error("a publicKeyMultibase is not an Ed25519 multicodec key in base58btc");
    }
    return bytes.subarray(2);
  }
  const jwk = method?.publicKeyJwk;
  if (jwk?.kty === "OKP" && jwk.crv === "Ed25519" && typeof jwk.x === "string") {
    return Buffer.from(createPublicKey({ key: jwk, format: "jwk" }).export({ format: "jwk" }).x, "base64url");
  }
  throw new Error("a verificationMethod has no Ed25519 key in publicKeyMultibase or publicKeyJwk");
}

const RESPONDER_FIELDS = ["envelope.response.responderKeyid", "envelope.response.receiptPayloadJcs.responderKeyid"];

// The fields of RESPONDER_FIELDS in a receipt fixture whose keyid resolves to
// the request's key. A keyid resolves as in both verifiers: signatureParams.keyid
// to the key of keyidResolution, the key the request is verified with, any
// other keyid to the key of its own entry in envelope.keyidResolutions, and a
// keyid without an entry to no key. Keys are compared by their raw public-key
// bytes.
function requestSignerFields(fixture) {
  const requestKey = rawPublicKey(fixture.keyidResolution);
  const resolutions = fixture.envelope.keyidResolutions;
  const keyOf = (keyid) => {
    if (keyid === fixture.signatureParams.keyid) return requestKey;
    return Object.hasOwn(resolutions, keyid) ? rawPublicKey(resolutions[keyid]) : null;
  };
  return RESPONDER_FIELDS.filter((field) =>
    keyOf(field.split(".").reduce((value, member) => value[member], fixture))?.equals(requestKey),
  );
}

test("both verifiers accept a receipt whose responder is the request signer", (t) => {
  const dir = mkdtempSync(join(tmpdir(), "receipt-claims-"));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const variants = selfAcknowledgedReceipts();
  const count = Object.keys(variants).length;
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
    assert.match(
      result.stdout,
      new RegExp(`^summary: ${count} pass, 0 fail, 0 error \\(${count} fixtures\\)$`, "m"),
      output,
    );
    assert.equal(result.status, 0, output);
  }
});

// Both responder fields of each receipt that the test above runs through both
// verifiers resolve to the request's key, and neither field of the committed
// receipt does: its responder keyid resolves to the counterparty's key. A
// publicKeyPem in a form PEM does not match, here with CRLF line ends, throws
// rather than resolve to no key.
test("the comparison flags both responder fields of each receipt the request signer signs, neither of the committed receipt, and throws for a PEM it does not read", () => {
  for (const [name, text] of Object.entries(selfAcknowledgedReceipts())) {
    assert.deepEqual(requestSignerFields(JSON.parse(text)), RESPONDER_FIELDS, name);
  }
  assert.deepEqual(requestSignerFields(readJson(RECEIPT)), [], RECEIPT);
  const keyid = "did:web:envoys.me:agents:second-keyid";
  const publicKeyPem = readJson("vectors/rfc8032-7-1.json").public.pemSpki.replace(/\n/g, "\r\n");
  const crlf = JSON.parse(selfAcknowledgedReceipt(keyid, { [keyid]: { shape: "compact", publicKeyPem } }));
  assert.throws(() => requestSignerFields(crlf), /^Error: a compact-form publicKeyPem is not an Ed25519 SPKI PEM/);
});

test("no fixture's receipt has a responder keyid that resolves to the request's key", () => {
  const root = join(REPO, "fixtures");
  const receipts = readdirSync(root, { recursive: true })
    .filter((name) => name.endsWith(".json"))
    .map((name) => [`fixtures/${name}`, JSON.parse(readFileSync(join(root, name), "utf8"))])
    .filter(([, fixture]) => fixture.envelope?.type === RECEIPT_ENVELOPE);
  assert.ok(receipts.length > 0, "no fixture under fixtures/ carries a bilateral receipt");
  for (const [rel, fixture] of receipts) {
    let fields;
    try {
      fields = requestSignerFields(fixture);
    } catch (err) {
      assert.fail(`${rel}: ${err.message}, so this test cannot compare its responder's key with the request's`);
    }
    assert.deepEqual(
      fields,
      [],
      `${rel}: these fields resolve to the request's key, so a fixture pins an outcome for a receipt whose responder is the request signer; ${CHANGE_TOGETHER}`,
    );
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
