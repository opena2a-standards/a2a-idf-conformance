#!/usr/bin/env node
// Reference Node.js verifier for A2A-IDF conformance fixtures.
// Pure Node stdlib — no third-party dependencies. Runs on Node ≥ 18
// (Node ships Ed25519 verification through OpenSSL via crypto.verify).
//
// Handles both fixture families:
//   - composition fixtures (fixtures/composition/**): RFC 9421 wire signature
//     + A2A-IDF §6 dual-shape keyid resolution
//   - level fixtures (fixtures/levels/**): A2A-IDF §1 verification levels
//     (SELF_ASSERTED / DOMAIN_VERIFIED / ORGANIZATION_VERIFIED)
// Every fixture is first checked against its family's schema in ../schemas/;
// a fixture missing a required field fails at stage `schema`.
//
// Usage:  node verify.mjs <fixture.json | directory> [...]
// Directories are walked recursively for *.json fixtures.
// Exit code: 0 if every fixture's expected verdict (and reject category,
// when pinned) is met, else 1.

import { lstatSync, readFileSync, readdirSync, statSync } from "node:fs";
import { resolve, join } from "node:path";
import { createHash, createPublicKey, verify as cryptoVerify } from "node:crypto";

// Content-Digest algorithms supported by this verifier (RFC 9530).
// Fixtures may declare the expected digest with any of these prefixes;
// the verifier picks the algorithm from the fixture's expected.contentDigest.
const CONTENT_DIGEST_ALGORITHMS = {
  "sha-256": "sha256",
  "sha-512": "sha512",
};

const ED25519_SPKI_PREFIX = Buffer.from(
  "302a300506032b6570032100",
  "hex",
);
const MULTICODEC_ED25519_PUB = Buffer.from("ed01", "hex");
const BASE58_ALPHABET =
  "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

// Envoys signature/v1 §4.3: the RFC 9421 `tag` an A2A message signature carries.
const A2A_MESSAGE_TAG = "a2a-message";

const IDENTITY_EXTENSION_URI = "https://a2a-protocol.org/extensions/agent-identity";
const IDENTITY_LEVELS = ["SELF_ASSERTED", "DOMAIN_VERIFIED", "ORGANIZATION_VERIFIED"];
const AGENT_ID_URN_RE = /^urn:a2a:agent:[A-Za-z0-9.-]+:[A-Za-z0-9._~-]+:[A-Za-z0-9._~-]+$/;
const TIMESTAMP_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/;

function base58btcDecode(s) {
  if (s.length === 0) return new Uint8Array(0);
  const bytes = [0];
  for (const ch of s) {
    const value = BASE58_ALPHABET.indexOf(ch);
    if (value < 0) throw new Error(`invalid base58 character: ${ch}`);
    let carry = value;
    for (let j = 0; j < bytes.length; j++) {
      carry += bytes[j] * 58;
      bytes[j] = carry & 0xff;
      carry >>= 8;
    }
    while (carry > 0) {
      bytes.push(carry & 0xff);
      carry >>= 8;
    }
  }
  let leadingZeros = 0;
  for (const ch of s) {
    if (ch === "1") leadingZeros++;
    else break;
  }
  const out = Buffer.alloc(leadingZeros + bytes.length);
  for (let i = 0; i < bytes.length; i++) {
    out[leadingZeros + i] = bytes[bytes.length - 1 - i];
  }
  return out;
}

function multibaseToRawEd25519(mb) {
  if (!mb.startsWith("z")) {
    throw new Error(`unsupported multibase prefix in ${mb}`);
  }
  const decoded = base58btcDecode(mb.slice(1));
  if (
    decoded.length !== 34 ||
    decoded[0] !== MULTICODEC_ED25519_PUB[0] ||
    decoded[1] !== MULTICODEC_ED25519_PUB[1]
  ) {
    throw new Error("multibase value is not an Ed25519 multicodec key");
  }
  return decoded.subarray(2);
}

function rawEd25519ToSpkiPem(raw) {
  if (raw.length !== 32) {
    throw new Error(`raw Ed25519 public key must be 32 bytes (got ${raw.length})`);
  }
  const spki = Buffer.concat([ED25519_SPKI_PREFIX, Buffer.from(raw)]);
  const b64 = spki.toString("base64");
  return `-----BEGIN PUBLIC KEY-----\n${b64}\n-----END PUBLIC KEY-----\n`;
}

const PEM_BEGIN = "-----BEGIN PUBLIC KEY-----";
const PEM_END = "-----END PUBLIC KEY-----";
// Both verifiers read a compact-form PEM themselves, by the same rules, and
// hand the crypto library only the key bytes: given the PEM text, that library
// reads past a block of another label, takes a private key, ignores bytes
// after the key, decodes base64 leniently, reads bytes above 0x7f differently
// from one platform to another, and asks for a pass phrase on the terminal when
// the block carries an encryption header. The rules for lines are those of the
// PEM reader in OpenSSL: a line is at most 254 bytes, and the bytes at the end
// of a line that are a space or below it are dropped. A line that would be a
// BEGIN line but for bytes above 0x7f at its end is a BEGIN line of another
// label here.
const PEM_LINE_BYTES = 254;
const UTF8_BOM = "\xef\xbb\xbf";
const isPemTrailing = (byte) => byte <= 0x20;
const isPemTrailingOrNonAscii = (byte) => byte <= 0x20 || byte >= 0x80;

function stripEnd(line, isTrailing) {
  let end = line.length;
  while (end > 0 && isTrailing(line.charCodeAt(end - 1))) end--;
  return line.slice(0, end);
}

// The lines of a PEM, each as a binary string (one character a byte): a line
// ends at a line feed, or after 254 bytes when no line feed comes sooner, and a
// UTF-8 byte order mark at the start of the text is skipped. A lone surrogate
// is encoded as U+FFFD, three bytes.
function pemLines(pem) {
  const data = Buffer.from(pem, "utf8");
  const lines = [];
  let start = 0;
  while (start < data.length) {
    const feed = data.subarray(start, start + PEM_LINE_BYTES).indexOf(0x0a);
    const end = feed < 0 ? start + PEM_LINE_BYTES : start + feed + 1;
    const line = data.subarray(start, end).toString("latin1");
    lines.push(start === 0 && line.startsWith(UTF8_BOM) ? line.slice(UTF8_BOM.length) : line);
    start = end;
  }
  return lines;
}

// The base64 text between the BEGIN PUBLIC KEY line and the END PUBLIC KEY line
// that follows it, as verify.py reads it, or null. The text outside those two
// lines is not part of the key: lines before the BEGIN line are skipped and
// nothing after the END line is read, whatever characters they hold. null when
// the first PEM block is not a PUBLIC KEY block that ends in its END line, or
// when an empty line follows a line of base64 text.
function pemBody(pem) {
  const lines = pemLines(pem);
  let i = 0;
  for (; i < lines.length; i++) {
    const begin = stripEnd(lines[i], isPemTrailingOrNonAscii);
    if (begin.startsWith("-----BEGIN ") && begin.endsWith("-----")) break;
  }
  // The first block is the one read, whatever its label: a block of another
  // label before the key, a private key among them, is never read past.
  if (i === lines.length || stripEnd(lines[i], isPemTrailing) !== PEM_BEGIN) return null;
  const body = [];
  for (i++; i < lines.length; i++) {
    let line = stripEnd(lines[i], isPemTrailing);
    if (line.startsWith("-----END ")) return line === PEM_END ? body.join("") : null;
    // A line of the body ends at its first NUL, as OpenSSL reads it.
    line = line.split("\0", 1)[0];
    if (line === "") {
      // Empty lines may come before the base64 text (RFC 7468 Figure 1), never
      // within or after it.
      if (body.length > 0) return null;
      continue;
    }
    body.push(line);
  }
  return null;
}

// A PEM that cannot be read, or one that holds a key of another type (RSA, EC),
// is reported in one wording, as verify.py words it. The body must be the
// base64 text of the key bytes character for character: Buffer skips a
// character outside the base64 alphabet and reads the URL-safe alphabet too, so
// the key bytes are encoded again and compared with the body.
function ed25519KeyFromPem(pem) {
  const text = pemBody(pem);
  const der = Buffer.from(text ?? "", "base64");
  if (
    text === null ||
    der.toString("base64") !== text ||
    der.length !== ED25519_SPKI_PREFIX.length + 32 ||
    !der.subarray(0, ED25519_SPKI_PREFIX.length).equals(ED25519_SPKI_PREFIX)
  ) {
    throw new Error("compact-form publicKeyPem is not an Ed25519 SPKI PEM");
  }
  return createPublicKey({ key: der, format: "der", type: "spki" });
}

function extractPublicKeyFromKeyidResolution(kr) {
  if (kr.shape === "compact") {
    if (typeof kr.publicKeyPem !== "string") {
      throw new Error("compact-form keyidResolution missing publicKeyPem");
    }
    return ed25519KeyFromPem(kr.publicKeyPem);
  }
  if (kr.shape !== "did-json") {
    throw new Error(`unsupported keyidResolution shape: ${kr.shape}`);
  }
  const methods = kr.document?.verificationMethod;
  if (!Array.isArray(methods) || methods.length === 0) {
    throw new Error("DID Document has no verificationMethod entries");
  }
  // Prefer assertionMethod-referenced verificationMethod when present. An entry
  // that is not a JSON object (null among them) carries no key encoding.
  const preferredId = pickAssertionMethodId(kr.document);
  const method =
    methods.find((m) => preferredId !== null && m?.id === preferredId) ??
    methods[0];

  if (typeof method?.publicKeyMultibase === "string") {
    const raw = multibaseToRawEd25519(method.publicKeyMultibase);
    const pem = rawEd25519ToSpkiPem(raw);
    return createPublicKey({ key: pem, format: "pem" });
  }
  if (
    method?.publicKeyJwk &&
    method.publicKeyJwk.kty === "OKP" &&
    method.publicKeyJwk.crv === "Ed25519" &&
    typeof method.publicKeyJwk.x === "string"
  ) {
    return createPublicKey({ key: method.publicKeyJwk, format: "jwk" });
  }
  throw new Error("DID verificationMethod has no usable Ed25519 key encoding");
}

function pickAssertionMethodId(doc) {
  if (!Array.isArray(doc?.assertionMethod)) return null;
  for (const entry of doc.assertionMethod) {
    if (typeof entry === "string") return entry;
    if (entry && typeof entry.id === "string") return entry.id;
  }
  return null;
}

function buildSignatureBase(input, params) {
  const components = params.components;
  const lines = [];
  for (const c of components) {
    if (c === "@method") {
      lines.push(`"@method": ${input.method.toUpperCase()}`);
    } else if (c === "@path") {
      lines.push(`"@path": ${input.path}`);
    } else if (c === "content-digest") {
      lines.push(`"content-digest": ${input.contentDigest}`);
    } else {
      throw new Error(`unsupported component: ${c}`);
    }
  }
  const list = components.map((c) => `"${c}"`).join(" ");
  const paramStr = serializeParams(params);
  lines.push(`"@signature-params": (${list});${paramStr}`);
  return lines.join("\n");
}

function serializeParams(p) {
  const parts = [
    `keyid="${p.keyid}"`,
    `created=${p.created}`,
    `nonce="${p.nonce}"`,
  ];
  // A null tag is treated as an absent tag, never serialized as tag="null".
  if (p.tag !== undefined && p.tag !== null) parts.push(`tag="${p.tag}"`);
  return parts.join(";");
}

function buildSignatureInput(params) {
  const list = params.components.map((c) => `"${c}"`).join(" ");
  return `sig1=(${list});${serializeParams(params)}`;
}

function parseSignatureHeader(header) {
  // Strict accept of `sig1=:<base64>:`.
  if (!header.startsWith("sig1=:") || !header.endsWith(":")) return null;
  return Buffer.from(header.slice(6, -1), "base64");
}

// Gate a fixture's observed verdict/category against its pinned expectation.
function gateVerdict(path, expected, verdict, category) {
  const expectedResult = (expected.verifyResult ?? "ACCEPT").toUpperCase();
  const expectedCategory = expected.rejectCategory ?? null;
  const observed = verdict === "ACCEPT" ? "ACCEPT" : `REJECT[${category}]`;
  if (verdict !== expectedResult) {
    return {
      path,
      ok: false,
      observed,
      stage: "verdict",
      reason: `verify result ${observed} != expected ${expectedResult}`,
    };
  }
  if (verdict === "REJECT" && expectedCategory !== null && category !== expectedCategory) {
    return {
      path,
      ok: false,
      observed,
      stage: "reject-category",
      reason: `reject category ${category} != expected ${expectedCategory}`,
    };
  }
  return { path, ok: true, observed };
}

// --- composition fixtures (RFC 9421 wire layer + §6 keyid resolution) ----------

// The fixture has passed the schema stage (verifyFixture), so its required
// blocks are present and the optional crossSuiteEquivalence block and its
// `envoys` member, when present, are JSON objects.
function verifyCompositionFixture(fixture, path) {
  const expected = fixture.expected;

  // Recompute Content-Digest from body — confirms the fixture is internally consistent.
  // Algorithm is taken from the prefix of expected.contentDigest (RFC 9530).
  const bodyBytes = Buffer.from(
    fixture.input.body ?? "",
    fixture.input.bodyEncoding ?? "utf-8",
  );
  const expectedDigest = expected.contentDigest ?? "";
  const algMatch = expectedDigest.match(/^([a-z0-9-]+)=:/);
  const algLabel = algMatch ? algMatch[1] : "sha-256";
  const nodeAlg = CONTENT_DIGEST_ALGORITHMS[algLabel];
  if (!nodeAlg) {
    return {
      path,
      ok: false,
      stage: "content-digest",
      reason: `unsupported content-digest algorithm: ${algLabel}`,
    };
  }
  const recomputedDigest = `${algLabel}=:${createHash(nodeAlg)
    .update(bodyBytes)
    .digest("base64")}:`;
  if (recomputedDigest !== expected.contentDigest) {
    return {
      path,
      ok: false,
      stage: "content-digest",
      reason: `recomputed ${recomputedDigest} != expected ${expected.contentDigest}`,
    };
  }

  // Reconstruct the signature base and compare against the published one.
  const base = buildSignatureBase(
    { ...fixture.input, contentDigest: recomputedDigest },
    fixture.signatureParams,
  );
  if (base !== expected.signatureBase) {
    return {
      path,
      ok: false,
      stage: "signature-base",
      reason: "reconstructed base does not match fixture.expected.signatureBase",
      reconstructed: base,
      expected: expected.signatureBase,
    };
  }

  // Reconstruct the Signature-Input header.
  const sigInput = buildSignatureInput(fixture.signatureParams);
  if (sigInput !== expected.signatureInput) {
    return {
      path,
      ok: false,
      stage: "signature-input",
      reason: `reconstructed ${sigInput} != expected ${expected.signatureInput}`,
    };
  }

  // Envoys §4.3 tag rule, an application requirement on the signature
  // parameters (RFC 9421 §3.2.1), checked before any cryptography. An absent
  // (or null) tag is treated as `a2a-message` for back-compat; any other tag
  // marks a signature produced for a different application, which is rejected
  // even when it verifies.
  const tag = fixture.signatureParams.tag ?? A2A_MESSAGE_TAG;
  if (tag !== A2A_MESSAGE_TAG) {
    const gate = gateVerdict(path, expected, "REJECT", "TAG_MISMATCH");
    if (!gate.ok) gate.reason += ` (tag "${tag}" is not "${A2A_MESSAGE_TAG}")`;
    return gate;
  }

  // Extract the public key per A2A-IDF §6 dual-shape resolution.
  let publicKey;
  try {
    publicKey = extractPublicKeyFromKeyidResolution(fixture.keyidResolution);
  } catch (err) {
    return {
      path,
      ok: false,
      stage: "public-key-extraction",
      reason: err.message,
    };
  }

  // A byte-identity claim is only checkable against a pinned value, so a claim
  // without one is a malformed fixture, never a skipped comparison.
  const cse = fixture.crossSuiteEquivalence?.envoys;
  if (cse?.byteIdentical === true && !isNonEmptyString(cse.expectedSignatureBase64)) {
    return {
      path,
      ok: false,
      stage: "cross-suite-equivalence",
      reason:
        "crossSuiteEquivalence.envoys.byteIdentical is true but expectedSignatureBase64 is missing, empty or not a string",
    };
  }

  // Verify Ed25519 signature.
  const sigBytes = parseSignatureHeader(expected.signature);
  if (sigBytes === null) {
    return { path, ok: false, stage: "signature-parse", reason: "malformed Signature header" };
  }
  const baseBytes = Buffer.from(base, "utf-8");
  const ok = cryptoVerify(null, baseBytes, publicKey, sigBytes);

  // A signature that fails to verify against the resolved key (tampered bytes,
  // a substituted key, or a tampered body, since content-digest is a signed
  // component) is SIGNATURE_INVALID. When the fixture declares an Envoys
  // byte-match, a signature that verifies but is not the pinned vector is
  // CROSS_SUITE_MISMATCH. The comparison uses the bytes just verified, never
  // expected.signatureBase64, which a fixture can set independently of the
  // Signature header.
  let observed = { verdict: "ACCEPT" };
  if (!ok) {
    observed = { verdict: "REJECT", category: "SIGNATURE_INVALID" };
  } else if (cse?.byteIdentical === true) {
    if (sigBytes.toString("base64") !== cse.expectedSignatureBase64) {
      observed = {
        verdict: "REJECT",
        category: "CROSS_SUITE_MISMATCH",
        reason: `verified signature does not byte-match Envoys ${reasonText(cse.vector)}`,
      };
    }
  }

  const gate = gateVerdict(path, expected, observed.verdict, observed.category);
  if (!gate.ok && observed.reason) gate.reason += ` (${observed.reason})`;
  return gate;
}

// --- level fixtures (A2A-IDF §1 verification levels) ----------------------------

function b64urlDecode(s) {
  return Buffer.from(s, "base64url");
}

function b64urlNoPad(buf) {
  return Buffer.from(buf).toString("base64url");
}

// Minimal RFC 8785 (JCS) for the restricted value domain used by level
// fixtures: objects, arrays, and strings only (no numbers, booleans, null).
// Within that domain, sorted-key compact JSON is exactly the JCS form.
// Array.prototype.sort() compares UTF-16 code units, which is the property
// order RFC 8785 §3.2.3 requires (including keys outside the BMP).
// The walk keeps its own stack instead of recursing, so a deeply nested member
// reaches a verdict here and in verify.py rather than overflowing the call stack.
// A string on the stack is output text; a { value } entry is still to be written.
function jcs(root) {
  const out = [];
  const todo = [{ value: root }];
  const pushReversed = (entries) => {
    for (let i = entries.length - 1; i >= 0; i--) todo.push(entries[i]);
  };
  while (todo.length > 0) {
    const entry = todo.pop();
    if (typeof entry === "string") {
      out.push(entry);
      continue;
    }
    const { value } = entry;
    if (Array.isArray(value)) {
      const entries = ["["];
      value.forEach((v, i) => {
        if (i > 0) entries.push(",");
        entries.push({ value: v });
      });
      entries.push("]");
      pushReversed(entries);
    } else if (value !== null && typeof value === "object") {
      const entries = ["{"];
      Object.keys(value)
        .sort()
        .forEach((k, i) => entries.push(`${i > 0 ? "," : ""}${JSON.stringify(k)}:`, { value: value[k] }));
      entries.push("}");
      pushReversed(entries);
    } else if (typeof value === "string") {
      out.push(JSON.stringify(value));
    } else {
      throw new Error(`value type outside the fixture JCS domain: ${typeof value}`);
    }
  }
  return out.join("");
}

function isNonEmptyString(v) {
  return typeof v === "string" && v.length > 0;
}

// RegExp.test coerces its argument, so ["2026-01-01T00:00:00Z"] would match.
function isTimestamp(v) {
  return typeof v === "string" && TIMESTAMP_RE.test(v);
}

// A non-array attestations value (string, object, number) carries no attestation.
function attestationsOf(p) {
  return Array.isArray(p.attestations) ? p.attestations : [];
}

// With the `u` flag a surrogate pair is one code point, so this class matches
// lone surrogates only.
const LONE_SURROGATE_RE = /[\uD800-\uDFFF]/u;

// True when a string or property name anywhere in `value` holds a lone
// surrogate, which has no UTF-8 encoding and which RFC 8785 §3.2.2.2 forbids.
// Iterative for the reason given at jcs().
function hasLoneSurrogate(root) {
  const todo = [root];
  while (todo.length > 0) {
    const value = todo.pop();
    if (typeof value === "string") {
      if (LONE_SURROGATE_RE.test(value)) return true;
    } else if (Array.isArray(value)) {
      for (const v of value) todo.push(v);
    } else if (value !== null && typeof value === "object") {
      for (const [k, v] of Object.entries(value)) todo.push(k, v);
    }
  }
  return false;
}

function ed25519KeyFromJwk(jwk) {
  if (
    !jwk ||
    jwk.kty !== "OKP" ||
    jwk.crv !== "Ed25519" ||
    !isNonEmptyString(jwk.x) ||
    b64urlDecode(jwk.x).length !== 32
  ) {
    return null;
  }
  return createPublicKey({
    key: { kty: "OKP", crv: "Ed25519", x: jwk.x },
    format: "jwk",
  });
}

function hostnameOf(url) {
  // new URL() coerces its argument, so ["https://example.com"] would parse.
  if (typeof url !== "string") return null;
  try {
    // A URL without a host (mailto:, urn:) yields "", treated as unparseable.
    return new URL(url).hostname || null;
  } catch {
    return null;
  }
}

function reject(category, reason) {
  return { verdict: "REJECT", category, reason };
}

// A fixture value quoted in a reject reason: a string as it is, and any other
// value by its JSON type, as verify.py words it. Each runtime converts a value
// that is not a string to text in its own way, and Array.prototype.toString
// recurses once per level of nesting, so it overflows the call stack on a
// deeply nested array.
function reasonText(v) {
  if (typeof v === "string") return v;
  return v === undefined ? "(missing)" : `a JSON ${jsonType(v)}`;
}

// Evaluate the identity declaration. Returns {verdict, category, reason}.
// The check order is part of the cross-implementation contract. It is the
// numbered list under "Check order" in fixtures/levels/README.md, which is not
// shape-first: some shape checks run between binding checks.
function evaluateIdentity(fixture) {
  const card = fixture.agentCard;
  const extensions = card?.capabilities?.extensions;
  if (!Array.isArray(extensions)) {
    return reject("SHAPE_INVALID", "agentCard.capabilities.extensions missing");
  }
  const ext = extensions.find((e) => e?.uri === IDENTITY_EXTENSION_URI);
  // typeof is "object" for an array too, which verify.py does not take as params.
  if (!ext || jsonType(ext.params) !== "object") {
    return reject("SHAPE_INVALID", "agent-identity extension (or its params) missing");
  }
  const p = ext.params;
  if (!IDENTITY_LEVELS.includes(p.identityLevel)) {
    return reject("SHAPE_INVALID", `unknown identityLevel: ${reasonText(p.identityLevel)}`);
  }
  if (p.agentId !== undefined && !(typeof p.agentId === "string" && AGENT_ID_URN_RE.test(p.agentId))) {
    return reject(
      "SHAPE_INVALID",
      `agentId is not a urn:a2a:agent:{domain}:{agent-name}:{version} URN: ${reasonText(p.agentId)}`,
    );
  }
  const pk = p.publicKey;
  if (!pk || ed25519KeyFromJwk(pk) === null || !isNonEmptyString(pk.kid)) {
    return reject("SHAPE_INVALID", "publicKey is not an Ed25519 OKP JWK with a kid");
  }

  if (p.identityLevel === "SELF_ASSERTED") {
    // Level 0 makes no verifiable claim beyond well-formedness. A conforming
    // client MUST NOT treat the agent as verified (Security Considerations).
    return { verdict: "ACCEPT" };
  }
  if (p.identityLevel === "DOMAIN_VERIFIED") {
    return evaluateDomainVerified(fixture, card, p, pk);
  }
  return evaluateOrganizationVerified(fixture, p, pk);
}

function evaluateDomainVerified(fixture, card, p, pk) {
  const att = attestationsOf(p).find((a) => a?.type === "domain");
  if (!att) return reject("SHAPE_INVALID", "DOMAIN_VERIFIED requires a domain attestation");
  if (!isNonEmptyString(p.agentId)) {
    return reject("SHAPE_INVALID", "DOMAIN_VERIFIED requires an agentId");
  }
  const domain = hostnameOf(card.provider?.url);
  if (domain === null) return reject("SHAPE_INVALID", "provider.url missing or unparseable");
  if (att.domain !== domain) {
    return reject("DOMAIN_MISMATCH", `attestation domain ${reasonText(att.domain)} != provider domain ${domain}`);
  }
  const dnsTxt = fixture.evidence?.dnsTxt;
  if (!dnsTxt || !isNonEmptyString(dnsTxt.recordName) || !isNonEmptyString(dnsTxt.recordValue)) {
    return reject("SHAPE_INVALID", "evidence.dnsTxt.{recordName,recordValue} missing");
  }
  if (dnsTxt.recordName !== `_a2a-identity.${domain}`) {
    return reject("DOMAIN_MISMATCH", `record name ${dnsTxt.recordName} != _a2a-identity.${domain}`);
  }
  // A field the record does not carry is quoted as (missing).
  const fields = {};
  for (const part of dnsTxt.recordValue.split("; ")) {
    const eq = part.indexOf("=");
    if (eq > 0) fields[part.slice(0, eq)] = part.slice(eq + 1);
  }
  if (fields.v !== "a2a1") {
    return reject("SHAPE_INVALID", `unsupported record version: ${reasonText(fields.v)}`);
  }
  const urnParts = p.agentId.split(":");
  if (urnParts[3] !== domain) {
    return reject("DOMAIN_MISMATCH", `agentId domain ${urnParts[3]} != provider domain ${domain}`);
  }
  if (fields.agent !== urnParts[4]) {
    return reject("AGENT_MISMATCH", `record agent ${reasonText(fields.agent)} != agentId name ${urnParts[4]}`);
  }
  if (fields.kid !== pk.kid) {
    return reject("KID_MISMATCH", `record kid ${reasonText(fields.kid)} != declared kid ${pk.kid}`);
  }
  const fp = b64urlNoPad(createHash("sha256").update(b64urlDecode(pk.x)).digest());
  if (fields.fp !== fp) {
    return reject("FINGERPRINT_MISMATCH", `record fp ${reasonText(fields.fp)} != computed ${fp}`);
  }
  return { verdict: "ACCEPT" };
}

function evaluateOrganizationVerified(fixture, p, pk) {
  const att = attestationsOf(p).find((a) => a?.type === "organization");
  if (!att) return reject("SHAPE_INVALID", "ORGANIZATION_VERIFIED requires an organization attestation");
  const shapeOk =
    att.issuer && isNonEmptyString(att.issuer.name) && isNonEmptyString(att.issuer.kid) &&
    isNonEmptyString(att.issuer.url) &&
    att.subject && isNonEmptyString(att.subject.organization) &&
    isNonEmptyString(att.subject.agentId) && isNonEmptyString(att.subject.kid) &&
    isTimestamp(att.verifiedAt) && isTimestamp(att.expiresAt) &&
    isNonEmptyString(att.signature);
  if (!shapeOk) return reject("SHAPE_INVALID", "organization attestation is missing required fields");
  // The attestation is signed over its JCS form, which a lone surrogate cannot enter.
  if (hasLoneSurrogate(att)) {
    return reject("SHAPE_INVALID", "organization attestation holds a lone surrogate");
  }
  if (att.subject.agentId !== p.agentId || att.subject.kid !== pk.kid) {
    return reject("SUBJECT_MISMATCH", "attestation subject does not bind to the declared agentId/kid");
  }
  const ev = fixture.evidence ?? {};
  const issuerKey = ed25519KeyFromJwk(ev.issuerPublicKey);
  if (issuerKey === null || !isTimestamp(ev.validationTime)) {
    return reject("SHAPE_INVALID", "evidence.{issuerPublicKey,validationTime} missing or malformed");
  }
  const unsigned = { ...att };
  delete unsigned.signature;
  const tbs = Buffer.from(jcs(unsigned), "utf-8");
  const sig = b64urlDecode(att.signature);
  if (sig.length !== 64 || !cryptoVerify(null, tbs, issuerKey, sig)) {
    return reject("SIGNATURE_INVALID", "registry signature does not verify over the attestation JCS form");
  }
  // Timestamps share the fixed YYYY-MM-DDTHH:MM:SSZ format (enforced above),
  // so lexicographic comparison is chronological comparison.
  if (ev.validationTime < att.verifiedAt) {
    return reject("NOT_YET_VALID", `validationTime ${ev.validationTime} precedes verifiedAt ${att.verifiedAt}`);
  }
  if (ev.validationTime > att.expiresAt) {
    return reject("EXPIRED", `validationTime ${ev.validationTime} past expiresAt ${att.expiresAt}`);
  }
  return { verdict: "ACCEPT" };
}

function verifyLevelFixture(fixture, path) {
  const observed = evaluateIdentity(fixture);
  const gate = gateVerdict(path, fixture.expected ?? {}, observed.verdict, observed.category);
  if (!gate.ok && observed.reason && !gate.reason.includes(observed.reason)) {
    gate.reason += ` (${observed.reason})`;
  }
  return gate;
}

// --- fixture schema (schemas/*.json) ---------------------------------------------

// The committed JSON Schemas are the required-field contract for each fixture
// family. This checker implements exactly the keywords those schemas use:
// type, const, enum, required, properties, allOf, and if/then.
const SCHEMA_FILES = {
  composition: "fixture-composition-v1.json",
  level: "fixture-level-v1.json",
};
let schemaCache = null;

function loadSchemas() {
  if (schemaCache === null) {
    schemaCache = {};
    for (const [family, file] of Object.entries(SCHEMA_FILES)) {
      const url = new URL(`../schemas/${file}`, import.meta.url);
      schemaCache[family] = JSON.parse(readFileSync(url, "utf-8"));
    }
  }
  return schemaCache;
}

// The fixture's $schema selects its family; without a known $schema, a fixture
// carrying an agentCard is a level fixture and anything else is composition.
function fixtureFamily(fixture, schemas) {
  for (const [family, schema] of Object.entries(schemas)) {
    if (fixture?.$schema === schema.$id) return family;
  }
  return fixture?.agentCard !== undefined ? "level" : "composition";
}

function jsonType(v) {
  if (v === null) return "null";
  if (Array.isArray(v)) return "array";
  if (typeof v === "number") return Number.isInteger(v) ? "integer" : "number";
  return typeof v;
}

// A string, a boolean, null and a safe integer as JSON text, and any other
// value by its JSON type, as verify.py words a value: json.dumps there raises
// on a deeply nested array or object, and the two runtimes write a number
// outside the safe integers differently (1e-7 and 1e-07, null and Infinity for
// 1e400, 12345678901234567000 and 12345678901234567890).
function jsonText(v) {
  const type = jsonType(v);
  if (type === "array" || type === "object" || (typeof v === "number" && !Number.isSafeInteger(v))) {
    return `a JSON ${type}`;
  }
  return JSON.stringify(v);
}

function fieldPath(path, key) {
  return path === "" ? key : `${path}.${key}`;
}

// Returns the first violation as a message, or null when the value conforms.
// `type` is a type name or a list of them.
function schemaViolation(schema, value, path) {
  const where = path === "" ? "fixture" : path;
  const type = jsonType(value);
  if (schema.type !== undefined) {
    const types = [schema.type].flat();
    if (!types.some((t) => t === type || (t === "number" && type === "integer"))) {
      const names = types.join(" or ");
      return path === "" ? `fixture is not a JSON ${names}` : `${path} is present but is not a JSON ${names}`;
    }
  }
  if (schema.const !== undefined && value !== schema.const) {
    return `${where}: expected ${jsonText(schema.const)}, got ${jsonText(value)}`;
  }
  if (schema.enum !== undefined && !schema.enum.includes(value)) {
    return `${where}: ${jsonText(value)} is not one of ${schema.enum.map((v) => jsonText(v)).join(", ")}`;
  }
  if (type === "object") {
    for (const key of schema.required ?? []) {
      if (!Object.hasOwn(value, key)) return `missing required field ${fieldPath(path, key)}`;
    }
    for (const [key, sub] of Object.entries(schema.properties ?? {})) {
      if (!Object.hasOwn(value, key)) continue;
      const violation = schemaViolation(sub, value[key], fieldPath(path, key));
      if (violation !== null) return violation;
    }
  }
  for (const sub of schema.allOf ?? []) {
    const violation = schemaViolation(sub, value, path);
    if (violation !== null) return violation;
  }
  if (schema.if !== undefined && schema.then !== undefined && schemaViolation(schema.if, value, path) === null) {
    return schemaViolation(schema.then, value, path);
  }
  return null;
}

// --- driver ---------------------------------------------------------------------

function verifyFixture(path) {
  const fixture = JSON.parse(readFileSync(path, "utf-8"));
  const schemas = loadSchemas();
  const family = fixtureFamily(fixture, schemas);
  const violation = schemaViolation(schemas[family], fixture, "");
  if (violation !== null) {
    return { path, ok: false, stage: "schema", reason: violation };
  }
  if (family === "level") return verifyLevelFixture(fixture, path);
  return verifyCompositionFixture(fixture, path);
}

// Whether a path given on the command line is a directory, through a symlink
// too. A path whose status cannot be read (missing, a symlink loop) is not one.
function isDirectory(path) {
  try {
    return statSync(path).isDirectory();
  } catch {
    return false;
  }
}

// The listing of a `*.json` path met during the walk, or null for one that is a
// directory once symlinks are followed (a symlink to a directory is not a
// fixture). A regular file is listed, and so is a path whose status cannot be
// read at all (a dangling symlink, a symlink loop), which is then reported as
// ERROR when it is read. A path of any other kind (a socket, a FIFO, a device)
// is listed with an error and never read, as in verify.py: reading a socket
// fails, and reading a FIFO waits until a writer opens it.
function fixtureListing(path) {
  let status;
  try {
    status = statSync(path);
  } catch {
    return { path };
  }
  if (status.isDirectory()) return null;
  if (status.isFile()) return { path };
  return { path, error: new Error(`not a regular file: ${path}`) };
}

// The fixtures `arg` names, each with the error that kept it from being listed.
// A path that is not a directory is returned as it is, so one that cannot be
// read (missing, a symlink loop, no read permission) fails inside the
// per-fixture loop and is reported as ERROR, as verify.py does. A directory is
// walked for `*.json` files without following symlinks to directories, as in
// verify.py: a followed link lists the fixtures under it a second time, and
// once more per level when it points at a parent directory. A directory that
// cannot be listed, and an entry whose status cannot be read (every entry of a
// directory that can be listed but not searched, which may be a directory of
// fixtures), is returned with its error, so a permissions problem is reported
// as ERROR rather than read as a pass.
function collectFixtures(arg) {
  const abs = resolve(arg);
  if (!isDirectory(abs)) return [{ path: abs }];
  const out = [];
  const walk = (dir) => {
    let entries;
    try {
      entries = readdirSync(dir).sort();
    } catch (error) {
      out.push({ path: dir, error });
      return;
    }
    for (const entry of entries) {
      const p = join(dir, entry);
      let status;
      try {
        status = lstatSync(p);
      } catch (error) {
        out.push({ path: p, error });
        continue;
      }
      if (status.isDirectory()) {
        walk(p);
      } else if (p.endsWith(".json")) {
        const listing = fixtureListing(p);
        if (listing !== null) out.push(listing);
      }
    }
  };
  walk(abs);
  return out;
}

// Prints a line that can quote a fixture string as it is. A C0 or C1 control
// character (U+0000 to U+001F, U+007F to U+009F) is written as a lowercase
// \uXXXX escape, as in verify.py, so a fixture cannot break the line or send the
// terminal a command. So is a backslash followed by "u" (\u005c), so a \u in the
// line always begins an escape: a value of the six characters \u001b is not
// printed as U+001B is. A line of JSON text (jsonText true) keeps its
// backslashes, which JSON text writes as \\ already.
function report(line, jsonText = false) {
  const pattern = jsonText ? /[\u0000-\u001f\u007f-\u009f]/g : /[\u0000-\u001f\u007f-\u009f]|\\(?=u)/g;
  console.log(line.replace(pattern, (c) => `\\u${c.charCodeAt(0).toString(16).padStart(4, "0")}`));
}

function main() {
  const args = process.argv.slice(2);
  if (args.length === 0) {
    console.error("usage: node verify.mjs <fixture.json | directory> [...]");
    process.exit(2);
  }

  const paths = args.flatMap(collectFixtures);
  let passCount = 0;
  let failCount = 0;
  for (const { path: abs, error: listingError } of paths) {
    try {
      if (listingError !== undefined) throw listingError;
      const result = verifyFixture(abs);
      if (result.ok) {
        passCount++;
        report(`PASS  ${abs}`);
      } else {
        failCount++;
        report(`FAIL  ${abs}`);
      }
      if (result.observed !== undefined) {
        report(`      observed: ${result.observed}`);
      }
      if (!result.ok) {
        report(`      stage:  ${result.stage}`);
        // A schema reason quotes a string as JSON text.
        report(`      reason: ${result.reason}`, result.stage === "schema");
        if (result.reconstructed !== undefined) {
          report(`      reconstructed: ${JSON.stringify(result.reconstructed)}`, true);
          report(`      expected:      ${JSON.stringify(result.expected)}`, true);
        }
      }
    } catch (err) {
      failCount++;
      report(`ERROR ${abs}`);
      // A failed system call (ENOENT, ENOTDIR, EACCES, ELOOP) and an entry the
      // walk does not read are problems with the input, and their message names
      // the path; a stack trace is kept for a verifier fault. The trace is one
      // report line, its line feeds written as \u000a, because its message can
      // quote fixture text (a JSON.parse syntax error quotes the text around the
      // error) and a line feed there would start a line the parity gate reads.
      // collectFixtures walks directories, so no directory is read as a file
      // (EISDIR, whose message names no path).
      const inputError = err.syscall !== undefined || err === listingError;
      if (inputError) report(`      ${err.message}`);
      else report(`      ${err.stack ?? err.message}`);
    }
  }
  console.log(`summary: ${passCount} pass, ${failCount} fail (${paths.length} fixtures)`);
  process.exit(failCount === 0 ? 0 : 1);
}

main();
