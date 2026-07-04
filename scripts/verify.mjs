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
//
// Usage:  node verify.mjs <fixture.json | directory> [...]
// Directories are walked recursively for *.json fixtures.
// Exit code: 0 if every fixture's expected verdict (and reject category,
// when pinned) is met, else 1.

import { readFileSync, readdirSync, statSync } from "node:fs";
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

function extractPublicKeyFromKeyidResolution(kr) {
  if (kr.shape === "compact") {
    if (typeof kr.publicKeyPem !== "string") {
      throw new Error("compact-form keyidResolution missing publicKeyPem");
    }
    return createPublicKey({ key: kr.publicKeyPem, format: "pem" });
  }
  if (kr.shape !== "did-json") {
    throw new Error(`unsupported keyidResolution shape: ${kr.shape}`);
  }
  const methods = kr.document?.verificationMethod;
  if (!Array.isArray(methods) || methods.length === 0) {
    throw new Error("DID Document has no verificationMethod entries");
  }
  // Prefer assertionMethod-referenced verificationMethod when present.
  const preferredId = pickAssertionMethodId(kr.document);
  const method =
    methods.find((m) => preferredId !== null && m.id === preferredId) ??
    methods[0];

  if (typeof method.publicKeyMultibase === "string") {
    const raw = multibaseToRawEd25519(method.publicKeyMultibase);
    const pem = rawEd25519ToSpkiPem(raw);
    return createPublicKey({ key: pem, format: "pem" });
  }
  if (
    method.publicKeyJwk &&
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
  if (p.tag !== undefined) parts.push(`tag="${p.tag}"`);
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

  // Verify Ed25519 signature.
  const sigBytes = parseSignatureHeader(expected.signature);
  if (sigBytes === null) {
    return { path, ok: false, stage: "signature-parse", reason: "malformed Signature header" };
  }
  const baseBytes = Buffer.from(base, "utf-8");
  const ok = cryptoVerify(null, baseBytes, publicKey, sigBytes);

  // The only modeled negative outcome at the wire layer is a signature that
  // fails to verify against the resolved key — whether tampered bytes, a
  // substituted key, or a tampered body (content-digest is a signed component).
  const verdict = ok ? "ACCEPT" : "REJECT";
  const gate = gateVerdict(path, expected, verdict, "SIGNATURE_INVALID");
  if (!gate.ok) return gate;

  // Bonus: cross-suite byte-match check, if declared.
  const cse = fixture.crossSuiteEquivalence?.envoys;
  if (cse?.byteIdentical === true && cse.expectedSignatureBase64) {
    if (expected.signatureBase64 !== cse.expectedSignatureBase64) {
      return {
        path,
        ok: false,
        observed: gate.observed,
        stage: "cross-suite-equivalence",
        reason: `fixture signature does not byte-match Envoys ${cse.vector}`,
      };
    }
  }

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
function jcs(value) {
  if (Array.isArray(value)) return `[${value.map(jcs).join(",")}]`;
  if (value !== null && typeof value === "object") {
    const keys = Object.keys(value).sort();
    return `{${keys.map((k) => `${JSON.stringify(k)}:${jcs(value[k])}`).join(",")}}`;
  }
  if (typeof value === "string") return JSON.stringify(value);
  throw new Error(`value type outside the fixture JCS domain: ${typeof value}`);
}

function isNonEmptyString(v) {
  return typeof v === "string" && v.length > 0;
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
  try {
    return new URL(url).hostname;
  } catch {
    return null;
  }
}

function reject(category, reason) {
  return { verdict: "REJECT", category, reason };
}

// Evaluate the identity declaration. Returns {verdict, category, reason}.
// The check order is part of the cross-implementation contract: shape first,
// then per-level binding checks, then cryptography, then validity window.
function evaluateIdentity(fixture) {
  const card = fixture.agentCard;
  const extensions = card?.capabilities?.extensions;
  if (!Array.isArray(extensions)) {
    return reject("SHAPE_INVALID", "agentCard.capabilities.extensions missing");
  }
  const ext = extensions.find((e) => e?.uri === IDENTITY_EXTENSION_URI);
  if (!ext || typeof ext.params !== "object" || ext.params === null) {
    return reject("SHAPE_INVALID", "agent-identity extension (or its params) missing");
  }
  const p = ext.params;
  if (!IDENTITY_LEVELS.includes(p.identityLevel)) {
    return reject("SHAPE_INVALID", `unknown identityLevel: ${p.identityLevel}`);
  }
  if (p.agentId !== undefined && !(typeof p.agentId === "string" && AGENT_ID_URN_RE.test(p.agentId))) {
    return reject("SHAPE_INVALID", `agentId is not a urn:a2a:agent:{domain}:{agent-name}:{version} URN: ${p.agentId}`);
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
  const att = (p.attestations ?? []).find((a) => a?.type === "domain");
  if (!att) return reject("SHAPE_INVALID", "DOMAIN_VERIFIED requires a domain attestation");
  if (!isNonEmptyString(p.agentId)) {
    return reject("SHAPE_INVALID", "DOMAIN_VERIFIED requires an agentId");
  }
  const domain = hostnameOf(card.provider?.url);
  if (domain === null) return reject("SHAPE_INVALID", "provider.url missing or unparseable");
  if (att.domain !== domain) {
    return reject("DOMAIN_MISMATCH", `attestation domain ${att.domain} != provider domain ${domain}`);
  }
  const dnsTxt = fixture.evidence?.dnsTxt;
  if (!dnsTxt || !isNonEmptyString(dnsTxt.recordName) || !isNonEmptyString(dnsTxt.recordValue)) {
    return reject("SHAPE_INVALID", "evidence.dnsTxt.{recordName,recordValue} missing");
  }
  if (dnsTxt.recordName !== `_a2a-identity.${domain}`) {
    return reject("DOMAIN_MISMATCH", `record name ${dnsTxt.recordName} != _a2a-identity.${domain}`);
  }
  const fields = {};
  for (const part of dnsTxt.recordValue.split("; ")) {
    const eq = part.indexOf("=");
    if (eq > 0) fields[part.slice(0, eq)] = part.slice(eq + 1);
  }
  if (fields.v !== "a2a1") return reject("SHAPE_INVALID", `unsupported record version: ${fields.v}`);
  const urnParts = p.agentId.split(":");
  if (urnParts[3] !== domain) {
    return reject("DOMAIN_MISMATCH", `agentId domain ${urnParts[3]} != provider domain ${domain}`);
  }
  if (fields.agent !== urnParts[4]) {
    return reject("AGENT_MISMATCH", `record agent ${fields.agent} != agentId name ${urnParts[4]}`);
  }
  if (fields.kid !== pk.kid) {
    return reject("KID_MISMATCH", `record kid ${fields.kid} != declared kid ${pk.kid}`);
  }
  const fp = b64urlNoPad(createHash("sha256").update(b64urlDecode(pk.x)).digest());
  if (fields.fp !== fp) {
    return reject("FINGERPRINT_MISMATCH", `record fp ${fields.fp} != computed ${fp}`);
  }
  return { verdict: "ACCEPT" };
}

function evaluateOrganizationVerified(fixture, p, pk) {
  const att = (p.attestations ?? []).find((a) => a?.type === "organization");
  if (!att) return reject("SHAPE_INVALID", "ORGANIZATION_VERIFIED requires an organization attestation");
  const shapeOk =
    att.issuer && isNonEmptyString(att.issuer.name) && isNonEmptyString(att.issuer.kid) &&
    isNonEmptyString(att.issuer.url) &&
    att.subject && isNonEmptyString(att.subject.organization) &&
    isNonEmptyString(att.subject.agentId) && isNonEmptyString(att.subject.kid) &&
    TIMESTAMP_RE.test(att.verifiedAt ?? "") && TIMESTAMP_RE.test(att.expiresAt ?? "") &&
    isNonEmptyString(att.signature);
  if (!shapeOk) return reject("SHAPE_INVALID", "organization attestation is missing required fields");
  if (att.subject.agentId !== p.agentId || att.subject.kid !== pk.kid) {
    return reject("SUBJECT_MISMATCH", "attestation subject does not bind to the declared agentId/kid");
  }
  const ev = fixture.evidence ?? {};
  const issuerKey = ed25519KeyFromJwk(ev.issuerPublicKey);
  if (issuerKey === null || !TIMESTAMP_RE.test(ev.validationTime ?? "")) {
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

// --- driver ---------------------------------------------------------------------

function verifyFixture(path) {
  const fixture = JSON.parse(readFileSync(path, "utf-8"));
  if (fixture.agentCard !== undefined) return verifyLevelFixture(fixture, path);
  return verifyCompositionFixture(fixture, path);
}

function collectFixtures(arg) {
  const abs = resolve(arg);
  if (!statSync(abs).isDirectory()) return [abs];
  const out = [];
  const walk = (dir) => {
    for (const entry of readdirSync(dir).sort()) {
      const p = join(dir, entry);
      if (statSync(p).isDirectory()) walk(p);
      else if (p.endsWith(".json")) out.push(p);
    }
  };
  walk(abs);
  return out;
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
  for (const abs of paths) {
    try {
      const result = verifyFixture(abs);
      if (result.ok) {
        passCount++;
        console.log(`PASS  ${abs}`);
      } else {
        failCount++;
        console.log(`FAIL  ${abs}`);
      }
      if (result.observed !== undefined) {
        console.log(`      observed: ${result.observed}`);
      }
      if (!result.ok) {
        console.log(`      stage:  ${result.stage}`);
        console.log(`      reason: ${result.reason}`);
        if (result.reconstructed !== undefined) {
          console.log(`      reconstructed: ${JSON.stringify(result.reconstructed)}`);
          console.log(`      expected:      ${JSON.stringify(result.expected)}`);
        }
      }
    } catch (err) {
      failCount++;
      console.log(`ERROR ${abs}`);
      console.log(`      ${err.stack ?? err.message}`);
    }
  }
  console.log(`summary: ${passCount} pass, ${failCount} fail (${paths.length} fixtures)`);
  process.exit(failCount === 0 ? 0 : 1);
}

main();
