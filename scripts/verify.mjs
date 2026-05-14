#!/usr/bin/env node
// Reference Node.js verifier for A2A-IDF conformance fixtures.
// Pure Node stdlib — no third-party dependencies. Runs on Node ≥ 18
// (Node ships Ed25519 verification through OpenSSL via crypto.verify).
//
// Usage:  node verify.mjs <fixture.json> [<fixture.json> ...]
// Exit code: 0 if every fixture's verifyResult expectation is met, else 1.

import { readFileSync } from "node:fs";
import { resolve } from "node:path";
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

async function verifyFixture(path) {
  const fixture = JSON.parse(readFileSync(path, "utf-8"));
  const expected = fixture.expected;
  const expectedResult = (expected.verifyResult ?? "ACCEPT").toUpperCase();

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

  const actualResult = ok ? "ACCEPT" : "REJECT";
  if (actualResult !== expectedResult) {
    return {
      path,
      ok: false,
      stage: "ed25519-verify",
      reason: `verify result ${actualResult} != expected ${expectedResult}`,
    };
  }

  // Bonus: cross-suite byte-match check, if declared.
  const cse = fixture.crossSuiteEquivalence?.envoys;
  if (cse?.byteIdentical === true && cse.expectedSignatureBase64) {
    if (expected.signatureBase64 !== cse.expectedSignatureBase64) {
      return {
        path,
        ok: false,
        stage: "cross-suite-equivalence",
        reason: `fixture signature does not byte-match Envoys ${cse.vector}`,
      };
    }
  }

  return { path, ok: true };
}

async function main() {
  const args = process.argv.slice(2);
  if (args.length === 0) {
    console.error("usage: node verify.mjs <fixture.json> [<fixture.json> ...]");
    process.exit(2);
  }

  let allOk = true;
  for (const arg of args) {
    const abs = resolve(arg);
    try {
      const result = await verifyFixture(abs);
      if (result.ok) {
        console.log(`PASS  ${abs}`);
      } else {
        allOk = false;
        console.log(`FAIL  ${abs}`);
        console.log(`      stage:  ${result.stage}`);
        console.log(`      reason: ${result.reason}`);
        if (result.reconstructed !== undefined) {
          console.log(`      reconstructed: ${JSON.stringify(result.reconstructed)}`);
          console.log(`      expected:      ${JSON.stringify(result.expected)}`);
        }
      }
    } catch (err) {
      allOk = false;
      console.log(`ERROR ${abs}`);
      console.log(`      ${err.stack ?? err.message}`);
    }
  }
  process.exit(allOk ? 0 : 1);
}

await main();
