#!/usr/bin/env node
// Deterministic fixture generator for the A2A-IDF conformance suite.
//
// Regenerates every file under fixtures/ and vectors/, plus MANIFEST.sha256,
// from the RFC 8032 §7.1 test seeds and the fixture templates below. Running
// it twice produces byte-identical output; CI enforces that the committed
// tree matches a fresh generation (`git diff --exit-code`), so the committed
// fixtures cannot drift from their documented inputs.
//
// Pure Node stdlib. Ed25519 signing is deterministic (RFC 8032), so the
// signature bytes are stable across runs and platforms.
//
// Usage:  node scripts/generate-fixtures.mjs

import { createHash, createPrivateKey, createPublicKey, sign as cryptoSign } from "node:crypto";
import { mkdirSync, writeFileSync, readdirSync, statSync, readFileSync } from "node:fs";
import { dirname, join, relative } from "node:path";
import { fileURLToPath } from "node:url";

const REPO_ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");

// --- RFC 8032 §7.1 test seeds (published in the RFC; test-only) ---------------

const TEST1_SEED_HEX = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
const TEST2_SEED_HEX = "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb";

// Wire signatures pinned to Envoys signature/v1 §14 Vectors 1-3. The generator
// recomputes each signature from the seed and ASSERTS byte-equality with these
// constants — the suite's cross-suite byte-match claim is enforced at
// generation time, not just at verification time.
const ENVOYS_V1_SIG = "XUpjUHt36NbHgAZrQkFY2fSNUR19tgmRlGO1dBhaZDgBv4wb55qgJf2buv3wgnTYwtT+1sH2jzSbcgG6FLGKCA==";
const ENVOYS_V2_SIG = "i5tKcOHKhRTCztR2cazuzNAg9rPiRf47MKTOGve92Rs43gNmltuN5LVScedR6C08MGsQykMc7txJ21KCG8SEBQ==";
const ENVOYS_V3_SIG = "m2besJKk6Q0MIwFoTENobvvHxFan1fUTv7bzY4EB6OjfIlktqwKa7r/Ab0tDDWFGjQ0CbALgvWGcQfzDr/GeBQ==";

// --- key derivation ------------------------------------------------------------

const PKCS8_ED25519_PREFIX = Buffer.from("302e020100300506032b657004220420", "hex");
const SPKI_ED25519_PREFIX = Buffer.from("302a300506032b6570032100", "hex");
const MULTICODEC_ED25519_PUB = Buffer.from("ed01", "hex");
const BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

function base58btcEncode(bytes) {
  const digits = [0];
  for (const byte of bytes) {
    let carry = byte;
    for (let j = 0; j < digits.length; j++) {
      carry += digits[j] << 8;
      digits[j] = carry % 58;
      carry = (carry / 58) | 0;
    }
    while (carry > 0) {
      digits.push(carry % 58);
      carry = (carry / 58) | 0;
    }
  }
  let leadingZeros = 0;
  for (const byte of bytes) {
    if (byte === 0) leadingZeros++;
    else break;
  }
  return (
    "1".repeat(leadingZeros) +
    digits.reverse().map((d) => BASE58_ALPHABET[d]).join("")
  );
}

function b64url(buf) {
  return Buffer.from(buf).toString("base64url");
}

function deriveKeypair(seedHex) {
  const seed = Buffer.from(seedHex, "hex");
  const pkcs8 = Buffer.concat([PKCS8_ED25519_PREFIX, seed]);
  const privateKey = createPrivateKey({ key: pkcs8, format: "der", type: "pkcs8" });
  const publicKey = createPublicKey(privateKey);
  const spki = publicKey.export({ format: "der", type: "spki" });
  const rawPublic = spki.subarray(SPKI_ED25519_PREFIX.length);
  return {
    privateKey,
    seed,
    rawPublic,
    publicHex: rawPublic.toString("hex"),
    publicBase64: rawPublic.toString("base64"),
    pemSpki: `-----BEGIN PUBLIC KEY-----\n${spki.toString("base64")}\n-----END PUBLIC KEY-----\n`,
    pemPkcs8: `-----BEGIN PRIVATE KEY-----\n${pkcs8.toString("base64")}\n-----END PRIVATE KEY-----\n`,
    multibase: "z" + base58btcEncode(Buffer.concat([MULTICODEC_ED25519_PUB, rawPublic])),
    jwkX: b64url(rawPublic),
    jwkD: b64url(seed),
    seedBase64: seed.toString("base64"),
  };
}

const TEST1 = deriveKeypair(TEST1_SEED_HEX);
const TEST2 = deriveKeypair(TEST2_SEED_HEX);

function signEd25519(key, data) {
  return cryptoSign(null, Buffer.from(data, "utf-8"), key.privateKey);
}

function sha256(buf) {
  return createHash("sha256").update(buf).digest();
}

// --- RFC 9421 signature base (mirrors scripts/verify.mjs) ----------------------

function serializeParams(p) {
  const parts = [`keyid="${p.keyid}"`, `created=${p.created}`, `nonce="${p.nonce}"`];
  if (p.tag !== undefined) parts.push(`tag="${p.tag}"`);
  return parts.join(";");
}

function buildSignatureBase(input, contentDigest, params) {
  const lines = [];
  for (const c of params.components) {
    if (c === "@method") lines.push(`"@method": ${input.method.toUpperCase()}`);
    else if (c === "@path") lines.push(`"@path": ${input.path}`);
    else if (c === "content-digest") lines.push(`"content-digest": ${contentDigest}`);
    else throw new Error(`unsupported component: ${c}`);
  }
  const list = params.components.map((c) => `"${c}"`).join(" ");
  lines.push(`"@signature-params": (${list});${serializeParams(params)}`);
  return lines.join("\n");
}

function contentDigestOf(body) {
  return `sha-256=:${sha256(Buffer.from(body, "utf-8")).toString("base64")}:`;
}

// --- minimal RFC 8785 (JCS) for the restricted value domain used here ----------
// Fixture attestations contain only objects and strings (no numbers, arrays of
// scalars only, ASCII keys), for which sorted-key compact JSON is exactly the
// JCS canonical form. Keep fixture content inside that domain.

function jcs(value) {
  if (Array.isArray(value)) return `[${value.map(jcs).join(",")}]`;
  if (value !== null && typeof value === "object") {
    const keys = Object.keys(value).sort();
    return `{${keys.map((k) => `${JSON.stringify(k)}:${jcs(value[k])}`).join(",")}}`;
  }
  if (typeof value === "string") return JSON.stringify(value);
  throw new Error(`value type outside the fixture JCS domain: ${typeof value}`);
}

// --- shared building blocks -----------------------------------------------------

const KEYID = "https://envoys.me/agents/test@rfc8032-vec1.example";
const DID_ID = "did:web:envoys.me:agents:test%40rfc8032-vec1.example";
const KEYPAIR_REF = "../../../vectors/rfc8032-7-1.json";

function didDocument(multibase, jwkX) {
  return {
    "@context": [
      "https://www.w3.org/ns/did/v1",
      "https://w3id.org/security/suites/ed25519-2020/v1",
    ],
    id: DID_ID,
    verificationMethod: [
      {
        id: `${DID_ID}#key-1`,
        type: "Ed25519VerificationKey2020",
        controller: DID_ID,
        publicKeyMultibase: multibase,
      },
      {
        id: `${DID_ID}#key-2`,
        type: "JsonWebKey2020",
        controller: DID_ID,
        publicKeyJwk: { kty: "OKP", crv: "Ed25519", x: jwkX },
      },
    ],
    assertionMethod: [`${DID_ID}#key-1`, `${DID_ID}#key-2`],
    authentication: [`${DID_ID}#key-1`, `${DID_ID}#key-2`],
  };
}

function keyidResolution(multibase, jwkX) {
  return {
    shape: "did-json",
    contentType: "application/did+json",
    document: didDocument(multibase, jwkX),
  };
}

const SPEC_A2A_IDF_S6 = {
  id: "A2A-IDF",
  ref: "https://github.com/a2aproject/A2A/pull/1496",
  section: "§6 Public-key resolution (dual-shape: application/did+json vs compact form)",
};
const SPEC_ENVOYS = (section) => ({
  id: "Envoys signature/v1",
  ref: "https://envoys.me/specs/signature/v1",
  version: "1.5.1",
  specSha256: "d343e4282a27610f0b8f4f8f8922e35790deff7b558086e9e86fbd0c0857ec48",
  section,
});
const SPEC_RFC9421 = {
  id: "RFC 9421",
  ref: "https://datatracker.ietf.org/doc/html/rfc9421",
  section: "§2.5 Creating the Signature Base",
};
const SPEC_RFC9421_VERIFY = {
  id: "RFC 9421",
  ref: "https://datatracker.ietf.org/doc/html/rfc9421",
  section: "§3.2 Verifying a Signature",
};
const SPEC_RFC9530 = {
  id: "RFC 9530",
  ref: "https://datatracker.ietf.org/doc/html/rfc9530",
  section: "Content-Digest header field",
};
const SPEC_RFC8785 = (section) => ({
  id: "RFC 8785",
  ref: "https://datatracker.ietf.org/doc/html/rfc8785",
  section,
});
const SPEC_RFC8032 = (section) => ({
  id: "RFC 8032",
  ref: "https://datatracker.ietf.org/doc/html/rfc8032",
  section,
});
const SPEC_DID_CORE = {
  id: "W3C DID Core v1.0",
  ref: "https://www.w3.org/TR/did-core/",
  section: "§5.2 Verification Methods",
};

// Signs a composition input and returns the expected block.
function expectedBlock(input, params, signWith, { verifyResult = "ACCEPT", rejectCategory, signatureOverride } = {}) {
  const contentDigest = contentDigestOf(input.body);
  const signatureBase = buildSignatureBase(input, contentDigest, params);
  const list = params.components.map((c) => `"${c}"`).join(" ");
  const signatureInput = `sig1=(${list});${serializeParams(params)}`;
  const signatureBase64 =
    signatureOverride ?? signEd25519(signWith, signatureBase).toString("base64");
  const block = {
    contentDigest,
    signatureBase,
    signatureInput,
    signature: `sig1=:${signatureBase64}:`,
    signatureBase64,
    verifyResult,
  };
  if (rejectCategory) block.rejectCategory = rejectCategory;
  return block;
}

// --- composition fixtures: positives (Envoys §14 byte-match preserved) ----------

const INPUT_V1 = { method: "GET", path: "/api/health", body: "", bodyEncoding: "utf-8" };
const PARAMS_V1 = {
  components: ["@method", "@path", "content-digest"],
  keyid: KEYID,
  created: 1714000000,
  nonce: "AAECAwQFBgcICQoLDA0ODw",
};
const INPUT_V2 = {
  method: "POST",
  path: "/api/task",
  body: '{"task":"summarize","url":"https://example.com/doc"}',
  bodyEncoding: "utf-8",
};
const PARAMS_V2 = {
  components: ["@method", "@path", "content-digest"],
  keyid: KEYID,
  created: 1714000060,
  nonce: "EBESExQVFhcYGRobHB0eHw",
};
const INPUT_V3 = { method: "POST", path: "/api/echo", body: "{}", bodyEncoding: "utf-8" };
const PARAMS_V3 = {
  components: ["@method", "@path", "content-digest"],
  keyid: KEYID,
  created: 1714000120,
  nonce: "ICEiIyQlJicoKSorLC0uLw",
};

function signatureAloneFixture() {
  const expected = expectedBlock(INPUT_V1, PARAMS_V1, TEST1);
  assertEqual(expected.signatureBase64, ENVOYS_V1_SIG, "Envoys §14 Vector 1 byte-match");
  return {
    $schema: "https://a2a-idf.opena2a.org/schemas/fixture-composition-v1.json",
    name: "aim-did-rfc9421/signature-alone",
    description:
      "A2A-IDF identity-framework wrap of an Envoys §14 Vector 1 wire signature. The keyid URL resolves to a W3C DID Document (Ed25519VerificationKey2020 + publicKeyMultibase) rather than the Envoys §6 compact form. Because the RFC 9421 signature base depends only on the signed components and parameters, not on the keyid document shape, the resulting signature is byte-identical to Envoys §14 Vector 1. This fixture demonstrates that a verifier implementing A2A-IDF §6 dual-shape keyid resolution can interoperate with Envoys-signed traffic without re-keying or re-signing.",
    spec: [
      SPEC_A2A_IDF_S6,
      SPEC_ENVOYS("§14 Vector 1 (GET request, no body)"),
      SPEC_RFC9421,
      SPEC_RFC9530,
      SPEC_RFC8032("§7.1 Test 1 (Ed25519 keypair)"),
      SPEC_DID_CORE,
    ],
    keypairRef: KEYPAIR_REF,
    input: INPUT_V1,
    signatureParams: PARAMS_V1,
    keyidResolution: keyidResolution(TEST1.multibase, TEST1.jwkX),
    expected,
    crossSuiteEquivalence: {
      envoys: {
        vector: "§14 Vector 1",
        expectedSignatureBase64: ENVOYS_V1_SIG,
        byteIdentical: true,
        note: "Substituting the Envoys §6 compact-form keyid document for this DID Document at the keyid URL yields the same signature bytes. The signature base does not include the keyid document body; only the keyid URL string. A2A-IDF verifiers and Envoys verifiers reach the same Ed25519 verify(sig, base, pubkey) call site.",
      },
    },
  };
}

function bilateralReceiptFixture() {
  const expected = expectedBlock(INPUT_V2, PARAMS_V2, TEST1);
  assertEqual(expected.signatureBase64, ENVOYS_V2_SIG, "Envoys §14 Vector 2 byte-match");
  return {
    $schema: "https://a2a-idf.opena2a.org/schemas/fixture-composition-v1.json",
    name: "aim-did-rfc9421/bilateral-receipt",
    description:
      "A2A-IDF identity-framework wrap of an Envoys §14 Vector 2 wire signature (POST /api/task with a JSON body) inside an APS bilateral-receipt envelope. The initiator's wire signature is byte-identical to Envoys §14 Vector 2 by construction (the envelope does not re-sign the wire request). The envelope adds a responder acknowledgment over a JCS-canonical receipt payload referencing the initiator's wire signature. The conformance verifier checks the wire layer (RFC 9421 + A2A-IDF §6 dual-shape keyid resolution); deeper envelope verification (responder signature over the JCS receipt) is a planned extension.",
    spec: [
      {
        id: "A2A-IDF",
        ref: "https://github.com/a2aproject/A2A/pull/1496",
        section: "§6 Public-key resolution (dual-shape) and §8 Composition with bilateral receipts",
      },
      {
        id: "APS",
        ref: "https://github.com/a2aproject/A2A/issues/1575",
        section: "Bilateral receipt envelope",
      },
      SPEC_ENVOYS("§14 Vector 2 (POST request, JSON body)"),
      SPEC_RFC9421,
      SPEC_RFC9530,
      SPEC_RFC8785("JCS canonical form (envelope payload)"),
      SPEC_RFC8032("§7.1 Test 1 (Ed25519 keypair)"),
      SPEC_DID_CORE,
    ],
    keypairRef: KEYPAIR_REF,
    input: INPUT_V2,
    signatureParams: PARAMS_V2,
    keyidResolution: keyidResolution(TEST1.multibase, TEST1.jwkX),
    expected,
    crossSuiteEquivalence: {
      envoys: {
        vector: "§14 Vector 2",
        expectedSignatureBase64: ENVOYS_V2_SIG,
        byteIdentical: true,
        note: "Wire signature is unchanged when the envelope wraps the request. The envelope contributes responder acknowledgment, not a re-sign of the wire payload. Substituting the Envoys §6 compact-form keyid document at the keyid URL yields the same wire signature bytes.",
      },
    },
    envelope: {
      type: "aps-bilateral-receipt-v1",
      version: "draft-2026-05-13",
      ref: "https://github.com/a2aproject/A2A/issues/1575",
      request: {
        wireSignatureBase64Ref: "expected.signatureBase64",
        initiatorKeyid: KEYID,
        initiatedAt: "2026-05-13T13:31:00Z",
      },
      response: {
        responderKeyid: "did:web:counterparty.example:agents:receipt-test",
        respondedAt: "2026-05-13T13:31:02Z",
        status: "ACCEPTED",
        receiptPayloadJcs: {
          initiatorSignatureBase64: ENVOYS_V2_SIG,
          initiatorKeyid: KEYID,
          respondedAt: "2026-05-13T13:31:02Z",
          responderKeyid: "did:web:counterparty.example:agents:receipt-test",
          status: "ACCEPTED",
        },
        responderSignatureNote:
          "Responder signs the RFC 8785 JCS-canonical form of receiptPayloadJcs using its own keyid. The signature is intentionally omitted here because the responder keypair is illustrative; the fixture's verification scope is the wire layer per A2A-IDF §6. Deeper envelope verification lands in a future suite iteration once APS receipt schemas stabilize.",
      },
      conformanceNotes: [
        "Wire signature (Envoys §14 Vector 2) is byte-identical to a non-enveloped request signed with the same keypair and params.",
        "The envelope changes the framework-layer interpretation (a bilateral receipt is a bound request+response pair) but not the wire-layer bytes.",
        "A2A-IDF §6 dual-shape keyid resolution applies independently to initiator and responder keyids.",
      ],
    },
  };
}

function delegationChainFixture() {
  const expected = expectedBlock(INPUT_V3, PARAMS_V3, TEST1);
  assertEqual(expected.signatureBase64, ENVOYS_V3_SIG, "Envoys §14 Vector 3 byte-match");
  return {
    $schema: "https://a2a-idf.opena2a.org/schemas/fixture-composition-v1.json",
    name: "aim-did-rfc9421/delegation-chain-3link",
    description:
      "A2A-IDF identity-framework wrap of an Envoys §14 Vector 3 wire signature (POST /api/echo with an empty JSON object body) inside a 3-link APS delegation chain envelope. The wire signature is byte-identical to Envoys §14 Vector 3 by construction. The envelope adds three delegation links demonstrating the chain rules from A2A-IDF §7: scope monotonic narrowing, expiry monotonic non-increase, depth at most maxDepth (default 4), and previousSignature binding between consecutive links. The conformance verifier checks the wire layer (RFC 9421 + A2A-IDF §6 dual-shape keyid resolution); deeper chain verification (per-link signatures and rule enforcement against the link payloads' JCS form) is a planned extension.",
    spec: [
      {
        id: "A2A-IDF",
        ref: "https://github.com/a2aproject/A2A/pull/1496",
        section: "§6 Public-key resolution (dual-shape) and §7 Delegation chains",
      },
      {
        id: "APS",
        ref: "https://github.com/a2aproject/A2A/issues/1575",
        section: "Delegation chain envelopes",
      },
      SPEC_ENVOYS("§14 Vector 3 (POST request, empty JSON object body)"),
      SPEC_RFC9421,
      SPEC_RFC9530,
      SPEC_RFC8785("JCS canonical form (per-link payload)"),
      SPEC_RFC8032("§7.1 Test 1 (Ed25519 keypair)"),
      SPEC_DID_CORE,
    ],
    keypairRef: KEYPAIR_REF,
    input: INPUT_V3,
    signatureParams: PARAMS_V3,
    keyidResolution: keyidResolution(TEST1.multibase, TEST1.jwkX),
    expected,
    crossSuiteEquivalence: {
      envoys: {
        vector: "§14 Vector 3",
        expectedSignatureBase64: ENVOYS_V3_SIG,
        byteIdentical: true,
        note: "Wire signature is unchanged when wrapped in a delegation chain envelope. The chain context is framework-layer metadata; the wire bytes remain those of Envoys §14 Vector 3.",
      },
    },
    envelope: {
      type: "aps-delegation-chain-v1",
      version: "draft-2026-05-13",
      ref: "https://github.com/a2aproject/A2A/issues/1575",
      depth: 3,
      maxDepth: 4,
      links: [
        {
          index: 0,
          type: "root",
          issuerKeyid: KEYID,
          subjectKeyid: "did:web:counterparty.example:agents:delegate-level-1",
          scope: ["POST /api/echo", "POST /api/health", "GET /api/health"],
          issuedAt: "2026-05-01T00:00:00Z",
          expiresAt: "2026-12-31T00:00:00Z",
          linkPayloadJcsNote:
            "JCS canonical form of {issuerKeyid, subjectKeyid, scope, issuedAt, expiresAt, type:'root'} signed by the issuer.",
        },
        {
          index: 1,
          type: "derived",
          issuerKeyid: "did:web:counterparty.example:agents:delegate-level-1",
          subjectKeyid: "did:web:counterparty.example:agents:delegate-level-2",
          scope: ["POST /api/echo", "POST /api/health"],
          issuedAt: "2026-05-05T00:00:00Z",
          expiresAt: "2026-09-30T00:00:00Z",
          previousSignatureRef: "links[0].signature",
          linkPayloadJcsNote:
            "JCS canonical form of {issuerKeyid, subjectKeyid, scope, issuedAt, expiresAt, previousSignature, type:'derived'} signed by the issuer.",
        },
        {
          index: 2,
          type: "derived",
          issuerKeyid: "did:web:counterparty.example:agents:delegate-level-2",
          subjectKeyid: KEYID,
          scope: ["POST /api/echo"],
          issuedAt: "2026-05-10T00:00:00Z",
          expiresAt: "2026-06-30T00:00:00Z",
          previousSignatureRef: "links[1].signature",
          linkPayloadJcsNote:
            "JCS canonical form of {issuerKeyid, subjectKeyid, scope, issuedAt, expiresAt, previousSignature, type:'derived'} signed by the issuer.",
        },
      ],
      chainInvariants: {
        scopeMonotonicNarrow: true,
        scopeNarrowProof:
          "links[0].scope ⊇ links[1].scope ⊇ links[2].scope; final scope ['POST /api/echo'] matches the wire request",
        expiryMonotonicNonIncrease: true,
        expiryNonIncreaseProof: "2026-12-31 ≥ 2026-09-30 ≥ 2026-06-30",
        depthAtMostMaxDepth: true,
        depthProof: "depth=3 ≤ maxDepth=4",
        previousSignatureBinding:
          "Each derived link's previousSignature equals the prior link's signature, forming a hash-chain through Ed25519 signatures.",
      },
      wireRequestAuthorization: {
        finalScope: ["POST /api/echo"],
        wireRequest: "POST /api/echo",
        match: true,
        note: "The final subject (chain leaf) is the wire-signature signer; the final scope authorizes the wire request method and path.",
      },
      conformanceNotes: [
        "Wire signature (Envoys §14 Vector 3) is byte-identical to a non-enveloped request signed with the same keypair and params.",
        "Per-link signatures are intentionally omitted from this fixture; the conformance scope here is the wire layer per A2A-IDF §6. The link signatures are computed over the JCS canonical form of each link payload using the issuer's keyid; deeper verification lands in a future suite iteration once APS delegation schemas stabilize.",
        "Real chain verification per A2A-IDF §7 enforces scope-narrow, expiry-non-increase, depth ceiling, previousSignature binding, and per-link Ed25519 signature against the resolved issuer key.",
      ],
    },
  };
}

// --- composition fixtures: negatives ---------------------------------------------

function signatureTamperedFixture() {
  const valid = expectedBlock(INPUT_V1, PARAMS_V1, TEST1);
  const tamperedSig = "Y" + valid.signatureBase64.slice(1);
  assertEqual(tamperedSig === valid.signatureBase64, false, "tampered signature differs");
  const expected = expectedBlock(INPUT_V1, PARAMS_V1, TEST1, {
    verifyResult: "REJECT",
    rejectCategory: "SIGNATURE_INVALID",
    signatureOverride: tamperedSig,
  });
  return {
    $schema: "https://a2a-idf.opena2a.org/schemas/fixture-composition-v1.json",
    name: "aim-did-rfc9421/signature-tampered",
    description:
      "Negative fixture: the signature-alone request with its Ed25519 signature bytes tampered (first base64 character altered). Everything else — body, Content-Digest, signature base, Signature-Input, keyid resolution — is identical to the valid fixture. A conforming A2A-IDF verifier MUST reject the request: the signature no longer verifies against the resolved public key. Models in-flight modification of the Signature header.",
    spec: [
      SPEC_A2A_IDF_S6,
      SPEC_RFC9421_VERIFY,
      SPEC_RFC8032("§7.1 Test 1 (Ed25519 keypair)"),
      SPEC_DID_CORE,
    ],
    keypairRef: KEYPAIR_REF,
    input: INPUT_V1,
    signatureParams: PARAMS_V1,
    keyidResolution: keyidResolution(TEST1.multibase, TEST1.jwkX),
    expected,
  };
}

function keySubstitutedFixture() {
  const expected = expectedBlock(INPUT_V1, PARAMS_V1, TEST1, {
    verifyResult: "REJECT",
    rejectCategory: "SIGNATURE_INVALID",
    signatureOverride: ENVOYS_V1_SIG,
  });
  return {
    $schema: "https://a2a-idf.opena2a.org/schemas/fixture-composition-v1.json",
    name: "aim-did-rfc9421/key-substituted",
    description:
      "Negative fixture: the signature-alone request with the DID Document's verification keys substituted for a different valid Ed25519 key (RFC 8032 §7.1 Test 2, in both publicKeyMultibase and publicKeyJwk encodings). The signature bytes are the valid Envoys §14 Vector 1 signature, produced by the Test 1 key. A conforming A2A-IDF verifier MUST reject: the key material served at the keyid URL does not match the signing key. Models a key-substitution attack on the §6 resolution step — the resolved document is attacker-controlled but cannot validate a signature it did not produce.",
    spec: [
      SPEC_A2A_IDF_S6,
      SPEC_RFC9421_VERIFY,
      SPEC_RFC8032("§7.1 Test 2 (substituted Ed25519 public key)"),
      SPEC_DID_CORE,
    ],
    keypairRef: KEYPAIR_REF,
    substitutedKeyRef: "../../../vectors/rfc8032-7-1-test2.json",
    input: INPUT_V1,
    signatureParams: PARAMS_V1,
    keyidResolution: keyidResolution(TEST2.multibase, TEST2.jwkX),
    expected,
  };
}

function bodyTamperedFixture() {
  const tamperedInput = {
    method: "POST",
    path: "/api/task",
    body: '{"task":"summarize","url":"https://evil.example/doc"}',
    bodyEncoding: "utf-8",
  };
  const expected = expectedBlock(tamperedInput, PARAMS_V2, TEST1, {
    verifyResult: "REJECT",
    rejectCategory: "SIGNATURE_INVALID",
    signatureOverride: ENVOYS_V2_SIG,
  });
  return {
    $schema: "https://a2a-idf.opena2a.org/schemas/fixture-composition-v1.json",
    name: "aim-did-rfc9421/body-tampered",
    description:
      "Negative fixture: the bilateral-receipt request body modified after signing (url changed to https://evil.example/doc), with the Content-Digest header recomputed to match the new body — as an in-path attacker who cannot re-sign would do. The Signature header still carries the Envoys §14 Vector 2 signature over the ORIGINAL body's signature base. A conforming A2A-IDF verifier MUST reject: content-digest is a signed component, so the recomputed digest changes the signature base and Ed25519 verification fails.",
    spec: [
      SPEC_A2A_IDF_S6,
      SPEC_RFC9421_VERIFY,
      SPEC_RFC9530,
      SPEC_RFC8032("§7.1 Test 1 (Ed25519 keypair)"),
      SPEC_DID_CORE,
    ],
    keypairRef: KEYPAIR_REF,
    input: tamperedInput,
    signatureParams: PARAMS_V2,
    keyidResolution: keyidResolution(TEST1.multibase, TEST1.jwkX),
    expected,
  };
}

// --- level fixtures (A2A-IDF §1 verification levels) ------------------------------

const AGENT_ID = "urn:a2a:agent:example.com:financial-advisor:v2";
const AGENT_KID = "agent-a1b2c3d4";
const ISSUER_KID = "registry-x1y2z3";
const VALIDATION_TIME = "2026-07-03T00:00:00Z";

const SPEC_IDF_LEVELS = (section) => ({
  id: "A2A-IDF",
  ref: "https://github.com/a2aproject/A2A/pull/1496",
  section,
});

function agentPublicKeyJwk() {
  return { kty: "OKP", crv: "Ed25519", x: TEST1.jwkX, kid: AGENT_KID };
}

function agentCard(identityLevel, { agentId = AGENT_ID, attestations } = {}) {
  const params = {
    version: "1.0.0",
    identityLevel,
    agentId,
    publicKey: agentPublicKeyJwk(),
  };
  if (attestations !== undefined) params.attestations = attestations;
  return {
    name: "financial-advisor-agent",
    provider: { organization: "Example Corp", url: "https://example.com" },
    capabilities: {
      extensions: [
        {
          uri: "https://a2a-protocol.org/extensions/agent-identity",
          description: "Agent identity verification and trust signals",
          required: false,
          params,
        },
      ],
    },
  };
}

function agentFingerprint() {
  return b64url(sha256(TEST1.rawPublic));
}

function dnsTxtRecordValue(fp) {
  return `v=a2a1; agent=financial-advisor; kid=${AGENT_KID}; fp=${fp}`;
}

// Signs an organization attestation (RFC 8785 JCS of the object minus `signature`).
function signedOrgAttestation({ verifiedAt, expiresAt, tamper } = {}) {
  const unsigned = {
    type: "organization",
    issuer: {
      name: "A2A Trust Registry",
      kid: ISSUER_KID,
      url: "https://trust.a2a-registry.org",
    },
    subject: {
      organization: "Example Corp",
      agentId: AGENT_ID,
      kid: AGENT_KID,
    },
    verifiedAt,
    expiresAt,
  };
  const signature = b64url(signEd25519(TEST2, jcs(unsigned)));
  const att = { ...unsigned, signature };
  if (tamper) tamper(att);
  return att;
}

function levelSpecBase(sectionDetail) {
  return [
    SPEC_IDF_LEVELS(`§1 Agent Identity Verification Levels — ${sectionDetail}`),
    SPEC_RFC8032("§7.1 (Ed25519 test keypairs)"),
  ];
}

function level0Fixture() {
  return {
    $schema: "https://a2a-idf.opena2a.org/schemas/fixture-level-v1.json",
    name: "levels/level-0-self-asserted",
    description:
      "Level 0 (SELF_ASSERTED): an AgentCard declaring the agent-identity extension with identityLevel SELF_ASSERTED, a URN-format agentId, and an Ed25519 public key. No attestations are present and none are required — Level 0 makes no verifiable claim beyond well-formedness. A conforming verifier ACCEPTs the declaration shape while treating the identity as unverified (A2A-IDF Security Considerations: clients MUST NOT treat Level 0 agents as verified).",
    spec: levelSpecBase("Level 0 SELF_ASSERTED declaration shape"),
    level: 0,
    agentCard: agentCard("SELF_ASSERTED"),
    expected: { verifyResult: "ACCEPT" },
  };
}

function level0MalformedFixture() {
  return {
    $schema: "https://a2a-idf.opena2a.org/schemas/fixture-level-v1.json",
    name: "levels/level-0-agent-id-malformed",
    description:
      "Negative fixture: a SELF_ASSERTED AgentCard whose agentId is not in the urn:a2a:agent:{domain}:{agent-name}:{version} format required by A2A-IDF §1 for declared agent identifiers. A conforming verifier MUST reject the declaration shape: a malformed agentId cannot serve as a stable identifier across AgentCard updates and key rotations.",
    spec: levelSpecBase("Agent Identifiers (URN format)"),
    level: 0,
    agentCard: agentCard("SELF_ASSERTED", { agentId: "financial-advisor/v2" }),
    expected: { verifyResult: "REJECT", rejectCategory: "SHAPE_INVALID" },
  };
}

function level1Fixture() {
  const fp = agentFingerprint();
  return {
    $schema: "https://a2a-idf.opena2a.org/schemas/fixture-level-v1.json",
    name: "levels/level-1-domain-verified",
    description:
      "Level 1 (DOMAIN_VERIFIED): an AgentCard declaring DOMAIN_VERIFIED with a domain attestation, plus the pinned DNS TXT record the domain owner published at _a2a-identity.example.com. A conforming verifier extracts the domain from provider.url, checks the record name, and verifies that the record's agent name matches the agentId, its kid matches the declared key ID, and its fp equals base64url(sha256(raw public key bytes)) without padding. All checks are offline against the pinned record — live DNS resolution (and DNSSEC) is deployment behavior outside the suite's scope.",
    spec: levelSpecBase("Level 1 DNS Verification (_a2a-identity TXT record)"),
    level: 1,
    agentCard: agentCard("DOMAIN_VERIFIED", {
      attestations: [
        {
          type: "domain",
          domain: "example.com",
          verifiedAt: "2026-02-17T00:00:00Z",
          method: "DNS_TXT",
        },
      ],
    }),
    evidence: {
      dnsTxt: {
        recordName: "_a2a-identity.example.com",
        recordValue: dnsTxtRecordValue(fp),
      },
    },
    expected: { verifyResult: "ACCEPT" },
  };
}

function level1FingerprintMismatchFixture() {
  const wrongFp = b64url(sha256(TEST2.rawPublic));
  return {
    $schema: "https://a2a-idf.opena2a.org/schemas/fixture-level-v1.json",
    name: "levels/level-1-fingerprint-mismatch",
    description:
      "Negative fixture: the DOMAIN_VERIFIED AgentCard with a DNS TXT record whose fp field is the fingerprint of a DIFFERENT Ed25519 key (RFC 8032 §7.1 Test 2). Record name, agent name, and kid all match. A conforming verifier MUST reject: the fingerprint binds the DNS record to the exact public key bytes, and a mismatch means the domain owner did not endorse this key. Models an agent presenting a key the domain never authorized.",
    spec: levelSpecBase("Level 1 DNS Verification (fingerprint binding)"),
    level: 1,
    agentCard: agentCard("DOMAIN_VERIFIED", {
      attestations: [
        {
          type: "domain",
          domain: "example.com",
          verifiedAt: "2026-02-17T00:00:00Z",
          method: "DNS_TXT",
        },
      ],
    }),
    evidence: {
      dnsTxt: {
        recordName: "_a2a-identity.example.com",
        recordValue: dnsTxtRecordValue(wrongFp),
      },
    },
    expected: { verifyResult: "REJECT", rejectCategory: "FINGERPRINT_MISMATCH" },
  };
}

function issuerPublicKeyJwk() {
  return { kty: "OKP", crv: "Ed25519", x: TEST2.jwkX, kid: ISSUER_KID };
}

function level2Fixture() {
  const attestation = signedOrgAttestation({
    verifiedAt: "2026-02-17T00:00:00Z",
    expiresAt: "2027-02-17T00:00:00Z",
  });
  return {
    $schema: "https://a2a-idf.opena2a.org/schemas/fixture-level-v1.json",
    name: "levels/level-2-organization-verified",
    description:
      "Level 2 (ORGANIZATION_VERIFIED): an AgentCard carrying an organization attestation signed by a trust registry (Ed25519 over the RFC 8785 JCS canonicalization of the attestation object with the signature field excluded). A conforming verifier checks that the attestation subject binds to the declared agentId and kid, verifies the registry signature against the pinned issuer public key, and confirms the pinned validationTime falls inside [verifiedAt, expiresAt]. The issuer key is RFC 8032 §7.1 Test 2 (registry role); the agent key is Test 1.",
    spec: [
      SPEC_IDF_LEVELS("§1 Organization Verification (registry attestation)"),
      SPEC_RFC8785("JCS canonical form (attestation signing input)"),
      SPEC_RFC8032("§7.1 Test 1 (agent key), Test 2 (registry issuer key)"),
    ],
    level: 2,
    agentCard: agentCard("ORGANIZATION_VERIFIED", { attestations: [attestation] }),
    evidence: {
      issuerPublicKey: issuerPublicKeyJwk(),
      validationTime: VALIDATION_TIME,
    },
    expected: { verifyResult: "ACCEPT" },
  };
}

function level2TamperedFixture() {
  const attestation = signedOrgAttestation({
    verifiedAt: "2026-02-17T00:00:00Z",
    expiresAt: "2027-02-17T00:00:00Z",
    tamper: (att) => {
      att.subject.organization = "Wrong Corp";
    },
  });
  return {
    $schema: "https://a2a-idf.opena2a.org/schemas/fixture-level-v1.json",
    name: "levels/level-2-attestation-tampered",
    description:
      "Negative fixture: the ORGANIZATION_VERIFIED attestation with subject.organization altered AFTER signing (Example Corp → Wrong Corp). The signature was produced over the original JCS form, so it no longer verifies against the modified content. A conforming verifier MUST reject. Models post-issuance modification of a registry attestation.",
    spec: [
      SPEC_IDF_LEVELS("§1 Organization Verification (attestation integrity)"),
      SPEC_RFC8785("JCS canonical form (attestation signing input)"),
      SPEC_RFC8032("§7.1 Test 2 (registry issuer key)"),
    ],
    level: 2,
    agentCard: agentCard("ORGANIZATION_VERIFIED", { attestations: [attestation] }),
    evidence: {
      issuerPublicKey: issuerPublicKeyJwk(),
      validationTime: VALIDATION_TIME,
    },
    expected: { verifyResult: "REJECT", rejectCategory: "SIGNATURE_INVALID" },
  };
}

function level2ExpiredFixture() {
  const attestation = signedOrgAttestation({
    verifiedAt: "2024-02-17T00:00:00Z",
    expiresAt: "2025-02-17T00:00:00Z",
  });
  return {
    $schema: "https://a2a-idf.opena2a.org/schemas/fixture-level-v1.json",
    name: "levels/level-2-attestation-expired",
    description:
      "Negative fixture: an ORGANIZATION_VERIFIED attestation whose registry signature is VALID but whose validity window ended before the pinned validationTime (expiresAt 2025-02-17 < validationTime 2026-07-03). Every other field is well-formed and correctly bound. A conforming verifier MUST reject on the validity window alone. The fixture pins validationTime so the expiry decision is deterministic and never depends on the wall clock.",
    spec: [
      SPEC_IDF_LEVELS("§1 Organization Verification (validity window)"),
      SPEC_RFC8785("JCS canonical form (attestation signing input)"),
      SPEC_RFC8032("§7.1 Test 2 (registry issuer key)"),
    ],
    level: 2,
    agentCard: agentCard("ORGANIZATION_VERIFIED", { attestations: [attestation] }),
    evidence: {
      issuerPublicKey: issuerPublicKeyJwk(),
      validationTime: VALIDATION_TIME,
    },
    expected: { verifyResult: "REJECT", rejectCategory: "EXPIRED" },
  };
}

// --- keypair vectors ---------------------------------------------------------------

function keypairVector(kp, { name, test, role }) {
  return {
    $schema: "https://a2a-idf.opena2a.org/schemas/keypair-vector-v1.json",
    name,
    description: `Ed25519 keypair pinned to RFC 8032 §7.1 ${test}. ${role} The encoded forms below are all derivations of the same 32-byte public key and 32-byte private seed; the generator recomputes them from the seed on every run.`,
    source: {
      rfc: "RFC 8032",
      section: "§7.1",
      test,
      url: "https://datatracker.ietf.org/doc/html/rfc8032#section-7.1",
    },
    warning:
      "These keys are published in RFC 8032 itself and are for cross-implementation verification only. They MUST NOT be used to sign anything in any production deployment.",
    public: {
      rawHex: kp.publicHex,
      rawBase64: kp.publicBase64,
      pemSpki: kp.pemSpki,
      publicKeyMultibase: kp.multibase,
      publicKeyJwk: { kty: "OKP", crv: "Ed25519", x: kp.jwkX },
    },
    private: {
      rawHex: kp.seed.toString("hex"),
      rawBase64: kp.seedBase64,
      pemPkcs8: kp.pemPkcs8,
      privateKeyJwk: { kty: "OKP", crv: "Ed25519", x: kp.jwkX, d: kp.jwkD },
    },
  };
}

// --- output ---------------------------------------------------------------------

const FILES = {
  "vectors/rfc8032-7-1.json": keypairVector(TEST1, {
    name: "rfc8032-7-1",
    test: "Test 1",
    role: "Canonical agent signing keypair shared across this suite, the Envoys signature/v1 §14 reproducible vectors, and the aps-conformance-suite composition fixtures, so verifiers can demonstrate byte-match parity across implementations.",
  }),
  "vectors/rfc8032-7-1-test2.json": keypairVector(TEST2, {
    name: "rfc8032-7-1-test2",
    test: "Test 2",
    role: "Secondary keypair: the trust-registry issuer key for Level 2 organization-attestation fixtures, and the substituted key in the key-substituted negative fixture.",
  }),
  "fixtures/composition/aim-did-rfc9421/signature-alone.json": signatureAloneFixture(),
  "fixtures/composition/aim-did-rfc9421/bilateral-receipt.json": bilateralReceiptFixture(),
  "fixtures/composition/aim-did-rfc9421/delegation-chain-3link.json": delegationChainFixture(),
  "fixtures/composition/aim-did-rfc9421/signature-tampered.json": signatureTamperedFixture(),
  "fixtures/composition/aim-did-rfc9421/key-substituted.json": keySubstitutedFixture(),
  "fixtures/composition/aim-did-rfc9421/body-tampered.json": bodyTamperedFixture(),
  "fixtures/levels/level-0-self-asserted.json": level0Fixture(),
  "fixtures/levels/level-0-agent-id-malformed.json": level0MalformedFixture(),
  "fixtures/levels/level-1-domain-verified.json": level1Fixture(),
  "fixtures/levels/level-1-fingerprint-mismatch.json": level1FingerprintMismatchFixture(),
  "fixtures/levels/level-2-organization-verified.json": level2Fixture(),
  "fixtures/levels/level-2-attestation-tampered.json": level2TamperedFixture(),
  "fixtures/levels/level-2-attestation-expired.json": level2ExpiredFixture(),
};

function assertEqual(actual, expected, what) {
  if (actual !== expected) {
    throw new Error(`generator self-check failed (${what}): ${JSON.stringify(actual)} != ${JSON.stringify(expected)}`);
  }
}

function main() {
  const written = [];
  for (const [rel, content] of Object.entries(FILES)) {
    const abs = join(REPO_ROOT, rel);
    mkdirSync(dirname(abs), { recursive: true });
    writeFileSync(abs, JSON.stringify(content, null, 2) + "\n");
    written.push(rel);
  }

  // MANIFEST.sha256 over every JSON artifact under fixtures/ and vectors/,
  // sorted by path. Format matches `sha256sum` output.
  const manifestTargets = [];
  for (const dir of ["fixtures", "vectors"]) {
    walk(join(REPO_ROOT, dir), (p) => {
      if (p.endsWith(".json")) manifestTargets.push(relative(REPO_ROOT, p));
    });
  }
  manifestTargets.sort();
  const manifest = manifestTargets
    .map((rel) => `${sha256(readFileSync(join(REPO_ROOT, rel))).toString("hex")}  ${rel}`)
    .join("\n") + "\n";
  writeFileSync(join(REPO_ROOT, "MANIFEST.sha256"), manifest);

  console.log(`wrote ${written.length} fixture/vector files + MANIFEST.sha256 (${manifestTargets.length} pinned)`);
}

function walk(dir, fn) {
  for (const entry of readdirSync(dir).sort()) {
    const p = join(dir, entry);
    if (statSync(p).isDirectory()) walk(p, fn);
    else fn(p);
  }
}

main();
