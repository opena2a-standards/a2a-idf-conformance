#!/usr/bin/env node
// Deterministic fixture generator for the A2A-IDF conformance suite.
//
// Writes the fixtures and vectors listed in FILES below from the RFC 8032
// §7.1 test seeds and the fixture templates in this file, then writes
// MANIFEST.sha256 from the JSON files under fixtures/ and vectors/ as it finds
// them. Running it twice produces byte-identical output. CI reruns it and then
// runs `git diff --exit-code` (the byte-pin step), so a committed fixture that
// differs from what this script writes for it fails CI.
//
// The two snapshot fixtures in fixtures/composition/hippo-rfc9421/ are not in
// FILES: they are pinned in MANIFEST.sha256 but not regenerated. The manifest
// pins them as found, so the byte-pin step fails when one of them changes
// without MANIFEST.sha256 and passes when the change is committed together
// with the refreshed MANIFEST.sha256.
//
// Pure Node stdlib. Ed25519 signing is deterministic (RFC 8032), so the
// signature bytes are stable across runs and platforms.
//
// Usage:  node scripts/generate-fixtures.mjs
//         node scripts/generate-fixtures.mjs --help
// The generator takes no arguments, and reads them before it builds or writes
// anything: --help (or -h) prints the usage and exits 0, and any other
// argument is a usage error, exit 2. Neither writes a file.

import {
  createHash,
  createPrivateKey,
  createPublicKey,
  sign as cryptoSign,
  verify as cryptoVerify,
} from "node:crypto";
import { mkdirSync, writeFileSync, readdirSync, statSync, readFileSync } from "node:fs";
import { dirname, join, relative } from "node:path";
import { fileURLToPath } from "node:url";

const REPO_ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");

// --- arguments -------------------------------------------------------------------

const USAGE = "usage: node generate-fixtures.mjs";
const HELP = [
  USAGE,
  "Writes the fixtures and vectors this script owns, then MANIFEST.sha256. Takes no arguments.",
  "Exit code: 0 when the files are written, 2 for a usage error.",
].join("\n");

// Called before FILES is built, so --help and a usage error write nothing. The
// argument is printed with its control characters escaped, as verify.mjs prints
// an unknown option: it can be a file name a shell pattern expanded to.
function readArguments(args) {
  for (const arg of args) {
    if (arg === "--help" || arg === "-h") {
      console.log(HELP);
      process.exit(0);
    }
    const kind = arg.startsWith("-") && arg !== "-" ? "unknown option" : "unexpected argument";
    const shown = arg.replace(/[\u0000-\u001f\u007f-\u009f]/g, (c) => `\\u${c.charCodeAt(0).toString(16).padStart(4, "0")}`);
    console.error(USAGE);
    console.error(`generate-fixtures.mjs: ${kind}: ${shown}`);
    process.exit(2);
  }
}

readArguments(process.argv.slice(2));

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
  if (p.tag !== undefined && p.tag !== null) parts.push(`tag="${p.tag}"`);
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
// Fixture attestations and the signed envelope payloads (delegation-chain
// links, bilateral receipts) contain only objects, arrays, and strings (no
// numbers, booleans, or null), for which sorted-key compact JSON is exactly the JCS
// canonical form. Property names sort by UTF-16 code units (RFC 8785 §3.2.3),
// which is what Array.prototype.sort() does by default; keys outside the BMP
// are therefore in scope. Keep fixture content inside that domain.

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
const TEST2_KEYPAIR_REF = "../../../vectors/rfc8032-7-1-test2.json";

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
const SPEC_RFC9421_APP_REQUIREMENTS = {
  id: "RFC 9421",
  ref: "https://datatracker.ietf.org/doc/html/rfc9421",
  section: "§3.2.1 Enforcing Application Requirements",
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

// --- envelopes (A2A-IDF §7 delegation chains, §8 bilateral receipts) -------------
// The keyids an envelope names beside the wire keyid are counterparty.example
// DIDs, and each of them resolves to the RFC 8032 §7.1 Test 2 key. A verifier
// resolves the wire keyid through the fixture's keyidResolution and any other
// keyid through envelope.keyidResolutions. An envelope signature is an Ed25519
// signature, in base64 (RFC 4648 §4, padded), over the UTF-8 bytes of the
// RFC 8785 JCS form of the payload it signs.

const DELEGATE_1 = "did:web:counterparty.example:agents:delegate-level-1";
const DELEGATE_2 = "did:web:counterparty.example:agents:delegate-level-2";
const DELEGATE_3 = "did:web:counterparty.example:agents:delegate-level-3";
const RESPONDER = "did:web:counterparty.example:agents:receipt-test";
const APS_REF = "https://github.com/a2aproject/A2A/issues/1575";
const APS_VERSION = "draft-2026-05-13";

function signJcs(keyid, payload) {
  const key = keyid === KEYID ? TEST1 : TEST2;
  return signEd25519(key, jcs(payload)).toString("base64");
}

// A base64 signature with its first character changed, so its bytes no longer verify.
function tamperedBase64(signature) {
  const tampered = (signature[0] === "Y" ? "Z" : "Y") + signature.slice(1);
  assertEqual(tampered === signature, false, "tampered envelope signature differs");
  return tampered;
}

function counterpartyResolution(did) {
  return {
    shape: "did-json",
    contentType: "application/did+json",
    document: {
      "@context": [
        "https://www.w3.org/ns/did/v1",
        "https://w3id.org/security/suites/ed25519-2020/v1",
      ],
      id: did,
      verificationMethod: [
        {
          id: `${did}#key-1`,
          type: "Ed25519VerificationKey2020",
          controller: did,
          publicKeyMultibase: TEST2.multibase,
        },
      ],
      assertionMethod: [`${did}#key-1`],
    },
  };
}

function keyidResolutions(dids) {
  return Object.fromEntries(dids.map((did) => [did, counterpartyResolution(did)]));
}

// The chain of delegation-chain-3link: the wire keyid delegates to a
// counterparty agent, that agent to a second one, and the second back to the
// wire keyid, which signs the request. Each scope is a subset of the one
// before it, and no expiry is later than the one before it.
const CHAIN_LINKS = [
  {
    type: "root",
    issuerKeyid: KEYID,
    subjectKeyid: DELEGATE_1,
    scope: ["POST /api/echo", "POST /api/health", "GET /api/health"],
    issuedAt: "2026-05-01T00:00:00Z",
    expiresAt: "2026-12-31T00:00:00Z",
  },
  {
    type: "derived",
    issuerKeyid: DELEGATE_1,
    subjectKeyid: DELEGATE_2,
    scope: ["POST /api/echo", "POST /api/health"],
    issuedAt: "2026-05-05T00:00:00Z",
    expiresAt: "2026-09-30T00:00:00Z",
  },
  {
    type: "derived",
    issuerKeyid: DELEGATE_2,
    subjectKeyid: KEYID,
    scope: ["POST /api/echo"],
    issuedAt: "2026-05-10T00:00:00Z",
    expiresAt: "2026-06-30T00:00:00Z",
  },
];

const LINK_PAYLOAD_NOTE = {
  root: "JCS canonical form of {issuerKeyid, subjectKeyid, scope, issuedAt, expiresAt, type:'root'} signed by the issuer.",
  derived:
    "JCS canonical form of {issuerKeyid, subjectKeyid, scope, issuedAt, expiresAt, previousSignature, type:'derived'} signed by the issuer.",
};

// What the issuer of a link signs: the link's own fields and, for a derived
// link, previousSignature, the signature of the link before it.
function linkPayload(link, previousSignature) {
  const payload = {
    type: link.type,
    issuerKeyid: link.issuerKeyid,
    subjectKeyid: link.subjectKeyid,
    scope: link.scope,
    issuedAt: link.issuedAt,
    expiresAt: link.expiresAt,
  };
  if (previousSignature !== undefined) payload.previousSignature = previousSignature;
  return payload;
}

// Signs the links in order, each with its issuer's key, so a derived link is
// bound to the signature of the link before it.
function signedLinks(specs) {
  const links = [];
  for (const [index, spec] of specs.entries()) {
    const link = { index, ...spec, scope: [...spec.scope] };
    if (index > 0) link.previousSignatureRef = `links[${index - 1}].signature`;
    link.signature = signJcs(spec.issuerKeyid, linkPayload(spec, links[index - 1]?.signature));
    link.linkPayloadJcsNote = LINK_PAYLOAD_NOTE[spec.type];
    links.push(link);
  }
  return links;
}

// CHAIN_LINKS with the fields in `changes` replaced in link `index`.
function chainLinksWith(index, changes) {
  return CHAIN_LINKS.map((spec, i) => (i === index ? { ...spec, ...changes } : spec));
}

function chainEnvelope(links, { maxDepth = 4, resolved = [DELEGATE_1, DELEGATE_2] } = {}) {
  return {
    type: "aps-delegation-chain-v1",
    version: APS_VERSION,
    ref: APS_REF,
    depth: links.length,
    maxDepth,
    links,
    keyidResolutions: keyidResolutions(resolved),
    conformanceNotes: [
      "Wire signature (Envoys §14 Vector 3) is byte-identical to a non-enveloped request signed with the same keypair and params.",
      "Each link's signature is its issuer's Ed25519 signature, in base64, over the UTF-8 bytes of the RFC 8785 JCS form of the payload its linkPayloadJcsNote names. previousSignature is the signature member of the link before it, so a derived link is bound to the link it was issued under.",
      "The wire keyid resolves through keyidResolution and each other issuer keyid through envelope.keyidResolutions. The counterparty.example keyids resolve to the RFC 8032 §7.1 Test 2 key.",
    ],
  };
}

const RECEIPT_RESPONSE = {
  responderKeyid: RESPONDER,
  respondedAt: "2026-05-13T13:31:02Z",
  status: "ACCEPTED",
};

// The receipt of bilateral-receipt. `payload` replaces members of the receipt
// payload before the responder signs it; `tamper` alters the responder
// signature after signing.
function receiptEnvelope({ payload = {}, tamper = false } = {}) {
  const receiptPayloadJcs = {
    initiatorSignatureBase64: ENVOYS_V2_SIG,
    initiatorKeyid: KEYID,
    respondedAt: RECEIPT_RESPONSE.respondedAt,
    responderKeyid: RECEIPT_RESPONSE.responderKeyid,
    status: RECEIPT_RESPONSE.status,
    ...payload,
  };
  const signature = signJcs(receiptPayloadJcs.responderKeyid, receiptPayloadJcs);
  return {
    type: "aps-bilateral-receipt-v1",
    version: APS_VERSION,
    ref: APS_REF,
    request: {
      wireSignatureBase64Ref: "expected.signatureBase64",
      initiatorKeyid: KEYID,
      initiatedAt: "2026-05-13T13:31:00Z",
    },
    response: {
      ...RECEIPT_RESPONSE,
      receiptPayloadJcs,
      responderSignatureBase64: tamper ? tamperedBase64(signature) : signature,
    },
    keyidResolutions: keyidResolutions([RESPONDER]),
    conformanceNotes: [
      "Wire signature (Envoys §14 Vector 2) is byte-identical to a non-enveloped request signed with the same keypair and params.",
      "The envelope changes the framework-layer interpretation (a bilateral receipt is a bound request+response pair) but not the wire-layer bytes.",
      "responderSignatureBase64 is the responder's Ed25519 signature, in base64, over the UTF-8 bytes of the RFC 8785 JCS form of receiptPayloadJcs, whose initiatorSignatureBase64 is the wire signature the receipt acknowledges.",
      "A2A-IDF §6 dual-shape keyid resolution applies independently to initiator and responder keyids: the initiator keyid resolves through keyidResolution and the responder keyid through envelope.keyidResolutions, to the RFC 8032 §7.1 Test 2 key.",
    ],
  };
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

// A negative envelope fixture keeps the wire request of its positive one, which
// verifies; its rejectCategory names the envelope check it fails.
function rejectOptions(rejectCategory) {
  return rejectCategory === undefined ? {} : { verifyResult: "REJECT", rejectCategory };
}

function receiptFixture({ name, description, envelope, rejectCategory }) {
  const expected = expectedBlock(INPUT_V2, PARAMS_V2, TEST1, rejectOptions(rejectCategory));
  assertEqual(expected.signatureBase64, ENVOYS_V2_SIG, "Envoys §14 Vector 2 byte-match");
  return {
    $schema: "https://a2a-idf.opena2a.org/schemas/fixture-composition-v1.json",
    name: `aim-did-rfc9421/${name}`,
    description,
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
      SPEC_RFC8032("§7.1 Test 2 (responder Ed25519 keypair)"),
      SPEC_DID_CORE,
    ],
    keypairRef: KEYPAIR_REF,
    counterpartyKeypairRef: TEST2_KEYPAIR_REF,
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
    envelope,
  };
}

function bilateralReceiptFixture() {
  return receiptFixture({
    name: "bilateral-receipt",
    description:
      "A2A-IDF identity-framework wrap of an Envoys §14 Vector 2 wire signature (POST /api/task with a JSON body) inside an APS bilateral-receipt envelope. The initiator's wire signature is byte-identical to Envoys §14 Vector 2 by construction (the envelope does not re-sign the wire request). The envelope adds a responder acknowledgment: the responder's Ed25519 signature over the JCS-canonical receipt payload, which names the initiator's wire signature. Both reference verifiers check the wire layer (RFC 9421 + A2A-IDF §6 dual-shape keyid resolution) and then the envelope: the responder signature over the receipt payload, and that the payload acknowledges this request's signature and initiator and matches the response members beside it.",
    envelope: receiptEnvelope(),
  });
}

function chainFixture({ name, description, envelope, rejectCategory }) {
  const expected = expectedBlock(INPUT_V3, PARAMS_V3, TEST1, rejectOptions(rejectCategory));
  assertEqual(expected.signatureBase64, ENVOYS_V3_SIG, "Envoys §14 Vector 3 byte-match");
  return {
    $schema: "https://a2a-idf.opena2a.org/schemas/fixture-composition-v1.json",
    name: `aim-did-rfc9421/${name}`,
    description,
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
      SPEC_RFC8032("§7.1 Test 2 (delegate Ed25519 keypair)"),
      SPEC_DID_CORE,
    ],
    keypairRef: KEYPAIR_REF,
    counterpartyKeypairRef: TEST2_KEYPAIR_REF,
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
    envelope,
  };
}

function delegationChainFixture() {
  return chainFixture({
    name: "delegation-chain-3link",
    description:
      "A2A-IDF identity-framework wrap of an Envoys §14 Vector 3 wire signature (POST /api/echo with an empty JSON object body) inside a 3-link APS delegation chain envelope. The wire signature is byte-identical to Envoys §14 Vector 3 by construction. The envelope adds three signed delegation links demonstrating the chain rules from A2A-IDF §7: scope monotonic narrowing, expiry monotonic non-increase, depth at most maxDepth, and previousSignature binding between consecutive links. Both reference verifiers check the wire layer (RFC 9421 + A2A-IDF §6 dual-shape keyid resolution) and then the chain: its depth, each link's issuer and its Ed25519 signature over the JCS form of the link payload, scope narrowing and expiry non-increase from link to link, and that the last link delegates to the wire keyid with a scope that grants the request.",
    envelope: chainEnvelope(signedLinks(CHAIN_LINKS)),
  });
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

function crossSuiteMismatchFixture() {
  const expected = expectedBlock(INPUT_V1, PARAMS_V1, TEST2, {
    verifyResult: "REJECT",
    rejectCategory: "CROSS_SUITE_MISMATCH",
  });
  assertEqual(expected.signatureBase64 === ENVOYS_V1_SIG, false, "Test 2 signature differs from Envoys §14 Vector 1");
  // The naked field carries the Envoys pin while the Signature header carries
  // the Test 2 signature, so a verifier that byte-matches this field instead
  // of the bytes it verified observes ACCEPT and fails the fixture.
  expected.signatureBase64 = ENVOYS_V1_SIG;
  return {
    $schema: "https://a2a-idf.opena2a.org/schemas/fixture-composition-v1.json",
    name: "aim-did-rfc9421/cross-suite-mismatch",
    description:
      "Negative fixture: the signature-alone request signed by a different valid Ed25519 key (RFC 8032 §7.1 Test 2), with the DID Document serving that same key, so the Signature header verifies against the resolved key. The fixture still declares byte-identity with Envoys §14 Vector 1, and its expected.signatureBase64 field carries the Vector 1 bytes instead of the bytes in the Signature header. A conforming verifier MUST reject: the cross-suite byte-match is a claim about the signature the verifier checked, so it compares the bytes parsed from the Signature header with the pinned vector, and those are the Test 2 signature. A verifier that compares expected.signatureBase64 instead accepts this fixture.",
    spec: [
      SPEC_A2A_IDF_S6,
      SPEC_ENVOYS("§14 Vector 1 (GET request, no body)"),
      SPEC_RFC9421_VERIFY,
      SPEC_RFC8032("§7.1 Test 2 (signing key and resolved public key)"),
      SPEC_DID_CORE,
    ],
    keypairRef: "../../../vectors/rfc8032-7-1-test2.json",
    input: INPUT_V1,
    signatureParams: PARAMS_V1,
    keyidResolution: keyidResolution(TEST2.multibase, TEST2.jwkX),
    expected,
    crossSuiteEquivalence: {
      envoys: {
        vector: "§14 Vector 1",
        expectedSignatureBase64: ENVOYS_V1_SIG,
        byteIdentical: true,
        note: "The declared byte-match does not hold: the verified signature is the Test 2 signature over the Vector 1 signature base, not the Vector 1 signature.",
      },
    },
  };
}

function signatureTagNullFixture() {
  const params = { ...PARAMS_V1, tag: null };
  const expected = expectedBlock(INPUT_V1, params, TEST1);
  assertEqual(expected.signatureBase64, ENVOYS_V1_SIG, "null tag serializes as an absent tag (Envoys §14 Vector 1)");
  return {
    $schema: "https://a2a-idf.opena2a.org/schemas/fixture-composition-v1.json",
    name: "aim-did-rfc9421/signature-tag-null",
    description:
      "The signature-alone request (Envoys §14 Vector 1) with signatureParams.tag set to JSON null. A null tag is an absent tag: it is omitted from the @signature-params line and from the Signature-Input header, never serialized as tag=\"null\". The signature base, and therefore the signature, are byte-identical to Vector 1. Pins identical null handling across verifiers: a verifier that serializes the null reconstructs a different base and fails at the signature-base stage.",
    spec: [
      SPEC_A2A_IDF_S6,
      SPEC_ENVOYS("§14 Vector 1 (GET request, no body)"),
      SPEC_RFC9421,
      SPEC_RFC8032("§7.1 Test 1 (Ed25519 keypair)"),
      SPEC_DID_CORE,
    ],
    keypairRef: KEYPAIR_REF,
    input: INPUT_V1,
    signatureParams: params,
    keyidResolution: keyidResolution(TEST1.multibase, TEST1.jwkX),
    expected,
  };
}

// --- composition fixtures: Envoys §4.3 tag rule ----------------------------------
// The pair differs only in signatureParams.tag: an absent tag is treated as
// `a2a-message` (ACCEPT), and any other tag marks a signature produced for a
// different application (REJECT[TAG_MISMATCH]), even though it verifies.

const FOREIGN_TAG = "not-a2a-message";

function signatureTagAbsentFixture() {
  const expected = expectedBlock(INPUT_V1, PARAMS_V1, TEST1);
  assertEqual(expected.signatureBase64, ENVOYS_V1_SIG, "absent tag signs as Envoys §14 Vector 1");
  return {
    $schema: "https://a2a-idf.opena2a.org/schemas/fixture-composition-v1.json",
    name: "aim-did-rfc9421/signature-tag-absent",
    description:
      "The absent half of the §4.3 tag pair: the signature-alone request (Envoys §14 Vector 1) with no tag parameter. An absent tag is treated as `a2a-message` for back-compat, so a conforming verifier MUST accept it. Paired with signature-tag-foreign, which differs only in carrying a tag other than `a2a-message`: a verifier that requires an explicit tag fails this fixture, and one that ignores the tag fails the other.",
    spec: [
      SPEC_A2A_IDF_S6,
      SPEC_ENVOYS("§4.3 tag parameter"),
      SPEC_RFC9421_APP_REQUIREMENTS,
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

function signatureTagForeignFixture() {
  const params = { ...PARAMS_V1, tag: FOREIGN_TAG };
  const expected = expectedBlock(INPUT_V1, params, TEST1, {
    verifyResult: "REJECT",
    rejectCategory: "TAG_MISMATCH",
  });
  assertEqual(
    cryptoVerify(
      null,
      Buffer.from(expected.signatureBase, "utf-8"),
      TEST1.privateKey,
      Buffer.from(expected.signatureBase64, "base64"),
    ),
    true,
    "foreign-tag signature verifies, so the tag is the only defect",
  );
  return {
    $schema: "https://a2a-idf.opena2a.org/schemas/fixture-composition-v1.json",
    name: "aim-did-rfc9421/signature-tag-foreign",
    description: `Negative fixture, the foreign half of the §4.3 tag pair: the signature-alone request signed with tag="${FOREIGN_TAG}" by the correct key. Content-Digest, signature base, Signature-Input, keyid resolution and the Ed25519 signature are all valid. A conforming verifier MUST reject: the tag says the signature was produced for an application other than A2A messaging, and only \`a2a-message\` or an absent tag is accepted. Models cross-application replay of a signature that verifies. The tag check runs before the Ed25519 check, so the reject category is TAG_MISMATCH.`,
    spec: [
      SPEC_A2A_IDF_S6,
      SPEC_ENVOYS("§4.3 tag parameter"),
      SPEC_RFC9421_APP_REQUIREMENTS,
      SPEC_RFC8032("§7.1 Test 1 (Ed25519 keypair)"),
      SPEC_DID_CORE,
    ],
    keypairRef: KEYPAIR_REF,
    input: INPUT_V1,
    signatureParams: params,
    keyidResolution: keyidResolution(TEST1.multibase, TEST1.jwkX),
    expected,
  };
}

// signature-tag-foreign verifies, so a verifier rejects it with TAG_MISMATCH
// whether it applies the tag rule before or after the Ed25519 check. This one
// adds an altered signature: only the order "tag rule first" gives TAG_MISMATCH.
function signatureTagForeignTamperedFixture() {
  const params = { ...PARAMS_V1, tag: FOREIGN_TAG };
  const valid = expectedBlock(INPUT_V1, params, TEST1);
  const tamperedSig = "Y" + valid.signatureBase64.slice(1);
  assertEqual(
    cryptoVerify(
      null,
      Buffer.from(valid.signatureBase, "utf-8"),
      TEST1.privateKey,
      Buffer.from(tamperedSig, "base64"),
    ),
    false,
    "tampered foreign-tag signature does not verify, so the fixture carries two defects",
  );
  const expected = expectedBlock(INPUT_V1, params, TEST1, {
    verifyResult: "REJECT",
    rejectCategory: "TAG_MISMATCH",
    signatureOverride: tamperedSig,
  });
  return {
    $schema: "https://a2a-idf.opena2a.org/schemas/fixture-composition-v1.json",
    name: "aim-did-rfc9421/signature-tag-foreign-tampered",
    description: `Check-order fixture with two defects: the signature-alone request carries tag="${FOREIGN_TAG}" (a TAG_MISMATCH) and its Ed25519 signature bytes are altered in the first base64 character (a SIGNATURE_INVALID). The §4.3 tag rule is an application requirement on the signature parameters and is applied before key resolution and signature verification, so a conforming verifier MUST reject with TAG_MISMATCH. A verifier that checks the signature first reports SIGNATURE_INVALID and fails this fixture. signature-tag-foreign cannot pin this order: its signature verifies, so both orders reject it with TAG_MISMATCH.`,
    spec: [
      SPEC_A2A_IDF_S6,
      SPEC_ENVOYS("§4.3 tag parameter"),
      SPEC_RFC9421_APP_REQUIREMENTS,
      SPEC_RFC9421_VERIFY,
      SPEC_RFC8032("§7.1 Test 1 (Ed25519 keypair)"),
      SPEC_DID_CORE,
    ],
    keypairRef: KEYPAIR_REF,
    input: INPUT_V1,
    signatureParams: params,
    keyidResolution: keyidResolution(TEST1.multibase, TEST1.jwkX),
    expected,
  };
}

// --- composition fixtures: envelope negatives -------------------------------------
// Each one keeps the wire request of its positive fixture, which verifies, and
// carries one envelope defect.

function delegationChainDepthExceededFixture() {
  return chainFixture({
    name: "delegation-chain-depth-exceeded",
    rejectCategory: "DEPTH_EXCEEDED",
    description:
      "Negative fixture: the delegation-chain-3link request and chain with envelope.maxDepth set to 2. Every link is signed by its issuer and the chain rules hold, but the chain has 3 links, more than maxDepth allows. A conforming A2A-IDF verifier MUST reject it (DEPTH_EXCEEDED).",
    envelope: chainEnvelope(signedLinks(CHAIN_LINKS), { maxDepth: 2 }),
  });
}

function delegationChainIssuerNotDelegateFixture() {
  return chainFixture({
    name: "delegation-chain-issuer-not-delegate",
    rejectCategory: "CHAIN_BROKEN",
    description:
      "Negative fixture: the delegation-chain-3link chain with its last link issued by did:web:counterparty.example:agents:delegate-level-3, which envelope.keyidResolutions resolves, instead of delegate-level-2, the subject of the link before it. The link is signed by its issuer's key, so its signature verifies, but nothing in the chain delegates to delegate-level-3. A conforming A2A-IDF verifier MUST reject it (CHAIN_BROKEN).",
    envelope: chainEnvelope(signedLinks(chainLinksWith(2, { issuerKeyid: DELEGATE_3 })), {
      resolved: [DELEGATE_1, DELEGATE_2, DELEGATE_3],
    }),
  });
}

function delegationChainLeafNotSignerFixture() {
  return chainFixture({
    name: "delegation-chain-leaf-not-signer",
    rejectCategory: "CHAIN_BROKEN",
    description:
      "Negative fixture: the delegation-chain-3link chain with its last link delegating to did:web:counterparty.example:agents:delegate-level-3 instead of the wire keyid, signed by its issuer. Every link verifies and the chain rules hold, but the chain does not end at the key that signed the request. A conforming A2A-IDF verifier MUST reject it (CHAIN_BROKEN).",
    envelope: chainEnvelope(signedLinks(chainLinksWith(2, { subjectKeyid: DELEGATE_3 }))),
  });
}

function delegationChainRootTamperedFixture() {
  const links = signedLinks(CHAIN_LINKS);
  links[0].scope = [...links[0].scope, "DELETE /api/everything"];
  return chainFixture({
    name: "delegation-chain-root-tampered",
    rejectCategory: "LINK_SIGNATURE_INVALID",
    description:
      "Negative fixture: the delegation-chain-3link chain with DELETE /api/everything added to the scope of the root link after the root was signed. The links after it are unchanged and still narrow that scope, but the root signature no longer verifies over the root payload. A conforming A2A-IDF verifier MUST reject it (LINK_SIGNATURE_INVALID).",
    envelope: chainEnvelope(links),
  });
}

function delegationChainLinkTamperedFixture() {
  const links = signedLinks(CHAIN_LINKS);
  links[1].expiresAt = "2026-08-31T00:00:00Z";
  return chainFixture({
    name: "delegation-chain-link-tampered",
    rejectCategory: "LINK_SIGNATURE_INVALID",
    description:
      "Negative fixture: the delegation-chain-3link chain with the expiresAt of link 1 moved from 2026-09-30T00:00:00Z to 2026-08-31T00:00:00Z after the link was signed. Expiry still does not increase along the chain, but the signature of link 1 no longer verifies over its payload. A conforming A2A-IDF verifier MUST reject it (LINK_SIGNATURE_INVALID).",
    envelope: chainEnvelope(links),
  });
}

function delegationChainLinkReplacedFixture() {
  const links = signedLinks(CHAIN_LINKS);
  const replacement = signedLinks(chainLinksWith(1, { scope: ["POST /api/echo"] }))[1];
  assertEqual(replacement.signature === links[1].signature, false, "the replacement link has its own signature");
  links[1] = replacement;
  return chainFixture({
    name: "delegation-chain-link-replaced",
    rejectCategory: "LINK_SIGNATURE_INVALID",
    description:
      "Negative fixture: the delegation-chain-3link chain with link 1 replaced by another link from the same issuer to the same subject, with scope [POST /api/echo], which that issuer signed over the root's signature. The replacement verifies, but link 2 was signed over the signature of the link 1 it was issued under (its previousSignature), so link 2 no longer verifies. A conforming A2A-IDF verifier MUST reject it (LINK_SIGNATURE_INVALID).",
    envelope: chainEnvelope(links),
  });
}

function delegationChainScopeWidenedFixture() {
  return chainFixture({
    name: "delegation-chain-scope-widened",
    rejectCategory: "SCOPE_WIDENED",
    description:
      "Negative fixture: the delegation-chain-3link chain with DELETE /api/everything added to the scope of the last link, signed by its issuer. Every link verifies and the last link still grants the request, but it grants an entry that the link before it does not hold. A conforming A2A-IDF verifier MUST reject it (SCOPE_WIDENED).",
    envelope: chainEnvelope(
      signedLinks(chainLinksWith(2, { scope: ["POST /api/echo", "DELETE /api/everything"] })),
    ),
  });
}

function delegationChainExpiryExtendedFixture() {
  return chainFixture({
    name: "delegation-chain-expiry-extended",
    rejectCategory: "EXPIRY_EXTENDED",
    description:
      "Negative fixture: the delegation-chain-3link chain with the expiresAt of the last link set to 2099-01-01T00:00:00Z, signed by its issuer. Every link verifies, but the last link expires after the link before it (2026-09-30T00:00:00Z). A conforming A2A-IDF verifier MUST reject it (EXPIRY_EXTENDED).",
    envelope: chainEnvelope(signedLinks(chainLinksWith(2, { expiresAt: "2099-01-01T00:00:00Z" }))),
  });
}

function delegationChainRequestOutOfScopeFixture() {
  return chainFixture({
    name: "delegation-chain-request-out-of-scope",
    rejectCategory: "REQUEST_OUT_OF_SCOPE",
    description:
      "Negative fixture: the delegation-chain-3link chain with the scope of the last link narrowed to [POST /api/health], signed by its issuer. Every link verifies and every scope narrows the one before it, but the last link does not grant the request, POST /api/echo. A conforming A2A-IDF verifier MUST reject it (REQUEST_OUT_OF_SCOPE).",
    envelope: chainEnvelope(signedLinks(chainLinksWith(2, { scope: ["POST /api/health"] }))),
  });
}

function bilateralReceiptSignatureTamperedFixture() {
  return receiptFixture({
    name: "bilateral-receipt-signature-tampered",
    rejectCategory: "RECEIPT_SIGNATURE_INVALID",
    description:
      "Negative fixture: the bilateral-receipt request and receipt with the responder signature altered (first base64 character changed). The receipt payload is unchanged, but the signature no longer verifies over its JCS form. A conforming A2A-IDF verifier MUST reject it (RECEIPT_SIGNATURE_INVALID).",
    envelope: receiptEnvelope({ tamper: true }),
  });
}

function bilateralReceiptOtherRequestFixture() {
  return receiptFixture({
    name: "bilateral-receipt-other-request",
    rejectCategory: "RECEIPT_MISMATCH",
    description:
      "Negative fixture: the bilateral-receipt request with a receipt the responder signed for another request: receiptPayloadJcs.initiatorSignatureBase64 is the Envoys §14 Vector 1 signature, not the signature of this request. The responder signature verifies, but the receipt does not acknowledge this request. A conforming A2A-IDF verifier MUST reject it (RECEIPT_MISMATCH).",
    envelope: receiptEnvelope({ payload: { initiatorSignatureBase64: ENVOYS_V1_SIG } }),
  });
}

function bilateralReceiptStatusMismatchFixture() {
  return receiptFixture({
    name: "bilateral-receipt-status-mismatch",
    rejectCategory: "RECEIPT_MISMATCH",
    description:
      "Negative fixture: the bilateral-receipt request with a receipt whose signed payload has status REJECTED while envelope.response.status reads ACCEPTED. The responder signature verifies, but the response states a status the responder did not sign. A conforming A2A-IDF verifier MUST reject it (RECEIPT_MISMATCH).",
    envelope: receiptEnvelope({ payload: { status: "REJECTED" } }),
  });
}

// --- level fixtures (A2A-IDF §1 verification levels) ------------------------------

const AGENT_ID ="urn:a2a:agent:example.com:financial-advisor:v2";
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

function agentCard(
  identityLevel,
  { agentId = AGENT_ID, attestations, providerUrl = "https://example.com" } = {},
) {
  const params = {
    version: "1.0.0",
    identityLevel,
    agentId,
    publicKey: agentPublicKeyJwk(),
  };
  if (attestations !== undefined) params.attestations = attestations;
  return {
    name: "financial-advisor-agent",
    provider: { organization: "Example Corp", url: providerUrl },
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

function dnsTxtRecordValue(fp, { v = "a2a1", agent = "financial-advisor", kid = AGENT_KID } = {}) {
  return `v=${v}; agent=${agent}; kid=${kid}; fp=${fp}`;
}

function domainAttestations() {
  return [
    {
      type: "domain",
      domain: "example.com",
      verifiedAt: "2026-02-17T00:00:00Z",
      method: "DNS_TXT",
    },
  ];
}

// Signs an organization attestation (RFC 8785 JCS of the object minus `signature`).
// `extra` adds fields before signing; `tamper` edits the attestation after signing.
function signedOrgAttestation({ verifiedAt, expiresAt, subjectAgentId = AGENT_ID, subjectKid = AGENT_KID, tamper, extra } = {}) {
  const unsigned = {
    type: "organization",
    issuer: {
      name: "A2A Trust Registry",
      kid: ISSUER_KID,
      url: "https://trust.a2a-registry.org",
    },
    subject: {
      organization: "Example Corp",
      agentId: subjectAgentId,
      kid: subjectKid,
    },
    verifiedAt,
    expiresAt,
    ...extra,
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

function level0AgentIdNullFixture() {
  return {
    $schema: "https://a2a-idf.opena2a.org/schemas/fixture-level-v1.json",
    name: "levels/level-0-agent-id-null",
    description:
      "Negative fixture: a SELF_ASSERTED AgentCard whose agentId member is JSON null. A Level 0 card may omit agentId, but a member that is present declares an identifier, and null is not a urn:a2a:agent:{domain}:{agent-name}:{version} URN. A conforming verifier MUST reject the declaration shape. A verifier that reads a null member as an absent one accepts the card and fails this fixture.",
    spec: levelSpecBase("Agent Identifiers (declared agentId with a null value)"),
    level: 0,
    agentCard: agentCard("SELF_ASSERTED", { agentId: null }),
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
    agentCard: agentCard("DOMAIN_VERIFIED", { attestations: domainAttestations() }),
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
    agentCard: agentCard("DOMAIN_VERIFIED", { attestations: domainAttestations() }),
    evidence: {
      dnsTxt: {
        recordName: "_a2a-identity.example.com",
        recordValue: dnsTxtRecordValue(wrongFp),
      },
    },
    expected: { verifyResult: "REJECT", rejectCategory: "FINGERPRINT_MISMATCH" },
  };
}

function level1DomainMismatchFixture() {
  return {
    $schema: "https://a2a-idf.opena2a.org/schemas/fixture-level-v1.json",
    name: "levels/level-1-domain-mismatch",
    description:
      "Negative fixture: the DOMAIN_VERIFIED AgentCard served from provider.url https://example.com, with a matching domain attestation and a valid DNS TXT record at _a2a-identity.example.com, but an agentId that claims a different domain (urn:a2a:agent:example.org:financial-advisor:v2). The agentId is a well-formed URN and the record's agent name, kid, and fingerprint all match. A conforming verifier MUST reject: the domain that endorsed the key is not the domain the agent identifier claims. Models an agent asserting an identifier under a domain it does not control while presenting another domain's record.",
    spec: levelSpecBase("Level 1 DNS Verification (agentId domain binding)"),
    level: 1,
    agentCard: agentCard("DOMAIN_VERIFIED", {
      agentId: "urn:a2a:agent:example.org:financial-advisor:v2",
      attestations: domainAttestations(),
    }),
    evidence: {
      dnsTxt: {
        recordName: "_a2a-identity.example.com",
        recordValue: dnsTxtRecordValue(agentFingerprint()),
      },
    },
    expected: { verifyResult: "REJECT", rejectCategory: "DOMAIN_MISMATCH" },
  };
}

function level1AgentMismatchFixture() {
  return {
    $schema: "https://a2a-idf.opena2a.org/schemas/fixture-level-v1.json",
    name: "levels/level-1-agent-mismatch",
    description:
      "Negative fixture: the DOMAIN_VERIFIED AgentCard with a DNS TXT record whose agent field names a different agent under the same domain (agent=payments-bot, while the agentId names financial-advisor). Record name, kid, and fingerprint all match. A conforming verifier MUST reject: the domain owner endorsed this key for a different agent name. Models one agent reusing a record the domain published for another of its agents.",
    spec: levelSpecBase("Level 1 DNS Verification (agent name binding)"),
    level: 1,
    agentCard: agentCard("DOMAIN_VERIFIED", { attestations: domainAttestations() }),
    evidence: {
      dnsTxt: {
        recordName: "_a2a-identity.example.com",
        recordValue: dnsTxtRecordValue(agentFingerprint(), { agent: "payments-bot" }),
      },
    },
    expected: { verifyResult: "REJECT", rejectCategory: "AGENT_MISMATCH" },
  };
}

function level1KidMismatchFixture() {
  return {
    $schema: "https://a2a-idf.opena2a.org/schemas/fixture-level-v1.json",
    name: "levels/level-1-kid-mismatch",
    description:
      "Negative fixture: the DOMAIN_VERIFIED AgentCard with a DNS TXT record whose kid field (agent-e5f6a7b8) differs from the declared publicKey.kid (agent-a1b2c3d4). Record name, agent name, and fingerprint all match. A conforming verifier MUST reject on the key ID binding before computing the fingerprint: the record endorses a key under a different identifier than the one the AgentCard declares. Models a card whose declared key ID drifted from the published record, for example after a key rotation that was not reflected in DNS.",
    spec: levelSpecBase("Level 1 DNS Verification (kid binding)"),
    level: 1,
    agentCard: agentCard("DOMAIN_VERIFIED", { attestations: domainAttestations() }),
    evidence: {
      dnsTxt: {
        recordName: "_a2a-identity.example.com",
        recordValue: dnsTxtRecordValue(agentFingerprint(), { kid: "agent-e5f6a7b8" }),
      },
    },
    expected: { verifyResult: "REJECT", rejectCategory: "KID_MISMATCH" },
  };
}

function level1MultiDefectFixture() {
  return {
    $schema: "https://a2a-idf.opena2a.org/schemas/fixture-level-v1.json",
    name: "levels/level-1-multi-defect-domain-and-version",
    description:
      "Check-order fixture with two defects: the DNS TXT record was published at _a2a-identity.example.net while provider.url is https://example.com (a DOMAIN_MISMATCH), and the record carries an unsupported version v=a2a9 (a SHAPE_INVALID). The record-name binding check precedes the record-version shape check in the contract order, so a conforming verifier MUST reject with DOMAIN_MISMATCH. A verifier that runs every shape check before any binding check reports SHAPE_INVALID and fails this fixture.",
    spec: levelSpecBase("Level 1 DNS Verification (check order: record name before record version)"),
    level: 1,
    agentCard: agentCard("DOMAIN_VERIFIED", { attestations: domainAttestations() }),
    evidence: {
      dnsTxt: {
        recordName: "_a2a-identity.example.net",
        recordValue: dnsTxtRecordValue(agentFingerprint(), { v: "a2a9" }),
      },
    },
    expected: { verifyResult: "REJECT", rejectCategory: "DOMAIN_MISMATCH" },
  };
}

const IDN_PROVIDER_URL = "https://bücher.example";
const IDN_DOMAIN = "xn--bcher-kva.example";

function level1IdnProviderUrlFixture() {
  // The WHATWG URL parser reports an internationalized host as its A-label.
  assertEqual(new URL(IDN_PROVIDER_URL).hostname, IDN_DOMAIN, "IDN provider.url A-label");
  const fp = agentFingerprint();
  return {
    $schema: "https://a2a-idf.opena2a.org/schemas/fixture-level-v1.json",
    name: "levels/level-1-idn-provider-url",
    description:
      "Level 1 (DOMAIN_VERIFIED) for an internationalized domain: provider.url is https://bücher.example, and every binding (attestation domain, agentId domain, DNS record name) uses its ASCII A-label xn--bcher-kva.example, the only form the agentId URN grammar and DNS admit. A conforming verifier derives the domain from provider.url in A-label form, as the WHATWG URL parser reports it, and ACCEPTs. A verifier that compares the Unicode host against the A-label bindings reports a spurious DOMAIN_MISMATCH.",
    spec: [
      ...levelSpecBase("Level 1 DNS Verification (internationalized domain)"),
      { id: "WHATWG URL", ref: "https://url.spec.whatwg.org/#concept-domain-to-ascii", section: "domain to ASCII" },
    ],
    level: 1,
    agentCard: agentCard("DOMAIN_VERIFIED", {
      agentId: `urn:a2a:agent:${IDN_DOMAIN}:financial-advisor:v2`,
      providerUrl: IDN_PROVIDER_URL,
      attestations: [
        {
          type: "domain",
          domain: IDN_DOMAIN,
          verifiedAt: "2026-02-17T00:00:00Z",
          method: "DNS_TXT",
        },
      ],
    }),
    evidence: {
      dnsTxt: {
        recordName: `_a2a-identity.${IDN_DOMAIN}`,
        recordValue: dnsTxtRecordValue(fp),
      },
    },
    expected: { verifyResult: "ACCEPT" },
  };
}

function level1AttestationsNotArrayFixture() {
  return {
    $schema: "https://a2a-idf.opena2a.org/schemas/fixture-level-v1.json",
    name: "levels/level-1-attestations-not-array",
    description:
      "Negative fixture: the DOMAIN_VERIFIED AgentCard whose attestations member is the domain attestation object itself, not an array holding it. Every other field, and the pinned DNS TXT record, is valid. A conforming verifier MUST reject at the shape stage: a value that is not an array carries no attestation, so the card has no domain attestation. A verifier that searches the value without checking its type raises instead of reaching a verdict and fails this fixture.",
    spec: levelSpecBase("Level 1 DNS Verification (attestations array shape)"),
    level: 1,
    agentCard: agentCard("DOMAIN_VERIFIED", { attestations: domainAttestations()[0] }),
    evidence: {
      dnsTxt: {
        recordName: "_a2a-identity.example.com",
        recordValue: dnsTxtRecordValue(agentFingerprint()),
      },
    },
    expected: { verifyResult: "REJECT", rejectCategory: "SHAPE_INVALID" },
  };
}

// --- level 1: how the provider domain is derived from provider.url ------------------
// The provider domain is the host the WHATWG URL parser reports. Each fixture
// below sets one provider.url and binds the attestation domain, the agentId
// domain and the DNS record name to `domain`.

const SPEC_WHATWG_URL = (section) => ({
  id: "WHATWG URL",
  ref: "https://url.spec.whatwg.org/",
  section,
});

// The host `new URL(url)` reports for a string, or null where it throws or finds
// none. A value that is not a string has no host (new URL() would coerce it).
function whatwgHost(url) {
  if (typeof url !== "string") return null;
  try {
    return new URL(url).hostname || null;
  } catch {
    return null;
  }
}

function providerUrlFixture({ file, description, specDetail, whatwgSection, providerUrl, providerDomain, domain = "example.com", expected }) {
  assertEqual(whatwgHost(providerUrl), providerDomain, `${file}: provider domain of ${providerUrl}`);
  return {
    $schema: "https://a2a-idf.opena2a.org/schemas/fixture-level-v1.json",
    name: `levels/${file}`,
    description,
    spec: [
      ...levelSpecBase(`Level 1 DNS Verification (${specDetail})`),
      ...(whatwgSection ? [SPEC_WHATWG_URL(whatwgSection)] : []),
    ],
    level: 1,
    agentCard: agentCard("DOMAIN_VERIFIED", {
      agentId: `urn:a2a:agent:${domain}:financial-advisor:v2`,
      providerUrl,
      attestations: [
        {
          type: "domain",
          domain,
          verifiedAt: "2026-02-17T00:00:00Z",
          method: "DNS_TXT",
        },
      ],
    }),
    evidence: {
      dnsTxt: {
        recordName: `_a2a-identity.${domain}`,
        recordValue: dnsTxtRecordValue(agentFingerprint()),
      },
    },
    expected,
  };
}

function level1ProviderUrlNotStringFixture() {
  return providerUrlFixture({
    file: "level-1-provider-url-not-string",
    description:
      "Negative fixture: the DOMAIN_VERIFIED AgentCard whose provider.url is an array holding the URL string https://example.com, not the string itself. The domain attestation, the agentId and the DNS TXT record all name example.com. A conforming verifier MUST reject at the shape stage: provider.url must be a string. A verifier that hands the value to a URL parser without checking its type can have it coerced to the string inside, derive example.com, and accept.",
    specDetail: "provider.url that is not a string",
    providerUrl: ["https://example.com"],
    providerDomain: null,
    expected: { verifyResult: "REJECT", rejectCategory: "SHAPE_INVALID" },
  });
}

function level1ProviderUrlNoHostFixture() {
  return providerUrlFixture({
    file: "level-1-provider-url-no-host",
    description:
      "Negative fixture: the DOMAIN_VERIFIED AgentCard whose provider.url is mailto:ops@example.com, a URL that has no host. The domain attestation, the agentId and the DNS TXT record all name example.com. A conforming verifier MUST reject at the shape stage: provider.url yields no provider domain to bind to. A verifier that takes the empty host as the domain reports DOMAIN_MISMATCH and fails this fixture.",
    specDetail: "provider.url without a host",
    whatwgSection: "URL representation (a URL with an opaque path has a null host)",
    providerUrl: "mailto:ops@example.com",
    providerDomain: null,
    expected: { verifyResult: "REJECT", rejectCategory: "SHAPE_INVALID" },
  });
}

function level1ProviderUrlSpaceInHostFixture() {
  return providerUrlFixture({
    file: "level-1-provider-url-space-in-host",
    description:
      "Negative fixture: the DOMAIN_VERIFIED AgentCard whose provider.url is https://exa mple.com, with a space inside the host. A space is a forbidden host code point, so the URL does not parse. The domain attestation, the agentId and the DNS TXT record all name example.com. A conforming verifier MUST reject at the shape stage: provider.url yields no provider domain. A verifier whose URL parser returns the host with the space in it reports DOMAIN_MISMATCH and fails this fixture.",
    specDetail: "provider.url with a forbidden host code point",
    whatwgSection: "host parsing (forbidden domain code points)",
    providerUrl: "https://exa mple.com",
    providerDomain: null,
    expected: { verifyResult: "REJECT", rejectCategory: "SHAPE_INVALID" },
  });
}

function level1ProviderUrlPercentEncodedFixture() {
  return providerUrlFixture({
    file: "level-1-provider-url-percent-encoded",
    description:
      "Level 1 (DOMAIN_VERIFIED) with a percent-encoded provider host: provider.url is https://ex%61mple.com, where %61 is the letter a. Every binding names example.com. A conforming verifier percent-decodes the host before using it as the provider domain, as the WHATWG URL parser does, and ACCEPTs. A verifier that keeps the host as written, or refuses the percent sign, rejects and fails this fixture.",
    specDetail: "percent-encoded provider host",
    whatwgSection: "host parsing (percent-decoding of a domain)",
    providerUrl: "https://ex%61mple.com",
    providerDomain: "example.com",
    expected: { verifyResult: "ACCEPT" },
  });
}

function level1ProviderUrlBackslashAuthorityFixture() {
  return providerUrlFixture({
    file: "level-1-provider-url-backslash-authority",
    description:
      "Negative fixture: the DOMAIN_VERIFIED AgentCard whose provider.url is https://evil.example\\@example.com (one backslash before the @). In an http or https URL a backslash ends the authority exactly as a slash does, so the host is evil.example and the rest is the path. The domain attestation, the agentId and the DNS TXT record all name example.com. A conforming verifier MUST reject: the provider domain is evil.example, which no binding names. A verifier whose URL parser reads the text before the @ as credentials derives example.com and accepts a card served from another host.",
    specDetail: "backslash in the provider.url authority",
    whatwgSection: "URL parsing (authority state: a backslash ends the authority of a special scheme)",
    providerUrl: "https://evil.example\\@example.com",
    providerDomain: "evil.example",
    expected: { verifyResult: "REJECT", rejectCategory: "DOMAIN_MISMATCH" },
  });
}

function level1ProviderUrlIgnoredCodePointFixture() {
  return providerUrlFixture({
    file: "level-1-provider-url-ignored-code-point",
    description:
      "Level 1 (DOMAIN_VERIFIED) with a soft hyphen (U+00AD) in the provider host: provider.url is https://example.com with that code point between exam and ple, written as a JSON Unicode escape in this file. UTS #46 maps the soft hyphen to nothing, so the provider domain is example.com, which every binding names. A conforming verifier drops the ignored code point when it converts the domain to ASCII, as the WHATWG URL parser does, and ACCEPTs. A verifier that Punycode-encodes the label with the soft hyphen in it derives xn--example-oka.com and reports a spurious DOMAIN_MISMATCH.",
    specDetail: "ignored code point in the provider host",
    whatwgSection: "domain to ASCII (UTS #46 ignored code points)",
    providerUrl: "https://exam\u00adple.com",
    providerDomain: "example.com",
    expected: { verifyResult: "ACCEPT" },
  });
}

function level1ProviderUrlIpv4NumberFixture() {
  return providerUrlFixture({
    file: "level-1-provider-url-ipv4-number",
    description:
      "Negative fixture: the DOMAIN_VERIFIED AgentCard whose provider.url is https://0x7f.0.0.1, while the domain attestation, the agentId and the DNS TXT record name all spell the host the same way, 0x7f.0.0.1. A host whose last label is a number is an IPv4 address, and the WHATWG URL parser reports it in dotted-decimal form: the provider domain is 127.0.0.1. A conforming verifier MUST reject: no binding names 127.0.0.1. A verifier that compares the host as written accepts, and so treats two spellings of one address as two domains.",
    specDetail: "numeric provider host",
    whatwgSection: "host parsing (IPv4 parser)",
    providerUrl: "https://0x7f.0.0.1",
    providerDomain: "127.0.0.1",
    domain: "0x7f.0.0.1",
    expected: { verifyResult: "REJECT", rejectCategory: "DOMAIN_MISMATCH" },
  });
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

// RFC 8785 §3.2.3 property-sorting example, and the order the RFC requires:
// UTF-16 code units, so U+1F600 (surrogate pair D83D DE00) sorts before
// U+FB33, the reverse of code-point order.
const RFC8785_SORTING_EXAMPLE = {
  "€": "Euro Sign",
  "\r": "Carriage Return",
  "דּ": "Hebrew Letter Dalet With Dagesh",
  "1": "One",
  "😀": "Emoji: Grinning Face",
  "\u0080": "Control",
  "ö": "Latin Small Letter O With Diaeresis",
};
const RFC8785_SORTED_KEYS = ["\r", "1", "\u0080", "ö", "€", "😀", "דּ"];

function level2NonBmpKeysFixture() {
  assertEqual(
    jcs(RFC8785_SORTING_EXAMPLE),
    `{${RFC8785_SORTED_KEYS.map((k) => `${JSON.stringify(k)}:${JSON.stringify(RFC8785_SORTING_EXAMPLE[k])}`).join(",")}}`,
    "RFC 8785 §3.2.3 property sorting",
  );
  const attestation = signedOrgAttestation({
    verifiedAt: "2026-02-17T00:00:00Z",
    expiresAt: "2027-02-17T00:00:00Z",
    extra: { rfc8785SortingExample: RFC8785_SORTING_EXAMPLE },
  });
  return {
    $schema: "https://a2a-idf.opena2a.org/schemas/fixture-level-v1.json",
    name: "levels/level-2-attestation-non-bmp-keys",
    description:
      "Level 2 (ORGANIZATION_VERIFIED): the valid organization attestation with one additional member, rfc8785SortingExample, whose property names are the RFC 8785 §3.2.3 sorting example. That set contains a key outside the Basic Multilingual Plane (U+1F600) and a key in U+E000-U+FFFF (U+FB33), so ordering by UTF-16 code units (required) and by Unicode code points (not conforming) produce different signing inputs. The registry signed the UTF-16-ordered JCS form. A conforming verifier includes the unknown member in the signing input, sorts it per RFC 8785 §3.2.3, and ACCEPTs; a verifier that sorts by code point reconstructs different bytes and rejects with SIGNATURE_INVALID.",
    spec: [
      SPEC_IDF_LEVELS("§1 Organization Verification (registry attestation)"),
      SPEC_RFC8785("§3.2.3 Sorting of Object Properties (UTF-16 code units)"),
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

function level2IssuerNotObjectFixture() {
  const attestation = signedOrgAttestation({
    verifiedAt: "2026-02-17T00:00:00Z",
    expiresAt: "2027-02-17T00:00:00Z",
    tamper: (att) => {
      att.issuer = att.issuer.name;
    },
  });
  return {
    $schema: "https://a2a-idf.opena2a.org/schemas/fixture-level-v1.json",
    name: "levels/level-2-issuer-not-object",
    description:
      "Negative fixture: an ORGANIZATION_VERIFIED attestation whose issuer is a bare string (the registry name) instead of the {name, kid, url} object. Every other field is well-formed. A conforming verifier MUST reject at the shape stage, before any binding or signature check: a malformed field resolves to SHAPE_INVALID, never to an exception.",
    spec: [
      SPEC_IDF_LEVELS("§1 Organization Verification (attestation shape)"),
      SPEC_RFC8032("§7.1 Test 2 (registry issuer key)"),
    ],
    level: 2,
    agentCard: agentCard("ORGANIZATION_VERIFIED", { attestations: [attestation] }),
    evidence: {
      issuerPublicKey: issuerPublicKeyJwk(),
      validationTime: VALIDATION_TIME,
    },
    expected: { verifyResult: "REJECT", rejectCategory: "SHAPE_INVALID" },
  };
}

function level2VerifiedAtNotStringFixture() {
  const attestation = signedOrgAttestation({
    verifiedAt: "2026-02-17T00:00:00Z",
    expiresAt: "2027-02-17T00:00:00Z",
    tamper: (att) => {
      att.verifiedAt = [att.verifiedAt];
    },
  });
  return {
    $schema: "https://a2a-idf.opena2a.org/schemas/fixture-level-v1.json",
    name: "levels/level-2-verified-at-not-string",
    description:
      "Negative fixture: an ORGANIZATION_VERIFIED attestation whose verifiedAt is an array holding the timestamp string, not the string itself. Every other field is well-formed. A conforming verifier MUST reject at the shape stage: verifiedAt must be a string in YYYY-MM-DDTHH:MM:SSZ form. A verifier that tests the value against a pattern without checking its type can coerce the array to its only element, pass the shape check, and report SIGNATURE_INVALID instead.",
    spec: [
      SPEC_IDF_LEVELS("§1 Organization Verification (attestation shape)"),
      SPEC_RFC8032("§7.1 Test 2 (registry issuer key)"),
    ],
    level: 2,
    agentCard: agentCard("ORGANIZATION_VERIFIED", { attestations: [attestation] }),
    evidence: {
      issuerPublicKey: issuerPublicKeyJwk(),
      validationTime: VALIDATION_TIME,
    },
    expected: { verifyResult: "REJECT", rejectCategory: "SHAPE_INVALID" },
  };
}

// ASCII property names whose RFC 8785 §3.2.3 order (UTF-16 code units) differs
// from numeric order ("10" before "9") and from case-insensitive order ("B"
// and "Z" before "_" and "a").
const ASCII_KEY_ORDER_EXAMPLE = {
  a: "Latin Small Letter A",
  "9": "Digit Nine",
  B: "Latin Capital Letter B",
  "10": "Digits One Zero",
  aa: "Latin Small Letter A, twice",
  _: "Low Line",
  Z: "Latin Capital Letter Z",
};
const ASCII_KEY_ORDER_SORTED = ["10", "9", "B", "Z", "_", "a", "aa"];

function level2JcsUtf16KeyOrderFixture() {
  assertEqual(
    jcs(ASCII_KEY_ORDER_EXAMPLE),
    `{${ASCII_KEY_ORDER_SORTED.map((k) => `${JSON.stringify(k)}:${JSON.stringify(ASCII_KEY_ORDER_EXAMPLE[k])}`).join(",")}}`,
    "RFC 8785 §3.2.3 property sorting of ASCII names",
  );
  const attestation = signedOrgAttestation({
    verifiedAt: "2026-02-17T00:00:00Z",
    expiresAt: "2027-02-17T00:00:00Z",
    extra: { annotations: ASCII_KEY_ORDER_EXAMPLE },
  });
  return {
    $schema: "https://a2a-idf.opena2a.org/schemas/fixture-level-v1.json",
    name: "levels/level-2-jcs-utf16-key-order",
    description:
      "Level 2 (ORGANIZATION_VERIFIED) with an annotations object whose ASCII property names sort differently under RFC 8785 §3.2.3 than under two common alternatives. JCS compares property names as UTF-16 code units, so 10 sorts before 9 (digits compare as characters, not as numbers) and B and Z sort before _ and a (upper case before lower case). The registry signed that order. A conforming verifier ACCEPTs; a verifier that sorts numerically, case-insensitively or by locale collation reconstructs a different signing input and reports a spurious SIGNATURE_INVALID. The non-ASCII half of the rule, code units against code points, is pinned by level-2-attestation-non-bmp-keys.",
    spec: [
      SPEC_IDF_LEVELS("§1 Organization Verification (registry attestation)"),
      SPEC_RFC8785("§3.2.3 Sorting of Object Properties (UTF-16 code units)"),
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

function level2NotYetValidFixture() {
  const attestation = signedOrgAttestation({
    verifiedAt: "2026-09-01T00:00:00Z",
    expiresAt: "2027-09-01T00:00:00Z",
  });
  return {
    $schema: "https://a2a-idf.opena2a.org/schemas/fixture-level-v1.json",
    name: "levels/level-2-attestation-not-yet-valid",
    description:
      "Negative fixture: an ORGANIZATION_VERIFIED attestation whose registry signature is VALID but whose validity window starts after the pinned validationTime (verifiedAt 2026-09-01 > validationTime 2026-07-03). Every other field is well-formed and correctly bound. A conforming verifier MUST reject on the validity window alone. Models an attestation presented before its issuer-stated start time; the fixture pins validationTime so the decision never depends on the wall clock.",
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
    expected: { verifyResult: "REJECT", rejectCategory: "NOT_YET_VALID" },
  };
}

function level2SubjectMismatchFixture() {
  const attestation = signedOrgAttestation({
    verifiedAt: "2026-02-17T00:00:00Z",
    expiresAt: "2027-02-17T00:00:00Z",
    subjectAgentId: "urn:a2a:agent:example.com:payments-bot:v1",
  });
  return {
    $schema: "https://a2a-idf.opena2a.org/schemas/fixture-level-v1.json",
    name: "levels/level-2-subject-mismatch",
    description:
      "Negative fixture: an ORGANIZATION_VERIFIED AgentCard carrying a registry attestation that is validly signed and inside its validity window, but whose subject.agentId names a different agent of the same organization (urn:a2a:agent:example.com:payments-bot:v1). subject.kid matches the declared key ID. A conforming verifier MUST reject: the attestation does not bind to the declared agentId. Models replay of an attestation the registry issued to another agent.",
    spec: [
      SPEC_IDF_LEVELS("§1 Organization Verification (attestation subject binding)"),
      SPEC_RFC8785("JCS canonical form (attestation signing input)"),
      SPEC_RFC8032("§7.1 Test 2 (registry issuer key)"),
    ],
    level: 2,
    agentCard: agentCard("ORGANIZATION_VERIFIED", { attestations: [attestation] }),
    evidence: {
      issuerPublicKey: issuerPublicKeyJwk(),
      validationTime: VALIDATION_TIME,
    },
    expected: { verifyResult: "REJECT", rejectCategory: "SUBJECT_MISMATCH" },
  };
}

function level2MultiDefectFixture() {
  const attestation = signedOrgAttestation({
    verifiedAt: "2026-02-17T00:00:00Z",
    expiresAt: "2027-02-17T00:00:00Z",
    subjectKid: "agent-e5f6a7b8",
  });
  return {
    $schema: "https://a2a-idf.opena2a.org/schemas/fixture-level-v1.json",
    name: "levels/level-2-multi-defect-subject-and-evidence",
    description:
      "Check-order fixture with two defects: the validly signed attestation's subject.kid (agent-e5f6a7b8) does not match the declared publicKey.kid (agent-a1b2c3d4), a SUBJECT_MISMATCH, and evidence omits validationTime, a SHAPE_INVALID. The subject binding check precedes the evidence shape check in the contract order, so a conforming verifier MUST reject with SUBJECT_MISMATCH. A verifier that runs every shape check before any binding check reports SHAPE_INVALID and fails this fixture.",
    spec: [
      SPEC_IDF_LEVELS("§1 Organization Verification (check order: subject binding before evidence shape)"),
      SPEC_RFC8785("JCS canonical form (attestation signing input)"),
      SPEC_RFC8032("§7.1 Test 2 (registry issuer key)"),
    ],
    level: 2,
    agentCard: agentCard("ORGANIZATION_VERIFIED", { attestations: [attestation] }),
    evidence: {
      issuerPublicKey: issuerPublicKeyJwk(),
    },
    expected: { verifyResult: "REJECT", rejectCategory: "SUBJECT_MISMATCH" },
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
    role: "Secondary keypair: the trust-registry issuer key for Level 2 organization-attestation fixtures, the substituted key in the key-substituted negative fixture, and the key of the counterparty.example agents that sign delegation-chain links and bilateral receipts in the composition fixtures.",
  }),
  "fixtures/composition/aim-did-rfc9421/signature-alone.json": signatureAloneFixture(),
  "fixtures/composition/aim-did-rfc9421/bilateral-receipt.json": bilateralReceiptFixture(),
  "fixtures/composition/aim-did-rfc9421/delegation-chain-3link.json": delegationChainFixture(),
  "fixtures/composition/aim-did-rfc9421/signature-tampered.json": signatureTamperedFixture(),
  "fixtures/composition/aim-did-rfc9421/key-substituted.json": keySubstitutedFixture(),
  "fixtures/composition/aim-did-rfc9421/body-tampered.json": bodyTamperedFixture(),
  "fixtures/composition/aim-did-rfc9421/cross-suite-mismatch.json": crossSuiteMismatchFixture(),
  "fixtures/composition/aim-did-rfc9421/signature-tag-null.json": signatureTagNullFixture(),
  "fixtures/composition/aim-did-rfc9421/signature-tag-absent.json": signatureTagAbsentFixture(),
  "fixtures/composition/aim-did-rfc9421/signature-tag-foreign.json": signatureTagForeignFixture(),
  "fixtures/composition/aim-did-rfc9421/signature-tag-foreign-tampered.json": signatureTagForeignTamperedFixture(),
  "fixtures/composition/aim-did-rfc9421/delegation-chain-depth-exceeded.json": delegationChainDepthExceededFixture(),
  "fixtures/composition/aim-did-rfc9421/delegation-chain-issuer-not-delegate.json": delegationChainIssuerNotDelegateFixture(),
  "fixtures/composition/aim-did-rfc9421/delegation-chain-leaf-not-signer.json": delegationChainLeafNotSignerFixture(),
  "fixtures/composition/aim-did-rfc9421/delegation-chain-root-tampered.json": delegationChainRootTamperedFixture(),
  "fixtures/composition/aim-did-rfc9421/delegation-chain-link-tampered.json": delegationChainLinkTamperedFixture(),
  "fixtures/composition/aim-did-rfc9421/delegation-chain-link-replaced.json": delegationChainLinkReplacedFixture(),
  "fixtures/composition/aim-did-rfc9421/delegation-chain-scope-widened.json": delegationChainScopeWidenedFixture(),
  "fixtures/composition/aim-did-rfc9421/delegation-chain-expiry-extended.json": delegationChainExpiryExtendedFixture(),
  "fixtures/composition/aim-did-rfc9421/delegation-chain-request-out-of-scope.json": delegationChainRequestOutOfScopeFixture(),
  "fixtures/composition/aim-did-rfc9421/bilateral-receipt-signature-tampered.json": bilateralReceiptSignatureTamperedFixture(),
  "fixtures/composition/aim-did-rfc9421/bilateral-receipt-other-request.json": bilateralReceiptOtherRequestFixture(),
  "fixtures/composition/aim-did-rfc9421/bilateral-receipt-status-mismatch.json": bilateralReceiptStatusMismatchFixture(),
  "fixtures/levels/level-0-self-asserted.json": level0Fixture(),
  "fixtures/levels/level-0-agent-id-malformed.json": level0MalformedFixture(),
  "fixtures/levels/level-0-agent-id-null.json": level0AgentIdNullFixture(),
  "fixtures/levels/level-1-domain-verified.json": level1Fixture(),
  "fixtures/levels/level-1-fingerprint-mismatch.json": level1FingerprintMismatchFixture(),
  "fixtures/levels/level-1-domain-mismatch.json": level1DomainMismatchFixture(),
  "fixtures/levels/level-1-agent-mismatch.json": level1AgentMismatchFixture(),
  "fixtures/levels/level-1-kid-mismatch.json": level1KidMismatchFixture(),
  "fixtures/levels/level-1-multi-defect-domain-and-version.json": level1MultiDefectFixture(),
  "fixtures/levels/level-1-idn-provider-url.json": level1IdnProviderUrlFixture(),
  "fixtures/levels/level-1-attestations-not-array.json": level1AttestationsNotArrayFixture(),
  "fixtures/levels/level-1-provider-url-not-string.json": level1ProviderUrlNotStringFixture(),
  "fixtures/levels/level-1-provider-url-no-host.json": level1ProviderUrlNoHostFixture(),
  "fixtures/levels/level-1-provider-url-space-in-host.json": level1ProviderUrlSpaceInHostFixture(),
  "fixtures/levels/level-1-provider-url-percent-encoded.json": level1ProviderUrlPercentEncodedFixture(),
  "fixtures/levels/level-1-provider-url-backslash-authority.json": level1ProviderUrlBackslashAuthorityFixture(),
  "fixtures/levels/level-1-provider-url-ignored-code-point.json": level1ProviderUrlIgnoredCodePointFixture(),
  "fixtures/levels/level-1-provider-url-ipv4-number.json": level1ProviderUrlIpv4NumberFixture(),
  "fixtures/levels/level-2-organization-verified.json": level2Fixture(),
  "fixtures/levels/level-2-attestation-tampered.json": level2TamperedFixture(),
  "fixtures/levels/level-2-attestation-expired.json": level2ExpiredFixture(),
  "fixtures/levels/level-2-attestation-non-bmp-keys.json": level2NonBmpKeysFixture(),
  "fixtures/levels/level-2-attestation-not-yet-valid.json": level2NotYetValidFixture(),
  "fixtures/levels/level-2-subject-mismatch.json": level2SubjectMismatchFixture(),
  "fixtures/levels/level-2-multi-defect-subject-and-evidence.json": level2MultiDefectFixture(),
  "fixtures/levels/level-2-issuer-not-object.json": level2IssuerNotObjectFixture(),
  "fixtures/levels/level-2-verified-at-not-string.json": level2VerifiedAtNotStringFixture(),
  "fixtures/levels/level-2-jcs-utf16-key-order.json": level2JcsUtf16KeyOrderFixture(),
};

// A soft hyphen is invisible in most editors and diffs, so a fixture that
// carries one writes it as a JSON escape. The parsed value is the same.
function serialize(content) {
  return JSON.stringify(content, null, 2).replaceAll("\u00ad", "\\u00ad") + "\n";
}

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
    writeFileSync(abs, serialize(content));
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
