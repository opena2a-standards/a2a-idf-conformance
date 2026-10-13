// Regression tests for the two reference verifiers on fixture variants that
// cannot live under fixtures/ (a malformed fixture fails the suite run). Each
// variant is a copy of a committed fixture, mutated and written to a scratch
// directory. The Python verifier needs the `cryptography` package.
//
// Usage:  node --test scripts/test/*.test.mjs

import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { generateKeyPairSync } from "node:crypto";
import {
  chmodSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  realpathSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
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

function runVerifier([command, ...args], path, options = {}) {
  return spawnSync(command, [...args, path], { encoding: "utf8", ...options });
}

// A copy of the cross-suite-mismatch fixture that pins ACCEPT, so a verifier
// that skips the crossSuiteEquivalence block passes it.
function writeAcceptVariant(t, mutate) {
  return writeVariant(t, "fixtures/composition/aim-did-rfc9421/cross-suite-mismatch.json", (fx) => {
    mutate(fx);
    fx.expected.verifyResult = "ACCEPT";
    delete fx.expected.rejectCategory;
  });
}

for (const [label, pin] of [["no", undefined], ["an empty", ""], ["a non-string", 5]]) {
  test(`byteIdentical: true with ${label} expectedSignatureBase64 is a fixture error`, (t) => {
    const path = writeAcceptVariant(t, (fx) => {
      if (pin === undefined) delete fx.crossSuiteEquivalence.envoys.expectedSignatureBase64;
      else fx.crossSuiteEquivalence.envoys.expectedSignatureBase64 = pin;
    });
    for (const [name, argv] of Object.entries(VERIFIERS)) {
      const result = runVerifier(argv, path);
      assert.equal(result.status, 1, `${name}: ${result.stdout}${result.stderr}`);
      assert.match(result.stdout, /^FAIL {2}/m, name);
      assert.match(result.stdout, /stage: +cross-suite-equivalence/, name);
      assert.match(result.stdout, /reason: .*expectedSignatureBase64 is missing, empty or not a string$/m, name);
      assert.doesNotMatch(result.stdout, /observed: ACCEPT/, name);
    }
  });
}

// A block that is present but is not a JSON object must not be read as an
// absent one. The two verifiers print the same lines; only the path on the
// first line differs, because each resolves it in its own way.
for (const [label, field, mutate] of [
  ["a string envoys", "crossSuiteEquivalence.envoys", (fx) => (fx.crossSuiteEquivalence.envoys = "not-an-object")],
  ["an array envoys", "crossSuiteEquivalence.envoys", (fx) => (fx.crossSuiteEquivalence.envoys = [{ byteIdentical: true }])],
  ["a null envoys", "crossSuiteEquivalence.envoys", (fx) => (fx.crossSuiteEquivalence.envoys = null)],
  ["a string crossSuiteEquivalence", "crossSuiteEquivalence", (fx) => (fx.crossSuiteEquivalence = "not-an-object")],
  ["an array crossSuiteEquivalence", "crossSuiteEquivalence", (fx) => (fx.crossSuiteEquivalence = [{ envoys: {} }])],
  ["a null crossSuiteEquivalence", "crossSuiteEquivalence", (fx) => (fx.crossSuiteEquivalence = null)],
  // The schema check runs before any other check: with the body tampered as
  // well, the content-digest check would otherwise fail first.
  [
    "a null envoys and a tampered body",
    "crossSuiteEquivalence.envoys",
    (fx) => {
      fx.crossSuiteEquivalence.envoys = null;
      fx.input.body = `${fx.input.body ?? ""}tampered`;
    },
  ],
]) {
  test(`${label} fails at the schema stage in both verifiers`, (t) => {
    const path = writeAcceptVariant(t, mutate);
    const outcomes = {};
    for (const [name, argv] of Object.entries(VERIFIERS)) {
      const result = runVerifier(argv, path);
      assert.equal(result.status, 1, `${name}: ${result.stdout}${result.stderr}`);
      outcomes[name] = result.stdout.replace(/^(\w+) .*$/m, "$1");
    }
    assert.equal(
      outcomes.node,
      ["FAIL", "      stage:  schema", `      reason: ${field} is present but is not a JSON object`, "summary: 0 pass, 1 fail (1 fixtures)", ""].join("\n"),
    );
    assert.equal(outcomes.python, outcomes.node);
  });
}

// NaN, Infinity and -Infinity are not JSON. JSON.parse raises on them, and
// Python's json module reads them as numbers unless told not to, which would
// make verify.py reach a verdict where verify.mjs reports ERROR.
for (const constant of ["NaN", "Infinity", "-Infinity"]) {
  test(`a fixture holding ${constant} is reported as ERROR by both verifiers`, (t) => {
    const dir = mkdtempSync(join(tmpdir(), "verify-"));
    t.after(() => rmSync(dir, { recursive: true, force: true }));
    const source = readFileSync(join(REPO, "fixtures/levels/level-0-self-asserted.json"), "utf8");
    const text = source.replace('"spec": [', `"spec": [${constant}, `);
    assert.notEqual(text, source);
    const path = join(dir, "variant.json");
    writeFileSync(path, text);
    for (const [name, argv] of Object.entries(VERIFIERS)) {
      const result = runVerifier(argv, path);
      assert.equal(result.status, 1, `${name}: ${result.stdout}${result.stderr}`);
      assert.equal(result.stderr, "", name);
      const lines = result.stdout.split("\n");
      assert.match(lines[0], /^ERROR .*variant\.json$/, name);
      assert.doesNotMatch(result.stdout, /observed:/, name);
      assert.deepEqual(lines.slice(-2), ["summary: 0 pass, 1 fail (1 fixtures)", ""], name);
    }
  });
}

// Runs both verifiers once over a scratch directory holding `variants`, an
// object of file name to fixture text, and returns each verifier's output as
// { file name: [status, ...the lines printed under it] }, so the two are
// compared whatever order each walks the directory in.
function runOverVariants(t, variants) {
  const dir = mkdtempSync(join(tmpdir(), "verify-"));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  for (const [name, text] of Object.entries(variants)) writeFileSync(join(dir, name), text);
  const blocks = {};
  for (const [verifier, argv] of Object.entries(VERIFIERS)) {
    const result = runVerifier(argv, dir);
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

// The text of a fixture after `mutate`. When `literal` is given, `mutate` sets
// one member to PLACEHOLDER and the placeholder is replaced by `literal`, JSON
// text that JSON.stringify does not write (1.0, 1e400, an integer of 5,000
// digits).
const PLACEHOLDER = "literal-placeholder";

function literalVariant(source, mutate, literal) {
  const fixture = JSON.parse(readFileSync(join(REPO, source), "utf8"));
  mutate(fixture);
  const text = JSON.stringify(fixture);
  if (literal === undefined) return text;
  const replaced = text.replace(JSON.stringify(PLACEHOLDER), () => literal);
  assert.notEqual(replaced, text);
  return replaced;
}

// A reject reason quotes a string as it is and names any other value by its
// JSON type, in the same words in both verifiers. Each runtime's own text for
// such a value differed (an empty string and [] for an empty array, undefined
// and None for a missing member), and on a deeply nested value one verifier
// raised where the other reached a verdict. The variants pin ACCEPT, so the
// reason is printed.
const VALUE_KINDS = [
  ["array", "[[]]", "a JSON array"],
  ["object", '{"a":{}}', "a JSON object"],
  ["integer", "5", "a JSON integer"],
  ["number", "0.5", "a JSON number"],
  ["infinite", "1e400", "a JSON number"],
  ["boolean", "true", "a JSON boolean"],
  ["null", "null", "a JSON null"],
  ["string", '"PLATINUM"', "PLATINUM"],
  ["missing", undefined, "(missing)"],
];
const identityParams = (fx) => fx.agentCard.capabilities.extensions[0].params;

for (const [label, member, holder, category, reason] of [
  ["an identityLevel", "identityLevel", identityParams, "SHAPE_INVALID", (text) => `unknown identityLevel: ${text}`],
  [
    "an agentId",
    "agentId",
    identityParams,
    "SHAPE_INVALID",
    (text) => `agentId is not a urn:a2a:agent:{domain}:{agent-name}:{version} URN: ${text}`,
  ],
  [
    "an attestation domain",
    "domain",
    (fx) => identityParams(fx).attestations[0],
    "DOMAIN_MISMATCH",
    (text) => `attestation domain ${text} != provider domain example.com`,
  ],
]) {
  test(`a reject reason words ${label} that is not a string the same way in both verifiers`, (t) => {
    const variants = {};
    const expected = {};
    for (const [kind, literal, text] of VALUE_KINDS) {
      // An agentId that is missing is not declared, which is another check's reject.
      if (member === "agentId" && literal === undefined) continue;
      variants[`${kind}.json`] = literalVariant(
        "fixtures/levels/level-1-domain-verified.json",
        (fx) => {
          if (literal === undefined) delete holder(fx)[member];
          else holder(fx)[member] = PLACEHOLDER;
        },
        literal,
      );
      expected[`${kind}.json`] = [
        "FAIL",
        `observed: REJECT[${category}]`,
        "stage:  verdict",
        `reason: verify result REJECT[${category}] != expected ACCEPT (${reason(text)})`,
      ];
    }
    const blocks = runOverVariants(t, variants);
    assert.deepEqual(blocks.node, expected);
    assert.deepEqual(blocks.python, blocks.node);
  });
}

// The CROSS_SUITE_MISMATCH reason of a composition fixture quotes
// crossSuiteEquivalence.envoys.vector, which the schema does not type, in the
// same way. Each runtime's own text for a vector that is not a string differed
// (1e-7 and 1e-07, 1 and 1.0, an empty string and [] for an empty array,
// undefined and None for a missing vector), and converting a deeply nested one
// to text raised: Array.prototype.toString in verify.mjs on an array nested
// 5,000 levels, repr() in verify.py on an array or an object nested 200,000.
// The fixture pins REJECT, so each copy pins ACCEPT for the reason to be
// printed.
const DEPTH = 200_000;

test("the cross-suite mismatch reason words a vector that is not a string the same way in both verifiers", (t) => {
  const variants = {};
  const expected = {};
  for (const [kind, literal, text] of [
    ...VALUE_KINDS,
    ["empty-array", "[]", "a JSON array"],
    ["float-one", "1.0", "a JSON integer"],
    ["negative-zero", "-0.0", "a JSON integer"],
    ["twenty-digits", "12345678901234567890", "a JSON integer"],
    ["small-fraction", "1e-7", "a JSON number"],
    ["integer-of-5000-digits", "7".repeat(5000), "a JSON number"],
    ["deeply-nested-array", "[".repeat(DEPTH) + "]".repeat(DEPTH), "a JSON array"],
    ["deeply-nested-object", '{"a":'.repeat(DEPTH) + "{}" + "}".repeat(DEPTH), "a JSON object"],
  ]) {
    variants[`${kind}.json`] = literalVariant(
      "fixtures/composition/aim-did-rfc9421/cross-suite-mismatch.json",
      (fx) => {
        fx.expected.verifyResult = "ACCEPT";
        delete fx.expected.rejectCategory;
        if (literal === undefined) delete fx.crossSuiteEquivalence.envoys.vector;
        else fx.crossSuiteEquivalence.envoys.vector = PLACEHOLDER;
      },
      literal,
    );
    expected[`${kind}.json`] = [
      "FAIL",
      "observed: REJECT[CROSS_SUITE_MISMATCH]",
      "stage:  verdict",
      `reason: verify result REJECT[CROSS_SUITE_MISMATCH] != expected ACCEPT (verified signature does not byte-match Envoys ${text})`,
    ];
  }
  const blocks = runOverVariants(t, variants);
  assert.deepEqual(blocks.node, expected);
  assert.deepEqual(blocks.python, blocks.node);
});

// A schema reason writes a number as text only when it is a safe integer, which
// both runtimes write the same way, and names any other number by its JSON
// type. JSON.stringify and json.dumps wrote 1 and 1.0, null and Infinity, 0 and
// -0.0, 1e-7 and 1e-07, 12345678901234567000 and 12345678901234567890. An
// integer beyond the range of a double is an infinite number in both verifiers,
// so neither calls it a JSON integer.
test("a schema reason words a number the same way in both verifiers", (t) => {
  const variants = {};
  const expected = {};
  for (const [name, literal, text] of [
    ["float-one", "1.0", "1"],
    ["negative-zero", "-0.0", "0"],
    ["largest-safe-integer", "9007199254740991", "9007199254740991"],
    ["smallest-safe-integer", "-9007199254740991", "-9007199254740991"],
    ["first-unsafe-integer", "9007199254740992", "a JSON integer"],
    ["past-safe-integers", "9007199254740993", "a JSON integer"],
    ["twenty-digits", "12345678901234567890", "a JSON integer"],
    ["small-fraction", "1e-7", "a JSON number"],
    ["float-overflow", "1e400", "a JSON number"],
    ["integer-of-400-digits", "7".repeat(400), "a JSON number"],
    ["integer-of-5000-digits", "7".repeat(5000), "a JSON number"],
    ["negative-integer-of-5000-digits", `-${"7".repeat(5000)}`, "a JSON number"],
  ]) {
    variants[`${name}.json`] = literalVariant(
      "fixtures/levels/level-0-self-asserted.json",
      (fx) => (fx.expected.verifyResult = PLACEHOLDER),
      literal,
    );
    expected[`${name}.json`] = [
      "FAIL",
      "stage:  schema",
      `reason: expected.verifyResult: ${text} is not one of "ACCEPT", "REJECT"`,
    ];
  }
  // As `level`, an integer beyond the range of a double is not a JSON integer.
  for (const digits of [400, 5000]) {
    variants[`level-of-${digits}-digits.json`] = literalVariant(
      "fixtures/levels/level-0-self-asserted.json",
      (fx) => (fx.level = PLACEHOLDER),
      "7".repeat(digits),
    );
    expected[`level-of-${digits}-digits.json`] = [
      "FAIL",
      "stage:  schema",
      "reason: level is present but is not a JSON integer",
    ];
  }
  const blocks = runOverVariants(t, variants);
  assert.deepEqual(blocks.node, expected);
  assert.deepEqual(blocks.python, blocks.node);
});

// A schema reason quotes a string as JSON text, where JSON.stringify writes a
// lone surrogate, which UTF-8 cannot encode, as a lowercase \uXXXX escape.
// verify.py wrote it as U+FFFD, as both verifiers print a string that a reason
// quotes as it is.
test("a schema reason writes a lone surrogate the same way in both verifiers", (t) => {
  const variants = {};
  const expected = {};
  for (const [name, mutate, literal, reason] of [
    [
      "enum",
      (fx) => (fx.expected.verifyResult = PLACEHOLDER),
      '"X\\ud800"',
      'expected.verifyResult: "X\\ud800" is not one of "ACCEPT", "REJECT"',
    ],
    [
      "enum-low-surrogate-and-pair",
      (fx) => (fx.expected.verifyResult = PLACEHOLDER),
      '"\\uDC00\\ud83d\\ude00"',
      'expected.verifyResult: "\\udc00\u{1F600}" is not one of "ACCEPT", "REJECT"',
    ],
    [
      "enum-two-lone-surrogates",
      (fx) => (fx.expected.verifyResult = PLACEHOLDER),
      '"\\ud800\\ud800"',
      'expected.verifyResult: "\\ud800\\ud800" is not one of "ACCEPT", "REJECT"',
    ],
    [
      "const",
      (fx) => (fx.$schema = PLACEHOLDER),
      '"X\\ud800"',
      '$schema: expected "https://a2a-idf.opena2a.org/schemas/fixture-level-v1.json", got "X\\ud800"',
    ],
  ]) {
    variants[`${name}.json`] = literalVariant("fixtures/levels/level-0-self-asserted.json", mutate, literal);
    expected[`${name}.json`] = ["FAIL", "stage:  schema", `reason: ${reason}`];
  }
  const blocks = runOverVariants(t, variants);
  assert.deepEqual(blocks.node, expected);
  assert.deepEqual(blocks.python, blocks.node);
});

// A JSON number does not record how it was written, so `created` enters the
// signature base as JavaScript writes the number: 1714000000.0 as 1714000000,
// as verify.mjs wrote it and verify.py did not. A copy whose `created` is
// another value pins that value's text in its signature base and
// Signature-Input header, so it reaches the signature check, which fails.
test("the signature base writes created the same way in both verifiers", (t) => {
  const variants = {};
  const expected = {};
  for (const [name, literal, text] of [
    ["fraction-part", "1714000000.0", "1714000000"],
    ["exponent", "1.714e9", "1714000000"],
    ["past-safe-integers", "12345678901234567890", "12345678901234567000"],
    ["exponent-form", "1e21", "1e+21"],
  ]) {
    variants[`${name}.json`] = literalVariant(
      "fixtures/composition/aim-did-rfc9421/signature-alone.json",
      (fx) => {
        const written = `created=${fx.signatureParams.created}`;
        for (const field of ["signatureBase", "signatureInput"]) {
          assert.ok(fx.expected[field].includes(written), field);
          fx.expected[field] = fx.expected[field].replace(written, `created=${text}`);
        }
        fx.signatureParams.created = PLACEHOLDER;
        if (text !== "1714000000") {
          fx.expected.verifyResult = "REJECT";
          fx.expected.rejectCategory = "SIGNATURE_INVALID";
        }
      },
      literal,
    );
    expected[`${name}.json`] = [
      "PASS",
      `observed: ${text === "1714000000" ? "ACCEPT" : "REJECT[SIGNATURE_INVALID]"}`,
    ];
  }
  const blocks = runOverVariants(t, variants);
  assert.deepEqual(blocks.node, expected);
  assert.deepEqual(blocks.python, blocks.node);
});

// A DID verificationMethod entry that is not a JSON object carries no key
// encoding in either verifier: verify.py called .get on it and raised, and
// verify.mjs read a member of a null entry and failed with its own TypeError.
// An entry of the right kind later in the list is still found by its id.
test("a verificationMethod entry that is not an object fails the same way in both verifiers", (t) => {
  const variants = {};
  const expected = {};
  for (const [name, literal] of [
    ["array", "[[]]"],
    ["null", "[null]"],
    ["string", '["key-1"]'],
    ["integer", "[5]"],
    ["boolean", "[true]"],
  ]) {
    variants[`${name}.json`] = literalVariant(
      "fixtures/composition/aim-did-rfc9421/bilateral-receipt.json",
      (fx) => (fx.keyidResolution.document.verificationMethod = PLACEHOLDER),
      literal,
    );
    expected[`${name}.json`] = [
      "FAIL",
      "stage:  public-key-extraction",
      "reason: DID verificationMethod has no usable Ed25519 key encoding",
    ];
  }
  variants["null-before-the-referenced-entry.json"] = literalVariant(
    "fixtures/composition/aim-did-rfc9421/bilateral-receipt.json",
    (fx) => fx.keyidResolution.document.verificationMethod.unshift(null),
  );
  expected["null-before-the-referenced-entry.json"] = ["PASS", "observed: ACCEPT"];
  const blocks = runOverVariants(t, variants);
  assert.deepEqual(blocks.node, expected);
  assert.deepEqual(blocks.python, blocks.node);
});

// A compact-form publicKeyPem that does not hold an Ed25519 SPKI public key
// fails at stage public-key-extraction in one wording. verify.mjs passed the
// crypto library's error through (error:1E08010C:DECODER routines::unsupported)
// and took a key of another type, reaching REJECT[SIGNATURE_INVALID] where
// verify.py stopped; verify.py passed the base64 module's error through
// (Incorrect padding).
test("a publicKeyPem that is not an Ed25519 SPKI PEM fails the same way in both verifiers", (t) => {
  const publicPem = (type, options) =>
    generateKeyPairSync(type, options).publicKey.export({ type: "spki", format: "pem" });
  const variants = {};
  const expected = {};
  for (const [name, pem] of [
    ["empty", ""],
    ["not-a-pem", "not a pem"],
    ["rsa", publicPem("rsa", { modulusLength: 2048 })],
    ["ec-p256", publicPem("ec", { namedCurve: "P-256" })],
    ["x25519", publicPem("x25519")],
    ["ed448", publicPem("ed448")],
  ]) {
    variants[`${name}.json`] = literalVariant(
      "fixtures/composition/hippo-rfc9421/signature-alone-no-tag.json",
      (fx) => (fx.keyidResolution.publicKeyPem = pem),
    );
    expected[`${name}.json`] = [
      "FAIL",
      "stage:  public-key-extraction",
      "reason: compact-form publicKeyPem is not an Ed25519 SPKI PEM",
    ];
  }
  const blocks = runOverVariants(t, variants);
  assert.deepEqual(blocks.node, expected);
  assert.deepEqual(blocks.python, blocks.node);
});

// A publicKeyMultibase character outside the base58btc alphabet is named in
// the reason as it is, like any string a reason quotes. verify.py wrote it as
// a Python literal: '0' for 0, "'" for an apostrophe, '\\' for a backslash and
// '\ud800' for a lone surrogate, which verify.mjs prints as U+FFFD.
test("an invalid base58 character is worded the same way in both verifiers", (t) => {
  const variants = {};
  const expected = {};
  for (const [name, literal, character] of [
    ["zero", '"z0"', "0"],
    ["after-valid-characters", '"z6Mkl"', "l"],
    ["apostrophe", `"z'"`, "'"],
    ["backslash", '"z\\\\"', "\\"],
    ["non-ascii", '"zé"', "é"],
    ["surrogate-pair", '"z\\ud83d\\ude00"', "\u{1F600}"],
    ["lone-surrogate", '"z\\ud800"', "\u{FFFD}"],
  ]) {
    variants[`${name}.json`] = literalVariant(
      "fixtures/composition/aim-did-rfc9421/bilateral-receipt.json",
      (fx) => (fx.keyidResolution.document.verificationMethod[0].publicKeyMultibase = PLACEHOLDER),
      literal,
    );
    expected[`${name}.json`] = [
      "FAIL",
      "stage:  public-key-extraction",
      `reason: invalid base58 character: ${character}`,
    ];
  }
  const blocks = runOverVariants(t, variants);
  assert.deepEqual(blocks.node, expected);
  assert.deepEqual(blocks.python, blocks.node);
});

const COMPACT_FIXTURE = "fixtures/composition/hippo-rfc9421/signature-alone-no-tag.json";
const NOT_AN_ED25519_PEM = [
  "FAIL",
  "stage:  public-key-extraction",
  "reason: compact-form publicKeyPem is not an Ed25519 SPKI PEM",
];

// The BEGIN line, the one base64 line and the END line of the fixture's key.
function compactPemLines() {
  const pem = JSON.parse(readFileSync(join(REPO, COMPACT_FIXTURE), "utf8")).keyidResolution.publicKeyPem;
  const lines = pem.split("\n");
  assert.equal(lines.length, 4);
  assert.equal(lines[3], "");
  return lines.slice(0, 3);
}

// Text outside the armor of a compact-form publicKeyPem is not part of the
// key. The crypto library verify.mjs calls skips the lines before the BEGIN
// line and reads nothing after the END line. verify.py deleted the two armor
// lines wherever they stood and decoded all the text that was left, so a
// character outside ASCII after the END line failed the key in verify.py alone
// (the base64 module takes ASCII text only) where ASCII text there did not,
// text before the BEGIN line was decoded as part of the key, and armor that
// verify.mjs does not read (no END line, text on the END line, no line breaks)
// still gave verify.py a key. verify.py now reads the lines as that library
// does: a line ends at a line feed or after 254 bytes, a byte order mark before
// the first line is skipped, and a line of the body ends at a NUL. verify.mjs
// now reads them by the same rules itself. The last variants of each group
// fail when one of these rules is left out of verify.py: a lone surrogate
// counts as three bytes toward a line, a byte order mark is skipped before the
// first line only, the bytes at or below a space at the end of a body line or
// of the END line are dropped, and the bytes above 0x7f there are not.
test("text outside the armor of a publicKeyPem is not part of the key in either verifier", (t) => {
  const [begin, body, end] = compactPemLines();
  const pem = `${begin}\n${body}\n${end}\n`;
  const note = (line) => line.replace("PUBLIC KEY", "NOTE");
  const accepted = {
    "non-ascii-after-the-end-line": `${pem}\xe9`,
    "non-ascii-lines-after-the-end-line": `${pem}cl\xe9 publique\n\n`,
    "lone-surrogate-after-the-end-line": `${pem}\udc00`,
    "ascii-after-the-end-line": `${pem}abc`,
    "unreadable-block-after-the-end-line": `${pem}${begin}\nnot base64 \xe9\n${end}\n`,
    "non-ascii-before-the-begin-line": `\xe9\n${pem}`,
    "ascii-before-the-begin-line": `abc\n${pem}`,
    "end-line-before-the-begin-line": `${end}\n${pem}`,
    "byte-order-mark": `${String.fromCharCode(0xfeff)}${pem}`,
    "begin-line-after-254-bytes": `${" ".repeat(254)}${pem}`,
    "text-after-a-nul-in-a-body-line": `${begin}\n${body.slice(0, 20)}\u0000x\n${body.slice(20)}\n${end}\n`,
    "begin-line-after-84-lone-surrogates-and-2-spaces": `${"\udc00".repeat(84)}  ${pem}`,
    "space-after-the-base64-line": `${begin}\n${body} \n${end}\n`,
    "space-after-the-end-line": `${begin}\n${body}\n${end} \n`,
    "nul-after-the-end-line": `${begin}\n${body}\n${end}\u0000\n`,
  };
  const refused = {
    "begin-line-after-253-bytes": `${" ".repeat(253)}${pem}`,
    "text-on-the-end-line": `${begin}\n${body}\n${end} abc\n`,
    "end-line-of-another-label": `${begin}\n${body}\n${note(end)}\n${end}\n`,
    "block-of-another-label-left-open": `${note(begin)}\n${pem}`,
    "no-end-line": `${begin}\n${body}\n`,
    "no-begin-line": `${body}\n${end}\n`,
    "no-line-breaks": `${begin}${body}${end}`,
    "non-ascii-in-the-body": `${begin}\n${body.slice(0, 20)}\xe9${body.slice(20)}\n${end}\n`,
    "byte-order-mark-after-the-first-line": `abc\n${String.fromCharCode(0xfeff)}${pem}`,
    "non-ascii-after-the-begin-line": `${begin}\xe9\n${body}\n${end}\n`,
  };
  const variants = {};
  const expected = {};
  for (const [outcome, group] of [
    [["PASS", "observed: ACCEPT"], accepted],
    [NOT_AN_ED25519_PEM, refused],
  ]) {
    for (const [name, text] of Object.entries(group)) {
      variants[`${name}.json`] = literalVariant(COMPACT_FIXTURE, (fx) => (fx.keyidResolution.publicKeyPem = text));
      expected[`${name}.json`] = outcome;
    }
  }
  const blocks = runOverVariants(t, variants);
  assert.deepEqual(blocks.node, expected);
  assert.deepEqual(blocks.python, blocks.node);
});

// A line that would open a block of another label but for a byte above 0x7f at
// its end. Where measured (Node 26 on macOS arm64) the crypto library
// verify.mjs called dropped that byte, read the line as a BEGIN line and did
// not reach the key below it; on Linux arm64 (Node 22) it read past the line.
// Neither verifier depends on how that library reads the byte now: both refuse
// the key.
test("both verifiers refuse a key below a BEGIN line of another label that ends in a non-ASCII byte", (t) => {
  const [begin, body, end] = compactPemLines();
  const path = writeVariant(t, COMPACT_FIXTURE, (fx) => {
    fx.keyidResolution.publicKeyPem = `${begin.replace("PUBLIC KEY", "NOTE")}\xe9\n${begin}\n${body}\n${end}\n`;
  });
  for (const [name, argv] of Object.entries(VERIFIERS)) {
    const result = runVerifier(argv, path);
    assert.equal(result.stderr, "", name);
    assert.deepEqual(
      result.stdout.split("\n").slice(1, 3).map((line) => line.trim()),
      NOT_AN_ED25519_PEM.slice(1),
      name,
    );
  }
});

// The text between the armor lines of a compact-form publicKeyPem must be the
// base64 text of the key, character for character. verify.py decoded it with
// the base64 module, which skips characters outside the base64 alphabet and
// stops at padding, and gave an empty line no meaning, so it accepted every
// variant below that the crypto library verify.mjs called refused. That
// library reads past a block of another label, cuts a BEGIN label at a NUL,
// ignores bytes after the key structure and reads a private key, so verify.mjs
// accepted variants that verify.py refused, and reached the signature check
// with a private key. Empty lines may come before the base64 text (RFC 7468
// Figure 1), and the text may be wrapped over several lines.
test("both verifiers read the base64 text of a publicKeyPem strictly", (t) => {
  const [begin, body, end] = compactPemLines();
  const pem = `${begin}\n${body}\n${end}\n`;
  const within = (text) => `${begin}\n${body.slice(0, 20)}${text}${body.slice(20)}\n${end}\n`;
  const privatePem = generateKeyPairSync("ed25519").privateKey.export({ type: "pkcs8", format: "pem" });
  const accepted = {
    "empty-line-before-the-base64-text": `${begin}\n\n${body}\n${end}\n`,
    "line-of-spaces-before-the-base64-text": `${begin}\n   \n${body}\n${end}\n`,
    "base64-text-on-two-lines": `${begin}\n${body.slice(0, 20)}\n${body.slice(20)}\n${end}\n`,
  };
  const refused = {
    "empty-line-after-the-base64-text": `${begin}\n${body}\n\n${end}\n`,
    "line-of-spaces-after-the-base64-text": `${begin}\n${body}\n   \n${end}\n`,
    "nul-line-after-the-base64-text": `${begin}\n${body}\n\u0000\n${end}\n`,
    "empty-line-within-the-base64-text": `${begin}\n${body.slice(0, 20)}\n\n${body.slice(20)}\n${end}\n`,
    "colon-in-the-base64-text": within(":"),
    "colon-line": `${begin}\n:\n${body}\n${end}\n`,
    "exclamation-mark-in-the-base64-text": within("!"),
    "underscore-in-the-base64-text": within("_"),
    "full-stop-in-the-base64-text": within("."),
    "vertical-tab-in-the-base64-text": within("\u000b"),
    "form-feed-in-the-base64-text": within("\u000c"),
    "delete-in-the-base64-text": within("\u007f"),
    "space-in-the-base64-text": within(" "),
    "hyphen-before-the-base64-text": `${begin}\n-${body}\n${end}\n`,
    "hyphen-in-the-base64-text": within("-"),
    "padding-after-the-base64-text": `${begin}\n${body}=\n${end}\n`,
    "one-character-after-the-base64-text": `${begin}\n${body}A\n${end}\n`,
    "four-characters-after-the-base64-text": `${begin}\n${body}AAAA\n${end}\n`,
    "base64-line-twice": `${begin}\n${body}\n${body}\n${end}\n`,
    "a-byte-after-the-key": `${begin}\n${body.slice(0, -1)}A\n${end}\n`,
    "block-of-another-label-before-the-key": `-----BEGIN NOTE-----\nAAAA\n-----END NOTE-----\n${pem}`,
    "nul-in-the-begin-label": `${begin.replace("KEY-----", "KEY\u0000-----")}\n${body}\n${end}\n`,
    "non-ascii-after-the-base64-line": `${begin}\n${body}\xe9\n${end}\n`,
    "non-ascii-after-the-end-line-on-its-line": `${begin}\n${body}\n${end}\xe9\n`,
    "private-key": privatePem,
  };
  const variants = {};
  const expected = {};
  for (const [outcome, group] of [
    [["PASS", "observed: ACCEPT"], accepted],
    [NOT_AN_ED25519_PEM, refused],
  ]) {
    for (const [name, text] of Object.entries(group)) {
      variants[`${name}.json`] = literalVariant(COMPACT_FIXTURE, (fx) => (fx.keyidResolution.publicKeyPem = text));
      expected[`${name}.json`] = outcome;
    }
  }
  const blocks = runOverVariants(t, variants);
  assert.deepEqual(blocks.node, expected);
  assert.deepEqual(blocks.python, blocks.node);
});

// The crypto library verify.mjs called asked for a pass phrase on the terminal
// and waited when the block carried an encryption header; with no terminal it
// wrote the prompt to stderr. A fixture must not make a verifier wait for
// input. The verifiers run with no controlling terminal and no input, under a
// time limit, so this test cannot wait either.
test("an encryption header in a publicKeyPem does not make either verifier ask for a pass phrase", (t) => {
  const [begin, body, end] = compactPemLines();
  const path = writeVariant(t, COMPACT_FIXTURE, (fx) => {
    fx.keyidResolution.publicKeyPem = [
      begin,
      "Proc-Type: 4,ENCRYPTED",
      `DEK-Info: AES-128-CBC,${"0".repeat(32)}`,
      "",
      body,
      end,
      "",
    ].join("\n");
  });
  for (const [name, argv] of Object.entries(VERIFIERS)) {
    const result = runVerifier(argv, path, { detached: true, stdio: ["ignore", "pipe", "pipe"], timeout: 60_000 });
    assert.equal(result.error, undefined, name);
    assert.equal(result.stderr, "", name);
    assert.equal(result.status, 1, name);
    assert.deepEqual(
      result.stdout.split("\n").slice(1, 3).map((line) => line.trim()),
      NOT_AN_ED25519_PEM.slice(1),
      name,
    );
  }
});

// A reason that quotes a fixture string printed its control characters as they
// are, so a fixture could break the report line or move the cursor and erase
// lines on a terminal. Both verifiers write a C0 or C1 control character in a
// printed line as a lowercase \uXXXX escape; a schema reason already wrote a C0
// control character that way, as JSON text, but not a C1 one.
test("a control character in a quoted value is written as an escape by both verifiers", (t) => {
  const DID_FIXTURE = "fixtures/composition/aim-did-rfc9421/bilateral-receipt.json";
  const variants = {};
  const expected = {};
  for (const [name, value, reason] of [
    ["escape-sequences", "x\u001b[1A\u001b[2KPASS", "unsupported multibase prefix in x\\u001b[1A\\u001b[2KPASS"],
    ["line-feed", "z\n", "invalid base58 character: \\u000a"],
    ["carriage-return", "x\rPASS", "unsupported multibase prefix in x\\u000dPASS"],
    ["delete", "z\u007f", "invalid base58 character: \\u007f"],
    ["c1-control", "x\u009b2K", "unsupported multibase prefix in x\\u009b2K"],
  ]) {
    variants[`${name}.json`] = literalVariant(
      DID_FIXTURE,
      (fx) => (fx.keyidResolution.document.verificationMethod[0].publicKeyMultibase = value),
    );
    expected[`${name}.json`] = ["FAIL", "stage:  public-key-extraction", `reason: ${reason}`];
  }
  variants["schema-reason-c1-control.json"] = literalVariant(
    "fixtures/levels/level-0-self-asserted.json",
    (fx) => (fx.expected.verifyResult = "X\u009b\u001b"),
  );
  expected["schema-reason-c1-control.json"] = [
    "FAIL",
    "stage:  schema",
    'reason: expected.verifyResult: "X\\u009b\\u001b" is not one of "ACCEPT", "REJECT"',
  ];
  const blocks = runOverVariants(t, variants);
  assert.deepEqual(blocks.node, expected);
  assert.deepEqual(blocks.python, blocks.node);
});

// The escape written for a control character was not itself escaped, so a
// quoted value of the six characters \u001b printed the same line as one of
// U+001B. Both verifiers write a backslash followed by "u" in a printed line as
// \, and only that backslash; a schema reason quotes a string as JSON
// text, which writes a backslash as \\ already, and keeps its backslashes.
test("a backslash before u in a quoted value is escaped by both verifiers", (t) => {
  const DID_FIXTURE = "fixtures/composition/aim-did-rfc9421/bilateral-receipt.json";
  const variants = {};
  const expected = {};
  for (const [name, value, reason] of [
    ["control-character", "x\u001b", "unsupported multibase prefix in x\\u001b"],
    ["backslash-u", "x\\u001b", "unsupported multibase prefix in x\\u005cu001b"],
    ["two-backslashes-u", "x\\\\u", "unsupported multibase prefix in x\\\\u005cu"],
    ["backslash-n", "x\\n", "unsupported multibase prefix in x\\n"],
  ]) {
    variants[`${name}.json`] = literalVariant(
      DID_FIXTURE,
      (fx) => (fx.keyidResolution.document.verificationMethod[0].publicKeyMultibase = value),
    );
    expected[`${name}.json`] = ["FAIL", "stage:  public-key-extraction", `reason: ${reason}`];
  }
  for (const [name, value, text] of [
    ["schema-reason-control-character", "X\u001b", '"X\\u001b"'],
    ["schema-reason-backslash-u", "X\\u001b", '"X\\\\u001b"'],
  ]) {
    variants[`${name}.json`] = literalVariant(
      "fixtures/levels/level-0-self-asserted.json",
      (fx) => (fx.expected.verifyResult = value),
    );
    expected[`${name}.json`] = [
      "FAIL",
      "stage:  schema",
      `reason: expected.verifyResult: ${text} is not one of "ACCEPT", "REJECT"`,
    ];
  }
  const blocks = runOverVariants(t, variants);
  assert.deepEqual(blocks.node, expected);
  assert.deepEqual(blocks.python, blocks.node);
});

// Reject reasons of level fixtures that the two verifiers worded differently:
// a field the DNS TXT record does not carry (undefined and None), identity
// params that are a JSON array (verify.mjs took an array as params), a Level 2
// signature that is not 64 bytes (verify.py had a reason of its own), and a
// quoted string holding a lone surrogate, which UTF-8 cannot encode (U+FFFD
// from verify.mjs, \ud800 from verify.py), each of them when it holds two. A
// provider URL holding two lone surrogates names an opaque host in which the
// URL parser read each of them as U+FFFD and percent-encoded it. The variants
// pin ACCEPT, so the reason is printed.
test("level reject reasons are worded the same way in both verifiers", (t) => {
  const LEVEL_1 = "fixtures/levels/level-1-domain-verified.json";
  const LEVEL_2 = "fixtures/levels/level-2-organization-verified.json";
  const record = Object.fromEntries(
    JSON.parse(readFileSync(join(REPO, LEVEL_1), "utf8"))
      .evidence.dnsTxt.recordValue.split("; ")
      .map((part) => part.split("=", 2)),
  );
  const withoutField = (name) => (fx) => {
    fx.evidence.dnsTxt.recordValue = Object.entries(record)
      .filter(([key]) => key !== name)
      .map(([key, value]) => `${key}=${value}`)
      .join("; ");
  };
  const organizationAttestation = (fx) =>
    identityParams(fx).attestations.find((a) => a.type === "organization");
  const variants = {};
  const expected = {};
  for (const [name, source, mutate, category, reason, literal] of [
    ["record-without-v", LEVEL_1, withoutField("v"), "SHAPE_INVALID", "unsupported record version: (missing)"],
    ["record-agent-only", LEVEL_1, (fx) => (fx.evidence.dnsTxt.recordValue = "agent=x"), "SHAPE_INVALID", "unsupported record version: (missing)"],
    ["record-without-agent", LEVEL_1, withoutField("agent"), "AGENT_MISMATCH", "record agent (missing) != agentId name financial-advisor"],
    ["record-without-kid", LEVEL_1, withoutField("kid"), "KID_MISMATCH", `record kid (missing) != declared kid ${record.kid}`],
    ["record-without-fp", LEVEL_1, withoutField("fp"), "FINGERPRINT_MISMATCH", `record fp (missing) != computed ${record.fp}`],
    [
      "params-array",
      LEVEL_1,
      (fx) => (fx.agentCard.capabilities.extensions[0].params = []),
      "SHAPE_INVALID",
      "agent-identity extension (or its params) missing",
    ],
    [
      "signature-not-base64url",
      LEVEL_2,
      (fx) => (organizationAttestation(fx).signature = "x"),
      "SIGNATURE_INVALID",
      "registry signature does not verify over the attestation JCS form",
    ],
    [
      "signature-of-3-bytes",
      LEVEL_2,
      (fx) => (organizationAttestation(fx).signature = "AAAA"),
      "SIGNATURE_INVALID",
      "registry signature does not verify over the attestation JCS form",
    ],
    [
      "lone-surrogate",
      LEVEL_1,
      (fx) => (identityParams(fx).identityLevel = PLACEHOLDER),
      "SHAPE_INVALID",
      "unknown identityLevel: X�",
      '"X\\ud800"',
    ],
    [
      "two-lone-surrogates",
      LEVEL_1,
      (fx) => (identityParams(fx).identityLevel = PLACEHOLDER),
      "SHAPE_INVALID",
      "unknown identityLevel: ��",
      '"\\ud800\\ud800"',
    ],
    [
      "provider-url-two-lone-surrogates",
      LEVEL_1,
      (fx) => (fx.agentCard.provider.url = PLACEHOLDER),
      "DOMAIN_MISMATCH",
      "attestation domain example.com != provider domain ex%EF%BF%BD%EF%BF%BDample.com",
      '"foo://ex\\ud800\\ud800ample.com/"',
    ],
  ]) {
    variants[`${name}.json`] = literalVariant(
      source,
      (fx) => {
        mutate(fx);
        fx.expected = { verifyResult: "ACCEPT" };
      },
      literal,
    );
    expected[`${name}.json`] = [
      "FAIL",
      `observed: REJECT[${category}]`,
      "stage:  verdict",
      `reason: verify result REJECT[${category}] != expected ACCEPT (${reason})`,
    ];
  }
  const blocks = runOverVariants(t, variants);
  assert.deepEqual(blocks.node, expected);
  assert.deepEqual(blocks.python, blocks.node);
});

// A fixture path that does not exist is an ERROR fixture with a summary line,
// not an uncaught exception. The message wording is each runtime's own.
test("a fixture path that does not exist is reported as ERROR by both verifiers", (t) => {
  const dir = mkdtempSync(join(tmpdir(), "verify-"));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const path = join(dir, "missing.json");
  for (const [name, argv] of Object.entries(VERIFIERS)) {
    const result = runVerifier(argv, path);
    assert.equal(result.status, 1, `${name}: ${result.stdout}${result.stderr}`);
    assert.equal(result.stderr, "", name);
    const lines = result.stdout.split("\n");
    assert.match(lines[0], /^ERROR .*missing\.json$/, name);
    assert.match(lines[1], /^ {6}.*no such file or directory.*missing\.json/i, name);
    assert.deepEqual(lines.slice(2), ["summary: 0 pass, 1 fail (1 fixtures)", ""], name);
  }
});

// A path that cannot be stat'ed or read, or a directory that cannot be listed,
// is an ERROR entry whose message names it, and the run goes on to the summary
// line: never an uncaught exception, and never a run that skips the entry and
// exits 0. `errors` lists each expected ERROR entry as [path, message pattern].
const SYMLINK_LOOP = /too many (levels of )?symbolic links/i;
const NO_PERMISSION = /permission denied/i;

function assertErrorEntries(name, result, dir, errors, summary) {
  assert.equal(result.status, 1, `${name}: ${result.stdout}${result.stderr}`);
  assert.equal(result.stderr, "", name);
  const lines = result.stdout.split("\n");
  for (const [path, message] of errors) {
    const at = lines.indexOf(`ERROR ${join(dir, path)}`);
    assert.notEqual(at, -1, `${name}: no ERROR line for ${path}\n${result.stdout}`);
    assert.match(lines[at + 1], message, name);
    assert.ok(lines[at + 1].includes(join(dir, path)), `${name}: ${lines[at + 1]}`);
  }
  assert.deepEqual(lines.slice(-2), [summary, ""], name);
}

// A scratch directory holding `valid.json`, a copy of a fixture both verifiers
// pass, so each case shows the walk going on past the entry it cannot read. The
// directory is given without symlinks, so both verifiers print the paths
// written here.
function scratchFixtureDir(t) {
  const dir = realpathSync(mkdtempSync(join(tmpdir(), "verify-")));
  const locked = [];
  t.after(() => {
    for (const path of locked) chmodSync(path, 0o755);
    rmSync(dir, { recursive: true, force: true });
  });
  writeFileSync(join(dir, "valid.json"), readFileSync(join(REPO, "fixtures/levels/level-0-self-asserted.json")));
  return { dir, lock: (path, mode = 0o000) => (locked.push(path), chmodSync(path, mode)) };
}

test("a symlink loop is reported as ERROR by both verifiers", { skip: process.platform === "win32" }, (t) => {
  const { dir } = scratchFixtureDir(t);
  symlinkSync("loop-b.json", join(dir, "loop-a.json"));
  symlinkSync("loop-a.json", join(dir, "loop-b.json"));
  // Not a fixture name, so the walk passes over it in both verifiers.
  symlinkSync("loop-c", join(dir, "loop-c"));
  for (const [name, argv] of Object.entries(VERIFIERS)) {
    assertErrorEntries(
      `${name} (named)`,
      runVerifier(argv, join(dir, "loop-a.json")),
      dir,
      [["loop-a.json", SYMLINK_LOOP]],
      "summary: 0 pass, 1 fail (1 fixtures)",
    );
    assertErrorEntries(
      `${name} (walked)`,
      runVerifier(argv, dir),
      dir,
      [
        ["loop-a.json", SYMLINK_LOOP],
        ["loop-b.json", SYMLINK_LOOP],
      ],
      "summary: 1 pass, 2 fail (3 fixtures)",
    );
  }
});

// The walk does not follow a symlink to a directory, so both verifiers list the
// same fixtures: verify.mjs followed one, listing the fixtures under it a second
// time and once more per level through a link to a parent directory. A symlink
// to a file is a fixture, and a directory named on the command line is walked
// when it is a symlink.
test("a symlink to a directory is not followed during the walk by either verifier", { skip: process.platform === "win32" }, (t) => {
  const { dir } = scratchFixtureDir(t);
  mkdirSync(join(dir, "real"));
  writeFileSync(join(dir, "real", "a.json"), readFileSync(join(dir, "valid.json")));
  symlinkSync("real", join(dir, "alias"));
  symlinkSync(".", join(dir, "parent"));
  // A fixture name does not make a symlink to a directory a fixture.
  symlinkSync("real", join(dir, "directory.json"));
  symlinkSync(join("real", "a.json"), join(dir, "file.json"));
  const passed = (result) =>
    result.stdout.split("\n").filter((line) => line.startsWith("PASS  ")).map((line) => line.slice(6)).sort();
  for (const [name, argv] of Object.entries(VERIFIERS)) {
    const walked = runVerifier(argv, dir);
    assert.equal(walked.status, 0, `${name}: ${walked.stdout}${walked.stderr}`);
    assert.deepEqual(passed(walked), ["file.json", join("real", "a.json"), "valid.json"].map((path) => join(dir, path)), name);
    assert.deepEqual(walked.stdout.split("\n").slice(-2), ["summary: 3 pass, 0 fail (3 fixtures)", ""], name);
    const named = runVerifier(argv, join(dir, "alias"));
    assert.equal(named.status, 0, `${name}: ${named.stdout}${named.stderr}`);
    assert.deepEqual(passed(named), [join(dir, "alias", "a.json")], name);
    assert.deepEqual(named.stdout.split("\n").slice(-2), ["summary: 1 pass, 0 fail (1 fixtures)", ""], name);
  }
});

// A symlink to a directory is the only `*.json` entry the walk passes over. An
// entry that is neither a regular file nor a directory (here a Unix socket and
// a FIFO) is listed and reported as ERROR without being read, in both
// verifiers: verify.py passed over it and exited 0, and verify.mjs read it, so
// a FIFO held the run until a writer opened it. The socket is bound by a
// relative name from inside the directory, because a socket address holds
// about 100 bytes. The timeout ends a run that waits on the FIFO.
test("a socket or a FIFO named *.json met during the walk is reported as ERROR by both verifiers", { skip: process.platform === "win32" }, (t) => {
  const { dir } = scratchFixtureDir(t);
  const bound = spawnSync(
    VERIFIERS.python[0],
    ["-c", "import socket; socket.socket(socket.AF_UNIX).bind('socket.json')"],
    { cwd: dir, encoding: "utf8" },
  );
  assert.equal(bound.status, 0, bound.stderr);
  const made = spawnSync("mkfifo", [join(dir, "fifo.json")], { encoding: "utf8" });
  assert.equal(made.status, 0, made.stderr);
  for (const [name, argv] of Object.entries(VERIFIERS)) {
    assertErrorEntries(
      name,
      runVerifier(argv, dir, { timeout: 60_000 }),
      dir,
      [
        ["socket.json", /^ {6}not a regular file: /],
        ["fifo.json", /^ {6}not a regular file: /],
      ],
      "summary: 1 pass, 2 fail (3 fixtures)",
    );
  }
});

// A directory that can be listed but not searched names its entries and does
// not give their status, so neither verifier can tell a directory of fixtures
// from a file among them. Each entry is reported as ERROR under its own path:
// both verifiers passed over the subdirectory and exited 0.
test(
  "the entries of a directory that can be listed but not searched are reported as ERROR by both verifiers",
  { skip: process.platform === "win32" || process.getuid?.() === 0 },
  (t) => {
    const { dir, lock } = scratchFixtureDir(t);
    mkdirSync(join(dir, "locked", "sub"), { recursive: true });
    writeFileSync(join(dir, "locked", "sub", "a.json"), readFileSync(join(dir, "valid.json")));
    writeFileSync(join(dir, "locked", "b.json"), readFileSync(join(dir, "valid.json")));
    lock(join(dir, "locked"), 0o400);
    const errors = [
      [join("locked", "b.json"), NO_PERMISSION],
      [join("locked", "sub"), NO_PERMISSION],
    ];
    for (const [name, argv] of Object.entries(VERIFIERS)) {
      assertErrorEntries(`${name} (named)`, runVerifier(argv, join(dir, "locked")), dir, errors, "summary: 0 pass, 2 fail (2 fixtures)");
      assertErrorEntries(`${name} (walked)`, runVerifier(argv, dir), dir, errors, "summary: 1 pass, 2 fail (3 fixtures)");
    }
  },
);

test(
  "a directory that cannot be listed is reported as ERROR by both verifiers",
  { skip: process.platform === "win32" || process.getuid?.() === 0 },
  (t) => {
    const { dir, lock } = scratchFixtureDir(t);
    mkdirSync(join(dir, "locked"));
    lock(join(dir, "locked"));
    for (const [name, argv] of Object.entries(VERIFIERS)) {
      assertErrorEntries(
        `${name} (named)`,
        runVerifier(argv, join(dir, "locked")),
        dir,
        [["locked", NO_PERMISSION]],
        "summary: 0 pass, 1 fail (1 fixtures)",
      );
      assertErrorEntries(
        `${name} (walked)`,
        runVerifier(argv, dir),
        dir,
        [["locked", NO_PERMISSION]],
        "summary: 1 pass, 1 fail (2 fixtures)",
      );
    }
  },
);
