# Reference verifiers

Part of [Reference verifiers and suite tooling](../scripts/README.md).

The suite has two reference verifiers: [`verify.mjs`](../scripts/verify.mjs) for Node.js and [`verify.py`](../scripts/verify.py) for Python. They take the same arguments and print the same output. This page gives what they check, the arguments they read and the output contract. An implementation tested with the parity gate prints the same per-fixture blocks ([Testing another implementation](./testing-another-implementation.md)).

`verify.mjs` uses only the Node standard library (`node:crypto`). `verify.py` has one dependency, the [`cryptography`](https://pypi.org/project/cryptography/) package ([Install](./install.md#python)).

## What they check

Each fixture is first checked against the JSON Schema of its family (see [Stage `schema`](#stage-schema)).

For a composition fixture, a verifier:

1. reconstructs the RFC 9421 signature base;
2. applies the Envoys §4.3 tag rule: the tag `a2a-message`, or no tag, is accepted, and any other tag is rejected as `TAG_MISMATCH`;
3. extracts the public key by A2A-IDF §6 dual-shape keyid resolution. With `application/did+json`, the key comes from the DID Document: an `Ed25519VerificationKey2020` with `publicKeyMultibase`, or a `JsonWebKey2020` JWK. Otherwise it is a compact-form PEM SPKI key ([Compact-form keys](#compact-form-keys));
4. verifies the Ed25519 signature.

When the request verifies and the fixture wraps it in an envelope, the verifier then checks the envelope:

- For a delegation chain, it checks each link's signature over the RFC 8785 JCS form of the link, the depth, issuer continuity, scope narrowing, expiry non-increase and the last link.
- For a bilateral receipt, it checks the responder's signature and its binding to the request.

The check order and the reject categories are under [`envelope`](../fixtures/composition/SCHEMA.md#envelope-optional). A malformed envelope member fails the fixture at stage `envelope`.

For a level fixture, a verifier evaluates the A2A-IDF §1 identity declaration: its shape, the DNS TXT binding, the registry attestation over the RFC 8785 JCS form, and the validity window.

`verify.py` has the same check order and makes the same accept/reject/category decisions as `verify.mjs` on every fixture. It derives the provider domain of a Level 1 card with its own implementation of the WHATWG URL host rules. What that implementation approximates is listed under [Provider domain](../fixtures/levels/README.md#provider-domain).

### Compact-form keys

Both verifiers read a compact-form `publicKeyPem` by the same rules, and only the key bytes reach the crypto library:

- The first PEM block in the text is the one read. It must be a `PUBLIC KEY` block that ends in its `END PUBLIC KEY` line.
- Text before its BEGIN line and after its END line is not part of the key.
- Between those two lines, empty lines (or lines of spaces) may come before the base64 text, never within or after it.
- The base64 text must be the encoding of a 44-byte Ed25519 SPKI key, character for character.

Any other text fails at stage `public-key-extraction` with `reason: compact-form publicKeyPem is not an Ed25519 SPKI PEM`. So neither verifier reads past a block of another label, takes a private key or asks for a pass phrase.

## Arguments

Both verifiers accept fixture files or directories. A directory is walked recursively for `*.json` files.

- A symlink to a directory met during the walk is not followed, so a fixture is not listed a second time under another name.
- A symlink to a fixture file is read, and a directory named on the command line is walked when it is a symlink.
- A `*.json` entry met during the walk that is neither a regular file nor a directory (a socket, a FIFO, a device) is reported as `ERROR` (`not a regular file`) and not read. So a FIFO cannot hold the run until a writer opens it.

`--help` or `-h` prints the usage and the exit codes on stdout and exits 0 without reading a fixture. Any other argument that starts with `-`, other than `-` alone, is an unknown option. It is reported on stderr with exit code 2 and never read as a path. Every argument after `--` is a path, even one that starts with `-`.

An empty argument is a usage error rather than the current directory. An unset variable gives one, as in `node scripts/verify.mjs "$FIXTURE"`. It is reported on stderr as `an empty argument is not a path` with exit code 2, without reading a fixture.

`verify.py` without the `cryptography` package prints one line on stderr and exits 2: `verify.py needs the cryptography package: python3 -m pip install cryptography (see scripts/README.md#install)`. It reads its arguments first, so `--help` and a usage error do not need the package.

## Output

Each verifier prints one block per fixture:

```
PASS  /abs/path/to/fixture.json
      observed: ACCEPT
```

A negative fixture is a `PASS` when the observed rejection matches the pinned expectation:

```
PASS  /abs/path/to/signature-tampered.json
      observed: REJECT[SIGNATURE_INVALID]
```

### FAIL

On failure, the block line is `FAIL`. It is followed by `stage:` (which validation step failed) and `reason:` (the specific mismatch).

#### Stage `schema`

The first stage is `schema`. Each fixture is checked against its family's JSON Schema in [`schemas/`](../schemas/), selected by the fixture's `$schema` URL. A missing required field fails there, for example with `reason: missing required field expected.signatureBase64`. A value of the wrong type is reported as, for example, `reason: crossSuiteEquivalence is present but is not a JSON object`.

The verifiers implement the keywords those schemas use: `type` (as one type name or a list of them), `const`, `enum`, `required`, `properties`, `allOf`, and `if`/`then`. The schema test fails if a schema adds any other.

### ERROR

When a verifier cannot evaluate a fixture at all, the block line is `ERROR`. It is followed by the error, with no `observed:` line:

```
ERROR /abs/path/to/fixture.json
      value type outside the fixture JCS domain: int
```

`ERROR` means the verifier raised instead of reaching a verdict. Two examples are a fixture that is not JSON text and an attestation value outside the minimal JCS domain (numbers, booleans, null). In both verifiers, a fixture holding `NaN`, `Infinity` or `-Infinity` is not JSON text.

The line under `ERROR` is the error's message:

- For a fixture that is not JSON text, both verifiers print `fixture is not valid JSON: ` followed by the message of their JSON parser. Given the top-level `README.md`, `verify.py` prints `fixture is not valid JSON: Expecting value: line 1 column 1 (char 0)`, and `verify.mjs` on Node 26.12.0 prints `fixture is not valid JSON: Unexpected token '#', "# A2A-IDF "... is not valid JSON`.
- `verify.mjs` prints the message alone for a failed system call, an entry the walk does not read and a fixture that is not JSON text. A failed system call is, for example, opening a fixture path that does not exist, a file without read permission or a symlink loop, or listing a directory without read permission. For any other error, `verify.mjs` prints its stack trace. The trace is one line, with each line feed of the trace written as `\u000a`.
- `verify.py` prints the message of every error.

Some problems with a fixture are not an `ERROR`:

- A fixture missing a required block fails at stage `schema`.
- A malformed level-fixture field resolves to `REJECT[SHAPE_INVALID]`. That includes a lone surrogate in an organization attestation, which cannot enter the JCS form the attestation is signed over.

A permissions problem cannot read as a pass. A directory that cannot be listed is an `ERROR` under its own path. So is each entry of a directory that can be listed but not searched (read permission without execute permission): the status of such an entry cannot be read, and it may be a directory of fixtures.

### Nesting, numbers and lone surrogates

Neither verifier recurses on a fixture's nesting to read it, to check it against its schema, to word a reject reason or to write an attestation's JCS form. So in those steps, nesting depth alone does not make either verifier raise. A schema reason names an array or an object by its JSON type, not by its contents. A reject reason quotes a string and names any other value by its JSON type, as in `unknown identityLevel: a JSON array`.

Nor does the length of an integer make a verifier raise. Both verifiers read an integer beyond the range of a double as an infinite number, which is not a JSON integer. A schema reason writes a number only when it is an integer of at most 2^53 - 1 in magnitude. It names any other number by its JSON type (`a JSON integer`, `a JSON number`), so the two verifiers print the same reason.

UTF-8 cannot encode a lone surrogate. A reason that quotes a string as it is prints a lone surrogate in it as U+FFFD, in both verifiers. A schema reason quotes a string as JSON text and writes a lone surrogate in it as a lowercase `\uXXXX` escape (`"X\ud800"`), in both verifiers.

### Escaped characters

Both verifiers write each C0 or C1 control character (U+0000 to U+001F, U+007F to U+009F) of a printed line as a lowercase `\uXXXX` escape. So a fixture value that a reason quotes cannot break a line of the report or send the terminal a command. For example, a `publicKeyMultibase` of `z` followed by a line feed fails with `reason: invalid base58 character: \u000a`.

In a printed line that is not JSON text, they also write a backslash followed by `u` as `\`, and no other backslash. So a `\u` in such a line always begins an escape the verifier wrote:

- A `publicKeyMultibase` of `x` followed by the six characters `\u001b` fails with `reason: unsupported multibase prefix in x\u001b`.
- One of `x` followed by U+001B fails with `reason: unsupported multibase prefix in x\u001b`.

Some lines quote strings as JSON text, which writes a backslash as `\\` already, and keep their backslashes: a schema reason, and the `reconstructed:` and `expected:` lines that `verify.mjs` prints at stage `signature-base`. For the same two values, a schema reason quotes `"X\\u001b"` and `"X\u001b"`.

### Summary line and exit code

The final line is `summary: N pass, M fail, E error (T fixtures)`. `M` counts the fixtures that missed their pinned outcome (`FAIL`). `E` counts the fixtures the verifier could not evaluate (`ERROR`), so a path typo does not read as a conformance failure.

The exit code is 0 if every fixture met its expected verdict (and reject category, when pinned), else 1. A `FAIL` and an `ERROR` both make it 1. It is 2 for a usage error, and for `verify.py` without the `cryptography` package.

The parity gate reads the `PASS`/`FAIL`/`ERROR` lines and the `observed:` lines, not the summary line, to assert cross-implementation agreement. An `ERROR` in one verifier and a verdict in the other is reported as a divergence.
