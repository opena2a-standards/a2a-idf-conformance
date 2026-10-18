# A2A-IDF Conformance Suite

Canonical conformance suite for the **A2A-IDF** (Agent-to-Agent Identity Framework) specification proposed in [a2aproject/A2A#1496](https://github.com/a2aproject/A2A/pull/1496).

The suite is intentionally narrow: it covers the identity-framework layer (verification levels, attestation array shape, message-signing wire format, delegation chain and bilateral receipt envelope shapes (unverified)) and composes with adjacent conformance suites for the wire signature layer ([#1829](https://github.com/a2aproject/A2A/issues/1829)) and the delegation/continuity layer ([#1575](https://github.com/a2aproject/A2A/issues/1575) APS). The identity-claim envelope layer (CTEF) is not yet composed ([Coverage](./docs/coverage.md#status)).

## Testing an implementation

Run the parity gate with one command. It needs [pipx](https://pipx.pypa.io/) and `node` on the `PATH` ([Node version](./scripts/README.md#install)):

```bash
pipx run --spec git+https://github.com/opena2a-standards/a2a-idf-conformance a2a-idf-conformance
```

pipx fetches the suite from this repository, installs it with `cryptography`, the Python verifier's one dependency, into a virtual environment of its own, and runs the gate from that copy; nothing is cloned or written into the current directory. A later run reuses that environment, so after a fixture lands, `pipx run --no-cache --spec git+https://github.com/opena2a-standards/a2a-idf-conformance a2a-idf-conformance` fetches the suite again. Without `node` on the `PATH`, the gate reports `node verifier could not start` and exits 1.

What `pipx run --spec git+https://github.com/opena2a-standards/a2a-idf-conformance a2a-idf-conformance` prints, trimmed ([full output](./docs/captures/parity.txt)):

```
...
  composition/aim-did-rfc9421/signature-alone.json             node=PASS:ACCEPT  python=PASS:ACCEPT
...
  levels/level-1-domain-mismatch.json                          node=PASS:REJECT[DOMAIN_MISMATCH]  python=PASS:REJECT[DOMAIN_MISMATCH]
...

PARITY: PASS (all implementations agree on gate, verdict, and category, and match the pinned outcomes)
```

The gate runs every fixture through the Node and Python reference verifiers and passes only when both agree with each other and with the outcome pinned in each fixture.

Wrap your implementation in a command that takes a fixtures directory, evaluates every `*.json` fixture under it, and prints the reference verifier output format (`PASS|FAIL|ERROR <path>`, then `observed: ACCEPT` or `observed: REJECT[CATEGORY]`). Then add it to the parity gate:

```bash
pipx run --spec git+https://github.com/opena2a-standards/a2a-idf-conformance a2a-idf-conformance --verifier mylib="node ../mylib/conformance.js"
```

The gate runs it beside both reference verifiers and reports `PARITY: PASS` only when every implementation agrees on every fixture and matches the outcome pinned in the fixture; otherwise it reports `PARITY: FAIL` and exits 1. The full input and output contract is in [`scripts/README.md`](./scripts/README.md#testing-another-implementation).

To change the suite, for example to add a fixture or to run the tooling tests, run the gate from a clone:

```bash
git clone https://github.com/opena2a-standards/a2a-idf-conformance
cd a2a-idf-conformance
python3 -m venv .venv
. .venv/bin/activate
python3 -m pip install cryptography
python3 scripts/parity/parity.py
```

The `venv` line creates a virtual environment in `.venv` and the next line activates it in the current shell, so the `pip` line downloads `cryptography`, the Python verifier's one dependency, and installs it into that environment.

Outside a virtual environment, a Python marked as externally managed (PEP 668), such as Homebrew Python, refuses the `pip` line with `error: externally-managed-environment` ([other install options](./scripts/README.md#install)).

## Layout

```
fixtures/
  levels/          Verification-level fixtures (Level 0 self-asserted, Level 1 domain-verified, Level 2 organization-verified)
  composition/     Multi-layer composition fixtures (A2A-IDF wrap of #1829 wire signatures, with DID Document or compact-form key resolution)
vectors/           Pinned test vectors (Ed25519 keypairs per RFC 8032 §7.1)
schemas/           JSON Schemas for the composition and level fixture families
scripts/           Reference verifiers, parity gate, deterministic fixture generator, profile generator
src/               The `a2a-idf-conformance` console script, which runs the parity gate from an installed copy of the suite
pyproject.toml     Package definition; the wheel carries the fixtures, schemas, vectors, MANIFEST.sha256, both verifiers and the gate
hatch_build.py     Build hook; the package's description is this README with each relative link rewritten to its URL on GitHub
MANIFEST.sha256    SHA-256 byte-pin over every fixture and vector (generator-emitted, CI-verified)
conformance.json   Machine-readable conformance profile (derived from the fixtures, CI-verified)
COSIGNERS.md       Second-party cosignature registry over MANIFEST.sha256
```

## Composition fixtures

The first composition fixture set is `fixtures/composition/aim-did-rfc9421/`, which exercises:

- **L1:** [#1829](https://github.com/a2aproject/A2A/issues/1829) wire signature (Ed25519 over RFC 9421 components `("@method" "@path" "content-digest")` with `created` / `nonce` / `keyid`)
- **L2:** [#1496](https://github.com/a2aproject/A2A/pull/1496) identity-framework layer: A2A-IDF §6 keyid resolution (DID Document), pinned in each fixture's `keyidResolution` member
- **Key resolution:** W3C DID Document with `Ed25519VerificationKey2020` and `publicKeyMultibase`

Three shapes per fixture, pinned to the RFC 8032 §7.1 keypair:

1. Signature alone
2. Signature wrapped in a bilateral receipt envelope
3. Signature wrapped in a 3-link delegation chain

The reference verifiers check the wire signature in all three shapes.

The envelopes are pinned as data only: the chain links and the receipt carry no signatures, and neither verifier reads the `envelope` block, so a chain whose scope widens or whose expiry increases is still accepted. Envelope verification is listed under `notCovered` in [`conformance.json`](./conformance.json).

These shapes parallel the `envoys-rfc9421/` fixtures hosted in `aeoess/aps-conformance-suite` so that any verifier passing both suites can demonstrate cross-implementation byte-match.

## Reference implementation

[**AIM**](https://github.com/opena2a-org) is the canonical reference implementation of A2A-IDF and ships Ed25519 message signing, JCS canonicalization, and W3C DID Document resolution today. AIM does not have a privileged position in the specification: any conforming implementation may serve as the basis for cross-validation.

The test vectors in this suite are not taken from AIM or from any deployment.

The keypairs in [`vectors/`](./vectors/) are the RFC 8032 §7.1 Test 1 and Test 2 seeds, and every generator-owned fixture is derived from those two seeds and the templates in [`scripts/generate-fixtures.mjs`](./scripts/generate-fixtures.mjs). The generator also asserts that the `aim-did-rfc9421/` composition signatures byte-match [Envoys signature/v1 §14 Vectors 1-3](https://envoys.me/specs/signature/v1).

## Documentation

- [Coverage](./docs/coverage.md): what each fixture family pins, the adjacent conformance suites, and where the contributed snapshots come from
- [Reference verifiers and suite tooling](./scripts/README.md): install, the published entry point, output format, and the contract for testing another implementation
- [Verification-level fixtures](./fixtures/levels/README.md): fixture shape, check order and provider domain
- [Composition fixtures](./fixtures/composition/README.md) and the [composition fixture schema](./fixtures/composition/SCHEMA.md)
- [Test vectors](./vectors/README.md): the RFC 8032 keypairs the fixtures use
- [Cosigners](./COSIGNERS.md): second-party cosignature registry over `MANIFEST.sha256`
- [Contributing](./docs/CONTRIBUTING.md): where each kind of fixture lives, and the requirements a new fixture meets

## License

Apache License 2.0. See [LICENSE](./LICENSE).
