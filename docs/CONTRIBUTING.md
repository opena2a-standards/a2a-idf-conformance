# Contributing

Pull requests welcome.

## Two kinds of fixtures, two homes

| Fixture kind | Example | Lives in |
|---|---|---|
| **Implementation-only.** A wire-format implementation's own conformance vectors. | Envoys §14 Vectors 1-3 in `envoys-rfc9421/`; APS continuity vectors; CTEF envelope vectors. | The implementation's home repository. |
| **Cross-layer composition.** An implementation's wire signature combined with A2A-IDF §6 identity-framework resolution (compact-form or DID Document), proving the signature bytes are unchanged across resolution shapes. | `aim-did-rfc9421/signature-alone.json` (Envoys §14 Vector 1 wrapped with a W3C DID Document). | **This repo**, under `fixtures/composition/<impl>-<wire-spec>/`. |

If your PR wraps an existing wire-signature implementation in A2A-IDF §6 resolution to demonstrate dual-shape interoperability, it belongs here. If your PR pins your implementation's own primary vectors, those belong in your home repository and can be referenced from a composition fixture here.

## Requirements

1. **Generated, not hand-edited.** Fixtures are owned by [`scripts/generate-fixtures.mjs`](../scripts/generate-fixtures.mjs): add your fixture's generation code there and run it to emit the fixture and refresh `MANIFEST.sha256`. CI reruns the generator and fails when a fixture it writes differs from the committed file, so a pull request that edits a generated fixture by hand fails CI and is not merged. Snapshot-only fixtures (signatures committed without enough information to regenerate them) are not accepted.
2. **Passes both reference verifiers and the parity gate.** `node scripts/verify.mjs fixtures` and `python3 scripts/verify.py fixtures` must both report `0 fail`, and `python3 scripts/parity/parity.py` must report PARITY: PASS. When the gate's output changes, refresh the [captured run](./captures/parity.txt) with `python3 scripts/parity/parity.py --json docs/captures/parity.json > docs/captures/parity.txt`.
3. **Matches the schema** for its family: [`schemas/fixture-composition-v1.json`](../schemas/fixture-composition-v1.json) (prose: [`fixtures/composition/SCHEMA.md`](../fixtures/composition/SCHEMA.md)) for composition fixtures, [`schemas/fixture-level-v1.json`](../schemas/fixture-level-v1.json) (prose: [`fixtures/levels/README.md`](../fixtures/levels/README.md)) for verification-level fixtures. Both verifiers enforce it: a fixture that does not match fails at stage `schema`.

Coordination thread: [a2aproject/A2A#1496](https://github.com/a2aproject/A2A/pull/1496).
