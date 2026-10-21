# Composition fixtures

Multi-layer fixtures that exercise A2A-IDF in combination with adjacent layers: the wire signature layer in every fixture, and a delegation/continuity envelope (a delegation chain or a bilateral receipt, which both reference verifiers check) in fourteen. The identity-claim layer ([#1786](https://github.com/a2aproject/A2A/issues/1786)) is not composed yet; see [Planned fixtures](#planned-fixtures).

## Shipped fixtures

### `aim-did-rfc9421/`

A2A-IDF identity-framework wrap of an [#1829](https://github.com/a2aproject/A2A/issues/1829) wire signature, with the `keyid` URL resolving to a W3C DID Document (`Ed25519VerificationKey2020` + `publicKeyMultibase`).

Three positive shapes per the [aps-conformance-suite](https://github.com/aeoess/aps-conformance-suite) composition convention:

- `signature-alone.json` — per-message signature, no enclosing envelope
- `bilateral-receipt.json` — signature wrapped in an APS bilateral receipt
- `delegation-chain-3link.json` — signature wrapped in a 3-link APS delegation chain

All three pin to the RFC 8032 §7.1 keypair so verifiers running both suites produce byte-identical results for the signature-alone case.

Plus four negative fixtures a conforming verifier MUST reject: `signature-tampered.json` (signature bytes altered in flight), `key-substituted.json` (DID Document serves a different valid Ed25519 key than the one that signed), `body-tampered.json` (body modified and Content-Digest recomputed, signature not re-produced), and `cross-suite-mismatch.json` (declares byte-identity with Envoys §14 Vector 1, but the signature that verifies was produced by a different key). The Envoys §4.3 tag rule is pinned by a pair that differs only in the tag: `signature-tag-absent.json` (absent tag accepted as `a2a-message`) and `signature-tag-foreign.json` (a correctly signed request tagged for another application, rejected as `TAG_MISMATCH`). Two more fixtures pin the edges of that rule: `signature-tag-null.json` (a `null` tag is an absent tag, accepted as `a2a-message`) and `signature-tag-foreign-tampered.json` (a foreign tag and an altered signature, rejected as `TAG_MISMATCH` because the tag rule runs before signature verification).

Twelve more negative fixtures pin the envelope checks, each with one defect in the envelope of `delegation-chain-3link.json` or `bilateral-receipt.json`: `delegation-chain-depth-exceeded.json`, `delegation-chain-issuer-not-delegate.json`, `delegation-chain-leaf-not-signer.json`, `delegation-chain-root-tampered.json`, `delegation-chain-link-tampered.json`, `delegation-chain-link-replaced.json`, `delegation-chain-scope-widened.json`, `delegation-chain-expiry-extended.json`, `delegation-chain-request-out-of-scope.json`, `bilateral-receipt-signature-tampered.json`, `bilateral-receipt-other-request.json` and `bilateral-receipt-status-mismatch.json`. The envelope members and the order of the checks are in [`SCHEMA.md`](./SCHEMA.md#envelope-optional). See [`aim-did-rfc9421/README.md`](./aim-did-rfc9421/README.md) for the full table.

## Planned fixtures

### `envoys-rfc9421-cross-validate/` (planned)

Direct cross-validation against [`envoys-rfc9421/`](https://github.com/aeoess/aps-conformance-suite) fixtures. A2A-IDF verifiers MUST produce the same accept/reject decisions on these inputs as the Envoys reference verifier.

### Identity-claim envelope (not yet composed, blocked on upstream)

No fixture in this directory combines a [#1786](https://github.com/a2aproject/A2A/issues/1786) identity-claim envelope with A2A-IDF, and neither reference verifier reads one. The fixture shape depends on the upstream envelope decision, so there is nothing byte-stable to pin yet. Revisit when the envelope is decided.

### `erc-8004-bridge/` (proposed, blocked on upstream)

Cross-layer composition between A2A-IDF (off-chain identity framework) and [ERC-8004](https://eips.ethereum.org/EIPS/eip-8004) (Ethereum on-chain Identity Registry). An Identity Registry entry's token URI resolves to an agent registration file; the proposed fixture set would pin both the on-chain entry hash and an off-chain A2A-IDF DID Document's wire signature.

Not scheduled. ERC-8004 is `status: Draft` on the EIP track (checked 2026-08-19 against [`ethereum/ERCs`](https://github.com/ethereum/ERCs/blob/master/ERCS/erc-8004.md)) and defines no conformance test cases, so there is no upstream shape to conform to yet. A second open question is our own byte-pin gate: CI reruns the deterministic generator and fails when a fixture it writes differs from the committed file, so a bridge fixture would need a pinned chain-state snapshot (fixed block number plus committed response body) rather than a live RPC read at generation time.

Tracked in [#5](https://github.com/opena2a-standards/a2a-idf-conformance/issues/5), which stays open. Revisit when ERC-8004 leaves Draft, or when we decide to pin a specific revision and accept the churn.

## Fixture format

The normative fixture schema — required fields, supported `keyidResolution` shapes, the exact signature-base format, the envelope members and the order of their checks, and the `rejectCategory` values used by negative fixtures — is documented in [`SCHEMA.md`](./SCHEMA.md), and its required fields, types and allowed values are machine-checked by both verifiers against [`../../schemas/fixture-composition-v1.json`](../../schemas/fixture-composition-v1.json). Verifiers in [`../../scripts/`](../../scripts/) consume these fixtures and emit `PASS` / `FAIL` per fixture. The fixtures in [`aim-did-rfc9421/`](./aim-did-rfc9421/) are emitted by the deterministic generator ([`../../scripts/generate-fixtures.mjs`](../../scripts/generate-fixtures.mjs)), the two in [`hippo-rfc9421/`](./hippo-rfc9421/) are contributed snapshots that it does not write, and both sets are byte-pinned in [`../../MANIFEST.sha256`](../../MANIFEST.sha256).
