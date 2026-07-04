# Verification-level fixtures

Fixtures for A2A-IDF §1 identity verification levels: what a conforming verifier
must ACCEPT or REJECT when evaluating an AgentCard's agent-identity extension.

Every fixture is fully offline-verifiable: DNS answers and validation times are
pinned inside the fixture, so the expected verdict never depends on the network
or the wall clock. Live DNS resolution (and DNSSEC preference) is deployment
behavior outside the suite's scope — the fixtures pin what the record must
*contain*, not how it is fetched.

## Fixtures

| Fixture | Level | Expected | Pins |
|---|---|---|---|
| [`level-0-self-asserted.json`](./level-0-self-asserted.json) | 0 SELF_ASSERTED | ACCEPT | Declaration shape: extension URI, identityLevel, URN agentId, Ed25519 OKP JWK. No attestations required — and no verified-identity claim made. |
| [`level-0-agent-id-malformed.json`](./level-0-agent-id-malformed.json) | 0 | REJECT[SHAPE_INVALID] | agentId not in `urn:a2a:agent:{domain}:{agent-name}:{version}` format. |
| [`level-1-domain-verified.json`](./level-1-domain-verified.json) | 1 DOMAIN_VERIFIED | ACCEPT | `_a2a-identity.{domain}` TXT record: `v=a2a1`, agent name from agentId, kid, and `fp` = base64url(sha256(raw public key)) without padding. |
| [`level-1-fingerprint-mismatch.json`](./level-1-fingerprint-mismatch.json) | 1 | REJECT[FINGERPRINT_MISMATCH] | TXT record `fp` is the fingerprint of a different key (RFC 8032 §7.1 Test 2) — the domain never endorsed the presented key. |
| [`level-2-organization-verified.json`](./level-2-organization-verified.json) | 2 ORGANIZATION_VERIFIED | ACCEPT | Registry attestation: Ed25519 over the RFC 8785 JCS form of the attestation minus `signature`; subject binds to agentId + kid; validationTime inside [verifiedAt, expiresAt]. |
| [`level-2-attestation-tampered.json`](./level-2-attestation-tampered.json) | 2 | REJECT[SIGNATURE_INVALID] | subject.organization altered after signing. |
| [`level-2-attestation-expired.json`](./level-2-attestation-expired.json) | 2 | REJECT[EXPIRED] | Valid signature, but expiresAt precedes the pinned validationTime. |

Keys: the agent key is RFC 8032 §7.1 Test 1 ([`../../vectors/rfc8032-7-1.json`](../../vectors/rfc8032-7-1.json));
the trust-registry issuer key is Test 2 ([`../../vectors/rfc8032-7-1-test2.json`](../../vectors/rfc8032-7-1-test2.json)).

## Fixture shape

```jsonc
{
  "$schema": "https://a2a-idf.opena2a.org/schemas/fixture-level-v1.json",
  "name": "levels/<filename-without-extension>",
  "description": "...",
  "spec": [ /* spec citations */ ],
  "level": 0,                       // 0 | 1 | 2

  "agentCard": {                    // the AgentCard under evaluation
    "name": "...",
    "provider": { "organization": "...", "url": "https://example.com" },
    "capabilities": {
      "extensions": [{
        "uri": "https://a2a-protocol.org/extensions/agent-identity",
        "params": {
          "identityLevel": "SELF_ASSERTED | DOMAIN_VERIFIED | ORGANIZATION_VERIFIED",
          "agentId": "urn:a2a:agent:example.com:financial-advisor:v2",
          "publicKey": { "kty": "OKP", "crv": "Ed25519", "x": "...", "kid": "..." },
          "attestations": [ /* per-level attestation entries */ ]
        }
      }]
    }
  },

  "evidence": {                     // pinned out-of-band material, per level
    "dnsTxt": { "recordName": "_a2a-identity.example.com", "recordValue": "v=a2a1; agent=...; kid=...; fp=..." },
    "issuerPublicKey": { "kty": "OKP", "crv": "Ed25519", "x": "...", "kid": "..." },
    "validationTime": "2026-07-03T00:00:00Z"
  },

  "expected": {
    "verifyResult": "ACCEPT | REJECT",
    "rejectCategory": "SHAPE_INVALID | DOMAIN_MISMATCH | AGENT_MISMATCH | KID_MISMATCH | FINGERPRINT_MISMATCH | SUBJECT_MISMATCH | SIGNATURE_INVALID | NOT_YET_VALID | EXPIRED"
  }
}
```

`evidence` carries only what exists outside the AgentCard: the pinned DNS answer
(Level 1) or the issuer public key and evaluation time (Level 2). The attestation
itself travels inside the AgentCard's `params.attestations`, as in production.

## Check order (cross-implementation contract)

Both reference verifiers apply checks in the same order, so a fixture with
multiple defects always resolves to the same category:

1. **Shape** — extension present, known identityLevel, URN agentId (when
   declared), Ed25519 OKP JWK with kid → `SHAPE_INVALID`
2. **Binding** — domain/agent/kid fields (Level 1) or attestation subject
   (Level 2) match the declaration → `*_MISMATCH`
3. **Cryptography** — fingerprint (Level 1) or registry signature over the JCS
   form (Level 2) → `FINGERPRINT_MISMATCH` / `SIGNATURE_INVALID`
4. **Validity window** — pinned validationTime against [verifiedAt, expiresAt]
   → `NOT_YET_VALID` / `EXPIRED`

Committed fixtures pin exactly one defect each, so category assignment never
depends on tie-breaking; the shared order keeps future multi-defect fixtures
unambiguous.

## JCS note

Attestation values are restricted to JSON objects, arrays, and strings (no
numbers, booleans, or null). Within that domain, sorted-key compact JSON is
exactly the RFC 8785 canonical form, which keeps the reference verifiers'
minimal JCS implementations exact. Keep new fixtures inside that domain.
