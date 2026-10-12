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
| [`level-1-domain-mismatch.json`](./level-1-domain-mismatch.json) | 1 | REJECT[DOMAIN_MISMATCH] | agentId claims `example.org` while provider.url, the domain attestation, and the TXT record are all `example.com`. |
| [`level-1-agent-mismatch.json`](./level-1-agent-mismatch.json) | 1 | REJECT[AGENT_MISMATCH] | TXT record `agent` names a different agent under the same domain. |
| [`level-1-kid-mismatch.json`](./level-1-kid-mismatch.json) | 1 | REJECT[KID_MISMATCH] | TXT record `kid` differs from the declared publicKey.kid; the fingerprint still matches. |
| [`level-1-multi-defect-domain-and-version.json`](./level-1-multi-defect-domain-and-version.json) | 1 | REJECT[DOMAIN_MISMATCH] | Two defects: TXT record name is `_a2a-identity.example.net` and the record version is `v=a2a9`. Pins that the record-name check runs before the record-version check. |
| [`level-2-organization-verified.json`](./level-2-organization-verified.json) | 2 ORGANIZATION_VERIFIED | ACCEPT | Registry attestation: Ed25519 over the RFC 8785 JCS form of the attestation minus `signature`; subject binds to agentId + kid; validationTime inside [verifiedAt, expiresAt]. |
| [`level-2-attestation-tampered.json`](./level-2-attestation-tampered.json) | 2 | REJECT[SIGNATURE_INVALID] | subject.organization altered after signing. |
| [`level-2-attestation-expired.json`](./level-2-attestation-expired.json) | 2 | REJECT[EXPIRED] | Valid signature, but expiresAt precedes the pinned validationTime. |
| [`level-2-attestation-non-bmp-keys.json`](./level-2-attestation-non-bmp-keys.json) | 2 ORGANIZATION_VERIFIED | ACCEPT | The attestation carries an extra member whose property names are the RFC 8785 §3.2.3 sorting example (U+1F600 and U+FB33 among them). The signing input orders them by UTF-16 code units. A verifier that sorts by code point rejects it with SIGNATURE_INVALID. |
| [`level-2-attestation-not-yet-valid.json`](./level-2-attestation-not-yet-valid.json) | 2 | REJECT[NOT_YET_VALID] | Valid signature, but verifiedAt follows the pinned validationTime. |
| [`level-2-subject-mismatch.json`](./level-2-subject-mismatch.json) | 2 | REJECT[SUBJECT_MISMATCH] | Validly signed attestation issued to a different agentId of the same organization. |
| [`level-2-multi-defect-subject-and-evidence.json`](./level-2-multi-defect-subject-and-evidence.json) | 2 | REJECT[SUBJECT_MISMATCH] | Two defects: attestation subject.kid differs from the declared kid and `evidence.validationTime` is missing. Pins that the subject binding check runs before the evidence shape check. |

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

Both reference verifiers apply the checks below in exactly this order and stop
at the first one that fails; its category is the reject category. A fixture
with multiple defects therefore always resolves to the same category.

The order is not "every shape check, then every binding check". Some shape
checks inspect material that is only read after an earlier binding check
(the DNS record value, the issuer evidence), so they sit between binding
checks. Follow the numbered list, not the phase names.

**Declaration (every level)**

1. `agentCard.capabilities.extensions` is an array → `SHAPE_INVALID`
2. The agent-identity extension is present and its `params` is an object
   → `SHAPE_INVALID`
3. `identityLevel` is `SELF_ASSERTED`, `DOMAIN_VERIFIED` or
   `ORGANIZATION_VERIFIED` → `SHAPE_INVALID`
4. `agentId`, when declared, is a `urn:a2a:agent:{domain}:{agent-name}:{version}`
   URN → `SHAPE_INVALID`
5. `publicKey` is an Ed25519 OKP JWK (32-byte `x`) with a non-empty `kid`
   → `SHAPE_INVALID`

Level 0 ACCEPTs here.

**Level 1 (DOMAIN_VERIFIED)**, continuing from step 5:

6. A `type: "domain"` attestation is present → `SHAPE_INVALID`
7. `agentId` is declared → `SHAPE_INVALID`
8. `provider.url` parses to a hostname (the provider domain) → `SHAPE_INVALID`
9. The attestation `domain` equals the provider domain → `DOMAIN_MISMATCH`
10. `evidence.dnsTxt.recordName` and `recordValue` are non-empty strings
    → `SHAPE_INVALID`
11. `recordName` equals `_a2a-identity.{provider domain}` → `DOMAIN_MISMATCH`
12. The record's `v` field is `a2a1` → `SHAPE_INVALID`
13. The agentId domain equals the provider domain → `DOMAIN_MISMATCH`
14. The record's `agent` field equals the agentId agent name → `AGENT_MISMATCH`
15. The record's `kid` field equals `publicKey.kid` → `KID_MISMATCH`
16. The record's `fp` field equals base64url(sha256(raw public key)) without
    padding → `FINGERPRINT_MISMATCH`

**Level 2 (ORGANIZATION_VERIFIED)**, continuing from step 5:

6. A `type: "organization"` attestation is present → `SHAPE_INVALID`
7. The attestation has non-empty `issuer.{name,kid,url}`,
   `subject.{organization,agentId,kid}` and `signature`, and `verifiedAt` and
   `expiresAt` in `YYYY-MM-DDTHH:MM:SSZ` form → `SHAPE_INVALID`
8. `subject.agentId` equals `agentId` and `subject.kid` equals `publicKey.kid`
   → `SUBJECT_MISMATCH`
9. `evidence.issuerPublicKey` is an Ed25519 OKP JWK and
   `evidence.validationTime` is in `YYYY-MM-DDTHH:MM:SSZ` form
   → `SHAPE_INVALID`
10. `signature` is 64 bytes and verifies under the issuer key over the RFC 8785
    JCS form of the attestation minus `signature` → `SIGNATURE_INVALID`
11. `validationTime` is not before `verifiedAt` → `NOT_YET_VALID`
12. `validationTime` is not after `expiresAt` → `EXPIRED`

Every reject category has a single-defect fixture above. Two fixtures carry two
defects each, chosen where the order is easiest to get wrong: a binding check
that runs before a later shape check (Level 1 steps 11 and 12, Level 2 steps 8
and 9). A verifier that runs every shape check first reports `SHAPE_INVALID`
on both and fails them.

## JCS note

Attestation values are restricted to JSON objects, arrays, and strings (no
numbers, booleans, or null). Within that domain, sorted-key compact JSON is
exactly the RFC 8785 canonical form, which keeps the reference verifiers'
minimal JCS implementations exact. Keep new fixtures inside that domain.

"Sorted" means RFC 8785 §3.2.3 order: property names compared as arrays of
UTF-16 code units, not as Unicode code points. The two orders differ when one
key holds a character above U+FFFF (encoded as a surrogate pair, D800-DFFF)
and another holds a character in U+E000-U+FFFF. JavaScript's default
`Array.prototype.sort()` already compares code units. Python's `sorted()`
compares code points, so `verify.py` sorts on the key's UTF-16BE encoding.
Property names are not restricted to ASCII.
[`level-2-attestation-non-bmp-keys.json`](./level-2-attestation-non-bmp-keys.json)
pins this case.
