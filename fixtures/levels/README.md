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
| [`level-0-agent-id-null.json`](./level-0-agent-id-null.json) | 0 | REJECT[SHAPE_INVALID] | `agentId` is JSON `null`. A member that is present declares an identifier, so `null` is a malformed agentId, not an absent one. |
| [`level-1-domain-verified.json`](./level-1-domain-verified.json) | 1 DOMAIN_VERIFIED | ACCEPT | `_a2a-identity.{domain}` TXT record: `v=a2a1`, agent name from agentId, kid, and `fp` = base64url(sha256(raw public key)) without padding. |
| [`level-1-fingerprint-mismatch.json`](./level-1-fingerprint-mismatch.json) | 1 | REJECT[FINGERPRINT_MISMATCH] | TXT record `fp` is the fingerprint of a different key (RFC 8032 §7.1 Test 2) — the domain never endorsed the presented key. |
| [`level-1-domain-mismatch.json`](./level-1-domain-mismatch.json) | 1 | REJECT[DOMAIN_MISMATCH] | agentId claims `example.org` while provider.url, the domain attestation, and the TXT record are all `example.com`. |
| [`level-1-agent-mismatch.json`](./level-1-agent-mismatch.json) | 1 | REJECT[AGENT_MISMATCH] | TXT record `agent` names a different agent under the same domain. |
| [`level-1-kid-mismatch.json`](./level-1-kid-mismatch.json) | 1 | REJECT[KID_MISMATCH] | TXT record `kid` differs from the declared publicKey.kid; the fingerprint still matches. |
| [`level-1-multi-defect-domain-and-version.json`](./level-1-multi-defect-domain-and-version.json) | 1 | REJECT[DOMAIN_MISMATCH] | Two defects: TXT record name is `_a2a-identity.example.net` and the record version is `v=a2a9`. Pins that the record-name check runs before the record-version check. |
| [`level-1-idn-provider-url.json`](./level-1-idn-provider-url.json) | 1 | ACCEPT | Internationalized provider.url (`https://bücher.example`) with every binding in A-label form (`xn--bcher-kva.example`): the domain is derived as the WHATWG URL parser reports it, in ASCII. |
| [`level-1-attestations-not-array.json`](./level-1-attestations-not-array.json) | 1 | REJECT[SHAPE_INVALID] | `attestations` is the domain attestation object itself, not an array holding it: a value that is not an array carries no attestation. |
| [`level-1-provider-url-not-string.json`](./level-1-provider-url-not-string.json) | 1 | REJECT[SHAPE_INVALID] | provider.url is an array holding the URL string: a value that is not a string is never handed to the URL parser, which would coerce it. |
| [`level-1-provider-url-no-host.json`](./level-1-provider-url-no-host.json) | 1 | REJECT[SHAPE_INVALID] | provider.url is `mailto:ops@example.com`: a URL without a host yields no provider domain. |
| [`level-1-provider-url-space-in-host.json`](./level-1-provider-url-space-in-host.json) | 1 | REJECT[SHAPE_INVALID] | provider.url is `https://exa mple.com`: a space is a forbidden host code point, so the URL does not parse. |
| [`level-1-provider-url-percent-encoded.json`](./level-1-provider-url-percent-encoded.json) | 1 | ACCEPT | provider.url is `https://ex%61mple.com`: the host is percent-decoded, so the provider domain is `example.com`. |
| [`level-1-provider-url-backslash-authority.json`](./level-1-provider-url-backslash-authority.json) | 1 | REJECT[DOMAIN_MISMATCH] | provider.url is `https://evil.example\@example.com` while every binding names `example.com`: a backslash ends the authority of an `https` URL, so the provider domain is `evil.example`. |
| [`level-1-provider-url-ignored-code-point.json`](./level-1-provider-url-ignored-code-point.json) | 1 | ACCEPT | provider.url host is `example.com` with a soft hyphen (U+00AD) inside it. UTS #46 maps that code point to nothing, so the provider domain is `example.com`. |
| [`level-1-provider-url-ipv4-number.json`](./level-1-provider-url-ipv4-number.json) | 1 | REJECT[DOMAIN_MISMATCH] | provider.url is `https://0x7f.0.0.1` and every binding is spelled `0x7f.0.0.1`: a host that ends in a number is an IPv4 address, so the provider domain is `127.0.0.1`, which no binding names. |
| [`level-2-organization-verified.json`](./level-2-organization-verified.json) | 2 ORGANIZATION_VERIFIED | ACCEPT | Registry attestation: Ed25519 over the RFC 8785 JCS form of the attestation minus `signature`; subject binds to agentId + kid; validationTime inside [verifiedAt, expiresAt]. |
| [`level-2-attestation-tampered.json`](./level-2-attestation-tampered.json) | 2 | REJECT[SIGNATURE_INVALID] | subject.organization altered after signing. |
| [`level-2-attestation-expired.json`](./level-2-attestation-expired.json) | 2 | REJECT[EXPIRED] | Valid signature, but expiresAt precedes the pinned validationTime. |
| [`level-2-attestation-non-bmp-keys.json`](./level-2-attestation-non-bmp-keys.json) | 2 ORGANIZATION_VERIFIED | ACCEPT | The attestation carries an extra member whose property names are the RFC 8785 §3.2.3 sorting example (U+1F600 and U+FB33 among them). The signing input orders them by UTF-16 code units. A verifier that sorts by code point rejects it with SIGNATURE_INVALID. |
| [`level-2-attestation-not-yet-valid.json`](./level-2-attestation-not-yet-valid.json) | 2 | REJECT[NOT_YET_VALID] | Valid signature, but verifiedAt follows the pinned validationTime. |
| [`level-2-subject-mismatch.json`](./level-2-subject-mismatch.json) | 2 | REJECT[SUBJECT_MISMATCH] | Validly signed attestation issued to a different agentId of the same organization. |
| [`level-2-multi-defect-subject-and-evidence.json`](./level-2-multi-defect-subject-and-evidence.json) | 2 | REJECT[SUBJECT_MISMATCH] | Two defects: attestation subject.kid differs from the declared kid and `evidence.validationTime` is missing. Pins that the subject binding check runs before the evidence shape check. |
| [`level-2-issuer-not-object.json`](./level-2-issuer-not-object.json) | 2 | REJECT[SHAPE_INVALID] | Attestation `issuer` is a string, not the `{name, kid, url}` object: a malformed field is a shape reject, never a verifier exception. |
| [`level-2-verified-at-not-string.json`](./level-2-verified-at-not-string.json) | 2 | REJECT[SHAPE_INVALID] | Attestation `verifiedAt` is an array holding the timestamp, not a string: the timestamp check looks at the type before the format. |
| [`level-2-jcs-utf16-key-order.json`](./level-2-jcs-utf16-key-order.json) | 2 | ACCEPT | Signed attestation carries ASCII property names (`10`, `9`, `B`, `Z`, `_`, `a`, `aa`) whose UTF-16 code-unit order differs from numeric order and from case-insensitive order. A verifier that sorts either of those ways rejects it with SIGNATURE_INVALID. |

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
8. `provider.url` is a string that parses to a URL with a host (the
   [provider domain](#provider-domain)) → `SHAPE_INVALID`
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
   `subject.{organization,agentId,kid}` and `signature`, `verifiedAt` and
   `expiresAt` are strings in `YYYY-MM-DDTHH:MM:SSZ` form, and no string or
   property name in it holds a lone surrogate → `SHAPE_INVALID`
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

## Provider domain

The provider domain of Level 1 step 8 is the host of `provider.url` as the
[WHATWG URL parser](https://url.spec.whatwg.org/) reports it (in JavaScript,
`new URL(url).hostname`). A value that is not a string, a URL that parser
refuses and a URL without a host all fail step 8. The bindings of steps 9, 11
and 13 are compared with that host as plain strings, so they must spell it
the way the parser reports it:

| Rule | Example | Provider domain | Fixture |
|---|---|---|---|
| A domain is lowercased, and an internationalized domain is its A-label | `https://bücher.example` | `xn--bcher-kva.example` | `level-1-idn-provider-url.json` |
| Percent-encoded bytes in a host are decoded | `https://ex%61mple.com` | `example.com` | `level-1-provider-url-percent-encoded.json` |
| Code points UTS #46 maps to nothing are dropped | `example.com` with a soft hyphen (U+00AD) inside | `example.com` | `level-1-provider-url-ignored-code-point.json` |
| In a special scheme (`http`, `https`, `ws`, `wss`, `ftp`, `file`) a backslash ends the authority, as a slash does | `https://evil.example\@example.com` | `evil.example` | `level-1-provider-url-backslash-authority.json` |
| A host that ends in a number is an IPv4 address, in dotted-decimal form | `https://0x7f.0.0.1` | `127.0.0.1` | `level-1-provider-url-ipv4-number.json` |
| A forbidden host code point fails the URL | `https://exa mple.com` | none | `level-1-provider-url-space-in-host.json` |
| A URL without a host has no provider domain | `mailto:ops@example.com` | none | `level-1-provider-url-no-host.json` |
| A value that is not a string has no provider domain | `["https://example.com"]` | none | `level-1-provider-url-not-string.json` |

`scripts/verify.py` follows the URL Standard for all of the above without a
URL-parsing dependency. Its conversion of a non-ASCII host to an A-label is an
approximation: it does not make the UTS #46 validity checks, so for a host
those checks refuse (a disallowed code point, a joiner out of context, a Bidi
rule violation) it reports a Punycode form where `scripts/verify.mjs` reports
no host. No fixture depends on that difference.

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

Code-unit order also differs from two orders a sort routine may offer for
ASCII names: numeric order (`10` sorts before `9`) and case-insensitive order
(`B` and `Z` sort before `_` and `a`).
[`level-2-jcs-utf16-key-order.json`](./level-2-jcs-utf16-key-order.json)
pins that case, so the two fixtures fail for different defects.

A lone surrogate (an unpaired `\uD800`-`\uDFFF` escape) has no UTF-8
encoding, and RFC 8785 §3.2.2.2 requires a JCS implementation to stop on one.
Both reference verifiers reject an organization attestation that holds one, in
a string or in a property name, with `SHAPE_INVALID` (Level 2 step 7). No
fixture pins this: JSON parsers differ on whether they load such a string at
all (RFC 8259 §8.2), so a fixture would fail some implementations before
their verifier ran. `scripts/parity/test_verifier_agreement.py` covers it for
the two reference verifiers.
