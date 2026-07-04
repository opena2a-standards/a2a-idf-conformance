#!/usr/bin/env python3
"""
Reference Python verifier for A2A-IDF conformance fixtures.

Depends only on the `cryptography` package (the de-facto standard Python
crypto library; ships with most distros and is a single `pip install`
elsewhere). No third-party JSON or HTTP libraries; uses Python stdlib for
everything else.

Handles both fixture families:
  - composition fixtures (fixtures/composition/**): RFC 9421 wire signature
    + A2A-IDF §6 dual-shape keyid resolution
  - level fixtures (fixtures/levels/**): A2A-IDF §1 verification levels
    (SELF_ASSERTED / DOMAIN_VERIFIED / ORGANIZATION_VERIFIED)

Usage:  python3 verify.py <fixture.json | directory> [...]
Directories are walked recursively for *.json fixtures.
Exit code: 0 if every fixture's expected verdict (and reject category,
when pinned) is met, else 1.
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

# Content-Digest algorithms supported by this verifier (RFC 9530).
# Fixtures may declare the expected digest with any of these prefixes;
# the verifier picks the algorithm from the fixture's expected.contentDigest.
CONTENT_DIGEST_ALGORITHMS = {
    "sha-256": hashlib.sha256,
    "sha-512": hashlib.sha512,
}

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


IDENTITY_EXTENSION_URI = "https://a2a-protocol.org/extensions/agent-identity"
IDENTITY_LEVELS = ("SELF_ASSERTED", "DOMAIN_VERIFIED", "ORGANIZATION_VERIFIED")
AGENT_ID_URN_RE = re.compile(
    r"^urn:a2a:agent:[A-Za-z0-9.-]+:[A-Za-z0-9._~-]+:[A-Za-z0-9._~-]+$"
)
TIMESTAMP_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")


# --- multibase / multicodec ---------------------------------------------------

BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
MULTICODEC_ED25519_PUB = bytes([0xED, 0x01])


def base58btc_decode(s: str) -> bytes:
    if not s:
        return b""
    out = bytearray([0])
    for ch in s:
        value = BASE58_ALPHABET.find(ch)
        if value < 0:
            raise ValueError(f"invalid base58 character: {ch!r}")
        carry = value
        for j in range(len(out)):
            carry += out[j] * 58
            out[j] = carry & 0xFF
            carry >>= 8
        while carry > 0:
            out.append(carry & 0xFF)
            carry >>= 8
    leading_zeros = 0
    for ch in s:
        if ch == "1":
            leading_zeros += 1
        else:
            break
    return bytes([0] * leading_zeros) + bytes(reversed(out))


def multibase_to_raw_ed25519(mb: str) -> bytes:
    if not mb.startswith("z"):
        raise ValueError(f"unsupported multibase prefix in {mb}")
    decoded = base58btc_decode(mb[1:])
    if len(decoded) != 34 or decoded[:2] != MULTICODEC_ED25519_PUB:
        raise ValueError("multibase value is not an Ed25519 multicodec key")
    return decoded[2:]


# --- public-key extraction (A2A-IDF §6 dual-shape) ----------------------------


def extract_public_key(keyid_resolution: dict[str, Any]) -> Ed25519PublicKey:
    shape = keyid_resolution.get("shape")

    if shape == "compact":
        pem = keyid_resolution.get("publicKeyPem")
        if not isinstance(pem, str):
            raise ValueError("compact-form keyidResolution missing publicKeyPem")
        # We only support Ed25519 SPKI PEM at MVP.
        return _pem_spki_to_ed25519(pem)

    if shape != "did-json":
        raise ValueError(f"unsupported keyidResolution shape: {shape}")

    doc = keyid_resolution.get("document") or {}
    methods = doc.get("verificationMethod")
    if not isinstance(methods, list) or not methods:
        raise ValueError("DID Document has no verificationMethod entries")

    preferred_id = _pick_assertion_method_id(doc)
    method = None
    if preferred_id is not None:
        method = next((m for m in methods if m.get("id") == preferred_id), None)
    if method is None:
        method = methods[0]

    mb = method.get("publicKeyMultibase")
    if isinstance(mb, str):
        raw = multibase_to_raw_ed25519(mb)
        return Ed25519PublicKey.from_public_bytes(raw)

    jwk = method.get("publicKeyJwk")
    if (
        isinstance(jwk, dict)
        and jwk.get("kty") == "OKP"
        and jwk.get("crv") == "Ed25519"
        and isinstance(jwk.get("x"), str)
    ):
        raw = _b64url_decode(jwk["x"])
        return Ed25519PublicKey.from_public_bytes(raw)

    raise ValueError("DID verificationMethod has no usable Ed25519 key encoding")


def _pick_assertion_method_id(doc: dict[str, Any]) -> str | None:
    am = doc.get("assertionMethod")
    if not isinstance(am, list):
        return None
    for entry in am:
        if isinstance(entry, str):
            return entry
        if isinstance(entry, dict) and isinstance(entry.get("id"), str):
            return entry["id"]
    return None


def _pem_spki_to_ed25519(pem: str) -> Ed25519PublicKey:
    body = (
        pem.replace("-----BEGIN PUBLIC KEY-----", "")
        .replace("-----END PUBLIC KEY-----", "")
        .replace("\n", "")
        .replace("\r", "")
        .strip()
    )
    der = base64.b64decode(body)
    prefix = bytes.fromhex("302a300506032b6570032100")
    if not der.startswith(prefix) or len(der) != len(prefix) + 32:
        raise ValueError("SPKI is not an Ed25519 public key")
    return Ed25519PublicKey.from_public_bytes(der[len(prefix) :])


def _b64url_decode(s: str) -> bytes:
    pad = "=" * ((4 - len(s) % 4) % 4)
    return base64.urlsafe_b64decode(s + pad)


def _b64url_nopad(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


# --- signature base (RFC 9421 §2.5) -------------------------------------------


def serialize_params(p: dict[str, Any]) -> str:
    parts = [f'keyid="{p["keyid"]}"', f'created={p["created"]}', f'nonce="{p["nonce"]}"']
    if "tag" in p and p["tag"] is not None:
        parts.append(f'tag="{p["tag"]}"')
    return ";".join(parts)


def build_signature_base(input_obj: dict[str, Any], params: dict[str, Any]) -> str:
    components: list[str] = list(params["components"])
    lines: list[str] = []
    for c in components:
        if c == "@method":
            lines.append(f'"@method": {input_obj["method"].upper()}')
        elif c == "@path":
            lines.append(f'"@path": {input_obj["path"]}')
        elif c == "content-digest":
            lines.append(f'"content-digest": {input_obj["contentDigest"]}')
        else:
            raise ValueError(f"unsupported component: {c}")
    list_str = " ".join(f'"{c}"' for c in components)
    lines.append(f'"@signature-params": ({list_str});{serialize_params(params)}')
    return "\n".join(lines)


def build_signature_input(params: dict[str, Any]) -> str:
    list_str = " ".join(f'"{c}"' for c in params["components"])
    return f"sig1=({list_str});{serialize_params(params)}"


def parse_signature_header(header: str) -> bytes | None:
    if not header.startswith("sig1=:") or not header.endswith(":"):
        return None
    return base64.b64decode(header[6:-1])


# --- verdict gate ----------------------------------------------------------------


def gate_verdict(
    expected: dict[str, Any], verdict: str, category: str | None
) -> tuple[bool, str, list[str]]:
    """Gate an observed verdict/category against the fixture's pinned expectation.

    Returns (ok, observed_string, failure_lines)."""
    expected_result = (expected.get("verifyResult") or "ACCEPT").upper()
    expected_category = expected.get("rejectCategory")
    observed = "ACCEPT" if verdict == "ACCEPT" else f"REJECT[{category}]"
    if verdict != expected_result:
        return False, observed, [
            "stage:  verdict",
            f"reason: verify result {observed} != expected {expected_result}",
        ]
    if verdict == "REJECT" and expected_category is not None and category != expected_category:
        return False, observed, [
            "stage:  reject-category",
            f"reason: reject category {category} != expected {expected_category}",
        ]
    return True, observed, []


# --- composition fixtures (RFC 9421 wire layer + §6 keyid resolution) -------------


def verify_composition_fixture(fixture: dict[str, Any]) -> tuple[bool, str | None, list[str]]:
    expected = fixture.get("expected", {})

    # Recompute Content-Digest. Algorithm is taken from the prefix of
    # expected.contentDigest (RFC 9530).
    input_obj = fixture["input"]
    body_text = input_obj.get("body", "")
    body_encoding = input_obj.get("bodyEncoding", "utf-8")
    if body_encoding == "base64":
        body_bytes = base64.b64decode(body_text)
    else:
        body_bytes = body_text.encode(body_encoding)
    expected_digest = expected.get("contentDigest") or ""
    alg_match = re.match(r"^([a-z0-9-]+)=:", expected_digest)
    alg_label = alg_match.group(1) if alg_match else "sha-256"
    hash_fn = CONTENT_DIGEST_ALGORITHMS.get(alg_label)
    if hash_fn is None:
        return False, None, [
            "stage:  content-digest",
            f"reason: unsupported content-digest algorithm: {alg_label}",
        ]
    digest = base64.b64encode(hash_fn(body_bytes).digest()).decode("ascii")
    recomputed = f"{alg_label}=:{digest}:"
    if recomputed != expected.get("contentDigest"):
        return False, None, [
            "stage:  content-digest",
            f"reason: recomputed {recomputed} != expected {expected.get('contentDigest')}",
        ]

    # Reconstruct the signature base.
    base = build_signature_base(
        {**input_obj, "contentDigest": recomputed},
        fixture["signatureParams"],
    )
    if base != expected.get("signatureBase"):
        return False, None, [
            "stage:  signature-base",
            "reason: reconstructed base does not match fixture.expected.signatureBase",
        ]

    sig_input = build_signature_input(fixture["signatureParams"])
    if sig_input != expected.get("signatureInput"):
        return False, None, [
            "stage:  signature-input",
            f"reason: reconstructed {sig_input} != expected {expected.get('signatureInput')}",
        ]

    # Extract public key per A2A-IDF §6 dual-shape resolution.
    try:
        pubkey = extract_public_key(fixture["keyidResolution"])
    except ValueError as exc:
        return False, None, ["stage:  public-key-extraction", f"reason: {exc}"]

    # Verify Ed25519.
    sig = parse_signature_header(expected["signature"])
    if sig is None:
        return False, None, ["stage:  signature-parse", "reason: malformed Signature header"]
    base_bytes = base.encode("utf-8")
    try:
        pubkey.verify(sig, base_bytes)
        verdict = "ACCEPT"
    except InvalidSignature:
        verdict = "REJECT"

    # The only modeled negative outcome at the wire layer is a signature that
    # fails to verify against the resolved key — whether tampered bytes, a
    # substituted key, or a tampered body (content-digest is a signed component).
    ok, observed, lines = gate_verdict(expected, verdict, "SIGNATURE_INVALID")
    if not ok:
        return False, observed, lines

    # Cross-suite byte-match check, if declared.
    cse = (fixture.get("crossSuiteEquivalence") or {}).get("envoys") or {}
    if cse.get("byteIdentical") is True and cse.get("expectedSignatureBase64"):
        if expected.get("signatureBase64") != cse["expectedSignatureBase64"]:
            return False, observed, [
                "stage:  cross-suite-equivalence",
                f"reason: fixture signature does not byte-match Envoys {cse.get('vector')}",
            ]

    return True, observed, []


# --- level fixtures (A2A-IDF §1 verification levels) ------------------------------


def _jcs(value: Any) -> str:
    """Minimal RFC 8785 (JCS) for the restricted value domain used by level
    fixtures: objects, arrays, and strings only (no numbers, booleans, null).
    Within that domain, sorted-key compact JSON is exactly the JCS form."""
    if isinstance(value, list):
        return "[" + ",".join(_jcs(v) for v in value) + "]"
    if isinstance(value, dict):
        return "{" + ",".join(
            f"{json.dumps(k, ensure_ascii=False)}:{_jcs(value[k])}" for k in sorted(value)
        ) + "}"
    if isinstance(value, str):
        return json.dumps(value, ensure_ascii=False)
    raise ValueError(f"value type outside the fixture JCS domain: {type(value).__name__}")


def _is_nonempty_str(v: Any) -> bool:
    return isinstance(v, str) and len(v) > 0


def _ed25519_key_from_jwk(jwk: Any) -> Ed25519PublicKey | None:
    if (
        not isinstance(jwk, dict)
        or jwk.get("kty") != "OKP"
        or jwk.get("crv") != "Ed25519"
        or not _is_nonempty_str(jwk.get("x"))
    ):
        return None
    try:
        raw = _b64url_decode(jwk["x"])
    except Exception:
        return None
    if len(raw) != 32:
        return None
    return Ed25519PublicKey.from_public_bytes(raw)


def _hostname_of(url: Any) -> str | None:
    if not isinstance(url, str):
        return None
    host = urlparse(url).hostname
    return host if host else None


def _reject(category: str, reason: str) -> dict[str, Any]:
    return {"verdict": "REJECT", "category": category, "reason": reason}


def evaluate_identity(fixture: dict[str, Any]) -> dict[str, Any]:
    """Evaluate the identity declaration. Returns {verdict, category?, reason?}.

    The check order is part of the cross-implementation contract: shape first,
    then per-level binding checks, then cryptography, then validity window."""
    card = fixture.get("agentCard") or {}
    extensions = (card.get("capabilities") or {}).get("extensions")
    if not isinstance(extensions, list):
        return _reject("SHAPE_INVALID", "agentCard.capabilities.extensions missing")
    ext = next(
        (e for e in extensions if isinstance(e, dict) and e.get("uri") == IDENTITY_EXTENSION_URI),
        None,
    )
    if ext is None or not isinstance(ext.get("params"), dict):
        return _reject("SHAPE_INVALID", "agent-identity extension (or its params) missing")
    p = ext["params"]
    if p.get("identityLevel") not in IDENTITY_LEVELS:
        return _reject("SHAPE_INVALID", f"unknown identityLevel: {p.get('identityLevel')}")
    agent_id = p.get("agentId")
    if agent_id is not None and not (
        isinstance(agent_id, str) and AGENT_ID_URN_RE.match(agent_id)
    ):
        return _reject(
            "SHAPE_INVALID",
            f"agentId is not a urn:a2a:agent:{{domain}}:{{agent-name}}:{{version}} URN: {agent_id}",
        )
    pk = p.get("publicKey")
    if _ed25519_key_from_jwk(pk) is None or not _is_nonempty_str((pk or {}).get("kid")):
        return _reject("SHAPE_INVALID", "publicKey is not an Ed25519 OKP JWK with a kid")

    level = p["identityLevel"]
    if level == "SELF_ASSERTED":
        # Level 0 makes no verifiable claim beyond well-formedness. A conforming
        # client MUST NOT treat the agent as verified (Security Considerations).
        return {"verdict": "ACCEPT"}
    if level == "DOMAIN_VERIFIED":
        return evaluate_domain_verified(fixture, card, p, pk)
    return evaluate_organization_verified(fixture, p, pk)


def evaluate_domain_verified(
    fixture: dict[str, Any], card: dict[str, Any], p: dict[str, Any], pk: dict[str, Any]
) -> dict[str, Any]:
    att = next(
        (a for a in (p.get("attestations") or []) if isinstance(a, dict) and a.get("type") == "domain"),
        None,
    )
    if att is None:
        return _reject("SHAPE_INVALID", "DOMAIN_VERIFIED requires a domain attestation")
    if not _is_nonempty_str(p.get("agentId")):
        return _reject("SHAPE_INVALID", "DOMAIN_VERIFIED requires an agentId")
    domain = _hostname_of((card.get("provider") or {}).get("url"))
    if domain is None:
        return _reject("SHAPE_INVALID", "provider.url missing or unparseable")
    if att.get("domain") != domain:
        return _reject(
            "DOMAIN_MISMATCH", f"attestation domain {att.get('domain')} != provider domain {domain}"
        )
    dns_txt = (fixture.get("evidence") or {}).get("dnsTxt") or {}
    record_name = dns_txt.get("recordName")
    record_value = dns_txt.get("recordValue")
    if not _is_nonempty_str(record_name) or not _is_nonempty_str(record_value):
        return _reject("SHAPE_INVALID", "evidence.dnsTxt.{recordName,recordValue} missing")
    if record_name != f"_a2a-identity.{domain}":
        return _reject(
            "DOMAIN_MISMATCH", f"record name {record_name} != _a2a-identity.{domain}"
        )
    fields: dict[str, str] = {}
    for part in record_value.split("; "):
        eq = part.find("=")
        if eq > 0:
            fields[part[:eq]] = part[eq + 1 :]
    if fields.get("v") != "a2a1":
        return _reject("SHAPE_INVALID", f"unsupported record version: {fields.get('v')}")
    urn_parts = p["agentId"].split(":")
    if urn_parts[3] != domain:
        return _reject(
            "DOMAIN_MISMATCH", f"agentId domain {urn_parts[3]} != provider domain {domain}"
        )
    if fields.get("agent") != urn_parts[4]:
        return _reject(
            "AGENT_MISMATCH", f"record agent {fields.get('agent')} != agentId name {urn_parts[4]}"
        )
    if fields.get("kid") != pk["kid"]:
        return _reject("KID_MISMATCH", f"record kid {fields.get('kid')} != declared kid {pk['kid']}")
    fp = _b64url_nopad(hashlib.sha256(_b64url_decode(pk["x"])).digest())
    if fields.get("fp") != fp:
        return _reject("FINGERPRINT_MISMATCH", f"record fp {fields.get('fp')} != computed {fp}")
    return {"verdict": "ACCEPT"}


def evaluate_organization_verified(
    fixture: dict[str, Any], p: dict[str, Any], pk: dict[str, Any]
) -> dict[str, Any]:
    att = next(
        (
            a
            for a in (p.get("attestations") or [])
            if isinstance(a, dict) and a.get("type") == "organization"
        ),
        None,
    )
    if att is None:
        return _reject("SHAPE_INVALID", "ORGANIZATION_VERIFIED requires an organization attestation")
    issuer = att.get("issuer") or {}
    subject = att.get("subject") or {}
    shape_ok = (
        _is_nonempty_str(issuer.get("name"))
        and _is_nonempty_str(issuer.get("kid"))
        and _is_nonempty_str(issuer.get("url"))
        and _is_nonempty_str(subject.get("organization"))
        and _is_nonempty_str(subject.get("agentId"))
        and _is_nonempty_str(subject.get("kid"))
        and TIMESTAMP_RE.match(att.get("verifiedAt") or "") is not None
        and TIMESTAMP_RE.match(att.get("expiresAt") or "") is not None
        and _is_nonempty_str(att.get("signature"))
    )
    if not shape_ok:
        return _reject("SHAPE_INVALID", "organization attestation is missing required fields")
    if subject.get("agentId") != p.get("agentId") or subject.get("kid") != pk["kid"]:
        return _reject(
            "SUBJECT_MISMATCH", "attestation subject does not bind to the declared agentId/kid"
        )
    ev = fixture.get("evidence") or {}
    issuer_key = _ed25519_key_from_jwk(ev.get("issuerPublicKey"))
    validation_time = ev.get("validationTime")
    if issuer_key is None or TIMESTAMP_RE.match(validation_time or "") is None:
        return _reject("SHAPE_INVALID", "evidence.{issuerPublicKey,validationTime} missing or malformed")
    unsigned = {k: v for k, v in att.items() if k != "signature"}
    tbs = _jcs(unsigned).encode("utf-8")
    try:
        sig = _b64url_decode(att["signature"])
    except Exception:
        sig = b""
    if len(sig) != 64:
        return _reject("SIGNATURE_INVALID", "signature is not 64 bytes of base64url")
    try:
        issuer_key.verify(sig, tbs)
    except InvalidSignature:
        return _reject(
            "SIGNATURE_INVALID", "registry signature does not verify over the attestation JCS form"
        )
    # Timestamps share the fixed YYYY-MM-DDTHH:MM:SSZ format (enforced above),
    # so lexicographic comparison is chronological comparison.
    if validation_time < att["verifiedAt"]:
        return _reject(
            "NOT_YET_VALID", f"validationTime {validation_time} precedes verifiedAt {att['verifiedAt']}"
        )
    if validation_time > att["expiresAt"]:
        return _reject("EXPIRED", f"validationTime {validation_time} past expiresAt {att['expiresAt']}")
    return {"verdict": "ACCEPT"}


def verify_level_fixture(fixture: dict[str, Any]) -> tuple[bool, str | None, list[str]]:
    observed = evaluate_identity(fixture)
    ok, observed_str, lines = gate_verdict(
        fixture.get("expected") or {}, observed["verdict"], observed.get("category")
    )
    if not ok and observed.get("reason") and lines:
        lines[-1] += f" ({observed['reason']})"
    return ok, observed_str, lines


# --- driver -----------------------------------------------------------------------


def verify_fixture(path: Path) -> tuple[bool, str | None, list[str]]:
    fixture = json.loads(path.read_text(encoding="utf-8"))
    if "agentCard" in fixture:
        return verify_level_fixture(fixture)
    return verify_composition_fixture(fixture)


def collect_fixtures(arg: str) -> list[Path]:
    path = Path(arg).resolve()
    if not path.is_dir():
        return [path]
    return sorted(p for p in path.rglob("*.json") if p.is_file())


def main() -> int:
    args = sys.argv[1:]
    if not args:
        print("usage: python3 verify.py <fixture.json | directory> [...]", file=sys.stderr)
        return 2

    paths = [p for arg in args for p in collect_fixtures(arg)]
    pass_count = 0
    fail_count = 0
    for path in paths:
        try:
            ok, observed, lines = verify_fixture(path)
            if ok:
                pass_count += 1
                print(f"PASS  {path}")
            else:
                fail_count += 1
                print(f"FAIL  {path}")
            if observed is not None:
                print(f"      observed: {observed}")
            for line in lines:
                print(f"      {line}")
        except Exception as exc:
            fail_count += 1
            print(f"ERROR {path}")
            print(f"      {exc}")
    print(f"summary: {pass_count} pass, {fail_count} fail ({len(paths)} fixtures)")
    return 0 if fail_count == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
