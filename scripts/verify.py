#!/usr/bin/env python3
"""
Reference Python verifier for A2A-IDF conformance fixtures.

Depends only on the `cryptography` package (the de-facto standard Python
crypto library; ships with most distros and is a single `pip install`
elsewhere). No third-party JSON or HTTP libraries; uses Python stdlib for
everything else.

Usage:  python3 verify.py <fixture.json> [<fixture.json> ...]
Exit code: 0 if every fixture's verifyResult expectation is met, else 1.
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any

# Content-Digest algorithms supported by this verifier (RFC 9530).
# Fixtures may declare the expected digest with any of these prefixes;
# the verifier picks the algorithm from the fixture's expected.contentDigest.
CONTENT_DIGEST_ALGORITHMS = {
    "sha-256": hashlib.sha256,
    "sha-512": hashlib.sha512,
}

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


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


# --- per-fixture verifier -----------------------------------------------------


def verify_fixture(path: Path) -> tuple[bool, list[str]]:
    fixture = json.loads(path.read_text(encoding="utf-8"))
    expected = fixture.get("expected", {})
    expected_result = (expected.get("verifyResult") or "ACCEPT").upper()

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
        return False, [
            "stage:  content-digest",
            f"reason: unsupported content-digest algorithm: {alg_label}",
        ]
    digest = base64.b64encode(hash_fn(body_bytes).digest()).decode("ascii")
    recomputed = f"{alg_label}=:{digest}:"
    if recomputed != expected.get("contentDigest"):
        return False, [
            "stage:  content-digest",
            f"reason: recomputed {recomputed} != expected {expected.get('contentDigest')}",
        ]

    # Reconstruct the signature base.
    base = build_signature_base(
        {**input_obj, "contentDigest": recomputed},
        fixture["signatureParams"],
    )
    if base != expected.get("signatureBase"):
        return False, [
            "stage:  signature-base",
            "reason: reconstructed base does not match fixture.expected.signatureBase",
        ]

    sig_input = build_signature_input(fixture["signatureParams"])
    if sig_input != expected.get("signatureInput"):
        return False, [
            "stage:  signature-input",
            f"reason: reconstructed {sig_input} != expected {expected.get('signatureInput')}",
        ]

    # Extract public key per A2A-IDF §6 dual-shape resolution.
    try:
        pubkey = extract_public_key(fixture["keyidResolution"])
    except ValueError as exc:
        return False, ["stage:  public-key-extraction", f"reason: {exc}"]

    # Verify Ed25519.
    sig = parse_signature_header(expected["signature"])
    if sig is None:
        return False, ["stage:  signature-parse", "reason: malformed Signature header"]
    base_bytes = base.encode("utf-8")
    try:
        pubkey.verify(sig, base_bytes)
        actual = "ACCEPT"
    except InvalidSignature:
        actual = "REJECT"

    if actual != expected_result:
        return False, [
            "stage:  ed25519-verify",
            f"reason: verify result {actual} != expected {expected_result}",
        ]

    # Cross-suite byte-match check, if declared.
    cse = (fixture.get("crossSuiteEquivalence") or {}).get("envoys") or {}
    if cse.get("byteIdentical") is True and cse.get("expectedSignatureBase64"):
        if expected.get("signatureBase64") != cse["expectedSignatureBase64"]:
            return False, [
                "stage:  cross-suite-equivalence",
                f"reason: fixture signature does not byte-match Envoys {cse.get('vector')}",
            ]

    return True, []


def main() -> int:
    args = sys.argv[1:]
    if not args:
        print("usage: python3 verify.py <fixture.json> [<fixture.json> ...]", file=sys.stderr)
        return 2

    all_ok = True
    for arg in args:
        path = Path(arg).resolve()
        try:
            ok, lines = verify_fixture(path)
            if ok:
                print(f"PASS  {path}")
            else:
                all_ok = False
                print(f"FAIL  {path}")
                for line in lines:
                    print(f"      {line}")
        except Exception as exc:
            all_ok = False
            print(f"ERROR {path}")
            print(f"      {exc}")
    return 0 if all_ok else 1


if __name__ == "__main__":
    sys.exit(main())
