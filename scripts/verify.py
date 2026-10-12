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
Every fixture is first checked against its family's schema in ../schemas/;
a fixture missing a required field fails at stage `schema`.

Usage:  python3 verify.py <fixture.json | directory> [...]
Directories are walked recursively for *.json fixtures.
Exit code: 0 if every fixture's expected verdict (and reject category,
when pinned) is met, else 1.
"""

from __future__ import annotations

import base64
import hashlib
import ipaddress
import json
import os
import re
import stat
import sys
import unicodedata
from pathlib import Path
from typing import Any
from urllib.parse import unquote

# Content-Digest algorithms supported by this verifier (RFC 9530).
# Fixtures may declare the expected digest with any of these prefixes;
# the verifier picks the algorithm from the fixture's expected.contentDigest.
CONTENT_DIGEST_ALGORITHMS = {
    "sha-256": hashlib.sha256,
    "sha-512": hashlib.sha512,
}

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

# Envoys signature/v1 §4.3: the RFC 9421 `tag` an A2A message signature carries.
A2A_MESSAGE_TAG = "a2a-message"

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
    # A null tag is treated as an absent tag, as in verify.mjs.
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
    """The fixture has passed the schema stage (verify_fixture), so its required
    blocks are present and the optional crossSuiteEquivalence block and its
    `envoys` member, when present, are JSON objects."""
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

    # Envoys §4.3 tag rule, checked before any cryptography as in verify.mjs:
    # an absent (or null) tag is `a2a-message`, any other tag is rejected.
    tag = fixture["signatureParams"].get("tag")
    if tag is None:
        tag = A2A_MESSAGE_TAG
    if tag != A2A_MESSAGE_TAG:
        ok, observed, lines = gate_verdict(expected, "REJECT", "TAG_MISMATCH")
        if not ok:
            lines[-1] += f' (tag "{tag}" is not "{A2A_MESSAGE_TAG}")'
        return ok, observed, lines

    # Extract public key per A2A-IDF §6 dual-shape resolution.
    try:
        pubkey = extract_public_key(fixture["keyidResolution"])
    except ValueError as exc:
        return False, None, ["stage:  public-key-extraction", f"reason: {exc}"]

    # A byte-identity claim is only checkable against a pinned value, so a claim
    # without one is a malformed fixture, never a skipped comparison.
    cse = fixture.get("crossSuiteEquivalence", {}).get("envoys", {})
    if cse.get("byteIdentical") is True and not _is_nonempty_str(cse.get("expectedSignatureBase64")):
        return False, None, [
            "stage:  cross-suite-equivalence",
            "reason: crossSuiteEquivalence.envoys.byteIdentical is true but "
            "expectedSignatureBase64 is missing, empty or not a string",
        ]

    # Verify Ed25519.
    sig = parse_signature_header(expected["signature"])
    if sig is None:
        return False, None, ["stage:  signature-parse", "reason: malformed Signature header"]
    base_bytes = base.encode("utf-8")
    try:
        pubkey.verify(sig, base_bytes)
        verified = True
    except InvalidSignature:
        verified = False

    # A signature that fails to verify against the resolved key (tampered bytes,
    # a substituted key, or a tampered body, since content-digest is a signed
    # component) is SIGNATURE_INVALID. When the fixture declares an Envoys
    # byte-match, a signature that verifies but is not the pinned vector is
    # CROSS_SUITE_MISMATCH. The comparison uses the bytes just verified, never
    # expected.signatureBase64, which a fixture can set independently of the
    # Signature header.
    verdict, category, reason = "ACCEPT", None, None
    if not verified:
        verdict, category = "REJECT", "SIGNATURE_INVALID"
    elif cse.get("byteIdentical") is True:
        if base64.b64encode(sig).decode("ascii") != cse["expectedSignatureBase64"]:
            verdict, category = "REJECT", "CROSS_SUITE_MISMATCH"
            reason = f"verified signature does not byte-match Envoys {cse.get('vector')}"

    ok, observed, lines = gate_verdict(expected, verdict, category)
    if not ok and reason and lines:
        lines[-1] += f" ({reason})"
    return ok, observed, lines


# --- level fixtures (A2A-IDF §1 verification levels) ------------------------------


def _utf16_sort_key(key: str) -> bytes:
    # Big-endian bytes compare in the same order as 16-bit code units.
    # surrogatepass keeps a lone surrogate sortable, as it is in JavaScript.
    return key.encode("utf-16-be", "surrogatepass")


def _jcs(value: Any) -> str:
    """Minimal RFC 8785 (JCS) for the restricted value domain used by level
    fixtures: objects, arrays, and strings only (no numbers, booleans, null).
    Within that domain, sorted-key compact JSON is exactly the JCS form.

    RFC 8785 §3.2.3 orders property names by UTF-16 code units. Python's
    default str ordering is by code point, which disagrees once a key holds a
    character above U+FFFF (a surrogate pair, D800-DFFF) and another holds one
    in U+E000-U+FFFF, so the sort key is the UTF-16BE encoding.

    The walk keeps its own stack instead of recursing, so a deeply nested
    member reaches a verdict here and in verify.mjs rather than exceeding the
    recursion limit. Each stack entry is (is_text, item): output text, or a
    value still to be written."""
    out: list[str] = []
    todo: list[tuple[bool, Any]] = [(False, value)]
    while todo:
        is_text, item = todo.pop()
        if is_text:
            out.append(item)
        elif isinstance(item, list):
            entries: list[tuple[bool, Any]] = [(True, "[")]
            for i, v in enumerate(item):
                if i:
                    entries.append((True, ","))
                entries.append((False, v))
            entries.append((True, "]"))
            todo.extend(reversed(entries))
        elif isinstance(item, dict):
            entries = [(True, "{")]
            for i, k in enumerate(sorted(item, key=_utf16_sort_key)):
                entries.append((True, ("," if i else "") + json.dumps(k, ensure_ascii=False) + ":"))
                entries.append((False, item[k]))
            entries.append((True, "}"))
            todo.extend(reversed(entries))
        elif isinstance(item, str):
            out.append(json.dumps(item, ensure_ascii=False))
        else:
            raise ValueError(f"value type outside the fixture JCS domain: {type(item).__name__}")
    return "".join(out)


def _is_nonempty_str(v: Any) -> bool:
    return isinstance(v, str) and len(v) > 0


def _is_timestamp(v: Any) -> bool:
    return isinstance(v, str) and TIMESTAMP_RE.match(v) is not None


def _as_dict(v: Any) -> dict[str, Any]:
    """A JSON object as a dict; any other value (string, list, null) as {}.

    Mirrors the Node verifier, where reading a field of a non-object yields
    undefined, so a malformed field resolves to SHAPE_INVALID, not an exception."""
    return v if isinstance(v, dict) else {}


def _as_list(v: Any) -> list[Any]:
    return v if isinstance(v, list) else []


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


# A surrogate code point. json.loads joins a well-formed escape pair such as
# \ud83d\ude00 into one character, so a surrogate left in a str is a lone one.
_SURROGATE = re.compile("[\ud800-\udfff]")


def _has_lone_surrogate(value: Any) -> bool:
    """True when a string or property name anywhere in `value` holds a lone
    surrogate, which has no UTF-8 encoding and which RFC 8785 §3.2.2.2 forbids.
    Iterative for the reason given in _jcs."""
    todo = [value]
    while todo:
        item = todo.pop()
        if isinstance(item, str):
            if _SURROGATE.search(item) is not None:
                return True
        elif isinstance(item, list):
            todo.extend(item)
        elif isinstance(item, dict):
            todo.extend(item.keys())
            todo.extend(item.values())
    return False


# --- provider domain (WHATWG URL host) ---------------------------------------------

# Label separators UTS #46 maps to "." (full stop, ideographic, fullwidth, halfwidth).
_HOST_LABEL_SEPARATORS = re.compile(
    "[.\N{IDEOGRAPHIC FULL STOP}\N{FULLWIDTH FULL STOP}\N{HALFWIDTH IDEOGRAPHIC FULL STOP}]"
)

# Code points UTS #46 maps to nothing ("ignored"): the soft hyphen, zero width
# space, word joiner, variation selectors and other invisible format characters.
# This is the set the WHATWG URL parser of Node 26 removes from a domain; a
# parser built on older UTS #46 data rejects some of the later additions instead
# (Node 22 refuses 24 of them, U+115F and U+3164 among them). Agreement with
# verify.mjs on such a host is stated for Node 26; see fixtures/levels/README.md.
_UTS46_IGNORED = re.compile(
    "[\u00ad\u034f\u115f\u1160\u17b4\u17b5\u180b-\u180f\u200b\u2060-\u2064"
    "\u206a-\u206f\u3164\ufe00-\ufe0f\ufeff\uffa0"
    "\U0001bca0-\U0001bca3\U0001d173-\U0001d17a\U000e0100-\U000e01ef]"
)


def _ascii_host(host: str) -> str | None:
    """A domain in the ASCII form the WHATWG URL parser reports, or None.

    An internationalized domain is reported as its A-label (`bücher.example`
    -> `xn--bcher-kva.example`). Non-ASCII labels are mapped as UTS #46
    non-transitional processing maps them in the common case (ignored code
    points removed, NFKC, lowercase; `ß` is kept), then Punycode-encoded with
    the `xn--` prefix. U+FFFD, which stands for an undecodable byte or a lone
    surrogate, is disallowed."""
    if host.isascii():
        return host.lower()
    mapped = unicodedata.normalize("NFKC", _UTS46_IGNORED.sub("", host)).lower()
    if "�" in mapped:
        return None
    labels = []
    for label in _HOST_LABEL_SEPARATORS.split(mapped):
        if label.isascii():
            labels.append(label)
        else:
            labels.append("xn--" + label.encode("punycode").decode("ascii"))
    return ".".join(labels)


def _ipv4_number(part: str) -> int | None:
    """One part of a WHATWG IPv4 address: decimal, `0x` hexadecimal or `0` octal."""
    if part == "":
        return None
    radix = 10
    if part[:2] in ("0x", "0X"):
        part, radix = part[2:], 16
    elif len(part) > 1 and part.startswith("0"):
        part, radix = part[1:], 8
    if any(ch not in "0123456789abcdef"[:radix] for ch in part.lower()):
        return None
    part = part.lstrip("0")
    # More than 16 digits exceeds every limit below; Python also caps the length
    # of a decimal string it converts.
    return 256**4 if len(part) > 16 else int(part or "0", radix)


def _ipv4_or_domain(host: str) -> str | None:
    """`host` unchanged, unless its last label is a number: the WHATWG parser then
    reads the whole host as an IPv4 address (`0x7f.0.0.1` and `127.1` are both
    127.0.0.1). Returns the dotted-decimal form, or None when it is not valid."""
    parts = host.split(".")
    if parts[-1] == "" and len(parts) > 1:
        parts.pop()
    last = parts[-1]
    all_digits = last != "" and all(ch in "0123456789" for ch in last)
    if not all_digits and _ipv4_number(last) is None:
        return host
    numbers = [_ipv4_number(part) for part in parts]
    if len(numbers) > 4 or None in numbers:
        return None
    if any(n > 255 for n in numbers[:-1]) or numbers[-1] >= 256 ** (5 - len(numbers)):
        return None
    address = numbers[-1] + sum(n * 256 ** (3 - i) for i, n in enumerate(numbers[:-1]))
    return ".".join(str(address >> shift & 255) for shift in (24, 16, 8, 0))


def _serialize_ipv6(address: ipaddress.IPv6Address) -> str:
    """The WHATWG IPv6 serializer: eight lowercase hexadecimal pieces, the first
    longest run of two or more zero pieces written as `::`."""
    pieces = [int(address) >> shift & 0xFFFF for shift in range(112, -1, -16)]
    start, length, i = 0, 1, 0
    while i < 8:
        j = i
        while j < 8 and pieces[j] == 0:
            j += 1
        if j - i > length:
            start, length = i, j - i
        i = max(j, i + 1)
    if length == 1:
        return ":".join(f"{p:x}" for p in pieces)
    head = ":".join(f"{p:x}" for p in pieces[:start])
    tail = ":".join(f"{p:x}" for p in pieces[start + length :])
    return f"{head}::{tail}"


# Forbidden host and forbidden domain code points: the WHATWG URL parser refuses
# a host containing one (the domain set adds C0 controls, "%" and DEL).
_FORBIDDEN_HOST_CHARS = re.compile(r"[\x00\t\n\r #/:<>?@\[\\\]^|]")
_FORBIDDEN_DOMAIN_CHARS = re.compile(r"[\x00-\x20#%/:<>?@\[\\\]^|\x7f]")


def _parse_host(host: str, opaque: bool) -> str | None:
    """The WHATWG host parser: the serialized host, or None on failure."""
    if host.startswith("["):
        if not host.endswith("]") or "%" in host:
            return None
        try:
            return f"[{_serialize_ipv6(ipaddress.IPv6Address(host[1:-1]))}]"
        except ValueError:
            return None
    if opaque:
        # The host of a non-special scheme is kept as written, with C0 controls
        # and everything above "~" percent-encoded.
        if _FORBIDDEN_HOST_CHARS.search(host):
            return None
        return "".join(
            ch if " " <= ch <= "~" else "".join(f"%{b:02X}" for b in ch.encode("utf-8"))
            for ch in host
        )
    domain = _ascii_host(unquote(host))
    if not domain or _FORBIDDEN_DOMAIN_CHARS.search(domain):
        return None
    return _ipv4_or_domain(domain)


# Schemes the WHATWG URL Standard calls special: "\" is a path separator in them
# and their host is a domain or an IP address.
_SPECIAL_SCHEMES = frozenset({"ftp", "file", "http", "https", "ws", "wss"})
_URL_SCHEME = re.compile(r"[A-Za-z][A-Za-z0-9+.-]*:")
_C0_CONTROL_OR_SPACE = "".join(map(chr, range(0x21)))
_AUTHORITY_END = re.compile(r"[/?#]")
_SPECIAL_AUTHORITY_END = re.compile(r"[/\\?#]")
_WINDOWS_DRIVE_LETTER = re.compile(r"[A-Za-z][:|]")


def _valid_port(port: str) -> bool:
    if port == "":
        return True
    # Leading zeros are allowed. Convert the digits without them: Python caps the
    # length of a decimal string it converts.
    digits = port.lstrip("0")
    return port.isascii() and port.isdigit() and len(digits) <= 5 and int(digits or "0") <= 65535


def _hostname_of(url: Any) -> str | None:
    """The provider domain: the host of `url` as the WHATWG URL Standard derives
    it, which is what Node's `new URL(url).hostname` reports. None where that
    parser fails or finds no host.

    Followed from the standard: the scheme and where its authority starts and
    ends (in a special scheme `\\` ends it like `/`, and the slashes after the
    colon are optional), credentials, the port (which must be valid), IPv6
    literals, percent-decoding, forbidden code points, numeric IPv4 forms, the
    `file:` host rules and the opaque host of a non-special scheme.

    Approximated: the mapping of a non-ASCII domain (see `_ascii_host`). The
    UTS #46 validity checks are not made, so a domain those checks refuse (a
    disallowed code point other than U+FFFD, a joiner out of context, a Bidi
    rule violation) is reported here as a host, usually a Punycode form, and
    can be plain ASCII (U+2024 ONE DOT LEADER maps to a full stop), and an
    `xn--` label given in ASCII is returned as written."""
    if not isinstance(url, str):
        return None
    # The parser reads a lone surrogate as U+FFFD, drops C0 controls and spaces
    # around the URL, and removes every tab and newline inside it.
    url = _SURROGATE.sub("�", url).strip(_C0_CONTROL_OR_SPACE)
    url = url.translate({0x09: None, 0x0A: None, 0x0D: None})
    scheme = _URL_SCHEME.match(url)
    if scheme is None:
        return None
    name, rest = scheme.group()[:-1].lower(), url[scheme.end() :]
    special = name in _SPECIAL_SCHEMES
    if name == "file":
        # Two slashes open a file: host, which has no credentials or port. An
        # empty host, a Windows drive letter and "localhost" all mean no host.
        if len(rest) < 2 or rest[0] not in "/\\" or rest[1] not in "/\\":
            return None
        host = _SPECIAL_AUTHORITY_END.split(rest[2:], maxsplit=1)[0]
        if host == "" or _WINDOWS_DRIVE_LETTER.fullmatch(host):
            return None
        host = _parse_host(host, opaque=False)
        return None if host == "localhost" else host
    if special:
        rest = rest.lstrip("/\\")
    elif rest.startswith("//"):
        rest = rest[2:]
    else:
        return None  # no authority (mailto:, urn:)
    authority_end = _SPECIAL_AUTHORITY_END if special else _AUTHORITY_END
    # Credentials end at the last "@"; the port starts at the first ":" outside
    # square brackets.
    hostport = authority_end.split(rest, maxsplit=1)[0].rpartition("@")[2]
    host, port, in_brackets = hostport, "", False
    for i, ch in enumerate(hostport):
        if ch == "[":
            in_brackets = True
        elif ch == "]":
            in_brackets = False
        elif ch == ":" and not in_brackets:
            host, port = hostport[:i], hostport[i + 1 :]
            break
    if host == "" or not _valid_port(port):
        return None
    return _parse_host(host, opaque=not special)


def _reject(category: str, reason: str) -> dict[str, Any]:
    return {"verdict": "REJECT", "category": category, "reason": reason}


def evaluate_identity(fixture: dict[str, Any]) -> dict[str, Any]:
    """Evaluate the identity declaration. Returns {verdict, category?, reason?}.

    The check order is part of the cross-implementation contract. It is the
    numbered list under "Check order" in fixtures/levels/README.md, which is not
    shape-first: some shape checks run between binding checks."""
    card = _as_dict(fixture.get("agentCard"))
    extensions = _as_dict(card.get("capabilities")).get("extensions")
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
    # A declared agentId must be a URN; a JSON null counts as declared, as in verify.mjs.
    agent_id = p.get("agentId")
    if "agentId" in p and not (
        isinstance(agent_id, str) and AGENT_ID_URN_RE.match(agent_id)
    ):
        return _reject(
            "SHAPE_INVALID",
            f"agentId is not a urn:a2a:agent:{{domain}}:{{agent-name}}:{{version}} URN: {agent_id}",
        )
    pk = p.get("publicKey")
    if _ed25519_key_from_jwk(pk) is None or not _is_nonempty_str(pk.get("kid")):
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
        (a for a in _as_list(p.get("attestations")) if isinstance(a, dict) and a.get("type") == "domain"),
        None,
    )
    if att is None:
        return _reject("SHAPE_INVALID", "DOMAIN_VERIFIED requires a domain attestation")
    if not _is_nonempty_str(p.get("agentId")):
        return _reject("SHAPE_INVALID", "DOMAIN_VERIFIED requires an agentId")
    domain = _hostname_of(_as_dict(card.get("provider")).get("url"))
    if domain is None:
        return _reject("SHAPE_INVALID", "provider.url missing or unparseable")
    if att.get("domain") != domain:
        return _reject(
            "DOMAIN_MISMATCH", f"attestation domain {att.get('domain')} != provider domain {domain}"
        )
    dns_txt = _as_dict(_as_dict(fixture.get("evidence")).get("dnsTxt"))
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
            for a in _as_list(p.get("attestations"))
            if isinstance(a, dict) and a.get("type") == "organization"
        ),
        None,
    )
    if att is None:
        return _reject("SHAPE_INVALID", "ORGANIZATION_VERIFIED requires an organization attestation")
    issuer = _as_dict(att.get("issuer"))
    subject = _as_dict(att.get("subject"))
    shape_ok = (
        _is_nonempty_str(issuer.get("name"))
        and _is_nonempty_str(issuer.get("kid"))
        and _is_nonempty_str(issuer.get("url"))
        and _is_nonempty_str(subject.get("organization"))
        and _is_nonempty_str(subject.get("agentId"))
        and _is_nonempty_str(subject.get("kid"))
        and _is_timestamp(att.get("verifiedAt"))
        and _is_timestamp(att.get("expiresAt"))
        and _is_nonempty_str(att.get("signature"))
    )
    if not shape_ok:
        return _reject("SHAPE_INVALID", "organization attestation is missing required fields")
    # The attestation is signed over its JCS form, which a lone surrogate cannot enter.
    if _has_lone_surrogate(att):
        return _reject("SHAPE_INVALID", "organization attestation holds a lone surrogate")
    if subject.get("agentId") != p.get("agentId") or subject.get("kid") != pk["kid"]:
        return _reject(
            "SUBJECT_MISMATCH", "attestation subject does not bind to the declared agentId/kid"
        )
    ev = _as_dict(fixture.get("evidence"))
    issuer_key = _ed25519_key_from_jwk(ev.get("issuerPublicKey"))
    validation_time = ev.get("validationTime")
    if issuer_key is None or not _is_timestamp(validation_time):
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
        _as_dict(fixture.get("expected")), observed["verdict"], observed.get("category")
    )
    if not ok and observed.get("reason") and lines:
        lines[-1] += f" ({observed['reason']})"
    return ok, observed_str, lines


# --- fixture schema (schemas/*.json) ----------------------------------------------

# The committed JSON Schemas are the required-field contract for each fixture
# family. This checker implements exactly the keywords those schemas use:
# type, const, enum, required, properties, allOf, and if/then.
SCHEMA_DIR = Path(__file__).resolve().parent.parent / "schemas"
SCHEMA_FILES = {
    "composition": "fixture-composition-v1.json",
    "level": "fixture-level-v1.json",
}
_schema_cache: dict[str, dict[str, Any]] = {}


def load_schemas() -> dict[str, dict[str, Any]]:
    if not _schema_cache:
        for family, name in SCHEMA_FILES.items():
            _schema_cache[family] = json.loads((SCHEMA_DIR / name).read_text(encoding="utf-8"))
    return _schema_cache


def fixture_family(fixture: Any, schemas: dict[str, dict[str, Any]]) -> str:
    """The fixture's $schema selects its family; without a known $schema, a
    fixture carrying an agentCard is a level fixture and anything else is
    composition."""
    declared = fixture.get("$schema") if isinstance(fixture, dict) else None
    for family, schema in schemas.items():
        if declared == schema["$id"]:
            return family
    return "level" if isinstance(fixture, dict) and "agentCard" in fixture else "composition"


def _json_type(v: Any) -> str:
    if v is None:
        return "null"
    if isinstance(v, bool):
        return "boolean"
    if isinstance(v, int):
        return "integer"
    if isinstance(v, float):
        return "integer" if v.is_integer() else "number"
    if isinstance(v, str):
        return "string"
    if isinstance(v, list):
        return "array"
    return "object"


def _json_text(v: Any) -> str:
    """A scalar as JSON text, and an array or an object by its JSON type:
    json.dumps recurses once per level of nesting, so it raises on a deeply
    nested value. verify.mjs words a value the same way."""
    vtype = _json_type(v)
    if vtype in ("array", "object"):
        return f"a JSON {vtype}"
    return json.dumps(v, ensure_ascii=False, separators=(",", ":"))


def _field_path(path: str, key: str) -> str:
    return key if path == "" else f"{path}.{key}"


def _same_value(a: Any, b: Any) -> bool:
    # JSON equality: true is not 1, as in JavaScript's ===.
    return _json_type(a) == _json_type(b) and a == b


def schema_violation(schema: dict[str, Any], value: Any, path: str) -> str | None:
    """Returns the first violation as a message, or None when the value conforms.
    `type` is a type name or a list of them."""
    where = path or "fixture"
    vtype = _json_type(value)
    stype = schema.get("type")
    if stype is not None:
        types = stype if isinstance(stype, list) else [stype]
        if not any(t == vtype or (t == "number" and vtype == "integer") for t in types):
            names = " or ".join(types)
            if path == "":
                return f"fixture is not a JSON {names}"
            return f"{path} is present but is not a JSON {names}"
    if "const" in schema and not _same_value(value, schema["const"]):
        return f"{where}: expected {_json_text(schema['const'])}, got {_json_text(value)}"
    if "enum" in schema and not any(_same_value(value, v) for v in schema["enum"]):
        allowed = ", ".join(_json_text(v) for v in schema["enum"])
        return f"{where}: {_json_text(value)} is not one of {allowed}"
    if vtype == "object":
        for key in schema.get("required", []):
            if key not in value:
                return f"missing required field {_field_path(path, key)}"
        for key, sub in schema.get("properties", {}).items():
            if key not in value:
                continue
            violation = schema_violation(sub, value[key], _field_path(path, key))
            if violation is not None:
                return violation
    for sub in schema.get("allOf", []):
        violation = schema_violation(sub, value, path)
        if violation is not None:
            return violation
    if "if" in schema and "then" in schema and schema_violation(schema["if"], value, path) is None:
        return schema_violation(schema["then"], value, path)
    return None


# --- driver -----------------------------------------------------------------------


def _reject_constant(name: str) -> None:
    # json.loads reads NaN, Infinity and -Infinity as numbers. They are not JSON,
    # and JSON.parse in verify.mjs raises on them.
    raise ValueError(f"fixture is not valid JSON: {name} is not a JSON value")


_JSON_SCAN = json.JSONDecoder(parse_constant=_reject_constant).scan_once
_JSON_WHITESPACE = re.compile(r"[ \t\n\r]*")


def _load_json(text: str) -> Any:
    """json.loads(text, parse_constant=_reject_constant), without recursion.
    json.loads recurses once per level of nesting and raises past a depth that
    depends on the interpreter (fewer than 1,000 levels on CPython 3.11, fewer
    than 10,000 on 3.12 and 3.13), where JSON.parse in verify.mjs reaches a
    verdict. Here the open arrays and objects are kept on a list, and every
    string, number and literal is read by the json module's own scanner, so
    each value decodes as json.loads decodes it."""
    skip = _JSON_WHITESPACE.match
    # Each open container with the key its next value is stored under (None
    # for an array).
    stack: list[tuple[Any, str | None]] = []
    idx = skip(text).end()
    while True:
        # Read one value at idx: open a container, or scan a complete value.
        opener = text[idx : idx + 1]
        if opener in ("[", "{"):
            container: Any = [] if opener == "[" else {}
            idx = skip(text, idx + 1).end()
            if text[idx : idx + 1] != ("]" if opener == "[" else "}"):
                key = None
                if opener == "{":
                    key, idx = _json_member_name(text, idx)
                stack.append((container, key))
                continue
            value, idx = container, idx + 1
        else:
            try:
                value, idx = _JSON_SCAN(text, idx)
            except StopIteration as stop:
                raise json.JSONDecodeError("Expecting value", text, stop.value) from None
        # Store the value in the container it closes, then close every
        # container that ends after it.
        while stack:
            container, key = stack[-1]
            if key is None:
                container.append(value)
            else:
                container[key] = value
            idx = skip(text, idx).end()
            delimiter = text[idx : idx + 1]
            if delimiter == ",":
                idx = skip(text, idx + 1).end()
                if key is not None:
                    key, idx = _json_member_name(text, idx)
                    stack[-1] = (container, key)
                break
            if delimiter != ("]" if key is None else "}"):
                raise json.JSONDecodeError("Expecting ',' delimiter", text, idx)
            stack.pop()
            value, idx = container, idx + 1
        else:
            end = skip(text, idx).end()
            if end != len(text):
                raise json.JSONDecodeError("Extra data", text, end)
            return value


def _json_member_name(text: str, idx: int) -> tuple[str, int]:
    """The member name at idx and the index of the value after its colon."""
    if text[idx : idx + 1] != '"':
        raise json.JSONDecodeError("Expecting property name enclosed in double quotes", text, idx)
    name, idx = _JSON_SCAN(text, idx)
    idx = _JSON_WHITESPACE.match(text, idx).end()
    if text[idx : idx + 1] != ":":
        raise json.JSONDecodeError("Expecting ':' delimiter", text, idx)
    return name, _JSON_WHITESPACE.match(text, idx + 1).end()


def verify_fixture(path: Path) -> tuple[bool, str | None, list[str]]:
    fixture = _load_json(path.read_text(encoding="utf-8"))
    schemas = load_schemas()
    family = fixture_family(fixture, schemas)
    violation = schema_violation(schemas[family], fixture, "")
    if violation is not None:
        return False, None, ["stage:  schema", f"reason: {violation}"]
    if family == "level":
        return verify_level_fixture(fixture)
    return verify_composition_fixture(fixture)


def _is_real_directory(path: Path) -> bool:
    try:
        return stat.S_ISDIR(os.lstat(path).st_mode)
    except OSError:
        return False


def _is_fixture_file(path: Path) -> bool:
    """A `*.json` path that is a file, or one that cannot be read at all (a
    dangling symlink, a symlink loop), which is then reported as ERROR."""
    if not path.name.endswith(".json"):
        return False
    try:
        return stat.S_ISREG(os.stat(path).st_mode)
    except OSError:
        return True


def collect_fixtures(arg: str) -> list[tuple[Path, OSError | None]]:
    """The fixtures `arg` names, each with the error that kept it from being
    listed (None when it was listed). A path that is not a directory is
    returned as it is, so one that cannot be read (missing, a symlink loop,
    no read permission) is reported as ERROR when it is read. A directory is
    walked for `*.json` files without following symlinks to directories, and
    a directory that cannot be listed is returned with its error, so a
    permissions problem is reported as ERROR rather than read as a pass. The
    path is made absolute without resolving symlinks, as in verify.mjs."""
    path = Path(os.path.abspath(arg))
    if not os.path.isdir(path):
        return [(path, None)]
    found: list[tuple[Path, OSError | None]] = []
    pending = [path]
    while pending:
        directory = pending.pop()
        try:
            names = os.listdir(directory)
        except OSError as exc:
            found.append((directory, exc))
            continue
        for name in names:
            entry = directory / name
            if _is_real_directory(entry):
                pending.append(entry)
            elif _is_fixture_file(entry):
                found.append((entry, None))
    return sorted(found, key=lambda item: item[0])


def main() -> int:
    args = sys.argv[1:]
    if not args:
        print("usage: python3 verify.py <fixture.json | directory> [...]", file=sys.stderr)
        return 2

    # A reason line can quote a fixture string that holds a lone surrogate, which
    # UTF-8 cannot encode: print it escaped instead of raising while reporting.
    sys.stdout.reconfigure(errors="backslashreplace")

    paths = [entry for arg in args for entry in collect_fixtures(arg)]
    pass_count = 0
    fail_count = 0
    for path, listing_error in paths:
        try:
            if listing_error is not None:
                raise listing_error
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
