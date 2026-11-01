"""Hash identification.

Given a hash string, guess the algorithm(s) that could have produced it using
length, character set, and known prefixes. This is a heuristic (no AI/ML):
several algorithms share the same output length (e.g. MD5 and NTLM are both
32 hex chars), so results are returned as a RANKED list of candidates with
notes rather than a single definitive answer.
"""
from __future__ import annotations

import re
from typing import Optional

HEX_RE = re.compile(r"^[0-9a-fA-F]+$")

# length (hex chars) -> list of (name, confidence, note)
_BY_LENGTH = {
    32:  [("MD5", "medium", "Also matches NTLM / MD4 (same 128-bit length)."),
          ("NTLM", "low", "Windows NT hash; identical length to MD5.")],
    40:  [("SHA-1", "high", "160-bit; also RIPEMD-160.")],
    56:  [("SHA-224", "high", "SHA-2 family, 224-bit.")],
    64:  [("SHA-256", "high", "SHA-2 family; also SHA3-256 / BLAKE2s.")],
    96:  [("SHA-384", "high", "SHA-2 family, 384-bit.")],
    128: [("SHA-512", "high", "SHA-2 family; also SHA3-512 / BLAKE2b.")],
}


def identify(value: str) -> list[dict]:
    """Return ranked candidate identifications for `value`."""
    v = (value or "").strip()
    if not v:
        return [{"name": "Unknown", "confidence": "n/a",
                 "note": "Empty input."}]

    # Self-describing / prefixed formats first.
    prefixed = _match_prefix(v)
    if prefixed:
        return prefixed

    if not HEX_RE.match(v):
        return [{"name": "Unknown / non-hex",
                 "confidence": "n/a",
                 "note": "Not a plain hex digest and no known prefix. "
                         "May be Base64, a salted format, or encrypted."}]

    candidates = _BY_LENGTH.get(len(v))
    if not candidates:
        return [{"name": "Unknown",
                 "confidence": "n/a",
                 "note": f"Unrecognised hex length ({len(v)} chars)."}]
    return [{"name": n, "confidence": c, "note": note}
            for (n, c, note) in candidates]


def _match_prefix(v: str) -> Optional[list[dict]]:
    low = v.lower()
    if low.startswith("pbkdf2_sha256$"):
        return [{"name": "PBKDF2-HMAC-SHA256", "confidence": "high",
                 "note": "Salted, slow KDF (this tool's secure format). "
                         "Resistant to dictionary/rainbow attacks."}]
    if low.startswith("scrypt$"):
        return [{"name": "scrypt", "confidence": "high",
                 "note": "Salted, memory-hard KDF. Resistant to precomputed "
                         "tables and GPU cracking."}]
    if v.startswith("$2a$") or v.startswith("$2b$") or v.startswith("$2y$"):
        return [{"name": "bcrypt", "confidence": "high",
                 "note": "Adaptive salted hash; strong against offline attacks."}]
    if v.startswith("$argon2"):
        return [{"name": "Argon2", "confidence": "high",
                 "note": "Modern memory-hard KDF (PHC winner)."}]
    if v.startswith("$1$"):
        return [{"name": "md5crypt", "confidence": "high",
                 "note": "Legacy Unix crypt; weak by modern standards."}]
    if v.startswith("$6$"):
        return [{"name": "sha512crypt", "confidence": "high",
                 "note": "Unix crypt, SHA-512 based."}]
    return None


def is_salted_format(value: str) -> bool:
    """True if the value is a known salted/slow format (not a bare digest)."""
    v = (value or "").strip().lower()
    return (v.startswith("pbkdf2_sha256$") or v.startswith("scrypt$")
            or v.startswith("$2a$") or v.startswith("$2b$")
            or v.startswith("$2y$") or v.startswith("$argon2")
            or v.startswith("$6$") or v.startswith("$1$"))
