"""Hashing utilities.

Two families:

1. FAST, UNSALTED digests (md5/sha1/sha2 family) -- what the attacks target.
   These are intentionally weak for password storage; a matching plaintext is
   recoverable, which is the whole point the tool demonstrates.

2. SALTED, SLOW KDFs from the stdlib (PBKDF2-HMAC-SHA256 and scrypt) -- the
   "secure storage" example. Each password gets a unique random salt, so the
   same password yields different stored values and precomputed tables fail.

Verification uses `hmac.compare_digest` for constant-time comparison.
No external dependencies -- stdlib only, so it installs cleanly on Python 3.14.
"""
from __future__ import annotations

import hashlib
import hmac
import secrets
from typing import Optional

import config


def compute(password: str, algo: str = "sha256") -> str:
    """Return the hex digest of `password` under a fast, unsalted algorithm."""
    algo = algo.lower()
    if algo not in config.FAST_ALGOS:
        raise ValueError(f"Unsupported fast algorithm: {algo!r}. "
                         f"Choose from {config.FAST_ALGOS}.")
    h = hashlib.new(algo)
    h.update(password.encode("utf-8"))
    return h.hexdigest()


def available_algorithms() -> list[str]:
    return list(config.FAST_ALGOS)


# --- Salted, slow KDFs (secure storage example) ----------------------------
def _gen_salt() -> str:
    return secrets.token_hex(config.SALT_BYTES)


def hash_pbkdf2(password: str, salt: Optional[str] = None,
                iterations: int = config.PBKDF2_ITERATIONS) -> str:
    """PBKDF2-HMAC-SHA256. Returns a self-describing string:

        pbkdf2_sha256$<iterations>$<salt_hex>$<hash_hex>
    """
    salt = salt or _gen_salt()
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"),
                             bytes.fromhex(salt), iterations)
    return f"pbkdf2_sha256${iterations}${salt}${dk.hex()}"


def hash_scrypt(password: str, salt: Optional[str] = None) -> str:
    """scrypt. Returns:  scrypt$<n>$<r>$<p>$<salt_hex>$<hash_hex>"""
    salt = salt or _gen_salt()
    dk = hashlib.scrypt(password.encode("utf-8"), salt=bytes.fromhex(salt),
                        n=config.SCRYPT_N, r=config.SCRYPT_R, p=config.SCRYPT_P,
                        dklen=32)
    return (f"scrypt${config.SCRYPT_N}${config.SCRYPT_R}${config.SCRYPT_P}$"
            f"{salt}${dk.hex()}")


def hash_secure(password: str, algo: str = "pbkdf2_sha256",
                salt: Optional[str] = None) -> str:
    if algo == "pbkdf2_sha256":
        return hash_pbkdf2(password, salt)
    if algo == "scrypt":
        return hash_scrypt(password, salt)
    raise ValueError(f"Unsupported secure algorithm: {algo!r}")


# --- Verification -----------------------------------------------------------
def verify(password: str, stored: str, algo: Optional[str] = None,
           salt: Optional[str] = None) -> bool:
    """Constant-time verification of `password` against a stored value.

    - If `stored` is a self-describing KDF string (pbkdf2_sha256$... or
      scrypt$...), parameters are parsed from it and `algo`/`salt` are ignored.
    - Otherwise `stored` is treated as a fast unsalted hex digest; `algo` is
      required (or inferred by length when omitted).
    """
    if stored.startswith("pbkdf2_sha256$"):
        try:
            _, iters, s, _h = stored.split("$", 3)
            candidate = hash_pbkdf2(password, salt=s, iterations=int(iters))
        except ValueError:
            return False
        return hmac.compare_digest(candidate, stored)

    if stored.startswith("scrypt$"):
        try:
            _, n, r, p, s, _h = stored.split("$", 5)
        except ValueError:
            return False
        dk = hashlib.scrypt(password.encode("utf-8"), salt=bytes.fromhex(s),
                            n=int(n), r=int(r), p=int(p), dklen=32)
        candidate = f"scrypt${n}${r}${p}${s}${dk.hex()}"
        return hmac.compare_digest(candidate, stored)

    # Fast unsalted digest.
    if algo is None:
        algo = _infer_fast_algo(stored)
        if algo is None:
            return False
    candidate = compute(password, algo)
    return hmac.compare_digest(candidate, stored.lower())


def _infer_fast_algo(digest: str) -> Optional[str]:
    by_len = {32: "md5", 40: "sha1", 56: "sha224", 64: "sha256",
              96: "sha384", 128: "sha512"}
    return by_len.get(len(digest.strip()))
