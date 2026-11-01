"""Import / create datasets from user-supplied authorized data.

Three entry points feed the same validation + persistence path:
  * rows_from_csv       -- a CSV with username/hash_value(/hash_algo/salt)
  * rows_from_hashes    -- pasted hashes, one per line (optional user:hash)
  * rows_from_plaintext -- sample passwords hashed HERE (build synthetic data
                           without handling pre-existing hashes)

Each producer returns (rows, errors): `rows` are entry dicts ready for
database.add_entries; `errors` are human-readable per-line problems to surface
in the UI. Algorithm is auto-detected from a hash's length/format when not given.
"""
from __future__ import annotations

import csv
import io
from typing import Optional

import config
from backend import database as db, hashing
from backend import hash_identifier as hid

_NAME_TO_ALGO = {
    "MD5": "md5", "SHA-1": "sha1", "SHA-224": "sha224", "SHA-256": "sha256",
    "SHA-384": "sha384", "SHA-512": "sha512",
}


def detect(hash_value: str) -> tuple[Optional[str], bool]:
    """Return (algo_key, is_salted) for a hash, or (None, False) if unknown."""
    h = (hash_value or "").strip()
    if not h:
        return None, False
    if hid.is_salted_format(h):
        low = h.lower()
        if low.startswith("pbkdf2_sha256$"):
            return "pbkdf2_sha256", True
        if low.startswith("scrypt$"):
            return "scrypt", True
        # bcrypt/argon2/etc: store the identified name; attacks can't crack it.
        return hid.identify(h)[0]["name"], True
    top = hid.identify(h)[0]["name"]
    return _NAME_TO_ALGO.get(top), False


def _entry(username: str, hash_value: str, algo: str, salted: bool,
           salt: Optional[str] = None) -> dict:
    return {"username": username, "hash_value": hash_value, "hash_algo": algo,
            "salt": salt, "is_salted": bool(salted)}


def _split_user(line: str, default_user: str) -> tuple[str, str]:
    """Split 'user:value' / 'user,value' into (user, value). Salted formats
    use '$' (not ':'/',') as separators, so splitting on the first ':'/',' is
    safe for a leading username."""
    for sep in (",", ":"):
        if sep in line:
            user, _, rest = line.partition(sep)
            user, rest = user.strip(), rest.strip()
            if user and rest:
                return user, rest
    return default_user, line.strip()


def rows_from_hashes(text: str, algo: str = "auto") -> tuple[list[dict], list[str]]:
    rows, errors = [], []
    for i, raw in enumerate((text or "").splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        user, value = _split_user(line, f"user{len(rows) + 1}")
        if algo == "auto":
            a, salted = detect(value)
        else:
            a, salted = algo, algo in config.SECURE_ALGOS
        if not a:
            errors.append(f"Line {i}: could not identify the hash algorithm.")
            continue
        rows.append(_entry(user, value, a, salted))
    return rows, errors


def rows_from_plaintext(text: str, algo: str = "sha256"
                        ) -> tuple[list[dict], list[str]]:
    """Hash sample passwords here (authorized synthetic test data)."""
    rows, errors = [], []
    for i, raw in enumerate((text or "").splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        user, pw = _split_user(line, f"user{len(rows) + 1}")
        try:
            if algo in config.FAST_ALGOS:
                rows.append(_entry(user, hashing.compute(pw, algo), algo, False))
            elif algo in config.SECURE_ALGOS:
                stored = hashing.hash_secure(pw, algo)
                salt = stored.split("$")[2] if "$" in stored else None
                rows.append(_entry(user, stored, algo, True, salt))
            else:
                errors.append(f"Line {i}: unsupported algorithm {algo!r}.")
        except Exception as exc:  # pragma: no cover - defensive
            errors.append(f"Line {i}: {exc}")
    return rows, errors


def rows_from_csv(text: str) -> tuple[list[dict], list[str]]:
    rows, errors = [], []
    reader = csv.DictReader(io.StringIO(text))
    if not reader.fieldnames:
        return [], ["CSV is empty or has no header row."]
    cols = {c.lower().strip(): c for c in reader.fieldnames}
    if "hash_value" not in cols:
        return [], ["CSV must have a 'hash_value' column "
                    "(optional: username, hash_algo, salt, is_salted)."]
    for i, r in enumerate(reader, 2):  # row 1 is the header
        value = (r.get(cols["hash_value"]) or "").strip()
        if not value:
            continue
        user = (r.get(cols.get("username", ""), "") or f"user{len(rows) + 1}").strip()
        algo = (r.get(cols.get("hash_algo", ""), "") or "").strip().lower()
        salt = (r.get(cols.get("salt", ""), "") or "").strip() or None
        if algo:
            salted = (algo in config.SECURE_ALGOS) or hid.is_salted_format(value)
        else:
            algo, salted = detect(value)
        raw_salted = (r.get(cols.get("is_salted", ""), "") or "").strip().lower()
        if raw_salted in ("1", "true", "yes"):
            salted = True
        if not algo:
            errors.append(f"Row {i}: could not identify the hash algorithm.")
            continue
        rows.append(_entry(user, value, algo, salted, salt))
    return rows, errors


def create_dataset(name: str, description: str, rows: list[dict],
                   db_path: Optional[str] = None) -> int:
    """Persist a new dataset from validated rows. Raises ValueError on bad input."""
    name = (name or "").strip()
    if not name:
        raise ValueError("Dataset name is required.")
    if not rows:
        raise ValueError("No valid accounts to import.")
    if any(d["name"] == name for d in db.list_datasets(db_path=db_path)):
        raise ValueError(f"A dataset named {name!r} already exists.")
    dataset_id = db.create_dataset(name, description, "imported", db_path=db_path)
    db.add_entries(dataset_id, rows, db_path=db_path)
    return dataset_id
