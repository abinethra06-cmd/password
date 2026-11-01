"""Generate synthetic wordlist + authorized test datasets, and seed SQLite.

Everything here is SYNTHETIC. The "common passwords" are well-known, publicly
documented weak passwords used in security education (not tied to any real
person or breach victim). The synthetic accounts use fictional usernames and
passwords we choose ourselves, so expected crack counts are known in advance
and results can be verified (no fabricated outputs).

Design of the three tiers (lets each attack show distinct coverage):
  * weak   -> password IS in the wordlist         -> cracked by DICTIONARY
  * medium -> base word + mangling (year/number/   -> cracked by HYBRID only
              symbol/leet/caps)
  * strong -> long random high-entropy string      -> cracked by NONE

Run:  python scripts/generate_test_data.py
"""
from __future__ import annotations

import csv
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import config
from backend import database as db
from backend import hashing

# --- Curated common weak passwords (public, synthetic use) -----------------
COMMON_PASSWORDS = [
    "123456", "password", "123456789", "12345678", "12345", "qwerty",
    "1234567", "111111", "1234567890", "123123", "abc123", "1234",
    "password1", "iloveyou", "admin", "welcome", "monkey", "login",
    "dragon", "letmein", "football", "baseball", "master", "sunshine",
    "princess", "666666", "qwertyuiop", "superman", "trustno1", "hello",
    "freedom", "whatever", "shadow", "michael", "jennifer", "hunter",
    "ranger", "harley", "batman", "soccer", "tigger", "charlie",
    "jordan", "pepper", "ginger", "summer", "winter", "spring", "autumn",
    "flower", "cookie", "chocolate", "computer", "internet", "samsung",
    "google", "starwars", "pokemon", "cheese", "banana", "orange",
    "purple", "secret", "access", "money", "ninja", "pass", "test",
    "guest", "root", "oracle", "mysql", "qwerty123", "zaq12wsx",
    "asdfgh", "zxcvbn", "liverpool", "arsenal", "chelsea", "rangers",
    "coffee", "scooter", "mustang", "corvette", "ferrari", "porsche",
    "diamond", "silver", "golden", "angel", "robert", "thomas", "daniel",
    "andrew", "joshua", "william", "matthew", "nicole", "ashley", "amanda",
    "jessica", "hannah", "samantha", "elizabeth", "victoria", "september",
    "october", "november", "december", "january", "february", "august",
]

# Extra dictionary base words used by medium-tier passwords + hybrid bases.
BASE_WORDS = [
    "welcome", "summer", "winter", "dragon", "monkey", "password",
    "qwerty", "flower", "ninja", "shadow", "coffee", "rocket", "galaxy",
    "orange", "purple", "thunder", "falcon", "garden", "silver", "golden",
]


def build_wordlist(path: str = None) -> str:
    """Write the combined, de-duplicated wordlist and return its path."""
    path = path or config.DEFAULT_WORDLIST
    words: list[str] = []
    seen = set()
    for w in COMMON_PASSWORDS + BASE_WORDS:
        if w not in seen:
            seen.add(w)
            words.append(w)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(words) + "\n")
    return path


# --- Synthetic accounts (username, plaintext, tier) ------------------------
# weak passwords are members of COMMON_PASSWORDS; medium are mangled base
# words the hybrid engine can regenerate; strong are random high-entropy.
SYNTHETIC_ACCOUNTS = [
    # weak -> dictionary
    ("alice",   "password",   "weak"),
    ("bob",     "123456",     "weak"),
    ("carol",   "qwerty",     "weak"),
    ("dave",    "letmein",    "weak"),
    ("erin",    "dragon",     "weak"),
    ("frank",   "monkey",     "weak"),
    ("grace",   "iloveyou",   "weak"),
    ("heidi",   "sunshine",   "weak"),
    # medium -> hybrid (base word + mangling)
    ("ivan",    "Summer2021", "medium"),   # cap + year
    ("judy",    "welcome1",   "medium"),   # + digit
    ("mallory", "dragon!",    "medium"),   # + symbol
    ("niaj",    "Monkey99",   "medium"),   # cap + number
    ("olivia",  "p@$$w0rd",   "medium"),   # full leet of "password"
    ("peggy",   "Qwerty123",  "medium"),   # cap + 123
    # strong -> none (long random, mixed classes)
    ("rupert",  "x9#Kq2@mZ!7vLp$R", "strong"),
    ("sybil",   "Tr0ub4dour&3xplore_42", "strong"),
    ("trent",   "9f!Gv7^wQ2zE5&nB8xU", "strong"),
]


def _entries_for(algo: str, salted: bool) -> list[dict]:
    out = []
    for username, pw, _tier in SYNTHETIC_ACCOUNTS:
        if salted:
            stored = hashing.hash_pbkdf2(pw)
            # salt is embedded in the stored string; keep column for clarity
            salt = stored.split("$")[2]
            out.append({"username": username, "hash_value": stored,
                        "hash_algo": "pbkdf2_sha256", "salt": salt,
                        "is_salted": True})
        else:
            out.append({"username": username, "hash_value": hashing.compute(pw, algo),
                        "hash_algo": algo, "salt": None, "is_salted": False})
    return out


def _write_csv(name: str, entries: list[dict]) -> None:
    path = os.path.join(config.DATASET_DIR, f"{name}.csv")
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["username", "hash_value", "hash_algo", "salt", "is_salted"])
        for e in entries:
            w.writerow([e["username"], e["hash_value"], e["hash_algo"],
                        e["salt"] or "", int(e["is_salted"])])


def seed(db_path: str = None) -> dict:
    """Reset DB, write wordlist, create the three datasets. Returns a summary."""
    db.reset_db(db_path)
    wl = build_wordlist()

    # Create the salted dataset FIRST so that list_datasets (ordered newest-
    # first) surfaces a fast UNSALTED dataset as the default UI selection.
    datasets = {
        "Secure store PBKDF2 (salted)":
            ("Same synthetic accounts stored with salted PBKDF2 (secure).",
             "pbkdf2_sha256", True),
        "Corp MD5 dump (unsalted)":
            ("Synthetic corporate password hashes stored as unsalted MD5.", "md5", False),
        "Web app SHA-256 (unsalted)":
            ("Synthetic web-app accounts stored as unsalted SHA-256.", "sha256", False),
    }

    created = {}
    for name, (desc, algo, salted) in datasets.items():
        did = db.create_dataset(name, desc, "synthetic", db_path=db_path)
        entries = _entries_for(algo, salted)
        db.add_entries(did, entries, db_path=db_path)
        _write_csv(name.replace(" ", "_").replace("(", "").replace(")", ""), entries)
        created[name] = {"dataset_id": did, "entries": len(entries)}

    expected = {
        "weak": sum(1 for _u, _p, t in SYNTHETIC_ACCOUNTS if t == "weak"),
        "medium": sum(1 for _u, _p, t in SYNTHETIC_ACCOUNTS if t == "medium"),
        "strong": sum(1 for _u, _p, t in SYNTHETIC_ACCOUNTS if t == "strong"),
    }
    return {"wordlist": wl, "wordlist_size": len(open(wl, encoding="utf-8").read().split()),
            "datasets": created, "expected_tiers": expected}


if __name__ == "__main__":
    summary = seed()
    print("Seeded synthetic data:")
    print(f"  Wordlist: {summary['wordlist']} ({summary['wordlist_size']} words)")
    for name, info in summary["datasets"].items():
        print(f"  Dataset [{info['dataset_id']}] {name}: {info['entries']} entries")
    print(f"  Expected crackable tiers: {summary['expected_tiers']}")
    print("  (weak->dictionary, medium->hybrid, strong->none; "
          "salted dataset resists all)")
