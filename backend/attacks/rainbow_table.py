"""Rainbow-table (precomputed hash-lookup) attack.

We precompute a table mapping {digest: plaintext} for every word in a wordlist
under a chosen algorithm and persist it to disk. Recovery at attack time is then
an O(1) dictionary lookup -- no hashing needed -- which is the space-for-time
trade-off that makes precomputed attacks so fast against unsalted hashes.

HONEST SCOPE NOTE: a classic "rainbow table" additionally uses reduction-function
chains to compress storage at the cost of lookup time. This implementation uses a
direct hash-lookup table, which demonstrates the same practically-relevant idea
(precomputation defeats unsalted hashing) without the chain machinery. This is
stated plainly in the UI and report.

SALTING DEFEATS IT: because a salted hash mixes in a unique random salt, the same
password produces a digest that is NOT in any salt-agnostic precomputed table, so
the lookup fails. `demonstrate_salting()` shows this side by side.

Limitations: table storage grows with coverage; a precomputed table only covers
the passwords it was built from; and it is useless against salted/slow hashes.
"""
from __future__ import annotations

import json
import os
import time
from typing import Callable, Optional

import config
from backend import hashing
from backend.attacks.dictionary_attack import iter_words
from backend.attacks.hybrid_attack import variants

ProgressCb = Optional[Callable[[float, str], None]]
METHOD = "rainbow"


def table_path(algo: str, with_variants: bool = False) -> str:
    tag = f"{algo}{'_hybrid' if with_variants else ''}"
    return os.path.join(config.RAINBOW_DIR, f"rainbow_{tag}.json")


def build_table(algo: str = "md5", wordlist_path: Optional[str] = None,
                with_variants: bool = False, progress: ProgressCb = None,
                force: bool = False) -> dict:
    """Precompute and persist a {digest: plaintext} table. Returns metadata."""
    if algo not in config.FAST_ALGOS:
        raise ValueError(f"Rainbow tables target fast unsalted algos, not {algo!r}")
    wordlist_path = wordlist_path or config.DEFAULT_WORDLIST
    path = table_path(algo, with_variants)
    if os.path.exists(path) and not force:
        meta = _read_meta(path)
        if meta:
            return meta

    start = time.perf_counter()
    table: dict[str, str] = {}
    words = list(iter_words(wordlist_path))
    n = max(len(words), 1)
    for i, word in enumerate(words):
        candidates = [word]
        if with_variants:
            candidates = list(variants(word))
        for cand in candidates:
            table[hashing.compute(cand, algo)] = cand
        if progress and (i % 20 == 0):
            progress((i + 1) / n, f"building {algo} table: {i + 1}/{n} words")
    build_time = time.perf_counter() - start

    meta = {"algo": algo, "with_variants": with_variants, "entries": len(table),
            "build_time_sec": round(build_time, 4), "path": path}
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump({"_meta": meta, "table": table}, fh)
    if progress:
        progress(1.0, f"{algo} table built: {len(table)} entries")
    return meta


def _read_meta(path: str) -> Optional[dict]:
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh).get("_meta")
    except (OSError, ValueError):
        return None


def load_table(algo: str, with_variants: bool = False) -> dict[str, str]:
    path = table_path(algo, with_variants)
    if not os.path.exists(path):
        raise FileNotFoundError(f"No precomputed table at {path}. Build it first.")
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)["table"]


def lookup(digest: str, algo: str, with_variants: bool = False) -> Optional[str]:
    return load_table(algo, with_variants).get(digest.strip().lower())


def run(targets: list[dict], wordlist_path: Optional[str] = None,
        with_variants: bool = False, progress: ProgressCb = None) -> dict:
    """Attack targets using precomputed tables (built on demand per algo)."""
    wordlist_path = wordlist_path or config.DEFAULT_WORDLIST
    results = {
        t["id"]: {
            "entry_id": t.get("id"), "username": t.get("username"),
            "hash_algo": t.get("hash_algo"), "cracked": False,
            "recovered_password": None, "method": METHOD,
            "attempts": 1, "time_sec": 0.0,
        } for t in targets
    }
    start = time.perf_counter()
    attempts = 0

    # Ensure tables exist for each fast algo present among unsalted targets.
    algos = {(t["hash_algo"] or "").lower() for t in targets
             if not t.get("is_salted")}
    tables: dict[str, dict] = {}
    for algo in algos:
        if algo in config.FAST_ALGOS:
            build_table(algo, wordlist_path, with_variants, progress)
            tables[algo] = load_table(algo, with_variants)

    for t in targets:
        res = results[t["id"]]
        attempts += 1
        if t.get("is_salted"):
            # Salted hash -> not a plain digest in any salt-agnostic table.
            continue
        algo = (t["hash_algo"] or "").lower()
        tbl = tables.get(algo)
        if tbl is not None:
            pw = tbl.get(t["hash_value"].strip().lower())
            if pw is not None:
                res["cracked"] = True
                res["recovered_password"] = pw

    elapsed = time.perf_counter() - start
    for r in results.values():
        r["time_sec"] = round(elapsed, 6)
    cracked = sum(1 for r in results.values() if r["cracked"])
    if progress:
        progress(1.0, f"rainbow lookup done: {cracked}/{len(targets)} cracked")
    return {"results": list(results.values()), "attempts": attempts,
            "elapsed": elapsed, "cracked_count": cracked}


def demonstrate_salting(password: str, algo: str = "md5",
                        wordlist_path: Optional[str] = None) -> dict:
    """Show that an unsalted digest is recoverable from the table while the
    same password salted is not. Returns a structured comparison for the UI."""
    wordlist_path = wordlist_path or config.DEFAULT_WORDLIST
    build_table(algo, wordlist_path)
    tbl = load_table(algo)

    unsalted_digest = hashing.compute(password, algo)
    unsalted_found = tbl.get(unsalted_digest)

    salted_stored = hashing.hash_pbkdf2(password)       # unique random salt
    salt = salted_stored.split("$")[2]
    # The salted stored value is not a bare digest; a table lookup cannot match.
    salted_found = tbl.get(salted_stored.lower())

    return {
        "password": password,
        "algo": algo,
        "table_entries": len(tbl),
        "unsalted": {
            "stored": unsalted_digest,
            "recovered": unsalted_found,
            "cracked": unsalted_found is not None,
        },
        "salted": {
            "stored": salted_stored,
            "salt": salt,
            "recovered": salted_found,
            "cracked": salted_found is not None,
        },
        "conclusion": (
            "Unsalted hash recovered instantly by table lookup; the salted hash "
            "is absent from the table (unique salt), so precomputation fails."),
    }
