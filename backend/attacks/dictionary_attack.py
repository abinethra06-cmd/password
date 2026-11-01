"""Dictionary attack.

Tests a wordlist of candidate passwords against authorized target hashes.

Two code paths:
  * UNSALTED fast hashes  -> hash each candidate ONCE, O(1) lookup against a
    map of {digest: [targets]}. One pass over the wordlist cracks every target
    sharing that algorithm. This batch speed-up is exactly what salting removes.
  * SALTED KDFs           -> each target has a unique salt, so candidates must
    be re-hashed per target (hashing.verify). Far slower; demonstrates that
    salting defeats precomputation/batching (though a weak password can still
    eventually fall to online guessing).

Limitation: can only find passwords that appear in the wordlist. A password
absent from the list is never found, regardless of effort.
"""
from __future__ import annotations

import time
from typing import Callable, Iterable, Optional

import config
from backend import hashing

ProgressCb = Optional[Callable[[float, str], None]]
METHOD = "dictionary"


def iter_words(path: str) -> Iterable[str]:
    with open(path, "r", encoding="utf-8", errors="ignore") as fh:
        for line in fh:
            w = line.rstrip("\n\r")
            if w:
                yield w


def count_words(path: str) -> int:
    with open(path, "r", encoding="utf-8", errors="ignore") as fh:
        return sum(1 for line in fh if line.strip())


def _blank_result(t: dict) -> dict:
    return {
        "entry_id": t.get("id"),
        "username": t.get("username"),
        "hash_algo": t.get("hash_algo"),
        "cracked": False,
        "recovered_password": None,
        "method": METHOD,
        "attempts": 0,
        "time_sec": 0.0,
    }


def run(targets: list[dict], wordlist_path: Optional[str] = None,
        progress: ProgressCb = None, salted_budget_sec: float = 8.0) -> dict:
    """Run a dictionary attack against `targets`.

    Each target: {id, username, hash_value, hash_algo, salt, is_salted}.
    `salted_budget_sec` caps wall-clock time spent on the (slow) salted path;
    when exhausted, remaining salted accounts are left uncracked and
    `budget_exhausted` is set -- the honest demonstration that salted, slow
    hashing makes batch guessing infeasible.
    Returns {results, attempts, elapsed, cracked_count, budget_exhausted}.
    """
    wordlist_path = wordlist_path or config.DEFAULT_WORDLIST
    results = {t["id"]: _blank_result(t) for t in targets}
    start = time.perf_counter()
    attempts = 0
    budget_exhausted = False

    salted = [t for t in targets if t.get("is_salted")]
    unsalted = [t for t in targets if not t.get("is_salted")]

    # --- Unsalted: single pass, O(1) lookups ------------------------------
    if unsalted:
        # group targets by algorithm, map digest -> [target ids]
        by_algo: dict[str, dict[str, list[int]]] = {}
        for t in unsalted:
            algo = (t["hash_algo"] or "").lower()
            by_algo.setdefault(algo, {}).setdefault(
                t["hash_value"].strip().lower(), []).append(t["id"])

        total = max(count_words(wordlist_path), 1)
        for i, word in enumerate(iter_words(wordlist_path)):
            for algo, digest_map in by_algo.items():
                if algo not in config.FAST_ALGOS:
                    continue
                d = hashing.compute(word, algo)
                attempts += 1
                hit = digest_map.get(d)
                if hit:
                    for tid in hit:
                        if not results[tid]["cracked"]:
                            results[tid]["cracked"] = True
                            results[tid]["recovered_password"] = word
                            results[tid]["attempts"] = i + 1
            if progress and (i % 25 == 0):
                progress(0.6 * (i + 1) / total, f"dictionary: {i + 1}/{total} words")

    # --- Salted: per-target verification, time-budgeted -------------------
    if salted:
        words = list(iter_words(wordlist_path))
        salted_start = time.perf_counter()
        for j, t in enumerate(salted):
            res = results[t["id"]]
            if time.perf_counter() - salted_start > salted_budget_sec:
                budget_exhausted = True
                break
            for k, word in enumerate(words):
                attempts += 1
                if hashing.verify(word, t["hash_value"]):
                    res["cracked"] = True
                    res["recovered_password"] = word
                    res["attempts"] = k + 1
                    break
                if time.perf_counter() - salted_start > salted_budget_sec:
                    budget_exhausted = True
                    break
            if progress:
                progress(0.6 + 0.4 * (j + 1) / len(salted),
                         f"dictionary (salted): {j + 1}/{len(salted)} accounts")
            if budget_exhausted:
                break

    elapsed = time.perf_counter() - start
    for r in results.values():
        r["time_sec"] = round(elapsed, 4)

    cracked = sum(1 for r in results.values() if r["cracked"])
    if progress:
        progress(1.0, f"dictionary done: {cracked}/{len(targets)} cracked")
    return {
        "results": list(results.values()),
        "attempts": attempts,
        "elapsed": elapsed,
        "cracked_count": cracked,
        "budget_exhausted": budget_exhausted,
    }
