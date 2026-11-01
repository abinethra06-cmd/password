"""Hybrid attack.

Combines dictionary words with common human password patterns: capitalisation,
leetspeak substitution, and appended/prepended numbers, years and symbols.
This catches passwords that are *based on* a dictionary word but mutated enough
to miss a plain dictionary attack (e.g. "Summer2021", "welcome1", "p@$$w0rd").

Candidate generation per base word (bounded by `max_variants_per_word`):
  1. case forms:   word, lower, UPPER, Capitalised, full leetspeak
  2. for each case form: append a suffix (0-99, 123/1234, years, symbols)
  3. a few prepend forms (symbol/number + word)

Limitations:
  * Only finds mutations expressible by these rules; novel schemes are missed.
  * The candidate space grows multiplicatively, so the per-word cap trades
    coverage for runtime. Against SALTED hashes each candidate must be re-hashed
    per account, so a per-account budget keeps it responsive (and realistically
    shows the attack becoming infeasible).
"""
from __future__ import annotations

import time
from typing import Callable, Iterable, Iterator, Optional

import config
from backend import hashing
from backend.attacks.dictionary_attack import iter_words

ProgressCb = Optional[Callable[[float, str], None]]
METHOD = "hybrid"


def _leet(word: str) -> str:
    return "".join(config.LEET_MAP.get(c, c) for c in word.lower())


def _case_forms(word: str) -> list[str]:
    forms = []
    for f in (word, word.lower(), word.upper(), word.capitalize(), _leet(word)):
        if f not in forms:
            forms.append(f)
    return forms


def _ordered_suffixes() -> list[str]:
    """Suffixes in priority order so high-value mutations (common numbers,
    years, symbols) are covered for every case form before the exhaustive
    0-99 range is exhausted and the per-word cap is reached."""
    common = ["", "1", "123", "1234", "12", "12345", "007", "69",
              "99", "00", "11", "111", "2", "3", "21", "01"]
    years = [str(y) for y in config.HYBRID_YEARS]
    symbols = config.HYBRID_SUFFIX_SYMBOLS
    rest = [s for s in config.HYBRID_SUFFIX_NUMBERS if s not in common]
    ordered, seen = [], set()
    for s in common + years + symbols + rest:
        if s not in seen:
            seen.add(s)
            ordered.append(s)
    return ordered


def variants(word: str, max_variants: int = config.HYBRID_MAX_VARIANTS_PER_WORD
             ) -> Iterator[str]:
    """Yield mangled variants of `word`, de-duplicated and capped.

    Generation is suffix-outer / form-inner: for each suffix (in priority
    order) we apply it to every case form. This guarantees fair coverage of
    year/number/symbol patterns across all casings within the variant budget.
    """
    seen: set[str] = set()
    count = 0
    forms = _case_forms(word)
    prefixes = ["1", "123", "!", "@", "#"]

    def emit(v: str):
        nonlocal count
        if v and v not in seen:
            seen.add(v)
            count += 1
            return True
        return False

    for suf in _ordered_suffixes():
        for form in forms:
            if count >= max_variants:
                return
            cand = form + suf
            if emit(cand):
                yield cand
    for pre in prefixes:
        for form in forms:
            if count >= max_variants:
                return
            cand = pre + form
            if emit(cand):
                yield cand


def run(targets: list[dict], wordlist_path: Optional[str] = None,
        progress: ProgressCb = None,
        max_variants_per_word: int = config.HYBRID_MAX_VARIANTS_PER_WORD,
        max_candidates_per_target_salted: int = 3000,
        salted_budget_sec: float = 8.0) -> dict:
    """Run a hybrid attack against `targets` (same shape as dictionary_attack).

    `salted_budget_sec` caps total wall-clock time on the slow salted path.
    """
    wordlist_path = wordlist_path or config.DEFAULT_WORDLIST
    budget_exhausted = False
    results = {
        t["id"]: {
            "entry_id": t.get("id"), "username": t.get("username"),
            "hash_algo": t.get("hash_algo"), "cracked": False,
            "recovered_password": None, "method": METHOD,
            "attempts": 0, "time_sec": 0.0,
        } for t in targets
    }
    start = time.perf_counter()
    attempts = 0

    base_words = list(iter_words(wordlist_path))
    salted = [t for t in targets if t.get("is_salted")]
    unsalted = [t for t in targets if not t.get("is_salted")]

    # --- Unsalted: generate variants once, O(1) lookups -------------------
    if unsalted:
        by_algo: dict[str, dict[str, list[int]]] = {}
        for t in unsalted:
            algo = (t["hash_algo"] or "").lower()
            by_algo.setdefault(algo, {}).setdefault(
                t["hash_value"].strip().lower(), []).append(t["id"])

        remaining = {tid for m in by_algo.values() for ids in m.values() for tid in ids}
        n_words = max(len(base_words), 1)
        for wi, word in enumerate(base_words):
            for cand in variants(word, max_variants_per_word):
                for algo, digest_map in by_algo.items():
                    if algo not in config.FAST_ALGOS:
                        continue
                    d = hashing.compute(cand, algo)
                    attempts += 1
                    hit = digest_map.get(d)
                    if hit:
                        for tid in hit:
                            if not results[tid]["cracked"]:
                                results[tid]["cracked"] = True
                                results[tid]["recovered_password"] = cand
                                results[tid]["attempts"] = attempts
                                remaining.discard(tid)
            if progress and (wi % 10 == 0):
                progress(0.6 * (wi + 1) / n_words,
                         f"hybrid: base word {wi + 1}/{n_words}")
            if not remaining:
                break

    # --- Salted: per-target, bounded by candidate cap AND time budget -----
    if salted:
        salted_start = time.perf_counter()
        for j, t in enumerate(salted):
            if time.perf_counter() - salted_start > salted_budget_sec:
                budget_exhausted = True
                break
            res = results[t["id"]]
            tried = 0
            done = False
            for word in base_words:
                if done:
                    break
                for cand in variants(word, max_variants_per_word):
                    attempts += 1
                    tried += 1
                    if hashing.verify(cand, t["hash_value"]):
                        res["cracked"] = True
                        res["recovered_password"] = cand
                        res["attempts"] = tried
                        done = True
                        break
                    if tried >= max_candidates_per_target_salted:
                        done = True
                        break
                    if time.perf_counter() - salted_start > salted_budget_sec:
                        budget_exhausted = True
                        done = True
                        break
            if progress:
                progress(0.6 + 0.4 * (j + 1) / len(salted),
                         f"hybrid (salted): {j + 1}/{len(salted)} accounts")
            if budget_exhausted:
                break

    elapsed = time.perf_counter() - start
    for r in results.values():
        r["time_sec"] = round(elapsed, 4)
    cracked = sum(1 for r in results.values() if r["cracked"])
    if progress:
        progress(1.0, f"hybrid done: {cracked}/{len(targets)} cracked")
    return {"results": list(results.values()), "attempts": attempts,
            "elapsed": elapsed, "cracked_count": cracked,
            "budget_exhausted": budget_exhausted}
