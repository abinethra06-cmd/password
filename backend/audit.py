"""Audit orchestrator.

Loads a dataset's hashes, runs one or all attack engines against them,
classifies per-account risk, persists the run + results, and returns a summary.

Design choices:
  * For "all", engines run in order dictionary -> rainbow -> hybrid, and each
    subsequent engine only sees accounts not yet cracked (saves work, and the
    stored `method` reflects the first/cheapest technique that succeeded).
  * Only derived results are persisted. Recovered passwords stored here are
    SYNTHETIC test values, not real secrets.
"""
from __future__ import annotations

from typing import Callable, Optional

import config
from backend import database as db
from backend import risk
from backend.attacks import dictionary_attack, hybrid_attack, rainbow_table

ProgressCb = Optional[Callable[[float, str], None]]

ENGINES = {
    "dictionary": dictionary_attack.run,
    "hybrid": hybrid_attack.run,
    "rainbow": rainbow_table.run,
}
ATTACK_PLANS = {
    "dictionary": ["dictionary"],
    "hybrid": ["hybrid"],
    "rainbow": ["rainbow"],
    "all": ["dictionary", "rainbow", "hybrid"],
}


def _targets_from_entries(entries: list[dict]) -> list[dict]:
    return [{
        "id": e["id"],
        "username": e["username"],
        "hash_value": e["hash_value"],
        "hash_algo": e["hash_algo"],
        "salt": e.get("salt"),
        "is_salted": bool(e.get("is_salted")),
    } for e in entries]


def _blank(t: dict) -> dict:
    return {"entry_id": t["id"], "username": t["username"],
            "hash_algo": t["hash_algo"], "cracked": False,
            "recovered_password": None, "method": None,
            "attempts": 0, "time_sec": 0.0, "is_salted": t["is_salted"]}


def _run_engine(name: str, targets: list[dict], params: dict,
                progress: ProgressCb) -> dict:
    wl = params.get("wordlist_path") or config.DEFAULT_WORDLIST
    budget = params.get("salted_budget_sec", 8.0)
    if name == "hybrid":
        return ENGINES[name](
            targets, wordlist_path=wl, progress=progress,
            max_variants_per_word=params.get(
                "max_variants_per_word", config.HYBRID_MAX_VARIANTS_PER_WORD),
            max_candidates_per_target_salted=params.get(
                "max_candidates_per_target_salted", 3000),
            salted_budget_sec=budget)
    if name == "rainbow":
        return ENGINES[name](targets, wordlist_path=wl, progress=progress,
                             with_variants=params.get("with_variants", False))
    return ENGINES[name](targets, wordlist_path=wl, progress=progress,
                         salted_budget_sec=budget)


def run_audit(dataset_id: int, attack_type: str = "all",
              params: Optional[dict] = None, db_path: Optional[str] = None,
              progress: ProgressCb = None) -> dict:
    if attack_type not in ATTACK_PLANS:
        raise ValueError(f"Unknown attack_type {attack_type!r}. "
                         f"Choose from {list(ATTACK_PLANS)}.")
    params = params or {}
    entries = db.get_entries(dataset_id, db_path=db_path)
    targets = _targets_from_entries(entries)
    if not targets:
        raise ValueError(f"Dataset {dataset_id} has no entries.")

    merged = {t["id"]: _blank(t) for t in targets}
    total_attempts = 0
    total_elapsed = 0.0

    plan = ATTACK_PLANS[attack_type]
    pending = list(targets)
    budget_exhausted = False
    for idx, name in enumerate(plan):
        if not pending:
            break

        def stage_progress(frac, msg, _i=idx, _n=len(plan)):
            if progress:
                progress((_i + frac) / _n, f"[{name}] {msg}")

        out = _run_engine(name, pending, params, stage_progress)
        total_attempts += out["attempts"]
        total_elapsed += out["elapsed"]
        budget_exhausted = budget_exhausted or out.get("budget_exhausted", False)
        for r in out["results"]:
            if r["cracked"] and not merged[r["entry_id"]]["cracked"]:
                m = merged[r["entry_id"]]
                m.update(cracked=True, recovered_password=r["recovered_password"],
                         method=r["method"], attempts=r["attempts"],
                         time_sec=r["time_sec"])
        pending = [t for t in targets if not merged[t["id"]]["cracked"]]

    # Classify risk per account.
    final = []
    for t in targets:
        r = merged[t["id"]]
        r["risk_level"] = risk.classify_account(
            r["cracked"], r.get("method"), t["is_salted"])
        final.append(r)

    summary = risk.summarize(final, entries=entries)
    summary["attack_type"] = attack_type
    summary["total_attempts"] = total_attempts
    summary["total_elapsed_sec"] = round(total_elapsed, 4)
    summary["budget_exhausted"] = budget_exhausted
    summary["recommendations"] = risk.recommendations(summary)

    run_id = db.create_run(dataset_id, attack_type, params, len(targets),
                           db_path=db_path)
    db.add_results(run_id, final, db_path=db_path)
    db.finish_run(run_id, summary["cracked_count"], total_elapsed, db_path=db_path)

    summary["run_id"] = run_id
    return {"run_id": run_id, "summary": summary, "results": final}
