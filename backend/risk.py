"""Security risk classification.

Turns a raw attack result (per account) into a Critical/High/Medium/Low risk
level, and rolls individual results up into a dataset-level summary that also
calls out the storage weakness (unsalted fast hashing vs salted KDF).
"""
from __future__ import annotations

from typing import Optional

import config


def classify_account(cracked: bool, method: Optional[str], is_salted: bool,
                     strength_score: Optional[int] = None) -> str:
    """Risk level for a single account given how (and whether) it was broken."""
    if cracked:
        if method == "dictionary":
            return "Critical"   # trivially guessable common password
        if method == "rainbow":
            return "Critical"   # instant recovery from precomputed table
        if method == "hybrid":
            return "High"       # predictable mutation of a dictionary word
        return "High"
    # Not cracked within this attack's scope.
    if strength_score is not None and strength_score < 50:
        return "Medium"         # survived THIS attack but still weak
    if is_salted:
        return "Low"            # strong handling, not broken
    return "Low"


def worst(levels: list[str]) -> str:
    if not levels:
        return "Low"
    return min(levels, key=lambda l: config.RISK_ORDER.get(l, 99))


def summarize(results: list[dict], entries: Optional[list[dict]] = None) -> dict:
    """Aggregate per-account results into a dataset-level risk summary.

    `results` items carry at least: cracked, risk_level, hash_algo, is_salted
    (is_salted falls back to the matching entry if provided).
    """
    total = len(results)
    cracked = sum(1 for r in results if r.get("cracked"))
    counts = {lvl: 0 for lvl in config.RISK_LEVELS}
    for r in results:
        lvl = r.get("risk_level") or "Low"
        counts[lvl] = counts.get(lvl, 0) + 1

    # Storage assessment.
    algos = {(r.get("hash_algo") or "").lower() for r in results}
    salted_flags = [bool(r.get("is_salted")) for r in results]
    if entries:
        salted_flags = [bool(e.get("is_salted")) for e in entries]
    any_salted = any(salted_flags)
    all_salted = all(salted_flags) and bool(salted_flags)
    fast_unsalted = any(a in config.FAST_ALGOS for a in algos) and not all_salted

    storage_grade = "Good" if all_salted else ("Mixed" if any_salted else "Poor")
    storage_notes = []
    if fast_unsalted:
        storage_notes.append(
            "Passwords are stored as fast, unsalted hashes -- vulnerable to "
            "dictionary, hybrid and rainbow-table attacks. Migrate to a salted, "
            "slow KDF (PBKDF2, scrypt, bcrypt or Argon2).")
    if all_salted:
        storage_notes.append(
            "Passwords use salted, slow hashing -- resistant to precomputation "
            "and batch attacks. Weak passwords can still fall to targeted guessing.")

    crack_rate = round(100 * cracked / total, 1) if total else 0.0
    overall = worst([r.get("risk_level") or "Low" for r in results])
    return {
        "total_accounts": total,
        "cracked_count": cracked,
        "crack_rate_pct": crack_rate,
        "risk_counts": counts,
        "overall_risk": overall,
        "storage_grade": storage_grade,
        "storage_notes": storage_notes,
        "algorithms": sorted(a for a in algos if a),
    }


def recommendations(summary: dict) -> list[str]:
    recs = []
    if summary["crack_rate_pct"] > 0:
        recs.append(
            f"{summary['cracked_count']} of {summary['total_accounts']} passwords "
            f"were recovered ({summary['crack_rate_pct']}%). Force resets for all "
            "affected accounts.")
    if summary["storage_grade"] != "Good":
        recs.append("Re-hash all stored passwords with a salted, slow KDF "
                    "(PBKDF2 >= 200k iters, scrypt, bcrypt, or Argon2id).")
    recs.append("Enforce a minimum length of 12+ characters and screen new "
                "passwords against a common-password blocklist.")
    recs.append("Enable multi-factor authentication to reduce the impact of any "
                "single compromised password.")
    return recs
