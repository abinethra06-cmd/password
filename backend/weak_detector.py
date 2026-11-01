"""Weak / common password detection.

Flags passwords that are common, too short, low-diversity, or built from
obvious patterns. Backed by the shipped wordlist (loaded once, cached).
"""
from __future__ import annotations

import os
from functools import lru_cache
from typing import Optional

import config
from backend import strength


@lru_cache(maxsize=4)
def load_common_set(path: Optional[str] = None) -> frozenset:
    path = path or config.DEFAULT_WORDLIST
    if not os.path.exists(path):
        return frozenset()
    with open(path, "r", encoding="utf-8", errors="ignore") as fh:
        return frozenset(line.strip().lower() for line in fh if line.strip())


def is_common(password: str, path: Optional[str] = None) -> bool:
    return (password or "").lower() in load_common_set(path)


def reasons(password: str, path: Optional[str] = None) -> list[str]:
    """Human-readable list of why a password is (or isn't) weak."""
    common = load_common_set(path)
    m = strength.analyze(password, common_set=common, dictionary_set=common)
    out = []
    if m["is_common"]:
        out.append("Appears in the common-password list.")
    if m["length"] < config.MIN_REASONABLE_LENGTH:
        out.append(f"Under {config.MIN_REASONABLE_LENGTH} characters.")
    if m["classes_present"] <= 2:
        out.append("Limited character-type diversity.")
    if m["has_sequence"]:
        out.append("Contains a sequential pattern.")
    if m["has_repeat"]:
        out.append("Contains repeated characters.")
    return out


def is_weak(password: str, path: Optional[str] = None,
            score_threshold: int = 50) -> bool:
    common = load_common_set(path)
    m = strength.analyze(password, common_set=common, dictionary_set=common)
    return m["is_common"] or m["score"] < score_threshold
