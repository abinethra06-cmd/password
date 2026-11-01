"""Rule-based + entropy password-strength evaluation.

No AI/ML: scoring is a transparent, defensible rubric over length, character-
class diversity, estimated entropy, and penalties for known weak patterns
(common passwords, dictionary words, sequences, repeats, date-like strings).

Privacy: `analyze()` works in memory and returns only derived METRICS. The
plaintext is never returned, logged, or stored by this module.
"""
from __future__ import annotations

import math
import re
from typing import Optional

import config

_LOWER = set("abcdefghijklmnopqrstuvwxyz")
_UPPER = set("ABCDEFGHIJKLMNOPQRSTUVWXYZ")
_DIGITS = set("0123456789")

_SEQUENCES = [
    "abcdefghijklmnopqrstuvwxyz",
    "0123456789",
    "qwertyuiop", "asdfghjkl", "zxcvbnm",
]


def _charset_size(pw: str) -> int:
    size = 0
    if any(c in _LOWER for c in pw):
        size += 26
    if any(c in _UPPER for c in pw):
        size += 26
    if any(c in _DIGITS for c in pw):
        size += 10
    if any((c not in _LOWER and c not in _UPPER and c not in _DIGITS) for c in pw):
        size += 33  # printable ASCII symbols/space
    return max(size, 1)


def _classes_present(pw: str) -> int:
    return sum([
        any(c in _LOWER for c in pw),
        any(c in _UPPER for c in pw),
        any(c in _DIGITS for c in pw),
        any((c not in _LOWER and c not in _UPPER and c not in _DIGITS) for c in pw),
    ])


def _has_sequence(pw: str, run: int = 3) -> bool:
    low = pw.lower()
    for seq in _SEQUENCES:
        for i in range(len(seq) - run + 1):
            chunk = seq[i:i + run]
            if chunk in low or chunk[::-1] in low:
                return True
    return False


def _has_repeat(pw: str, run: int = 3) -> bool:
    return re.search(r"(.)\1{" + str(run - 1) + r",}", pw) is not None


def _looks_like_year_or_date(pw: str) -> bool:
    return bool(re.fullmatch(r"\D*(19|20)\d{2}\D*", pw)) or \
        bool(re.fullmatch(r"\d{6,8}", pw))


def format_duration(seconds: float) -> str:
    if seconds < 1:
        return "< 1 second"
    units = [("year", 31536000), ("day", 86400), ("hour", 3600),
             ("minute", 60), ("second", 1)]
    for name, size in units:
        if seconds >= size:
            val = seconds / size
            if val >= 1e9:
                return f"{val/1e9:.1f} billion {name}s"
            if val >= 1e6:
                return f"{val/1e6:.1f} million {name}s"
            if val >= 1e3:
                return f"{val/1e3:.1f} thousand {name}s"
            return f"{val:.1f} {name}" + ("s" if val >= 2 else "")
    return "< 1 second"


def _crack_time_seconds(pw: str, charset: int) -> float:
    # Average case = half the keyspace, at the assumed offline guess rate.
    try:
        keyspace = charset ** len(pw)
    except OverflowError:
        return float("inf")
    return (keyspace / 2) / config.ASSUMED_GUESS_RATE


def _verdict(score: int) -> str:
    verdict = config.STRENGTH_VERDICTS[0][1]
    for threshold, label in config.STRENGTH_VERDICTS:
        if score >= threshold:
            verdict = label
    return verdict


def analyze(password: str, common_set: Optional[set] = None,
            dictionary_set: Optional[set] = None) -> dict:
    """Return strength METRICS for `password` (no plaintext in the result)."""
    pw = password or ""
    length = len(pw)
    classes = _classes_present(pw)
    charset = _charset_size(pw)
    entropy_bits = round(length * math.log2(charset), 2) if length else 0.0

    low = pw.lower()
    is_common = bool(common_set) and low in common_set
    is_dict_word = bool(dictionary_set) and low in dictionary_set
    contains_dict = False
    if dictionary_set and not is_dict_word and length >= 4:
        contains_dict = any(w in low for w in dictionary_set if len(w) >= 4)

    has_seq = _has_sequence(pw)
    has_rep = _has_repeat(pw)
    date_like = _looks_like_year_or_date(pw)

    # --- base score ------------------------------------------------------
    raw = 0.0
    raw += min(length, 20) / 20 * 40          # length -> up to 40
    raw += classes / 4 * 25                   # diversity -> up to 25
    raw += min(entropy_bits, 80) / 80 * 35    # entropy -> up to 35

    # --- penalties -------------------------------------------------------
    feedback = []
    penalty = 0
    if is_common:
        penalty += 60
        feedback.append("This is a well-known common password.")
    if is_dict_word:
        penalty += 30
        feedback.append("The whole password is a dictionary word.")
    elif contains_dict:
        penalty += 15
        feedback.append("Contains a dictionary word as its base.")
    if has_seq:
        penalty += 15
        feedback.append("Contains a sequential run (e.g. abc, 123, qwerty).")
    if has_rep:
        penalty += 10
        feedback.append("Contains a repeated-character run.")
    if classes <= 1:
        penalty += 15
        feedback.append("Uses only one character type.")
    if date_like:
        penalty += 10
        feedback.append("Looks like a year or date.")
    if length < 8:
        penalty += 20
        feedback.append("Shorter than 8 characters.")
    elif length < config.MIN_REASONABLE_LENGTH:
        penalty += 10
        feedback.append(f"Shorter than {config.MIN_REASONABLE_LENGTH} characters.")

    score = int(max(0, min(100, round(raw - penalty))))

    # Crack-time: known-weak passwords fall instantly regardless of entropy.
    if is_common or is_dict_word:
        crack_seconds = 0.0
        crack_est = "Instant (known weak password)"
    else:
        crack_seconds = _crack_time_seconds(pw, charset)
        crack_est = ("centuries+" if crack_seconds == float("inf")
                     else format_duration(crack_seconds))

    if not feedback:
        feedback.append("Good: long with mixed character types and no obvious patterns.")

    return {
        "length": length,
        "classes_present": classes,
        "charset_size": charset,
        "entropy_bits": entropy_bits,
        "score": score,
        "verdict": _verdict(score),
        "is_common": is_common,
        "is_dictionary_word": is_dict_word,
        "has_sequence": has_seq,
        "has_repeat": has_rep,
        "crack_seconds": crack_seconds,
        "crack_time_est": crack_est,
        "feedback": feedback,
    }
