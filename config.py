"""Central configuration: paths, algorithm lists, thresholds, constants.

Pure stdlib. Imported by every backend module so paths and tunables live in
one place.
"""
from __future__ import annotations

import os

# --- Paths -----------------------------------------------------------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data")
WORDLIST_DIR = os.path.join(DATA_DIR, "wordlists")
DATASET_DIR = os.path.join(DATA_DIR, "datasets")
RAINBOW_DIR = os.path.join(DATA_DIR, "rainbow")
REPORT_DIR = os.path.join(DATA_DIR, "reports")
DB_PATH = os.path.join(BASE_DIR, "auditor.db")
DEFAULT_WORDLIST = os.path.join(WORDLIST_DIR, "common_passwords.txt")

for _d in (DATA_DIR, WORDLIST_DIR, DATASET_DIR, RAINBOW_DIR, REPORT_DIR):
    os.makedirs(_d, exist_ok=True)

# --- Hash algorithms -------------------------------------------------------
# Fast, unsalted algorithms that the attacks target (and that make passwords
# recoverable). These are intentionally weak for password storage.
FAST_ALGOS = ["md5", "sha1", "sha224", "sha256", "sha384", "sha512"]

# Salted / slow KDFs used to demonstrate SECURE password storage.
SECURE_ALGOS = ["pbkdf2_sha256", "scrypt"]

# Default iteration/cost parameters for the secure KDFs.
PBKDF2_ITERATIONS = 200_000
SCRYPT_N = 2 ** 14
SCRYPT_R = 8
SCRYPT_P = 1
SALT_BYTES = 16

# --- Hybrid attack tuning --------------------------------------------------
HYBRID_MAX_VARIANTS_PER_WORD = 400      # cap to bound combinatorial blow-up
HYBRID_YEARS = list(range(1990, 2031))
HYBRID_SUFFIX_NUMBERS = [str(n) for n in range(0, 100)] + ["123", "1234", "12345"]
HYBRID_SUFFIX_SYMBOLS = ["!", "@", "#", "$", "!!", "!@#", ".", "*"]
LEET_MAP = {"a": "@", "e": "3", "i": "1", "o": "0", "s": "$", "t": "7"}

# --- Strength evaluation ---------------------------------------------------
# Assumed offline guessing rate (guesses/sec) for a single commodity machine
# against a fast unsalted hash. Used only to ESTIMATE crack time for reporting.
ASSUMED_GUESS_RATE = 1_000_000_000      # 1e9/s (illustrative, documented)
MIN_REASONABLE_LENGTH = 12

STRENGTH_VERDICTS = [
    (0, "Very Weak"),
    (30, "Weak"),
    (50, "Fair"),
    (70, "Strong"),
    (90, "Very Strong"),
]

# --- Risk classification ---------------------------------------------------
RISK_LEVELS = ["Critical", "High", "Medium", "Low"]
RISK_ORDER = {lvl: i for i, lvl in enumerate(RISK_LEVELS)}
RISK_COLORS = {
    "Critical": "#b00020",
    "High": "#e65100",
    "Medium": "#f9a825",
    "Low": "#2e7d32",
}

APP_TITLE = "Password Security Auditing Tool"
APP_TAGLINE = "Authorized password-strength assessment & storage-security analysis"
