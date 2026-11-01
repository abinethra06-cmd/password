# Password Security Auditing Tool

A practical, **authorized** password-security assessment application that helps
security teams, administrators and students identify weak passwords, evaluate
password vulnerabilities, and compare password-storage security — using
**traditional cybersecurity algorithms only (no AI/ML)**.

It implements three classic techniques — **dictionary**, **hybrid**, and
**rainbow-table (precomputed lookup)** attacks — against **synthetic test data
and locally-generated authorized hashes**, plus hash identification, password
verification, weak-password detection, rule-based strength evaluation, risk
classification, and downloadable audit reports (PDF / CSV / JSON).

> **Authorized use only.** This tool runs entirely offline on synthetic data.
> It performs no account access and collects no real credentials. Using
> password-recovery techniques against systems or data you are not explicitly
> authorized to test may be illegal. See [Ethics & Legal](#ethics--legal).

---

## Features

| Area | What it does |
|------|--------------|
| Dictionary attack | Hashes a wordlist and matches digests against target hashes (O(1) batch lookup for unsalted). |
| Hybrid attack | Mutates dictionary words (capitalisation, leetspeak, appended numbers/years/symbols). |
| Rainbow table | Precomputed `{digest: plaintext}` lookup table for instant unsalted recovery; shows salting defeats it. |
| Hash identification | Guesses algorithm by length / format / prefix (ranked candidates). |
| Password verification | Constant-time check of a candidate against a stored hash — no plaintext stored. |
| Weak-password detection | Flags common passwords, short length, low diversity, patterns. |
| Strength evaluation | Transparent rule-based + entropy score (0–100) with crack-time estimate. |
| Risk classification | Critical / High / Medium / Low per account + dataset rollup. |
| Audit reports | Downloadable PDF, CSV and JSON. |
| History | Past audit runs and (non-identifying) strength-check metrics. |

---

## System Architecture

```
Streamlit UI (app.py + pages/)        <- dashboard, run audit, attacks, tools, reports, history
        |
Backend package (backend/)            <- audit orchestrator + engines + analysis + reporting
  audit.py -> attacks/{dictionary,hybrid,rainbow} , strength , weak_detector , risk , reporting
  hashing.py / hash_identifier.py
        |
SQLite (backend/database.py) + data/  <- datasets, runs, results, history; wordlists & tables
```

Audit flow: **UI → `audit.run_audit(dataset_id, attack, params)` → load hashes
from SQLite → run engine(s) → classify risk → persist run + results → show
summary → `reporting` exports PDF/CSV/JSON.**

---

## Project Structure

```
Abi_password/
├── app.py                     # Streamlit home + authorized-use gate
├── config.py                  # paths, algorithms, thresholds, tunables
├── ui_helpers.py              # UI bootstrap, auth gate, shared helpers
├── requirements.txt
├── README.md
├── backend/
│   ├── database.py            # SQLite schema + CRUD
│   ├── hashing.py             # fast digests + salted PBKDF2/scrypt + verify
│   ├── hash_identifier.py     # identify hash type
│   ├── strength.py            # rule-based + entropy strength scoring
│   ├── weak_detector.py       # common/weak password detection
│   ├── risk.py                # risk classification + recommendations
│   ├── audit.py               # audit orchestrator
│   ├── reporting.py           # PDF / CSV / JSON reports
│   └── attacks/
│       ├── dictionary_attack.py
│       ├── hybrid_attack.py
│       └── rainbow_table.py
├── pages/                     # Streamlit multipage UI (1..7)
├── data/
│   ├── wordlists/             # generated common-password wordlist
│   ├── datasets/              # generated synthetic dataset CSVs
│   ├── rainbow/               # precomputed tables (runtime)
│   └── reports/               # generated reports (runtime)
├── scripts/generate_test_data.py   # builds wordlist + synthetic data, seeds DB
└── tests/                     # pytest suite (one file per module)
```

---

## Installation

Requires **Python 3.10+** (developed and tested on 3.14).

```bash
# from the project root
python -m pip install -r requirements.txt
```

> Compatibility note: Streamlit pulls in `numpy`/`pyarrow` (binary wheels). On a
> brand-new Python release these occasionally lag; if an install fails to build,
> use a Python version with available wheels (e.g. 3.12) or upgrade pip.

---

## Running the Application

```bash
# 1) generate synthetic wordlist + authorized test datasets and seed the DB
python scripts/generate_test_data.py

# 2) launch the dashboard
python -m streamlit run app.py
```

Then open the Local URL Streamlit prints (default http://localhost:8501),
tick the **authorized-use** acknowledgement on the Home page, and use the
sidebar to navigate. (You can also seed data from the Home page button.)

---

## How to Use

1. **Home** – accept the authorized-use notice; generate/reset synthetic data.
2. **Datasets** – create your own dataset to audit: upload a CSV of hashes, paste
   hashes (one per line, algorithm auto-detected), or type sample passwords that
   are hashed here. Also lists and deletes datasets.
2. **Run Audit** – pick a dataset and a technique (`dictionary`, `hybrid`,
   `rainbow`, or `all`), run it, and review recoveries, risk and recommendations.
3. **Attacks** – learn each technique and try it interactively; run the
   **salted-vs-unsalted** rainbow demonstration.
4. **Hash Tools** – identify a hash, verify a password (no storage), or generate
   hashes for building your own authorized test data.
5. **Password Strength** – evaluate a password (analysed in memory, not stored).
6. **Reports** – generate and download PDF / CSV / JSON for any run.
7. **History** – review past runs and strength-check metrics.

---

## Sample / Synthetic Data

`scripts/generate_test_data.py` creates fictional accounts in three tiers so each
technique shows distinct coverage, and stores them three ways:

- **Corp MD5 dump (unsalted)** and **Web app SHA-256 (unsalted)** — fast hashes.
- **Secure store PBKDF2 (salted)** — the same accounts stored securely.

Expected results (verifiable, not fabricated):

| Tier | Example | Dictionary | Hybrid | Rainbow (unsalted) | Salted |
|------|---------|:--:|:--:|:--:|:--:|
| weak (8) | `password`, `123456` | ✅ | ✅ | ✅ | time-budgeted |
| medium (6) | `Summer2021`, `p@$$w0rd` | ❌ | ✅ | ✅* | time-budgeted |
| strong (3) | `x9#Kq2@mZ!7vLp$R` | ❌ | ❌ | ❌ | ❌ |

\* rainbow recovers medium passwords only if the table is built *with variants*.
Against the salted dataset, dictionary/hybrid run under a wall-clock **time
budget** — demonstrating that salted, slow hashing makes batch guessing
impractical.

---

## Testing & Evaluation

Run the full suite (one test file per backend module):

```bash
python -m pytest -q
```

Covers: known hash vectors; dictionary cracks in-wordlist passwords only; hybrid
cracks mutated passwords a dictionary misses; rainbow lookup is correct **and
fails on salted** hashes; strength scores rise with complexity; risk
classification; and an end-to-end audit whose crack counts match the known
synthetic tiers (8 weak via dictionary, 14 via all, 3 strong resist).

End-to-end check:

```bash
python scripts/generate_test_data.py
python -m streamlit run app.py   # run an audit, confirm counts, download a PDF
```

---

## How Each Technique Works (and its Limits)

- **Dictionary** — hash each candidate once; O(1) match against a set of target
  digests. *Limit:* only finds passwords present in the wordlist.
- **Hybrid** — apply human mutation rules to dictionary words. *Limit:* only
  rule-expressible mutations; candidate space grows multiplicatively (a per-word
  cap trades coverage for speed).
- **Rainbow / lookup table** — precompute `{digest: plaintext}` for O(1)
  recovery. *Limit:* storage grows with coverage, it only covers precomputed
  passwords, and it is **defeated by salting**. This project uses a direct
  hash-lookup table (space-for-time), not reduction-chain rainbow tables — stated
  plainly in the UI and reports.
- **General** — tuned for clarity and demonstration at single-machine Python
  speed, not a GPU cracker.

---

## Secure Password-Handling Practices Demonstrated

- Salted, slow KDFs (PBKDF2-HMAC-SHA256, scrypt) with unique per-password salts.
- Constant-time verification (`hmac.compare_digest`).
- The strength checker and verifier never persist the plaintext; history stores
  only derived metrics (length, entropy, score, verdict).
- Recovered values in reports are **synthetic** and **redacted by default**.

---

## Ethics & Legal

This application is intended solely for **authorized** password-security
assessment and education, on synthetic data or systems you have explicit written
permission to test. Do not use these techniques against accounts, systems or data
you are not authorized to assess. The authors assume no liability for misuse.
