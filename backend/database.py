"""SQLite persistence layer: schema + CRUD.

Privacy note: `strength_checks` stores only derived metrics (length, entropy,
score, verdict) -- never the plaintext password or its hash. Recovered
passwords in `audit_results` are SYNTHETIC test data only.
"""
from __future__ import annotations

import json
import os
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Any, Iterable, Optional

import config

SCHEMA = """
CREATE TABLE IF NOT EXISTS datasets (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT NOT NULL UNIQUE,
    description TEXT,
    source      TEXT,
    created_at  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS dataset_entries (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    dataset_id  INTEGER NOT NULL,
    username    TEXT NOT NULL,
    hash_value  TEXT NOT NULL,
    hash_algo   TEXT NOT NULL,
    salt        TEXT,
    is_salted   INTEGER NOT NULL DEFAULT 0,
    FOREIGN KEY (dataset_id) REFERENCES datasets(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS audit_runs (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    dataset_id    INTEGER NOT NULL,
    attack_type   TEXT NOT NULL,
    params_json   TEXT,
    total_hashes  INTEGER NOT NULL DEFAULT 0,
    cracked_count INTEGER NOT NULL DEFAULT 0,
    duration_sec  REAL NOT NULL DEFAULT 0,
    status        TEXT NOT NULL DEFAULT 'completed',
    started_at    TEXT NOT NULL,
    finished_at   TEXT,
    FOREIGN KEY (dataset_id) REFERENCES datasets(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS audit_results (
    id                 INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id             INTEGER NOT NULL,
    entry_id           INTEGER,
    username           TEXT,
    hash_algo          TEXT,
    cracked            INTEGER NOT NULL DEFAULT 0,
    recovered_password TEXT,
    method             TEXT,
    attempts           INTEGER NOT NULL DEFAULT 0,
    time_sec           REAL NOT NULL DEFAULT 0,
    risk_level         TEXT,
    FOREIGN KEY (run_id) REFERENCES audit_runs(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS strength_checks (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    checked_at      TEXT NOT NULL,
    length          INTEGER,
    entropy_bits    REAL,
    score           INTEGER,
    verdict         TEXT,
    crack_time_est  TEXT
);

CREATE TABLE IF NOT EXISTS hash_identifications (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    checked_at  TEXT NOT NULL,
    input_hash  TEXT,
    guesses_json TEXT
);
"""


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


@contextmanager
def connect(db_path: Optional[str] = None):
    """Context-managed connection with row factory and FK enforcement."""
    path = db_path or config.DB_PATH
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def init_db(db_path: Optional[str] = None) -> None:
    with connect(db_path) as conn:
        conn.executescript(SCHEMA)


def reset_db(db_path: Optional[str] = None) -> None:
    """Drop the file and recreate the schema (used by tests / reseeding)."""
    path = db_path or config.DB_PATH
    if os.path.exists(path):
        os.remove(path)
    init_db(path)


# --- Datasets --------------------------------------------------------------
def create_dataset(name: str, description: str = "", source: str = "synthetic",
                   db_path: Optional[str] = None) -> int:
    with connect(db_path) as conn:
        cur = conn.execute(
            "INSERT INTO datasets (name, description, source, created_at) "
            "VALUES (?,?,?,?)",
            (name, description, source, _utcnow()),
        )
        return int(cur.lastrowid)


def add_entries(dataset_id: int, entries: Iterable[dict],
                db_path: Optional[str] = None) -> int:
    rows = [
        (dataset_id, e["username"], e["hash_value"], e["hash_algo"],
         e.get("salt"), int(bool(e.get("is_salted", False))))
        for e in entries
    ]
    with connect(db_path) as conn:
        conn.executemany(
            "INSERT INTO dataset_entries "
            "(dataset_id, username, hash_value, hash_algo, salt, is_salted) "
            "VALUES (?,?,?,?,?,?)",
            rows,
        )
    return len(rows)


def list_datasets(db_path: Optional[str] = None) -> list[dict]:
    with connect(db_path) as conn:
        cur = conn.execute(
            "SELECT d.*, "
            "(SELECT COUNT(*) FROM dataset_entries e WHERE e.dataset_id=d.id) "
            "AS entry_count FROM datasets d ORDER BY d.id DESC")
        return [dict(r) for r in cur.fetchall()]


def get_dataset(dataset_id: int, db_path: Optional[str] = None) -> Optional[dict]:
    with connect(db_path) as conn:
        cur = conn.execute("SELECT * FROM datasets WHERE id=?", (dataset_id,))
        row = cur.fetchone()
        return dict(row) if row else None


def get_entries(dataset_id: int, db_path: Optional[str] = None) -> list[dict]:
    with connect(db_path) as conn:
        cur = conn.execute(
            "SELECT * FROM dataset_entries WHERE dataset_id=? ORDER BY id",
            (dataset_id,))
        return [dict(r) for r in cur.fetchall()]


def delete_dataset(dataset_id: int, db_path: Optional[str] = None) -> None:
    with connect(db_path) as conn:
        conn.execute("DELETE FROM datasets WHERE id=?", (dataset_id,))


# --- Audit runs ------------------------------------------------------------
def create_run(dataset_id: int, attack_type: str, params: dict,
               total_hashes: int, db_path: Optional[str] = None) -> int:
    with connect(db_path) as conn:
        cur = conn.execute(
            "INSERT INTO audit_runs "
            "(dataset_id, attack_type, params_json, total_hashes, status, started_at) "
            "VALUES (?,?,?,?, 'running', ?)",
            (dataset_id, attack_type, json.dumps(params), total_hashes, _utcnow()),
        )
        return int(cur.lastrowid)


def finish_run(run_id: int, cracked_count: int, duration_sec: float,
               status: str = "completed", db_path: Optional[str] = None) -> None:
    with connect(db_path) as conn:
        conn.execute(
            "UPDATE audit_runs SET cracked_count=?, duration_sec=?, status=?, "
            "finished_at=? WHERE id=?",
            (cracked_count, duration_sec, status, _utcnow(), run_id),
        )


def add_results(run_id: int, results: Iterable[dict],
                db_path: Optional[str] = None) -> int:
    rows = [
        (run_id, r.get("entry_id"), r.get("username"), r.get("hash_algo"),
         int(bool(r.get("cracked", False))), r.get("recovered_password"),
         r.get("method"), int(r.get("attempts", 0)), float(r.get("time_sec", 0)),
         r.get("risk_level"))
        for r in results
    ]
    with connect(db_path) as conn:
        conn.executemany(
            "INSERT INTO audit_results "
            "(run_id, entry_id, username, hash_algo, cracked, recovered_password, "
            "method, attempts, time_sec, risk_level) VALUES (?,?,?,?,?,?,?,?,?,?)",
            rows,
        )
    return len(rows)


def list_runs(db_path: Optional[str] = None) -> list[dict]:
    with connect(db_path) as conn:
        cur = conn.execute(
            "SELECT r.*, d.name AS dataset_name FROM audit_runs r "
            "JOIN datasets d ON d.id=r.dataset_id ORDER BY r.id DESC")
        return [dict(x) for x in cur.fetchall()]


def get_run(run_id: int, db_path: Optional[str] = None) -> Optional[dict]:
    with connect(db_path) as conn:
        cur = conn.execute(
            "SELECT r.*, d.name AS dataset_name FROM audit_runs r "
            "JOIN datasets d ON d.id=r.dataset_id WHERE r.id=?", (run_id,))
        row = cur.fetchone()
        return dict(row) if row else None


def get_results(run_id: int, db_path: Optional[str] = None) -> list[dict]:
    with connect(db_path) as conn:
        cur = conn.execute(
            "SELECT * FROM audit_results WHERE run_id=? ORDER BY id", (run_id,))
        return [dict(r) for r in cur.fetchall()]


# --- Lightweight history logs ---------------------------------------------
def log_strength_check(metrics: dict, db_path: Optional[str] = None) -> int:
    with connect(db_path) as conn:
        cur = conn.execute(
            "INSERT INTO strength_checks "
            "(checked_at, length, entropy_bits, score, verdict, crack_time_est) "
            "VALUES (?,?,?,?,?,?)",
            (_utcnow(), metrics.get("length"), metrics.get("entropy_bits"),
             metrics.get("score"), metrics.get("verdict"),
             metrics.get("crack_time_est")),
        )
        return int(cur.lastrowid)


def list_strength_checks(limit: int = 100, db_path: Optional[str] = None) -> list[dict]:
    with connect(db_path) as conn:
        cur = conn.execute(
            "SELECT * FROM strength_checks ORDER BY id DESC LIMIT ?", (limit,))
        return [dict(r) for r in cur.fetchall()]


def log_hash_identification(input_hash: str, guesses: Any,
                            db_path: Optional[str] = None) -> int:
    with connect(db_path) as conn:
        cur = conn.execute(
            "INSERT INTO hash_identifications (checked_at, input_hash, guesses_json) "
            "VALUES (?,?,?)",
            (_utcnow(), input_hash, json.dumps(guesses)),
        )
        return int(cur.lastrowid)
