"""End-to-end audit on seeded synthetic data -> verifiable crack counts."""
import os
import sys
import tempfile

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import config
from backend import database as db, audit
from scripts import generate_test_data as gen

DB = os.path.join(tempfile.gettempdir(), "test_audit.db")


def setup_module(module):
    gen.seed(db_path=DB)


def teardown_module(module):
    if os.path.exists(DB):
        os.remove(DB)


def _dataset_id(name_contains):
    for d in db.list_datasets(db_path=DB):
        if name_contains in d["name"]:
            return d["id"]
    raise AssertionError(f"dataset {name_contains} not found")


def test_dictionary_only_cracks_weak_tier():
    ds = _dataset_id("MD5")
    out = audit.run_audit(ds, "dictionary", db_path=DB)
    # 8 weak-tier accounts are in the wordlist
    assert out["summary"]["cracked_count"] == 8
    cracked_methods = {r["method"] for r in out["results"] if r["cracked"]}
    assert cracked_methods == {"dictionary"}


def test_all_attacks_crack_weak_and_medium_not_strong():
    ds = _dataset_id("MD5")
    out = audit.run_audit(ds, "all", db_path=DB)
    # 8 weak + 6 medium = 14 crackable; 3 strong resist
    assert out["summary"]["cracked_count"] == 14
    strong = [r for r in out["results"] if not r["cracked"]]
    assert len(strong) == 3
    assert out["summary"]["storage_grade"] == "Poor"
    assert out["summary"]["overall_risk"] == "Critical"


def test_salted_dataset_resists_rainbow():
    ds = _dataset_id("PBKDF2")
    out = audit.run_audit(ds, "rainbow", db_path=DB)
    # rainbow tables cannot touch salted hashes at all
    assert out["summary"]["cracked_count"] == 0
    assert out["summary"]["storage_grade"] == "Good"


def test_run_is_persisted():
    ds = _dataset_id("SHA-256")
    out = audit.run_audit(ds, "dictionary", db_path=DB)
    run = db.get_run(out["run_id"], db_path=DB)
    assert run is not None and run["status"] == "completed"
    assert len(db.get_results(out["run_id"], db_path=DB)) == 17
