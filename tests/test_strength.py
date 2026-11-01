"""Strength scoring, weak detection, and risk classification."""
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from backend import strength, weak_detector as wd, risk
from scripts import generate_test_data as gen


def setup_module(module):
    gen.build_wordlist()


def test_score_monotonic_with_complexity():
    common = wd.load_common_set()
    weak = strength.analyze("password", common_set=common, dictionary_set=common)
    medium = strength.analyze("Summer2021!", common_set=common, dictionary_set=common)
    strong = strength.analyze("x9#Kq2@mZ!7vLp$R", common_set=common, dictionary_set=common)
    assert weak["score"] < medium["score"] < strong["score"]
    assert weak["is_common"] is True
    assert weak["crack_time_est"].lower().startswith("instant")


def test_verdicts_and_privacy():
    common = wd.load_common_set()
    m = strength.analyze("correct horse battery staple 2026!", common_set=common,
                         dictionary_set=common)
    assert m["verdict"] in ("Strong", "Very Strong")
    # no plaintext leaks into the metrics dict
    assert "password" not in m
    assert all(not isinstance(v, str) or "staple" not in v for v in m.values()
               if not isinstance(v, list))


def test_weak_detector():
    assert wd.is_common("password") is True
    assert wd.is_common("x9#Kq2@mZ!7vLp$R") is False
    assert wd.is_weak("123456") is True
    assert wd.is_weak("x9#Kq2@mZ!7vLp$R") is False
    assert any("common" in r.lower() for r in wd.reasons("password"))


def test_risk_classification():
    assert risk.classify_account(True, "dictionary", False) == "Critical"
    assert risk.classify_account(True, "rainbow", False) == "Critical"
    assert risk.classify_account(True, "hybrid", False) == "High"
    assert risk.classify_account(False, None, False, strength_score=20) == "Medium"
    assert risk.classify_account(False, None, True, strength_score=90) == "Low"


def test_summary_flags_unsalted_storage():
    results = [
        {"cracked": True, "risk_level": "Critical", "hash_algo": "md5", "is_salted": False},
        {"cracked": False, "risk_level": "Low", "hash_algo": "md5", "is_salted": False},
    ]
    s = risk.summarize(results)
    assert s["storage_grade"] == "Poor"
    assert s["crack_rate_pct"] == 50.0
    assert s["overall_risk"] == "Critical"
    assert any("unsalted" in n for n in s["storage_notes"])
