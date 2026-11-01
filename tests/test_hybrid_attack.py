"""Hybrid attack: cracks mangled base-word passwords a dictionary would miss."""
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from backend import hashing
from backend.attacks import hybrid_attack as ha
from backend.attacks import dictionary_attack as da
from scripts import generate_test_data as gen


def setup_module(module):
    gen.build_wordlist()


def _t(i, user, pw, algo="md5"):
    return {"id": i, "username": user, "hash_value": hashing.compute(pw, algo),
            "hash_algo": algo, "salt": None, "is_salted": False}


def test_variants_cover_common_mangles():
    vs = set(ha.variants("summer"))
    assert "Summer2021" in vs       # capitalise + year
    assert "summer1" in vs or "Summer1" in vs
    vs2 = set(ha.variants("password"))
    assert "p@$$w0rd" in vs2        # full leet


def test_hybrid_cracks_mangled_passwords():
    targets = [
        _t(1, "ivan", "Summer2021"),
        _t(2, "judy", "welcome1"),
        _t(3, "mallory", "dragon!"),
        _t(4, "olivia", "p@$$w0rd"),
        _t(5, "rupert", "x9#Kq2@mZ!7vLp$R"),  # strong -> should NOT crack
    ]
    out = ha.run(targets)
    by = {r["username"]: r for r in out["results"]}
    assert by["ivan"]["cracked"] and by["ivan"]["recovered_password"] == "Summer2021"
    assert by["judy"]["cracked"] and by["judy"]["recovered_password"] == "welcome1"
    assert by["mallory"]["cracked"] and by["mallory"]["recovered_password"] == "dragon!"
    assert by["olivia"]["cracked"] and by["olivia"]["recovered_password"] == "p@$$w0rd"
    assert by["rupert"]["cracked"] is False


def test_dictionary_misses_what_hybrid_finds():
    # "Summer2021" is not in the wordlist -> plain dictionary fails
    t = [_t(1, "ivan", "Summer2021")]
    assert da.run(t)["cracked_count"] == 0
    assert ha.run(t)["cracked_count"] == 1
