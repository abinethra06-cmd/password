"""Rainbow table: O(1) recovery of unsalted hashes; salting defeats it."""
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from backend import hashing
from backend.attacks import rainbow_table as rt
from scripts import generate_test_data as gen


def setup_module(module):
    gen.build_wordlist()
    rt.build_table("md5", force=True)
    rt.build_table("sha256", force=True)


def _t(i, user, pw, algo="md5", salted=False):
    if salted:
        return {"id": i, "username": user, "hash_value": hashing.hash_pbkdf2(pw),
                "hash_algo": "pbkdf2_sha256", "salt": None, "is_salted": True}
    return {"id": i, "username": user, "hash_value": hashing.compute(pw, algo),
            "hash_algo": algo, "salt": None, "is_salted": False}


def test_lookup_recovers_wordlist_password():
    d = hashing.compute("dragon", "md5")
    assert rt.lookup(d, "md5") == "dragon"
    assert rt.lookup(hashing.compute("notinlist_x9", "md5"), "md5") is None


def test_run_cracks_unsalted_not_salted():
    targets = [
        _t(1, "alice", "password", "md5"),
        _t(2, "carol", "qwerty", "sha256"),
        _t(3, "secure", "password", salted=True),  # same pw, salted
    ]
    out = rt.run(targets)
    by = {r["username"]: r for r in out["results"]}
    assert by["alice"]["cracked"] and by["alice"]["recovered_password"] == "password"
    assert by["carol"]["cracked"] and by["carol"]["recovered_password"] == "qwerty"
    # salting defeats the precomputed table
    assert by["secure"]["cracked"] is False
    assert out["cracked_count"] == 2


def test_demonstrate_salting():
    demo = rt.demonstrate_salting("password", "md5")
    assert demo["unsalted"]["cracked"] is True
    assert demo["unsalted"]["recovered"] == "password"
    assert demo["salted"]["cracked"] is False
    # two independent salted hashes of same pw differ
    a = hashing.hash_pbkdf2("password")
    b = hashing.hash_pbkdf2("password")
    assert a != b
