"""Dictionary attack: cracks weak (in-wordlist) passwords, misses others."""
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import config
from backend import hashing
from backend.attacks import dictionary_attack as da
from scripts import generate_test_data as gen


def setup_module(module):
    gen.build_wordlist()  # ensure wordlist exists


def _target(i, username, pw, algo="md5", salted=False):
    if salted:
        return {"id": i, "username": username, "hash_value": hashing.hash_pbkdf2(pw),
                "hash_algo": "pbkdf2_sha256", "salt": None, "is_salted": True}
    return {"id": i, "username": username, "hash_value": hashing.compute(pw, algo),
            "hash_algo": algo, "salt": None, "is_salted": False}


def test_cracks_wordlist_passwords_unsalted():
    targets = [
        _target(1, "alice", "password"),       # in wordlist
        _target(2, "bob", "dragon"),           # in wordlist
        _target(3, "carol", "Zx9#notlisted"),  # not in wordlist
    ]
    out = da.run(targets)
    by_user = {r["username"]: r for r in out["results"]}
    assert by_user["alice"]["cracked"] and by_user["alice"]["recovered_password"] == "password"
    assert by_user["bob"]["cracked"] and by_user["bob"]["recovered_password"] == "dragon"
    assert by_user["carol"]["cracked"] is False
    assert out["cracked_count"] == 2


def test_single_pass_batch_attempts_reasonable():
    # 3 unsalted md5 targets -> one pass over the wordlist hashing each word once
    n = da.count_words(config.DEFAULT_WORDLIST)
    targets = [_target(1, "a", "password"), _target(2, "b", "qwerty")]
    out = da.run(targets)
    # attempts == words hashed (one algo) == wordlist length
    assert out["attempts"] == n


def test_salted_still_cracks_weak_but_via_verify():
    targets = [_target(1, "alice", "password", salted=True)]
    out = da.run(targets)
    assert out["results"][0]["cracked"] is True
    assert out["results"][0]["recovered_password"] == "password"
