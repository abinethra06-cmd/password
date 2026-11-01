"""Tests for backend.hashing against known vectors + round-trips."""
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from backend import hashing


# Known published digests for the empty string and "abc".
def test_known_md5_vectors():
    assert hashing.compute("", "md5") == "d41d8cd98f00b204e9800998ecf8427e"
    assert hashing.compute("abc", "md5") == "900150983cd24fb0d6963f7d28e17f72"


def test_known_sha1_sha256_vectors():
    assert hashing.compute("abc", "sha1") == "a9993e364706816aba3e25717850c26c9cd0d89d"
    assert hashing.compute("abc", "sha256") == (
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")


def test_unsupported_algo_raises():
    try:
        hashing.compute("x", "md4")
    except ValueError:
        return
    assert False, "expected ValueError for unsupported algo"


def test_verify_fast_digest():
    d = hashing.compute("hunter2", "sha256")
    assert hashing.verify("hunter2", d, "sha256") is True
    assert hashing.verify("wrong", d, "sha256") is False
    # algo inference by length also works
    assert hashing.verify("hunter2", d) is True


def test_pbkdf2_salted_unique_and_verifies():
    a = hashing.hash_pbkdf2("Password1")
    b = hashing.hash_pbkdf2("Password1")
    # Unique random salts -> different stored values for same password.
    assert a != b
    assert a.startswith("pbkdf2_sha256$")
    assert hashing.verify("Password1", a) is True
    assert hashing.verify("Password1", b) is True
    assert hashing.verify("nope", a) is False


def test_scrypt_salted_verifies():
    s = hashing.hash_scrypt("S3cretValue!")
    assert s.startswith("scrypt$")
    assert hashing.verify("S3cretValue!", s) is True
    assert hashing.verify("other", s) is False


def test_hash_identifier_lengths_and_prefixes():
    from backend import hash_identifier as hid
    assert hid.identify(hashing.compute("x", "md5"))[0]["name"] == "MD5"
    assert hid.identify(hashing.compute("x", "sha1"))[0]["name"] == "SHA-1"
    assert hid.identify(hashing.compute("x", "sha256"))[0]["name"] == "SHA-256"
    assert hid.identify(hashing.compute("x", "sha512"))[0]["name"] == "SHA-512"
    assert hid.identify(hashing.hash_pbkdf2("x"))[0]["name"].startswith("PBKDF2")
    assert hid.is_salted_format(hashing.hash_pbkdf2("x")) is True
    assert hid.is_salted_format(hashing.compute("x", "md5")) is False
