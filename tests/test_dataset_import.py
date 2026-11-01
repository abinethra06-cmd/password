"""Dataset import: detection, parsing, and auditability of imported data."""
import os
import sys
import tempfile

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from backend import dataset_import as di, database as db, hashing, audit
from scripts import generate_test_data as gen

DB = os.path.join(tempfile.gettempdir(), "test_import.db")


def setup_module(module):
    gen.build_wordlist()
    db.reset_db(DB)


def teardown_module(module):
    if os.path.exists(DB):
        os.remove(DB)


def test_detect_algorithms():
    assert di.detect(hashing.compute("x", "md5")) == ("md5", False)
    assert di.detect(hashing.compute("x", "sha256")) == ("sha256", False)
    assert di.detect(hashing.hash_pbkdf2("x")) == ("pbkdf2_sha256", True)
    assert di.detect("not-a-hash!") == (None, False)


def test_rows_from_hashes_autodetect():
    text = (f"alice:{hashing.compute('password', 'md5')}\n"
            f"{hashing.compute('dragon', 'md5')}\n"
            "# a comment line\n")
    rows, errors = di.rows_from_hashes(text, algo="auto")
    assert not errors
    assert len(rows) == 2
    assert rows[0]["username"] == "alice" and rows[0]["hash_algo"] == "md5"
    assert rows[1]["username"] == "user2"


def test_rows_from_plaintext_roundtrip():
    rows, errors = di.rows_from_plaintext("bob,hunter2\nqwerty\n", algo="sha256")
    assert not errors and len(rows) == 2
    assert rows[0]["hash_value"] == hashing.compute("hunter2", "sha256")
    assert rows[0]["is_salted"] is False
    salted, _ = di.rows_from_plaintext("carol:secret", algo="pbkdf2_sha256")
    assert salted[0]["is_salted"] is True
    assert hashing.verify("secret", salted[0]["hash_value"])


def test_rows_from_csv():
    csv_text = ("username,hash_value,hash_algo\n"
                f"alice,{hashing.compute('password','md5')},md5\n"
                f"bob,{hashing.compute('letmein','sha256')},\n")  # algo auto
    rows, errors = di.rows_from_csv(csv_text)
    assert not errors and len(rows) == 2
    assert rows[1]["hash_algo"] == "sha256"


def test_create_and_audit_imported_dataset():
    text = "\n".join(hashing.compute(p, "md5")
                     for p in ["password", "dragon", "Zz9_not_in_list"])
    rows, _ = di.rows_from_hashes(text, algo="auto")
    did = di.create_dataset("my import", "pasted md5s", rows, db_path=DB)
    out = audit.run_audit(did, "dictionary", db_path=DB)
    assert out["summary"]["cracked_count"] == 2   # password + dragon

    # duplicate name rejected
    try:
        di.create_dataset("my import", "", rows, db_path=DB)
        assert False, "expected duplicate-name error"
    except ValueError:
        pass
