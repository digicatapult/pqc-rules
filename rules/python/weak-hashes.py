"""Test fixtures for pqc-semgrep-rules / Python / classically-broken hashes."""

import hashlib

from Crypto.Hash import MD5, SHA1


def vulnerable():
    # ---- MD5 ----
    # ruleid: pqc.python.md5
    hashlib.md5(b"x").hexdigest()
    # ruleid: pqc.python.md5
    hashlib.new("md5", b"x").hexdigest()
    # ruleid: pqc.python.md5
    MD5.new(b"x").hexdigest()

    # ---- SHA-1 ----
    # ruleid: pqc.python.sha1
    hashlib.sha1(b"y").hexdigest()
    # ruleid: pqc.python.sha1
    hashlib.new("sha1", b"y").hexdigest()
    # ruleid: pqc.python.sha1
    SHA1.new(b"y").hexdigest()


def safe():
    # ok: pqc.python.md5
    hashlib.sha256(b"safe").hexdigest()
    # ok: pqc.python.sha1
    hashlib.sha384(b"safe").hexdigest()
