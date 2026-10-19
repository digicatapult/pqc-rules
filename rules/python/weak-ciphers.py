"""Test fixtures for pqc-semgrep-rules / Python / classically-broken ciphers."""

from Crypto.Cipher import AES, ARC4, DES, DES3


def vulnerable():
    # ruleid: pqc.python.des
    DES.new(b"8bytekey", DES.MODE_ECB)

    # ruleid: pqc.python.3des
    DES3.new(b"24bytekeyforthis________", DES3.MODE_ECB)

    # ruleid: pqc.python.rc4
    ARC4.new(b"key")


def safe():
    # ok: pqc.python.des
    AES.new(b"32bytekeyforaesgcm______________", AES.MODE_GCM)
