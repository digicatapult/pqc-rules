"""Test fixtures for pqc-semgrep-rules / Python / Shor-broken cryptography."""

from cryptography.hazmat.primitives.asymmetric import dh, dsa, ec, rsa
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from Crypto.PublicKey import DSA, ECC, RSA  # pycryptodome


def vulnerable():
    # ---- RSA ----
    # ruleid: pqc.python.rsa
    rsa.generate_private_key(public_exponent=65537, key_size=2048)
    # ruleid: pqc.python.rsa
    RSA.generate(2048)
    # ruleid: pqc.python.rsa
    RSA.import_key(b"...")
    # ruleid: pqc.python.rsa
    RSA.construct((1, 2))

    # ---- EC (ECDSA / ECDH) ----
    # ruleid: pqc.python.ec
    ec.generate_private_key(ec.SECP256R1())
    # ruleid: pqc.python.ec
    ECC.generate(curve="P-256")

    # ---- DSA ----
    # ruleid: pqc.python.dsa
    dsa.generate_private_key(key_size=2048)
    # ruleid: pqc.python.dsa
    DSA.generate(2048)

    # ---- DH ----
    # ruleid: pqc.python.dh
    dh.generate_parameters(generator=2, key_size=2048)

    # ---- X25519 ----
    # ruleid: pqc.python.x25519
    X25519PrivateKey.generate()

    # ---- Ed25519 ----
    # ruleid: pqc.python.ed25519
    Ed25519PrivateKey.generate()


def safe():
    """These calls should NOT match any rule in this file."""
    import hashlib
    import os

    # ok: pqc.python.rsa
    token = os.urandom(32)
    # ok: pqc.python.ec
    digest = hashlib.sha256(token).hexdigest()
