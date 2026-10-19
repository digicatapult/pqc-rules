from __future__ import annotations

import pytest

from pqc_correlate.families import DEFAULT_RISK, match_key, normalise_family


@pytest.mark.parametrize(
    ("name", "family"),
    [
        ("RSA", "RSA"), ("RS256", "RSA"), ("PS384", "RSA"),
        ("ECC", "ECC"), ("EC", "ECC"), ("ECDSA", "ECC"), ("ECDH", "ECC"), ("SECP256R1", "ECC"),
        ("P-256", "ECC"), ("Ed25519", "ECC"), ("X25519", "ECC"),
        ("DSA", "DSA"), ("DH", "DH"), ("FFDHE2048", "DH"),
        ("MD5", "MD5"), ("SHA-1", "SHA-1"), ("SHA1", "SHA-1"),
        ("SHA256", "SHA-2"), ("SHA-256", "SHA-2"), ("SHA384", "SHA-2"), ("SHA-384", "SHA-2"),
        ("SHA512", "SHA-2"), ("SHA-512/256", "SHA-2"),
        ("SHA3-256", "SHA-3"), ("SHA-3", "SHA-3"), ("SHAKE256", "SHA-3"),
        ("AES-GCM", "AES"), ("ChaCha20", "ChaCha20"), ("3DES", "3DES"), ("DESede", "3DES"), ("DES", "DES"),
        ("RC4", "RC4"), ("TLSv1.1", "TLS-legacy"), ("SSLv3", "TLS-legacy"),
        ("Hybrid-KEM", "ML-KEM"), ("X25519MLKEM768", "ML-KEM"), ("ML-KEM", "ML-KEM"),
        ("ML-DSA", "ML-DSA"), ("SLH-DSA", "SLH-DSA"),
        # Names cryptoscan 1.4.0 emits in `algorithm` for its post-quantum signature patterns.
        ("FN-DSA", "FN-DSA"), ("Falcon-512", "FN-DSA"), ("XMSS", "XMSS"), ("LMS", "LMS"),
        # Not algorithm families on their own.
        ("ECB", None), ("TLS", None), ("SHA", None), ("bcrypt", None), ("", None), (None, None),
    ],
)
def test_normalise_family(name: str | None, family: str | None) -> None:
    assert normalise_family(name) == family


@pytest.mark.parametrize("family", sorted(DEFAULT_RISK))
def test_every_family_maps_to_itself(family: str) -> None:
    assert normalise_family(family) == family


def test_post_quantum_signatures_match_each_other_not_dsa() -> None:
    assert {match_key(f) for f in ("ML-DSA", "SLH-DSA", "FN-DSA", "XMSS", "LMS")} == {"PQ-SIG"}
    assert match_key("DSA") == "DSA"
