"""Algorithm family vocabulary shared by every source.

Each tool names algorithms differently ("ECC", "ECDSA", "secp256r1",
"Use of algorithm RSA"). Matching across tools only works once every name is
reduced to one family label, so this module is the single place that mapping
lives.
"""

from __future__ import annotations

import re

RISK_ORDER = ("broken", "vulnerable", "partial", "hybrid", "safe", "unknown")

# Coarse buckets used to decide whether sources *disagree*. "broken" and
# "vulnerable" both mean "needs migrating", so they must not count as conflict.
COARSE_RISK = {
    "broken": "at-risk",
    "vulnerable": "at-risk",
    "partial": "partial",
    "hybrid": "ok",
    "safe": "ok",
    "unknown": "unknown",
}

# Family -> default risk when a source does not state one.
DEFAULT_RISK = {
    "RSA": "vulnerable",
    "ECC": "vulnerable",
    "DSA": "vulnerable",
    "DH": "vulnerable",
    "DES": "broken",
    "3DES": "broken",
    "RC4": "broken",
    "MD5": "broken",
    "SHA-1": "broken",
    "TLS-legacy": "broken",
    "AES": "partial",
    "SHA-2": "partial",
    "SHA-3": "safe",
    "ChaCha20": "partial",
    "ML-KEM": "safe",
    "ML-DSA": "safe",
    "SLH-DSA": "safe",
    "FN-DSA": "safe",
    "XMSS": "safe",
    "LMS": "safe",
    # A committed private key whose algorithm the source cannot tell (PKCS#8, OpenSSH, PGP).
    "private-key": "vulnerable",
}

# Families that are the same thing for matching purposes.
_MATCH_KEY = {family: "PQ-SIG" for family in ("ML-DSA", "SLH-DSA", "FN-DSA", "XMSS", "LMS")}

# Ordered: the first pattern that matches wins, so specific names come first.
# Post-quantum signature names precede DSA, which they all contain, and SHA-2 digest
# sizes precede SHA-3, because "SHA384" contains "SHA3".
_ALIASES: tuple[tuple[str, str], ...] = (
    (r"X25519\s*MLKEM|MLKEM|ML-KEM|KYBER|HYBRID-KEM", "ML-KEM"),
    (r"SLH-DSA|SPHINCS", "SLH-DSA"),
    (r"ML-DSA|DILITHIUM|COMPOSITE-SIGNATURE", "ML-DSA"),
    (r"FN-?DSA|FALCON", "FN-DSA"),
    (r"XMSS", "XMSS"),
    (r"\bLMS\b|HSS[-_]?LMS|LEIGHTON", "LMS"),
    (r"3DES|TRIPLE-?DES|DESEDE|DES3|DES-EDE", "3DES"),
    (r"\bDES\b|^DES", "DES"),
    (r"RC4|ARC4|ARCFOUR", "RC4"),
    (r"MD5", "MD5"),
    (r"SHA-?1(?!\d)", "SHA-1"),
    (r"SHA-?2(?!\d)|SHA-?(224|256|384|512)(?!\d)", "SHA-2"),
    (r"SHA-?3(?!\d)|SHAKE", "SHA-3"),
    (r"ECDSA|ECDHE?|ECIES|ED25519|ED448|X25519|X448|(?<![A-Z])ECC?(?![A-Z0-9])|SECP|PRIME256|BRAINPOOL"
     r"|P-?(256|384|521)(?!\d)", "ECC"),
    (r"\bDSA\b|^DSA|SSH-DSS", "DSA"),
    (r"DIFFIE|\bDHE?\b|^DH|FFDHE", "DH"),
    (r"RSA|^RS(256|384|512)$|^PS(256|384|512)$", "RSA"),
    (r"AES", "AES"),
    (r"CHACHA", "ChaCha20"),
    (r"TLS-?LEGACY|TLSV1(\.|_)?[01]?$|SSLV[23]", "TLS-legacy"),
)
_COMPILED = tuple((re.compile(p, re.IGNORECASE), fam) for p, fam in _ALIASES)


def normalise_family(name: str | None) -> str | None:
    """Return the canonical family for an algorithm name, or None if unknown."""
    if not name:
        return None
    text = name.strip()
    if text in DEFAULT_RISK:
        return text
    for pattern, family in _COMPILED:
        if pattern.search(text):
            return family
    return None


def match_key(family: str) -> str:
    """Return the key used to decide whether two families are 'the same'."""
    return _MATCH_KEY.get(family, family)


def normalise_risk(value: str | None, family: str | None) -> str:
    """Map a source's risk label onto RISK_ORDER, falling back to the family default."""
    if value:
        lowered = value.strip().lower()
        if lowered in RISK_ORDER:
            return lowered
    if family:
        return DEFAULT_RISK.get(family, "unknown")
    return "unknown"
