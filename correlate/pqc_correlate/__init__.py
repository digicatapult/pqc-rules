"""Second-pass correlator for post-quantum cryptography scan results.

Normalises findings from cryptoscan, Semgrep (pqc-rules), CodeQL and
tls-analyzer into one record shape, groups findings that independent sources
agree on, and emits a minimal SARIF containing only the most credible results.
"""

__version__ = "0.1.0"
