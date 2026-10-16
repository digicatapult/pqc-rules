# Test fixtures

| File                      | Origin                                                                                                                                                                                                                                                                                |
| ------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `sample-app/`             | Hand-written sample code scanned to produce `semgrep.json` and `cryptoscan.json`.                                                                                                                                                                                                     |
| `semgrep.json`            | Real output: `semgrep scan --config rules --json` (Semgrep 1.180.0) over a copy of `sample-app/`; `time` and `paths` removed.                                                                                                                                                         |
| `cryptoscan.json`         | Real output: `cryptoscan scan sample-app --format json` (v1.4.0); absolute paths rewritten to repo-relative.                                                                                                                                                                          |
| `mapping-app/`            | Hand-written files that trigger the cryptoscan patterns the correlator maps by pattern id or splits: `TLS-001`, `TLS-002`, `PQC-FNDSA-001`, `PQC-XMSS-001`, `PQC-LMS-001` and two dependency findings. Renovate skips it, because `config:recommended` ignores `**/tests/**`.         |
| `cryptoscan-mapping.json` | Real output: `cryptoscan scan . --format json` (v1.4.0) run inside `mapping-app/`; absolute paths rewritten to relative and findings sorted by file, line and id.                                                                                                                     |
| `cryptoscan-key.json`     | Real output: `cryptoscan scan . --format json` (v1.4.0) over a scratch `config/` directory of header-only PEM files, one per header below; paths rewritten and findings sorted as above. Each file held only its `-----BEGIN ...-----` line, so the fixture contains no key material. |

Headers used for `cryptoscan-key.json`, with the pattern each one raises:

| File                               | Header                  | Patterns             |
| ---------------------------------- | ----------------------- | -------------------- |
| `config/rsa-private-key.key`       | `RSA PRIVATE KEY`       | `KEY-001`, `RSA-001` |
| `config/private-key.key`           | `PRIVATE KEY`           | `KEY-001`            |
| `config/ec-private-key.key`        | `EC PRIVATE KEY`        | `KEY-002`            |
| `config/dsa-private-key.key`       | `DSA PRIVATE KEY`       | `KEY-003`, `DSA-001` |
| `config/openssh-private-key.key`   | `OPENSSH PRIVATE KEY`   | `KEY-004`            |
| `config/pgp-private-key-block.key` | `PGP PRIVATE KEY BLOCK` | `KEY-005`            |
| `config/encrypted-private-key.key` | `ENCRYPTED PRIVATE KEY` | `KEY-006`            |

cryptoscan sets `algorithm` to null on every `KEY-00*` finding, which is why the correlator maps them by pattern id.
