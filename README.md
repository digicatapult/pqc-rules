# pqc-rules

Few official, publicly available Semgrep rules exist at the time of writing to scan for weak or vulnerable post-quantum cryptography patterns. So, this repository has two functions, (1) to create a suitable PQC ruleset for Semgrep and fill that gap, and then (2) to correlate results against other PQC tooling available today, whether production-ready or merely experimental, in the hope that the aggregation from many tools will better serve on-going and future migrations to quantum-safe algorithms.

This Semgrep ruleset is consumed by Digital Catapult's `scan-post-quantum-cryptography.yml` shared workflow in [digicatapult/shared-workflows](https://github.com/digicatapult/shared-workflows), which checks this repository out as a pinned commit SHA.

## Contents

| Path                       | Purpose                                                                                                  |
| -------------------------- | -------------------------------------------------------------------------------------------------------- |
| `rules/`                   | Semgrep rules for JavaScript/TypeScript, Python, Go and Java, each with a test fixture of the same name. |
| `correlate/pqc_correlate/` | Correlator. Python standard library only, no runtime dependencies.                                       |
| `correlate/tests/`         | pytest suite and fixtures (see `fixtures/README.md` for which are real tool output).                     |

## Rules

Every rule carries three metadata keys the correlator relies on:

| Key            | Values                                                                                            |
| -------------- | ------------------------------------------------------------------------------------------------- |
| `pqc-category` | `shor-broken`, `classically-broken`, `pqc-safe`, `pqc-hybrid`                                     |
| `pqc-family`   | `RSA`, `ECC`, `DSA`, `DH`, `DES`, `3DES`, `RC4`, `MD5`, `SHA-1`, `TLS-legacy`, `ML-KEM`, `ML-DSA` |
| `pqc-risk`     | `broken`, `vulnerable`, `hybrid`, `safe`                                                          |

Coverage beyond the upstream fork:

- **JWT**: `jsonwebtoken`, `jose` and PyJWT signing with `RS*`/`PS*` (RSA) or `ES*`/`EdDSA` (ECC).
- **WebCrypto**: `subtle.generateKey`/`importKey` with RSA or EC algorithms.
- **node-forge**: RSA key handling, MD5, SHA-1.
- **TLS configuration**: legacy minimum versions (Node, Python, Go), classical-only key-exchange groups, and hybrid `X25519MLKEM768` groups.
- **Post-quantum**: ML-KEM / ML-DSA / SLH-DSA via `@noble/post-quantum`, Node's `crypto` (`ml-kem-*`, `ml-dsa-*`), liboqs (Python) and Go's `crypto/mlkem` / circl. Reported at `INFO` so a scan can show crypto that is already safe, not only crypto that is not.

## Correlator

```sh
PYTHONPATH=correlate python -m pqc_correlate \
  --root . --out pqc-out \
  --semgrep semgrep.json --cryptoscan cryptoscan.json \
  [--codeql codeql.sarif] [--tls tls.json] \
  [--window 3] [--allowlist-extra 'semgrep:pqc.javascript.jwt-*'] [--allowlist-disable] \
  [--runtime-anchor docker-compose.yml] [--expected semgrep,cryptoscan,codeql,tls-analyzer]
```

Semgrep, cryptoscan, and the tls-analyzer all use JSON; CodeQL uses SARIF. Each flag can be repeated.

Every finding is reduced to `{source, file, line, family, risk}`. Findings in the same file, of the same family, within `--window` lines of each other form a group, and each group gets one evidence level:

| Evidence        | Meaning                                                                              |
| --------------- | ------------------------------------------------------------------------------------ |
| `corroborated`  | Two or more independent sources agree.                                               |
| `single-source` | Only one source saw it.                                                              |
| `conflicting`   | Sources agree on location and family but disagree on risk (e.g. safe vs vulnerable). |
| `runtime`       | Observed on a running localhost service by tls-analyzer.                             |

### GitHub Code Scanning

Correlation is a necessary guard against overly noisy outputs and situations where tools have markedly different signal-to-noise ratios. A lot of noise reaching GitHub's Advanced Security interface for a repository is unnecessary, and adds a real cost in time spent shifting through false positives and re-assessing for false negatives later. `pqc-security.sarif` contains only groups that are **quantum-vulnerable or classically broken**, **not conflicting**, and either:

- `corroborated` (SARIF level `warning`), or
- allowlisted single-source facts (SARIF level `note`). The default allowlist is:
  - `cryptoscan:KEY-00*`: private keys committed to the repository
  - `tls-analyzer:tls.certificate-key`, `tls-analyzer:tls.negotiated-key-exchange`, `tls-analyzer:tls.legacy-protocol`

`--allowlist-extra` adds `SOURCE:RULE_ID` globs. `--allowlist-disable` removes the defaults, so only corroborated findings are reported. Partial-risk (e.g. AES-128, SHA-256), safe and hybrid findings are never uploaded, but they are always kept in the artefacts.

### Outputs

| File                 | Contents                                                                                 |
| -------------------- | ---------------------------------------------------------------------------------------- |
| `pqc-all.json`       | Every group, with evidence level, sources and the original findings.                     |
| `pqc-cbom.cdx.json`  | CycloneDX 1.6 CBOM, one `cryptographic-asset` per algorithm family.                      |
| `pqc-security.sarif` | Reportable groups only (see above).                                                      |
| `pqc-summary.md`     | Step summary: counts by evidence level, sources expected but not run, reported findings. |

Exit codes: `0` success (findings never fail the run); `2` missing, unreadable or wrongly formatted input, or invalid arguments.

## Known limitations

- CodeQL's cryptography queries are experimental and exist for Python and Java only, so JavaScript/TypeScript corroboration depends on Semgrep and cryptoscan agreeing.
- Rules match concrete call shapes. Algorithms chosen through variables or configuration are not seen by Semgrep, and are only reported if cryptoscan's pattern match corroborates them.
- Semgrep's default `.semgrepignore` skips test directories in the scanned repository. This is a deliberate omission to cut down on noise from mocked data.
- Runtime TLS results have no source location. In SARIF, they are attached to `--runtime-anchor`, line 1.

## Development

```sh
python3 -m venv .venv || python -m venv .venv
pip install -r requirements-dev.txt
semgrep --validate --metrics=off --config rules/
semgrep scan --test --metrics=off --config rules/ rules/
python3 scripts/test_typescript_fixtures.py
PYTHONPATH=correlate python -m pytest -q correlate/tests
```

## Licence

Apache-2.0 unless otherwise stated. Rules were in part derived from [pe-version/pqc-semgrep-rules](https://github.com/pe-version/pqc-semgrep-rules) and so also remain under their MIT licence; see `third-party/NOTICE` and `third-party/LICENSE`.
