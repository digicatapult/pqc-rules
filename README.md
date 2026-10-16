# Post-quantum cryptography (PQC) Semgrep rules and correlator

Few official, publicly available Semgrep rules exist at the time of writing to scan for weak or vulnerable post-quantum cryptography patterns. So, this repository has two functions, (1) to create a suitable PQC ruleset for Semgrep and fill that gap, and then (2) to correlate results against other PQC tooling available today, whether production-ready or merely experimental, in the hope that the aggregation from many tools will better serve on-going and future migrations to quantum-safe algorithms.

This Semgrep ruleset is consumed by Digital Catapult's `scan-post-quantum-cryptography.yml` shared workflow in [digicatapult/shared-workflows](https://github.com/digicatapult/shared-workflows), which checks this repository out as a pinned commit SHA.

## Contents

| Path                       | Purpose                                                                                                  |
| -------------------------- | -------------------------------------------------------------------------------------------------------- |
| `rules/`                   | Semgrep rules for JavaScript/TypeScript, Python, Go and Java, each with a test fixture of the same name. |
| `correlate/pqc_correlate/` | Correlator. Python standard library only, no runtime dependencies.                                       |
| `correlate/tests/`         | pytest suite and fixtures (see `fixtures/README.md` for which are real tool output).                     |

## Rules

Every rule carries three metadata keys the correlator relies on. `correlate/tests/test_rule_metadata.py` checks each rule's `pqc-family` and `pqc-risk` against the correlator's vocabulary.

| Key            | Values                                                                                            |
| -------------- | ------------------------------------------------------------------------------------------------- |
| `pqc-category` | `shor-broken`, `classically-broken`, `pqc-safe`, `pqc-hybrid`                                     |
| `pqc-family`   | `RSA`, `ECC`, `DSA`, `DH`, `DES`, `3DES`, `RC4`, `MD5`, `SHA-1`, `TLS-legacy`, `ML-KEM`, `ML-DSA` |
| `pqc-risk`     | `broken`, `vulnerable`, `hybrid`, `safe`                                                          |

Coverage beyond the upstream fork:

- **JWT**: `jsonwebtoken`, `jose` and PyJWT signing with `RS*`/`PS*` (RSA) or `ES*`/`EdDSA` (ECC).
- **WebCrypto**: `subtle.generateKey`/`importKey` with RSA or EC algorithms.
- **node-forge**: RSA key handling, MD5, SHA-1.
- **Node `crypto`**: matched by function name, so `require("node:crypto")`, destructured imports and the module under any name are all covered.
- **TLS configuration**: legacy minimum versions (Node, Python incl. pyOpenSSL, Go), classical-only key-exchange groups, and hybrid ML-KEM groups (`X25519MLKEM768`, `SecP256r1MLKEM768`, `SecP384r1MLKEM1024`).
- **Post-quantum**: ML-KEM / ML-DSA / SLH-DSA via `@noble/post-quantum`, Node's `crypto` (`ml-kem-*`, `ml-dsa-*`, `slh-dsa-*`), liboqs (Python) and Go's `crypto/mlkem` / circl. Reported at `INFO` so a scan can show crypto that is already safe, not only crypto that is not.

## Correlator

```sh
PYTHONPATH=correlate python -m pqc_correlate \
  --root . --out pqc-out \
  --semgrep semgrep.json --cryptoscan cryptoscan.json \
  [--window 3] [--allowlist-extra 'semgrep:pqc.javascript.jwt-*'] \
  [--expected semgrep,cryptoscan]
```

Both inputs are the tools' JSON output (`semgrep --json`, `cryptoscan scan --format json`). Each flag can be repeated.

Every finding is reduced to `{source, file, line, family, risk}`. cryptoscan findings are mapped to a family by pattern id where the id says more than the text (`KEY-00*` private keys, `TLS-001` legacy TLS, `PQC-FNDSA-001`, `PQC-XMSS-001`, `PQC-LMS-001`), and dependency findings that list several algorithms become one finding per algorithm. A dependency's `quantumRisk` rates the library as a whole, so each of those findings takes its family's default risk instead. Findings that map to no family are counted, not correlated.

Within one file and family, each Semgrep finding starts its own group and other findings join the nearest Semgrep finding within `--window` lines. Findings with no Semgrep finding in range group together, but a group never spans more than `--window` lines from its first finding. Each group gets one evidence level:

| Evidence        | Meaning                                                                              |
| --------------- | ------------------------------------------------------------------------------------ |
| `corroborated`  | Two or more independent sources agree.                                               |
| `single-source` | Only one source saw it.                                                              |
| `conflicting`   | Sources agree on location and family but disagree on risk (e.g. safe vs vulnerable). |

### GitHub Code Scanning

Correlation is a necessary guard against overly noisy outputs and situations where tools have markedly different signal-to-noise ratios. A lot of noise reaching GitHub's Advanced Security interface for a repository is unnecessary, and adds a real cost in time spent shifting through false positives and re-assessing for false negatives later. `pqc-security.sarif` contains only groups that are **quantum-vulnerable or classically broken**, **not conflicting**, and either:

- `corroborated` (SARIF level `warning`), or
- allowlisted single-source findings (SARIF level `note`). There is no default allowlist; the shared workflow adds its own entries for Semgrep's JWT and TLS rules. `--allowlist-extra` adds `SOURCE:RULE_ID` globs. Partial-risk (e.g. AES-128, SHA-256), safe and hybrid findings are never uploaded, but they are always kept in the artefacts.

Committed private keys (cryptoscan `KEY-00*`) are kept in `pqc-all.json` and the CBOM but are not reported by default. cryptoscan matches only the `-----BEGIN ... PRIVATE KEY-----` header, so it also flags PEM-handling code and its tests. GitHub secret scanning detects real keys from their body; use `--allowlist-extra 'cryptoscan:KEY-00*'` to report cryptoscan's matches as well.

### Outputs

| File                 | Contents                                                                                                            |
| -------------------- | ------------------------------------------------------------------------------------------------------------------- |
| `pqc-all.json`       | Every group, with evidence level, sources and the original findings, plus `unmapped` counts per source and rule id. |
| `pqc-cbom.cdx.json`  | CycloneDX 1.6 CBOM, one `cryptographic-asset` per algorithm family, with every location a finding of it was seen.   |
| `pqc-security.sarif` | Reportable groups only (see above).                                                                                 |
| `pqc-summary.md`     | Step summary: counts by evidence level, sources expected but not run, unmapped findings, reported findings.         |

Exit codes: `0` success (findings never fail the run); `2` missing, unreadable or wrongly formatted input, or invalid arguments.

## Known limitations

- Corroboration needs both Semgrep and cryptoscan to see the same thing. cryptoscan's legacy TLS pattern (`TLS-001`) matches `TLSv1.1`, `TLSv1_1` and `SSLv3`, but not a bare `TLSv1`, `tls.VersionTLS10` or `TLSv1_method`, so Semgrep's `tls-legacy-version` findings for those stay single-source.
- Node's `crypto.encapsulate()`/`decapsulate()` are not reported as ML-KEM, because they accept RSA, EC and X25519/X448 keys too. ML-KEM is reported where the key pair is generated.
- Go's `CurvePreferences` is judged only when written as a `[]tls.CurveID{...}` literal in the `tls.Config`; a classical list held in a variable is not reported.
- Rules match concrete call shapes. Algorithms chosen through variables or configuration are not seen by Semgrep, and are only reported if cryptoscan's pattern match corroborates them.
- Semgrep's default `.semgrepignore` skips test directories in the scanned repository. This is a deliberate omission to cut down on noise from mocked data.
- Only Semgrep and cryptoscan are correlated. GitHub's [cbom-action](https://github.com/advanced-security/cbom-action) (CodeQL) was left out because it only covers Python for our purposes and its last release (v1.0.1) is three years old. CSNP's [tls-analyzer](https://github.com/csnp/tls-analyzer) was left out because it only recognises the X25519MLKEM768 hybrid, not SecP256r1MLKEM768 or SecP384r1MLKEM1024, so a service using those would not show as hybrid.

## Development

```sh
python3 -m venv .venv || python -m venv .venv
source .venv/bin/activate
pip install -r requirements-dev.txt
semgrep --validate --metrics=off --config rules/
semgrep scan --test --metrics=off --config rules/ rules/
python3 scripts/test_typescript_fixtures.py
PYTHONPATH=correlate python -m pytest -q correlate/tests
```

## Licence

Apache-2.0 unless otherwise stated. Rules were in part derived from [pe-version/pqc-semgrep-rules](https://github.com/pe-version/pqc-semgrep-rules) and so also remain under their MIT licence; see `third-party/NOTICE` and `third-party/LICENSE`.
