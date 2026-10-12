# Test fixtures

| File | Origin |
| --- | --- |
| `sample-app/` | Hand-written sample code scanned to produce the files below. |
| `semgrep.json` | Real output: `semgrep scan --config rules --json` (Semgrep 1.180.0) over a copy of `sample-app/`; `time` and `paths` removed. |
| `cryptoscan.json` | Real output: `cryptoscan scan sample-app --format json` (v1.4.0); absolute paths rewritten to repo-relative. |
| `tls.json` | Real output: `tlsanalyzer localhost:3443 --format json --skip-vulns` (v0.4.1) against `openssl s_server` with a throwaway RSA-2048 certificate. |
| `codeql.sarif` | **Synthetic.** Mirrors the message shape of CodeQL's `py/quantum-readiness/cbom/*` queries (`"Use of algorithm <NAME>"`). Replace with real output once the CodeQL job has run. |
| `cryptoscan-key.json` | **Synthetic.** A cryptoscan `KEY-001` finding with no key material, used to test the allowlist without committing anything that push protection would flag. |
