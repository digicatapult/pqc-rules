"""cryptoscan mapping, checked against real cryptoscan 1.4.0 output (see fixtures/README.md)."""

from __future__ import annotations

import json
from pathlib import Path

from pqc_correlate.cli import main
from pqc_correlate.correlate import CORROBORATED, correlate, reportable
from pqc_correlate.normalise import Finding, parse_cryptoscan

FIXTURES = Path(__file__).parent / "fixtures"


def families_by_rule(fixture: str) -> dict[str, set[tuple[str, str]]]:
    parsed = parse_cryptoscan(FIXTURES / fixture, FIXTURES)
    out: dict[str, set[tuple[str, str]]] = {}
    for finding in parsed.findings:
        out.setdefault(finding.rule_id, set()).add((finding.family, finding.risk))
    return out


def test_every_committed_key_header_is_kept() -> None:
    by_rule = families_by_rule("cryptoscan-key.json")
    assert by_rule["KEY-001"] == {("private-key", "vulnerable")}
    assert by_rule["KEY-002"] == {("ECC", "vulnerable")}
    assert by_rule["KEY-003"] == {("DSA", "vulnerable")}
    for rule in ("KEY-004", "KEY-005", "KEY-006"):
        assert by_rule[rule] == {("private-key", "vulnerable")}
    assert by_rule["RSA-001"] == {("RSA", "vulnerable")}


def test_every_committed_key_is_reported_by_default(tmp_path: Path) -> None:
    out = tmp_path / "out"
    assert main(["--root", str(FIXTURES), "--out", str(out), "--cryptoscan", str(FIXTURES / "cryptoscan-key.json")]) == 0
    groups = json.loads((out / "pqc-all.json").read_text())["groups"]
    key_files = {g["file"] for g in groups if any(f["rule_id"].startswith("KEY-") for f in g["findings"])}
    assert len(key_files) == 7
    for group in groups:
        if any(f["rule_id"].startswith("KEY-") for f in group["findings"]):
            assert group["allowlisted"] and group["reported"], group["file"]
    cbom = json.loads((out / "pqc-cbom.cdx.json").read_text())
    key = next(c for c in cbom["components"] if c["name"] == "private-key")
    assert key["cryptoProperties"]["assetType"] == "related-crypto-material"
    assert len(key["evidence"]["occurrences"]) == 5


def test_legacy_tls_maps_by_id_and_modern_tls_is_counted_as_unmapped() -> None:
    parsed = parse_cryptoscan(FIXTURES / "cryptoscan-mapping.json", FIXTURES)
    tls = [f for f in parsed.findings if f.rule_id.startswith("TLS-")]
    assert [(f.rule_id, f.family, f.risk, f.line) for f in tls] == [("TLS-001", "TLS-legacy", "vulnerable", 3)]
    assert parsed.unmapped["TLS-002"] == 1


def test_legacy_tls_corroborates_semgrep() -> None:
    parsed = parse_cryptoscan(FIXTURES / "cryptoscan-mapping.json", FIXTURES)
    semgrep = Finding("semgrep", "tls_versions.py", 3, "TLS-legacy", "broken",
                      "pqc.python.tls-legacy-version", "TLS 1.0 / 1.1")
    groups = correlate([*parsed.findings, semgrep], window=3, allowlist=())
    (group,) = [g for g in groups if g.anchor.family == "TLS-legacy"]
    assert group.evidence == CORROBORATED
    assert reportable(group)


def test_post_quantum_signatures_are_safe_and_not_dsa() -> None:
    by_rule = families_by_rule("cryptoscan-mapping.json")
    assert by_rule["PQC-FNDSA-001"] == {("FN-DSA", "safe")}
    assert by_rule["PQC-XMSS-001"] == {("XMSS", "safe")}
    assert by_rule["PQC-LMS-001"] == {("LMS", "safe")}


def test_falcon_does_not_join_a_neighbouring_dsa_group() -> None:
    parsed = parse_cryptoscan(FIXTURES / "cryptoscan-mapping.json", FIXTURES)
    dsa = Finding("semgrep", "pq_signatures.py", 1, "DSA", "vulnerable", "pqc.python.dsa", "DSA")
    groups = correlate([*parsed.findings, dsa], window=3, allowlist=())
    dsa_group = next(g for g in groups if g.anchor.family == "DSA")
    assert dsa_group.sources == ["semgrep"]


def test_dependency_findings_split_into_one_finding_per_family() -> None:
    parsed = parse_cryptoscan(FIXTURES / "cryptoscan-mapping.json", FIXTURES)
    by_file: dict[str, list[str]] = {}
    for finding in parsed.findings:
        if finding.rule_id.startswith("DEP-"):
            by_file.setdefault(finding.file, []).append(finding.family)
    # node-forge: "RSA, AES, DES, SHA, MD5". Bare "SHA" names no family and is skipped.
    assert by_file["package.json"] == ["RSA", "AES", "DES", "MD5"]
    assert by_file["requirements.txt"] == ["RSA", "ECC", "AES", "ChaCha20"]


def test_unmapped_findings_are_counted_in_outputs(tmp_path: Path) -> None:
    out = tmp_path / "out"
    assert main(["--root", str(FIXTURES), "--out", str(out),
                 "--cryptoscan", str(FIXTURES / "cryptoscan-mapping.json")]) == 0
    data = json.loads((out / "pqc-all.json").read_text())
    assert data["unmapped"] == {"cryptoscan": {"TLS-002": 1}}
    summary = (out / "pqc-summary.md").read_text()
    assert "Findings with no known algorithm family, not correlated: cryptoscan 1" in summary
