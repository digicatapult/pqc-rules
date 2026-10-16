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


def _key_groups(out: Path) -> list[dict]:
    groups = json.loads((out / "pqc-all.json").read_text())["groups"]
    return [g for g in groups if any(f["rule_id"].startswith("KEY-") for f in g["findings"])]


def test_committed_keys_are_kept_but_not_reported_by_default(tmp_path: Path) -> None:
    # KEY-00* also matches PEM header strings in code and tests, so keys are left to secret
    # scanning and only recorded in the artefacts.
    out = tmp_path / "out"
    assert main(["--root", str(FIXTURES), "--out", str(out), "--cryptoscan", str(FIXTURES / "cryptoscan-key.json")]) == 0
    key_groups = _key_groups(out)
    assert len({g["file"] for g in key_groups}) == 7
    assert not any(g["allowlisted"] or g["reported"] for g in key_groups)
    assert json.loads((out / "pqc-security.sarif").read_text())["runs"][0]["results"] == []
    cbom = json.loads((out / "pqc-cbom.cdx.json").read_text())
    key = next(c for c in cbom["components"] if c["name"] == "private-key")
    assert key["cryptoProperties"]["assetType"] == "related-crypto-material"
    assert len(key["evidence"]["occurrences"]) == 5


def test_committed_keys_can_be_allowlisted(tmp_path: Path) -> None:
    out = tmp_path / "out"
    assert main(["--root", str(FIXTURES), "--out", str(out), "--cryptoscan", str(FIXTURES / "cryptoscan-key.json"),
                 "--allowlist-extra", "cryptoscan:KEY-00*"]) == 0
    key_groups = _key_groups(out)
    assert key_groups
    assert all(g["allowlisted"] and g["reported"] for g in key_groups)


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


def test_cbom_lists_every_post_quantum_signature_in_a_shared_group(tmp_path: Path) -> None:
    # FN-DSA, XMSS and LMS on lines 1-3 share a match key, so they form one group.
    out = tmp_path / "out"
    assert main(["--root", str(FIXTURES), "--out", str(out),
                 "--cryptoscan", str(FIXTURES / "cryptoscan-mapping.json")]) == 0
    groups = json.loads((out / "pqc-all.json").read_text())["groups"]
    assert len([g for g in groups if g["file"] == "pq_signatures.py"]) == 1
    cbom = json.loads((out / "pqc-cbom.cdx.json").read_text())
    components = {c["name"]: c for c in cbom["components"]}
    for family in ("FN-DSA", "XMSS", "LMS"):
        component = components[family]
        assert [o["location"] for o in component["evidence"]["occurrences"]] == ["pq_signatures.py"]
        assert {"name": "pqc:risk", "value": "safe"} in component["properties"]


def test_dependency_findings_split_into_one_finding_per_family() -> None:
    parsed = parse_cryptoscan(FIXTURES / "cryptoscan-mapping.json", FIXTURES)
    by_file: dict[str, list[tuple[str, str]]] = {}
    for finding in parsed.findings:
        if finding.rule_id.startswith("DEP-"):
            by_file.setdefault(finding.file, []).append((finding.family, finding.risk))
    # node-forge: "RSA, AES, DES, SHA, MD5". Bare "SHA" names no family and is skipped.
    # cryptoscan rates both libraries VULNERABLE as a whole; each algorithm gets its own risk.
    assert by_file["package.json"] == [
        ("RSA", "vulnerable"), ("AES", "partial"), ("DES", "broken"), ("MD5", "broken"),
    ]
    assert by_file["requirements.txt"] == [
        ("RSA", "vulnerable"), ("ECC", "vulnerable"), ("AES", "partial"), ("ChaCha20", "partial"),
    ]


def test_safe_dependency_does_not_make_classical_algorithms_safe(tmp_path: Path) -> None:
    # Same shape as the fixture's dependency findings, for a library cryptoscan rates SAFE.
    finding = {
        "id": "DEP-bcprov-jdk18on-pom.xml", "type": "Crypto Library Dependency",
        "findingType": "dependency", "category": "dependency",
        "algorithm": "RSA, ECC, AES, ML-KEM", "quantumRisk": "SAFE", "file": "pom.xml", "line": 1,
    }
    path = tmp_path / "cryptoscan.json"
    path.write_text(json.dumps({"findings": [finding]}))
    parsed = parse_cryptoscan(path, tmp_path)
    assert [(f.family, f.risk) for f in parsed.findings] == [
        ("RSA", "vulnerable"), ("ECC", "vulnerable"), ("AES", "partial"), ("ML-KEM", "safe"),
    ]


def test_unmapped_findings_are_counted_in_outputs(tmp_path: Path) -> None:
    out = tmp_path / "out"
    assert main(["--root", str(FIXTURES), "--out", str(out),
                 "--cryptoscan", str(FIXTURES / "cryptoscan-mapping.json")]) == 0
    data = json.loads((out / "pqc-all.json").read_text())
    assert data["unmapped"] == {"cryptoscan": {"TLS-002": 1}}
    summary = (out / "pqc-summary.md").read_text()
    assert "Findings with no known algorithm family, not correlated: cryptoscan 1" in summary
