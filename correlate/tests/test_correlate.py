from __future__ import annotations

import json
from pathlib import Path

import pytest

from pqc_correlate.cli import main
from pqc_correlate.correlate import CONFLICTING, CORROBORATED, SINGLE_SOURCE, correlate, reportable
from pqc_correlate.normalise import Finding

FIXTURES = Path(__file__).parent / "fixtures"


def run(tmp_path: Path, *extra: str) -> tuple[int, dict, dict]:
    out = tmp_path / "out"
    code = main(["--root", str(FIXTURES / "sample-app"), "--out", str(out), *extra])
    if code != 0:
        return code, {}, {}
    return code, json.loads((out / "pqc-all.json").read_text()), json.loads((out / "pqc-security.sarif").read_text())


def all_sources(*extra: str) -> list[str]:
    return [
        "--semgrep", str(FIXTURES / "semgrep.json"),
        "--cryptoscan", str(FIXTURES / "cryptoscan.json"),
        *extra,
    ]


def find(groups: list[dict], file: str, line: int, family: str) -> dict:
    for group in groups:
        lines = {f["line"] for f in group["findings"]}
        if group["file"] == file and group["family"] == family and line in lines:
            return group
    raise AssertionError(f"no group for {file}:{line} {family}")


def test_two_sources_agreeing_are_corroborated_and_reported(tmp_path: Path) -> None:
    _, data, _ = run(tmp_path, *all_sources())
    rsa = find(data["groups"], "app.js", 4, "RSA")
    assert rsa["evidence"] == CORROBORATED
    assert rsa["sources"] == ["cryptoscan", "semgrep"]
    assert rsa["reported"] is True
    assert find(data["groups"], "app.js", 6, "MD5")["reported"] is True


def test_two_sources_agree_on_python_crypto(tmp_path: Path) -> None:
    _, data, _ = run(tmp_path, *all_sources())
    rsa = find(data["groups"], "crypto_samples.py", 3, "RSA")
    assert rsa["sources"] == ["cryptoscan", "semgrep"]
    assert rsa["line"] == 3, "anchor should be the Semgrep line, not the import"
    assert find(data["groups"], "crypto_samples.py", 5, "ECC")["sources"] == ["cryptoscan", "semgrep"]


def test_single_source_outside_window_is_kept_but_not_reported(tmp_path: Path) -> None:
    _, data, _ = run(tmp_path, *all_sources())
    jwt = find(data["groups"], "app.js", 8, "RSA")
    assert jwt["evidence"] == SINGLE_SOURCE
    assert jwt["reported"] is False


def test_wider_window_never_merges_distinct_semgrep_findings(tmp_path: Path) -> None:
    _, data, _ = run(tmp_path, *all_sources("--window", "4"))
    jwt = find(data["groups"], "app.js", 8, "RSA")
    assert {f["line"] for f in jwt["findings"]} == {8}
    assert find(data["groups"], "app.js", 4, "RSA")["evidence"] == CORROBORATED


def test_partial_risk_is_never_reported(tmp_path: Path) -> None:
    _, data, _ = run(tmp_path, *all_sources())
    aes = find(data["groups"], "app.js", 10, "AES")
    assert aes["risk"] == "partial"
    assert aes["reported"] is False


def test_allowlist_disable_reports_only_corroborated(tmp_path: Path) -> None:
    _, data, sarif = run(tmp_path, *all_sources("--allowlist-disable"))
    assert all(g["evidence"] == CORROBORATED for g in data["groups"] if g["reported"])
    assert {r["level"] for r in sarif["runs"][0]["results"]} == {"warning"}


def test_allowlist_extra_promotes_single_source(tmp_path: Path) -> None:
    _, data, _ = run(tmp_path, *all_sources("--allowlist-extra", "semgrep:pqc.javascript.jwt-*"))
    assert find(data["groups"], "app.js", 8, "RSA")["reported"] is True


def test_sarif_results_all_have_locations(tmp_path: Path) -> None:
    _, _, sarif = run(tmp_path, *all_sources())
    results = sarif["runs"][0]["results"]
    assert results
    for result in results:
        region = result["locations"][0]["physicalLocation"]["region"]
        assert region["startLine"] >= 1
        assert result["partialFingerprints"]["pqcGroup/v1"]


def test_cbom_is_cyclonedx_16(tmp_path: Path) -> None:
    run(tmp_path, *all_sources())
    cbom = json.loads((tmp_path / "out" / "pqc-cbom.cdx.json").read_text())
    assert cbom["bomFormat"] == "CycloneDX" and cbom["specVersion"] == "1.6"
    names = {c["name"] for c in cbom["components"]}
    assert {"RSA", "ECC", "MD5", "AES"} <= names
    assert all(c["type"] == "cryptographic-asset" for c in cbom["components"])


def test_summary_flags_expected_but_missing_sources(tmp_path: Path) -> None:
    run(tmp_path, "--semgrep", str(FIXTURES / "semgrep.json"), "--expected", "semgrep,cryptoscan")
    summary = (tmp_path / "out" / "pqc-summary.md").read_text()
    assert "Sources expected but not run: cryptoscan" in summary


def test_disagreeing_sources_are_conflicting_and_not_reported() -> None:
    findings = [
        Finding("cryptoscan", "kem.py", 10, "ML-KEM", "safe", "PQC-MLKEM-001", "ML-KEM"),
        Finding("semgrep", "kem.py", 11, "ML-KEM", "vulnerable", "pqc.python.x", "flagged"),
    ]
    (group,) = correlate(findings, window=3, allowlist=())
    assert group.evidence == CONFLICTING
    assert reportable(group) is False


def _semgrep(line: int, family: str, rule: str) -> Finding:
    return Finding("semgrep", "app.js", line, family, "vulnerable", f"pqc.javascript.{rule}", rule)


def _cryptoscan(line: int, family: str) -> Finding:
    return Finding("cryptoscan", "app.js", line, family, "vulnerable", f"{family}-001", family)


def test_neighbouring_semgrep_findings_stay_separate() -> None:
    # RSA key (8), EC key (9), ECDH (10), RS256 JWT (11), ES256 JWT (12): five distinct calls.
    findings = [
        _semgrep(8, "RSA", "rsa"), _cryptoscan(8, "RSA"),
        _semgrep(9, "ECC", "ec"), _cryptoscan(9, "ECC"),
        _semgrep(10, "ECC", "ec"), _cryptoscan(10, "ECC"),
        _semgrep(11, "RSA", "jwt-rsa"),
        _semgrep(12, "ECC", "jwt-ecc"),
    ]
    groups = correlate(findings, window=3, allowlist=("semgrep:pqc.*.jwt-*",))
    by_line = {g.anchor.line: g for g in groups}
    assert sorted(by_line) == [8, 9, 10, 11, 12]
    assert all(by_line[line].evidence == CORROBORATED for line in (8, 9, 10))
    assert all(by_line[line].evidence == SINGLE_SOURCE for line in (11, 12))
    assert all(reportable(g) for g in groups)


def test_pattern_finding_joins_nearest_anchor_only() -> None:
    findings = [_semgrep(10, "RSA", "rsa"), _semgrep(14, "RSA", "jwt-rsa"), _cryptoscan(13, "RSA")]
    groups = correlate(findings, window=3, allowlist=())
    jwt = next(g for g in groups if g.anchor.rule_id == "pqc.javascript.jwt-rsa")
    key = next(g for g in groups if g.anchor.rule_id == "pqc.javascript.rsa")
    assert jwt.sources == ["cryptoscan", "semgrep"]
    assert key.sources == ["semgrep"]


def test_pattern_findings_without_anchor_still_cluster() -> None:
    findings = [_cryptoscan(5, "MD5"), _cryptoscan(7, "MD5"), _semgrep(20, "MD5", "md5")]
    groups = correlate(findings, window=3, allowlist=())
    assert sorted(len(g.findings) for g in groups) == [1, 2]
    assert all(g.evidence == SINGLE_SOURCE for g in groups)


@pytest.mark.parametrize(
    "args",
    [
        ["--semgrep", "does-not-exist.json"],
        ["--allowlist-extra", "no-source-prefix"],
        ["--window", "-1"],
    ],
)
def test_bad_input_exits_2(tmp_path: Path, args: list[str]) -> None:
    code, _, _ = run(tmp_path, *args)
    assert code == 2


def test_wrong_format_is_rejected(tmp_path: Path) -> None:
    code, _, _ = run(tmp_path, "--semgrep", str(FIXTURES / "cryptoscan.json"))
    assert code == 2


def test_reviewer_chain_does_not_form_one_group() -> None:
    # Semgrep-only RSA every three lines from 10 to 28, then one cryptoscan finding at 31.
    findings = [_semgrep(line, "RSA", "rsa") for line in range(10, 29, 3)] + [_cryptoscan(31, "RSA")]
    groups = correlate(findings, window=3, allowlist=())
    assert len(groups) == 7
    corroborated = [g for g in groups if g.evidence == CORROBORATED]
    assert [g.anchor.line for g in corroborated] == [28]
    assert all(g.evidence == SINGLE_SOURCE for g in groups if g.anchor.line < 28)


def test_cluster_without_anchor_is_bounded_by_its_first_line() -> None:
    findings = [_cryptoscan(line, "RSA") for line in (5, 8, 11, 14, 17)]
    groups = correlate(findings, window=3, allowlist=())
    assert [sorted(f.line for f in g.findings) for g in groups] == [[5, 8], [11, 14], [17]]
    for group in groups:
        lines = [f.line for f in group.findings]
        assert max(lines) - min(lines) <= 3


def _write(tmp_path: Path, name: str, content: object) -> Path:
    path = tmp_path / name
    path.write_text(json.dumps(content))
    return path


@pytest.mark.parametrize(
    ("source", "content"),
    [
        ("--semgrep", {"results": "not-a-list"}),
        ("--semgrep", {"results": ["not-an-object"]}),
        ("--semgrep", {"results": [{"extra": ["not-an-object"]}]}),
        ("--semgrep", {"results": [{"extra": {"metadata": {"pqc-family": "RSA"}}, "start": {"line": "x"}}]}),
        ("--cryptoscan", {"findings": {"id": "RSA-001-1-1"}}),
        ("--cryptoscan", {"findings": [None]}),
        ("--cryptoscan", ["not", "an", "object"]),
    ],
)
def test_malformed_input_exits_2(tmp_path: Path, source: str, content: object) -> None:
    code, _, _ = run(tmp_path, source, str(_write(tmp_path, "input.json", content)))
    assert code == 2


def test_directory_as_input_exits_2(tmp_path: Path) -> None:
    code, _, _ = run(tmp_path, "--semgrep", str(FIXTURES))
    assert code == 2


def test_non_utf8_input_exits_2(tmp_path: Path) -> None:
    path = tmp_path / "input.json"
    path.write_bytes(b"\xff\xfe{}")
    code, _, _ = run(tmp_path, "--cryptoscan", str(path))
    assert code == 2


def test_empty_results_are_valid(tmp_path: Path) -> None:
    code, data, _ = run(tmp_path, "--semgrep", str(_write(tmp_path, "s.json", {"results": None})),
                        "--cryptoscan", str(_write(tmp_path, "c.json", {"findings": None})))
    assert code == 0
    assert data["groups"] == []
