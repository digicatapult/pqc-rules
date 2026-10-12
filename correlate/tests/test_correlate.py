from __future__ import annotations

import json
from pathlib import Path

import pytest

from pqc_correlate.cli import main
from pqc_correlate.correlate import CONFLICTING, CORROBORATED, RUNTIME, SINGLE_SOURCE, correlate, reportable
from pqc_correlate.families import normalise_family
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
        "--codeql", str(FIXTURES / "codeql.sarif"),
        "--tls", str(FIXTURES / "tls.json"),
        *extra,
    ]


def find(groups: list[dict], file: str, line: int, family: str) -> dict:
    for group in groups:
        lines = {f["line"] for f in group["findings"]}
        if group["file"] == file and group["family"] == family and line in lines:
            return group
    raise AssertionError(f"no group for {file}:{line} {family}")


@pytest.mark.parametrize(
    ("name", "family"),
    [
        ("RSA", "RSA"), ("ECC", "ECC"), ("SECP256R1", "ECC"), ("Ed25519", "ECC"),
        ("MD5", "MD5"), ("SHA-1", "SHA-1"), ("SHA256", "SHA-2"), ("AES-GCM", "AES"),
        ("3DES", "3DES"), ("DES", "DES"), ("Hybrid-KEM", "ML-KEM"), ("X25519MLKEM768", "ML-KEM"),
        ("ML-DSA", "ML-DSA"), ("SLH-DSA", "SLH-DSA"), ("bcrypt", None), (None, None),
    ],
)
def test_normalise_family(name: str | None, family: str | None) -> None:
    assert normalise_family(name) == family


def test_two_sources_agreeing_are_corroborated_and_reported(tmp_path: Path) -> None:
    _, data, _ = run(tmp_path, *all_sources())
    rsa = find(data["groups"], "app.js", 4, "RSA")
    assert rsa["evidence"] == CORROBORATED
    assert rsa["sources"] == ["cryptoscan", "semgrep"]
    assert rsa["reported"] is True
    assert find(data["groups"], "app.js", 6, "MD5")["reported"] is True


def test_three_sources_agree_on_python_crypto(tmp_path: Path) -> None:
    _, data, _ = run(tmp_path, *all_sources())
    rsa = find(data["groups"], "crypto_samples.py", 3, "RSA")
    assert rsa["sources"] == ["codeql", "cryptoscan", "semgrep"]
    assert rsa["line"] == 3, "anchor should be the line all sources agree on, not the import"
    assert find(data["groups"], "crypto_samples.py", 5, "ECC")["sources"] == ["codeql", "cryptoscan", "semgrep"]


def test_single_source_outside_window_is_kept_but_not_reported(tmp_path: Path) -> None:
    _, data, _ = run(tmp_path, *all_sources())
    jwt = find(data["groups"], "app.js", 8, "RSA")
    assert jwt["evidence"] == SINGLE_SOURCE
    assert jwt["reported"] is False


def test_wider_window_merges_nearby_findings(tmp_path: Path) -> None:
    _, data, _ = run(tmp_path, *all_sources("--window", "4"))
    merged = find(data["groups"], "app.js", 8, "RSA")
    assert {f["line"] for f in merged["findings"]} >= {4, 8}


def test_partial_risk_is_never_reported(tmp_path: Path) -> None:
    _, data, _ = run(tmp_path, *all_sources())
    aes = find(data["groups"], "app.js", 10, "AES")
    assert aes["risk"] == "partial"
    assert aes["reported"] is False


def test_tls_certificate_key_is_allowlisted_runtime_finding(tmp_path: Path) -> None:
    _, data, sarif = run(tmp_path, *all_sources("--runtime-anchor", "docker-compose.yml"))
    runtime = [g for g in data["groups"] if g["evidence"] == RUNTIME]
    cert = next(g for g in runtime if g["findings"][0]["rule_id"] == "tls.certificate-key")
    assert cert["family"] == "RSA" and cert["reported"] is True
    hybrid = next(g for g in runtime if g["findings"][0]["rule_id"] == "tls.negotiated-key-exchange")
    assert hybrid["risk"] == "hybrid" and hybrid["reported"] is False
    notes = [r for r in sarif["runs"][0]["results"] if r["level"] == "note"]
    assert notes[0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "docker-compose.yml"


def test_committed_key_is_allowlisted_by_default(tmp_path: Path) -> None:
    _, data, _ = run(tmp_path, "--cryptoscan", str(FIXTURES / "cryptoscan-key.json"))
    assert data["groups"][0]["allowlisted"] is True
    assert data["groups"][0]["reported"] is True


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
    assert {"RSA", "ECC", "MD5", "AES", "ML-KEM"} <= names
    assert all(c["type"] == "cryptographic-asset" for c in cbom["components"])


def test_summary_flags_expected_but_missing_sources(tmp_path: Path) -> None:
    run(tmp_path, "--semgrep", str(FIXTURES / "semgrep.json"), "--expected", "semgrep,codeql")
    summary = (tmp_path / "out" / "pqc-summary.md").read_text()
    assert "Sources expected but not run: codeql" in summary


def test_disagreeing_sources_are_conflicting_and_not_reported() -> None:
    findings = [
        Finding("cryptoscan", "kem.py", 10, "ML-KEM", "safe", "PQC-MLKEM-001", "ML-KEM"),
        Finding("semgrep", "kem.py", 11, "ML-KEM", "vulnerable", "pqc.python.x", "flagged"),
    ]
    (group,) = correlate(findings, window=3, allowlist=())
    assert group.evidence == CONFLICTING
    assert reportable(group) is False


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
