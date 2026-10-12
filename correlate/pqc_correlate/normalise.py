"""Parsers that turn each tool's native output into Finding records."""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .families import normalise_family, normalise_risk

RUNTIME_FILE = "<runtime>"


@dataclass(frozen=True)
class Finding:
    """One normalised observation from one source."""

    source: str
    file: str
    line: int
    family: str
    risk: str
    rule_id: str
    message: str
    extra: dict[str, Any] = field(default_factory=dict, compare=False, hash=False)

    @property
    def is_runtime(self) -> bool:
        return self.file == RUNTIME_FILE


class InputError(ValueError):
    """Raised when an input file is missing or not in the expected format."""


def _load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise InputError(f"input file not found: {path}") from exc
    except json.JSONDecodeError as exc:
        raise InputError(f"{path} is not valid JSON: {exc}") from exc


def _relative(file: str, root: Path) -> str:
    """Make a path repo-relative with forward slashes, so sources can be compared."""
    file = re.sub(r"^file://", "", file)
    candidate = Path(file)
    if candidate.is_absolute():
        try:
            candidate = candidate.resolve().relative_to(root.resolve())
        except ValueError:
            return file.replace(os.sep, "/")
    return os.path.normpath(str(candidate)).replace(os.sep, "/").removeprefix("./")


_CRYPTOSCAN_ID = re.compile(r"^(?P<pattern>.+?)-\d+-\d+$")


def parse_cryptoscan(path: Path, root: Path) -> list[Finding]:
    """Parse `cryptoscan scan --format json` output."""
    data = _load_json(path)
    if not isinstance(data, dict) or "findings" not in data:
        raise InputError(f"{path}: expected cryptoscan JSON with a 'findings' array")
    findings: list[Finding] = []
    for item in data["findings"] or []:
        raw_id = str(item.get("id", ""))
        match = _CRYPTOSCAN_ID.match(raw_id)
        pattern_id = match.group("pattern") if match else raw_id
        family = normalise_family(item.get("algorithm")) or normalise_family(item.get("type"))
        if family is None:
            continue
        findings.append(
            Finding(
                source="cryptoscan",
                file=_relative(str(item.get("file", "")), root),
                line=int(item.get("line") or 0),
                family=family,
                risk=normalise_risk(item.get("quantumRisk"), family),
                rule_id=pattern_id,
                message=str(item.get("description") or item.get("type") or pattern_id),
                extra={"category": item.get("category"), "confidence": item.get("confidence")},
            )
        )
    return findings


_SEMGREP_ID = re.compile(r"pqc\.[a-z]+\.[\w-]+$")


def parse_semgrep(path: Path, root: Path) -> list[Finding]:
    """Parse `semgrep --json` output produced with the pqc-rules ruleset."""
    data = _load_json(path)
    if not isinstance(data, dict) or "results" not in data:
        raise InputError(f"{path}: expected Semgrep JSON with a 'results' array")
    findings: list[Finding] = []
    for item in data["results"]:
        meta = (item.get("extra") or {}).get("metadata") or {}
        family = normalise_family(meta.get("pqc-family"))
        if family is None:
            continue
        check_id = str(item.get("check_id", ""))
        # Semgrep prefixes the rule id with the config path (e.g. "w.rules.javascript.pqc.javascript.rsa").
        id_match = _SEMGREP_ID.search(check_id)
        rule_id = id_match.group(0) if id_match else check_id
        findings.append(
            Finding(
                source="semgrep",
                file=_relative(str(item.get("path", "")), root),
                line=int((item.get("start") or {}).get("line") or 0),
                family=family,
                risk=normalise_risk(meta.get("pqc-risk"), family),
                rule_id=rule_id,
                message=str((item.get("extra") or {}).get("message", "")).strip(),
            )
        )
    return findings


_CODEQL_ALGO = re.compile(r"(?:Use of algorithm\s+)?(?P<algo>[\w\-+/]+)")


def parse_codeql(path: Path, root: Path) -> list[Finding]:
    """Parse SARIF from CodeQL's experimental cryptography inventory queries."""
    data = _load_json(path)
    if not isinstance(data, dict) or "runs" not in data:
        raise InputError(f"{path}: expected SARIF with a 'runs' array")
    findings: list[Finding] = []
    for run in data["runs"]:
        for result in run.get("results", []):
            text = (result.get("message") or {}).get("text", "")
            match = _CODEQL_ALGO.search(text.split("Use of algorithm", 1)[-1].strip() or text)
            family = normalise_family(match.group("algo") if match else text)
            locations = result.get("locations") or []
            if family is None or not locations:
                continue
            physical = locations[0].get("physicalLocation") or {}
            findings.append(
                Finding(
                    source="codeql",
                    file=_relative(str((physical.get("artifactLocation") or {}).get("uri", "")), root),
                    line=int((physical.get("region") or {}).get("startLine") or 0),
                    family=family,
                    risk=normalise_risk(None, family),
                    rule_id=str(result.get("ruleId", "")),
                    message=text,
                )
            )
    return findings


def parse_tls(path: Path, _root: Path) -> list[Finding]:
    """Parse `tlsanalyzer --format json`; findings are runtime, not file-located."""
    data = _load_json(path)
    targets = data if isinstance(data, list) else [data]
    findings: list[Finding] = []
    for target in targets:
        if not isinstance(target, dict) or "target" not in target:
            raise InputError(f"{path}: expected tls-analyzer JSON with a 'target' field")
        name = str(target["target"])
        if target.get("error"):
            raise InputError(f"{path}: tls-analyzer could not scan {name}: {target['error']}")
        findings.extend(_tls_findings(name, target))
    return findings


def _tls_findings(name: str, target: dict[str, Any]) -> list[Finding]:
    out: list[Finding] = []

    def add(rule: str, family: str, risk: str, message: str) -> None:
        out.append(Finding("tls-analyzer", RUNTIME_FILE, 0, family, risk, rule, message, {"target": name}))

    cert = target.get("certificate") or {}
    family = normalise_family(cert.get("publicKeyAlgorithm"))
    if family and not cert.get("quantumSafe", False):
        bits = cert.get("publicKeyBits")
        add("tls.certificate-key", family, "vulnerable",
            f"{name} presents a {cert.get('publicKeyAlgorithm')}-{bits} certificate key (quantum-vulnerable).")
    for kx in target.get("keyExchanges") or []:
        if not kx.get("negotiated"):
            continue
        kx_type = kx.get("type")
        risk = {"classical": "vulnerable", "hybrid": "hybrid", "pqc": "safe"}.get(kx_type, "unknown")
        kx_family = "ML-KEM" if kx_type in ("hybrid", "pqc") else normalise_family(kx.get("name")) or "ECC"
        add("tls.negotiated-key-exchange", kx_family, risk,
            f"{name} negotiated key exchange {kx.get('name')} ({kx_type}).")
    for proto in target.get("protocols") or []:
        version = str(proto.get("version", ""))
        if proto.get("supported") and version in ("TLS 1.0", "TLS 1.1", "SSL 3.0"):
            add("tls.legacy-protocol", "TLS-legacy", "broken", f"{name} still accepts {version}.")
    return out


PARSERS = {
    "cryptoscan": parse_cryptoscan,
    "semgrep": parse_semgrep,
    "codeql": parse_codeql,
    "tls": parse_tls,
}
