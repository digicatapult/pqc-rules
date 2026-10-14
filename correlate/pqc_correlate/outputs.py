"""Writers for the correlator's artefacts: JSON, CycloneDX CBOM, SARIF, Markdown."""

from __future__ import annotations

import hashlib
import uuid
from collections import Counter, defaultdict
from datetime import datetime, timezone
from typing import Any

from . import __version__
from .families import RISK_ORDER
from .correlate import CONFLICTING, CORROBORATED, SINGLE_SOURCE, Group, reportable

TOOL_NAME = "pqc-correlate"
INFORMATION_URI = "https://github.com/digicatapult/pqc-rules"

_PRIMITIVE = {
    "RSA": "pke", "ECC": "signature", "DSA": "signature", "DH": "key-agree",
    "ML-KEM": "kem", "ML-DSA": "signature", "SLH-DSA": "signature",
    "FN-DSA": "signature", "XMSS": "signature", "LMS": "signature",
    "AES": "block-cipher", "DES": "block-cipher", "3DES": "block-cipher",
    "RC4": "stream-cipher", "ChaCha20": "stream-cipher",
    "MD5": "hash", "SHA-1": "hash", "SHA-2": "hash", "SHA-3": "hash",
}


def _group_dict(group: Group) -> dict[str, Any]:
    anchor = group.anchor
    return {
        "file": anchor.file,
        "line": anchor.line,
        "family": anchor.family,
        "risk": group.risk,
        "evidence": group.evidence,
        "allowlisted": group.allowlisted,
        "reported": reportable(group),
        "sources": group.sources,
        "findings": [
            {"source": f.source, "file": f.file, "line": f.line, "family": f.family,
             "risk": f.risk, "rule_id": f.rule_id, "message": f.message, **f.extra}
            for f in group.findings
        ],
    }


def to_json(groups: list[Group], sources_run: list[str], unmapped: dict[str, Counter[str]]) -> dict[str, Any]:
    """Every group, plus per-source counts of findings that mapped to no family (by rule id)."""
    return {
        "tool": {"name": TOOL_NAME, "version": __version__},
        "sources_run": sources_run,
        "unmapped": {source: dict(sorted(counts.items())) for source, counts in unmapped.items()},
        "groups": [_group_dict(g) for g in groups],
    }


def _crypto_properties(family: str) -> dict[str, Any]:
    if family == "TLS-legacy":
        return {"assetType": "protocol"}
    if family == "private-key":
        return {"assetType": "related-crypto-material", "relatedCryptoMaterialProperties": {"type": "private-key"}}
    properties: dict[str, Any] = {"assetType": "algorithm"}
    if family in _PRIMITIVE:
        properties["algorithmProperties"] = {"primitive": _PRIMITIVE[family]}
    return properties


def to_cbom(groups: list[Group]) -> dict[str, Any]:
    """CycloneDX 1.6 CBOM: one cryptographic-asset component per algorithm family."""
    by_family: dict[str, list[Group]] = defaultdict(list)
    for group in groups:
        by_family[group.anchor.family].append(group)
    components = []
    for family in sorted(by_family):
        members = by_family[family]
        occurrences = [{"location": g.anchor.file, "line": g.anchor.line} for g in members]
        component: dict[str, Any] = {
            "type": "cryptographic-asset",
            "bom-ref": f"crypto/algorithm/{family}",
            "name": family,
            "cryptoProperties": _crypto_properties(family),
            "properties": [
                {"name": "pqc:risk", "value": min((g.risk for g in members), key=RISK_ORDER.index)},
                {"name": "pqc:evidence", "value": ",".join(sorted({g.evidence for g in members}))},
            ],
        }
        component["evidence"] = {"occurrences": occurrences}
        components.append(component)
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "tools": {"components": [{"type": "application", "name": TOOL_NAME, "version": __version__}]},
        },
        "components": components,
    }


def _fingerprint(group: Group) -> str:
    anchor = group.anchor
    key = f"{anchor.file}|{anchor.family}|{anchor.line}|{','.join(group.sources)}"
    return hashlib.sha256(key.encode()).hexdigest()


def to_sarif(groups: list[Group]) -> dict[str, Any]:
    """SARIF 2.1.0 containing only reportable groups."""
    rules: dict[str, dict[str, Any]] = {}
    results = []
    for group in filter(reportable, groups):
        anchor = group.anchor
        rule_id = f"pqc/{anchor.family.lower()}"
        rules.setdefault(rule_id, {
            "id": rule_id,
            "name": f"PQC{anchor.family.replace('-', '')}",
            "shortDescription": {"text": f"Quantum-vulnerable or broken cryptography: {anchor.family}"},
            "properties": {"tags": ["security", "cryptography", "post-quantum"]},
        })
        level = "warning" if group.evidence == CORROBORATED else "note"
        detail = "; ".join(sorted({f"{f.source}: {f.message.splitlines()[0]}" for f in group.findings}))
        results.append({
            "ruleId": rule_id,
            "level": level,
            "message": {"text": f"[{group.evidence}; risk={group.risk}; sources={','.join(group.sources)}] {detail}"},
            "locations": [{"physicalLocation": {
                "artifactLocation": {"uri": anchor.file},
                "region": {"startLine": max(anchor.line, 1)},
            }}],
            "partialFingerprints": {"pqcGroup/v1": _fingerprint(group)},
            "properties": {"evidence": group.evidence, "risk": group.risk,
                           "sources": group.sources, "allowlisted": group.allowlisted},
        })
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": TOOL_NAME, "version": __version__,
                                "informationUri": INFORMATION_URI, "rules": list(rules.values())}},
            "results": results,
        }],
    }


def to_summary(
    groups: list[Group], sources_run: list[str], sources_expected: list[str], unmapped: dict[str, Counter[str]]
) -> str:
    counts = Counter(g.evidence for g in groups)
    reported = sum(1 for g in groups if reportable(g))
    missing = sorted(set(sources_expected) - set(sources_run))
    lines = [
        "## Post-quantum cryptography scan",
        "",
        f"Sources run: {', '.join(sources_run) or 'none'}",
    ]
    if missing:
        lines.append(f"Sources expected but not run: {', '.join(missing)}")
    dropped = {source: sum(counts.values()) for source, counts in unmapped.items() if counts}
    if dropped:
        lines.append(
            "Findings with no known algorithm family, not correlated: "
            + ", ".join(f"{source} {count}" for source, count in sorted(dropped.items()))
            + " (see `unmapped` in `pqc-all.json`)"
        )
    lines += [
        "",
        "| Evidence | Groups |",
        "| --- | --- |",
        *(f"| {level} | {counts.get(level, 0)} |" for level in (CORROBORATED, SINGLE_SOURCE, CONFLICTING)),
        "",
        f"**Reported to code scanning:** {reported} (quantum-vulnerable/broken, corroborated or allowlisted).",
        "All other findings are in the `pqc-all.json` artefact.",
    ]
    at_risk = [g for g in groups if reportable(g)]
    if at_risk:
        lines += ["", "| Location | Family | Risk | Evidence | Sources |", "| --- | --- | --- | --- | --- |"]
        for g in at_risk:
            lines.append(f"| `{g.anchor.file}:{g.anchor.line}` | {g.anchor.family} | {g.risk} | {g.evidence} | {', '.join(g.sources)} |")
    return "\n".join(lines) + "\n"
