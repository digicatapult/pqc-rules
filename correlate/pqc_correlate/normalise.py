"""Parsers that turn each tool's native output into Finding records."""

from __future__ import annotations

import json
import os
import re
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .families import normalise_family, normalise_risk


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


@dataclass
class Parsed:
    """A parser's findings, plus a count of the source's findings that mapped to no family."""

    findings: list[Finding] = field(default_factory=list)
    unmapped: Counter[str] = field(default_factory=Counter)


class InputError(ValueError):
    """Raised when an input file is missing, unreadable or not in the expected format."""


def _load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise InputError(f"input file not found: {path}") from exc
    except OSError as exc:
        raise InputError(f"cannot read input file {path}: {exc.strerror or exc}") from exc
    except UnicodeDecodeError as exc:
        raise InputError(f"{path} is not UTF-8 text: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise InputError(f"{path} is not valid JSON: {exc}") from exc


def _items(data: Any, key: str, path: Path, expected: str) -> list[dict[str, Any]]:
    """Return data[key] as a list of objects, or raise InputError naming what was expected."""
    if not isinstance(data, dict) or key not in data:
        raise InputError(f"{path}: expected {expected} with a '{key}' array")
    items = data[key]
    if items is None:
        return []
    if not isinstance(items, list) or not all(isinstance(item, dict) for item in items):
        raise InputError(f"{path}: '{key}' must be an array of objects")
    return items


def _object(value: Any, what: str, path: Path) -> dict[str, Any]:
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise InputError(f"{path}: {what} must be an object, got {type(value).__name__}")
    return value


def _line(value: Any, path: Path) -> int:
    try:
        return int(value or 0)
    except (TypeError, ValueError) as exc:
        raise InputError(f"{path}: line number {value!r} is not an integer") from exc


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

# cryptoscan patterns whose `algorithm`/`type` text does not name the family, or names
# the wrong one, keyed by pattern id (cryptoscan 1.4.0, pkg/patterns/matcher.go).
# None means "deliberately not correlated": the alias table is not consulted for it.
_CRYPTOSCAN_PATTERN_FAMILY: dict[str, str | None] = {
    # KEY-001 matches both "BEGIN RSA PRIVATE KEY" and "BEGIN PRIVATE KEY" (PKCS#8), and
    # KEY-004..006 (OpenSSH, PGP, PKCS#8) do not reveal the key type either. An RSA header
    # also raises RSA-001 on the same line, so the algorithm is not lost.
    "KEY-001": "private-key",
    "KEY-002": "ECC",
    "KEY-003": "DSA",
    "KEY-004": "private-key",
    "KEY-005": "private-key",
    "KEY-006": "private-key",
    "TLS-001": "TLS-legacy",
    # TLS 1.2/1.3: not a legacy protocol, and not an algorithm the other sources report.
    "TLS-002": None,
    "PQC-FNDSA-001": "FN-DSA",
    "PQC-XMSS-001": "XMSS",
    "PQC-LMS-001": "LMS",
}


def _is_dependency(item: dict[str, Any]) -> bool:
    return item.get("category") == "dependency" or item.get("findingType") == "dependency"


def _cryptoscan_families(pattern_id: str, item: dict[str, Any]) -> list[str]:
    """Families a cryptoscan finding refers to: by pattern id first, then by its text.

    Dependency findings list several algorithms ("RSA, AES, DES, SHA, MD5"), so each
    is mapped on its own rather than letting the first alias that matches win.
    """
    if pattern_id in _CRYPTOSCAN_PATTERN_FAMILY:
        family = _CRYPTOSCAN_PATTERN_FAMILY[pattern_id]
        return [family] if family else []
    algorithm = str(item.get("algorithm") or "")
    if _is_dependency(item):
        families = (normalise_family(part) for part in algorithm.split(","))
        return list(dict.fromkeys(f for f in families if f))
    family = normalise_family(algorithm) or normalise_family(item.get("type"))
    return [family] if family else []


def parse_cryptoscan(path: Path, root: Path) -> Parsed:
    """Parse `cryptoscan scan --format json` output."""
    parsed = Parsed()
    for item in _items(_load_json(path), "findings", path, "cryptoscan JSON"):
        raw_id = str(item.get("id", ""))
        match = _CRYPTOSCAN_ID.match(raw_id)
        pattern_id = match.group("pattern") if match else raw_id
        families = _cryptoscan_families(pattern_id, item)
        if not families:
            parsed.unmapped[pattern_id] += 1
            continue
        # A dependency's quantumRisk rates the library as a whole (node-forge VULNERABLE,
        # Bouncy Castle SAFE), not each algorithm it provides, so use the family default.
        source_risk = None if _is_dependency(item) else item.get("quantumRisk")
        for family in families:
            parsed.findings.append(
                Finding(
                    source="cryptoscan",
                    file=_relative(str(item.get("file", "")), root),
                    line=_line(item.get("line"), path),
                    family=family,
                    risk=normalise_risk(source_risk, family),
                    rule_id=pattern_id,
                    message=str(item.get("description") or item.get("type") or pattern_id),
                    extra={"category": item.get("category"), "confidence": item.get("confidence")},
                )
            )
    return parsed


_SEMGREP_ID = re.compile(r"pqc\.[a-z]+\.[\w-]+$")


def parse_semgrep(path: Path, root: Path) -> Parsed:
    """Parse `semgrep --json` output produced with the pqc-rules ruleset."""
    parsed = Parsed()
    for item in _items(_load_json(path), "results", path, "Semgrep JSON"):
        extra = _object(item.get("extra"), "result 'extra'", path)
        meta = _object(extra.get("metadata"), "result metadata", path)
        check_id = str(item.get("check_id", ""))
        # Semgrep prefixes the rule id with the config path (e.g. "w.rules.javascript.pqc.javascript.rsa").
        id_match = _SEMGREP_ID.search(check_id)
        rule_id = id_match.group(0) if id_match else check_id
        family = normalise_family(meta.get("pqc-family"))
        if family is None:
            parsed.unmapped[rule_id] += 1
            continue
        parsed.findings.append(
            Finding(
                source="semgrep",
                file=_relative(str(item.get("path", "")), root),
                line=_line(_object(item.get("start"), "result 'start'", path).get("line"), path),
                family=family,
                risk=normalise_risk(meta.get("pqc-risk"), family),
                rule_id=rule_id,
                message=str(extra.get("message", "")).strip(),
            )
        )
    return parsed


PARSERS = {
    "cryptoscan": parse_cryptoscan,
    "semgrep": parse_semgrep,
}
