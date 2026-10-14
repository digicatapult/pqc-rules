"""Every Semgrep rule must carry metadata the correlator understands.

A rule whose `pqc-family` is not a canonical family, or whose `pqc-risk` is not a
known risk, still validates and passes `semgrep --test`, but the correlator then
drops or misfiles its findings. These tests close that gap rule by rule.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from ruamel.yaml import YAML  # Installed with Semgrep, which already parses these files with it.

from pqc_correlate.families import RISK_ORDER, normalise_family

RULES_DIR = Path(__file__).resolve().parents[2] / "rules"


def _rules() -> list[tuple[str, dict[str, Any]]]:
    yaml = YAML(typ="safe")
    out = []
    for path in sorted(RULES_DIR.rglob("*.yaml")):
        for rule in yaml.load(path.read_text(encoding="utf-8"))["rules"]:
            out.append((f"{path.relative_to(RULES_DIR)}:{rule['id']}", rule))
    return out


RULES = _rules()


def test_rules_were_found() -> None:
    assert len(RULES) >= 60


@pytest.mark.parametrize(("where", "rule"), RULES, ids=[where for where, _ in RULES])
def test_rule_family_is_canonical(where: str, rule: dict[str, Any]) -> None:
    family = (rule.get("metadata") or {}).get("pqc-family")
    assert family, f"{where} has no pqc-family"
    assert normalise_family(family) == family, f"{where}: pqc-family {family!r} is not a canonical family"


@pytest.mark.parametrize(("where", "rule"), RULES, ids=[where for where, _ in RULES])
def test_rule_risk_is_known(where: str, rule: dict[str, Any]) -> None:
    risk = (rule.get("metadata") or {}).get("pqc-risk")
    assert risk in RISK_ORDER, f"{where}: pqc-risk {risk!r} is not one of {RISK_ORDER}"
