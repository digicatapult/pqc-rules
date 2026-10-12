"""Group findings across sources and decide how credible each group is."""

from __future__ import annotations

import fnmatch
from collections import defaultdict
from dataclasses import dataclass, field

from .families import COARSE_RISK, RISK_ORDER, match_key
from .normalise import Finding

CORROBORATED = "corroborated"
SINGLE_SOURCE = "single-source"
CONFLICTING = "conflicting"
RUNTIME = "runtime"

# Single-source findings that are facts rather than pattern guesses.
# cryptoscan KEY-001..006 match PEM private-key headers committed to the repo;
# the TLS entries are direct observations of a running localhost service.
DEFAULT_ALLOWLIST: tuple[str, ...] = (
    "cryptoscan:KEY-00*",
    "tls-analyzer:tls.certificate-key",
    "tls-analyzer:tls.negotiated-key-exchange",
    "tls-analyzer:tls.legacy-protocol",
)


@dataclass
class Group:
    """Findings that refer to the same crypto at (roughly) the same place."""

    findings: list[Finding] = field(default_factory=list)
    evidence: str = SINGLE_SOURCE
    allowlisted: bool = False

    @property
    def sources(self) -> list[str]:
        return sorted({f.source for f in self.findings})

    @property
    def anchor(self) -> Finding:
        """The finding on the line most sources agree on (earliest line breaks ties)."""
        votes: dict[int, set[str]] = defaultdict(set)
        for finding in self.findings:
            votes[finding.line].add(finding.source)
        best_line = min(votes, key=lambda line: (-len(votes[line]), line))
        return min((f for f in self.findings if f.line == best_line), key=lambda f: f.source)

    @property
    def risk(self) -> str:
        """Most severe risk any source assigned (RISK_ORDER is worst-first)."""
        return min((f.risk for f in self.findings), key=RISK_ORDER.index)

    @property
    def coarse_risk(self) -> str:
        return COARSE_RISK[self.risk]


def _cluster(findings: list[Finding], window: int) -> list[list[Finding]]:
    """Single-link clustering on line distance within one (file, family) bucket."""
    ordered = sorted(findings, key=lambda f: f.line)
    clusters: list[list[Finding]] = []
    for finding in ordered:
        if clusters and finding.line - clusters[-1][-1].line <= window:
            clusters[-1].append(finding)
        else:
            clusters.append([finding])
    return clusters


def _is_conflicting(group: Group) -> bool:
    known = {COARSE_RISK[f.risk] for f in group.findings if f.risk != "unknown"}
    return len(known) > 1


def _allowlisted(group: Group, patterns: tuple[str, ...]) -> bool:
    return any(
        fnmatch.fnmatchcase(f"{f.source}:{f.rule_id}", pattern)
        for f in group.findings
        for pattern in patterns
    )


def correlate(findings: list[Finding], window: int, allowlist: tuple[str, ...]) -> list[Group]:
    """Return every finding grouped, each group labelled with an evidence level."""
    if window < 0:
        raise ValueError(f"line window must be >= 0, got {window}")
    buckets: dict[tuple[str, str], list[Finding]] = defaultdict(list)
    groups: list[Group] = []
    for finding in findings:
        if finding.is_runtime:
            groups.append(Group([finding], evidence=RUNTIME))
        else:
            buckets[(finding.file, match_key(finding.family))].append(finding)
    for bucket in buckets.values():
        groups.extend(Group(cluster) for cluster in _cluster(bucket, window))

    for group in groups:
        if group.evidence != RUNTIME:
            if _is_conflicting(group):
                group.evidence = CONFLICTING
            elif len(group.sources) >= 2:
                group.evidence = CORROBORATED
        group.allowlisted = _allowlisted(group, allowlist)
    groups.sort(key=lambda g: (g.anchor.file, g.anchor.line, g.anchor.family))
    return groups


def reportable(group: Group) -> bool:
    """Whether a group is credible *and* actionable enough for the Security tab.

    Only quantum-vulnerable or classically broken crypto is reported; safe,
    hybrid and partial findings stay in the artefacts. Conflicting groups are
    never reported, even if allowlisted, because the sources disagree.
    """
    if group.coarse_risk != "at-risk" or group.evidence == CONFLICTING:
        return False
    return group.evidence == CORROBORATED or group.allowlisted
