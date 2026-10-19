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

# Sources whose findings are rule-precise: each one is a distinct finding and is never
# merged with another finding from the same source, however close it is.
ANCHOR_SOURCES: frozenset[str] = frozenset({"semgrep"})


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
        """The anchor-source finding if there is one, else the line most sources agree on.

        Ties between lines resolve to the earliest line.
        """
        anchors = [f for f in self.findings if f.source in ANCHOR_SOURCES]
        if anchors:
            return min(anchors, key=lambda f: (f.line, f.rule_id))
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


def _attach_to_anchors(findings: list[Finding], window: int) -> list[list[Finding]]:
    """Group one (file, family) bucket around its anchor findings.

    Every anchor finding starts its own group, so distinct calls on neighbouring
    lines (an RSA key and an RS256 JWT, say) stay separate. Every other finding
    joins the nearest anchor within the window; an exact line match always wins,
    and equally distant anchors resolve to the earlier line. Findings with no
    anchor in range are clustered among themselves, as before.
    """
    anchors = sorted((f for f in findings if f.source in ANCHOR_SOURCES), key=lambda f: (f.line, f.rule_id))
    groups: list[list[Finding]] = [[anchor] for anchor in anchors]
    unattached: list[Finding] = []
    for finding in findings:
        if finding.source in ANCHOR_SOURCES:
            continue
        distances = [(abs(finding.line - anchor.line), anchor.line, index) for index, anchor in enumerate(anchors)]
        in_range = [d for d in distances if d[0] <= window]
        if in_range:
            groups[min(in_range)[2]].append(finding)
        else:
            unattached.append(finding)
    return groups + _cluster(unattached, window)


def _cluster(findings: list[Finding], window: int) -> list[list[Finding]]:
    """Cluster findings for buckets with no anchor findings.

    A cluster spans at most `window` lines from its first finding, so a run of
    findings a few lines apart cannot chain into one group of unbounded length.
    """
    ordered = sorted(findings, key=lambda f: f.line)
    clusters: list[list[Finding]] = []
    for finding in ordered:
        if clusters and finding.line - clusters[-1][0].line <= window:
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
        buckets[(finding.file, match_key(finding.family))].append(finding)
    for bucket in buckets.values():
        groups.extend(Group(cluster) for cluster in _attach_to_anchors(bucket, window))

    for group in groups:
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
