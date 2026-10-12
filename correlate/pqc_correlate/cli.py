"""Command-line entry point: python -m pqc_correlate ..."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .correlate import DEFAULT_ALLOWLIST, correlate
from .normalise import PARSERS, Finding, InputError
from .outputs import to_cbom, to_json, to_sarif, to_summary

OUTPUT_FILES = {
    "all": "pqc-all.json",
    "cbom": "pqc-cbom.cdx.json",
    "sarif": "pqc-security.sarif",
    "summary": "pqc-summary.md",
}


def _parse_args(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(prog="pqc_correlate", description=__doc__)
    for source in PARSERS:
        parser.add_argument(f"--{source}", action="append", default=[], type=Path,
                            metavar="FILE", help=f"{source} output (repeatable)")
    parser.add_argument("--root", type=Path, default=Path.cwd(),
                        help="repository root that file paths are made relative to")
    parser.add_argument("--out", type=Path, required=True, help="directory to write artefacts to")
    parser.add_argument("--window", type=int, default=3,
                        help="max line distance for findings to be treated as the same (default 3)")
    parser.add_argument("--allowlist-extra", default="",
                        help="comma-separated SOURCE:RULE_ID globs to report even when single-source")
    parser.add_argument("--allowlist-disable", action="store_true",
                        help="drop the default allowlist; only corroborated findings are reported")
    parser.add_argument("--runtime-anchor", default="README.md",
                        help="repo file that runtime (TLS) results are attached to in SARIF")
    parser.add_argument("--expected", default="",
                        help="comma-separated sources the caller enabled, to flag any that produced no input")
    return parser.parse_args(argv)


def _allowlist(args: argparse.Namespace) -> tuple[str, ...]:
    extra = tuple(p.strip() for p in args.allowlist_extra.split(",") if p.strip())
    for pattern in extra:
        if ":" not in pattern:
            raise InputError(f"allowlist entry {pattern!r} must be SOURCE:RULE_ID (e.g. semgrep:pqc.javascript.rsa)")
    return extra if args.allowlist_disable else DEFAULT_ALLOWLIST + extra


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    try:
        allowlist = _allowlist(args)
        findings: list[Finding] = []
        sources_run: list[str] = []
        for source, parser in PARSERS.items():
            paths: list[Path] = getattr(args, source)
            for path in paths:
                findings.extend(parser(path, args.root))
            if paths:
                sources_run.append("tls-analyzer" if source == "tls" else source)
        groups = correlate(findings, args.window, allowlist)
    except (InputError, ValueError) as exc:
        print(f"pqc_correlate: error: {exc}", file=sys.stderr)
        return 2

    expected = [s.strip() for s in args.expected.split(",") if s.strip()]
    args.out.mkdir(parents=True, exist_ok=True)
    (args.out / OUTPUT_FILES["all"]).write_text(json.dumps(to_json(groups, sources_run), indent=2))
    (args.out / OUTPUT_FILES["cbom"]).write_text(json.dumps(to_cbom(groups), indent=2))
    (args.out / OUTPUT_FILES["sarif"]).write_text(json.dumps(to_sarif(groups, args.runtime_anchor), indent=2))
    (args.out / OUTPUT_FILES["summary"]).write_text(to_summary(groups, sources_run, expected))
    return 0


if __name__ == "__main__":
    sys.exit(main())
