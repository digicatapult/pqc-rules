#!/usr/bin/env python3
"""Verify TypeScript fixtures alongside the JavaScript ones.

Semgrep's --test mode auto-discovers a single fixture per rule (matching the
rule file's basename). To guarantee the rules also match through the TypeScript
parser path, we add parallel .ts fixtures and verify them with this script.

For every .ts file under rules/javascript/, this script:
  - Parses `// ruleid: <id>` markers and asserts the next code line matches <id>.
  - Parses `// ok: <id>` markers and asserts the next code line does NOT match <id>.
  - Asserts there are no unexpected matches.
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
FIXTURES = sorted((REPO / "rules" / "javascript").glob("*.ts"))

RULEID_RE = re.compile(r"//\s*ruleid:\s*(\S+)")
OK_RE = re.compile(r"//\s*ok:\s*(\S+)")


def _next_code_line(lines: list[str], start: int) -> int | None:
    """Return 0-indexed index of the next non-blank, non-comment-only line."""
    for i in range(start, len(lines)):
        stripped = lines[i].strip()
        if stripped and not stripped.startswith("//"):
            return i
    return None


def parse_markers(path: Path) -> tuple[dict[int, str], dict[int, str]]:
    """Return ({1-indexed match line: rule_id}, {1-indexed protected line: rule_id})."""
    expected: dict[int, str] = {}
    ok: dict[int, str] = {}
    lines = path.read_text().splitlines()
    for i, line in enumerate(lines):
        m = RULEID_RE.search(line)
        if m:
            nxt = _next_code_line(lines, i + 1)
            if nxt is not None:
                expected[nxt + 1] = m.group(1)
        m = OK_RE.search(line)
        if m:
            nxt = _next_code_line(lines, i + 1)
            if nxt is not None:
                ok[nxt + 1] = m.group(1)
    return expected, ok


def short_rule_id(check_id: str) -> str:
    return ".".join(check_id.split(".")[-3:])


def run_semgrep(path: Path) -> list[dict]:
    proc = subprocess.run(
        [
            "semgrep", "scan",
            "--config", str(REPO / "rules"),
            "--json", "--quiet", "--no-git-ignore",
            str(path),
        ],
        capture_output=True, text=True, check=True,
    )
    return json.loads(proc.stdout)["results"]


def check(path: Path) -> list[str]:
    expected, ok = parse_markers(path)
    findings = run_semgrep(path)

    actual: dict[int, str] = {f["start"]["line"]: short_rule_id(f["check_id"]) for f in findings}
    errors: list[str] = []

    for line, rule_id in expected.items():
        if actual.get(line) != rule_id:
            errors.append(f"  line {line}: expected {rule_id}, got {actual.get(line) or 'no match'}")
    for line, rule_id in ok.items():
        if actual.get(line) == rule_id:
            errors.append(f"  line {line}: rule {rule_id} fired but was marked ok")
    for line, rule_id in actual.items():
        if line not in expected:
            errors.append(f"  line {line}: unexpected match for {rule_id}")

    return errors


def main() -> int:
    failed = 0
    for fixture in FIXTURES:
        errors = check(fixture)
        if errors:
            failed += 1
            print(f"FAIL {fixture.relative_to(REPO)}")
            for e in errors:
                print(e)
        else:
            print(f"OK   {fixture.relative_to(REPO)}")
    if failed:
        print(f"\n{failed}/{len(FIXTURES)} TypeScript fixtures failed.")
        return 1
    print(f"\nAll {len(FIXTURES)} TypeScript fixtures verified.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
