#!/usr/bin/env python3
"""Reject hand-rolled Incus binary pushes in Claude skills."""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SKILLS = Path(".claude/skills")
_FORBIDDEN = re.compile(r"\bincus\s+file\s+push\b", re.IGNORECASE)


def findings(root: Path = ROOT) -> list[str]:
    """Return skill-file locations that document a manual binary push."""
    skill_root = root / SKILLS
    if not skill_root.is_dir():
        return [f"{SKILLS}: skills directory is missing"]

    found: list[str] = []
    for path in sorted(skill_root.rglob("*.md")):
        for number, line in enumerate(
            path.read_text(encoding="utf-8").splitlines(), 1
        ):
            if _FORBIDDEN.search(line):
                found.append(f"{path.relative_to(root)}:{number}: {line.strip()}")
    return found


def main() -> int:
    matches = findings()
    if matches:
        print("Claude skill lint: hand-rolled Incus binary pushes are forbidden:", file=sys.stderr)
        print("\n".join(matches), file=sys.stderr)
        return 1
    print("Claude skill lint: no hand-rolled Incus binary pushes")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
