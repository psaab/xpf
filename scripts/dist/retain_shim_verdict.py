#!/usr/bin/env python3
"""Validate and attach the shim verifier verdict to a GitHub release."""

from __future__ import annotations

import hashlib
import json
import math
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from typing import Callable


_OBJECT = Path("pkg/dataplane/userspace_xdp_bpfel.o")
_VERDICT = Path("pkg/dataplane/userspace_xdp_gate_verdict.json")


def validate_verdict(repo_root: Path) -> Path:
    """Fail closed unless the sidecar is a complete verdict for this object."""
    object_path = repo_root / _OBJECT
    verdict_path = repo_root / _VERDICT
    try:
        verdict = json.loads(verdict_path.read_text(encoding="utf-8"))
        actual_hash = hashlib.sha256(object_path.read_bytes()).hexdigest()
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"cannot read release object/verdict: {exc}") from exc

    if (
        not isinstance(verdict, dict)
        or type(verdict.get("schema_version")) is not int
        or verdict["schema_version"] != 1
    ):
        raise ValueError("unsupported or missing shim gate-verdict schema")
    if verdict.get("object_sha256") != actual_hash:
        raise ValueError("shim gate verdict does not match the release object's SHA-256")
    label = verdict.get("verdict")
    override = verdict.get("override_consumed")
    if not isinstance(label, str) or label not in {"PASS", "OVERRIDDEN"} or not isinstance(override, bool):
        raise ValueError("shim gate verdict has an invalid verdict/override field")
    if override != (label == "OVERRIDDEN"):
        raise ValueError("shim gate verdict and override bit disagree")
    if not isinstance(verdict.get("reason"), str) or not verdict["reason"].strip():
        raise ValueError("shim gate verdict has no reason")
    try:
        verified_at = datetime.fromisoformat(verdict["verified_at"].replace("Z", "+00:00"))
    except (KeyError, AttributeError, TypeError, ValueError) as exc:
        raise ValueError("shim gate verdict has no valid verification timestamp") from exc
    if verified_at.tzinfo is None:
        raise ValueError("shim gate verdict timestamp must include a timezone")

    stats = verdict.get("stats")
    if not isinstance(stats, dict) or not isinstance(stats.get("measured"), bool):
        raise ValueError("shim gate verdict has no verifier stats")
    if stats["measured"]:
        if not all(type(stats.get(key)) is int and stats[key] > 0 for key in ("processed_insns", "insn_limit")):
            raise ValueError("measured shim gate verdict has invalid verifier counts")
        if not all(
            type(stats.get(key)) in (int, float)
            and math.isfinite(stats[key])
            and 0 <= stats[key] <= 100
            for key in ("headroom_pct", "floor_pct")
        ) or stats["floor_pct"] == 0:
            raise ValueError("measured shim gate verdict has invalid headroom stats")
        if type(stats.get("slack_to_floor_insns")) is not int:
            raise ValueError("measured shim gate verdict has invalid slack stats")
        if label == "PASS" and stats["headroom_pct"] < stats["floor_pct"]:
            raise ValueError("passing shim gate verdict is below its recorded floor")
        if override and stats["headroom_pct"] >= stats["floor_pct"]:
            raise ValueError("shim gate override was recorded although measured headroom met the floor")
    elif not override:
        raise ValueError("unmeasured shim gate verdict was not explicitly overridden")
    elif any(stats.get(key) != 0 for key in ("processed_insns", "insn_limit", "headroom_pct", "slack_to_floor_insns")):
        raise ValueError("unmeasured shim gate verdict has nonzero measured stats")
    return verdict_path


def upload_verdict(repo_root: Path, tag: str, run: Callable[..., object] = subprocess.run) -> None:
    verdict_path = validate_verdict(repo_root)
    run(["gh", "release", "upload", tag, str(verdict_path), "--clobber"], check=True)


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if len(args) != 1 or not args[0]:
        print("usage: retain_shim_verdict.py <release-tag>", file=sys.stderr)
        return 2
    try:
        upload_verdict(Path.cwd(), args[0])
    except (OSError, ValueError, subprocess.CalledProcessError) as exc:
        print(f"retain-shim-verdict: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
