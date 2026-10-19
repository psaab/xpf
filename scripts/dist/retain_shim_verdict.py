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
_TOOLCHAIN_TOML = Path("userspace-xdp/rust-toolchain.toml")

# Mirrors ShimPinnedBPFLinkerVersion in pkg/dataplane and
# PINNED_BPF_LINKER_VERSION in build-userspace-xdp.sh (#15218).
_PINNED_BPF_LINKER = "0.10.2"
# SHA-256 of "RUSTFLAGS=\nCARGO_ENCODED_RUSTFLAGS=\n": the scrubbed
# codegen environment build-userspace-xdp.sh enforces (#15218).
_WELL_KNOWN_CODEGEN_ENV_DIGEST = hashlib.sha256(b"RUSTFLAGS=\nCARGO_ENCODED_RUSTFLAGS=\n").hexdigest()


def _pinned_toolchain(repo_root: Path) -> str:
    """Parse the pinned channel exactly as the build recipe does."""
    try:
        lines = (repo_root / _TOOLCHAIN_TOML).read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise ValueError(f"cannot read toolchain pin: {exc}") from exc
    in_toolchain = False
    channels: list[str] = []
    for line in lines:
        trimmed = line.strip()
        if trimmed.startswith("["):
            in_toolchain = trimmed == "[toolchain]"
            continue
        if not in_toolchain or "=" not in trimmed:
            continue
        key, _, value = trimmed.partition("=")
        if key.strip() != "channel":
            continue
        channels.append(value.split("#", 1)[0].strip().strip("\"'"))
    if len(channels) != 1 or not channels[0].startswith("nightly-"):
        raise ValueError("toolchain pin (rust-toolchain.toml) is missing or ambiguous")
    return channels[0]


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
        or verdict["schema_version"] != 2
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

    # #15218: provenance. A verdict that cannot prove a pinned build
    # under the scrubbed codegen env is not retained: an unpinned or
    # RUSTFLAGS-tainted install must not reach a release as a PASS.
    provenance = verdict.get("provenance")
    if not isinstance(provenance, dict):
        raise ValueError("shim gate verdict records no build provenance")
    if provenance.get("pinned") is not True:
        raise ValueError("shim gate verdict was built with an unpinned toolchain")
    if provenance.get("toolchain") != _pinned_toolchain(repo_root):
        raise ValueError("shim gate verdict toolchain does not match the rust-toolchain.toml pin")
    if provenance.get("bpf_linker") != _PINNED_BPF_LINKER:
        raise ValueError("shim gate verdict bpf-linker does not match the pin")
    if provenance.get("codegen_env_digest") != _WELL_KNOWN_CODEGEN_ENV_DIGEST:
        raise ValueError("shim gate verdict was built under an unscrubbed codegen environment")

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
