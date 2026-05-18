#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any


class ValidationFailure(Exception):
    pass


@dataclass(frozen=True)
class PolicyCounter:
    packets: int
    bytes: int


def _load_json(path: Path) -> dict[str, Any]:
    try:
        with path.open("r", encoding="utf-8") as f:
            value = json.load(f)
    except FileNotFoundError as exc:
        raise ValidationFailure(f"missing artifact: {path}") from exc
    except json.JSONDecodeError as exc:
        raise ValidationFailure(f"{path}: invalid JSON: {exc}") from exc
    if not isinstance(value, dict):
        raise ValidationFailure(f"{path}: top-level JSON must be an object")
    return value


def _status_from_doc(path: Path) -> dict[str, Any]:
    doc = _load_json(path)
    if "ok" in doc and doc.get("ok") is not True:
        raise ValidationFailure(f"{path}: control response ok != true")
    status = doc.get("status", doc)
    if not isinstance(status, dict):
        raise ValidationFailure(f"{path}: status must be an object")
    return status


def _as_int(value: Any, default: int = 0) -> int:
    if value is None:
        return default
    if isinstance(value, bool):
        return int(value)
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _require_userspace_runtime(label: str, status: dict[str, Any]) -> None:
    version = _as_int(status.get("config_snapshot_protocol_version"))
    if version < 2:
        raise ValidationFailure(
            f"{label}: config_snapshot_protocol_version={version}, want >= 2"
        )

    capabilities = status.get("capabilities", {})
    if not isinstance(capabilities, dict):
        raise ValidationFailure(f"{label}: capabilities must be an object")
    if capabilities.get("forwarding_supported") is not True:
        raise ValidationFailure(f"{label}: forwarding_supported is not true")
    if status.get("forwarding_armed") is not True:
        raise ValidationFailure(f"{label}: forwarding_armed is not true")
    if status.get("enabled") is not True:
        raise ValidationFailure(f"{label}: userspace helper enabled is not true")

    mode = status.get("dataplane_mode")
    if mode == "ebpf_only":
        raise ValidationFailure(f"{label}: dataplane_mode is ebpf_only")

    programs = status.get("entry_programs")
    if not isinstance(programs, dict) or not programs:
        raise ValidationFailure(f"{label}: entry_programs must be a non-empty object")
    if not any("xdp_userspace" in str(name) for name in programs.values()):
        raise ValidationFailure(
            f"{label}: entry_programs do not show xdp_userspace attachment"
        )


def _policy_counter(label: str, status: dict[str, Any], rule_id: str) -> PolicyCounter:
    counters = status.get("policy_rule_counters", [])
    if not isinstance(counters, list):
        raise ValidationFailure(f"{label}: policy_rule_counters must be a list")
    for counter in counters:
        if isinstance(counter, dict) and counter.get("rule_id") == rule_id:
            return PolicyCounter(
                packets=_as_int(counter.get("packets")),
                bytes=_as_int(counter.get("bytes")),
            )
    raise ValidationFailure(f"{label}: missing policy_rule_counters entry {rule_id!r}")


def _read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except FileNotFoundError as exc:
        raise ValidationFailure(f"missing artifact: {path}") from exc


def validate_artifacts(
    root: Path,
    *,
    rule_id: str,
    active_status: str = "active-status.json",
    rebuild_status: str = "rebuild-status.json",
    inactive_status: str = "inactive-status.json",
    failover_status: str | None = "failover-status.json",
    missing_scheduler_output: str = "missing-scheduler-commit.txt",
    min_active_packets: int = 1,
    min_failover_packet_delta: int = 1,
) -> dict[str, Any]:
    active = _status_from_doc(root / active_status)
    rebuild = _status_from_doc(root / rebuild_status)
    inactive = _status_from_doc(root / inactive_status)
    statuses = [
        ("active", active),
        ("rebuild", rebuild),
        ("inactive", inactive),
    ]
    failover: dict[str, Any] | None = None
    if failover_status is not None:
        failover = _status_from_doc(root / failover_status)
        statuses.append(("failover", failover))

    for label, status in statuses:
        _require_userspace_runtime(label, status)

    active_counter = _policy_counter("active", active, rule_id)
    rebuild_counter = _policy_counter("rebuild", rebuild, rule_id)
    inactive_counter = _policy_counter("inactive", inactive, rule_id)

    if active_counter.packets < min_active_packets:
        raise ValidationFailure(
            f"active: packets={active_counter.packets}, want >= {min_active_packets}"
        )
    if rebuild_counter.packets < active_counter.packets:
        raise ValidationFailure(
            "rebuild: policy counter went backward "
            f"({rebuild_counter.packets} < {active_counter.packets})"
        )
    if rebuild_counter.bytes < active_counter.bytes:
        raise ValidationFailure(
            "rebuild: policy bytes went backward "
            f"({rebuild_counter.bytes} < {active_counter.bytes})"
        )
    if inactive_counter != rebuild_counter:
        raise ValidationFailure(
            "inactive: scheduled rule counter changed while scheduler was inactive "
            f"(inactive={inactive_counter}, rebuild={rebuild_counter})"
        )

    failover_counter: PolicyCounter | None = None
    if failover is not None:
        failover_counter = _policy_counter("failover", failover, rule_id)
        required = rebuild_counter.packets + min_failover_packet_delta
        if failover_counter.packets < required:
            raise ValidationFailure(
                "failover: policy counter did not advance on the new userspace owner "
                f"({failover_counter.packets} < {required})"
            )

    missing_text = _read_text(root / missing_scheduler_output)
    if not re.search(r"references undefined scheduler|scheduler .+ not defined", missing_text):
        raise ValidationFailure(
            "missing scheduler commit artifact does not contain the strict rejection"
        )
    if re.search(r"\bcommit complete\b|\bcommit successful\b", missing_text, re.I):
        raise ValidationFailure(
            "missing scheduler commit artifact looks like a successful commit"
        )

    summary: dict[str, Any] = {
        "verdict": "PASS",
        "rule_id": rule_id,
        "active": active_counter.__dict__,
        "rebuild": rebuild_counter.__dict__,
        "inactive": inactive_counter.__dict__,
    }
    if failover_counter is not None:
        summary["failover"] = failover_counter.__dict__
    return summary


def _parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Validate #1378 userspace policy scheduler evidence artifacts."
    )
    parser.add_argument("artifact_dir", type=Path)
    parser.add_argument(
        "--rule-id",
        default="trust->untrust/scheduled-allow",
        help="stable userspace policy rule_id to validate",
    )
    parser.add_argument("--active-status", default="active-status.json")
    parser.add_argument("--rebuild-status", default="rebuild-status.json")
    parser.add_argument("--inactive-status", default="inactive-status.json")
    parser.add_argument("--failover-status", default="failover-status.json")
    parser.add_argument(
        "--no-failover",
        action="store_true",
        help="skip failover-status.json validation",
    )
    parser.add_argument(
        "--missing-scheduler-output",
        default="missing-scheduler-commit.txt",
    )
    parser.add_argument("--min-active-packets", type=int, default=1)
    parser.add_argument("--min-failover-packet-delta", type=int, default=1)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(list(sys.argv[1:] if argv is None else argv))
    try:
        summary = validate_artifacts(
            args.artifact_dir,
            rule_id=args.rule_id,
            active_status=args.active_status,
            rebuild_status=args.rebuild_status,
            inactive_status=args.inactive_status,
            failover_status=None if args.no_failover else args.failover_status,
            missing_scheduler_output=args.missing_scheduler_output,
            min_active_packets=args.min_active_packets,
            min_failover_packet_delta=args.min_failover_packet_delta,
        )
    except ValidationFailure as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
