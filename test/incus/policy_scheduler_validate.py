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
    if value is None or isinstance(value, bool):
        return default
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


def _counter_int(label: str, rule_id: str, field: str, value: Any) -> int:
    if type(value) is not int or value < 0:
        raise ValidationFailure(
            f"{label}: policy_rule_counters entry {rule_id!r} field {field!r} "
            f"must be a non-negative integer, got {value!r}"
        )
    return value


def _policy_counters(label: str, status: dict[str, Any]) -> dict[str, PolicyCounter]:
    rows = status.get("policy_rule_counters", [])
    if not isinstance(rows, list):
        raise ValidationFailure(f"{label}: policy_rule_counters must be a list")
    result: dict[str, PolicyCounter] = {}
    for counter in rows:
        if not isinstance(counter, dict):
            raise ValidationFailure(
                f"{label}: policy_rule_counters entries must be objects"
            )
        rule_id = counter.get("rule_id")
        if not isinstance(rule_id, str) or not rule_id:
            raise ValidationFailure(
                f"{label}: policy_rule_counters entry has invalid rule_id {rule_id!r}"
            )
        if rule_id in result:
            raise ValidationFailure(
                f"{label}: duplicate policy_rule_counters entry {rule_id!r}"
            )
        result[rule_id] = PolicyCounter(
            packets=_counter_int(label, rule_id, "packets", counter.get("packets")),
            bytes=_counter_int(label, rule_id, "bytes", counter.get("bytes")),
        )
    return result


def _policy_counter(label: str, status: dict[str, Any], rule_id: str) -> PolicyCounter:
    counters = _policy_counters(label, status)
    try:
        return counters[rule_id]
    except KeyError as exc:
        raise ValidationFailure(
            f"{label}: missing policy_rule_counters entry {rule_id!r}"
        ) from exc


def _fallthrough_packets(
    counters: dict[str, PolicyCounter], rule_id: str
) -> int:
    prefix, separator, _ = rule_id.partition("/")
    if not separator or not prefix:
        return 0
    zone_pair_prefix = prefix + "/"
    return sum(
        counter.packets
        for candidate, counter in counters.items()
        if candidate.startswith(zone_pair_prefix) and candidate != rule_id
    )


def _read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except FileNotFoundError as exc:
        raise ValidationFailure(f"missing artifact: {path}") from exc


_PING_STATS_RE = re.compile(
    r"^\s*(\d+) packets transmitted, (\d+) (?:packets )?received, "
    r"(\d+(?:\.\d+)?)% packet loss",
    re.MULTILINE,
)


def _inactive_traffic_witness(path: Path, min_packets: int) -> dict[str, Any]:
    text = _read_text(path)
    matches = _PING_STATS_RE.findall(text)
    if len(matches) != 1:
        raise ValidationFailure(
            f"inactive: expected exactly one ping statistics block in "
            f"{path.name}, found {len(matches)}"
        )
    transmitted_str, received_str, loss_str = matches[0]
    transmitted = int(transmitted_str)
    received = int(received_str)
    loss_pct = float(loss_str)
    if transmitted < min_packets:
        raise ValidationFailure(
            f"inactive: traffic witness offered {transmitted} packets during "
            f"the inactive scheduler window, want >= {min_packets}"
        )
    allowed = received == transmitted and loss_pct == 0.0
    denied = received == 0 and loss_pct == 100.0
    if not (allowed or denied):
        raise ValidationFailure(
            "inactive: traffic witness is not decisive "
            f"(transmitted={transmitted}, received={received}, "
            f"loss={loss_str}%); want full success or full deny while the "
            "scheduled rule is inactive"
        )
    return {
        "transmitted": transmitted,
        "received": received,
        "loss_pct": loss_pct,
        "outcome": "allowed" if allowed else "denied",
    }


def validate_artifacts(
    root: Path,
    *,
    rule_id: str,
    active_status: str = "active-status.json",
    rebuild_status: str = "rebuild-status.json",
    inactive_status: str = "inactive-status.json",
    inactive_traffic: str = "inactive-traffic.stdout",
    failover_status: str | None = "failover-status.json",
    missing_scheduler_output: str = "missing-scheduler-commit.txt",
    min_active_packets: int = 1,
    min_inactive_packets: int = 1,
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

    rebuild_counters = _policy_counters("rebuild", rebuild)
    inactive_counters = _policy_counters("inactive", inactive)
    active_counter = _policy_counter("active", active, rule_id)
    rebuild_counter = rebuild_counters.get(rule_id)
    inactive_counter = inactive_counters.get(rule_id)
    if rebuild_counter is None:
        raise ValidationFailure(
            f"rebuild: missing policy_rule_counters entry {rule_id!r}"
        )
    if inactive_counter is None:
        raise ValidationFailure(
            f"inactive: missing policy_rule_counters entry {rule_id!r}"
        )

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

    inactive_witness = _inactive_traffic_witness(
        root / inactive_traffic, min_inactive_packets
    )
    if inactive_witness["outcome"] == "allowed":
        rebuild_fallthrough = _fallthrough_packets(rebuild_counters, rule_id)
        inactive_fallthrough = _fallthrough_packets(inactive_counters, rule_id)
        fallthrough_delta = inactive_fallthrough - rebuild_fallthrough
        if fallthrough_delta < min_inactive_packets:
            raise ValidationFailure(
                "inactive: fall-through policy counters did not advance by the "
                "offered traffic "
                f"({fallthrough_delta} < {min_inactive_packets})"
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
        if failover_counter.bytes < rebuild_counter.bytes:
            raise ValidationFailure(
                "failover: policy bytes went backward "
                f"({failover_counter.bytes} < {rebuild_counter.bytes})"
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
        "inactive_traffic": inactive_witness,
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
    parser.add_argument("--inactive-traffic", default="inactive-traffic.stdout")
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
    parser.add_argument("--min-inactive-packets", type=int, default=1)
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
            inactive_traffic=args.inactive_traffic,
            failover_status=None if args.no_failover else args.failover_status,
            missing_scheduler_output=args.missing_scheduler_output,
            min_active_packets=args.min_active_packets,
            min_inactive_packets=args.min_inactive_packets,
            min_failover_packet_delta=args.min_failover_packet_delta,
        )
    except ValidationFailure as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
