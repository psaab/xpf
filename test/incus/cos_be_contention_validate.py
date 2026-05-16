#!/usr/bin/env python3
"""Validate CoS exact-vs-best-effort contention harness artifacts.

The live shell harness records a manifest, iperf3 JSON summaries, iperf exit
codes, and before/during/after userspace dataplane status snapshots. This
module deliberately validates only those reduced artifacts so CI can exercise
the fail-closed rules without a running Incus cluster.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import json
import math
from pathlib import Path
import sys
from typing import Any


DEFAULT_MAX_EXACT_DROP_RATIO = 0.15
DEFAULT_WRONG_QUEUE_SENT_BYTES_TOLERANCE = 0
DEFAULT_MIN_EXPECTED_SENT_BYTES = 1
DEFAULT_MIN_CONTENDER_BPS = 100_000_000.0
DEFAULT_MIN_EXACT_BASELINE_CAP_RATIO = 0.70
DEFAULT_MIN_CONTENDED_ROOT_PRESSURE_RATIO = 0.90
DEFAULT_ROOT_SHAPE_BPS = 25_000_000_000.0

FORWARDING_CLASS_BY_PORT = {
    5200: "best-effort",
    5201: "iperf-100m",
    5202: "iperf-1g",
    5203: "iperf-3g",
    5204: "iperf-6g",
    5205: "iperf-9g",
    5206: "iperf-12g",
    5207: "iperf-15g",
    5208: "iperf-18g",
    5209: "iperf-21g",
    5210: "iperf-24g",
    5211: "iperf-uncapped",
}

PORT_CAP_BPS_BY_PORT = {
    5201: 100_000_000.0,
    5202: 1_000_000_000.0,
    5203: 3_000_000_000.0,
    5204: 6_000_000_000.0,
    5205: 9_000_000_000.0,
    5206: 12_000_000_000.0,
    5207: 15_000_000_000.0,
    5208: 18_000_000_000.0,
    5209: 21_000_000_000.0,
    5210: 24_000_000_000.0,
}


class ValidationError(ValueError):
    pass


@dataclass(frozen=True)
class QueueShape:
    queue_id: int
    forwarding_class: str
    sent_bytes: int
    park_root: int
    park_queue: int


@dataclass(frozen=True)
class QueueDelta:
    queue_id: int
    forwarding_class: str
    sent_bytes: int
    park_root: int
    park_queue: int


def _finite_nonnegative_number(value: Any, field: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValidationError(f"{field} must be a number")
    out = float(value)
    if not math.isfinite(out) or out < 0:
        raise ValidationError(f"{field} must be finite and non-negative")
    return out


def _nonnegative_int(value: Any, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValidationError(f"{field} must be an integer")
    if value < 0:
        raise ValidationError(f"{field} must be non-negative")
    return value


def _forwarding_class(raw: Any, port: Any, field: str) -> str:
    if raw is not None:
        if not isinstance(raw, str) or raw == "":
            raise ValidationError(f"{field} must be a non-empty string")
        if isinstance(port, int) and port in FORWARDING_CLASS_BY_PORT:
            expected = FORWARDING_CLASS_BY_PORT[port]
            if raw != expected:
                raise ValidationError(
                    f"{field} {raw!r} does not match canonical class {expected!r} "
                    f"for port {port}"
                )
        return raw
    if isinstance(port, int) and port in FORWARDING_CLASS_BY_PORT:
        return FORWARDING_CLASS_BY_PORT[port]
    raise ValidationError(f"{field} is required for port {port!r}")


def _positive_bps(value: Any, field: str) -> float:
    out = _finite_nonnegative_number(value, field)
    if out <= 0:
        raise ValidationError(f"{field} must be positive")
    return out


def _exact_cap_bps(raw: Any, port: int, field: str) -> float:
    if raw is not None:
        return _positive_bps(raw, field)
    if port in PORT_CAP_BPS_BY_PORT:
        return PORT_CAP_BPS_BY_PORT[port]
    raise ValidationError(f"{field} is required for exact port {port}")


def _default_min_contender_bps(exact_cap_bps: float, root_shape_bps: float) -> float:
    root_headroom = max(root_shape_bps - exact_cap_bps, 0.0)
    if root_headroom > 0:
        return min(exact_cap_bps * 0.50, root_headroom)
    return exact_cap_bps * 0.05


def load_json(path: Path) -> dict[str, Any]:
    try:
        with path.open("r", encoding="utf-8") as f:
            value = json.load(f)
    except FileNotFoundError as exc:
        raise ValidationError(f"missing JSON artifact: {path}") from exc
    except json.JSONDecodeError as exc:
        raise ValidationError(f"invalid JSON artifact {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise ValidationError(f"JSON artifact must be an object: {path}")
    return value


def read_exit_code(path: Path) -> int:
    try:
        raw = path.read_text(encoding="utf-8").strip()
    except FileNotFoundError as exc:
        raise ValidationError(f"missing exit-code artifact: {path}") from exc
    try:
        code = int(raw)
    except ValueError as exc:
        raise ValidationError(f"invalid exit-code artifact {path}: {raw!r}") from exc
    if code < 0:
        raise ValidationError(f"invalid negative exit code in {path}: {code}")
    return code


def iperf_bps(artifact: dict[str, Any]) -> float:
    """Return the receiver-side iperf3 bits/sec summary when available."""
    end = artifact.get("end")
    if not isinstance(end, dict):
        raise ValidationError("iperf JSON missing object field end")

    candidate_paths = (
        ("end", "sum_received", "bits_per_second"),
        ("end", "sum", "bits_per_second"),
        ("end", "sum_sent", "bits_per_second"),
    )
    for _root, section, field in candidate_paths:
        value = end.get(section)
        if isinstance(value, dict) and field in value:
            bps = _finite_nonnegative_number(value[field], f"iperf.{section}.{field}")
            if bps > 0:
                return bps
    raise ValidationError("iperf JSON has no positive end summary bits_per_second")


def _status_object(snapshot: dict[str, Any]) -> dict[str, Any]:
    status = snapshot.get("status", snapshot)
    if not isinstance(status, dict):
        raise ValidationError("status snapshot must be an object")
    return status


def queue_shapes(
    snapshot: dict[str, Any],
    *,
    interface_name: str | None = None,
    ifindex: int | None = None,
) -> dict[int, QueueShape]:
    status = _status_object(snapshot)
    cos_interfaces = status.get("cos_interfaces", [])
    if not isinstance(cos_interfaces, list):
        raise ValidationError("status.cos_interfaces must be a list")

    shapes: dict[int, QueueShape] = {}
    for iface_index, iface in enumerate(cos_interfaces):
        if not isinstance(iface, dict):
            raise ValidationError(f"status.cos_interfaces[{iface_index}] must be an object")
        name = iface.get("interface_name")
        iface_ifindex = iface.get("ifindex")
        if interface_name and name != interface_name:
            continue
        if ifindex is not None and iface_ifindex != ifindex:
            continue
        queues = iface.get("queues", [])
        if not isinstance(queues, list):
            raise ValidationError(f"status.cos_interfaces[{iface_index}].queues must be a list")
        for queue_index, queue in enumerate(queues):
            if not isinstance(queue, dict):
                raise ValidationError(
                    f"status.cos_interfaces[{iface_index}].queues[{queue_index}] must be an object"
                )
            queue_id = _nonnegative_int(queue.get("queue_id"), "queue.queue_id")
            previous = shapes.get(queue_id)
            sent = _nonnegative_int(queue.get("drain_sent_bytes", 0), "queue.drain_sent_bytes")
            root = _nonnegative_int(
                queue.get("drain_park_root_tokens", 0),
                "queue.drain_park_root_tokens",
            )
            queue_park = _nonnegative_int(
                queue.get("drain_park_queue_tokens", 0),
                "queue.drain_park_queue_tokens",
            )
            forwarding_class = str(queue.get("forwarding_class", "-"))
            current = QueueShape(queue_id, forwarding_class, sent, root, queue_park)
            if previous is None:
                shapes[queue_id] = current
            else:
                shapes[queue_id] = QueueShape(
                    queue_id=queue_id,
                    forwarding_class=previous.forwarding_class,
                    sent_bytes=previous.sent_bytes + current.sent_bytes,
                    park_root=previous.park_root + current.park_root,
                    park_queue=previous.park_queue + current.park_queue,
                )
    return shapes


def queue_deltas(before: dict[int, QueueShape], after: dict[int, QueueShape]) -> dict[int, QueueDelta]:
    queue_ids = set(before) | set(after)
    deltas: dict[int, QueueDelta] = {}
    for queue_id in sorted(queue_ids):
        b = before.get(queue_id, QueueShape(queue_id, "-", 0, 0, 0))
        a = after.get(queue_id, QueueShape(queue_id, b.forwarding_class, 0, 0, 0))
        deltas[queue_id] = QueueDelta(
            queue_id=queue_id,
            forwarding_class=a.forwarding_class,
            sent_bytes=a.sent_bytes - b.sent_bytes,
            park_root=a.park_root - b.park_root,
            park_queue=a.park_queue - b.park_queue,
        )
    return deltas


def _phase_status_paths(phase_dir: Path) -> tuple[Path, Path, Path]:
    return (
        phase_dir / "status-before.json",
        phase_dir / "status-during.json",
        phase_dir / "status-after.json",
    )


def _validate_status_capture(phase_dir: Path) -> list[str]:
    failures: list[str] = []
    for phase in ("before", "during", "after"):
        rc_path = phase_dir / f"status-{phase}.rc"
        if not rc_path.exists():
            failures.append(f"{phase_dir.name}: missing status-{phase}.rc")
            continue
        rc = read_exit_code(rc_path)
        if rc != 0:
            failures.append(f"{phase_dir.name}: status-{phase} capture exited {rc}")
    return failures


def analyze_phase(
    phase_dir: Path,
    *,
    expected_queues: dict[int, str],
    interface_name: str | None,
    ifindex: int | None,
    wrong_queue_sent_bytes_tolerance: int,
    min_expected_sent_bytes: int,
) -> dict[str, Any]:
    failures = _validate_status_capture(phase_dir)
    before_path, during_path, after_path = _phase_status_paths(phase_dir)
    before_json = load_json(before_path)
    during_json = load_json(during_path)
    after_json = load_json(after_path)
    before_shapes = queue_shapes(before_json, interface_name=interface_name, ifindex=ifindex)
    during_shapes = queue_shapes(during_json, interface_name=interface_name, ifindex=ifindex)
    after_shapes = queue_shapes(after_json, interface_name=interface_name, ifindex=ifindex)
    deltas = queue_deltas(before_shapes, after_shapes)

    negative = [
        delta
        for delta in deltas.values()
        if delta.sent_bytes < 0 or delta.park_root < 0 or delta.park_queue < 0
    ]
    if negative:
        formatted = ", ".join(
            f"q{d.queue_id}=sent:{d.sent_bytes}/root:{d.park_root}/queue:{d.park_queue}"
            for d in negative
        )
        failures.append(f"{phase_dir.name}: negative DrainShape delta: {formatted}")

    for queue_id in sorted(expected_queues):
        delta = deltas.get(queue_id, QueueDelta(queue_id, "-", 0, 0, 0))
        if delta.sent_bytes < min_expected_sent_bytes:
            failures.append(
                f"{phase_dir.name}: expected queue {queue_id} sent_bytes delta "
                f"{delta.sent_bytes} below {min_expected_sent_bytes}"
            )
        expected_class = expected_queues[queue_id]
        if expected_class and delta.forwarding_class != expected_class:
            failures.append(
                f"{phase_dir.name}: expected queue {queue_id} class {expected_class!r}, "
                f"got {delta.forwarding_class!r}"
            )

    wrong = [
        delta
        for queue_id, delta in sorted(deltas.items())
        if queue_id not in expected_queues
        and delta.sent_bytes > wrong_queue_sent_bytes_tolerance
    ]
    if wrong:
        formatted = ", ".join(f"q{d.queue_id}={d.sent_bytes}" for d in wrong)
        failures.append(
            f"{phase_dir.name}: unexpected queue drain sent_bytes above "
            f"{wrong_queue_sent_bytes_tolerance}: {formatted}"
        )

    shape_rows = [
        {
            "queue_id": queue_id,
            "class": delta.forwarding_class,
            "sent_bytes_delta": delta.sent_bytes,
            "park_root_delta": delta.park_root,
            "park_queue_delta": delta.park_queue,
            "before": before_shapes.get(queue_id).__dict__ if queue_id in before_shapes else None,
            "during": during_shapes.get(queue_id).__dict__ if queue_id in during_shapes else None,
            "after": after_shapes.get(queue_id).__dict__ if queue_id in after_shapes else None,
        }
        for queue_id, delta in sorted(deltas.items())
    ]
    return {
        "verdict": "PASS" if not failures else "FAIL",
        "failure_reasons": failures,
        "queue_deltas": [delta.__dict__ for delta in deltas.values()],
        "drain_shape": shape_rows,
    }


def analyze_iperf(phase_dir: Path, roles: tuple[str, ...]) -> tuple[dict[str, Any], list[str]]:
    summaries: dict[str, Any] = {}
    failures: list[str] = []
    for role in roles:
        rc = read_exit_code(phase_dir / f"{role}-iperf.rc")
        if rc != 0:
            failures.append(f"{phase_dir.name}: {role} iperf exited {rc}")
        try:
            bps = iperf_bps(load_json(phase_dir / f"{role}-iperf.json"))
        except ValidationError as exc:
            failures.append(f"{phase_dir.name}: {role} {exc}")
            bps = 0.0
        summaries[role] = {
            "bps": bps,
            "mbps": bps / 1_000_000.0,
            "exit_code": rc,
        }
    return summaries, failures


def _resolve_phase_dir(root: Path, raw: Any, field: str) -> Path:
    if not isinstance(raw, str) or not raw:
        raise ValidationError(f"manifest cell missing non-empty {field}")
    path = Path(raw)
    if not path.is_absolute():
        path = root / path
    return path


def validate_artifacts(
    root: Path,
    *,
    max_exact_drop_ratio: float,
    wrong_queue_sent_bytes_tolerance: int,
    min_expected_sent_bytes: int,
    min_contender_bps: float,
    min_exact_baseline_cap_ratio: float,
    min_contended_root_pressure_ratio: float,
) -> dict[str, Any]:
    min_contender_bps = _finite_nonnegative_number(
        min_contender_bps,
        "min_contender_bps",
    )
    min_exact_baseline_cap_ratio = _finite_nonnegative_number(
        min_exact_baseline_cap_ratio,
        "min_exact_baseline_cap_ratio",
    )
    min_contended_root_pressure_ratio = _finite_nonnegative_number(
        min_contended_root_pressure_ratio,
        "min_contended_root_pressure_ratio",
    )
    manifest = load_json(root / "manifest.json")
    cells = manifest.get("cells")
    if not isinstance(cells, list) or not cells:
        raise ValidationError("manifest.cells must be a non-empty list")
    root_shape_bps = _positive_bps(
        manifest.get("root_shape_bps", DEFAULT_ROOT_SHAPE_BPS),
        "manifest.root_shape_bps",
    )
    interface_name = manifest.get("cos_interface_name", "reth0.80")
    if interface_name == "":
        interface_name = None
    if interface_name is not None and not isinstance(interface_name, str):
        raise ValidationError("manifest.cos_interface_name must be a string")
    ifindex_raw = manifest.get("cos_ifindex")
    ifindex = None if ifindex_raw in (None, "") else _nonnegative_int(ifindex_raw, "manifest.cos_ifindex")
    if interface_name is None and ifindex is None:
        raise ValidationError("manifest must specify cos_interface_name or cos_ifindex")

    summary_cells: list[dict[str, Any]] = []
    failures: list[str] = []

    for index, cell in enumerate(cells):
        if not isinstance(cell, dict):
            raise ValidationError(f"manifest.cells[{index}] must be an object")
        label = str(cell.get("label") or f"cell-{index}")
        exact_port = _nonnegative_int(cell.get("exact_port"), f"{label}.exact_port")
        exact_queue = _nonnegative_int(cell.get("exact_queue"), f"{label}.exact_queue")
        contender_port = _nonnegative_int(cell.get("contender_port"), f"{label}.contender_port")
        contender_queue = _nonnegative_int(cell.get("contender_queue"), f"{label}.contender_queue")
        exact_forwarding_class = _forwarding_class(
            cell.get("exact_forwarding_class"),
            exact_port,
            f"{label}.exact_forwarding_class",
        )
        contender_forwarding_class = _forwarding_class(
            cell.get("contender_forwarding_class"),
            contender_port,
            f"{label}.contender_forwarding_class",
        )
        exact_cap_bps = _exact_cap_bps(
            cell.get("exact_cap_bps"),
            exact_port,
            f"{label}.exact_cap_bps",
        )
        cell_min_contender_bps = max(
            min_contender_bps,
            _finite_nonnegative_number(
                cell.get(
                    "min_contender_bps",
                    _default_min_contender_bps(exact_cap_bps, root_shape_bps),
                ),
                f"{label}.min_contender_bps",
            ),
        )
        baseline_dir = _resolve_phase_dir(root, cell.get("baseline_dir"), f"{label}.baseline_dir")
        contended_dir = _resolve_phase_dir(root, cell.get("contended_dir"), f"{label}.contended_dir")

        baseline_iperf, baseline_iperf_failures = analyze_iperf(baseline_dir, ("exact",))
        contended_iperf, contended_iperf_failures = analyze_iperf(contended_dir, ("exact", "contender"))
        baseline_phase = analyze_phase(
            baseline_dir,
            expected_queues={exact_queue: exact_forwarding_class},
            interface_name=interface_name,
            ifindex=ifindex,
            wrong_queue_sent_bytes_tolerance=wrong_queue_sent_bytes_tolerance,
            min_expected_sent_bytes=min_expected_sent_bytes,
        )
        contended_phase = analyze_phase(
            contended_dir,
            expected_queues={
                exact_queue: exact_forwarding_class,
                contender_queue: contender_forwarding_class,
            },
            interface_name=interface_name,
            ifindex=ifindex,
            wrong_queue_sent_bytes_tolerance=wrong_queue_sent_bytes_tolerance,
            min_expected_sent_bytes=min_expected_sent_bytes,
        )

        cell_failures = (
            baseline_iperf_failures
            + contended_iperf_failures
            + baseline_phase["failure_reasons"]
            + contended_phase["failure_reasons"]
        )
        baseline_bps = baseline_iperf["exact"]["bps"]
        contended_exact_bps = contended_iperf["exact"]["bps"]
        contender_bps = contended_iperf["contender"]["bps"]
        contended_total_bps = contended_exact_bps + contender_bps
        minimum_baseline_bps = exact_cap_bps * min_exact_baseline_cap_ratio
        minimum_exact_bps = baseline_bps * (1.0 - max_exact_drop_ratio)
        minimum_contended_total_bps = root_shape_bps * min_contended_root_pressure_ratio
        if baseline_bps < minimum_baseline_bps:
            cell_failures.append(
                f"exact-alone baseline {baseline_bps / 1_000_000.0:.3f} Mbps below "
                f"{minimum_baseline_bps / 1_000_000.0:.3f} Mbps "
                f"({min_exact_baseline_cap_ratio:.2%} of {exact_cap_bps / 1_000_000.0:.3f} Mbps cap)"
            )
        elif contended_exact_bps < minimum_exact_bps:
            cell_failures.append(
                f"exact throughput dropped from {baseline_bps / 1_000_000.0:.3f} Mbps "
                f"to {contended_exact_bps / 1_000_000.0:.3f} Mbps, below "
                f"{minimum_exact_bps / 1_000_000.0:.3f} Mbps"
            )
        if contender_bps < cell_min_contender_bps:
            cell_failures.append(
                f"contender throughput {contender_bps / 1_000_000.0:.3f} Mbps below "
                f"{cell_min_contender_bps / 1_000_000.0:.3f} Mbps; contention pressure "
                "is too low to prove exact isolation"
            )
        if contended_total_bps < minimum_contended_total_bps:
            cell_failures.append(
                f"contended total throughput {contended_total_bps / 1_000_000.0:.3f} Mbps below "
                f"{minimum_contended_total_bps / 1_000_000.0:.3f} Mbps "
                f"({min_contended_root_pressure_ratio:.2%} of root shape "
                f"{root_shape_bps / 1_000_000.0:.3f} Mbps); root pressure is too low "
                "to prove best-effort/uncapped isolation"
            )

        if cell_failures:
            failures.extend(f"{label}: {reason}" for reason in cell_failures)

        summary_cells.append(
            {
                "label": label,
                "exact_port": exact_port,
                "exact_queue": exact_queue,
                "exact_forwarding_class": exact_forwarding_class,
                "contender_port": contender_port,
                "contender_queue": contender_queue,
                "contender_forwarding_class": contender_forwarding_class,
                "exact_cap_bps": exact_cap_bps,
                "root_shape_bps": root_shape_bps,
                "verdict": "PASS" if not cell_failures else "FAIL",
                "failure_reasons": cell_failures,
                "throughput": {
                    "exact_cap_mbps": exact_cap_bps / 1_000_000.0,
                    "baseline_exact_mbps": baseline_bps / 1_000_000.0,
                    "contended_exact_mbps": contended_exact_bps / 1_000_000.0,
                    "contender_mbps": contender_bps / 1_000_000.0,
                    "contended_total_mbps": contended_total_bps / 1_000_000.0,
                    "minimum_baseline_exact_mbps": minimum_baseline_bps / 1_000_000.0,
                    "minimum_contended_exact_mbps": minimum_exact_bps / 1_000_000.0,
                    "minimum_contender_mbps": cell_min_contender_bps / 1_000_000.0,
                    "minimum_contended_total_mbps": minimum_contended_total_bps / 1_000_000.0,
                },
                "baseline": {
                    "iperf": baseline_iperf,
                    "dataplane": baseline_phase,
                },
                "contended": {
                    "iperf": contended_iperf,
                    "dataplane": contended_phase,
                },
            }
        )

    return {
        "verdict": "PASS" if not failures else "FAIL",
        "failure_reasons": failures,
        "thresholds": {
            "max_exact_drop_ratio": max_exact_drop_ratio,
            "wrong_queue_sent_bytes_tolerance": wrong_queue_sent_bytes_tolerance,
            "min_expected_sent_bytes": min_expected_sent_bytes,
            "min_contender_bps": min_contender_bps,
            "min_exact_baseline_cap_ratio": min_exact_baseline_cap_ratio,
            "min_contended_root_pressure_ratio": min_contended_root_pressure_ratio,
        },
        "cos_interface_name": interface_name,
        "cos_ifindex": ifindex,
        "cells": summary_cells,
    }


def write_summary_tsv(summary: dict[str, Any], path: Path) -> None:
    with path.open("w", encoding="utf-8") as f:
        f.write(
            "cell\texact_port\texact_queue\tcontender_port\tcontender_queue\tverdict\t"
            "exact_cap_mbps\tbaseline_exact_mbps\tminimum_baseline_exact_mbps\t"
            "contended_exact_mbps\tminimum_contended_exact_mbps\t"
            "contender_mbps\tminimum_contender_mbps\t"
            "contended_total_mbps\tminimum_contended_total_mbps\tfailure_reasons\n"
        )
        for cell in summary["cells"]:
            throughput = cell["throughput"]
            f.write(
                "\t".join(
                    [
                        str(cell["label"]),
                        str(cell["exact_port"]),
                        str(cell["exact_queue"]),
                        str(cell["contender_port"]),
                        str(cell["contender_queue"]),
                        str(cell["verdict"]),
                        f"{throughput['exact_cap_mbps']:.3f}",
                        f"{throughput['baseline_exact_mbps']:.3f}",
                        f"{throughput['minimum_baseline_exact_mbps']:.3f}",
                        f"{throughput['contended_exact_mbps']:.3f}",
                        f"{throughput['minimum_contended_exact_mbps']:.3f}",
                        f"{throughput['contender_mbps']:.3f}",
                        f"{throughput['minimum_contender_mbps']:.3f}",
                        f"{throughput['contended_total_mbps']:.3f}",
                        f"{throughput['minimum_contended_total_mbps']:.3f}",
                        "; ".join(cell["failure_reasons"]),
                    ]
                )
                + "\n"
            )


def write_drain_shape_tsv(summary: dict[str, Any], path: Path) -> None:
    with path.open("w", encoding="utf-8") as f:
        f.write(
            "cell\tphase\tqueue_id\tclass\tsent_bytes_delta\tpark_root_delta\tpark_queue_delta\n"
        )
        for cell in summary["cells"]:
            for phase_name in ("baseline", "contended"):
                for delta in cell[phase_name]["dataplane"]["queue_deltas"]:
                    f.write(
                        "\t".join(
                            [
                                str(cell["label"]),
                                phase_name,
                                str(delta["queue_id"]),
                                str(delta["forwarding_class"]),
                                str(delta["sent_bytes"]),
                                str(delta["park_root"]),
                                str(delta["park_queue"]),
                            ]
                        )
                        + "\n"
                    )


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("artifact_root", type=Path)
    parser.add_argument("--summary-json", type=Path)
    parser.add_argument("--summary-tsv", type=Path)
    parser.add_argument("--drain-shape-tsv", type=Path)
    parser.add_argument(
        "--max-exact-drop-ratio",
        type=float,
        default=DEFAULT_MAX_EXACT_DROP_RATIO,
    )
    parser.add_argument(
        "--wrong-queue-sent-bytes-tolerance",
        type=int,
        default=DEFAULT_WRONG_QUEUE_SENT_BYTES_TOLERANCE,
    )
    parser.add_argument(
        "--min-expected-sent-bytes",
        type=int,
        default=DEFAULT_MIN_EXPECTED_SENT_BYTES,
    )
    parser.add_argument(
        "--min-contender-bps",
        type=float,
        default=DEFAULT_MIN_CONTENDER_BPS,
    )
    parser.add_argument(
        "--min-exact-baseline-cap-ratio",
        type=float,
        default=DEFAULT_MIN_EXACT_BASELINE_CAP_RATIO,
    )
    parser.add_argument(
        "--min-contended-root-pressure-ratio",
        type=float,
        default=DEFAULT_MIN_CONTENDED_ROOT_PRESSURE_RATIO,
    )
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    try:
        summary = validate_artifacts(
            args.artifact_root,
            max_exact_drop_ratio=args.max_exact_drop_ratio,
            wrong_queue_sent_bytes_tolerance=args.wrong_queue_sent_bytes_tolerance,
            min_expected_sent_bytes=args.min_expected_sent_bytes,
            min_contender_bps=args.min_contender_bps,
            min_exact_baseline_cap_ratio=args.min_exact_baseline_cap_ratio,
            min_contended_root_pressure_ratio=args.min_contended_root_pressure_ratio,
        )
    except ValidationError as exc:
        print(f"cos_be_contention_validate: {exc}", file=sys.stderr)
        return 2

    summary_json = args.summary_json or args.artifact_root / "summary.json"
    summary_tsv = args.summary_tsv or args.artifact_root / "summary.tsv"
    drain_shape_tsv = args.drain_shape_tsv or args.artifact_root / "drain-shape.tsv"
    summary_json.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    write_summary_tsv(summary, summary_tsv)
    write_drain_shape_tsv(summary, drain_shape_tsv)
    print(f"cos_be_contention_validate: wrote {summary_json}")
    print(f"cos_be_contention_validate: wrote {summary_tsv}")
    print(f"cos_be_contention_validate: wrote {drain_shape_tsv}")
    return 0 if summary["verdict"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
