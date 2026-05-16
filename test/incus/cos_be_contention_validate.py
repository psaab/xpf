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
    expected_queues: set[int],
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

    for queue_id in sorted(expected_queues):
        delta = deltas.get(queue_id, QueueDelta(queue_id, "-", 0, 0, 0))
        if delta.sent_bytes < min_expected_sent_bytes:
            failures.append(
                f"{phase_dir.name}: expected queue {queue_id} sent_bytes delta "
                f"{delta.sent_bytes} below {min_expected_sent_bytes}"
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
) -> dict[str, Any]:
    manifest = load_json(root / "manifest.json")
    cells = manifest.get("cells")
    if not isinstance(cells, list) or not cells:
        raise ValidationError("manifest.cells must be a non-empty list")
    interface_name = manifest.get("cos_interface_name", "reth0.80")
    if interface_name == "":
        interface_name = None
    if interface_name is not None and not isinstance(interface_name, str):
        raise ValidationError("manifest.cos_interface_name must be a string")
    ifindex_raw = manifest.get("cos_ifindex")
    ifindex = None if ifindex_raw in (None, "") else _nonnegative_int(ifindex_raw, "manifest.cos_ifindex")

    summary_cells: list[dict[str, Any]] = []
    failures: list[str] = []

    for index, cell in enumerate(cells):
        if not isinstance(cell, dict):
            raise ValidationError(f"manifest.cells[{index}] must be an object")
        label = str(cell.get("label") or f"cell-{index}")
        exact_queue = _nonnegative_int(cell.get("exact_queue"), f"{label}.exact_queue")
        contender_queue = _nonnegative_int(cell.get("contender_queue"), f"{label}.contender_queue")
        baseline_dir = _resolve_phase_dir(root, cell.get("baseline_dir"), f"{label}.baseline_dir")
        contended_dir = _resolve_phase_dir(root, cell.get("contended_dir"), f"{label}.contended_dir")

        baseline_iperf, baseline_iperf_failures = analyze_iperf(baseline_dir, ("exact",))
        contended_iperf, contended_iperf_failures = analyze_iperf(contended_dir, ("exact", "contender"))
        baseline_phase = analyze_phase(
            baseline_dir,
            expected_queues={exact_queue},
            interface_name=interface_name,
            ifindex=ifindex,
            wrong_queue_sent_bytes_tolerance=wrong_queue_sent_bytes_tolerance,
            min_expected_sent_bytes=min_expected_sent_bytes,
        )
        contended_phase = analyze_phase(
            contended_dir,
            expected_queues={exact_queue, contender_queue},
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
        minimum_exact_bps = baseline_bps * (1.0 - max_exact_drop_ratio)
        if baseline_bps <= 0:
            cell_failures.append("exact-alone baseline has zero throughput")
        elif contended_exact_bps < minimum_exact_bps:
            cell_failures.append(
                f"exact throughput dropped from {baseline_bps / 1_000_000.0:.3f} Mbps "
                f"to {contended_exact_bps / 1_000_000.0:.3f} Mbps, below "
                f"{minimum_exact_bps / 1_000_000.0:.3f} Mbps"
            )

        if cell_failures:
            failures.extend(f"{label}: {reason}" for reason in cell_failures)

        summary_cells.append(
            {
                "label": label,
                "exact_port": cell.get("exact_port"),
                "exact_queue": exact_queue,
                "contender_port": cell.get("contender_port"),
                "contender_queue": contender_queue,
                "verdict": "PASS" if not cell_failures else "FAIL",
                "failure_reasons": cell_failures,
                "throughput": {
                    "baseline_exact_mbps": baseline_bps / 1_000_000.0,
                    "contended_exact_mbps": contended_exact_bps / 1_000_000.0,
                    "contender_mbps": contended_iperf["contender"]["bps"] / 1_000_000.0,
                    "minimum_contended_exact_mbps": minimum_exact_bps / 1_000_000.0,
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
        },
        "cos_interface_name": interface_name,
        "cos_ifindex": ifindex,
        "cells": summary_cells,
    }


def write_summary_tsv(summary: dict[str, Any], path: Path) -> None:
    with path.open("w", encoding="utf-8") as f:
        f.write(
            "cell\texact_port\texact_queue\tcontender_port\tcontender_queue\tverdict\t"
            "baseline_exact_mbps\tcontended_exact_mbps\tcontender_mbps\t"
            "minimum_contended_exact_mbps\tfailure_reasons\n"
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
                        f"{throughput['baseline_exact_mbps']:.3f}",
                        f"{throughput['contended_exact_mbps']:.3f}",
                        f"{throughput['contender_mbps']:.3f}",
                        f"{throughput['minimum_contended_exact_mbps']:.3f}",
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
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    try:
        summary = validate_artifacts(
            args.artifact_root,
            max_exact_drop_ratio=args.max_exact_drop_ratio,
            wrong_queue_sent_bytes_tolerance=args.wrong_queue_sent_bytes_tolerance,
            min_expected_sent_bytes=args.min_expected_sent_bytes,
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
