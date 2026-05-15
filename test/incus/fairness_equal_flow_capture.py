#!/usr/bin/env python3
"""Reduce raw Prometheus scrapes to equal-flow estimator artifacts."""

from __future__ import annotations

import argparse
import json
import math
from pathlib import Path
import re
import statistics
import sys
from typing import Any


# Metric names are the current Prometheus API from pkg/api/metrics.go.
AGGREGATE_METRICS = {
    "xpf_fairness_equal_flow_estimate_valid": "estimate_valid",
    "xpf_fairness_equal_flow_sampled_active_workers": "sampled_active_workers",
    "xpf_fairness_equal_flow_unsampled_active_workers": "unsampled_active_workers",
    "xpf_fairness_equal_flow_target_per_flow_bps": "target_per_flow_bps",
    "xpf_fairness_equal_flow_observed_bps": "observed_bps",
    "xpf_fairness_equal_flow_capped_bps": "capped_bps",
    "xpf_fairness_equal_flow_suppressed_bps": "suppressed_bps",
    "xpf_fairness_equal_flow_throughput_loss_ratio": "throughput_loss_ratio",
}

WORKER_METRICS = {
    "xpf_fairness_equal_flow_worker_observed_bps": "observed_bps",
    "xpf_fairness_equal_flow_worker_observed_per_flow_bps": "observed_per_flow_bps",
    "xpf_fairness_equal_flow_worker_cap_bps": "cap_bps",
    "xpf_fairness_equal_flow_worker_suppressed_bps": "suppressed_bps",
}

AGGREGATE_FIELDS = tuple(AGGREGATE_METRICS.values())
WORKER_FIELDS = tuple(WORKER_METRICS.values())
IPERF_ARTIFACT_CANDIDATES = (
    "iperf-single.json",
    "iperf-primary.json",
    "iperf-mixed.json",
)
IPERF_ARTIFACT_BY_ROLE = {
    "single": "iperf-single.json",
    "primary": "iperf-primary.json",
    "mixed": "iperf-mixed.json",
}
PROM_SAMPLE_RE = re.compile(r"^([a-zA-Z_:][a-zA-Z0-9_:]*)\{([^}]*)\}\s+(\S+)(?:\s+\d+)?$")
LABEL_RE = re.compile(r'([a-zA-Z_][a-zA-Z0-9_]*)="((?:\\.|[^"\\])*)"')
BEGIN_RE = re.compile(r"^# xpf_fairness_scrape_begin timestamp=(\S+)$")
END_RE = re.compile(r"^# xpf_fairness_scrape_end timestamp=(\S+)$")
EMPTY_RE = re.compile(r"^# xpf_fairness_scrape_empty timestamp=(\S+)$")
ERROR_RE = re.compile(r"^# xpf_fairness_scrape_error timestamp=(\S+) status=(\S+)$")


class CaptureError(RuntimeError):
    pass


def _decode_label_value(value: str) -> str:
    return (
        value.replace(r"\\", "\\")
        .replace(r"\"", '"')
        .replace(r"\n", "\n")
    )


def parse_labels(raw: str) -> dict[str, str]:
    labels: dict[str, str] = {}
    pos = 0
    while pos < len(raw):
        match = LABEL_RE.match(raw, pos)
        if match is None:
            raise CaptureError(f"malformed Prometheus labels: {raw!r}")
        labels[match.group(1)] = _decode_label_value(match.group(2))
        pos = match.end()
        if pos == len(raw):
            break
        if raw[pos] != ",":
            raise CaptureError(f"malformed Prometheus labels: {raw!r}")
        pos += 1
    return labels


def parse_number(raw: str) -> float:
    try:
        value = float(raw)
    except ValueError as exc:
        raise CaptureError(f"metric value is not numeric: {raw!r}") from exc
    if not math.isfinite(value):
        raise CaptureError(f"metric value is not finite: {raw!r}")
    return value


def split_scrapes(raw: str) -> tuple[list[dict[str, Any]], list[str], list[str]]:
    scrapes: list[dict[str, Any]] = []
    empty_timestamps: list[str] = []
    error_timestamps: list[str] = []
    current: dict[str, Any] | None = None
    saw_markers = False

    for line in raw.splitlines():
        begin = BEGIN_RE.match(line)
        if begin is not None:
            if current is not None:
                raise CaptureError(
                    f"scrape {current['timestamp']} missing end marker before scrape {begin.group(1)}"
                )
            saw_markers = True
            current = {"timestamp": begin.group(1), "lines": [], "empty": False}
            continue

        end = END_RE.match(line)
        if end is not None:
            saw_markers = True
            if current is None:
                raise CaptureError(f"scrape end marker without begin marker at {end.group(1)}")
            scrapes.append(current)
            current = None
            continue

        empty = EMPTY_RE.match(line)
        if empty is not None:
            empty_timestamps.append(empty.group(1))
            if current is not None:
                current["empty"] = True
            continue

        error = ERROR_RE.match(line)
        if error is not None:
            error_timestamps.append(f"{error.group(1)}:{error.group(2)}")
            continue

        if current is not None:
            current["lines"].append(line)

    if current is not None:
        raise CaptureError(f"scrape {current['timestamp']} missing end marker")
    if not saw_markers and raw.strip():
        scrapes.append({"timestamp": "unknown", "lines": raw.splitlines(), "empty": False})
    return scrapes, empty_timestamps, error_timestamps


def require_count_metric(value: float, field_name: str, timestamp: str) -> int:
    if not value.is_integer() or value < 0:
        raise CaptureError(f"{timestamp}: {field_name} must be a non-negative integer, got {value:g}")
    return int(value)


def require_nonnegative_number(value: Any, field_name: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise CaptureError(f"{field_name} must be numeric")
    number = float(value)
    if not math.isfinite(number) or number < 0:
        raise CaptureError(f"{field_name} must be a non-negative finite number")
    return number


def parse_nonnegative_seconds_arg(raw: str) -> int:
    try:
        value = int(raw, 10)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"{raw!r} must be a non-negative integer second count") from exc
    if str(value) != raw or value < 0:
        raise argparse.ArgumentTypeError(f"{raw!r} must be a non-negative integer second count")
    return value


def parse_equal_flow_line(line: str) -> tuple[str, dict[str, str], float] | None:
    if not line or line.startswith("#"):
        return None
    if not line.startswith("xpf_fairness_equal_flow_"):
        return None
    match = PROM_SAMPLE_RE.match(line)
    if match is None:
        raise CaptureError(f"malformed equal-flow metric line: {line!r}")
    metric = match.group(1)
    if metric not in AGGREGATE_METRICS and metric not in WORKER_METRICS:
        raise CaptureError(f"unknown equal-flow metric name: {metric}")
    return metric, parse_labels(match.group(2)), parse_number(match.group(3))


def _read_json_object(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise CaptureError(f"{path}: invalid JSON: {exc}") from exc
    except OSError as exc:
        raise CaptureError(f"{path}: {exc}") from exc
    if not isinstance(value, dict):
        raise CaptureError(f"{path}: expected JSON object")
    return value


def _find_iperf_artifact(sample_dir: Path, role: str) -> Path:
    artifact_dir = sample_dir / "artifacts"
    if role != "auto":
        path = artifact_dir / IPERF_ARTIFACT_BY_ROLE[role]
        if path.is_file():
            return path
        raise CaptureError(f"{sample_dir}: missing {path.name} for --iperf-artifact-role {role}")

    found = [artifact_dir / name for name in IPERF_ARTIFACT_CANDIDATES if (artifact_dir / name).is_file()]
    if len(found) != 1:
        candidates = ", ".join(str(artifact_dir / name) for name in IPERF_ARTIFACT_CANDIDATES)
        if not found:
            raise CaptureError(f"{sample_dir}: no iperf JSON artifact found; expected one of {candidates}")
        raise CaptureError(
            f"{sample_dir}: multiple iperf JSON artifacts found: {', '.join(str(p) for p in found)}; "
            "pass --iperf-artifact-role primary or --iperf-artifact-role mixed"
        )
    return found[0]


def load_steady_windows(
    sample_summary_path: Path,
    *,
    warmup_secs: int,
    final_burst_secs: int,
    estimator_window_secs: int,
    iperf_artifact_role: str = "auto",
) -> list[dict[str, Any]]:
    summary = _read_json_object(sample_summary_path)
    samples = summary.get("samples")
    if not isinstance(samples, list) or not samples:
        raise CaptureError(f"{sample_summary_path}: samples must be a non-empty array")

    windows: list[dict[str, Any]] = []
    for position, sample in enumerate(samples, start=1):
        if not isinstance(sample, dict):
            raise CaptureError(f"{sample_summary_path}: sample {position} must be an object")
        sample_dir_raw = sample.get("sample_dir")
        if not isinstance(sample_dir_raw, str) or not sample_dir_raw:
            raise CaptureError(f"{sample_summary_path}: sample {position} missing sample_dir")
        sample_dir = Path(sample_dir_raw)
        iperf_path = _find_iperf_artifact(sample_dir, iperf_artifact_role)
        iperf = _read_json_object(iperf_path)
        try:
            start_epoch = require_nonnegative_number(
                iperf["start"]["timestamp"]["timesecs"],
                f"{iperf_path}: start.timestamp.timesecs",
            )
            duration_secs = require_nonnegative_number(
                iperf["start"]["test_start"]["duration"],
                f"{iperf_path}: start.test_start.duration",
            )
        except KeyError as exc:
            raise CaptureError(f"{iperf_path}: missing iperf start timestamp or duration field") from exc

        if duration_secs <= warmup_secs + estimator_window_secs + final_burst_secs:
            raise CaptureError(
                f"{iperf_path}: duration {duration_secs:g}s <= warmup {warmup_secs:g}s + "
                f"estimator-window {estimator_window_secs:g}s + final-burst {final_burst_secs:g}s"
            )
        steady_start = start_epoch + warmup_secs + estimator_window_secs
        steady_end = start_epoch + duration_secs - final_burst_secs
        windows.append(
            {
                "sample": sample.get("sample", position),
                "sample_dir": str(sample_dir),
                "iperf_json": str(iperf_path),
                "start_epoch": steady_start,
                "end_epoch": steady_end,
            }
        )
    return windows


def filter_scrapes_to_steady_windows(
    scrapes: list[dict[str, Any]],
    windows: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    if not windows:
        return scrapes
    selected: list[dict[str, Any]] = []
    for scrape in scrapes:
        timestamp_raw = scrape["timestamp"]
        try:
            timestamp = float(timestamp_raw)
        except ValueError as exc:
            raise CaptureError(f"scrape timestamp is not numeric and cannot be steady-window filtered: {timestamp_raw}") from exc
        if not math.isfinite(timestamp):
            raise CaptureError(f"scrape timestamp is not finite and cannot be steady-window filtered: {timestamp_raw}")
        if any(window["start_epoch"] <= timestamp < window["end_epoch"] for window in windows):
            selected.append(scrape)
    if not selected:
        first = windows[0]
        last = windows[-1]
        raise CaptureError(
            "steady-window filter selected no scrapes "
            f"(first={first['start_epoch']:g}-{first['end_epoch']:g}, "
            f"last={last['start_epoch']:g}-{last['end_epoch']:g})"
        )
    return selected


def reduce_scrapes(scrapes: list[dict[str, Any]], ifindex: str, queue_id: str) -> dict[str, Any]:
    if not scrapes:
        raise CaptureError("raw metrics contained no scrapes")

    target_rows: list[dict[str, Any]] = []
    complete_rows: list[dict[str, Any]] = []
    missing_by_timestamp: list[str] = []

    for scrape in scrapes:
        aggregate: dict[str, float] = {}
        workers: dict[str, dict[str, float]] = {}
        target_seen = False
        for line in scrape["lines"]:
            parsed = parse_equal_flow_line(line)
            if parsed is None:
                continue
            metric, labels, value = parsed
            if labels.get("ifindex") != ifindex or labels.get("queue_id") != queue_id:
                continue
            target_seen = True
            if metric in AGGREGATE_METRICS:
                aggregate[AGGREGATE_METRICS[metric]] = value
            else:
                worker_id = labels.get("worker_id")
                if worker_id is None or not worker_id.isdigit():
                    raise CaptureError(f"{metric} missing numeric worker_id label")
                workers.setdefault(worker_id, {})[WORKER_METRICS[metric]] = value

        if not target_seen:
            continue

        row = {
            "timestamp": scrape["timestamp"],
            "aggregate": aggregate,
            "workers": workers,
        }
        target_rows.append(row)
        missing = [field for field in AGGREGATE_FIELDS if field not in aggregate]
        valid = aggregate.get("estimate_valid") == 1.0
        complete_workers = {
            wid: fields
            for wid, fields in workers.items()
            if all(field in fields for field in WORKER_FIELDS)
        }
        if missing:
            missing_by_timestamp.append(f"{scrape['timestamp']}: missing {','.join(missing)}")
            continue
        sampled_count = require_count_metric(
            aggregate["sampled_active_workers"], "sampled_active_workers", scrape["timestamp"]
        )
        require_count_metric(
            aggregate["unsampled_active_workers"], "unsampled_active_workers", scrape["timestamp"]
        )
        if not valid:
            continue
        if len(complete_workers) != sampled_count:
            missing_by_timestamp.append(
                f"{scrape['timestamp']}: worker row count {len(complete_workers)} != sampled_active_workers {sampled_count}"
            )
            continue
        row["workers"] = complete_workers
        complete_rows.append(row)

    if not target_rows:
        raise CaptureError(f"no equal-flow estimator rows for ifindex {ifindex} queue {queue_id}")
    if not complete_rows:
        detail = "; ".join(missing_by_timestamp[:3]) if missing_by_timestamp else "no valid estimator scrape"
        raise CaptureError(
            f"no complete valid equal-flow estimator rows for ifindex {ifindex} queue {queue_id}: {detail}"
        )

    latest = complete_rows[-1]
    latest_aggregate = dict(latest["aggregate"])
    latest_aggregate["worker_count"] = len(latest["workers"])
    latest_aggregate["timestamp"] = latest["timestamp"]

    series: dict[str, dict[str, float]] = {}
    for field in AGGREGATE_FIELDS:
        values = [float(row["aggregate"][field]) for row in complete_rows]
        series[field] = {
            "mean": statistics.mean(values),
            "min": min(values),
            "max": max(values),
            "latest": values[-1],
        }

    return {
        "ifindex": ifindex,
        "queue_id": queue_id,
        "scrape_count": len(scrapes),
        "target_scrape_count": len(target_rows),
        "complete_scrape_count": len(complete_rows),
        "latest": latest_aggregate,
        "series": series,
        "complete_rows": complete_rows,
    }


def write_aggregate_tsv(path: Path, reduced: dict[str, Any]) -> None:
    with path.open("w", encoding="utf-8") as f:
        f.write(
            "timestamp\tifindex\tqueue_id\testimate_valid\tsampled_active_workers\t"
            "unsampled_active_workers\ttarget_per_flow_bps\tobserved_bps\t"
            "capped_bps\tsuppressed_bps\tthroughput_loss_ratio\n"
        )
        for row in reduced["complete_rows"]:
            aggregate = row["aggregate"]
            values = [row["timestamp"], reduced["ifindex"], reduced["queue_id"]]
            values.extend(str(aggregate[field]) for field in AGGREGATE_FIELDS)
            f.write("\t".join(values) + "\n")


def write_worker_tsv(path: Path, reduced: dict[str, Any]) -> None:
    with path.open("w", encoding="utf-8") as f:
        f.write(
            "timestamp\tifindex\tqueue_id\tworker_id\tobserved_bps\t"
            "observed_per_flow_bps\tcap_bps\tsuppressed_bps\n"
        )
        for row in reduced["complete_rows"]:
            for worker_id in sorted(row["workers"], key=lambda value: int(value)):
                worker = row["workers"][worker_id]
                values = [row["timestamp"], reduced["ifindex"], reduced["queue_id"], worker_id]
                values.extend(str(worker[field]) for field in WORKER_FIELDS)
                f.write("\t".join(values) + "\n")


def public_summary(reduced: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in reduced.items() if key != "complete_rows"}


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--raw", type=Path, required=True)
    parser.add_argument("--ifindex", required=True)
    parser.add_argument("--queue-id", required=True)
    parser.add_argument(
        "--sample-summary",
        type=Path,
        help=(
            "fairness_multi_sample.py summary.json. When set, equal-flow "
            "scrapes are reduced only inside each sample's iperf steady-state window."
        ),
    )
    parser.add_argument("--warmup-secs", type=parse_nonnegative_seconds_arg, default=5)
    parser.add_argument(
        "--estimator-window-secs",
        type=parse_nonnegative_seconds_arg,
        default=0,
        help=(
            "Additional seconds after warmup to exclude so rolling equal-flow "
            "gauges no longer include pre-steady traffic. The class sweep passes 30s."
        ),
    )
    parser.add_argument("--final-burst-secs", type=parse_nonnegative_seconds_arg, default=1)
    parser.add_argument(
        "--iperf-artifact-role",
        choices=("auto", "single", "primary", "mixed"),
        default="auto",
        help=(
            "Which preserved iperf JSON artifact defines the timing window. "
            "Use primary or mixed when a future mixed-mode wrapper preserves both."
        ),
    )
    parser.add_argument("--summary-json", type=Path, required=True)
    parser.add_argument("--aggregate-tsv", type=Path, required=True)
    parser.add_argument("--worker-tsv", type=Path, required=True)
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    try:
        raw = args.raw.read_text(encoding="utf-8")
        scrapes, empty_timestamps, error_timestamps = split_scrapes(raw)
        if empty_timestamps:
            raise CaptureError(
                "empty metrics scrape(s): " + ", ".join(empty_timestamps[:5])
            )
        if error_timestamps:
            raise CaptureError(
                "metrics scrape curl failure(s): " + ", ".join(error_timestamps[:5])
            )
        raw_scrape_count = len(scrapes)
        steady_windows: list[dict[str, Any]] = []
        if args.sample_summary is not None:
            steady_windows = load_steady_windows(
                args.sample_summary,
                warmup_secs=args.warmup_secs,
                final_burst_secs=args.final_burst_secs,
                estimator_window_secs=args.estimator_window_secs,
                iperf_artifact_role=args.iperf_artifact_role,
            )
            scrapes = filter_scrapes_to_steady_windows(scrapes, steady_windows)
        reduced = reduce_scrapes(scrapes, args.ifindex, args.queue_id)
        reduced["raw_scrape_count"] = raw_scrape_count
        reduced["steady_window_scrape_count"] = len(scrapes)
        reduced["steady_windows"] = steady_windows
        reduced["warmup_secs"] = args.warmup_secs
        reduced["estimator_window_secs"] = args.estimator_window_secs
        reduced["final_burst_secs"] = args.final_burst_secs
        args.summary_json.write_text(
            json.dumps(public_summary(reduced), indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        write_aggregate_tsv(args.aggregate_tsv, reduced)
        write_worker_tsv(args.worker_tsv, reduced)
    except (OSError, CaptureError) as exc:
        print(f"fairness-equal-flow-capture: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
