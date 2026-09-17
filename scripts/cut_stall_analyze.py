#!/usr/bin/env python3
"""Analyze iperf3/ping evidence around HA cutovers.

The loss-cluster cut recorder historically saved human-readable ``iperf3``
output at one-second resolution.  This module accepts that format and
iperf3's line-delimited JSON (or one full JSON document), so old runs can be
compared with finer samplers without requiring an iperf3 version-specific
JSON schema.  It reports per-stream zero windows, cwnd-floor windows, SUM
masking, timestamped ping gaps, and cut timing budgets.  It does not contact
or mutate a cluster.
"""

from __future__ import annotations

import argparse
import dataclasses
import json
import math
import re
import sys
from pathlib import Path
from typing import Iterable, Mapping, Sequence


_UNIT_SCALE = {
    "Bytes": 1.0,
    "KBytes": 1024.0,
    "MBytes": 1024.0 * 1024.0,
    "GBytes": 1024.0 * 1024.0 * 1024.0,
    "bits/sec": 1.0,
    "Kbits/sec": 1000.0,
    "Mbits/sec": 1000.0 * 1000.0,
    "Gbits/sec": 1000.0 * 1000.0 * 1000.0,
}


@dataclasses.dataclass(frozen=True)
class Interval:
    """One iperf3 interval for a stream or the SUM row."""

    stream_id: str
    start: float
    end: float
    bytes: float
    bps: float
    retr: int | None
    cwnd_bytes: float | None
    event_index: int | None = None


@dataclasses.dataclass(frozen=True)
class Gap:
    """A contiguous run of zero-throughput intervals."""

    start: float
    end: float
    intervals: int

    @property
    def duration(self) -> float:
        return self.end - self.start


@dataclasses.dataclass(frozen=True)
class PingReply:
    epoch: float
    seq: int
    rtt_ms: float


@dataclasses.dataclass(frozen=True)
class PingGap:
    prev_seq: int
    next_seq: int
    missing: int
    gap_sec: float
    prev_epoch: float
    next_epoch: float


@dataclasses.dataclass(frozen=True)
class LossBucket:
    start: float
    end: float
    received: int
    expected: int
    loss_pct: float


# iperf3's text formatter uses aligned columns but no fixed width guarantee;
# capture the semantic fields and permit a missing cwnd on SUM lines.
_IPERF_INTERVAL_RE = re.compile(
    r"^\[\s*(?P<id>\d+|SUM)\]\s+"
    r"(?P<start>\d+(?:\.\d+)?)-(?P<end>\d+(?:\.\d+)?)\s+sec\s+"
    r"(?P<bytes>[0-9]+(?:\.[0-9]+)?)\s+(?P<byte_unit>Bytes|KBytes|MBytes|GBytes)\s+"
    r"(?P<bps>[0-9]+(?:\.[0-9]+)?)\s+(?P<bps_unit>bits/sec|Kbits/sec|Mbits/sec|Gbits/sec)"
    r"(?:\s+(?P<retr>-|[0-9]+))?"
    r"(?:\s+(?P<cwnd>[0-9]+(?:\.[0-9]+)?)\s+(?P<cwnd_unit>Bytes|KBytes|MBytes|GBytes))?\s*$"
)
_IPERF_SUMMARY_RE = re.compile(
    r"^\[\s*(?P<id>\d+|SUM)\]\s+"
    r"(?P<start>\d+(?:\.\d+)?)-(?P<end>\d+(?:\.\d+)?)\s+sec\s+"
    r".*\s+(?P<kind>sender|receiver)\s*$"
)
_IPERF_TEXT_RECORD_RE = re.compile(r"^\[\s*(\d+|SUM|ID)\b")
_IPERF_PORT_RE = re.compile(
    r"^\[\s*(?P<id>\d+)\]\s+local\s+\S+\s+port\s+(?P<port>\d+)\s+connected\s+"
)
_PING_REPLY_RE = re.compile(
    r"^\[(?P<epoch>[0-9]+(?:\.[0-9]+)?)\].*?icmp_seq=(?P<seq>[0-9]+).*?"
    r"time=(?P<rtt>[0-9]+(?:\.[0-9]+)?)\s*ms\s*$"
)


def _scaled(number: str, unit: str) -> float:
    try:
        return float(number) * _UNIT_SCALE[unit]
    except KeyError as exc:
        raise ValueError(f"unknown iperf unit {unit!r}") from exc

def parse_iperf_text(path: Path) -> dict[str, object]:
    """Parse human-readable iperf3 output into per-stream interval rows.

    Unknown lines (connection summaries, separators, ``iperf Done``) are
    intentionally ignored.  Valid sender/receiver completion summaries are
    also ignored as aggregate metadata rather than treated as intervals.  A
    line that looks like an interval but is malformed raises an error,
    except for one final unterminated line, which is reported as a truncated
    tail.
    """

    streams: dict[str, list[Interval]] = {}
    sums: list[Interval] = []
    ports: dict[str, int] = {}
    saw_interval = False
    saw_completion = False
    warnings: list[str] = []
    raw_text = path.read_text(encoding="utf-8")
    has_trailing_newline = raw_text.endswith(("\n", "\r"))
    lines = raw_text.splitlines()
    total_lines = len(lines)
    for lineno, raw in enumerate(lines, 1):
        line = raw.strip()
        if not line:
            continue
        port_match = _IPERF_PORT_RE.match(line)
        if port_match:
            ports[port_match.group("id")] = int(port_match.group("port"))
            continue
        if not line.startswith("[") or "]" not in line:
            continue
        if _IPERF_SUMMARY_RE.match(line):
            saw_completion = True
            continue
        match = _IPERF_INTERVAL_RE.match(line)
        if not match:
            # Header and separator rows also start with ``[``.  Only reject
            # rows whose bracket contains a numeric stream id or SUM.
            prefix = line[1 : line.find("]")].strip()
            if prefix.isdigit() or prefix == "SUM":
                if lineno == total_lines and not has_trailing_newline:
                    if "truncated_final_line" not in warnings:
                        warnings.append("truncated_final_line")
                    continue
                raise ValueError(f"malformed iperf interval at {path}:{lineno}: {raw!r}")
            continue
        saw_interval = True
        stream_id = match.group("id")
        interval = Interval(
            stream_id=stream_id,
            start=float(match.group("start")),
            end=float(match.group("end")),
            bytes=_scaled(match.group("bytes"), match.group("byte_unit")),
            bps=_scaled(match.group("bps"), match.group("bps_unit")),
            retr=(None if match.group("retr") in (None, "-") else int(match.group("retr"))),
            cwnd_bytes=(
                None
                if match.group("cwnd") is None
                else _scaled(match.group("cwnd"), match.group("cwnd_unit"))
            ),
        )
        if interval.end < interval.start:
            raise ValueError(f"iperf interval ends before start at {path}:{lineno}")
        if stream_id == "SUM":
            sums.append(interval)
        else:
            streams.setdefault(stream_id, []).append(interval)
    if not saw_interval and not saw_completion:
        raise ValueError(f"no iperf interval or completion rows found in {path}")
    result: dict[str, object] = {"streams": streams, "sum": sums, "ports": ports}
    if warnings:
        result["warnings"] = warnings
    return result
def _json_interval(
    stream_id: str, row: Mapping[str, object], event_index: int | None = None
) -> Interval:
    start = float(row.get("start") or 0.0)
    end_value = row.get("end")
    if end_value is None:
        end = start + float(row.get("seconds") or 0.0)
    else:
        end = float(end_value)
    return Interval(
        stream_id=stream_id,
        start=start,
        end=end,
        bytes=float(row.get("bytes") or 0.0),
        bps=float(row.get("bits_per_second") or 0.0),
        retr=(
            None
            if row.get("retransmits") is None
            else int(row.get("retransmits") or 0)
        ),
        cwnd_bytes=(
            None
            if row.get("snd_cwnd") is None
            else float(row.get("snd_cwnd") or 0.0)
        ),
        event_index=event_index,
    )
def _append_json_interval(
    data: Mapping[str, object],
    streams: dict[str, list[Interval]],
    sums: list[Interval],
    event_index: int | None = None,
) -> None:
    for stream in data.get("streams", []):
        if not isinstance(stream, Mapping):
            continue
        stream_id = str(stream.get("socket") or stream.get("id") or "?")
        streams.setdefault(stream_id, []).append(
            _json_interval(stream_id, stream, event_index)
        )
    total = data.get("sum")
    if isinstance(total, Mapping):
        sums.append(_json_interval("SUM", total, event_index))

def parse_iperf_json_stream(path: Path) -> dict[str, object]:
    """Parse iperf3 ``-J --json-stream`` output or one full JSON document."""

    raw = path.read_text(encoding="utf-8")
    streams: dict[str, list[Interval]] = {}
    sums: list[Interval] = []
    ports: dict[str, int] = {}
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError:
        events = []
        for lineno, line in enumerate(raw.splitlines(), 1):
            if not line.strip():
                continue
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError as exc:
                raise ValueError(
                    f"malformed iperf JSON stream line {path}:{lineno}: {line!r}"
                ) from exc
    else:
        # ``-J --json-stream-full-output`` is one complete document; a
        # single event/document is also accepted for captured short runs.
        events = payload if isinstance(payload, list) else [payload]

    saw_interval = False
    interval_index = 0
    for event in events:
        if not isinstance(event, Mapping):
            continue
        if "event" in event:
            kind = event.get("event")
            data = event.get("data")
            if kind == "start" and isinstance(data, Mapping):
                connected = data.get("connected", [])
                for conn in connected:
                    if isinstance(conn, Mapping) and conn.get("socket") is not None:
                        ports[str(conn["socket"])] = int(conn.get("local_port") or 0)
            if kind == "interval" and isinstance(data, Mapping):
                _append_json_interval(data, streams, sums, interval_index)
                interval_index += 1
                saw_interval = True
            continue
        if "intervals" in event:
            start = event.get("start")
            if isinstance(start, Mapping):
                for conn in start.get("connected", []):
                    if isinstance(conn, Mapping) and conn.get("socket") is not None:
                        ports[str(conn["socket"])] = int(conn.get("local_port") or 0)
            for interval in event.get("intervals", []):
                if isinstance(interval, Mapping):
                    _append_json_interval(interval, streams, sums, interval_index)
                    interval_index += 1
                    saw_interval = True

    if not saw_interval:
        raise ValueError(f"no iperf JSON interval events found in {path}")
    return {"streams": streams, "sum": sums, "ports": ports}

def parse_iperf(path: Path) -> dict[str, object]:
    """Select the text or JSON parser from the artifact's first record."""

    raw = path.read_text(encoding="utf-8")
    first_line = next((line.strip() for line in raw.splitlines() if line.strip()), "")
    if not first_line:
        raise ValueError(f"empty iperf artifact {path}")
    if _IPERF_TEXT_RECORD_RE.match(first_line):
        return parse_iperf_text(path)
    if first_line.startswith("{"):
        return parse_iperf_json_stream(path)
    if first_line.startswith("["):
        try:
            json.loads(raw)
        except json.JSONDecodeError:
            return parse_iperf_text(path)
        return parse_iperf_json_stream(path)
    return parse_iperf_text(path)




def _merge_windows(rows: Iterable[Interval], predicate) -> list[Gap]:
    windows: list[Gap] = []
    start: float | None = None
    end: float | None = None
    count = 0
    for row in rows:
        if predicate(row):
            if start is None:
                start, end, count = row.start, row.end, 1
            elif row.start <= (end or row.start) + 1e-6:
                end = max(end or row.end, row.end)
                count += 1
            else:
                windows.append(Gap(start, end or start, count))
                start, end, count = row.start, row.end, 1
        elif start is not None:
            windows.append(Gap(start, end or start, count))
            start = end = None
            count = 0
    if start is not None:
        windows.append(Gap(start, end or start, count))
    return windows


def stream_gaps(intervals: Sequence[Interval], zero_bps: float = 0.0) -> list[Gap]:
    """Return contiguous intervals at or below ``zero_bps``."""

    return _merge_windows(intervals, lambda row: row.bps <= zero_bps)


def cwnd_pin_windows(
    intervals: Sequence[Interval], floor_bytes: float = 1.5 * 1024, bps_limit: float = 0.0
) -> list[Gap]:
    """Return contiguous zero/near-zero rows with cwnd at a configured floor."""

    return _merge_windows(
        intervals,
        lambda row: row.cwnd_bytes is not None
        and row.cwnd_bytes <= floor_bytes
        and row.bps <= bps_limit,
    )


def _interval_key(row: Interval) -> tuple[float, float]:
    return (round(row.start, 6), round(row.end, 6))


def _rows_for_sum(
    total: Interval, streams: Mapping[str, Sequence[Interval]]
) -> list[Interval]:
    # JSON-stream intervals carry the event index shared by every socket and
    # its SUM row.  Use that index rather than exact timestamps: each socket
    # can report a slightly different end time under live scheduling.
    tolerance = max(0.001, (total.end - total.start) * 0.1)
    key = _interval_key(total)
    matched: list[Interval] = []
    for rows in streams.values():
        if total.event_index is not None:
            candidates = [row for row in rows if row.event_index == total.event_index]
        else:
            candidates = [row for row in rows if _interval_key(row) == key]
            if not candidates:
                candidates = [
                    row
                    for row in rows
                    if abs(row.start - total.start) <= tolerance
                    and abs(row.end - total.end) <= tolerance
                ]
        if candidates:
            matched.append(min(candidates, key=lambda row: abs(row.start - total.start)))
    return matched


def sum_masking(
    streams: Mapping[str, Sequence[Interval]],
    sums: Sequence[Interval],
    zero_bps: float = 0.0,
) -> dict[str, float | int]:
    """Quantify per-stream zero time hidden by a healthy SUM row.

    ``any_stream_zero_sec`` is the union of SUM intervals in which at least
    one stream is zero. ``masked_sec`` is the subset where SUM is non-zero;
    ``sum_zero_sec`` is the SUM-level zero duration.  Rows without a
    same-period stream sample are omitted from that interval's per-stream
    attribution rather than guessed; small timestamp skew is tolerated.
    """

    any_zero = 0.0
    masked = 0.0
    sum_zero = 0.0
    stream_zero_rows = 0
    for total in sums:
        duration = max(0.0, total.end - total.start)
        rows = _rows_for_sum(total, streams)
        zero_rows = [row for row in rows if row.bps <= zero_bps]
        if zero_rows:
            any_zero += duration
            stream_zero_rows += len(zero_rows)
            if total.bps > zero_bps:
                masked += duration
        if total.bps <= zero_bps:
            sum_zero += duration
    return {
        "sum_intervals": len(sums),
        "stream_zero_rows": stream_zero_rows,
        "any_stream_zero_sec": any_zero,
        "masked_sec": masked,
        "sum_zero_sec": sum_zero,
    }


def parse_ping_d(path: Path) -> list[PingReply]:
    """Parse timestamped Linux ``ping -D`` replies."""

    replies: list[PingReply] = []
    for lineno, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        match = _PING_REPLY_RE.match(raw.strip())
        if not match:
            continue
        replies.append(
            PingReply(
                epoch=float(match.group("epoch")),
                seq=int(match.group("seq")),
                rtt_ms=float(match.group("rtt")),
            )
        )
    if not replies:
        raise ValueError(f"no timestamped ping replies found in {path}")
    return replies


def ping_gaps(replies: Sequence[PingReply], gap_thresh_sec: float = 0.5) -> list[PingGap]:
    """Find sequence gaps whose observed wall-time gap exceeds a threshold."""

    if gap_thresh_sec < 0:
        raise ValueError("gap threshold must be non-negative")
    ordered = sorted(replies, key=lambda reply: reply.epoch)
    gaps: list[PingGap] = []
    for previous, current in zip(ordered, ordered[1:]):
        missing = current.seq - previous.seq - 1
        gap_sec = current.epoch - previous.epoch
        if missing > 0 and gap_sec >= gap_thresh_sec:
            gaps.append(
                PingGap(
                    prev_seq=previous.seq,
                    next_seq=current.seq,
                    missing=missing,
                    gap_sec=gap_sec,
                    prev_epoch=previous.epoch,
                    next_epoch=current.epoch,
                )
            )
    return gaps

def loss_buckets(
    replies: Sequence[PingReply], bucket_sec: float = 1.0, interval_sec: float = 0.2
) -> list[LossBucket]:
    """Bucket observed replies and sequence gaps relative to the first reply.

    The expected count comes from the ICMP sequence stream, not from assuming
    that every wall-clock bucket contains exactly ``bucket_sec / interval_sec``
    replies.  Missing sequence numbers between two replies are assigned an
    interpolated epoch, which avoids reporting false loss when scheduling
    jitter moves contiguous replies across a bucket boundary.
    """

    if bucket_sec <= 0 or interval_sec <= 0:
        raise ValueError("bucket and probe intervals must be positive")
    if not replies:
        return []
    ordered = sorted(replies, key=lambda reply: reply.epoch)
    first = ordered[0].epoch
    last = ordered[-1].epoch
    count = max(1, int(math.floor((last - first) / bucket_sec)) + 1)
    received = [0] * count
    missing = [0] * count

    def bucket_index(epoch: float) -> int:
        return min(count - 1, max(0, int(math.floor((epoch - first) / bucket_sec))))

    for reply in ordered:
        received[bucket_index(reply.epoch)] += 1
    for previous, current in zip(ordered, ordered[1:]):
        gap = current.seq - previous.seq - 1
        if gap <= 0:
            continue
        for sequence_offset in range(1, gap + 1):
            fraction = sequence_offset / (gap + 1)
            epoch = previous.epoch + fraction * (current.epoch - previous.epoch)
            missing[bucket_index(epoch)] += 1

    buckets: list[LossBucket] = []
    for index in range(count):
        start = first + index * bucket_sec
        end = start + bucket_sec
        expected = received[index] + missing[index]
        loss_pct = 0.0 if expected == 0 else 100.0 * missing[index] / expected
        buckets.append(LossBucket(start, end, received[index], expected, loss_pct))
    return buckets


def apply_skew(epoch: float, host_minus_node_sec: float) -> float:
    """Translate a node-local wall epoch to host time."""

    return epoch + host_minus_node_sec


def cut_budget(markers: Sequence[tuple[str, float]]) -> dict[str, float]:
    """Compute ordered cut phases from marker timestamps.

    Marker values may be seconds or milliseconds.  Values above 1e10 are
    treated as Unix milliseconds, matching journald/JSON export conventions.
    ``armed`` is required so process creation is not confused with dataplane
    readiness.
    """

    required = ("drain", "stop", "proc", "armed", "helper", "sync_ready")
    values = dict(markers)
    missing = [name for name in required if name not in values]
    if missing:
        raise ValueError("missing cut markers: " + ", ".join(missing))
    ordered = [values[name] for name in required]
    if any(later < earlier for earlier, later in zip(ordered, ordered[1:])):
        raise ValueError("cut markers are out of order")
    scale = 1000.0 if max(abs(value) for value in ordered) > 1e10 else 1.0
    drain, stop, proc, armed, helper, sync = (value / scale for value in ordered)
    return {
        "drain_to_stop": stop - drain,
        "stop_to_proc": proc - stop,
        "proc_to_armed": armed - proc,
        "armed_to_helper": helper - armed,
        "proc_to_helper": helper - proc,
        "helper_to_sync": sync - helper,
        "stop_to_sync": sync - stop,
    }


def _as_json(value):
    if dataclasses.is_dataclass(value):
        return dataclasses.asdict(value)
    if isinstance(value, Mapping):
        return {str(key): _as_json(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_as_json(item) for item in value]
    return value


def analyze_iperf(path: Path, floor_bytes: float = 1.5 * 1024) -> dict[str, object]:
    parsed = parse_iperf(path)
    streams = parsed["streams"]
    sums = parsed["sum"]
    assert isinstance(streams, dict)
    assert isinstance(sums, list)
    stream_report: dict[str, object] = {}
    for stream_id, rows in sorted(streams.items()):
        stream_report[stream_id] = {
            "intervals": len(rows),
            "zero_gaps": stream_gaps(rows),
            "cwnd_pin_windows": cwnd_pin_windows(rows, floor_bytes=floor_bytes),
            "zero_sec": sum(gap.duration for gap in stream_gaps(rows)),
            "retransmits": sum(row.retr or 0 for row in rows),
        }
    result: dict[str, object] = {
        "path": str(path),
        "ports": parsed["ports"],
        "streams": stream_report,
        "sum": {"intervals": len(sums)},
        "masking": sum_masking(streams, sums),
    }
    if parsed.get("warnings"):
        result["warnings"] = parsed["warnings"]
    return result


def _cli() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    iperf = subparsers.add_parser("iperf", help="analyze iperf3 text or JSON-stream output")
    iperf.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    iperf.add_argument("--floor-bytes", type=float, default=1.5 * 1024)
    iperf.add_argument("path", type=Path)

    ping = subparsers.add_parser("ping", help="analyze timestamped ping -D output")
    ping.add_argument("--json", action="store_true")
    ping.add_argument("--gap-threshold", type=float, default=0.5)
    ping.add_argument("--bucket-sec", type=float, default=1.0)
    ping.add_argument("--interval-sec", type=float, default=0.1,
                      help="accepted but vestigial: loss_buckets is sequence-based, expected counts come from ICMP sequence numbers, not wall-clock buckets")
    ping.add_argument("path", type=Path)

    args = parser.parse_args()
    if args.command == "iperf":
        result = analyze_iperf(args.path, floor_bytes=args.floor_bytes)
    else:
        replies = parse_ping_d(args.path)
        buckets = loss_buckets(
            replies, bucket_sec=args.bucket_sec, interval_sec=args.interval_sec
        )
        result = {
            "path": str(args.path),
            "replies": len(replies),
            "gaps": ping_gaps(replies, gap_thresh_sec=args.gap_threshold),
            "buckets": buckets,
            "max_loss": max((bucket.loss_pct for bucket in buckets), default=0.0),
        }
    # JSON is the stable interface even without --json; human-readable output
    # is just pretty JSON so reports can quote exact values without scraping.
    print(json.dumps(_as_json(result), indent=None if args.json else 2, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(_cli())
