"""Parser and failover oracle for iperf3 JSON-stream or legacy text output.

The reached failover client uses ``--json-stream --forceflush``. The text
``[SUM]`` parser remains available for the sibling harnesses that still use
human-readable interval output.

The text regexes intentionally retain their historical behavior: the
``[SUM]`` matcher also recognizes the final sender/receiver summary and
warmup ``(omitted)`` rows. Existing text callers run without ``-O`` and the
oracle filters summaries by the full-interval duration bound.
"""

import argparse
import json
import math
import re
import sys
from typing import Optional, Tuple

# Match `[SUM]   <start>-<end>   sec  <transferred> <unit>  <rate> <rate-unit>/sec`.
# Capture (rate_value, rate_unit_prefix).
_SUM_RE = re.compile(
    r"^\[SUM\]\s+\d+(?:\.\d+)?-\d+(?:\.\d+)?\s+sec\s+\S+\s+\S+\s+(\S+)\s+([KMGT]?)bits/sec",
    re.IGNORECASE,
)

_UNIT_MULTIPLIER = {
    "": 1,
    "K": 1_000,
    "M": 1_000_000,
    "G": 1_000_000_000,
    "T": 1_000_000_000_000,
}


def parse_sum_line(line: str) -> Optional[Tuple[float, int]]:
    """Return (rate_value, rate_bps) or None if not a [SUM] line."""
    m = _SUM_RE.match(line)
    if not m:
        return None
    try:
        rate_value = float(m.group(1))
    except ValueError:
        return None
    unit = m.group(2).upper()
    multiplier = _UNIT_MULTIPLIER.get(unit)
    if multiplier is None:
        return None
    return (rate_value, int(rate_value * multiplier))


def parse_sum_bps(line: str) -> Optional[int]:
    """Return rate in bits/sec, or None."""
    parsed = parse_sum_line(line)
    return None if parsed is None else parsed[1]


# Match per-interval aggregate or per-stream rows. Capture (stream ID or SUM,
# interval start, interval end, rate value, rate unit prefix).
_INTERVAL_RE = re.compile(
    r"^\[\s*(SUM|[0-9]+)\s*\]\s+(\d+(?:\.\d+)?)-(\d+(?:\.\d+)?)\s+sec\s+\S+\s+\S+\s+(\S+)\s+([KMGT]?)bits/sec",
    re.IGNORECASE,
)


def parse_interval_line(line: str) -> Optional[Tuple[Optional[int], float, float, int]]:
    """Return (stream ID or None for SUM, start, end, bits/sec), or None."""
    match = _INTERVAL_RE.match(line)
    if not match:
        return None
    stream = match.group(1).upper()
    try:
        start = float(match.group(2))
        end = float(match.group(3))
        rate = float(match.group(4))
        bps = int(rate * _UNIT_MULTIPLIER[match.group(5).upper()])
    except (KeyError, ValueError, OverflowError):
        return None
    return (None if stream == "SUM" else int(stream), start, end, bps)

def _json_number(value, field: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"{field} is not numeric")
    try:
        number = float(value)
    except OverflowError as exc:
        raise ValueError(f"{field} is out of range") from exc
    if not math.isfinite(number):
        raise ValueError(f"{field} is not finite")
    return number


def _reject_json_constant(value: str):
    raise ValueError(f"non-standard JSON constant: {value}")


def _json_stream_interval_rows(text: str):
    rows = []
    for lineno, line in enumerate(text.splitlines(), start=1):
        if not line.strip():
            continue
        try:
            event = json.loads(line, parse_constant=_reject_json_constant)
        except (json.JSONDecodeError, ValueError) as exc:
            raise ValueError(f"invalid JSON-stream line {lineno}: {exc}") from exc
        if not isinstance(event, dict):
            raise ValueError(f"JSON-stream line {lineno} is not an event object")
        event_name = event.get("event")
        if not isinstance(event_name, str):
            raise ValueError(f"JSON-stream line {lineno} has no event name")
        if event_name != "interval":
            continue

        data = event.get("data")
        if not isinstance(data, dict):
            raise ValueError(f"JSON interval line {lineno} has no data object")
        streams = data.get("streams", [])
        if not isinstance(streams, list):
            raise ValueError(f"JSON interval line {lineno} has malformed streams")

        stream_rows = []
        for index, stream in enumerate(streams, start=1):
            if not isinstance(stream, dict):
                raise ValueError(f"JSON interval line {lineno} has malformed stream")
            start = _json_number(stream.get("start"), "stream start")
            end = _json_number(stream.get("end"), "stream end")
            bps = _json_number(stream.get("bits_per_second"), "stream bits_per_second")
            stream_id = stream.get("socket", stream.get("id", index))
            if isinstance(stream_id, bool) or not isinstance(stream_id, int):
                raise ValueError(f"JSON interval line {lineno} has malformed stream id")
            if end < start:
                raise ValueError(f"JSON interval line {lineno} has reversed stream interval")
            stream_rows.append((stream_id, start, end, int(bps)))

        summary = data.get("sum")
        if "sum" in data and not isinstance(summary, dict):
            raise ValueError(f"JSON interval line {lineno} has malformed sum")
        if summary is not None:
            start = _json_number(summary.get("start"), "sum start")
            end = _json_number(summary.get("end"), "sum end")
            bps = _json_number(summary.get("bits_per_second"), "sum bits_per_second")
            if end < start:
                raise ValueError(f"JSON interval line {lineno} has reversed sum interval")
            rows.append((None, start, end, int(bps)))
        elif stream_rows:
            start = min(row[1] for row in stream_rows)
            end = max(row[2] for row in stream_rows)
            rows.append((None, start, end, sum(row[3] for row in stream_rows)))
        rows.extend(stream_rows)
    return rows


def _oracle_interval_rows(text: str, json_stream: bool):
    first = next((char for char in text if not char.isspace()), "")
    use_json = json_stream or first == "{"
    if use_json:
        return _json_stream_interval_rows(text), True
    return [
        row for line in text.splitlines()
        if (row := parse_interval_line(line)) is not None
    ], False


def failover_interval_verdict(
    text: str,
    min_bps: int = 1_000_000_000,
    max_consecutive_low: int = 2,
    *,
    json_stream: bool = False,
) -> Tuple[bool, str]:
    """Bound low-rate one-second runs (two intervals maximum); fail closed on gaps."""
    try:
        rows, is_json = _oracle_interval_rows(text, json_stream)
    except ValueError as exc:
        return False, f"invalid JSON-stream interval telemetry: {exc}"
    intervals = [
        row for row in rows
        if row[0] is None and 0.5 <= row[2] - row[1] <= 1.5
    ]
    intervals.sort(key=lambda row: row[1])
    if not intervals:
        source = "JSON interval" if is_json else "[SUM] interval"
        return False, f"no per-second {source} measurements"

    longest = 0
    streak = 0
    previous_end = None
    for _, start, end, bps in intervals:
        if previous_end is not None and start - previous_end > 0.25:
            source = "JSON interval" if is_json else "[SUM] interval telemetry"
            return False, f"missing {source} after {previous_end:.2f}s"
        if bps < min_bps:
            streak += 1
            longest = max(longest, streak)
        else:
            streak = 0
        previous_end = end

    if longest > max_consecutive_low:
        return False, (
            f"longest outage was {longest} consecutive low-throughput intervals "
            f"(budget {max_consecutive_low})"
        )
    return True, (
        f"longest outage was {longest} consecutive low-throughput intervals "
        f"(budget {max_consecutive_low})"
    )


def failover_stream_verdict(
    text: str,
    event_seconds: float,
    expected_streams: int,
    pre_window_seconds: float = 5,
    recovery_deadline_seconds: float = 3,
    *,
    json_stream: bool = False,
    event_label: str = "failover",
) -> Tuple[Optional[bool], str]:
    """Require all expected streams to resume within three seconds of the event."""
    try:
        rows, _ = _oracle_interval_rows(text, json_stream)
    except ValueError as exc:
        return False, f"invalid JSON-stream interval telemetry: {exc}"
    intervals = [
        row for row in rows
        if row[0] is not None and 0.5 <= row[2] - row[1] <= 1.5
    ]

    if intervals:
        last_end = max(row[2] for row in intervals)
        if last_end < event_seconds + 1:
            return (
                None if event_label == "failback" else False,
                f"client telemetry ends at {last_end:.2f}s, before the {event_label} "
                f"event at {event_seconds:g}s: no {event_label} stream evidence",
            )

    before = {
        stream for stream, start, _, bps in intervals
        if event_seconds - pre_window_seconds <= start < event_seconds and bps > 0
    }
    if len(before) != expected_streams:
        return False, (
            f"expected {expected_streams} active streams before {event_label}, observed "
            f"{len(before)} ({', '.join(map(str, sorted(before))) or 'none'})"
        )

    after = {
        stream for stream, start, _, bps in intervals
        if event_seconds + 1 <= start <= event_seconds + recovery_deadline_seconds
        and bps > 0
    }
    missing = sorted(before - after)
    if missing:
        return False, (
            f"streams {', '.join(map(str, missing))} carried data before {event_label} "
            f"but did not resume within {recovery_deadline_seconds:g}s"
        )
    return True, (
        f"all {len(before)} pre-{event_label} streams ({', '.join(map(str, sorted(before)))}) "
        f"resumed data within {recovery_deadline_seconds:g}s"
    )




def main() -> int:
    parser = argparse.ArgumentParser(
        description="Check failover iperf3 interval and stream telemetry."
    )
    parser.add_argument("--failover-check", action="store_true", required=True)
    parser.add_argument("--streams", type=int, required=True)
    parser.add_argument("--min-throughput-gbps", type=float, required=True)
    parser.add_argument("--crash-at", type=float, required=True)
    parser.add_argument(
        "--failback-at",
        type=float,
        default=None,
        help=(
            "seconds from iperf start to the manual-failback instant "
            "(last RG moved); adds a second per-stream verdict"
        ),
    )
    parser.add_argument(
        "--json-stream",
        action="store_true",
        help="parse iperf3 JSON Lines instead of legacy text output",
    )
    args = parser.parse_args()

    text = sys.stdin.read()
    checks = [
        failover_interval_verdict(
            text,
            min_bps=int(args.min_throughput_gbps * 1_000_000_000),
            json_stream=args.json_stream,
        ),
        failover_stream_verdict(
            text, args.crash_at, args.streams, json_stream=args.json_stream
        ),
    ]
    if args.failback_at is not None:
        if args.failback_at <= args.crash_at:
            checks.append((
                False,
                f"failback event at {args.failback_at:g}s does not follow the crash "
                f"event at {args.crash_at:g}s: failback stream evidence is unordered",
            ))
        else:
            checks.append(
                failover_stream_verdict(
                    text,
                    args.failback_at,
                    args.streams,
                    json_stream=args.json_stream,
                    event_label="failback",
                )
            )
    for ok, message in checks:
        status = "VOID" if ok is None else ("PASS" if ok else "FAIL")
        print(f"{status} {message}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
