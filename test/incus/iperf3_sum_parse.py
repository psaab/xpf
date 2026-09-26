"""Parser and failover oracle for `iperf3 -i 1 --forceflush -P N` text output.

Per-second rows look like:
    [SUM]   3.00-4.00   sec  118 MBytes  990 Mbits/sec   ...

Final summary lines look like:
    [SUM]   0.00-60.00  sec  6.96 GBytes  996 Mbits/sec   ...      receiver
    [SUM]   0.00-60.00  sec  6.96 GBytes  996 Mbits/sec   ...      sender

`parse_sum_line` accepts only `[SUM]` aggregate rows. `parse_interval_line`
also recognizes `[N]` per-stream rows for failover survival checks.

CAUTION (hb166 V-12): the regex is NOT anchored at end-of-line, so BOTH
the final-summary rows above AND warmup `(omitted)` rows —
    [SUM]   0.00-1.00   sec  1.00 GBytes  8.59 Gbits/sec  ...  (omitted)
— match `parse_sum_line`. Current callers pass runs without `-O`, so no
omitted rows exist, and they explicitly drop the trailing final-summary
rows. A future caller that scrapes a run started with `-O` (omit N
warmup seconds) MUST filter the leading omitted rows itself; this parser
returns them as ordinary per-second rows.
"""

import argparse
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


def failover_interval_verdict(
    text: str,
    min_bps: int = 1_000_000_000,
    max_consecutive_low: int = 2,
) -> Tuple[bool, str]:
    """Bound low-rate one-second runs (two intervals maximum); fail closed on gaps."""
    intervals = []
    for line in text.splitlines():
        row = parse_interval_line(line)
        if row is not None and row[0] is None and 0.5 <= row[2] - row[1] <= 1.5:
            intervals.append(row)
    intervals.sort(key=lambda row: row[1])
    if not intervals:
        return False, "no per-second [SUM] interval measurements"

    longest = 0
    streak = 0
    previous_end = None
    for _, start, end, bps in intervals:
        if previous_end is not None and start - previous_end > 0.25:
            return False, f"missing [SUM] interval telemetry after {previous_end:.2f}s"
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
) -> Tuple[bool, str]:
    """Require all expected streams to resume within three seconds of failover."""
    intervals = []
    for line in text.splitlines():
        row = parse_interval_line(line)
        if row is not None and row[0] is not None and 0.5 <= row[2] - row[1] <= 1.5:
            intervals.append(row)

    before = {
        stream for stream, start, _, bps in intervals
        if event_seconds - pre_window_seconds <= start < event_seconds and bps > 0
    }
    if len(before) != expected_streams:
        return False, (
            f"expected {expected_streams} active streams before failover, observed "
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
            f"streams {', '.join(map(str, missing))} carried data before failover "
            f"but did not resume within {recovery_deadline_seconds:g}s"
        )
    return True, (
        f"all {len(before)} pre-failover streams ({', '.join(map(str, sorted(before)))}) "
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
    args = parser.parse_args()

    text = sys.stdin.read()
    checks = [
        failover_interval_verdict(
            text, min_bps=int(args.min_throughput_gbps * 1_000_000_000)
        ),
        failover_stream_verdict(text, args.crash_at, args.streams),
    ]
    for ok, message in checks:
        print(f"{'PASS' if ok else 'FAIL'} {message}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
