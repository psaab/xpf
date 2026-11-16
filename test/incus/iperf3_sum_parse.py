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
import statistics
from typing import Dict, List, NamedTuple, Optional, Tuple

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

    last_end = max((row[2] for row in intervals), default=None)
    if event_label == "failback":
        has_post_event_interval = any(
            start >= event_seconds + 1 for _, start, _, _ in intervals
        )
        if not has_post_event_interval:
            if last_end is not None and last_end < event_seconds + 1:
                return None, (
                    f"client telemetry ends at {last_end:.2f}s, before the "
                    f"failback event at {event_seconds:g}s: no failback stream evidence"
                )
            return None, (
                f"client telemetry has no per-stream interval starting at or after "
                f"{event_seconds + 1:g}s: failback recovery window is uncovered"
            )
    elif last_end is not None and last_end < event_seconds + 1:
        return (
            False,
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


# ── #18692: the crash/failback cells in real seconds ──────────────────────
#
# The integer verdict above takes a `$SECONDS` difference as the event
# instant. It can sit a second early or late on iperf3's own clock, and its
# 1 s interval rule then decides a stream that resumed 3-4 s after the event
# by where the second fell. The path below (opt-in: ``--straggler-cost``,
# which test-failover passes) fixes both and changes the cell's policy:
#
#   1. The event instant comes from a sub-second source (an ``EventAnchor``
#      with an explicit uncertainty), never from `$SECONDS`.
#   2. Each stream's resume instant is read INSIDE its first data interval
#      (``stream_resume_instants``), so deadlines are judged in real seconds.
#   3. Policy (#18692 review, the coordinator's decision): a stream that has
#      not resumed within RESUME_FAIL_SECONDS is dead or stuck (FAIL); one
#      that resumed after RESUME_COST_SECONDS is a straggler (COST: counted
#      as passed, its latency in the cell text, judged master-relative). The
#      3 s line sits inside TCP's RTO backoff on loss (resumes at 0.97-2.91 s,
#      a gap, then stragglers at 3.75-4.59 s), so as a FAIL line it decided
#      about a quarter of crash runs, master's included, by which side of a
#      retransmission a stream landed on.
#
# With no stop near the crash (a fast takeover), the crash cell is judged
# over a window with MEASURED edges on CLOCK_MONOTONIC (the sysrq command's
# dispatch, and fw1's peer-lost receipt), at both of its ends (#19123,
# measured_window below).
# Without a clock window that holds the crash, the cell first looks for the
# aggregate's stop within ±1 s of the integer anchor (iperf3's own clock, no
# clock reading needed). Without one it falls back to the integer verdict
# evaluated at the integer anchor and one second either side of it, never
# counting an interval that starts before anchor+1 as resume evidence; it
# keeps that verdict when all three agree and is VOID when they do not.
# Callers without ``--straggler-cost`` (ha-smoke-iperf-lib.sh) get the
# integer verdict exactly as before.

RESUME_COST_SECONDS = 3.0
RESUME_FAIL_SECONDS = 10.0
# A stream counts as rate-recovered once it reaches this fraction of its
# reference rate (#18692 ask 2).
RATE_RECOVERY_FRACTION = 0.5
# The reference is the LOWER of the stream's own mean over [event-6, event-1)
# and its median over [event+5, event+15). After a takeover the streams
# re-share the link; a stream that comes back at a smaller, steady share is
# recovered at that share, not "never" (one real loss run kept a stream at
# 15-43 % of its pre-crash rate for 66 s while the aggregate ran at or above
# its pre-crash rate). The post window ends at event+15 so later disruptions
# in the run (the crashed node's rejoin, the planned RG split, the failback)
# cannot set it.
_REF_PRE = (6.0, 1.0)
_REF_POST = (5.0, 15.0)
# Data-path anchor: the aggregate must fall below this fraction of its
# pre-event rate for one whole interval to count as the event's stop.
_STOP_EMPTY_FRACTION = 0.05
# DESIGN BUDGET for the data-path stop estimate, not a measured bound: rate
# noise inside the stop interval (the loss aggregate varies about 2 % interval
# to interval, so about 0.02 s of a 1 s interval) plus the time the client's
# socket buffers take to fill once the path is dead (which only reads late).
# test-failover records the stop's distance from the crash command's epoch
# (`crash_stop_after_epoch_s`) so live runs build the evidence.
_STOP_UNCERTAINTY = 0.05
# The stream-group fallback also requires a corresponding aggregate drop in
# interval k+1, so a later partial group pause cannot impersonate the crash.
_STREAMS_STOP_AGGREGATE_FRACTION = 0.5

# A clock-only anchor wider than this is not precise: the crash's clock window
# runs from the sysrq dispatch to the exec's return (seconds), so without the
# aggregate's stop inside it the cell falls back to the integer verdict.
_MAX_CLOCK_UNCERTAINTY = 0.25


class EventAnchor:
    """An event instant on iperf3's interval clock, with its error bound."""

    def __init__(self, seconds: float, uncertainty: float, source: str):
        self.seconds = seconds
        self.uncertainty = uncertainty
        self.source = source
        # Seconds from the mapped event-command epoch to this anchor, when
        # the anchor is a data stop inside a clock window (a live residual).
        self.after_epoch: Optional[float] = None
        # #19123: a window [seconds, latest] that holds the event, judged at
        # both of its ends (bounded_stream_cell), not a point to judge at.
        self.bounded = False

    @property
    def latest(self) -> float:
        return self.seconds + self.uncertainty

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"EventAnchor({self.seconds:.3f}±{self.uncertainty:.3f}, {self.source!r})"


def json_stream_start_epoch(text: str) -> Optional[float]:
    """Wall-clock instant (iperf3 client host clock) of the test start.

    iperf3 3.17+ writes ``start.timestamp.timemillisecs`` (ms resolution);
    ``timesecs`` alone is integer and cannot fix the sub-second phase, so it
    is not used. The stamp is taken when the control connection is made, a
    few milliseconds before the interval clock's zero (the streams connect
    in between), so a mapped instant reads that much late on the interval
    clock. Returns None when the field is absent or malformed.
    """
    for line in text.splitlines():
        if not line.strip():
            continue
        try:
            event = json.loads(line, parse_constant=_reject_json_constant)
        except ValueError:
            return None
        if not isinstance(event, dict) or event.get("event") != "start":
            continue
        data = event.get("data")
        stamp = data.get("timestamp") if isinstance(data, dict) else None
        millis = stamp.get("timemillisecs") if isinstance(stamp, dict) else None
        if isinstance(millis, bool) or not isinstance(millis, int) or millis <= 0:
            return None
        return millis / 1000.0
    return None


def clock_window(
    text: str,
    before: Optional[float],
    after: Optional[float],
    offset: Optional[float],
    rtt: Optional[float],
) -> Optional[Tuple[float, float]]:
    """``[lo, hi]`` on iperf3's interval clock that must hold the event.

    - ``before``/``after``: orchestrator ``date +%s.%N`` taken just before the
      event's command and just after it returned (for an observed instant,
      both are the observation's stamp).
    - ``offset``/``rtt``: iperf3 client host clock minus orchestrator clock,
      from the minimum-RTT ``incus exec date`` reading
      (``_failover_clock_offset``); its error bound is ``rtt / 2``.

    Only the orchestrator and the client host clocks enter; no firewall
    node's clock (and no node0/node1 skew) is involved.
    """
    if None in (before, after, offset, rtt) or rtt < 0 or after < before:
        return None
    start = json_stream_start_epoch(text)
    if start is None:
        return None
    return before + offset - rtt / 2 - start, after + offset + rtt / 2 - start


def data_stop_anchor(text: str, lo: float, hi: float) -> Optional[EventAnchor]:
    """The instant the aggregate stopped, on iperf3's own clock, in [lo, hi].

    A crash kills the forwarding path for every stream at once, so the client
    stops sending (its socket buffers fill). The interval holding the crash
    carries a fraction of the pre-event rate equal to the fraction of it
    before the crash; the next interval is empty. This reads the event on the
    SAME clock as the windows, so no skew enters at all.

    The first such stop at or after ``lo - 1.5`` is the candidate; it counts
    only inside ``[lo, hi]``. With no empty interval at all (a takeover faster
    than one interval) there is none.
    """
    rows, json_rows = _oracle_interval_rows(text, True)
    if not json_rows:
        return None
    sums = sorted(
        (start, end, bps) for stream, start, end, bps in rows
        if stream is None and 0.5 <= end - start <= 1.5
    )
    for j in range(1, len(sums)):
        k = j - 1
        start_k, end_k, bps_k = sums[k]
        start_j, end_j, bps_j = sums[j]
        if end_k < lo - 1.5 or start_k > hi:
            continue
        pre = [bps for start, end, bps in sums if start_k - 5 <= start < start_k]
        if len(pre) < 3:
            continue
        rate = statistics.mean(pre)
        if rate <= 0 or bps_j >= _STOP_EMPTY_FRACTION * rate or bps_k <= _STOP_EMPTY_FRACTION * rate:
            continue
        stop = (
            start_k
            + (end_k - start_k) * min(1.0, bps_k / rate)
            + (end_j - start_j) * (bps_j / rate)
        )
        if lo <= stop <= hi:
            return EventAnchor(
                stop,
                _STOP_UNCERTAINTY,
                f"aggregate stop on iperf3's own interval clock, inside [{lo:.3f}, {hi:.3f}]s",
            )
        return None
    return _streams_stop_anchor(rows, lo, hi)


def _streams_stop_anchor(rows, lo: float, hi: float) -> Optional[EventAnchor]:
    """The crash read from the streams that stopped together, in [lo, hi].

    A fast takeover can resume some streams inside the interval after the
    crash, so the AGGREGATE never empties (a live loss run on 0.0.29546 kept
    8 % of its rate there). The streams that stayed down for that whole
    interval still carry the crash: each one's bytes in the interval holding
    it are its own pre-crash rate times the part of the interval before the
    crash. At least a quarter of the streams (and at least three) must stop
    in the same interval, which is the crash's signature rather than one
    stream's stall; their median fraction is the stop.

    Those streams sent bytes in interval ``k`` and none in ``k+1``, so the
    crash lies inside ``k`` and ``k+1`` is wholly after it, whatever the
    fraction's error: the anchor cannot make a pre-crash byte count as a
    resume.

    The aggregate's next interval must also be below half its pre-event rate.
    That confirms a path-wide drop while permitting a fast takeover to retain
    a small amount of aggregate throughput; a later pause affecting only a
    stream group cannot anchor when the rest of the aggregate stays live.
    Candidates are examined from earliest to latest, with no assumption about
    how long the sysrq write takes to reach the kernel.
    """
    streams = _stream_intervals(rows)
    aggregates = sorted(
        (start, end, bps) for stream, start, end, bps in rows
        if stream is None and 0.5 <= end - start <= 1.5
    )
    if not streams or not aggregates:
        return None
    need = max(3, (len(streams) + 3) // 4)
    starts = sorted({start for intervals in streams.values() for start, _, _ in intervals})
    for k_start in starts:
        if k_start > hi or k_start < lo - 1.5:
            continue
        aggregate_index = next(
            (i for i, row in enumerate(aggregates) if abs(row[0] - k_start) < 0.05),
            None,
        )
        if aggregate_index is None or aggregate_index + 1 >= len(aggregates):
            continue
        _, aggregate_end, _ = aggregates[aggregate_index]
        following_start, _, aggregate_following = aggregates[aggregate_index + 1]
        if abs(following_start - aggregate_end) >= 0.05:
            continue
        aggregate_pre = [
            bps for start, _, bps in aggregates if k_start - 5 <= start < k_start
        ]
        if len(aggregate_pre) < 3:
            continue
        aggregate_rate = statistics.mean(aggregate_pre)
        if (
            aggregate_rate <= 0
            or aggregate_following >= _STREAMS_STOP_AGGREGATE_FRACTION * aggregate_rate
        ):
            continue
        fractions = []
        for intervals in streams.values():
            index = next((i for i, row in enumerate(intervals) if abs(row[0] - k_start) < 0.05), None)
            if index is None or index + 1 >= len(intervals):
                continue
            start, end, bps = intervals[index]
            following = intervals[index + 1][2]
            pre = [b for a, _, b in intervals if start - 5 <= a < start]
            if len(pre) < 3 or following != 0 or bps <= 0:
                continue
            rate = statistics.mean(pre)
            if rate > 0:
                fractions.append((end - start) * min(1.0, bps / rate))
        if len(fractions) >= need:
            stop = k_start + statistics.median(fractions)
            if lo <= stop <= hi:
                return EventAnchor(
                    stop,
                    _STOP_UNCERTAINTY,
                    f"stop of {len(fractions)} streams together on iperf3's own interval clock "
                    f"(the aggregate never emptied), inside [{lo:.3f}, {hi:.3f}]s",
                )
            return None
    return None


def event_anchor(
    text: str,
    *,
    before: Optional[float],
    after: Optional[float],
    offset: Optional[float],
    rtt: Optional[float],
    label: str,
    data_stop: bool,
) -> Optional[EventAnchor]:
    """The precise anchor for one event, or None to fall back.

    - With ``data_stop`` (the crash): the aggregate's stop inside the clock
      window. The window runs to the sysrq exec's return, so it is far wider
      than the stop's own budget and only says where to look.
    - Otherwise, or with no stop in the window: the window's midpoint, if the
      window is narrow enough to count as precise (an observed instant).
    """
    window = clock_window(text, before, after, offset, rtt)
    if window is None:
        return None
    lo, hi = window
    source = (
        f"{label}: orchestrator clock mapped to the iperf3 client clock "
        f"(offset {offset:+.3f}s, rtt {rtt:.3f}s) against start.timestamp.timemillisecs"
    )
    if data_stop:
        try:
            stop = data_stop_anchor(text, lo, hi)
        except ValueError:
            stop = None
        if stop is not None:
            stop.source = f"{label}: {stop.source}, the window of {source}"
            stop.after_epoch = stop.seconds - (before + offset - json_stream_start_epoch(text))
            return stop
    if (hi - lo) / 2 > _MAX_CLOCK_UNCERTAINTY:
        return None
    return EventAnchor((lo + hi) / 2, (hi - lo) / 2, source)


def _stream_intervals(rows) -> Dict[int, List[Tuple[float, float, int]]]:
    streams: Dict[int, List[Tuple[float, float, int]]] = {}
    for stream, start, end, bps in rows:
        if stream is None or not 0.5 <= end - start <= 1.5:
            continue
        streams.setdefault(stream, []).append((start, end, bps))
    for intervals in streams.values():
        intervals.sort()
    return streams


def stream_resume_instants(rows, anchor: EventAnchor):
    """Per-stream resume instant, its interval, and the rate-recovery start.

    Returns ``{stream: (resume, rate_start, interval)}`` on iperf3's clock,
    ``interval`` being the ``(start, end)`` of the first data interval; each
    is None when the stream never gets there.

    Only intervals starting at or after ``anchor.latest`` are used: they hold
    no byte that can predate the event.

    - ``resume``: inside the first such interval with data, ``[s, e)`` at
      ``bps``. The stream's next interval gives its post-resume rate, so the
      data took ``(e - s) * bps / bps_next`` of the interval and the stream
      resumed at ``e`` minus that (clamped to ``s`` when the first interval
      is the faster one, and ``s`` when there is no next interval). The true
      instant is somewhere in ``[s, e)``: a stream still ramping inside the
      interval makes the read late, a burst followed by a smaller share in
      the next interval makes it early. Callers flag a deadline that falls
      inside that interval rather than trust the read there.
    - ``rate_start``: start of the first such interval at or above
      ``RATE_RECOVERY_FRACTION`` of the stream's reference rate (the issue's
      interval-granular definition; the true instant is within one interval
      after it).
    """
    result = {}
    for stream, intervals in _stream_intervals(rows).items():
        seconds = anchor.seconds
        pre = [
            bps for start, _, bps in intervals
            if seconds - _REF_PRE[0] <= start < seconds - _REF_PRE[1]
        ]
        post = [
            bps for start, _, bps in intervals
            if seconds + _REF_POST[0] <= start < seconds + _REF_POST[1]
        ]
        refs = [
            value for value in (
                statistics.mean(pre) if pre else None,
                statistics.median(post) if post else None,
            ) if value
        ]
        reference = min(refs) if refs else 0
        after = [row for row in intervals if row[0] >= anchor.latest]
        resume = interval = None
        for index, (start, end, bps) in enumerate(after):
            if bps <= 0:
                continue
            following = after[index + 1][2] if index + 1 < len(after) else 0
            if following > 0:
                resume = end - (end - start) * min(1.0, bps / following)
            else:
                resume = start
            interval = (start, end)
            break
        rate_start = next(
            (start for start, _, bps in after
             if reference > 0 and bps >= RATE_RECOVERY_FRACTION * reference),
            None,
        )
        result[stream] = (resume, rate_start, interval)
    return result


def _pre_event_streams(rows, seconds: float, pre_window_seconds: float = 5):
    return {
        stream for stream, start, end, bps in rows
        if stream is not None and 0.5 <= end - start <= 1.5
        and seconds - pre_window_seconds <= start < seconds and bps > 0
    }


def resume_latencies(text: str, anchor: EventAnchor, *, json_stream: bool, streams=None):
    """``{stream: (data_latency, rate_latency, interval)}`` after the anchor.

    Latencies are seconds after ``anchor.seconds``; ``interval`` is the first
    data interval on iperf3's clock. ``streams`` defaults to the streams that
    carried data in the five seconds before the event, the set the cell
    judges.
    """
    rows, _ = _oracle_interval_rows(text, json_stream)
    if streams is None:
        streams = _pre_event_streams(rows, anchor.seconds)
    result = {}
    for stream, (resume, rate_start, interval) in stream_resume_instants(rows, anchor).items():
        if stream not in streams:
            continue
        result[stream] = (
            None if resume is None else max(0.0, resume - anchor.seconds),
            None if rate_start is None else max(0.0, rate_start - anchor.seconds),
            interval,
        )
    return result


def _latency_text(latencies, anchor: EventAnchor) -> str:
    def stat(index):
        values = [entry[index] for entry in latencies.values() if entry[index] is not None]
        never = sum(1 for entry in latencies.values() if entry[index] is None)
        if not values:
            return "none"
        text = f"max {max(values):.2f}s median {statistics.median(values):.2f}s"
        return text + (f", {never} never" if never else "")

    def fmt(value):
        return "never" if value is None else f"{value:.2f}"

    per_stream = " ".join(
        f"s{stream}={fmt(entry[0])}/{fmt(entry[1])}"
        for stream, entry in sorted(latencies.items())
    )
    return (
        f"resume after the event: data {stat(0)}; "
        f">={int(RATE_RECOVERY_FRACTION * 100)}% rate {stat(1)} "
        f"(per stream data/rate s: {per_stream}); "
        f"event at {anchor.seconds:.3f}s ±{anchor.uncertainty:.3f}s on iperf3's clock, "
        f"from {anchor.source}"
    )


def precise_stream_cell(
    text: str,
    anchor: EventAnchor,
    expected_streams: int,
    pre_window_seconds: float = 5,
    *,
    json_stream: bool = True,
    event_label: str = "failover",
) -> Tuple[str, str]:
    """``(status, message)``: PASS, COST, FAIL or VOID, judged in real seconds.

    - FAIL: a pre-event stream has not resumed within RESUME_FAIL_SECONDS
      (dead or stuck), or the evidence is missing.
    - COST: every stream resumed, some after RESUME_COST_SECONDS (named, with
      their latency).
    - PASS: every stream resumed within RESUME_COST_SECONDS.

    The message carries each stream's data and rate latency plus max and
    median, and names any stream whose verdict at a deadline rests on the
    in-interval read or on the anchor's own uncertainty: one whose first data
    interval, widened by the anchor's uncertainty, contains the deadline.
    """
    try:
        rows, _ = _oracle_interval_rows(text, json_stream)
    except ValueError as exc:
        return "FAIL", f"invalid JSON-stream interval telemetry: {exc}"
    intervals = [
        row for row in rows
        if row[0] is not None and 0.5 <= row[2] - row[1] <= 1.5
    ]
    event = anchor.seconds
    last_end = max((row[2] for row in intervals), default=None)
    has_post_event_interval = any(start >= anchor.latest for _, start, _, _ in intervals)
    if event_label == "failback" and not has_post_event_interval:
        if last_end is not None and last_end < anchor.latest:
            return "VOID", (
                f"client telemetry ends at {last_end:.2f}s, before the "
                f"failback event at {event:.3f}s: no failback stream evidence"
            )
        return "VOID", (
            f"client telemetry has no per-stream interval starting at or after "
            f"{anchor.latest:.3f}s: failback recovery window is uncovered"
        )
    if event_label != "failback" and (last_end is None or last_end < anchor.latest + 1):
        return "FAIL", (
            f"client telemetry ends at {last_end if last_end is not None else 0:.2f}s, "
            f"before a whole interval after the {event_label} event at {event:.3f}s: "
            f"no {event_label} stream evidence"
        )

    before = _pre_event_streams(rows, event, pre_window_seconds)
    if len(before) != expected_streams:
        return "FAIL", (
            f"expected {expected_streams} active streams before {event_label}, observed "
            f"{len(before)} ({', '.join(map(str, sorted(before))) or 'none'})"
        )

    latencies = resume_latencies(text, anchor, json_stream=json_stream, streams=before)
    dead = sorted(
        stream for stream in before
        if latencies[stream][0] is None or latencies[stream][0] > RESUME_FAIL_SECONDS
    )
    late = sorted(
        stream for stream in before
        if stream not in dead and latencies[stream][0] > RESUME_COST_SECONDS
    )
    close = []
    for deadline in (RESUME_COST_SECONDS, RESUME_FAIL_SECONDS):
        streams = sorted(
            stream for stream in before
            if latencies[stream][2] is not None
            and latencies[stream][2][0] - anchor.uncertainty
            <= event + deadline
            < latencies[stream][2][1] + anchor.uncertainty
        )
        if streams:
            close.append(
                f"the {deadline:g}s line falls inside the interval streams "
                f"{', '.join(map(str, streams))} resumed in (±{anchor.uncertainty:.3f}s anchor), "
                "so the in-interval read decided their side of it"
            )
    detail = f" [{_latency_text(latencies, anchor)}" + "".join(f"; {note}" for note in close) + "]"
    if dead:
        return "FAIL", (
            f"streams {', '.join(map(str, dead))} carried data before {event_label} "
            f"but did not resume within {RESUME_FAIL_SECONDS:g}s" + detail
        )
    if late:
        named = ", ".join(f"s{stream} {latencies[stream][0]:.2f}s" for stream in late)
        return "COST", (
            f"streams {', '.join(map(str, late))} resumed after {event_label} but later than "
            f"{RESUME_COST_SECONDS:g}s ({named}): stragglers, judged master-relative" + detail
        )
    return "PASS", (
        f"all {len(before)} pre-{event_label} streams ({', '.join(map(str, sorted(before)))}) "
        f"resumed data within {RESUME_COST_SECONDS:g}s" + detail
    )


def _integer_cell_at(rows, at, candidate, expected_streams, event_label):
    """One candidate of the integer fallback: (status, message).

    The old rule (resume evidence from per-stream intervals starting in
    ``[candidate+1, candidate+deadline]``) under the COST/FAIL policy, with
    one change: no interval starting before ``at + 1`` is resume evidence, for
    any candidate. With ``candidate = at - 1`` the old window would start at
    ``at``, and when the true event lies in ``[at, at+1)`` the interval holding
    it starts just after ``at``: its PRE-event bytes would read as a resume for
    every stream, a dead one included (#18703 review).
    """
    intervals = [
        row for row in rows
        if row[0] is not None and 0.5 <= row[2] - row[1] <= 1.5
    ]
    lower = max(candidate + 1, at + 1)
    last_end = max((row[2] for row in intervals), default=None)
    if event_label == "failback" and not any(start >= lower for _, start, _, _ in intervals):
        return "VOID", (
            f"client telemetry has no per-stream interval starting at or after "
            f"{lower:g}s: failback recovery window is uncovered"
        )
    if event_label != "failback" and (last_end is None or last_end < lower):
        return "FAIL", (
            f"client telemetry ends at {last_end if last_end is not None else 0:.2f}s, before "
            f"the {event_label} event at {candidate:g}s: no {event_label} stream evidence"
        )
    before = _pre_event_streams(rows, candidate)
    if len(before) != expected_streams:
        return "FAIL", (
            f"expected {expected_streams} active streams before {event_label}, observed "
            f"{len(before)} ({', '.join(map(str, sorted(before))) or 'none'})"
        )

    def resumed(deadline):
        return {
            stream for stream, start, _, bps in intervals
            if lower <= start <= candidate + deadline and bps > 0
        }

    dead = sorted(before - resumed(RESUME_FAIL_SECONDS))
    if dead:
        return "FAIL", (
            f"streams {', '.join(map(str, dead))} carried data before {event_label} "
            f"but did not resume within {RESUME_FAIL_SECONDS:g}s"
        )
    late = sorted(before - resumed(RESUME_COST_SECONDS))
    if late:
        return "COST", (
            f"streams {', '.join(map(str, late))} resumed after {event_label} but later than "
            f"{RESUME_COST_SECONDS:g}s: stragglers, judged master-relative"
        )
    return "PASS", (
        f"all {len(before)} pre-{event_label} streams ({', '.join(map(str, sorted(before)))}) "
        f"resumed data within {RESUME_COST_SECONDS:g}s"
    )


def integer_three_anchor_cell(
    text: str,
    event_seconds: float,
    expected_streams: int,
    *,
    json_stream: bool,
    event_label: str = "failover",
) -> Tuple[str, str]:
    """The integer verdict at the integer anchor and one second either side
    of it (its own error). All three agreeing keeps the verdict; any
    disagreement is VOID, because the integer clock cannot say which side of
    a line a stream fell on."""
    try:
        rows, _ = _oracle_interval_rows(text, json_stream)
    except ValueError as exc:
        return "FAIL", f"invalid JSON-stream interval telemetry: {exc}"
    cells = {
        candidate: _integer_cell_at(rows, event_seconds, candidate, expected_streams, event_label)
        for candidate in (event_seconds - 1, event_seconds, event_seconds + 1)
    }
    statuses = {candidate: cell[0] for candidate, cell in cells.items()}
    status, message = cells[event_seconds]
    note = (
        f" [integer anchor {event_seconds:g}s (harness SECONDS) and ±1 s, resume evidence "
        f"from {event_seconds + 1:g}s on: "
        + ", ".join(f"{at:g}s {statuses[at]}" for at in sorted(cells)) + "]"
    )
    if len(set(statuses.values())) == 1:
        return status, message + note
    return "VOID", (
        f"the integer {event_label} anchor cannot place the streams: "
        f"the verdict changes within its own ±1 s" + note
    )


def resolve_anchor(
    text: str,
    at: float,
    *,
    before: Optional[float],
    after: Optional[float],
    offset: Optional[float],
    rtt: Optional[float],
    crash: bool,
) -> Optional[EventAnchor]:
    """The precise anchor for one event, or None for the integer fallback.

    1. The orchestrator's clock window (``event_anchor``): for the crash, the
       aggregate's stop inside it; for the failback, the landing poll's stamp.
    2. For the crash only, with no clock reading or no stop in its window:
       the aggregate's stop within ``[at-1, at+1]`` of the integer anchor. It
       is on iperf3's own clock and needs no clock reading (#18703 review;
       the offline re-judge anchored 24 of 29 runs this way).
    """
    anchor = event_anchor(
        text, before=before, after=after, offset=offset, rtt=rtt,
        label="crash" if crash else "failback landed", data_stop=crash,
    )
    if anchor is not None or not crash:
        return anchor
    try:
        stop = data_stop_anchor(text, at - 1, at + 1)
    except ValueError:
        return None
    window = clock_window(text, before, after, offset, rtt)
    if stop is not None and window is not None and stop.seconds < window[0]:
        return None  # a stop before the crash command was even sent is not the crash
    if stop is not None:
        stop.source = f"crash: {stop.source}, the integer anchor {at:g}s ±1 s (no clock window held it)"
    return stop


# ── #19123: a crash window bounded by MEASURED edges ─────────────────────
#
# A fast takeover leaves no empty aggregate interval and too few streams
# stopped together, so the stop reads above find nothing; the clock window
# (it runs to the sysrq exec's return) is seconds wide; and the integer
# anchor's ±1 s VOIDed 8 of 10 such runs. Both edges of a window that holds
# the crash can still be MEASURED, with no throughput model, and on
# CLOCK_MONOTONIC only: a realtime clock can step between two readings and
# move an edge across the crash (#19123 review, cycle 2). iperf3's interval
# clock IS the LAN host's CLOCK_MONOTONIC, less its zero.
#
#   - T_lo, the sysrq command's dispatch on the interval clock: the
#     orchestrator's CLOCK_MONOTONIC read just before the exec ("dispatch"),
#     mapped onto the LAN host's clock with the LAN host's offset (-rtt/2,
#     less the rate budget), minus the zero's UPPER bound. test-failover
#     stamps every line the client writes with the LAN host's CLOCK_MONOTONIC
#     as it arrives (failover_start_arrival_stamper); a line arrives only
#     after iperf3 emitted it at its interval's end, so zero <= stamp - end.
#   - T_hi, the survivor's own record that the crash had happened: the
#     journal's CLOCK_MONOTONIC receipt stamp of fw1's "marking peer lost",
#     mapped onto the orchestrator's clock with fw1's offset and onto the LAN
#     host's (each +rtt/2, plus the rate budget), minus the zero's LOWER
#     bound: the LAN host's CLOCK_MONOTONIC read before the client was
#     launched (failover_arrival_launch). It must follow the dispatch, or it
#     is not this crash's and there is no window.
#
# Each monotonic reading carries its host's boot id, and one host's readings
# must share one. Each host's offset is read before the crash and again after
# the run; the two must agree within their rtts plus the rate budget. A window
# wider than _MAX_WIDTH is declined: fw1 detects a silent peer within about
# 2.2 s even under the sync-recency guard, so a wider one means fw1's stamp is
# not this crash's detection (or the exec stalled). It could not confirm PASS
# anyway, and with T_hi near the telemetry's end it could FAIL both ends.
#
# bounded_stream_cell judges the window at BOTH ends with resume evidence
# from T_hi on; a disagreement is VOID. A PASS or COST must then also hold
# with each stream's resume taken at the END of its first data interval (an
# upper bound; never the in-interval read, which a late resume with a fast
# first burst reads early), measured from T_lo. And each stream must be
# observed carrying data in every interval from that one through
# RESUME_COST_SECONDS past its end. "PASS is never a true COST or FAIL, and
# COST never a true FAIL" rests on three premises:
#   (i)   launch <= zero <= stamp - end on the LAN host's CLOCK_MONOTONIC:
#         the launch reading returns before the client starts, iperf3 starts
#         its interval clock after it starts, and it writes an interval's line
#         only after that interval's end (iperf3 3.20 iperf_api.c);
#   (ii)  fw0 crashed before fw1's "marking peer lost" receipt stamp (fw1
#         declares its peer lost only after fw0's heartbeats stop; journald
#         stamps an entry when it receives it), and fw1 lost no peer between
#         the dispatch and the crash;
#   (iii) a min-RTT offset reading is right to +/-rtt/2 at its midpoint, and
#         two hosts' CLOCK_MONOTONIC never step and advance within
#         _CLOCK_RATE of each other (NTP slews each by at most 500 ppm). The
#         boot-id and agreement checks test this premise at the run's ends.
# With a stop seen but rejected (it contradicts the precise path's clock
# mapping), or without any reading, the cell is the integer three-anchor cell
# as before. Where the bounded cell is VOID, the CLI keeps the integer cell's
# verdict when its three anchors agree, so the bounded path never leaves the
# gate worse than master (#19123 review, R24 NEW-C).
_CLOCK_RATE = 1e-3
_MAX_WIDTH = 4.0
# Interval boundaries are contiguous when they agree to this many seconds.
_CONTIGUOUS = 1e-3


class MonoReading(NamedTuple):
    """One host's CLOCK_MONOTONIC minus the orchestrator's, read at ``at``
    (orchestrator CLOCK_MONOTONIC) over a round trip of ``rtt`` seconds."""

    offset: float
    rtt: float
    at: float
    boot: str


def _boot_id(text: str) -> str:
    """A boot id as journald prints it: /proc prints dashes, journald none."""
    return text.replace("-", "").lower()


def parse_crash_readings(text: Optional[str]) -> Optional[dict]:
    """test-failover's readings file, or None when malformed or incomplete.

    Lines: ``dispatch <mono>``; ``<lan|fw1> <pre|post> <offset> <rtt> <at>
    <boot_id>`` (failover_mono_reading); ``fw1 lost <fw1 mono> <boot_id>``.
    Every line appears once."""
    if text is None:
        return None
    out = {}
    for row in text.splitlines():
        fields = row.split()
        if not fields:
            continue
        try:
            if fields[0] == "dispatch" and len(fields) == 2:
                key, value = "dispatch", float(fields[1])
                numbers = (value,)
            elif fields[:2] == ["fw1", "lost"] and len(fields) == 4:
                key, value = "lost", (float(fields[2]), _boot_id(fields[3]))
                numbers = value[:1]
            elif fields[0] in ("lan", "fw1") and fields[1] in ("pre", "post") and len(fields) == 6:
                key = (fields[0], fields[1])
                value = MonoReading(
                    float(fields[2]), float(fields[3]), float(fields[4]), _boot_id(fields[5])
                )
                numbers = value[:3]
            else:
                return None
        except ValueError:
            return None
        if key in out or not all(math.isfinite(number) for number in numbers):
            return None
        out[key] = value
    needed = {"dispatch", "lost", ("lan", "pre"), ("lan", "post"), ("fw1", "pre"), ("fw1", "post")}
    if set(out) != needed:
        return None
    if any(out[(host, when)].rtt < 0 for host in ("lan", "fw1") for when in ("pre", "post")):
        return None
    return out


def arrival_zero_bounds(arrivals: Optional[str]) -> Optional[Tuple[float, float, str, int]]:
    """``(launch, zero_hi, boot, n)`` from the client's arrival file: the LAN
    host's CLOCK_MONOTONIC read before the client started (a lower bound for
    the interval clock's zero), and the least ``stamp - end`` over the ``n``
    stamped interval lines (an upper bound). A line stamped before the launch
    reading is not this run's and is skipped. None without the launch line or
    any stamped interval line."""
    if arrivals is None:
        return None
    launch = boot = None
    samples = []
    for row in arrivals.splitlines():
        head, sep, rest = row.partition("\t")
        if not sep:
            continue
        if head == "launch":
            value, _, tail = rest.partition("\t")
            if launch is not None:
                return None  # two launches: not one run's file
            try:
                launch = float(value)
            except ValueError:
                return None
            boot = _boot_id(tail.strip()) or None
            continue
        try:
            stamp = float(head)
            event = json.loads(rest, parse_constant=_reject_json_constant)
        except ValueError:
            continue
        if not math.isfinite(stamp) or not isinstance(event, dict) or event.get("event") != "interval":
            continue
        data = event.get("data")
        summary = data.get("sum") if isinstance(data, dict) else None
        end = summary.get("end") if isinstance(summary, dict) else None
        if isinstance(end, bool) or not isinstance(end, (int, float)) or not math.isfinite(end):
            continue
        samples.append((stamp, end))
    if launch is None or boot is None or not math.isfinite(launch):
        return None
    zeros = [stamp - end for stamp, end in samples if stamp >= launch]
    if not zeros:
        return None
    return launch, min(zeros), boot, len(zeros)


def _mapping_error(reading: MonoReading, at: float) -> float:
    """How far ``reading`` can be off when used at orchestrator time ``at``."""
    return reading.rtt / 2 + _CLOCK_RATE * abs(at - reading.at)


def measured_window(
    arrivals: Optional[str], readings: Optional[dict]
) -> Tuple[Optional[EventAnchor], str]:
    """``(anchor, reason)``: ``EventAnchor(T_lo, T_hi - T_lo)`` with ``bounded``
    set, on iperf3's interval clock, from the measured edges above; None and
    the reason when a reading is missing or a check fails."""
    zero = arrival_zero_bounds(arrivals)
    if zero is None:
        return None, "no launch reading or no stamped interval line"
    if readings is None:
        return None, "the clock readings are missing or malformed"
    launch, zero_hi, lan_boot, samples = zero
    if zero_hi < launch:
        return None, "an arrival stamp implies an interval zero before the client's launch"
    lost, lost_boot = readings["lost"]
    for host, boot in (("lan", lan_boot), ("fw1", lost_boot)):
        pre, post = readings[(host, "pre")], readings[(host, "post")]
        if pre.boot != boot or post.boot != boot:
            return None, f"{host}'s monotonic readings span more than one boot"
        if abs(post.offset - pre.offset) > (
            (pre.rtt + post.rtt) / 2 + _CLOCK_RATE * abs(post.at - pre.at)
        ):
            return None, (
                f"{host}'s clock offset moved from {pre.offset:+.6f}s to {post.offset:+.6f}s "
                "over the run, beyond the readings' rtts and the rate budget"
            )
    lan, fw1 = readings[("lan", "pre")], readings[("fw1", "pre")]
    dispatch = readings["dispatch"]
    lost_at = lost - fw1.offset
    lost_error = _mapping_error(fw1, lost_at)
    if lost_at - lost_error < dispatch:
        return None, "fw1 lost its peer before the sysrq was sent: not this crash"
    t_lo = dispatch + lan.offset - _mapping_error(lan, dispatch) - zero_hi
    lost_latest = lost_at + lost_error
    t_hi = lost_latest + lan.offset + _mapping_error(lan, lost_latest) - launch
    if t_hi - t_lo > _MAX_WIDTH:
        return None, (
            f"the window is {t_hi - t_lo:.2f}s wide, over {_MAX_WIDTH:g}s: fw1's peer-lost "
            "stamp is too late to be this crash's detection"
        )
    anchor = EventAnchor(
        t_lo,
        t_hi - t_lo,
        f"crash bounded by the sysrq command's dispatch and fw1's peer-lost receipt on "
        f"CLOCK_MONOTONIC (zero in [{launch:.3f}, {zero_hi:.3f}] from the launch reading and "
        f"{samples} arrival stamps; LAN offset {lan.offset:+.3f}s rtt {lan.rtt:.3f}s, fw1 "
        f"offset {fw1.offset:+.3f}s rtt {fw1.rtt:.3f}s)",
    )
    anchor.bounded = True
    return anchor, "measured"


def measured_bounded_anchor(arrivals: Optional[str], readings: Optional[dict]):
    return measured_window(arrivals, readings)[0]


def stop_seen(
    text: str,
    at: float,
    *,
    before: Optional[float],
    after: Optional[float],
    offset: Optional[float],
    rtt: Optional[float],
) -> bool:
    """Whether a stop candidate exists near the crash (in ``at`` ±1 s, or from
    1.5 s before the clock window to its end). Called when ``resolve_anchor``
    found no anchor, a True means it SAW a stop and rejected it: the stop lies
    before the mapped dispatch, so the precise path's clock mapping reads
    late; the bounded window does not override that contradiction (#19123
    review)."""
    lo, hi = at - 1, at + 1
    window = clock_window(text, before, after, offset, rtt)
    if window is not None:
        lo, hi = min(lo, window[0] - 1.5), max(hi, window[1])
    try:
        return data_stop_anchor(text, lo, hi) is not None
    except ValueError:
        return False


def _first_data_intervals(rows, latest: float, streams) -> Dict[int, Optional[Tuple[float, float]]]:
    """Each stream's first interval with data among those starting at or after
    ``latest`` (they hold no byte that can predate the event), or None."""
    instants = stream_resume_instants(rows, EventAnchor(latest, 0.0, "bounded"))
    return {
        stream: instants[stream][2] if stream in instants else None
        for stream in streams
    }


def _uncovered_resumes(rows, firsts) -> List[int]:
    """The streams not observed carrying data in EVERY interval from their
    first data interval through RESUME_COST_SECONDS past its end: a missing
    interval (a gap, or telemetry that ends) or an empty one fails."""
    intervals = _stream_intervals(rows)
    out = []
    for stream, first in sorted(firsts.items()):
        if first is None:
            continue
        horizon = first[1] + RESUME_COST_SECONDS
        cursor, covered = first[0], False
        for start, end, bps in intervals.get(stream, []):
            if start < first[0] - _CONTIGUOUS:
                continue
            if abs(start - cursor) > _CONTIGUOUS:
                break  # a missing interval
            if bps <= 0:
                break  # an empty one
            cursor = end
            if cursor >= horizon - _CONTIGUOUS:
                covered = True
                break
        if not covered:
            out.append(stream)
    return out


def bounded_stream_cell(
    text: str,
    anchor: EventAnchor,
    expected_streams: int,
    *,
    event_label: str = "failover",
) -> Tuple[str, str]:
    """The crash cell over a bounded window: ``precise_stream_cell`` at its
    earliest end (latencies from ``anchor.seconds``) and at its latest end
    (from ``anchor.latest``), both with resume evidence only from intervals
    starting at or after ``anchor.latest``. A disagreement is VOID. A PASS or
    COST must also hold with every judged stream's resume at the END of its
    first data interval, measured from the earliest end, and with data in
    every interval through RESUME_COST_SECONDS past that end; else VOID."""
    earliest = EventAnchor(anchor.seconds, anchor.uncertainty, anchor.source)
    latest = EventAnchor(anchor.latest, 0.0, anchor.source)
    status_lo, message_lo = precise_stream_cell(
        text, earliest, expected_streams, json_stream=True, event_label=event_label
    )
    status_hi, message_hi = precise_stream_cell(
        text, latest, expected_streams, json_stream=True, event_label=event_label
    )
    note = (
        f" [{event_label} bounded to [{anchor.seconds:.3f}, {anchor.latest:.3f}]s, judged at "
        f"both ends: {status_lo} at the earliest, {status_hi} at the latest]"
    )
    if status_lo != status_hi:
        return "VOID", (
            f"the bounded {event_label} window cannot place the streams: the verdict changes "
            f"between its ends" + note + f"; at the earliest end: {message_lo}"
        )
    if status_lo in ("PASS", "COST"):
        rows, _ = _oracle_interval_rows(text, True)
        firsts = _first_data_intervals(
            rows, anchor.latest, _pre_event_streams(rows, anchor.seconds)
        )
        line = RESUME_COST_SECONDS if status_lo == "PASS" else RESUME_FAIL_SECONDS
        late = sorted(
            stream for stream, first in firsts.items()
            if first is None or first[1] - anchor.seconds > line
        )
        if late:
            return "VOID", (
                f"the bounded {event_label} window cannot confirm {status_lo}: streams "
                f"{', '.join(map(str, late))} have a first data interval ending more than "
                f"{line:g}s after the window's earliest end, so only the in-interval read puts "
                f"their resume inside {line:g}s" + note
            )
        uncovered = _uncovered_resumes(rows, firsts)
        if uncovered:
            return "VOID", (
                f"the bounded {event_label} window's resume evidence is not sustained: streams "
                f"{', '.join(map(str, uncovered))} are not observed carrying data in every "
                f"interval through {RESUME_COST_SECONDS:g}s past their first data interval" + note
            )
    return status_lo, message_lo + note


def integer_stream_cell(
    text: str,
    event_seconds: float,
    expected_streams: int,
    *,
    json_stream: bool,
    event_label: str = "failover",
) -> Tuple[str, str]:
    """The fallback cell when no clock window gives a precise anchor.

    For the crash, the aggregate's stop within ±1 s of the integer anchor
    first (``resolve_anchor``); without one, ``integer_three_anchor_cell``.
    """
    if json_stream and event_label != "failback":
        stop = resolve_anchor(
            text, event_seconds, before=None, after=None, offset=None, rtt=None, crash=True
        )
        if stop is not None:
            return precise_stream_cell(
                text, stop, expected_streams, json_stream=True, event_label=event_label
            )
    return integer_three_anchor_cell(
        text, event_seconds, expected_streams, json_stream=json_stream, event_label=event_label
    )


def _add_bounded_window_args(parser) -> None:
    """#19123's measured-window readings, shared by both CLI modes."""
    parser.add_argument(
        "--client-arrivals",
        default=None,
        help="the client's arrival file: a launch line, then <LAN-host CLOCK_MONOTONIC>TAB<line> "
        "(failover_arrival_launch, failover_start_arrival_stamper)",
    )
    parser.add_argument(
        "--crash-readings",
        default=None,
        help="the dispatch, offset and peer-lost CLOCK_MONOTONIC readings "
        "(parse_crash_readings)",
    )


def _read_text(path):
    if not path:
        return None
    try:
        with open(path, encoding="utf-8", errors="replace") as handle:
            return handle.read()
    except OSError:
        return None


def print_crash_anchor(argv) -> int:
    """``--print-crash-anchor``: the crash instant the stream cell will use.

    Prints ``<seconds> <uncertainty> precise``, ``<T_lo> <width> bounded``
    (#19123: the window's earliest edge, which the cell's latencies are
    measured from at their most conservative) or ``<integer-at> 1 integer``,
    so test-failover can hand the zero-interval producer the same anchor
    before the cells run.
    """
    parser = argparse.ArgumentParser(description="Print the #18692 crash anchor.")
    parser.add_argument("--print-crash-anchor", action="store_true", required=True)
    parser.add_argument("--crash-at", type=float, required=True)
    parser.add_argument("--crash-epoch", type=float, default=None)
    parser.add_argument("--crash-epoch-after", type=float, default=None)
    parser.add_argument("--client-clock-offset", type=float, default=None)
    parser.add_argument("--client-clock-rtt", type=float, default=None)
    _add_bounded_window_args(parser)
    args = parser.parse_args(argv)
    text = sys.stdin.read()
    try:
        anchor = resolve_anchor(
            text, args.crash_at, before=args.crash_epoch, after=args.crash_epoch_after,
            offset=args.client_clock_offset, rtt=args.client_clock_rtt, crash=True,
        )
    except ValueError:
        anchor = None
    seen = anchor is None and stop_seen(
        text, args.crash_at, before=args.crash_epoch, after=args.crash_epoch_after,
        offset=args.client_clock_offset, rtt=args.client_clock_rtt,
    )
    if anchor is None and not seen:
        bounded = measured_bounded_anchor(
            _read_text(args.client_arrivals), parse_crash_readings(_read_text(args.crash_readings))
        )
        if bounded is not None:
            print(f"{bounded.seconds:.3f} {bounded.uncertainty:.3f} bounded")
            return 0
    if anchor is None:
        print(f"{args.crash_at:g} 1 integer")
    else:
        print(f"{anchor.seconds:.3f} {anchor.uncertainty:.3f} precise")
    return 0


def main() -> int:
    if "--print-crash-anchor" in sys.argv[1:]:
        return print_crash_anchor(sys.argv[1:])
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
    # #18692. Without --straggler-cost the stream cells are the integer
    # verdict exactly as before (ha-smoke-iperf-lib.sh relies on that).
    parser.add_argument(
        "--straggler-cost",
        action="store_true",
        help=(
            "judge the stream cells in real seconds when an anchor is precise: "
            f"FAIL unresumed within {RESUME_FAIL_SECONDS:g}s, COST resumed after "
            f"{RESUME_COST_SECONDS:g}s; otherwise the integer verdict at the anchor "
            "and +/-1 s, VOID when those disagree"
        ),
    )
    parser.add_argument(
        "--crash-epoch",
        type=float,
        default=None,
        help="orchestrator wall clock (date +%%s.%%N) just before the crash command",
    )
    parser.add_argument(
        "--crash-epoch-after",
        type=float,
        default=None,
        help="orchestrator wall clock just after the crash command returned or failed",
    )
    parser.add_argument(
        "--failback-epoch",
        type=float,
        default=None,
        help="orchestrator wall clock just after the poll that saw the last RG land",
    )
    parser.add_argument(
        "--client-clock-offset",
        type=float,
        default=None,
        help="iperf3 client host clock minus orchestrator clock, seconds",
    )
    parser.add_argument(
        "--client-clock-rtt",
        type=float,
        default=None,
        help="round trip of the reading that produced --client-clock-offset",
    )
    _add_bounded_window_args(parser)
    parser.add_argument(
        "--emit-metrics",
        action="store_true",
        help="after the verdicts, print numeric METRIC lines (anchors and resume latencies)",
    )
    args = parser.parse_args()
    precise_inputs = (
        args.crash_epoch, args.crash_epoch_after, args.failback_epoch,
        args.client_clock_offset, args.client_clock_rtt, args.client_arrivals,
        args.crash_readings,
    )
    if not args.straggler_cost and any(value is not None for value in precise_inputs):
        parser.error("the epoch and clock flags need --straggler-cost")

    text = sys.stdin.read()
    arrivals = _read_text(args.client_arrivals)
    readings = parse_crash_readings(_read_text(args.crash_readings))

    def legacy_check(at, label):
        return failover_stream_verdict(
            text, at, args.streams, json_stream=args.json_stream, event_label=label
        )

    def cell(at, before, after, label, crash):
        anchor = None
        if args.json_stream:
            anchor = resolve_anchor(
                text, at, before=before, after=after, offset=args.client_clock_offset,
                rtt=args.client_clock_rtt, crash=crash,
            )
        if anchor is None and args.json_stream and crash and not stop_seen(
            text, at, before=before, after=after, offset=args.client_clock_offset,
            rtt=args.client_clock_rtt,
        ):
            # #19123: no stop to anchor on (a fast takeover); a window with
            # measured edges, judged at both ends.
            anchor = measured_bounded_anchor(arrivals, readings)
        if anchor is not None and anchor.bounded:
            status, message = bounded_stream_cell(
                text, anchor, args.streams, event_label=label
            )
            if status == "VOID":
                # Never worse than master: where the bounded window cannot
                # decide, master's integer cell does whenever its three
                # anchors agree.
                fallback, fallback_message = integer_three_anchor_cell(
                    text, at, args.streams, json_stream=args.json_stream, event_label=label
                )
                if fallback != "VOID":
                    status, anchor = fallback, None
                    message = (
                        fallback_message + f" [#19123: the bounded window is VOID ({message}); "
                        "the three integer anchors agree, so their verdict stands, as on master]"
                    )
        elif anchor is not None:
            status, message = precise_stream_cell(
                text, anchor, args.streams, json_stream=True, event_label=label
            )
        else:
            status, message = integer_three_anchor_cell(
                text, at, args.streams, json_stream=args.json_stream, event_label=label
            )
        return status, message, anchor

    def as_line(ok, message):
        return ("VOID" if ok is None else ("PASS" if ok else "FAIL")), message

    lines = [as_line(*failover_interval_verdict(
        text,
        min_bps=int(args.min_throughput_gbps * 1_000_000_000),
        json_stream=args.json_stream,
    ))]
    events = []
    if args.straggler_cost:
        status, message, anchor = cell(
            args.crash_at, args.crash_epoch, args.crash_epoch_after, "failover", True
        )
        lines.append((status, message))
        events.append(("crash", args.crash_at, anchor))
    else:
        lines.append(as_line(*legacy_check(args.crash_at, "failover")))
    if args.failback_at is not None:
        if args.failback_at <= args.crash_at:
            lines.append((
                "FAIL",
                f"failback event at {args.failback_at:g}s does not follow the crash "
                f"event at {args.crash_at:g}s: failback stream evidence is unordered",
            ))
        elif args.straggler_cost:
            status, message, anchor = cell(
                args.failback_at, args.failback_epoch, args.failback_epoch, "failback", False
            )
            lines.append((status, message))
            events.append(("failback", args.failback_at, anchor))
        else:
            lines.append(as_line(*legacy_check(args.failback_at, "failback")))
    for status, message in lines:
        print(f"{status} {message}")
    if args.emit_metrics:
        for name, at, anchor in events:
            # Numeric values only: harness-result.sh records `key=<number>`.
            if anchor is None:
                print(f"METRIC {name}_anchor_precise=0")
                print(f"METRIC {name}_anchor_bounded=0")
                print(f"METRIC {name}_at_s={at:g}")
                continue
            # #19123: a bounded window is not a precise point. Its at_s is the
            # earliest edge and its uncertainty the window's width, so the
            # resume latencies below are the conservative (latest) reading.
            print(f"METRIC {name}_anchor_precise={0 if anchor.bounded else 1}")
            print(f"METRIC {name}_anchor_bounded={1 if anchor.bounded else 0}")
            print(f"METRIC {name}_at_s={anchor.seconds:.3f}")
            print(f"METRIC {name}_anchor_uncertainty_s={anchor.uncertainty:.3f}")
            if anchor.after_epoch is not None:
                print(f"METRIC {name}_stop_after_epoch_s={anchor.after_epoch:.3f}")
            try:
                latencies = resume_latencies(text, anchor, json_stream=True)
            except ValueError:
                continue
            for index, kind in ((0, "data"), (1, "rate")):
                values = [entry[index] for entry in latencies.values() if entry[index] is not None]
                if values:
                    print(f"METRIC {name}_resume_{kind}_max_s={max(values):.3f}")
                    print(f"METRIC {name}_resume_{kind}_median_s={statistics.median(values):.3f}")
                never = sum(1 for entry in latencies.values() if entry[index] is None)
                print(f"METRIC {name}_resume_{kind}_never={never}")
            late = sum(
                1 for entry in latencies.values()
                if entry[0] is not None and RESUME_COST_SECONDS < entry[0] <= RESUME_FAIL_SECONDS
            )
            print(f"METRIC {name}_resume_straggler_streams={late}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
