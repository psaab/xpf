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
from typing import Dict, List, Optional, Tuple

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


# ── #18692: the crash/failback window in real seconds ─────────────────────
#
# The legacy window above takes an integer `$SECONDS` difference as the event
# instant. It can sit a second early or late on iperf3's own clock, and a 1 s
# interval rule then decides a stream that resumed 3-4 s after the event by
# where the second fell. The precise path below fixes both:
#
#   1. The event instant comes from a sub-second source (an ``EventAnchor``
#      with an explicit uncertainty), never from `$SECONDS`.
#   2. Each stream's resume instant is read INSIDE its first data interval
#      (``stream_resume_instants``), so the deadline is judged in real seconds
#      rather than by which 1 s interval the first bytes fell in.
#
# The legacy verdict is kept byte-for-byte as the floor: any input the precise
# path cannot use (no timestamps, no clock offset, legacy text output) falls
# back to it.

# A stream counts as rate-recovered once it reaches this fraction of its
# reference rate (#18692 ask 2).
RATE_RECOVERY_FRACTION = 0.5
# The reference is the LOWER of the stream's own mean over [event-6, event-1)
# and its median over [event+5, event+15). After a takeover the streams
# re-share the link; a stream that comes back at a smaller, steady share is
# recovered at that share, not "never" (one real loss run kept a stream at
# 15-43 % of its pre-crash rate for 66 s while the aggregate ran at or above
# its pre-crash rate).
# The post window ends at event+15 so later disruptions in the run (the
# crashed node's rejoin, the planned RG split, the failback) cannot set it.
_REF_PRE = (6.0, 1.0)
_REF_POST = (5.0, 15.0)
# Data-path anchor: the aggregate must fall below this fraction of its
# pre-event rate for one whole interval to count as the event's stop.
_STOP_EMPTY_FRACTION = 0.05
# Error of the data-path stop estimate: rate noise inside the stop interval
# (the loss aggregate varies about 2 % interval to interval, so about 0.02 s
# of a 1 s interval) plus the time the client's socket buffers take to fill
# once the path is dead.
_STOP_UNCERTAINTY = 0.05


class EventAnchor:
    """An event instant on iperf3's interval clock, with its error bound."""

    def __init__(self, seconds: float, uncertainty: float, source: str):
        self.seconds = seconds
        self.uncertainty = uncertainty
        self.source = source

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


def clock_anchor(
    text: str,
    epoch: Optional[float],
    slack: float,
    offset: Optional[float],
    rtt: Optional[float],
    label: str,
) -> Optional[EventAnchor]:
    """Map an orchestrator wall-clock instant onto iperf3's interval clock.

    - ``epoch``: orchestrator ``date +%s.%N`` taken just before the event's
      command (the sysrq exec) or just after the poll that observed it.
    - ``slack``: how long after ``epoch`` the event may still have happened
      (the crash exec's own dispatch time, bounded by that node's measured
      incus-exec round trip); 0 for an observed instant.
    - ``offset``/``rtt``: iperf3 client host clock minus orchestrator clock,
      from the minimum-RTT ``incus exec date`` reading
      (``_failover_clock_offset``); its error bound is ``rtt / 2``.

    Only the orchestrator and the client host clocks enter; no firewall
    node's clock (and no node0/node1 skew) is involved. The event lies in
    ``[epoch - rtt/2, epoch + slack + rtt/2]`` after mapping; the anchor is
    that interval's midpoint with half its width as the uncertainty.
    """
    if epoch is None or offset is None or rtt is None or rtt < 0 or slack < 0:
        return None
    start = json_stream_start_epoch(text)
    if start is None:
        return None
    return EventAnchor(
        epoch + offset + slack / 2 - start,
        (slack + rtt) / 2,
        f"{label}: orchestrator clock mapped to the iperf3 client clock "
        f"(offset {offset:+.3f}s, rtt {rtt:.3f}s, slack {slack:.3f}s) against "
        "start.timestamp.timemillisecs",
    )


def data_stop_anchor(text: str, lo: float, hi: float) -> Optional[EventAnchor]:
    """The instant the aggregate stopped, on iperf3's own clock, in [lo, hi].

    A crash kills the forwarding path for every stream at once, so the client
    stops sending within milliseconds (its socket buffers fill). The interval
    holding the crash carries a fraction of the pre-event rate equal to the
    fraction of it before the crash; the next interval is empty. This reads
    the event on the SAME clock as the windows, so no skew enters at all.

    It is only a refinement: the caller passes the window the event must lie
    in (from ``clock_anchor``), and a stop outside it, or no empty interval at
    all (a takeover faster than one interval), returns None.
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
    return None


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
    """Per-stream resume instant and rate-recovery interval after an event.

    Returns ``{stream: (resume, rate_start)}``, each on iperf3's clock or None.

    Only intervals starting at or after ``anchor.latest`` are used: they hold
    no byte that can predate the event.

    - ``resume``: inside the first such interval with data, ``[s, e)`` at
      ``bps``. The stream's next interval gives its post-resume rate, so the
      data took ``(e - s) * bps / bps_next`` of the interval and the stream
      resumed at ``e`` minus that (clamped to ``s`` when the first interval
      is the faster one, and ``s`` when there is no next interval). A stream
      still ramping up inside its first interval carried fewer bytes than
      the next interval's rate implies, which makes the estimate read late,
      never early.
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
        resume = None
        for index, (start, end, bps) in enumerate(after):
            if bps <= 0:
                continue
            following = after[index + 1][2] if index + 1 < len(after) else 0
            if following > 0:
                resume = end - (end - start) * min(1.0, bps / following)
            else:
                resume = start
            break
        rate_start = next(
            (start for start, _, bps in after
             if reference > 0 and bps >= RATE_RECOVERY_FRACTION * reference),
            None,
        )
        result[stream] = (resume, rate_start)
    return result


def _latency_text(latencies, anchor: EventAnchor) -> str:
    def stat(index):
        values = [pair[index] for pair in latencies.values() if pair[index] is not None]
        never = sum(1 for pair in latencies.values() if pair[index] is None)
        if not values:
            return "none"
        text = f"max {max(values):.2f}s median {statistics.median(values):.2f}s"
        return text + (f", {never} never" if never else "")

    def fmt(value):
        return "never" if value is None else f"{value:.2f}"

    per_stream = " ".join(
        f"s{stream}={fmt(resume)}/{fmt(rate)}"
        for stream, (resume, rate) in sorted(latencies.items())
    )
    return (
        f"resume after the event: data {stat(0)}; "
        f">={int(RATE_RECOVERY_FRACTION * 100)}% rate {stat(1)} "
        f"(per stream data/rate s: {per_stream}); "
        f"event at {anchor.seconds:.3f}s ±{anchor.uncertainty:.3f}s on iperf3's clock, "
        f"from {anchor.source}"
    )


def resume_latencies(text: str, anchor: EventAnchor, *, json_stream: bool, streams=None):
    """``{stream: (data_latency, rate_latency)}`` in seconds after the anchor.

    ``streams`` defaults to the streams that carried data in the five seconds
    before the event, the set the verdict judges.
    """
    rows, _ = _oracle_interval_rows(text, json_stream)
    if streams is None:
        streams = {
            stream for stream, start, end, bps in rows
            if stream is not None and 0.5 <= end - start <= 1.5
            and anchor.seconds - 5 <= start < anchor.seconds and bps > 0
        }
    result = {}
    for stream, (resume, rate_start) in stream_resume_instants(rows, anchor).items():
        if stream not in streams:
            continue
        result[stream] = (
            None if resume is None else max(0.0, resume - anchor.seconds),
            None if rate_start is None else max(0.0, rate_start - anchor.seconds),
        )
    return result


def precise_stream_verdict(
    text: str,
    anchor: EventAnchor,
    expected_streams: int,
    pre_window_seconds: float = 5,
    recovery_deadline_seconds: float = 3,
    *,
    json_stream: bool = True,
    event_label: str = "failover",
) -> Tuple[Optional[bool], str]:
    """``failover_stream_verdict`` with the window in real seconds (#18692).

    Every pre-event stream must resume (``stream_resume_instants``) no later
    than ``recovery_deadline_seconds`` after ``anchor.seconds``. The message
    carries each stream's data and rate latency plus their max and median,
    and says when a stream's margin to the deadline is inside the anchor's
    own uncertainty.
    """
    try:
        rows, _ = _oracle_interval_rows(text, json_stream)
    except ValueError as exc:
        return False, f"invalid JSON-stream interval telemetry: {exc}"
    intervals = [
        row for row in rows
        if row[0] is not None and 0.5 <= row[2] - row[1] <= 1.5
    ]
    event = anchor.seconds
    last_end = max((row[2] for row in intervals), default=None)
    has_post_event_interval = any(start >= anchor.latest for _, start, _, _ in intervals)
    if event_label == "failback" and not has_post_event_interval:
        if last_end is not None and last_end < anchor.latest:
            return None, (
                f"client telemetry ends at {last_end:.2f}s, before the "
                f"failback event at {event:.3f}s: no failback stream evidence"
            )
        return None, (
            f"client telemetry has no per-stream interval starting at or after "
            f"{anchor.latest:.3f}s: failback recovery window is uncovered"
        )
    if event_label != "failback" and (last_end is None or last_end < anchor.latest + 1):
        return False, (
            f"client telemetry ends at {last_end if last_end is not None else 0:.2f}s, "
            f"before a whole interval after the {event_label} event at {event:.3f}s: "
            f"no {event_label} stream evidence"
        )

    before = {
        stream for stream, start, _, bps in intervals
        if event - pre_window_seconds <= start < event and bps > 0
    }
    if len(before) != expected_streams:
        return False, (
            f"expected {expected_streams} active streams before {event_label}, observed "
            f"{len(before)} ({', '.join(map(str, sorted(before))) or 'none'})"
        )

    latencies = resume_latencies(text, anchor, json_stream=json_stream, streams=before)
    deadline = recovery_deadline_seconds
    missing = sorted(
        stream for stream in before
        if latencies[stream][0] is None or latencies[stream][0] > deadline
    )
    close = sorted(
        stream for stream in before
        if latencies[stream][0] is not None
        and abs(latencies[stream][0] - deadline) <= anchor.uncertainty
    )
    detail = f" [{_latency_text(latencies, anchor)}"
    if close:
        detail += (
            f"; streams {', '.join(map(str, close))} are within the anchor's "
            f"±{anchor.uncertainty:.3f}s of the deadline"
        )
    detail += "]"
    if missing:
        return False, (
            f"streams {', '.join(map(str, missing))} carried data before {event_label} "
            f"but did not resume within {deadline:g}s" + detail
        )
    return True, (
        f"all {len(before)} pre-{event_label} streams ({', '.join(map(str, sorted(before)))}) "
        f"resumed data within {deadline:g}s" + detail
    )


def event_anchor(
    text: str,
    *,
    epoch: Optional[float],
    slack: float,
    offset: Optional[float],
    rtt: Optional[float],
    label: str,
    data_stop: bool,
) -> Optional[EventAnchor]:
    """The precise anchor for one event, or None to fall back to the legacy one.

    ``clock_anchor`` is the measured source. For a crash (``data_stop``) the
    aggregate's stop inside the clock window refines it to the stream data's
    own clock; outside that window, or with no empty interval, the clock
    anchor stands.
    """
    clock = clock_anchor(text, epoch, slack, offset, rtt, label)
    if clock is None:
        return None
    if data_stop:
        try:
            stop = data_stop_anchor(
                text, clock.seconds - clock.uncertainty, clock.latest
            )
        except ValueError:
            stop = None
        if stop is not None:
            stop.source = f"{label}: {stop.source} = the window of {clock.source}"
            return stop
    return clock


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
    # #18692 precise anchors. With --client-clock-offset/--client-clock-rtt
    # and an epoch, the matching verdict is judged in real seconds; without
    # them (or without start.timestamp.timemillisecs in the log) it falls
    # back to the integer --crash-at/--failback-at verdict unchanged.
    parser.add_argument(
        "--crash-epoch",
        type=float,
        default=None,
        help="orchestrator wall clock (date +%%s.%%N) just before the crash command",
    )
    parser.add_argument(
        "--crash-slack",
        type=float,
        default=0.0,
        help=(
            "seconds after --crash-epoch the crash may still have happened "
            "(the crashed node's measured incus-exec round trip)"
        ),
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
    parser.add_argument(
        "--emit-metrics",
        action="store_true",
        help="after the verdicts, print METRIC lines (anchor and resume latencies)",
    )
    args = parser.parse_args()

    text = sys.stdin.read()

    def precise(epoch, slack, label, data_stop):
        if not args.json_stream:
            return None
        return event_anchor(
            text,
            epoch=epoch,
            slack=slack,
            offset=args.client_clock_offset,
            rtt=args.client_clock_rtt,
            label=label,
            data_stop=data_stop,
        )

    def stream_check(at, anchor, label):
        if anchor is not None:
            return precise_stream_verdict(
                text, anchor, args.streams, json_stream=True, event_label=label
            )
        return failover_stream_verdict(
            text, at, args.streams, json_stream=args.json_stream, event_label=label
        )

    crash_anchor = precise(args.crash_epoch, args.crash_slack, "crash", True)
    checks = [
        failover_interval_verdict(
            text,
            min_bps=int(args.min_throughput_gbps * 1_000_000_000),
            json_stream=args.json_stream,
        ),
        stream_check(args.crash_at, crash_anchor, "failover"),
    ]
    events = [("crash", args.crash_at, crash_anchor)]
    if args.failback_at is not None:
        if args.failback_at <= args.crash_at:
            checks.append((
                False,
                f"failback event at {args.failback_at:g}s does not follow the crash "
                f"event at {args.crash_at:g}s: failback stream evidence is unordered",
            ))
        else:
            failback_anchor = precise(args.failback_epoch, 0.0, "failback landed", False)
            checks.append(stream_check(args.failback_at, failback_anchor, "failback"))
            events.append(("failback", args.failback_at, failback_anchor))
    for ok, message in checks:
        status = "VOID" if ok is None else ("PASS" if ok else "FAIL")
        print(f"{status} {message}")
    if args.emit_metrics:
        for name, at, anchor in events:
            # Numeric values only: harness-result.sh records `key=<number>`.
            if anchor is None:
                print(f"METRIC {name}_anchor_precise=0")
                print(f"METRIC {name}_at_s={at:g}")
                continue
            print(f"METRIC {name}_anchor_precise=1")
            print(f"METRIC {name}_at_s={anchor.seconds:.3f}")
            print(f"METRIC {name}_anchor_uncertainty_s={anchor.uncertainty:.3f}")
            try:
                latencies = resume_latencies(text, anchor, json_stream=True)
            except ValueError:
                continue
            for index, kind in ((0, "data"), (1, "rate")):
                values = [pair[index] for pair in latencies.values() if pair[index] is not None]
                if values:
                    print(f"METRIC {name}_resume_{kind}_max_s={max(values):.3f}")
                    print(f"METRIC {name}_resume_{kind}_median_s={statistics.median(values):.3f}")
                never = sum(1 for pair in latencies.values() if pair[index] is None)
                print(f"METRIC {name}_resume_{kind}_never={never}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
