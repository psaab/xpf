#!/usr/bin/env python3
"""PASS/FAIL oracle over a rolling-upgrade iperf3 evidence log (#12200).

The live client is an established multi-stream `iperf3 --json-stream -i 0.1`
flow. `cluster-setup.sh` writes wall-clock `cut_start`/`cut_end` markers just
around each `xpfd upgrade --rolling`; a separate sampler records the SHA256
of each running `/proc/<MainPID>/exe` throughout the two cuts. The oracle
correlates those records with every per-stream interval and reports exactly
one CUT verdict for each cut plus a version/mixed-version verdict.

A cut fails if a stream was not carrying traffic beforehand, no sample for a
stream appears across the cut, a stream has a multi-second zero window, or an
iperf error event is present. The replay path accepts the historical #10023
text log, whose 30-second stranded streams are the hermetic #10261-shaped red
control. A no-op-drain build (new executable SHA equals old SHA) is rejected.

Exit status: 0 all pass; 1 measured regression; 2 unusable evidence.
"""

from __future__ import annotations

import argparse
import json
import math
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping, Sequence

import cut_stall_analyze as csa

EXIT_PASS = 0
EXIT_FAIL = 1
EXIT_UNUSABLE = 2
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


@dataclass(frozen=True)
class Cut:
    node: int
    start_epoch: float
    end_epoch: float


def read_cut_trace(path: Path, started_at: float) -> list[Cut]:
    """Parse the two timestamped cut-start/end pairs emitted by cluster-setup."""
    events: dict[int, dict[str, float]] = {}
    for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        fields = line.split()
        if not fields:
            continue
        if len(fields) != 3 or not fields[1].startswith("event=") or not fields[2].startswith("node="):
            raise ValueError(f"malformed cut trace line {lineno}")
        try:
            epoch = float(fields[0])
            node = int(fields[2][5:])
        except ValueError as exc:
            raise ValueError(f"malformed cut trace line {lineno}") from exc
        if not math.isfinite(epoch) or node not in (0, 1):
            raise ValueError(f"invalid cut trace value on line {lineno}")
        event = fields[1][6:]
        if event not in ("cut_start", "cut_end") or event in events.setdefault(node, {}):
            raise ValueError(f"duplicate or unknown cut event on line {lineno}")
        events[node][event] = epoch
    if set(events) != {0, 1} or any(set(events[node]) != {"cut_start", "cut_end"} for node in (0, 1)):
        raise ValueError("cut trace must contain one start/end pair for each node")
    cuts = [Cut(node, events[node]["cut_start"], events[node]["cut_end"]) for node in (0, 1)]
    cuts.sort(key=lambda cut: cut.start_epoch)
    if cuts[0].start_epoch >= cuts[1].start_epoch:
        raise ValueError("cut trace start times are not ordered")
    for cut in cuts:
        if cut.start_epoch < started_at or cut.end_epoch < cut.start_epoch:
            raise ValueError(f"invalid timestamps for node{cut.node} cut")
    return cuts


def read_version_samples(path: Path) -> list[tuple[float, str, str]]:
    """Parse `epoch sha0 sha1` samples; '-' is a fail-closed unavailable read."""
    rows: list[tuple[float, str, str]] = []
    for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        fields = line.split()
        if len(fields) != 3:
            raise ValueError(f"malformed version sample line {lineno}")
        try:
            epoch = float(fields[0])
        except ValueError as exc:
            raise ValueError(f"malformed version sample timestamp on line {lineno}") from exc
        if not math.isfinite(epoch):
            raise ValueError(f"non-finite version sample timestamp on line {lineno}")
        for sha in fields[1:]:
            if sha != "-" and not _SHA256.fullmatch(sha):
                raise ValueError(f"malformed running-exe SHA on line {lineno}")
        rows.append((epoch, fields[1], fields[2]))
    if len(rows) < 2:
        raise ValueError("version sampler produced fewer than two samples")
    if any(right[0] <= left[0] for left, right in zip(rows, rows[1:])):
        raise ValueError("version sample timestamps are not strictly increasing")
    return rows


def version_verdict(
    samples: Sequence[tuple[float, str, str]],
    cuts: Sequence[Cut],
    expected_version: str,
    mixed_min_seconds: float = 0.1,
    mixed_max_sample_gap_seconds: float = 2.0,
) -> tuple[bool, str]:
    """Require both running images to change and a sampled mixed interval."""
    if not _SHA256.fullmatch(expected_version):
        return False, "expected .deb xpfd SHA256 is unavailable or malformed"
    before = [row for row in samples if row[0] < cuts[0].start_epoch]
    after = [row for row in samples if row[0] >= cuts[-1].end_epoch]
    if not before or not after:
        return False, "version samples do not bracket both rolling cuts"
    old = before[0][1:]
    new = after[-1][1:]
    for node in (0, 1):
        if not _SHA256.fullmatch(old[node]):
            return False, f"node{node} has no pre-cut running-exe identity"
        if not _SHA256.fullmatch(new[node]):
            return False, f"node{node} has no post-cut running-exe identity"
        if old[node] == expected_version:
            return False, f"no-op drain: node{node} already runs the candidate .deb xpfd"
        if new[node] != expected_version:
            return False, f"node{node} running-exe SHA did not change to the candidate .deb"
    mixed_rows = [
        row for row in samples
        if cuts[0].end_epoch <= row[0] < cuts[1].start_epoch
        and ((row[1] == expected_version and row[2] == old[1])
             or (row[2] == expected_version and row[1] == old[0]))
    ]
    if len(mixed_rows) < 2:
        return False, "no sampled mixed-version interval between the two cuts"
    if mixed_rows[-1][0] - mixed_rows[0][0] < mixed_min_seconds:
        return False, "mixed-version samples do not span a measurable interval"
    if any(
        right[0] - left[0] > mixed_max_sample_gap_seconds
        for left, right in zip(mixed_rows, mixed_rows[1:])
    ):
        return False, "mixed-version sampling has an unexplained interval gap"
    return True, "both nodes changed to the candidate xpfd SHA; mixed-version interval observed"


def _error_event_lines(raw_text: str) -> list[int]:
    lines: list[int] = []
    for lineno, line in enumerate(raw_text.splitlines(), 1):
        if not line.strip().startswith("{"):
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(event, dict) and event.get("event") == "error":
            lines.append(lineno)
    return lines


def cut_verdict(
    parsed: Mapping[str, object],
    raw_text: str,
    cut: Cut,
    started_at: float,
    expected_streams: int,
    resume_deadline_seconds: float = 3.0,
    pre_window_seconds: float = 5.0,
    max_interval_seconds: float | None = None,
) -> tuple[bool, str]:
    """Require per-stream traffic before and across one cut without stalls."""
    streams = parsed.get("streams")
    if not isinstance(streams, dict) or len(streams) != expected_streams:
        observed = len(streams) if isinstance(streams, dict) else 0
        return False, f"only {observed}/{expected_streams} expected streams in interval evidence"
    start = cut.start_epoch - started_at
    end = cut.end_epoch - started_at
    before: set[str] = set()
    for sid, intervals in streams.items():
        if any(start - pre_window_seconds <= iv.start < start and iv.bps > 0 for iv in intervals):
            before.add(str(sid))
    if len(before) != expected_streams:
        missing = sorted(set(map(str, streams)) - before)
        return False, f"only {len(before)}/{expected_streams} streams carried data before cut (missing {','.join(missing)})"
    errors = _error_event_lines(raw_text)
    if errors:
        return False, f"iperf error event(s) at evidence line(s) {','.join(map(str, errors))}"

    horizon = end + resume_deadline_seconds
    for sid in sorted(before):
        intervals = sorted(streams[sid], key=lambda iv: iv.start)
        continuity = [
            iv for iv in intervals
            if iv.end > start - pre_window_seconds and iv.start < horizon
        ]
        active = [iv for iv in intervals if iv.end > start and iv.start < horizon]
        if not active:
            return False, f"stream {sid} has no interval evidence across cut"
        if max_interval_seconds is not None:
            previous_end: float | None = None
            for interval in continuity:
                if interval.end - interval.start > max_interval_seconds:
                    return False, (
                        f"stream {sid} interval width {interval.end - interval.start:.3f}s "
                        f"exceeds the {max_interval_seconds:g}s sampling limit"
                    )
                if previous_end is not None and interval.start - previous_end > 2 * max_interval_seconds:
                    return False, f"stream {sid} interval evidence has a sampling gap"
                previous_end = interval.end

        longest_zero = 0.0
        zero_start: float | None = None
        zero_end: float | None = None
        for interval in continuity:
            if interval.bps <= 0:
                if zero_start is None or zero_end is None or interval.start - zero_end > 1.5:
                    if zero_start is not None and zero_end is not None:
                        longest_zero = max(longest_zero, zero_end - zero_start)
                    zero_start = interval.start
                zero_end = interval.end
            elif zero_start is not None and zero_end is not None:
                longest_zero = max(longest_zero, zero_end - zero_start)
                zero_start = zero_end = None
        if zero_start is not None and zero_end is not None:
            longest_zero = max(longest_zero, zero_end - zero_start)
        if longest_zero >= resume_deadline_seconds:
            return False, (
                f"stream {sid} had a {longest_zero:.2f}s zero-throughput interval "
                f"window across cut (limit {resume_deadline_seconds:g}s; #10261 shape)"
            )
        if not any(end <= iv.start <= horizon and iv.bps > 0 for iv in intervals):
            return False, f"stream {sid} did not resume positive throughput after cut"
    return True, f"all {expected_streams} streams remained live across cut with no multi-second zero window"


def load_evidence(path: Path) -> tuple[Mapping[str, object], str]:
    raw = path.read_text(encoding="utf-8")
    parsed = csa.parse_iperf(path)
    return parsed, raw


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="PASS/FAIL oracle for rolling-upgrade client evidence.")
    parser.add_argument("--evidence", required=True, help="iperf3 text or JSON-stream log")
    parser.add_argument("--cuts", required=True, help="cluster-setup timestamped cut trace")
    parser.add_argument("--samples", required=True, help="timestamped running-exe SHA samples")
    parser.add_argument("--started-at", required=True, type=float, help="client launch epoch seconds")
    parser.add_argument("--expected-version", required=True, help="xpfd SHA inside candidate .deb")
    parser.add_argument("--streams", required=True, type=int)
    parser.add_argument("--resume-deadline", type=float, default=3.0)
    parser.add_argument("--max-interval-sec", type=float, default=None,
                        help="require intervals no wider than this and reject >2x gaps")
    args = parser.parse_args(argv)
    try:
        parsed, raw = load_evidence(Path(args.evidence))
        cuts = read_cut_trace(Path(args.cuts), args.started_at)
        samples = read_version_samples(Path(args.samples))
    except (OSError, UnicodeError, ValueError) as exc:
        print(f"VERSION FAIL unusable evidence: {exc}")
        return EXIT_UNUSABLE
    if (
        args.streams < 1
        or not math.isfinite(args.resume_deadline)
        or args.resume_deadline <= 0
        or (
            args.max_interval_sec is not None
            and (not math.isfinite(args.max_interval_sec) or args.max_interval_sec <= 0)
        )
    ):
        print("VERSION FAIL invalid oracle thresholds")
        return EXIT_UNUSABLE

    cells = [
        ("VERSION", version_verdict(samples, cuts, args.expected_version)),
        (
            "CUT 1",
            cut_verdict(
                parsed, raw, cuts[0], args.started_at, args.streams,
                args.resume_deadline, max_interval_seconds=args.max_interval_sec,
            ),
        ),
        (
            "CUT 2",
            cut_verdict(
                parsed, raw, cuts[1], args.started_at, args.streams,
                args.resume_deadline, max_interval_seconds=args.max_interval_sec,
            ),
        ),
    ]
    failed = False
    for label, (ok, message) in cells:
        print(f"{label} {'PASS' if ok else 'FAIL'} {message}")
        failed = failed or not ok
    return EXIT_FAIL if failed else EXIT_PASS


if __name__ == "__main__":
    raise SystemExit(main())
