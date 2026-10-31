#!/usr/bin/env python3
import argparse
import json
import statistics
import sys
from pathlib import Path


def interval_bps(interval):
    summary = interval.get("sum")
    if isinstance(summary, dict) and summary.get("bits_per_second") is not None:
        return float(summary.get("bits_per_second") or 0.0), float(summary.get("start") or 0.0), float(summary.get("end") or 0.0)
    total = 0.0
    start = None
    end = None
    for stream in interval.get("streams", []):
        total += float(stream.get("bits_per_second") or 0.0)
        if start is None:
            start = float(stream.get("start") or 0.0)
        end = float(stream.get("end") or 0.0)
    return total, float(start or 0.0), float(end or 0.0)


def load_iperf_payload(path):
    text = path.read_text(encoding="utf-8")
    try:
        return {"format": "json", "data": json.loads(text)}
    except Exception:
        pass

    events = []
    for lineno, raw in enumerate(text.splitlines(), start=1):
        raw = raw.strip()
        if not raw:
            continue
        try:
            events.append(json.loads(raw))
        except Exception as exc:
            raise ValueError(f"failed to parse iperf JSON stream line {lineno}: {exc}") from exc
    return {"format": "json-stream", "data": events}


def collect_intervals(payload):
    if payload["format"] == "json":
        return [interval_bps(interval) for interval in payload["data"].get("intervals", [])], payload["data"].get("end", {})

    intervals = []
    end = {}
    for event in payload["data"]:
        if event.get("event") == "interval":
            intervals.append(interval_bps(event.get("data") or {}))
        elif event.get("event") == "end":
            end = event.get("data") or {}
    return intervals, end


def stream_client_error(payload):
    """Return the text of a json-stream `error` event, or "".

    A client that is interrupted (the harness SIGTERMs one that has not exited
    on its own) emits an `error` event and then an `end` block it builds
    locally. That block is not a completion. Its `sum_received` is all zeros
    because the server's results never arrived, and its `seconds` run to the
    signal rather than the configured duration. Plain `-J` output reports the
    same condition as a top-level `error` key, which `summarize` handles.
    """
    if payload["format"] != "json-stream":
        return ""
    for event in payload["data"]:
        if event.get("event") == "error":
            return str(event.get("data") or "iperf3 error event without text")
    return ""


# An interval that ends this far past the configured duration is the
# interrupt's closing report (the time the client spent hung before the
# signal), not a measured reporting interval.
POST_DURATION_SLACK_SEC = 1.0


def end_throughput_summary(end):
    for name in ("sum_received", "sum", "sum_sent"):
        candidate = end.get(name) or {}
        if isinstance(candidate, dict) and candidate.get("bits_per_second") is not None:
            return candidate
    return {}


def merge_windows(windows):
    """Union of [lo, hi] windows, so an interval inside two overlapping
    anchors' windows (a request and a landing 1-2 s apart) is inside."""
    merged = []
    for lo, hi in sorted(windows):
        if merged and lo <= merged[-1][1] + 1e-9:
            merged[-1] = (merged[-1][0], max(merged[-1][1], hi))
        else:
            merged.append((lo, hi))
    return merged


def parse_planned_move(spec, width):
    """LABEL=T1[,T2...]: one move anchored at every instant given (the
    request and the observed landing), each with a [T, T+width] window."""
    label, sep, anchors = spec.partition("=")
    if not sep or not label or not anchors:
        raise SystemExit(f"--planned-move {spec!r}: expected LABEL=T1[,T2...]")
    try:
        times = [float(t) for t in anchors.split(",") if t != ""]
    except ValueError:
        raise SystemExit(f"--planned-move {spec!r}: anchors must be numbers")
    if not times:
        raise SystemExit(f"--planned-move {spec!r}: no anchors")
    return {
        "label": label,
        "anchors": times,
        "windows": merge_windows((t, t + width) for t in times),
    }


def score_planned_move(move, rows, args, inside):
    """Score one planned move by H11's rules at iperf3's 1 s resolution.

    Sessions are on both nodes before a planned move, so a zero interval in
    its window is a transition cost, not an excused outage (H10: a planned
    single-RG move loses at most 3 pings, and any stall of 300 ms or more
    fails; one 1 s zero interval is already over that).
    - PASS: no stream had a zero interval in the window.
    - COST: exactly ONE stream stalled, its stall (the whole consecutive zero
      run that touches the window, inside or past it) lasted at most
      --planned-max-stall-sec, and it carried data again afterwards.
    - FAIL: every stream zero in one interval (an aggregate outage over H11's
      1 s), more than one stream stalled, a stall longer than the bound, or a
      stream that never carried data again (it died).
    """
    in_window = [i for i, (lo, hi, _, _, _) in enumerate(rows) if inside(move["windows"], lo, hi)]
    # rows[i][3]: stalled (under --planned-stall-gbps, H11's 1 Mbit/s);
    # rows[i][4]: "zero" by the run's --zero-gbps (0.05 Gbit/s). A stream at a
    # few tens of Mbit/s is starved of the split-RG fabric's share, not
    # stalled: it is reported as low-share, and judged by H9's aggregate row.
    stalled = sorted({sid for i in in_window for sid, z in rows[i][3].items() if z})
    zero_count = sum(1 for i in in_window for z in rows[i][3].values() if z)
    low_share = sorted({sid for i in in_window for sid, z in rows[i][4].items() if z} - set(stalled))
    aggregate_zero = sum(1 for i in in_window if rows[i][3] and all(rows[i][3].values()))
    stalls = {}
    died = []
    for sid in stalled:
        best = 0.0
        recovered_all = True
        for i in in_window:
            if not rows[i][3].get(sid):
                continue
            lo_i = i
            while lo_i > 0 and rows[lo_i - 1][3].get(sid):
                lo_i -= 1
            hi_i = i
            while hi_i + 1 < len(rows) and rows[hi_i + 1][3].get(sid):
                hi_i += 1
            best = max(best, rows[hi_i][1] - rows[lo_i][0])
            if not any(rows[j][3].get(sid) is False for j in range(hi_i + 1, len(rows))):
                recovered_all = False
        stalls[sid] = round(best, 3)
        if not recovered_all:
            died.append(sid)
    reasons = []
    if aggregate_zero:
        reasons.append(f"every stream at or below {args.zero_gbps} Gbit/s in {aggregate_zero} interval(s): an aggregate outage over 1 s")
    if len(stalled) > 1:
        reasons.append(f"{len(stalled)} streams stalled ({', '.join(stalled)})")
    over = [sid for sid, sec in stalls.items() if sec > args.planned_max_stall_sec + 1e-9]
    if over:
        reasons.append(
            "stall over the %g s bound: %s" % (args.planned_max_stall_sec, ", ".join(f"stream {s} {stalls[s]:g} s" for s in over))
        )
    if died:
        reasons.append(f"stream(s) {', '.join(died)} never carried data again")
    anchors = ", ".join(f"{t:g}" for t in move["anchors"])
    share_note = (
        f"; {len(low_share)} more stream(s) at or below {args.zero_gbps:g} Gbit/s but not stalled ({', '.join(low_share)})"
        if low_share else ""
    )
    if not stalled and not aggregate_zero:
        verdict, text = "PASS", f"no stream stalled within [T, T+{args.event_window_sec:g}] of {anchors} s"
    elif reasons:
        verdict, text = "FAIL", "; ".join(reasons)
    else:
        sid = stalled[0]
        verdict, text = "COST", f"stream {sid} stalled {stalls[sid]:g} s at the move and recovered"
    text += share_note
    return {
        "label": move["label"],
        "anchors": move["anchors"],
        "low_share_streams": low_share,
        "windows": [list(w) for w in move["windows"]],
        "stalled_streams": stalled,
        "stall_sec": stalls,
        "aggregate_zero_intervals": aggregate_zero,
        "zero_stream_intervals": zero_count,
        "verdict": verdict,
        "text": text,
    }


def summarize(path, args):
    summary = {
        "path": str(path),
        "ok": False,
        "error": "",
        "format": "",
        "protocol": "",
        "completed": False,
        "observed_end_sec": 0.0,
        "avg_gbps": 0.0,
        "retransmits": 0,
        "udp_loss_percent": 0.0,
        "udp_jitter_ms": 0.0,
        "interval_gbps": [],
        "peak_gbps": 0.0,
        "peak_interval_index": -1,
        "tail_gbps": [],
        "tail_median_gbps": 0.0,
        "tail_min_gbps": 0.0,
        "tail_peak_ratio": 0.0,
        "zero_intervals_total": 0,
        "stream_zero_intervals_total": 0,
        "stream_zero_intervals_outside_events_total": 0,
        "zero_streams_outside_events_total": 0,
        "zero_streams_total": 0,
        "planned_moves": [],
        "planned_move_cost_total": 0,
        "planned_move_fail_total": 0,
        "planned_move_zero_intervals_total": 0,
        "zero_intervals_after_peak": 0,
        "stalled_intervals_after_peak": 0,
        "collapse_detected": False,
        "collapse_reason": "",
    }
    try:
        payload = load_iperf_payload(path)
    except Exception as exc:
        summary["error"] = f"failed to parse iperf JSON: {exc}"
        return summary

    summary["format"] = payload["format"]
    data = payload["data"]
    if payload["format"] == "json" and data.get("error"):
        summary["error"] = str(data["error"])
        return summary

    intervals, end = collect_intervals(payload)
    client_error = stream_client_error(payload)
    summary["client_error"] = client_error
    # An interrupted client's `end` block is a local stub, not a completion.
    summary["completed"] = bool(end) and not client_error
    test_start = {}
    if payload["format"] == "json":
        test_start = data.get("start", {}).get("test_start", {}) or {}
    elif payload["format"] == "json-stream":
        start = next((event.get("data") or {} for event in data if event.get("event") == "start"), {})
        test_start = start.get("test_start", {}) or {}
    summary["protocol"] = str(test_start.get("protocol") or "").upper()
    sum_sent = end.get("sum_sent") or end.get("sum") or {}
    sum_received = end.get("sum_received") or {}
    throughput_summary = end_throughput_summary(end)
    summary["avg_gbps"] = float(throughput_summary.get("bits_per_second") or 0.0) / 1e9
    summary["avg_source"] = "end" if throughput_summary else "none"
    summary["retransmits"] = int(sum_sent.get("retransmits") or 0)
    # Use `is not None` instead of `or` chaining — 0.0 is a valid value
    # that `or` would treat as falsy, falling through to the wrong source.
    def _first_defined(*sources):
        for v in sources:
            if v is not None:
                return float(v)
        return 0.0

    summary["udp_loss_percent"] = _first_defined(
        sum_received.get("lost_percent"),
        sum_sent.get("lost_percent"),
        end.get("sum", {}).get("lost_percent"),
    )
    summary["udp_jitter_ms"] = _first_defined(
        sum_received.get("jitter_ms"),
        sum_sent.get("jitter_ms"),
        end.get("sum", {}).get("jitter_ms"),
    )

    full_intervals = []
    observed_end = 0.0
    normalized_intervals = []
    if payload["format"] == "json":
        normalized_intervals = list(data.get("intervals", []))
    else:
        normalized_intervals = [
            (event.get("data") or {}) for event in payload["data"] if event.get("event") == "interval"
        ]
    # An interrupted client closes with one report covering the time it spent
    # hung before the signal, after the configured duration. Every stream reads
    # zero in it, so counting it would add a phantom zero interval and mark
    # every stream as affected. Drop only intervals that END past the
    # configured duration, and only when the client was interrupted.
    configured_duration = float(test_start.get("duration") or 0.0)
    summary["post_duration_intervals_excluded"] = 0
    if client_error and configured_duration > 0 and len(normalized_intervals) == len(intervals):
        limit = configured_duration + POST_DURATION_SLACK_SEC
        kept = [
            (parsed, raw)
            for parsed, raw in zip(intervals, normalized_intervals)
            if parsed[2] <= limit
        ]
        summary["post_duration_intervals_excluded"] = len(intervals) - len(kept)
        intervals = [parsed for parsed, _ in kept]
        normalized_intervals = [raw for _, raw in kept]
    # EXCUSED windows (--event-sec): transitions whose outage is by design,
    # i.e. the crash, where peer-loss detection alone takes 1.0-2.2 s. Their
    # zero intervals are not counted anywhere.
    exclude_windows = merge_windows(
        (float(event_sec), float(event_sec) + args.event_window_sec)
        for event_sec in args.event_sec
    )
    # PLANNED moves (--planned-move): moves the harness itself makes, with
    # sessions already on both nodes, so every lost packet is a transition
    # cost (#18617 review, matrix H10/H11). Their zero intervals are NOT
    # excused: each move is scored PASS/COST/FAIL below, and they are kept out
    # of the "outside" counter only so they are not counted twice.
    planned = [parse_planned_move(spec, args.event_window_sec) for spec in args.planned_move]

    def is_full(start, end_s):
        return end_s - start >= args.min_full_interval_sec - 1e-9

    def inside(windows, start, end_s):
        # Only a full-length interval lying wholly inside one window counts
        # as inside. Partial/straddling intervals stay counted outside: the
        # calibration issue requires "count only full intervals" outside
        # [T, T+3], so an interval that is not fully inside the window is
        # not fully explained by the transition.
        if not is_full(start, end_s):
            return False
        return any(start >= lo - 1e-9 and end_s <= hi + 1e-9 for lo, hi in windows)

    def fully_excluded(start, end_s):
        return inside(exclude_windows, start, end_s) or any(
            inside(move["windows"], start, end_s) for move in planned
        )

    stream_zero_total = 0
    stream_zero_outside_total = 0
    zero_stream_ids = set()
    zero_stream_ids_outside = set()
    # Per-interval rows for the planned-move scoring: bounds, aggregate rate,
    # and each stream's zero flag.
    rows = []
    for interval in normalized_intervals:
        streams = interval.get("streams", [])
        # Interval bounds from the interval sum when present, else the
        # first/last stream bounds (mirrors interval_bps).
        interval_total, interval_start, interval_end = interval_bps(interval)
        excluded = fully_excluded(interval_start, interval_end)
        zero_by_stream = {}
        stall_by_stream = {}
        for stream in streams:
            stream_id = str(stream.get("socket") or stream.get("id") or "?")
            bps = float(stream.get("bits_per_second") or 0.0)
            is_zero = bps <= args.zero_gbps * 1e9
            zero_by_stream[stream_id] = is_zero
            stall_by_stream[stream_id] = bps < args.planned_stall_gbps * 1e9
            if is_zero:
                stream_zero_total += 1
                zero_stream_ids.add(stream_id)
                if not excluded:
                    stream_zero_outside_total += 1
                    zero_stream_ids_outside.add(stream_id)
        rows.append((interval_start, interval_end, interval_total, stall_by_stream, zero_by_stream))
    moves_out = [score_planned_move(move, rows, args, inside) for move in planned]
    summary["planned_moves"] = moves_out
    summary["planned_move_cost_total"] = sum(1 for m in moves_out if m["verdict"] == "COST")
    summary["planned_move_fail_total"] = sum(1 for m in moves_out if m["verdict"] == "FAIL")
    summary["planned_move_zero_intervals_total"] = sum(m["zero_stream_intervals"] for m in moves_out)
    for bps, start, end_s in intervals:
        observed_end = max(observed_end, end_s)
        duration = end_s - start
        if duration >= args.min_full_interval_sec:
            full_intervals.append(bps / 1e9)
    if client_error or not end:
        # An interrupted client's stub has zero sum_received and a sum_sent
        # diluted by the hung time. A client killed outright (SIGKILL after the
        # TERM grace) leaves no end block at all. Either way, the measured
        # intervals are the only honest rate.
        measured_seconds = sum(max(0.0, end_s - start) for _, start, end_s in intervals)
        if measured_seconds > 0:
            summary["avg_gbps"] = (
                sum(bps * max(0.0, end_s - start) for bps, start, end_s in intervals)
                / measured_seconds
                / 1e9
            )
            summary["avg_source"] = "intervals"
    if end and not client_error:
        observed_end = max(
            observed_end,
            float((throughput_summary.get("end") or sum_sent.get("end") or 0.0)),
        )
    summary["observed_end_sec"] = observed_end
    summary["stream_zero_intervals_total"] = stream_zero_total
    summary["stream_zero_intervals_outside_events_total"] = stream_zero_outside_total
    summary["zero_streams_outside_events_total"] = len(zero_stream_ids_outside)
    summary["zero_streams_total"] = len(zero_stream_ids)
    summary["zero_intervals_total"] = (
        sum(1 for value in full_intervals if value <= args.zero_gbps) + stream_zero_total
    )

    summary["interval_gbps"] = full_intervals
    if not full_intervals:
        summary["ok"] = True
        return summary

    peak_gbps = max(full_intervals)
    peak_index = full_intervals.index(peak_gbps)
    tail = full_intervals[-args.tail_window:] if len(full_intervals) >= args.tail_window else list(full_intervals)
    tail_median = statistics.median(tail)
    tail_min = min(tail)
    after_peak = full_intervals[peak_index + 1 :]
    zero_after_peak = sum(1 for value in after_peak if value <= args.zero_gbps)
    stalled_after_peak = sum(1 for value in after_peak if value <= args.stall_gbps)
    tail_peak_ratio = tail_median / peak_gbps if peak_gbps > 0 else 0.0

    summary.update(
        {
            "ok": True,
            "peak_gbps": peak_gbps,
            "peak_interval_index": peak_index,
            "tail_gbps": tail,
            "tail_median_gbps": tail_median,
            "tail_min_gbps": tail_min,
            "tail_peak_ratio": tail_peak_ratio,
            "zero_intervals_after_peak": zero_after_peak,
            "stalled_intervals_after_peak": stalled_after_peak,
        }
    )

    if peak_gbps >= args.min_peak_gbps:
        reasons = []
        if zero_after_peak > 0:
            reasons.append(f"{zero_after_peak} zero interval(s) after peak")
        if len(after_peak) >= 2 and stalled_after_peak >= 2:
            reasons.append(f"{stalled_after_peak} stalled interval(s) after peak")
        if tail_peak_ratio < args.min_tail_ratio:
            reasons.append(
                f"tail/peak ratio {tail_peak_ratio:.3f} below {args.min_tail_ratio:.3f}"
            )
        if reasons:
            summary["collapse_detected"] = True
            summary["collapse_reason"] = "; ".join(reasons)

    return summary


def main():
    parser = argparse.ArgumentParser(description="Summarize and flag iperf3 JSON interval collapse.")
    parser.add_argument("json_path", help="Path to an iperf3 -J output file")
    parser.add_argument("--tail-window", type=int, default=2)
    parser.add_argument("--min-full-interval-sec", type=float, default=0.95)
    parser.add_argument("--min-peak-gbps", type=float, default=2.0)
    parser.add_argument("--min-tail-ratio", type=float, default=0.35)
    parser.add_argument("--zero-gbps", type=float, default=0.05)
    parser.add_argument("--stall-gbps", type=float, default=0.25)
    parser.add_argument(
        "--event-sec",
        type=float,
        action="append",
        default=[],
        help="transition instant (seconds from iperf start); may repeat. "
        "Full per-stream intervals wholly inside [T, T+--event-window-sec] "
        "are excluded from stream_zero_intervals_outside_events_total.",
    )
    parser.add_argument(
        "--planned-move",
        action="append",
        default=[],
        metavar="LABEL=T1[,T2...]",
        help="a move the harness itself makes, anchored at each instant given "
        "(the request and the observed landing); may repeat. Its zero intervals "
        "are scored PASS/COST/FAIL in planned_moves, never excused.",
    )
    parser.add_argument(
        "--planned-stall-gbps",
        type=float,
        default=0.001,
        help="a stream under this rate in a planned move's interval is STALLED "
        "(H11's 1 Mbit/s stall threshold); --zero-gbps (0.05) stays the "
        "zero-interval definition of the other counters",
    )
    parser.add_argument(
        "--planned-max-stall-sec",
        type=float,
        default=10.0,
        help="longest single-stream stall a planned move may cost before it "
        "FAILs (H11's SOAK_MAX_COST_STALL_MS, 10 s)",
    )
    parser.add_argument(
        "--event-window-sec",
        type=float,
        default=3.0,
        help="width of each transition exclusion window (default 3s; #12618)",
    )
    args = parser.parse_args()

    summary = summarize(Path(args.json_path), args)
    json.dump(summary, sys.stdout, sort_keys=True)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
