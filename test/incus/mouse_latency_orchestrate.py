"""Helper functions for the test-mouse-latency.sh orchestrator.

Keeps complex logic out of shell heredocs (which get tangled with
variable interpolation and quoting). Each function is invoked via
`python3 mouse_latency_orchestrate.py <subcommand> ...`.

Subcommands:
- check-cwnd-settle: parse a (snapshot of) iperf3.txt, return 0 if
  the last 3 [SUM] rows are within ±15 % AND ≥ 0.7 × shaper.
- settle-diagnostics: parse the same snapshot and emit JSON evidence
  explaining the settle verdict.
- check-collapse: parse a final iperf3.txt, return 0 if any 3
  consecutive [SUM] rows fell below 0.5 × shaper.
- parse-cluster-state: read cluster-status text from stdin, print
  one line per (rg, node, state) triple.
- rg-state-flapped: read the rg-state-poll file, return 0 if any
  triple drifted from the initial sample.
"""

import argparse
import json
import math
import re
import statistics
import sys

from cluster_status_parse import parse_cluster_status
from iperf3_sum_parse import parse_sum_bps

# The cwnd-settle gate (build_cwnd_settle_diagnostics) requires the
# aggregate to reach 0.7 * SHAPER_BPS. Keep this in lockstep with
# `min_aggregate_utilization` below; the env-consistency guard uses it
# to decide whether a (ELEPHANT_PORT, SHAPER_BPS) pairing can ever pass.
_SETTLE_MIN_UTILIZATION = 0.7

# The fixture parser, rate-cap semantics and CoSFixtureError moved to
# cos_fixture_spec.py (#13070 / D10-15): the CoS port grid had been
# restated in eight scripts and drifted; this module is now a CONSUMER of
# the single parser instead of its owner. The names stay bound here for
# the subcommands below and for mouse_latency_orchestrate_test.py.
from cos_fixture_spec import (  # noqa: E402  (sibling module, see header)
    DEFAULT_COS_SET,
    CoSFixtureError,
    parse_cos_class_caps,
)


def check_settle_threshold_satisfiable(
    elephant_port: int,
    shaper_bps: int,
    *,
    set_text: str | None = None,
    min_utilization: float = _SETTLE_MIN_UTILIZATION,
) -> dict:
    """Decide whether the cwnd-settle gate can ever pass for a pairing.

    The cwnd-settle gate requires the elephant aggregate to reach
    `min_utilization * shaper_bps`. The class implied by `elephant_port`
    can only ever deliver up to its configured cap (`cap_bps`). If the
    floor exceeds that cap, the gate is arithmetically unsatisfiable
    regardless of dataplane or scheduler health — exactly the #1365
    misconfiguration (port 5202 = 1 Gbps exact class vs SHAPER_BPS=10G,
    floor 7 Gbps > 1 Gbps cap).

    Returns a dict with keys:
        satisfiable (bool), reason (str), forwarding_class, scheduler,
        cap_bps, floor_bps, shaper_bps, elephant_port.
    Raises CoSFixtureError if the port is not present in the fixture.
    """
    if set_text is None:
        with open(DEFAULT_COS_SET) as f:
            set_text = f.read()
    caps = parse_cos_class_caps(set_text)
    info = caps.get(elephant_port)
    if info is None:
        raise CoSFixtureError(
            f"ELEPHANT_PORT={elephant_port} is not classified by the CoS "
            f"fixture; known ports: {sorted(caps)}"
        )
    # The real cwnd-settle gate compares the aggregate against the FLOAT
    # threshold `mn < min_utilization * shaper_bps`. Round the floor UP
    # (ceil) so the guard never under-reports it: a borderline pairing
    # whose true float threshold sits just above the integer cap must be
    # called unsatisfiable, not "satisfiable" by truncation. The aggregate
    # is an integer bps count, so the smallest aggregate that can clear a
    # float threshold T is ceil(T) (the first integer >= T; for integer T
    # an aggregate of exactly T also clears it since the gate uses `<`).
    floor_bps = math.ceil(min_utilization * shaper_bps)
    cap_bps = info["cap_bps"]
    satisfiable = floor_bps <= cap_bps
    if satisfiable:
        reason = (
            f"settle floor {floor_bps} bps <= class {info['forwarding_class']} "
            f"cap {cap_bps} bps"
        )
    else:
        reason = (
            f"settle floor {floor_bps} bps "
            f"({min_utilization:g} * SHAPER_BPS={shaper_bps}) exceeds class "
            f"{info['forwarding_class']} cap {cap_bps} bps "
            f"(scheduler {info['scheduler']}); the cwnd-settle gate can "
            f"never pass for this ELEPHANT_PORT/SHAPER_BPS pairing"
        )
    return {
        "satisfiable": satisfiable,
        "reason": reason,
        "forwarding_class": info["forwarding_class"],
        "scheduler": info["scheduler"],
        "cap_bps": cap_bps,
        "floor_bps": floor_bps,
        "shaper_bps": shaper_bps,
        "elephant_port": elephant_port,
        "min_utilization": min_utilization,
    }

_IPERF_INTERVAL_RE = re.compile(
    r"^\[\s*(?P<stream_id>SUM|\d+)\]\s+"
    r"(?P<start>\d+(?:\.\d+)?)-(?P<end>\d+(?:\.\d+)?)\s+sec\s+"
    r"\S+\s+\S+\s+"
    r"(?P<rate>\S+)\s+(?P<rate_unit>[KMGT]?)bits/sec"
    r"(?:\s+(?P<retransmits>\d+)\s+(?P<cwnd>\S+)\s+(?P<cwnd_unit>[KMGT]?)Bytes)?",
    re.IGNORECASE,
)

_UNIT_MULTIPLIER = {
    "": 1,
    "K": 1_000,
    "M": 1_000_000,
    "G": 1_000_000_000,
    "T": 1_000_000_000_000,
}
_BYTE_UNIT_MULTIPLIER = {
    "": 1,
    "K": 1024,
    "M": 1024 * 1024,
    "G": 1024 * 1024 * 1024,
    "T": 1024 * 1024 * 1024 * 1024,
}


def _parse_iperf_interval_rows(text: str) -> list[dict]:
    """Parse iperf3 text interval rows, including stream-level TCP fields."""
    rows = []
    for line in text.splitlines():
        m = _IPERF_INTERVAL_RE.match(line)
        if not m:
            continue
        rate_multiplier = _UNIT_MULTIPLIER.get(m.group("rate_unit").upper())
        if rate_multiplier is None:
            continue
        try:
            start = float(m.group("start"))
            end = float(m.group("end"))
            rate_bps = int(float(m.group("rate")) * rate_multiplier)
        except ValueError:
            continue

        stream_id_raw = m.group("stream_id")
        stream_id: str | int = (
            "SUM" if stream_id_raw.upper() == "SUM" else int(stream_id_raw)
        )
        retransmits = None
        if m.group("retransmits") is not None:
            retransmits = int(m.group("retransmits"))
        cwnd_bytes = None
        if m.group("cwnd") is not None:
            cwnd_multiplier = _BYTE_UNIT_MULTIPLIER.get(m.group("cwnd_unit").upper())
            if cwnd_multiplier is not None:
                try:
                    cwnd_bytes = int(float(m.group("cwnd")) * cwnd_multiplier)
                except ValueError:
                    cwnd_bytes = None
        rows.append({
            "stream_id": stream_id,
            "start": start,
            "end": end,
            "duration": end - start,
            "bps": rate_bps,
            "retransmits": retransmits,
            "cwnd_bytes": cwnd_bytes,
            # iperf3 final sender/receiver summaries span the whole run.
            "summary": (end - start) > 1.5,
        })
    return rows


def _median_int(values: list[int]) -> int | None:
    if not values:
        return None
    return int(statistics.median(values))


def _min_median_max(values: list[int]) -> dict:
    if not values:
        return {"min": None, "median": None, "max": None}
    return {
        "min": min(values),
        "median": _median_int(values),
        "max": max(values),
    }


def build_cwnd_settle_diagnostics(
    text: str,
    shaper_bps: int,
    *,
    window_rows: int = 3,
    elapsed_sec: int | None = None,
    sample_index: int | None = None,
) -> dict:
    """Return settle verdict details for a text-mode iperf3 snapshot."""
    rows = _parse_iperf_interval_rows(text)
    sum_rows = [
        r for r in rows
        if r["stream_id"] == "SUM" and not r["summary"]
    ]
    if len(sum_rows) < window_rows:
        return {
            "settled": False,
            "reasons": [
                f"insufficient-sum-rows: have={len(sum_rows)} need={window_rows}",
            ],
            "elapsed_sec": elapsed_sec,
            "sample_index": sample_index,
            "thresholds": {
                "window_rows": window_rows,
                "max_aggregate_spread_ratio": 0.15,
                "min_aggregate_utilization": 0.7,
                "min_aggregate_bps": int(0.7 * shaper_bps),
                "shaper_bps": shaper_bps,
            },
            "aggregate": {
                "sum_rows_seen": len(sum_rows),
                "window_bps": [],
                "window_bps_min": None,
                "window_bps_max": None,
                "window_bps_mean": None,
                "window_spread_ratio": None,
                "window_min_utilization": None,
            },
            "per_flow": {
                "flow_count": 0,
                "mean_bps": _min_median_max([]),
                "retransmits_total": 0,
                "cwnd_bytes": _min_median_max([]),
                "slowest_streams": [],
                "fastest_streams": [],
            },
        }

    window = sum_rows[-window_rows:]
    window_keys = {(r["start"], r["end"]) for r in window}
    window_bps = [int(r["bps"]) for r in window]
    mn, mx = min(window_bps), max(window_bps)
    spread_ratio = None if mx <= 0 else (mx - mn) / mx
    min_utilization = None if shaper_bps <= 0 else mn / shaper_bps

    by_stream: dict[int, list[dict]] = {}
    for row in rows:
        if row["stream_id"] == "SUM" or row["summary"]:
            continue
        if (row["start"], row["end"]) not in window_keys:
            continue
        by_stream.setdefault(int(row["stream_id"]), []).append(row)

    stream_summaries = []
    for stream_id, stream_rows in sorted(by_stream.items()):
        bps_values = [int(r["bps"]) for r in stream_rows]
        retransmits = sum(int(r["retransmits"] or 0) for r in stream_rows)
        latest_cwnd = next(
            (
                r["cwnd_bytes"]
                for r in sorted(stream_rows, key=lambda r: (r["end"], r["start"]), reverse=True)
                if r["cwnd_bytes"] is not None
            ),
            None,
        )
        stream_summaries.append({
            "stream_id": stream_id,
            "samples": len(stream_rows),
            "mean_bps": int(statistics.fmean(bps_values)) if bps_values else 0,
            "min_bps": min(bps_values) if bps_values else None,
            "max_bps": max(bps_values) if bps_values else None,
            "retransmits": retransmits,
            "cwnd_bytes_last": latest_cwnd,
        })

    flow_means = [s["mean_bps"] for s in stream_summaries]
    cwnds = [
        int(s["cwnd_bytes_last"])
        for s in stream_summaries
        if s["cwnd_bytes_last"] is not None
    ]
    retransmits_total = sum(int(s["retransmits"]) for s in stream_summaries)
    slowest = sorted(stream_summaries, key=lambda s: s["mean_bps"])[:5]
    fastest = sorted(stream_summaries, key=lambda s: s["mean_bps"], reverse=True)[:5]

    reasons = []
    if spread_ratio is not None and spread_ratio > 0.15:
        reasons.append(
            f"aggregate-window-spread: ratio={spread_ratio:.4f} > 0.1500"
        )
    min_required_bps = 0.7 * shaper_bps
    if mn < min_required_bps:
        reasons.append(
            f"aggregate-too-low: min_bps={mn} < threshold_bps={int(min_required_bps)}"
        )

    return {
        "settled": not reasons,
        "reasons": reasons,
        "elapsed_sec": elapsed_sec,
        "sample_index": sample_index,
        "thresholds": {
            "window_rows": window_rows,
            "max_aggregate_spread_ratio": 0.15,
            "min_aggregate_utilization": 0.7,
            "min_aggregate_bps": int(min_required_bps),
            "shaper_bps": shaper_bps,
        },
        "aggregate": {
            "sum_rows_seen": len(sum_rows),
            "window_intervals": [
                {"start": r["start"], "end": r["end"]} for r in window
            ],
            "window_bps": window_bps,
            "window_bps_min": mn,
            "window_bps_max": mx,
            "window_bps_mean": int(statistics.fmean(window_bps)),
            "window_spread_ratio": spread_ratio,
            "window_min_utilization": min_utilization,
        },
        "per_flow": {
            "flow_count": len(stream_summaries),
            "mean_bps": _min_median_max(flow_means),
            "retransmits_total": retransmits_total,
            "cwnd_bytes": _min_median_max(cwnds),
            "slowest_streams": slowest,
            "fastest_streams": fastest,
        },
    }


def cmd_check_cwnd_settle(args: argparse.Namespace) -> int:
    """Exit 0 if cwnd is settled; non-zero otherwise."""
    with open(args.iperf3_txt) as f:
        text = f.read()
    diagnostics = build_cwnd_settle_diagnostics(
        text, args.shaper_bps, window_rows=getattr(args, "window_rows", 3),
    )
    return 0 if diagnostics["settled"] else 1


def cmd_settle_diagnostics(args: argparse.Namespace) -> int:
    """Emit JSON settle evidence and return 0 only when settled."""
    with open(args.iperf3_txt) as f:
        text = f.read()
    diagnostics = build_cwnd_settle_diagnostics(
        text,
        args.shaper_bps,
        window_rows=args.window_rows,
        elapsed_sec=args.elapsed_sec,
        sample_index=args.sample_index,
    )
    rendered = json.dumps(diagnostics, indent=2, sort_keys=True)
    if args.out:
        with open(args.out, "w") as f:
            f.write(rendered)
            f.write("\n")
    else:
        print(rendered)
    return 0 if diagnostics["settled"] else 1



def cmd_check_collapse(args: argparse.Namespace) -> int:
    """Exit 0 if collapse detected within the probe window; 1 if not.

    R5 HIGH: window must anchor on PROBE START, not "last N rows" —
    iperf3 runs SETTLE_BUDGET + DURATION + SLACK seconds, so "last
    DURATION rows" loses the first DURATION seconds of probe and
    gains SLACK seconds of post-probe teardown. Take rows
    [skip_front : skip_front + n_rows] from the per-second prefix
    instead.
    """
    threshold = args.shaper_bps * 0.5
    rows = []
    with open(args.iperf3_txt) as f:
        for line in f:
            bps = parse_sum_bps(line)
            if bps is not None:
                rows.append(bps)
    # iperf3 writes 1-2 trailing [SUM] summary lines (sender +
    # receiver) covering the full run. Drop the trailing rows whose
    # cumulative behavior would mask per-second interval semantics —
    # we use --n-rows from a known offset instead, so summary rows
    # only intrude if the run finished early.
    if args.n_rows > 0:
        start = max(0, args.skip_front)
        end = start + args.n_rows
        rows = rows[start:end]
    streak = 0
    for bps in rows:
        if bps < threshold:
            streak += 1
            if streak >= 3:
                return 0
        else:
            streak = 0
    return 1


def cmd_check_env_consistency(args: argparse.Namespace) -> int:
    """Exit 0 if the ELEPHANT_PORT/SHAPER_BPS pairing can settle; 1 if not.

    #1365: the canonical matrix run paired a 1 Gbps exact class port
    (5202) with SHAPER_BPS=10G, so the cwnd-settle floor (7 Gbps) could
    never be met and every loaded rep INVALIDated before reaching the
    mouse probe. This guard catches that misconfiguration statically,
    before the rep starts, with an actionable message.
    """
    set_text = None
    if args.set_file:
        with open(args.set_file) as f:
            set_text = f.read()
    try:
        result = check_settle_threshold_satisfiable(
            args.elephant_port, args.shaper_bps, set_text=set_text,
        )
    except CoSFixtureError as exc:
        print(f"ABORT: {exc}", file=sys.stderr)
        return 2
    if result["satisfiable"]:
        return 0
    print(f"ABORT: {result['reason']}", file=sys.stderr)
    print(
        f"hint: set SHAPER_BPS to the {result['forwarding_class']} class cap "
        f"({result['cap_bps']}) or pick an ELEPHANT_PORT whose class cap is "
        f">= {result['floor_bps']} bps",
        file=sys.stderr,
    )
    return 1


def cmd_parse_cluster_state(args: argparse.Namespace) -> int:
    """Read cluster-status text from stdin, emit one line per triple."""
    text = sys.stdin.read()
    triples = parse_cluster_status(text)
    ts_ms = args.ts_ms
    for rg, node, state in triples:
        print(f"{ts_ms}\trg={rg}\tnode={node}\tstate={state}")
    return 0


POLL_FAILED_STATE = "state=POLL_FAILED"


def cmd_rg_state_flapped(args: argparse.Namespace) -> int:
    """Exit 0 if state drifted from initial; 1 if stable; 2 if undetermined.

    R1 HIGH 5: an empty poll file means the orchestrator never got a
    successful cli sample. Returning 1 ("stable") would silently pass
    a contaminated rep. Return 2 instead so the orchestrator can
    invalidate.

    C175-HC-083: the 1 Hz poller pipes each `cli` sample with `|| true`,
    so a failed poll (cli error or empty status) appended nothing and the
    gap was invisible. A failover that happened entirely inside such a
    gap left the surrounding successful samples looking identical, so the
    rep passed "stable" even though the RG flapped. The poller now writes
    a `state=POLL_FAILED` sentinel line for every failed tick; any such
    marker means a failover-in-gap cannot be ruled out, so a
    no-drift result becomes undetermined (2), not stable (1). An optional
    `--expected-samples` floor catches missing ticks even without markers.
    """
    by_ts: "dict[str, set]" = {}
    failed_ts: "set[str]" = set()
    with open(args.poll_file) as f:
        for line in f:
            parts = line.strip().split("\t")
            if len(parts) != 4:
                continue
            ts, rg_part, node_part, state_part = parts
            if state_part == POLL_FAILED_STATE:
                failed_ts.add(ts)
                continue
            triple = (rg_part, node_part, state_part)
            by_ts.setdefault(ts, set()).add(triple)
    if not by_ts:
        print("no RG poll samples", file=sys.stderr)
        return 2
    samples = sorted(by_ts.items())
    initial = samples[0][1]
    if not initial:
        # First sample collected an empty triple set (cli succeeded
        # but parser found nothing). Treat as undetermined.
        print("first RG sample is empty", file=sys.stderr)
        return 2
    for ts, triples in samples[1:]:
        if triples != initial:
            for t in triples - initial:
                print(f"DRIFT at {ts}: appeared {t}")
            for t in initial - triples:
                print(f"DRIFT at {ts}: disappeared {t}")
            return 0
    # No drift in the successful samples. But a failover could hide in a
    # poll gap, so failed ticks or a shortfall vs the expected cadence
    # make "stable" unprovable — return undetermined instead.
    if failed_ts:
        print(
            f"{len(failed_ts)} RG poll(s) failed (POLL_FAILED); cannot "
            "certify stable — a failover in the gap cannot be ruled out",
            file=sys.stderr,
        )
        return 2
    expected_samples = getattr(args, "expected_samples", None)
    if expected_samples is not None and len(by_ts) < expected_samples:
        print(
            f"only {len(by_ts)} of {expected_samples} expected RG samples; "
            "poll coverage too sparse to certify stable",
            file=sys.stderr,
        )
        return 2
    return 1


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="cmd", required=True)

    p1 = sub.add_parser("check-cwnd-settle")
    p1.add_argument("iperf3_txt")
    p1.add_argument("shaper_bps", type=int)
    p1.add_argument("--window-rows", type=int, default=3)
    p1.set_defaults(func=cmd_check_cwnd_settle)

    p1_diag = sub.add_parser("settle-diagnostics")
    p1_diag.add_argument("iperf3_txt")
    p1_diag.add_argument("shaper_bps", type=int)
    p1_diag.add_argument("--window-rows", type=int, default=3)
    p1_diag.add_argument("--elapsed-sec", type=int)
    p1_diag.add_argument("--sample-index", type=int)
    p1_diag.add_argument("--out")
    p1_diag.set_defaults(func=cmd_settle_diagnostics)

    p2 = sub.add_parser("check-collapse")
    p2.add_argument("iperf3_txt")
    p2.add_argument("shaper_bps", type=int)
    p2.add_argument(
        "--n-rows", type=int, default=0,
        help="Scan N [SUM] rows from --skip-front. 0 = full log.",
    )
    p2.add_argument(
        "--skip-front", type=int, default=0,
        help="Skip this many leading [SUM] rows (settle warmup) before scanning.",
    )
    p2.set_defaults(func=cmd_check_collapse)

    p_env = sub.add_parser("check-env-consistency")
    p_env.add_argument("elephant_port", type=int)
    p_env.add_argument("shaper_bps", type=int)
    p_env.add_argument(
        "--set-file",
        help="Path to the CoS fixture (default: cos-iperf-config.set "
        "next to this script).",
    )
    p_env.set_defaults(func=cmd_check_env_consistency)

    p3 = sub.add_parser("parse-cluster-state")
    p3.add_argument("ts_ms")
    p3.set_defaults(func=cmd_parse_cluster_state)

    p4 = sub.add_parser("rg-state-flapped")
    p4.add_argument("poll_file")
    p4.add_argument(
        "--expected-samples",
        type=int,
        default=None,
        help=(
            "Minimum number of successful 1 Hz RG samples expected for the "
            "poll window. If fewer distinct samples were collected, poll "
            "coverage is too sparse to certify stable and the result is "
            "undetermined (exit 2). Optional; POLL_FAILED markers already "
            "force undetermined regardless of this floor."
        ),
    )
    p4.set_defaults(func=cmd_rg_state_flapped)

    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
