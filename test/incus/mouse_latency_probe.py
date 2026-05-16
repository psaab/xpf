"""Mouse-latency probe driver — closed-loop TCP echo probes.

Spawns M asyncio coroutines, each looping connect → send → recv-echo →
close until --duration expires. No per-iteration sleep (closed-loop
semantics; see plan §4.1). Writes a JSON file with histogram, percentiles,
per-coroutine attempt counts, and a validity verdict.

Validity model (plan §4.2):
- error_rate < 0.01.
- min(attempts_per_coroutine) >= 0.5 × median(attempts) (only when M >= 2).
- Min-attempts floor:
    - M == 1:  total attempts >= 500.
    - 2 <= M < 10:  total attempts >= 1000 (intermediate-concurrency
      cells are not in the matrix; the 1000 floor is a defensive default
      so a manual smoke run at e.g. M=5 still has a meaningful gate).
    - M >= 10: total attempts >= 5000.
"""

import argparse
import asyncio
import json
import os
import statistics
import sys
import time
from typing import List


# Histogram bucket upper bounds in microseconds (plan §4.3).
HISTOGRAM_BUCKETS_US = [
    10, 20, 50, 100, 250, 500, 1000, 2500, 5000, 10000, 25000, 100000,
]


async def _run_probe_coro(
    target: str,
    port: int,
    payload_bytes: int,
    deadline: float,
    rtts_us: List[int],
    attempt_counter: List[int],
    error_counter: List[int],
) -> None:
    """One coroutine: closed-loop probe loop until deadline.

    Copilot R3 #2: payload is generated once per coroutine — the
    echo server is byte-stateless and we don't need uniqueness
    across attempts; per-attempt `os.urandom` was avoidable CPU on
    the source.

    Copilot R3 #1: per-attempt connect/recv timeouts are bounded
    by remaining time to the deadline so the probe runtime is
    consistently ≤ duration + small constant, never the full 5s+5s
    above deadline.
    """
    payload = os.urandom(payload_bytes)
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        attempt_counter[0] += 1
        t0 = time.monotonic_ns()
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(target, port),
                timeout=min(5.0, remaining),
            )
            try:
                writer.write(payload)
                await writer.drain()
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    error_counter[0] += 1
                    break
                data = await asyncio.wait_for(
                    reader.readexactly(payload_bytes),
                    timeout=min(5.0, remaining),
                )
                if data != payload:
                    error_counter[0] += 1
                    continue
            finally:
                writer.close()
                try:
                    await writer.wait_closed()
                except (BrokenPipeError, ConnectionResetError, OSError):
                    pass
        except (
            asyncio.TimeoutError,
            ConnectionRefusedError,
            ConnectionResetError,
            BrokenPipeError,
            asyncio.IncompleteReadError,
            OSError,
        ):
            error_counter[0] += 1
            continue
        t1 = time.monotonic_ns()
        rtts_us.append((t1 - t0) // 1000)


def _compute_histogram(rtts_us: List[int]) -> List[int]:
    counts = [0] * len(HISTOGRAM_BUCKETS_US)
    for rtt in rtts_us:
        placed = False
        for i, upper in enumerate(HISTOGRAM_BUCKETS_US):
            if rtt <= upper:
                counts[i] += 1
                placed = True
                break
        if not placed:
            counts[-1] += 1  # > 100 ms goes into the top bucket.
    return counts


def _compute_percentiles(rtts_us: List[int]) -> dict:
    """Compute p50/p95/p99/p99.9 + IQR via stdlib `statistics.quantiles`.

    R1 MED 3: the plan calls for `statistics.quantiles` output, so
    the implementation and the unit tests share an estimator. With
    n=100 cut points (method="inclusive") we get p50=q[49], p95=q[94],
    p99=q[98] (the 99 cut points between 100 quantiles, zero-indexed).
    Issue #1321's 100E100M contract also needs p99.9, computed the
    same way with n=1000 and q[998].
    """
    if not rtts_us:
        return {
            "p50": None, "p95": None, "p99": None, "p999": None,
            "min": None, "max": None, "mean": None, "iqr": None,
        }
    s = sorted(rtts_us)
    if len(s) < 2:
        v = s[0]
        return {
            "p50": v, "p95": v, "p99": v, "p999": v,
            "min": v, "max": v, "mean": v, "iqr": 0,
        }
    cuts_100 = statistics.quantiles(s, n=100, method="inclusive")
    cuts_1000 = statistics.quantiles(s, n=1000, method="inclusive")
    cuts_4 = statistics.quantiles(s, n=4, method="inclusive")
    return {
        "p50": int(round(cuts_100[49])),
        "p95": int(round(cuts_100[94])),
        "p99": int(round(cuts_100[98])),
        "p999": int(round(cuts_1000[998])),
        "min": s[0],
        "max": s[-1],
        "mean": int(statistics.fmean(s)),
        "iqr": int(round(cuts_4[2] - cuts_4[0])),
    }


def compute_validity(
    concurrency: int,
    attempts_per_coroutine: List[int],
    completed: int,
    errors: int,
) -> dict:
    """Apply the §4.2 validity gates. Pure function — easy to unit-test."""
    reasons: List[str] = []
    attempted = sum(attempts_per_coroutine)
    # Internal consistency: each attempt is either completed or errored.
    # Copilot R1: surface the bookkeeping invariant rather than letting
    # `completed` go unused.
    if completed > attempted:
        reasons.append(
            f"inconsistent-counts: completed={completed} > attempted={attempted}"
        )
    if completed + errors != attempted:
        reasons.append(
            "inconsistent-counts: "
            f"completed+errors={completed + errors} != attempted={attempted}"
        )
    error_rate = errors / max(1, attempted)
    if error_rate >= 0.01:
        reasons.append(f"error_rate={error_rate:.4f} >= 0.01")
    if concurrency >= 2:
        median_a = statistics.median(attempts_per_coroutine) if attempts_per_coroutine else 0
        min_a = min(attempts_per_coroutine) if attempts_per_coroutine else 0
        if median_a > 0 and min_a < 0.5 * median_a:
            reasons.append(
                f"degenerate-coroutine: min={min_a} < 0.5 * median={median_a}"
            )
    floor = 5000 if concurrency >= 10 else 500 if concurrency == 1 else 1000
    if attempted < floor:
        reasons.append(f"min-attempts: attempted={attempted} < floor={floor}")
    return {"ok": not reasons, "reasons": reasons}


async def _run(args: argparse.Namespace) -> dict:
    rtts_per_coro: List[List[int]] = [[] for _ in range(args.concurrency)]
    attempts_per_coro: List[List[int]] = [[0] for _ in range(args.concurrency)]
    errors_per_coro: List[List[int]] = [[0] for _ in range(args.concurrency)]
    deadline = time.monotonic() + args.duration
    coros = [
        _run_probe_coro(
            args.target, args.port, args.payload_bytes, deadline,
            rtts_per_coro[i], attempts_per_coro[i], errors_per_coro[i],
        )
        for i in range(args.concurrency)
    ]
    await asyncio.gather(*coros)

    rtts_us: List[int] = []
    for sublist in rtts_per_coro:
        rtts_us.extend(sublist)
    attempts = [c[0] for c in attempts_per_coro]
    errors = sum(c[0] for c in errors_per_coro)

    completed = len(rtts_us)
    attempted = sum(attempts)
    achieved_rps_total = completed / max(0.001, args.duration)

    # R1 MED 4: report the distribution of achieved attempt-rate
    # across coroutines so closed-loop overload diagnosis can
    # distinguish client-side saturation (uniform low rate) from
    # probe-path asymmetry (one slow coroutine).
    #
    # Copilot R1: name the field `attempts_per_second` so it doesn't
    # get conflated with the completion-rate `achieved_rps_total`.
    # An attempt counts whether or not the echo round-trip completed,
    # so this is a workload-offered metric, not a completion metric.
    per_coro_aps = [a / max(0.001, args.duration) for a in attempts]
    if len(per_coro_aps) >= 2:
        cuts4 = statistics.quantiles(per_coro_aps, n=4, method="inclusive")
        per_coro_iqr = cuts4[2] - cuts4[0]
        per_coro_median = statistics.median(per_coro_aps)
    elif per_coro_aps:
        per_coro_iqr = 0.0
        per_coro_median = per_coro_aps[0]
    else:
        per_coro_iqr = 0.0
        per_coro_median = 0.0

    return {
        "config": {
            "target": args.target, "port": args.port,
            "concurrency": args.concurrency,
            "duration_s": args.duration,
            "payload_bytes": args.payload_bytes,
        },
        "totals": {
            "attempted": attempted,
            "completed": completed,
            "errors": errors,
            "error_rate": errors / max(1, attempted),
            "attempts_per_coroutine": attempts,
            "achieved_rps_total": achieved_rps_total,
            "attempts_per_second_per_coroutine_median": per_coro_median,
            "attempts_per_second_per_coroutine_iqr": per_coro_iqr,
        },
        "rtt_us": _compute_percentiles(rtts_us),
        "histogram_us": {
            "buckets": HISTOGRAM_BUCKETS_US,
            "counts": _compute_histogram(rtts_us),
        },
        "validity": compute_validity(
            args.concurrency, attempts, completed, errors,
        ),
    }


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--target", required=True)
    p.add_argument("--port", type=int, required=True)
    p.add_argument("--concurrency", type=int, required=True)
    p.add_argument("--duration", type=float, required=True)
    p.add_argument("--payload-bytes", type=int, default=64)
    p.add_argument("--out", required=True)
    args = p.parse_args()
    result = asyncio.run(_run(args))
    with open(args.out, "w") as f:
        json.dump(result, f, indent=2)
    return 0 if result["validity"]["ok"] else 2


if __name__ == "__main__":
    sys.exit(main())
