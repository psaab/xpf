"""Aggregate per-rep JSON outputs into a per-cell summary + verdict.

Cell directory layout: <root>/cell_N{n}_M{m}/rep_{i}/probe.json
Per-rep validity is read from probe.json["validity"]["ok"].

For each cell, the median valid rep for the configured gate percentile
is selected as the representative; its p50/p95/p99/p99.9 +
IQR-of-p99-across-reps + achieved-RPS summary populate summary.json.
Cells require 10 valid reps to report status OK; if the runner reaches
its 15-rep ceiling with fewer valid reps, the gate is
INSUFFICIENT-DATA.

Default decision threshold (#905, plan §7.2):
- p99(N=128, M=10, best-effort) ≤ 2 × p99(N=0, M=10, best-effort)

Issue #1321 can reuse the same artifact reducer for 100E100M by passing
`--gate-elephants 100 --gate-mice 100`. The reducer records p99.9 when
probe artifacts include it. The default hard gate remains p99 unless
the caller explicitly changes `--gate-percentile`; when changed, the
representative rep is selected by that same percentile.

The harness only runs best-effort, so cells are keyed by (N, M).
"""

import argparse
import json
import os
import statistics
import sys
from typing import Dict, List, Optional, Tuple

CellKey = Tuple[int, int]  # (N, M)
GATE_PERCENTILE_TO_RTT_KEY = {
    "p50_us": "p50",
    "p95_us": "p95",
    "p99_us": "p99",
    "p999_us": "p999",
}
REQUIRED_VALID_REPS = 10


def has_invalid_marker(rep_dir: str) -> bool:
    """Return True if the orchestrator wrote an INVALID-* marker file."""
    if not os.path.isdir(rep_dir):
        return False
    for entry in os.listdir(rep_dir):
        if entry.startswith("INVALID-"):
            return True
    return False


def load_cell_reps(cell_dir: str) -> List[dict]:
    """Load all rep_*/probe.json, applying orchestrator INVALID markers."""
    if not os.path.isdir(cell_dir):
        return []
    reps: List[dict] = []
    for entry in sorted(os.listdir(cell_dir)):
        if not entry.startswith("rep_"):
            continue
        rep_dir = os.path.join(cell_dir, entry)
        probe_path = os.path.join(rep_dir, "probe.json")
        # Always collect orchestrator INVALID-* marker reasons first,
        # regardless of probe.json availability (R2 HIGH 1 partial).
        marker_reasons = sorted(
            f"orchestrator: {m}"
            for m in os.listdir(rep_dir)
            if m.startswith("INVALID-")
        )
        if not os.path.isfile(probe_path):
            reasons = ["no-probe-json"] + marker_reasons
            reps.append({
                "validity": {"ok": False, "reasons": reasons},
                "rtt_us": {},
                "totals": {},
            })
            continue
        with open(probe_path) as f:
            try:
                rep = json.load(f)
            except json.JSONDecodeError:
                reasons = ["bad-json"] + marker_reasons
                reps.append({
                    "validity": {"ok": False, "reasons": reasons},
                    "rtt_us": {},
                    "totals": {},
                })
                continue
        if marker_reasons:
            v = rep.setdefault("validity", {"ok": False, "reasons": []})
            v["ok"] = False
            v.setdefault("reasons", []).extend(marker_reasons)
        reps.append(rep)
    return reps


def select_valid_reps(reps: List[dict]) -> List[dict]:
    return [r for r in reps if r.get("validity", {}).get("ok")]


def median_rep_by_percentile(valid_reps: List[dict], percentile_key: str = "p99") -> Optional[dict]:
    """Return the rep at the median position of the selected percentile."""
    if not valid_reps:
        return None
    sortable = sorted(
        valid_reps,
        key=lambda r: r.get("rtt_us", {}).get(percentile_key) or 0,
    )
    return sortable[len(sortable) // 2]


def median_rep_by_p99(valid_reps: List[dict]) -> Optional[dict]:
    """Backward-compatible helper for callers/tests that want p99 ordering."""
    return median_rep_by_percentile(valid_reps, "p99")


def summarize_cell(reps: List[dict], representative_percentile: str = "p99") -> dict:
    """Produce the per-cell summary record."""
    valid = select_valid_reps(reps)
    summary: dict = {
        "n_reps_total": len(reps),
        "n_reps_valid": len(valid),
        "median_rep": None,
        "iqr_p99_across_reps": None,
        "representative_percentile": representative_percentile,
    }
    if len(valid) < REQUIRED_VALID_REPS:
        summary["status"] = "INSUFFICIENT-VALID-REPS"
        return summary
    median = median_rep_by_percentile(valid, representative_percentile)
    p99s = sorted(
        r.get("rtt_us", {}).get("p99") or 0 for r in valid
    )
    n = len(p99s)
    if n >= 4:
        q1 = p99s[n // 4]
        q3 = p99s[(3 * n) // 4]
        summary["iqr_p99_across_reps"] = q3 - q1
    if median is not None:
        rtt = median.get("rtt_us", {})
        totals = median.get("totals", {})
        summary["median_rep"] = {
            "p50_us": rtt.get("p50"),
            "p95_us": rtt.get("p95"),
            "p99_us": rtt.get("p99"),
            "p999_us": rtt.get("p999"),
            "achieved_rps_total": totals.get("achieved_rps_total"),
            # R2 fresh MED 1: propagate per-coroutine attempt-rate
            # distribution to the summary so the diagnosis surface
            # MED-4 promised actually reaches the report. Field
            # renamed (Copilot R1): per-coroutine values are
            # workload-offered (attempts), not completion-rate.
            "attempts_per_second_per_coroutine_median":
                totals.get("attempts_per_second_per_coroutine_median"),
            "attempts_per_second_per_coroutine_iqr":
                totals.get("attempts_per_second_per_coroutine_iqr"),
            "attempts_per_coroutine": totals.get("attempts_per_coroutine"),
        }
    summary["status"] = "OK"
    return summary


def decide(
    summaries: Dict[CellKey, dict],
    *,
    gate_elephants: int = 128,
    gate_mice: int = 10,
    threshold_ratio: float = 2.0,
    gate_percentile: str = "p99_us",
) -> dict:
    """Compute the mouse-latency gate verdict for the requested cell."""
    gate_loaded = summaries.get((gate_elephants, gate_mice))
    gate_idle = summaries.get((0, gate_mice))
    if gate_loaded is None or gate_idle is None:
        return {
            "verdict": "INSUFFICIENT-DATA",
            "reason": (
                f"missing gate cell: loaded=N{gate_elephants}_M{gate_mice}, "
                f"idle=N0_M{gate_mice}"
            ),
        }
    if gate_loaded.get("status") != "OK" or gate_idle.get("status") != "OK":
        return {
            "verdict": "INSUFFICIENT-DATA",
            "reason": (
                f"gate cell status: loaded={gate_loaded.get('status')}, "
                f"idle={gate_idle.get('status')}"
            ),
        }
    loaded_value = (gate_loaded.get("median_rep") or {}).get(gate_percentile)
    idle_value = (gate_idle.get("median_rep") or {}).get(gate_percentile)
    if loaded_value is None or idle_value is None or idle_value == 0:
        return {
            "verdict": "INSUFFICIENT-DATA",
            "reason": f"missing {gate_percentile} in gate cell",
        }
    ratio = loaded_value / idle_value
    verdict = {
        "verdict": "PASS" if ratio <= threshold_ratio else "FAIL",
        "ratio": ratio,
        "idle_us": idle_value,
        "loaded_us": loaded_value,
        "threshold": threshold_ratio,
        "percentile": gate_percentile,
        "gate": (
            f"{gate_percentile}(N={gate_elephants}, M={gate_mice}) <= "
            f"{threshold_ratio:g} * {gate_percentile}(N=0, M={gate_mice})"
        ),
    }
    if gate_percentile == "p99_us":
        verdict["p99_idle_us"] = idle_value
        verdict["p99_loaded_us"] = loaded_value
    return verdict


def discover_cells(root: str) -> Dict[CellKey, List[dict]]:
    """Find all cell_N{n}_M{m}/ directories under root and load reps."""
    if not os.path.isdir(root):
        return {}
    out: Dict[CellKey, List[dict]] = {}
    for entry in sorted(os.listdir(root)):
        if not entry.startswith("cell_N"):
            continue
        try:
            _, rest = entry.split("cell_N", 1)
            n_str, m_part = rest.split("_M", 1)
            n = int(n_str)
            m = int(m_part)
        except (ValueError, IndexError):
            continue
        out[(n, m)] = load_cell_reps(os.path.join(root, entry))
    return out


def render_markdown(summaries: Dict[CellKey, dict], verdict: dict) -> str:
    lines: List[str] = []
    lines.append("| N elephants | M mice | reps (valid/total) | p50 us | p95 us | p99 us | p99.9 us | RPS | status |")
    lines.append("|---|---|---|---|---|---|---|---|---|")
    for key in sorted(summaries.keys()):
        n, m = key
        s = summaries[key]
        median = s.get("median_rep") or {}
        lines.append(
            f"| {n} | {m} | {s['n_reps_valid']}/{s['n_reps_total']} "
            f"| {median.get('p50_us', '-')} "
            f"| {median.get('p95_us', '-')} "
            f"| {median.get('p99_us', '-')} "
            f"| {median.get('p999_us', '-')} "
            f"| {median.get('achieved_rps_total', '-')} "
            f"| {s.get('status', '-')} |"
        )
    lines.append("")
    lines.append(f"**Verdict:** {verdict.get('verdict')}")
    if "ratio" in verdict:
        lines.append(
            f"  ratio = {verdict['ratio']:.2f} "
            f"({verdict.get('percentile', 'p99_us')} loaded {verdict['loaded_us']} us / "
            f"idle {verdict['idle_us']} us); "
            f"threshold ≤ {verdict['threshold']}"
        )
    elif "reason" in verdict:
        lines.append(f"  reason: {verdict['reason']}")
    return "\n".join(lines)


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--root", required=True)
    p.add_argument("--out", required=True)
    p.add_argument("--gate-elephants", type=int, default=128)
    p.add_argument("--gate-mice", type=int, default=10)
    p.add_argument("--threshold-ratio", type=float, default=2.0)
    p.add_argument(
        "--gate-percentile",
        choices=("p50_us", "p95_us", "p99_us", "p999_us"),
        default="p99_us",
    )
    args = p.parse_args()

    cells = discover_cells(args.root)
    representative_percentile = GATE_PERCENTILE_TO_RTT_KEY[args.gate_percentile]
    summaries = {
        key: summarize_cell(reps, representative_percentile=representative_percentile)
        for key, reps in cells.items()
    }
    verdict = decide(
        summaries,
        gate_elephants=args.gate_elephants,
        gate_mice=args.gate_mice,
        threshold_ratio=args.threshold_ratio,
        gate_percentile=args.gate_percentile,
    )

    with open(args.out, "w") as f:
        json.dump(
            {
                "summaries": {f"N{n}_M{m}": s for (n, m), s in summaries.items()},
                "verdict": verdict,
            },
            f,
            indent=2,
        )

    print(render_markdown(summaries, verdict))
    return 0 if verdict["verdict"] in ("PASS", "FAIL") else 2


if __name__ == "__main__":
    sys.exit(main())
