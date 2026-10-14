"""Aggregate per-rep JSON outputs into a per-cell summary + verdict.

Cell directory layout: <root>/cell_N{n}_M{m}/rep_{i}/probe.json
Per-rep validity is read from probe.json["validity"]["ok"].

For each cell, the median valid rep for the configured gate percentile
is selected as the representative; its p50/p95/p99/p99.9 +
IQR-of-the-representative-percentile-across-reps + achieved-RPS summary
populate summary.json.
Cells require 10 valid reps to report status OK; if the runner reaches
its 15-rep ceiling with fewer valid reps, the gate is
INSUFFICIENT-DATA.
Gate cells must use the same mouse-probe connection mode and pacing
interval; otherwise the reducer returns INSUFFICIENT-DATA instead of
comparing unlike latency artifacts. Valid reps must also agree on where
their flows terminated: reps declaring different (mouse_target,
elephant_target) pairs mark the cell INCONSISTENT-TARGETS (#13066)
instead of summarising it with the targets silently dropped — that drop
let a shared-target cell bypass the #8259 VOID-NOT-ATTRIBUTABLE guard
and emit a citable PASS.

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
DEFAULT_PROBE_CONFIG = {
    "connection_mode": "per-attempt",
    "min_interval_ms": 0.0,
}


def _normalize_min_interval_ms(value) -> object:
    if value is None:
        return DEFAULT_PROBE_CONFIG["min_interval_ms"]
    try:
        return float(value)
    except (TypeError, ValueError):
        return value


def _probe_config_from_rep(rep: dict) -> dict:
    """Return the probe mode/pacing tuple for a rep.

    New artifacts record the values in both manifest.json and
    probe.json["config"]. Older artifacts predate the fields and are
    treated as the historical defaults: per-attempt mode with no
    min-interval pacing.
    """
    manifest = rep.get("manifest")
    if not isinstance(manifest, dict):
        manifest = {}
    config = rep.get("config")
    if not isinstance(config, dict):
        config = {}
    mode = manifest.get("mouse_probe_connection_mode")
    if mode is None:
        mode = config.get("connection_mode")
    if mode is None:
        mode = DEFAULT_PROBE_CONFIG["connection_mode"]
    interval = manifest.get("mouse_probe_min_interval_ms")
    if interval is None:
        interval = config.get("min_interval_ms")
    return {
        "connection_mode": mode,
        "min_interval_ms": _normalize_min_interval_ms(interval),
    }


def _target_pair_from_rep(rep: dict) -> Optional[Tuple[str, str]]:
    """The (mouse_target, elephant_target) this rep was captured against.

    #8259. `None` when the rep predates the split — an older artifact cannot
    say where its flows terminated, and inventing a default would be the same
    class of error the void verdict exists to prevent.
    """
    # The manifest is NESTED under rep["manifest"], not merged at top level —
    # reading it flat returns None for every rep and the void check below
    # becomes a silent no-op. Same access shape as _probe_config_from_rep.
    manifest = rep.get("manifest")
    if not isinstance(manifest, dict):
        manifest = {}
    mouse = manifest.get("mouse_target")
    elephant = manifest.get("elephant_target")
    if not mouse or not elephant:
        return None
    return (str(mouse), str(elephant))


def _unique_target_pairs(reps: List[dict]) -> List[Tuple[str, str]]:
    """The distinct (mouse_target, elephant_target) pairs the reps declare.

    `None` declarations — reps whose artifacts predate the #8259 target
    split — contribute nothing, so a legacy-only cell returns an empty
    list and stays summarisable. More than one distinct pair is the
    caller's defect to report (#13066): a cell whose valid reps
    terminated on different hosts cannot be summarised at all, and
    quietly dropping the pair would hand `decide()` a `(None, None)`
    that skips the void guard.
    """
    return sorted(
        {p for p in (_target_pair_from_rep(r) for r in reps) if p is not None}
    )


def _probe_config_key(config: dict) -> Tuple[object, object]:
    return (config.get("connection_mode"), config.get("min_interval_ms"))


def _unique_probe_configs(reps: List[dict]) -> List[dict]:
    by_key = {}
    for rep in reps:
        config = _probe_config_from_rep(rep)
        by_key.setdefault(_probe_config_key(config), config)
    return [
        by_key[k]
        for k in sorted(by_key.keys(), key=lambda k: (str(k[0]), str(k[1])))
    ]


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
        manifest_path = os.path.join(rep_dir, "manifest.json")
        if os.path.isfile(manifest_path):
            try:
                with open(manifest_path) as f:
                    rep["manifest"] = json.load(f)
            except json.JSONDecodeError:
                pass
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


def _iqr_across_reps(values: List[float]) -> float:
    """Interquartile range across the reps' samples of one percentile.

    #13066 (D10-02): the old `values[n // 4]` / `values[(3 * n) // 4]`
    index slicing snapped the quartiles to order statistics, and the
    spread was only ever computed for p99 even when the gate selected
    and compared the representative rep by p999. Inclusive quartiles
    interpolate, so a 10-rep cell uses all of its samples.
    """
    q1, _, q3 = statistics.quantiles(values, n=4, method="inclusive")
    return q3 - q1


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
    if representative_percentile != "p99":
        summary[f"iqr_{representative_percentile}_across_reps"] = None
    target_pairs = _unique_target_pairs(valid)
    if len(target_pairs) == 1:
        # #8259: the gate needs to know where the two flows terminated.
        summary["mouse_target"], summary["elephant_target"] = target_pairs[0]
    elif len(target_pairs) > 1:
        # #13066 (D10-02): mixed pairs must not degrade to "no targets".
        # The old code dropped the pair here, decide() read (None, None),
        # and a cell whose reps mostly terminated on one shared host
        # sailed past the VOID-NOT-ATTRIBUTABLE guard to a citable PASS.
        # Attribution is the prior question, so this precedes both the
        # probe-config and the valid-rep count checks.
        summary["target_pairs"] = target_pairs
        summary["status"] = "INCONSISTENT-TARGETS"
        return summary
    probe_configs = _unique_probe_configs(valid)
    if len(probe_configs) == 1:
        summary["probe_config"] = probe_configs[0]
    elif len(probe_configs) > 1:
        summary["probe_configs"] = probe_configs
        summary["status"] = "INCONSISTENT-PROBE-CONFIG"
        return summary
    if len(valid) < REQUIRED_VALID_REPS:
        summary["status"] = "INSUFFICIENT-VALID-REPS"
        return summary
    median = median_rep_by_percentile(valid, representative_percentile)
    p99s = sorted(
        r.get("rtt_us", {}).get("p99") or 0 for r in valid
    )
    if len(p99s) >= 4:
        summary["iqr_p99_across_reps"] = _iqr_across_reps(p99s)
    if representative_percentile != "p99":
        representative_values = sorted(
            r.get("rtt_us", {}).get(representative_percentile) or 0
            for r in valid
        )
        if len(representative_values) >= 4:
            summary[f"iqr_{representative_percentile}_across_reps"] = (
                _iqr_across_reps(representative_values)
            )
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
            "phase_us": median.get("phase_us"),
            "coroutines": median.get("coroutines"),
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
    # #8259: REFUSE to emit a verdict this measurement cannot attribute.
    #
    # When the mice and the elephants terminate on the SAME host, the loaded
    # cell adds the elephants' full offered load to the very machine whose
    # service time is inside every mouse sample, while the idle cell does not.
    # The ratio then attributes that entire difference to firewall queueing.
    # On the standing loss cluster the two are ~8.6 Gbit/s apart.
    #
    # PASS is the dangerous half, not FAIL. A FAIL invites investigation; a
    # PASS gets cited as a control, and one already has been — the #7159
    # cross-class PASS was used as the comparison point for #8259's FAIL, and
    # it carries this same defect. A verdict that cannot mean what it says is
    # worse than no verdict.
    #
    # This is deliberately NOT a warning field alongside a PASS/FAIL. A warning
    # is discarded by every consumer that reads `verdict`, which is what let
    # the confound survive to be cited.
    #
    # ORDERING: this runs BEFORE the cell-status check, so a cell that is BOTH
    # short of valid reps AND on a shared target reports VOID rather than
    # INSUFFICIENT-DATA. That is the more useful of the two, and deliberate:
    # INSUFFICIENT-DATA says "collect more reps", and more reps cannot make an
    # unattributable comparison attributable. Attribution is the prior
    # question. A cell with NO valid reps has no targets recorded and still
    # reports INSUFFICIENT-DATA, which is also right — there is nothing to
    # attribute yet.
    #
    # The check passes the moment the two targets differ, so standing up a
    # second host on VLAN 80 and pointing ELEPHANT_TARGET_V4 at it turns the
    # gate back on with no further change. See target-services.sh for why
    # there is no second host today.
    loaded_pair = (gate_loaded.get("mouse_target"), gate_loaded.get("elephant_target"))
    idle_pair = (gate_idle.get("mouse_target"), gate_idle.get("elephant_target"))
    for cell_name, (mouse, elephant) in (("loaded", loaded_pair), ("idle", idle_pair)):
        if mouse and elephant and mouse == elephant:
            return {
                "verdict": "VOID-NOT-ATTRIBUTABLE",
                "reason": (
                    f"{cell_name} cell: mice and elephants both terminate on "
                    f"{mouse}, so the loaded cell adds the elephants' offered "
                    f"load to the host whose service time is inside every mouse "
                    f"sample. The loaded/idle ratio cannot separate firewall "
                    f"queueing from target-host service, and neither PASS nor "
                    f"FAIL would mean what it says (#8259)."
                ),
                "mouse_target": mouse,
                "elephant_target": elephant,
                "unblocked_by": (
                    "a second host on VLAN 80 with ELEPHANT_TARGET_V4 pointed "
                    "at it; see test/incus/target-services.sh"
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
    loaded_probe_config = gate_loaded.get("probe_config")
    idle_probe_config = gate_idle.get("probe_config")
    if loaded_probe_config != idle_probe_config:
        return {
            "verdict": "INSUFFICIENT-DATA",
            "reason": (
                "gate probe config mismatch: "
                f"loaded={loaded_probe_config}, idle={idle_probe_config}"
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


def exit_status_for_verdict(verdict: str) -> int:
    """Map a gate verdict to a process exit status.

    0 = PASS (gate satisfied), 1 = measured FAIL (gate violated),
    2 = insufficient / undetermined evidence (no confident verdict).

    A measured FAIL MUST exit non-zero so CI treats it as a failure.
    The prior ``return 0 if verdict in ("PASS", "FAIL") else 2`` painted a
    real FAIL green (C175-HC-029) — a latency regression that violated the
    gate read as success in CI.
    """
    if verdict == "PASS":
        return 0
    if verdict == "FAIL":
        return 1
    # INSUFFICIENT-DATA and any unexpected value: undetermined, not a pass.
    return 2


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
    return exit_status_for_verdict(verdict["verdict"])


if __name__ == "__main__":
    sys.exit(main())
