#!/usr/bin/env bash
# #1614 simul-load smoke harness — run all 11 CoS classes in parallel for
# 30 s, then reduce per-class achievement / CoV / retrans against the v5
# acceptance criteria (plan.md §7 gates 1, 2, 3, 8), as re-scoped by
# #1691 / #1614 §3.A: under full-11 simul the ~22-24 G C_phys push
# ceiling divides among the backlogged classes, so push gate 1 is a
# DIVIDED-CEILING REGRESSION FLOOR, not the >=95% guarantee (which is
# SOLO-only via #1630 cos-gate1-small-four-alone.sh). See
# docs/fairness-regimes.md "Aggregate push ceiling C_phys".
#
# Usage:
#   ./test/incus/cos-simul-load-smoke.sh [push|reverse]   # default push
#
# Expects the loss userspace cluster to be deployed and the
# cos-iperf-config.set fixture applied:
#   sg incus-admin -c "./test/incus/cluster-setup.sh deploy all"
#   sg incus-admin -c "./test/incus/apply-cos-config.sh loss:xpf-userspace-fw0"
#
# Direction default is push (the regression direction). Pass "reverse"
# explicitly to run the Phase 0 / R8 sanity check that determines whether
# the firewall or the generator is the bottleneck. See plan.md §7 gate 8.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# #13070 (D10-15): the port/class/shape grid comes from the shared CoS
# schedule library instead of script-local copies of cos-iperf-config.set.
# shellcheck source=cos-apply-lib.sh
source "${SCRIPT_DIR}/cos-apply-lib.sh"
# shellcheck source=cluster-env.sh
source "${SCRIPT_DIR}/cluster-env.sh"


DIRECTION="${1:-push}"
DURATION="${DURATION:-30}"
STREAMS="${STREAMS:-12}"
TARGET_V4="${TARGET_V4:-$IPERF_TARGET4}"
HOST="${HOST:-$CLUSTER_LAN_HOST}"
ART="${ART:-/tmp/cos-simul-load-$(date +%s)}"
COS_GATE_EMITTED=0
cos_gate_exit() {
  local status=$?
  trap - EXIT
  if [[ "$COS_GATE_EMITTED" != "1" ]]; then
    local reason=harness-aborted
    ((status == 0)) && reason=harness-incomplete
    printf 'COS_GATE cos-simul-load-smoke VOID reason=%s\n' "$reason"
  fi
  exit "$status"
}
trap cos_gate_exit EXIT
if [[ "${COS_GATE_SELFTEST:-0}" == "1" ]]; then
  echo "COS_GATE cos-simul-load-smoke PASS reason=-- aggregate_gbps=1"
  COS_GATE_EMITTED=1
  exit 0
fi

# All 11 shaped/priority classes: the canonical grid minus best-effort
# (#13070 / D10-15 — this list used to be a hand-maintained copy of
# cos-iperf-config.set; class names and shapes live only in the shared
# spec now, so there is nothing here to drift).
declare -a PORTS=("${COS_SCHEDULE_PORTS[@]:1}")
if [[ "${COS_GATE_REDUCER_SELFTEST:-0}" == "1" && ! -d "$ART" ]]; then
  echo "COS_GATE cos-simul-load-smoke VOID reason=generator-evidence-invalid"
  COS_GATE_EMITTED=1
  exit 2
fi

mkdir -p "$ART"
printf 'target_v4=%s\nlan_generator=%s\n' "$TARGET_V4" "$HOST" > "$ART/measurement-environment.txt"
echo "#1614 simul-load smoke: direction=$DIRECTION duration=${DURATION}s streams=$STREAMS target=$TARGET_V4 host=$HOST art=$ART"

REV_FLAG=""
if [ "$DIRECTION" = "reverse" ]; then
  REV_FLAG="-R"
fi

if [[ "${COS_GATE_REDUCER_SELFTEST:-0}" != "1" ]]; then
# Launch generator-side mpstat in parallel for the R8 check; we always
# capture it because generator CPU evidence is cheap and useful.
incus_exec "$HOST" mpstat -P ALL 1 "$DURATION" > "$ART/mpstat.txt" 2>&1 &
MPSTAT_PID=$!

# Launch the 11 iperf3 senders in parallel. Capture each generator's exit
# code to a .rc sidecar (instead of swallowing it with `|| true`) so the
# reducer can fail hard on a generator failure — a crashed or unlaunched
# sender must not read as a silent pass (#4239 V-1).
declare -a IPERF_PIDS=()
for port in "${PORTS[@]}"; do
  (
    rc=0
    incus_exec "$HOST" iperf3 -c "$TARGET_V4" -P "$STREAMS" -t "$DURATION" -p "$port" $REV_FLAG --json \
      > "$ART/sim_${port}.json" 2>"$ART/sim_${port}.err" || rc=$?
    echo "$rc" > "$ART/sim_${port}.rc"
  ) &
  IPERF_PIDS+=($!)
done

# Wait for all senders, then mpstat.
for pid in "${IPERF_PIDS[@]}"; do
  wait "$pid"
done
wait "$MPSTAT_PID" 2>/dev/null || true
fi

# Reduce verdict.
reducer_rc=0
reducer_output=$(python3 - "$ART" "$DIRECTION" "$SCRIPT_DIR" <<'PYEOF'
import json, math, os, sys

art_dir = sys.argv[1]
direction = sys.argv[2]
# Import the shared population-CoV mirror of the Rust fairness SSOT
# (userspace-dp/src/fairness.rs::compute_observed_cov). This heredoc runs
# on the operator host from an arbitrary cwd, so add the script's own
# directory to the import path explicitly (#4239 V-10).
sys.path.insert(0, sys.argv[3])
from fairness_cov import population_cov
from cos_fixture_spec import canonical_cos_schedule
# #13070 (D10-15): the port -> class / shape grid is DERIVED from the
# fixture via cos_fixture_spec (this heredoc used to carry its own copy).
# Uncapped is non-exact: it rides the priority-low root scheduler, so its
# exact shape is 0 and gate 2 reads it as ">= 5% of ceiling" instead.
schedule = canonical_cos_schedule()
ports = sorted(p for p in schedule if 5201 <= p <= 5211)
class_names = {p: schedule[p]["forwarding_class"] for p in ports}
shape_gbps = {
    p: (schedule[p]["cap_bps"] / 1e9) if schedule[p]["exact"] else 0.0
    for p in ports
}

rows = []
total_recv = 0.0
total_retr = 0
priority_low_gbps = 0.0
for port in ports:
    f = os.path.join(art_dir, f"sim_{port}.json")
    try:
        with open(f) as fh:
            d = json.load(fh)
        if not isinstance(d, dict) or d.get("error"):
            raise ValueError("iperf-error")
        end = d.get("end")
        if not isinstance(end, dict):
            raise ValueError("missing-end")
        streams = end.get("streams")
        if not isinstance(streams, list) or not streams:
            raise ValueError("missing-streams")
        rates = []
        for stream in streams:
            sender = stream.get("sender") if isinstance(stream, dict) else None
            bps = sender.get("bits_per_second") if isinstance(sender, dict) else None
            if isinstance(bps, bool) or not isinstance(bps, (int, float)) or not math.isfinite(bps) or bps < 0:
                raise ValueError("invalid-stream-rate")
            rates.append(bps / 1e9)
        sum_received = end.get("sum_received") or {}
        sum_sent = end.get("sum_sent") or {}
        if not isinstance(sum_received, dict) or not isinstance(sum_sent, dict):
            raise ValueError("invalid-summary")
        if "bits_per_second" in sum_received:
            recv_bps = sum_received["bits_per_second"]
        elif "bits_per_second" in sum_sent:
            recv_bps = sum_sent["bits_per_second"]
        else:
            raise ValueError("truncated")
        retr = sum_sent.get("retransmits")
        if isinstance(recv_bps, bool) or not isinstance(recv_bps, (int, float)) or not math.isfinite(recv_bps) or recv_bps < 0:
            raise ValueError("invalid-throughput")
        if isinstance(retr, bool) or not isinstance(retr, int) or retr < 0:
            raise ValueError("invalid-retransmits")
        recv_gbps = recv_bps / 1e9
    except Exception as e:
        rows.append({"port": port, "class": class_names[port], "error": str(e)})
        continue
    # Whole-run population CoV via the shared Rust-SSOT mirror. This is a
    # whole-run figure (warmup included); CoV is decorative here, not gated.
    cov = population_cov(rates) * 100
    spread = (max(rates) / min(rates)) if rates and min(rates) > 0 else float("inf")
    shape = shape_gbps[port]
    rows.append({
        "port": port,
        "class": class_names[port],
        "shape_gbps": shape,
        "recv_gbps": round(recv_gbps, 3),
        "whole_run_cov_pct": round(cov, 1),
        "spread": round(spread, 2) if spread != float("inf") else None,
        "retransmits": retr,
        "gen_error": None,
    })
    total_recv += recv_gbps
    total_retr += retr
    if port == 5211:
        priority_low_gbps = recv_gbps

print(f"\n#1614 simul-load smoke ({direction})")
print(f"{'port':<6} {'class':<16} {'shape':>7} {'recv_G':>7} {'%shape':>7} {'wrCoV%':>6} {'retr':>6}")
for r in rows:
    if "error" in r:
        print(f"{r['port']:<6} {r['class']:<16} ERROR: {r['error']}")
        continue
    pct = (r["recv_gbps"] / r["shape_gbps"] * 100) if r["shape_gbps"] > 0 else 0
    print(f"{r['port']:<6} {r['class']:<16} {r['shape_gbps']:>6.2f}G {r['recv_gbps']:>6.2f}G {pct:>6.1f}% {r['whole_run_cov_pct']:>5.1f}% {r['retransmits']:>6}")
print(f"{'':<6} {'Sum':<16} {'':>7} {total_recv:>6.2f}G")
print("wrCoV% = whole-run population CoV (Rust SSOT fairness.rs estimator, "
      "warmup included, zero-bps flows counted); decorative, not gated.")

# Gate verdict.
verdict = {
    "direction": direction,
    "aggregate_gbps": round(total_recv, 3),
    "cov_estimator": "whole_run_population",  # matches fairness.rs SSOT form
    "rows": rows,
}
gates = {}
# Gate 0 (both directions): every generator both exited 0 AND produced a
# parseable, error-free, complete JSON result. Two independent failure
# modes must both trip:
#   - a crashed/unlaunched sender leaves a nonzero (or missing) .rc; and
#   - a sender that exits rc==0 can still emit an unparseable, {"error":
#     ...}, or truncated payload (gen_error set during parse above).
# Checking the rc alone would let a middle-class garbage payload — a class
# no throughput floor reads — sail through, defeating the whole point of
# this harness (#4239 V-1 + Copilot row-readability follow-up).
gen_failures = []
rows_by_port = {r["port"]: r for r in rows}
for port in ports:
    rcf = os.path.join(art_dir, f"sim_{port}.rc")
    try:
        rc = int(open(rcf).read().strip())
    except Exception:
        rc = 1  # missing/unreadable .rc == generator never completed
    reasons = []
    if rc != 0:
        reasons.append(f"rc={rc}")
    row = rows_by_port.get(port)
    if row is None:
        reasons.append("no-row")
    elif "error" in row:
        reasons.append("unparseable")  # json.load raised on this port
    elif row.get("gen_error"):
        reasons.append(row["gen_error"])  # rc==0 but iperf-error / truncated
    if reasons:
        gen_failures.append({"port": port, "class": class_names[port], "reasons": reasons})
gates["gate_0_generators_healthy"] = {
    "failures": gen_failures,
    "pass": len(gen_failures) == 0,
}
if direction == "reverse":
    # Phase 0 / R8 gate 8: aggregate ≥ 22 G means firewall (not generator) is the bottleneck.
    gates["gate_8_reverse_simul_22g"] = total_recv >= 22.0
else:
    # Push direction gates (plan.md §7, re-scoped by #1691 / #1614 §3.A).
    # Gate 1 — DIVIDED-CEILING REGRESSION FLOOR (NOT the >=95% guarantee).
    #
    # This harness runs ALL 11 classes in parallel. Under full-11 simul
    # the ~22-24 G push ceiling C_phys (#1578) divides among the
    # backlogged classes, so even the smallest classes land far below
    # their solo rates: research #1614 §2.1 measured 100m=86%, 1g=63%,
    # 3g=43%, 6g=41% of shape. The >=95% small-class GUARANTEE is a SOLO
    # / few-competitor property and is asserted by the separate #1630
    # harness cos-gate1-small-four-alone.sh, NOT here. Asserting >=95%
    # on the full-11 run is structurally unsatisfiable for every class
    # incl 1g (#1691 / docs/fairness-regimes.md "Aggregate push ceiling
    # C_phys is the per-class denominator").
    #
    # We keep ALL four small classes (5201-5204) gated against a relaxed
    # per-class floor calibrated below today's measured full-11 value so
    # a COLLAPSE (e.g. starve-to-zero regression) still trips, while
    # normal ceiling-division does not. The 3g/6g >=95% guarantee under
    # multi-class contention is a confirmed-but-unresolved defect tracked
    # in #1692; this floor is a regression guard, not that guarantee.
    SIMUL_FLOOR_PCT = {5201: 0.60, 5202: 0.40, 5203: 0.25, 5204: 0.25}
    gate1_classes = []
    for r in rows:
        if "error" in r:
            continue
        if r["port"] in SIMUL_FLOOR_PCT:
            floor = SIMUL_FLOOR_PCT[r["port"]]
            target = r["shape_gbps"] * floor
            gate1_classes.append({
                "class": r["class"],
                "floor_pct": round(floor * 100),
                "target": target,
                "actual": r["recv_gbps"],
                "pass": r["recv_gbps"] >= target,
            })
    gates["gate_1_small_class_divided_ceiling_floor"] = {
        "semantics": ("divided-ceiling regression floor under full-11 simul, "
                      "NOT the >=95% guarantee (SOLO-only via #1630 "
                      "cos-gate1-small-four-alone.sh; 3g/6g guarantee = #1692)"),
        "classes": gate1_classes,
        # `all([]) == True`: if EVERY small-class row errored, gate1_classes
        # is empty and would vacuously pass. Require the full expected set
        # (#4239 V-1 all-error guard).
        "pass": (all(c["pass"] for c in gate1_classes)
                 and len(gate1_classes) == len(SIMUL_FLOOR_PCT)),
    }
    # Gate 2: priority-low ≥ 5% of cluster ceiling.
    ceiling = 18.0
    gates["gate_2_priority_low_min_share"] = {
        "target": ceiling * 0.05,
        "actual": priority_low_gbps,
        "pass": priority_low_gbps >= ceiling * 0.05,
    }
    # Gate 3: per-class retrans ≤ 100/30s.
    high_retr = [r for r in rows if "error" not in r and r["retransmits"] > 100]
    gates["gate_3_retrans_floor"] = {
        "high_retr_classes": [{"class": r["class"], "retr": r["retransmits"]} for r in high_retr],
        "pass": len(high_retr) == 0,
    }
verdict["gates"] = gates

verdict_path = os.path.join(art_dir, "verdict.json")
with open(verdict_path, "w") as f:
    json.dump(verdict, f, indent=2)
print(f"\nVerdict written: {verdict_path}")
print(json.dumps(gates, indent=2))

# Propagate the verdict as the process exit status. Gates are
# HETEROGENEOUS: dict gates carry a "pass" key; bare-bool gates are
# themselves the verdict. A naive `all(gates.values())` is WRONG — a
# failing DICT gate is still truthy as a raw dict. Under `set -euo
# pipefail` this heredoc is the LAST command, so a nonzero exit here
# becomes the script's exit status with no extra bash wiring (#4239 V-1).
def _ok(v):
    return v["pass"] if isinstance(v, dict) else bool(v)
failed = [name for name, gate in gates.items() if not _ok(gate)]


if gen_failures:
    print("COS_GATE cos-simul-load-smoke VOID reason=generator-evidence-invalid")
    sys.exit(2)
if failed:
    print(f"COS_GATE cos-simul-load-smoke FAIL reason=-- aggregate_gbps={round(total_recv, 3)}")
    sys.exit(1)
print(f"COS_GATE cos-simul-load-smoke PASS reason=-- aggregate_gbps={round(total_recv, 3)}")
sys.exit(0)
PYEOF
) || reducer_rc=$?
if grep -q '^COS_GATE cos-simul-load-smoke ' <<<"$reducer_output"; then
  COS_GATE_EMITTED=1
fi
printf '%s\n' "$reducer_output"
exit "$reducer_rc"
