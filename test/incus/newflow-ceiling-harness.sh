#!/usr/bin/env bash
# #4800 — new-flow (connection-rate) ceiling harness for the userspace
# dataplane, on the loss userspace cluster.
#
# WHAT THIS DOES, AND WHAT IT DELIBERATELY DOES NOT
# -------------------------------------------------
# This script DRIVES and COLLECTS. It does not derive. Every rate, ratio and
# attribution comes from `newflow_ceiling_analyze.py`, which is fed synthetic
# snapshot pairs by `newflow_ceiling_analyze_test.py` and can therefore be
# trusted to say what it means. Arithmetic embedded in shell is untestable,
# and the whole point of #4800 is a number somebody can defend.
#
# The measurement it produces answers: at a sustained new-flow rate, WHICH of
# the NAT allocator's `live` mutex, `publish_shared_session`, or the N-way
# `replicate_session_upsert` fan-out saturates first? #2852 Phase-2 sharding
# targets only the first, so a run that shows publish and replicate saturating
# earlier is a decision NOT to do that work.
#
# HOW IT CAN FAIL (it must be able to)
# ------------------------------------
# A cell is refused, not scored, when:
#   * the pool-mode SNAT rule was not actually in effect (zero pool
#     allocations over the window — NOT "0 flows/sec");
#   * the helper restarted mid-window (pid change or a backwards counter);
#   * the generator, client NIC or target bound before the firewall did;
#   * traffic landed on too few RX queues, so no cross-worker claim holds;
#   * the pool exhausted its ports (a capacity ceiling, not a lock ceiling).
# The analyzer exits 1 (INVALID) or 2 (INCONCLUSIVE) in those cases and this
# script propagates it. Do not paper over a non-zero exit.
#
# PREREQUISITES (see docs/userspace-newflow-ceiling.md for the full runbook)
#   1. `newflow-gen` built and pushed to the LAN host and the WAN target.
#   2. A pool-mode source-NAT rule on the WAN egress path, committed and
#      confirmed present in `show security nat source pool` before the run.
#   3. The sink running on the WAN target over the destination port range.
#
# USAGE
#   ./test/incus/newflow-ceiling-harness.sh --pool <name> --rule <name> \
#       [--rates 5000,10000,20000,40000] [--duration 30] [--threads 32]
#
# Runs under the shared-cluster lock: the loss cluster is not yours alone.

set -uo pipefail

_CELL_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${_CELL_DIR}/../.." && pwd)"

# Node-selection verdict (#6962). Pure bash+awk, no side effects, sourced
# before the --dry-run early exit so a syntax error in it cannot hide until a
# run has already taken the shared cluster lock.
# shellcheck source=newflow-ceiling-lib.sh
source "${_CELL_DIR}/newflow-ceiling-lib.sh"

ENV_FILE="${ENV_FILE:-$ROOT_DIR/test/incus/loss-userspace-cluster.env}"
ANALYZER="${ANALYZER:-$ROOT_DIR/test/incus/newflow_ceiling_analyze.py}"

POOL_NAME="${POOL_NAME:-}"
RULE_NAME="${RULE_NAME:-}"
RATES="${RATES:-5000,10000,20000,40000,80000}"
DURATION="${DURATION:-30}"
THREADS="${THREADS:-32}"
DST_PORTS="${DST_PORTS:-5300-5363}"
SRC_BIND="${SRC_BIND:-}"
CLOSE_MODE="${CLOSE_MODE:-rst}"
SETTLE_SEC="${SETTLE_SEC:-3}"
GEN_BIN="${GEN_BIN:-/usr/local/bin/newflow-gen}"
METRICS_URL="${METRICS_URL:-http://127.0.0.1:8080/metrics}"
ARTIFACT_ROOT="${ARTIFACT_ROOT:-}"
USE_SG_INCUS_ADMIN="${USE_SG_INCUS_ADMIN:-1}"
DRY_RUN="${DRY_RUN:-0}"

usage() {
    sed -n '2,45p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --pool) POOL_NAME="$2"; shift 2 ;;
        --rule) RULE_NAME="$2"; shift 2 ;;
        --rates) RATES="$2"; shift 2 ;;
        --duration) DURATION="$2"; shift 2 ;;
        --threads) THREADS="$2"; shift 2 ;;
        --dst-ports) DST_PORTS="$2"; shift 2 ;;
        --close) CLOSE_MODE="$2"; shift 2 ;;
        --artifacts) ARTIFACT_ROOT="$2"; shift 2 ;;
        --dry-run) DRY_RUN=1; shift ;;
        -h|--help) usage; exit 0 ;;
        *) echo "newflow-ceiling: unknown argument $1" >&2; usage >&2; exit 2 ;;
    esac
done

if [[ -z "$POOL_NAME" || -z "$RULE_NAME" ]]; then
    echo "newflow-ceiling: --pool and --rule are required." >&2
    echo "  They select the ONE pool under test. Summing every pool would add" >&2
    echo "  an idle pool's cold acquisition count to the loaded pool's" >&2
    echo "  contention numerator and understate saturation." >&2
    exit 2
fi

if [[ ! -f "$ENV_FILE" ]]; then
    echo "newflow-ceiling: env file not found: $ENV_FILE" >&2
    exit 2
fi
# shellcheck disable=SC1090
source "$ENV_FILE"

REMOTE_PREFIX="${INCUS_REMOTE:+${INCUS_REMOTE}:}"
FW0="${REMOTE_PREFIX}${VM0}"
FW1="${REMOTE_PREFIX}${VM1}"
HOST="${REMOTE_PREFIX}${LAN_HOST}"
TARGET_IP="${TARGET_IP:-${IPERF_TARGET4}}"

if [[ "$DRY_RUN" == "1" ]]; then
    echo "newflow-ceiling: DRY RUN — configuration only, no cluster access."
    echo "  env file:    $ENV_FILE"
    echo "  fw0 / fw1:   $FW0 / $FW1"
    echo "  lan host:    $HOST"
    echo "  source bind: ${SRC_BIND:-<default>}"
    echo "  wan target:  $TARGET_IP  ports $DST_PORTS"
    echo "  pool / rule: $POOL_NAME / $RULE_NAME"
    echo "  rates:       $RATES   duration=${DURATION}s threads=$THREADS close=$CLOSE_MODE"
    echo "  analyzer:    $ANALYZER"
    [[ -x "$ANALYZER" || -f "$ANALYZER" ]] || { echo "  MISSING analyzer" >&2; exit 2; }
    exit 0
fi

# Serialize against every other agent's deploy / smoke on the SHARED loss
# cluster (#1875 / #4020). Sourced AFTER argument parsing so --help and
# --dry-run never take the lock.
# shellcheck source=cluster-cell.sh
source "${_CELL_DIR}/cluster-cell.sh"

incus_cmd() {
    if [[ "$USE_SG_INCUS_ADMIN" == "1" ]] && ! incus list >/dev/null 2>&1; then
        sg incus-admin -c "incus $*"
    else
        incus "$@"
    fi
}

ARTIFACT_ROOT="${ARTIFACT_ROOT:-$ROOT_DIR/artifacts/newflow-ceiling/$(date -u +%Y%m%dT%H%M%SZ)}"
mkdir -p "$ARTIFACT_ROOT" || exit 2
echo "newflow-ceiling: artifacts -> $ARTIFACT_ROOT"

fail() { echo "newflow-ceiling: $*" >&2; exit 2; }

# --- preflight ------------------------------------------------------------
# Establish which node owns the measured path BEFORE any traffic. Reading
# counters off the standby would report a firewall that installed nothing.
#
# #6962: this used to be `grep -qi "primary"` over the whole status. That text
# contains BOTH nodes' rows on whichever node you ask, so it matched the PEER's
# row and $FW0 always won — and it won by printing a node name, not by
# erroring. Ask each node, ANCHOR the answer on that node's own row, and decide
# only after both have answered. The verdict + selection are in
# newflow-ceiling-lib.sh so `make test-newflow-ceiling-lib` can prove the
# selection on fixtures where the two nodes carry DIFFERENT states, which is
# the only shape in which the anchoring is observable.
node_status() { # node_status <instance>
    incus_cmd exec "$1" -- cli -c "show chassis cluster status" 2>/dev/null || true
}
V_FW0="$(newflow_cluster_primary_verdict "$(node_status "$FW0")")"
V_FW1="$(newflow_cluster_primary_verdict "$(node_status "$FW1")")"
echo "newflow-ceiling: $FW0 -> $V_FW0"
echo "newflow-ceiling: $FW1 -> $V_FW1"
SELECTION="$(newflow_select_active_node "$FW0" "$V_FW0" "$FW1" "$V_FW1")"
if [[ "${SELECTION%% *}" != "SELECT" ]]; then
    fail "${SELECTION#REFUSE }"
fi
ACTIVE_FW="${SELECTION#SELECT }"
echo "newflow-ceiling: active node = $ACTIVE_FW"

# The pool must already exist. This harness does NOT mutate the NAT config:
# an operator commits the pool-mode rule deliberately and confirms it, so a
# half-applied rewrite can never be mistaken for a dataplane result.
incus_cmd exec "$ACTIVE_FW" -- cli -c "show security nat source pool $POOL_NAME" \
    > "$ARTIFACT_ROOT/pool-preflight.txt" 2>&1 \
    || fail "pool '$POOL_NAME' not present on $ACTIVE_FW — commit the pool-mode source-NAT rule first (see docs/userspace-newflow-ceiling.md)"

scrape() { # scrape <output-path>
    incus_cmd exec "$ACTIVE_FW" -- curl -sf "$METRICS_URL" > "$1" \
        || fail "metrics scrape failed on $ACTIVE_FW ($METRICS_URL)"
}

# The helper pid is the analyzer's only direct restart detector, so a failed
# lookup must fail the cell rather than be papered over with a 0 — a snapshot
# without it would silently skip the restart comparison.
helper_pid() {
    local pid
    pid="$(incus_cmd exec "$ACTIVE_FW" -- pidof xpf-userspace-dp 2>/dev/null | awk '{print $1}')"
    if [[ -z "$pid" ]]; then
        return 1
    fi
    printf '%s' "$pid"
}

# --- rate sweep -----------------------------------------------------------
overall_rc=0
IFS=',' read -r -a RATE_LIST <<< "$RATES"
for rate in "${RATE_LIST[@]}"; do
    cell="$ARTIFACT_ROOT/rate-$rate"
    mkdir -p "$cell"
    echo "=== cell: offered ${rate} new flows/sec for ${DURATION}s ==="

    # Quiesce so the before-snapshot is not still absorbing the previous
    # cell's teardown (RST-closed sessions are held 2s, #4800 H1).
    sleep "$SETTLE_SEC"

    if ! pid_before="$(helper_pid)"; then
        echo "  helper pid not readable before the cell — cell refused" >&2
        overall_rc=1
        continue
    fi
    scrape "$cell/before.prom"
    t_before="$(date +%s.%N)"
    client_args=(
        --mode client --target "$TARGET_IP" --dst-ports "$DST_PORTS"
        --rate "$rate" --duration "$DURATION" --threads "$THREADS"
        --close "$CLOSE_MODE"
    )
    if [[ -n "$SRC_BIND" ]]; then
        client_args+=(--src-bind "$SRC_BIND")
    fi

    incus_cmd exec "$HOST" -- "$GEN_BIN" "${client_args[@]}" \
        > "$cell/generator.json" 2> "$cell/generator.err"
    gen_rc=$?

    t_after="$(date +%s.%N)"
    scrape "$cell/after.prom"
    if ! pid_after="$(helper_pid)"; then
        echo "  helper pid not readable after the cell (helper died?) —" \
             "cell refused" >&2
        overall_rc=1
        continue
    fi

    if [[ $gen_rc -ne 0 ]]; then
        echo "  generator exited $gen_rc — cell refused, see $cell/generator.err" >&2
        overall_rc=1
        continue
    fi

    # Normalize both scrapes into the snapshot shape the analyzer consumes.
    # Pool selection, monotonicity, validity and attribution all live on the
    # Python side; this step only reshapes.
    python3 - "$cell" "$POOL_NAME" "$RULE_NAME" "$t_before" "$t_after" \
        "$pid_before" "$pid_after" "$ANALYZER" <<'PY' \
        || fail "snapshot normalization failed for $cell (see $cell/*.prom)"
import json, os, sys

cell, pool, rule, t0, t1, pid0, pid1, analyzer = sys.argv[1:9]
sys.path.insert(0, os.path.dirname(os.path.abspath(analyzer)))
from newflow_ceiling_analyze import parse_prometheus_text

for name, ts, pid in (("before", t0, pid0), ("after", t1, pid1)):
    with open(os.path.join(cell, name + ".prom"), encoding="utf-8") as f:
        snap = parse_prometheus_text(
            f.read(),
            timestamp=float(ts),
            pool_name=pool,
            rule_name=rule,
            helper_pid=int(pid),
        )
    with open(os.path.join(cell, name + ".json"), "w", encoding="utf-8") as f:
        json.dump(snap, f, indent=2)
PY

    # Offered rate = the rate we REQUESTED of the generator, i.e. `$rate`.
    #
    # It used to be the generator's own ACHIEVED rate, which disabled the
    # generator-underdrive gate mathematically rather than merely weakening it:
    # the analyzer computes accept_ratio = accepted / offered, so feeding it the
    # achieved rate makes the ratio ~1 by construction. Request 100k/s, have the
    # client manage 20k/s, have the firewall install all 20k, and the cell came
    # back VALID at 20k — a GENERATOR ceiling reported as a firewall
    # measurement, which is the single most expensive way this harness can be
    # wrong. With the requested rate the same cell yields accept_ratio 0.2 and
    # is refused INCONCLUSIVE, which is what the gate exists to do (and what
    # newflow_ceiling_analyze_test.py has always asserted — the harness and its
    # own unit test disagreed about what was being fed in).
    #
    # The generator report is still parsed and still FAILS THE CELL when it is
    # unreadable or reports zero established connections. That check answers a
    # different question — "did the generator run at all" — and must never
    # degrade to 0, because a silent 0 would disable the underdrive gate from
    # the other side.
    # shellcheck disable=SC2034  # `offered` is deliberately WRITE-ONLY: the
    # value is not used, the EXIT STATUS is. The python snippet raises when the
    # generator reported no established connections, which is what refuses the
    # cell; capturing stdout keeps the parse and the liveness check in one
    # place. Named rather than assigned to `_` so the reason survives.
    if ! offered="$(python3 -c '
import json, sys
d = json.load(open(sys.argv[1]))
v = float(d["established_per_sec"])
if v <= 0:
    raise SystemExit("generator established no connections")
print(v)
' "$cell/generator.json")"; then
        echo "  generator report unparseable or reported zero established" \
             "connections — cell refused, see $cell/generator.json" >&2
        overall_rc=1
        continue
    fi

    # `$rate` is what we asked for; "$offered" above is only the liveness check.
    python3 "$ANALYZER" "$cell/before.json" "$cell/after.json" \
        --offered-rate "$rate" --json > "$cell/analysis.json"
    cell_rc=$?
    python3 "$ANALYZER" "$cell/before.json" "$cell/after.json" \
        --offered-rate "$rate" | tee "$cell/analysis.txt"
    [[ $cell_rc -eq 0 ]] || overall_rc=$cell_rc
done

echo
echo "newflow-ceiling: per-cell verdicts under $ARTIFACT_ROOT"
echo "  A ceiling is the highest cell that came back VALID and unsaturated,"
echo "  followed by a higher cell that came back VALID and saturated. A run"
echo "  with no VALID cells has no ceiling — report it as such."
exit "$overall_rc"
