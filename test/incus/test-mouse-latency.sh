#!/usr/bin/env bash
# Run one rep of the #905 mouse-latency cell.
#
# Usage: test-mouse-latency.sh <N> <M> <duration_s> <out_dir>
#   N: elephant streams against 172.16.80.200:5202 (1 Gbps exact)
#   M: concurrent mouse coroutines against 172.16.80.200:6200 (best-effort)
#   duration_s: probe duration in seconds (≥ 60 recommended)
#   out_dir: per-rep output directory (created if missing)
#
# See docs/pr/905-mouse-latency/plan.md for the full spec. Heavy
# parsing logic lives in mouse_latency_orchestrate.py.

set -euo pipefail

if [[ $# -ne 4 ]]; then
    echo "usage: $0 <N> <M> <duration_s> <out_dir>" >&2
    exit 1
fi

N="$1"
M="$2"
DURATION="$3"
OUT_DIR="$4"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=test/incus/mouse-elephant-lib.sh
. "${SCRIPT_DIR}/mouse-elephant-lib.sh"
# #13070 (D10-15): incus_run / incus_exec / detect_active_primary moved to
# the shared CoS schedule + CLI wrapper library (same implementations,
# same tolerant fallback doctrine); they are defined there now.
# shellcheck source=cos-apply-lib.sh
. "${SCRIPT_DIR}/cos-apply-lib.sh"

# Constants from plan §3.1.
INCUS_REMOTE="loss"
PRIMARY="xpf-userspace-fw0"
SECONDARY="xpf-userspace-fw1"
SOURCE="cluster-userspace-host"
TARGET_V4="172.16.80.200"
# #8259: the mouse and elephant targets are SEPARATE knobs that happen to
# default to the same address, because on the standing loss cluster there is
# only one host on VLAN 80 to point them at.
#
# They used to be one variable, and that is the whole defect: the gate ratios a
# loaded cell against an idle cell, and when both flows terminate on one host
# the loaded cell adds ~8.6 Gbit/s of receive load to the very machine whose
# service time is inside every mouse sample. The verdict then attributes that
# difference entirely to firewall queueing. `mouse_latency_aggregate.decide()`
# now refuses to emit PASS/FAIL when these two are equal.
#
# Splitting them here is what makes that check meaningful rather than
# permanently true: stand up a second host on VLAN 80, set
# ELEPHANT_TARGET_V4 to it, and the gate starts producing attributable numbers
# with no further change. See target-services.sh on why there is no second host
# today (the current one is external lab hardware with no management path).
MOUSE_TARGET_V4="${MOUSE_TARGET_V4:-$TARGET_V4}"
ELEPHANT_TARGET_V4="${ELEPHANT_TARGET_V4:-$TARGET_V4}"
# Env-var overridable so test-mouse-latency-same-class.sh can run a
# same-class variant by selecting the matching 520x elephant port and
# 620x TCP echo port. The canonical CoS fixture maps 6200..6211 to the
# same forwarding classes as 5200..5211, so same-class latency no longer
# needs the legacy port-7 override fixture.
# SHAPER_BPS MUST move with ELEPHANT_PORT because the cwnd-settle
# and collapse gates compare against it.
ELEPHANT_PORT="${ELEPHANT_PORT:-$MOUSE_DEFAULT_IPERF_PORT}"
MOUSE_PORT="${MOUSE_PORT:-$MOUSE_DEFAULT_ECHO_PORT}"
MOUSE_CLASS="${MOUSE_CLASS:-best-effort}"
MOUSE_COS_SURPLUS_SHARING="${MOUSE_COS_SURPLUS_SHARING:-0}"
MOUSE_PROBE_CONNECTION_MODE="${MOUSE_PROBE_CONNECTION_MODE:-per-attempt}"
MOUSE_PROBE_MIN_INTERVAL_MS="${MOUSE_PROBE_MIN_INTERVAL_MS:-0}"
SHAPER_BPS="${SHAPER_BPS:-$((1 * 1000 * 1000 * 1000))}"  # default 1 Gb/s (port 5202); same-class wrappers must override with their selected class cap.
SETTLE_BUDGET="${MOUSE_LATENCY_SETTLE_BUDGET:-20}"
# Validate env-overrides (Copilot D.5): ports/bps must be
# digits only so they can't smuggle shell metacharacters into
# the remote `bash -c` interpolations below. MOUSE_CLASS and
# MOUSE_PROBE_CONNECTION_MODE are whitelisted, MOUSE_COS_SURPLUS_SHARING
# is normalized as a boolean, and MOUSE_PROBE_MIN_INTERVAL_MS is numeric,
# so typos can't slip stray values into manifest.json or the probe CLI.
[[ "$ELEPHANT_PORT" =~ ^[0-9]+$ ]] \
    || { echo "ABORT: ELEPHANT_PORT='$ELEPHANT_PORT' must be digits" >&2; exit 1; }
[[ "$MOUSE_PORT" =~ ^[0-9]+$ ]] \
    || { echo "ABORT: MOUSE_PORT='$MOUSE_PORT' must be digits" >&2; exit 1; }
[[ "$SHAPER_BPS" =~ ^[0-9]+$ ]] \
    || { echo "ABORT: SHAPER_BPS='$SHAPER_BPS' must be digits" >&2; exit 1; }
[[ "$SETTLE_BUDGET" =~ ^[0-9]+$ && "$SETTLE_BUDGET" -gt 0 ]] \
    || { echo "ABORT: MOUSE_LATENCY_SETTLE_BUDGET='$SETTLE_BUDGET' must be a positive integer second count" >&2; exit 1; }
case "$MOUSE_CLASS" in
    best-effort|iperf-100m|iperf-1g|iperf-3g|iperf-6g|iperf-9g|iperf-12g|iperf-15g|iperf-18g|iperf-21g|iperf-24g|iperf-uncapped) ;;
    *) echo "ABORT: MOUSE_CLASS='$MOUSE_CLASS' must be one of best-effort/iperf-100m/iperf-1g/iperf-3g/iperf-6g/iperf-9g/iperf-12g/iperf-15g/iperf-18g/iperf-21g/iperf-24g/iperf-uncapped" >&2; exit 1 ;;
esac
case "${MOUSE_COS_SURPLUS_SHARING,,}" in
    0|false|no|off) MOUSE_COS_SURPLUS_SHARING=0 ;;
    1|true|yes|on) MOUSE_COS_SURPLUS_SHARING=1 ;;
    *) echo "ABORT: MOUSE_COS_SURPLUS_SHARING='$MOUSE_COS_SURPLUS_SHARING' must be boolean" >&2; exit 1 ;;
esac
case "$MOUSE_PROBE_CONNECTION_MODE" in
    per-attempt|persistent) ;;
    *) echo "ABORT: MOUSE_PROBE_CONNECTION_MODE='$MOUSE_PROBE_CONNECTION_MODE' must be per-attempt or persistent" >&2; exit 1 ;;
esac
[[ "$MOUSE_PROBE_MIN_INTERVAL_MS" =~ ^[0-9]+([.][0-9]+)?$ ]] \
    || { echo "ABORT: MOUSE_PROBE_MIN_INTERVAL_MS='$MOUSE_PROBE_MIN_INTERVAL_MS' must be a non-negative number" >&2; exit 1; }
# #1365 env-shape consistency guard: the cwnd-settle gate requires the
# elephant aggregate to reach 0.7 * SHAPER_BPS, but the class implied by
# ELEPHANT_PORT (per cos-iperf-config.set) can only ever deliver up to
# its configured cap. If the floor exceeds that cap the gate is
# arithmetically unsatisfiable — every loaded rep INVALIDates before the
# mouse probe ever starts (the reported #1365 symptom: port 5202 = 1 Gbps
# exact class paired with SHAPER_BPS=10G). Fail fast with an actionable
# message instead of burning a whole matrix cell on an impossible pairing.
# (Static check; runs offline, no cluster contact.)
python3 "${SCRIPT_DIR}/mouse_latency_orchestrate.py" check-env-consistency \
    "$ELEPHANT_PORT" "$SHAPER_BPS" \
    || { echo "ABORT: ELEPHANT_PORT=$ELEPHANT_PORT / SHAPER_BPS=$SHAPER_BPS is an unsatisfiable cwnd-settle pairing (see above)" >&2; exit 1; }
SLACK=10
CWND_SETTLE_OK="unknown"
CWND_SETTLE_ELAPSED=0

mkdir -p "$OUT_DIR"
# Include the cell name in REP_TAG so per-rep temp files on the
# remote source container don't collide across cells (e.g.
# cell_N0_M10/rep_00 vs cell_N128_M10/rep_00 — without the cell
# prefix, both write to /tmp/probe-rep_00.json and a failed pull
# in the second cell silently picks up the first cell's data).
# Codex R6 HIGH.
CELL_DIR="$(basename "$(dirname "$OUT_DIR")")"
REP_TAG="${CELL_DIR}_${OUT_DIR##*/}"

# Local-side stale-artifact guard (Codex R7 HIGH): if OUT_DIR is
# reused (rerun into an existing rep dir) and the new probe run
# fails before overwriting probe.json, the previous run's data
# would silently masquerade as the current rep's result. Wipe
# the artifacts at rep start; INVALID-* markers from a prior run
# are also cleared so the new rep's verdict is clean.
rm -f "${OUT_DIR}"/probe.json \
      "${OUT_DIR}"/probe-stdout.log \
      "${OUT_DIR}"/iperf3.txt \
      "${OUT_DIR}"/iperf3-settle.txt \
      "${OUT_DIR}"/cwnd-settle.json \
      "${OUT_DIR}"/mpstat-settle.txt \
      "${OUT_DIR}"/mpstat.txt \
      "${OUT_DIR}"/cos-interface-pre.txt \
      "${OUT_DIR}"/cos-interface-settle.txt \
      "${OUT_DIR}"/cos-interface-post.txt \
      "${OUT_DIR}"/screen-pre.txt \
      "${OUT_DIR}"/screen-pre-fw.txt \
      "${OUT_DIR}"/screen-post.txt \
      "${OUT_DIR}"/rg-state-poll.txt \
      "${OUT_DIR}"/rg-state-initial.txt \
      "${OUT_DIR}"/rg-state-final.txt \
      "${OUT_DIR}"/rg-state-flap.log \
      "${OUT_DIR}"/rg-state-final-diff.log \
      "${OUT_DIR}"/ha-transitions.log \
      "${OUT_DIR}"/manifest.json \
      "${OUT_DIR}"/cos-apply.log \
      "${OUT_DIR}"/jc-cursor-* \
      "${OUT_DIR}"/jc-stderr-*.txt \
      "${OUT_DIR}"/INVALID-*

# incus_run / incus_exec / current_primary used to be defined here; they
# moved to cos-apply-lib.sh (#13070 / D10-15) as incus_run / incus_exec /
# detect_active_primary so every CoS harness shares ONE wrapper set.
# Behavior notes for this script: incus_exec still qualifies bare targets
# with ${INCUS_REMOTE} (the lib does it), and current_primary's tolerant
# fallback is now `detect_active_primary "$PRIMARY" "$SECONDARY"` — same
# query, same parser, same fall-back-to-fw0 answer.

write_invalid_manifest() {
    local reason="$1"
    local started_at
    started_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    INVALID_REASON="$reason" STARTED_AT="$started_at" \
    N="$N" M="$M" DURATION="$DURATION" \
    ELEPHANT_PORT="$ELEPHANT_PORT" MOUSE_PORT="$MOUSE_PORT" \
    MOUSE_TARGET_V4="$MOUSE_TARGET_V4" ELEPHANT_TARGET_V4="$ELEPHANT_TARGET_V4" \
    MOUSE_CLASS="$MOUSE_CLASS" MOUSE_COS_SURPLUS_SHARING="$MOUSE_COS_SURPLUS_SHARING" \
    MOUSE_PROBE_CONNECTION_MODE="$MOUSE_PROBE_CONNECTION_MODE" \
    MOUSE_PROBE_MIN_INTERVAL_MS="$MOUSE_PROBE_MIN_INTERVAL_MS" \
    SHAPER_BPS="$SHAPER_BPS" SETTLE_BUDGET="$SETTLE_BUDGET" \
    CWND_SETTLE_OK="${CWND_SETTLE_OK:-unknown}" \
    CWND_SETTLE_ELAPSED="${CWND_SETTLE_ELAPSED:-0}" \
    python3 -c '
import json, os
settle_raw = os.environ["CWND_SETTLE_OK"]
if settle_raw == "true":
    settle_ok = True
elif settle_raw == "false":
    settle_ok = False
else:
    settle_ok = None
manifest = {
    "N": int(os.environ["N"]),
    "M": int(os.environ["M"]),
    "duration_s": int(os.environ["DURATION"]),
    "started_at": os.environ["STARTED_AT"],
    "status": "INVALID",
    "invalid_reason": os.environ["INVALID_REASON"],
    "elephant_port": int(os.environ["ELEPHANT_PORT"]),
    "mouse_port": int(os.environ["MOUSE_PORT"]),
    # #8259: the gate cannot attribute its verdict when these are equal.
    "mouse_target": os.environ["MOUSE_TARGET_V4"],
    "elephant_target": os.environ["ELEPHANT_TARGET_V4"],
    "mouse_class": os.environ["MOUSE_CLASS"],
    "cos_surplus_sharing": os.environ["MOUSE_COS_SURPLUS_SHARING"] == "1",
    "mouse_probe_connection_mode": os.environ["MOUSE_PROBE_CONNECTION_MODE"],
    "mouse_probe_min_interval_ms": float(os.environ["MOUSE_PROBE_MIN_INTERVAL_MS"]),
    "shaper_bps": int(os.environ["SHAPER_BPS"]),
    "settle_budget_s": int(os.environ["SETTLE_BUDGET"]),
    "cwnd_settle_ok": settle_ok,
    "cwnd_settle_elapsed_s": int(os.environ["CWND_SETTLE_ELAPSED"]),
}
print(json.dumps(manifest, indent=2))
' > "${OUT_DIR}/manifest.json" || true
}

invalidate() {
    local reason="$1"
    : > "${OUT_DIR}/INVALID-${reason}"
    write_invalid_manifest "$reason"
    echo "REP INVALID: $reason" >&2
    exit 0
}

# Stop one backgrounded remote job: close the local incus-exec client,
# then stop the process where it actually runs.
#
# #7159/#8270: killing the local $PID only closes the client. incus
# leaves the command running inside the instance when a non-interactive
# client disconnects, so on an early INVALID exit the remote process
# outlived its rep. For the elephant that was not a leak but a
# CORRUPTED CELL -- it kept sending for the rest of its 90 s budget
# while the next rep started ~8 s later, and that rep then shared the
# 1 Gb/s exact class with its own predecessor, so one marginal
# rejection cascaded into a cell of zero valid reps. For the mpstat
# samplers it is unaccounted CPU on the very container whose p99.9 tail
# this harness measures, plus an orphan still writing the file a later
# same-tag reuse reads.
#
# Unconditional, including on a rep that finished normally: the kill
# command confirms the recorded pid still belongs to the expected
# program before signalling, so there is nothing to gain by tracking
# whether we already waited, and running it always is what removes the
# pidfile on every path. See test/incus/mouse-elephant-lib.sh.
stop_remote_job() { # <local pid> <job name> <program name>
    local local_pid="$1" job="$2" prog="$3"
    [[ -n "$local_pid" ]] || return 0
    kill "$local_pid" 2>/dev/null || true
    incus_exec "$SOURCE" sh -c \
        "$(mouse_remote_job_kill_cmd "$job" "$REP_TAG" "$prog")" \
        < /dev/null > /dev/null 2>&1 || true
}

cleanup() {
    stop_remote_job "${IPERF_PID:-}" iperf3 iperf3
    stop_remote_job "${SETTLE_MPSTAT_PID:-}" mpstat-settle mpstat
    stop_remote_job "${MPSTAT_PID:-}" mpstat mpstat
    # RG_POLL_PID is a LOCAL subshell, not an incus-exec client: its $!
    # is a process on this host, so a plain kill is the correct and
    # complete stop. Routing it through stop_remote_job would add a
    # pointless remote round-trip per rep and stop nothing.
    [[ -n "${RG_POLL_PID:-}" ]] && kill "$RG_POLL_PID" 2>/dev/null || true
}
trap cleanup EXIT

# Defense in depth: remove any stale per-rep temp files on the
# remote source before this rep starts (Codex R6 HIGH: without
# REP_TAG including the cell name, two cells with the same rep
# index would collide; even with that fix, a failed pull
# previously left a stale file behind that the next reuse with the
# same tag would inherit. Belt-and-suspenders.)
incus_exec "$SOURCE" sh -c \
    "rm -f /tmp/mouse_latency_probe.py /tmp/probe-${REP_TAG}.json /tmp/mpstat-${REP_TAG}.txt /tmp/mpstat-settle-${REP_TAG}.txt /tmp/iperf3-${REP_TAG}.txt /tmp/iperf3-${REP_TAG}.pid /tmp/mpstat-${REP_TAG}.pid /tmp/mpstat-settle-${REP_TAG}.pid" \
    < /dev/null > /dev/null 2>&1 || true

# Push helper scripts to the source container (probe driver runs there).
incus_run file push "${SCRIPT_DIR}/mouse_latency_probe.py" \
    "${INCUS_REMOTE}:${SOURCE}/tmp/mouse_latency_probe.py"

# ---- step 0: echo-daemon preflight (Copilot D.3: must run BEFORE
# any CoS state mutation so a failure leaves the cluster in
# whatever state preceded this rep, not in the selected CoS fixture).
# Uses bash /dev/tcp rather than `nc -zw1` because the source
# container doesn't ship netcat by default.
if ! incus_exec "$SOURCE" timeout 2 bash -c \
        "exec 3<>/dev/tcp/${MOUSE_TARGET_V4}/${MOUSE_PORT}" \
        > /dev/null 2>&1; then
    echo "ABORT: mouse echo not reachable on ${MOUSE_TARGET_V4}:${MOUSE_PORT}" >&2
    echo "       (set MOUSE_PORT or stand up the echo daemon)" >&2
    exit 1
fi

# ---- step 0a: no other elephant may already be running on the source
# (#7159). Before the fix in mouse-elephant-lib.sh an early-INVALID rep
# orphaned its 90 s iperf3, and the next rep measured a class it was
# sharing with its own predecessor -- a silent halving of the offered
# rate that reads as a dataplane result. A leftover client is now a
# LOUD, attributed INVALID rather than a corrupted number. It also
# catches the other way this happens: another agent driving traffic
# from the same source container while this rep runs.
if ! incus_exec "$SOURCE" sh -c "$(mouse_elephant_stale_check_cmd)" \
        < /dev/null > /dev/null 2>&1; then
    echo "an iperf3 client is already running on ${SOURCE}" >&2
    invalidate "stale-elephant-client"
fi

# ---- step 1: CoS preflight (fixture-apply only, plan §3.3 + R4 MED 4).
# Copilot R3 #5: apply-cos-config replicates from primary to peer, so
# it must run against the current RG0 primary. If the cluster has
# already failed over before the rep starts, hard-coding fw0 would
# attempt to apply on the secondary.
PRE_PRIMARY=$(detect_active_primary "$PRIMARY" "$SECONDARY")
APPLY_COS_FLAGS=()
if [[ "$MOUSE_COS_SURPLUS_SHARING" -eq 1 ]]; then
    APPLY_COS_FLAGS+=(--surplus-sharing)
fi
"${SCRIPT_DIR}/apply-cos-config.sh" "${APPLY_COS_FLAGS[@]}" \
    "${INCUS_REMOTE}:${PRE_PRIMARY}" \
    > "${OUT_DIR}/cos-apply.log" 2>&1
incus_exec "$PRE_PRIMARY" cli -c "show class-of-service interface" \
    > "${OUT_DIR}/cos-interface-pre.txt" 2>/dev/null || true

# ---- step 3: RG state polling at 1 Hz (plan §4.5 step 3)
RG_POLL_FILE="${OUT_DIR}/rg-state-poll.txt"
: > "$RG_POLL_FILE"
(
    end_t=$(($(date +%s) + DURATION + SETTLE_BUDGET + SLACK + 5))
    while [[ $(date +%s) -lt $end_t ]]; do
        ts=$(date +%s%3N)
        # C175-HC-083: record every tick. A failed cli poll or an empty
        # parse must leave a POLL_FAILED sentinel so rg-state-flapped can
        # see the gap (a failover hiding in a dropped poll must not read
        # as "stable"). The old `... | ... >> file || true` appended
        # nothing on failure, making the gap invisible.
        if status_out=$(incus_exec "$PRIMARY" cli -c "show chassis cluster status" 2>/dev/null); then
            parsed=$(printf '%s\n' "$status_out" \
                | python3 "${SCRIPT_DIR}/mouse_latency_orchestrate.py" \
                      parse-cluster-state "$ts" 2>/dev/null || true)
            if [[ -n "$parsed" ]]; then
                printf '%s\n' "$parsed" >> "$RG_POLL_FILE"
            else
                printf '%s\trg=?\tnode=?\tstate=POLL_FAILED\n' "$ts" >> "$RG_POLL_FILE"
            fi
        else
            printf '%s\trg=?\tnode=?\tstate=POLL_FAILED\n' "$ts" >> "$RG_POLL_FILE"
        fi
        sleep 1
    done
) &
RG_POLL_PID=$!

# Initial RG state snapshot (one-shot).
incus_exec "$PRIMARY" cli -c "show chassis cluster status" \
    > "${OUT_DIR}/rg-state-initial.txt" 2>/dev/null || true

# ---- step 4: journalctl cursor capture on BOTH nodes (plan §4.5 step 4).
# Empty cursors lose HA coverage on that node; fail-fast if capture fails.
for FW in "$PRIMARY" "$SECONDARY"; do
    cursor_out=$(incus_exec "$FW" journalctl --show-cursor -n 0 2>/dev/null \
                 | tail -1) || cursor_out=""
    cursor=$(echo "$cursor_out" | sed -n 's/.*cursor: //p')
    if [[ -z "$cursor" ]]; then
        echo "journalctl cursor capture failed on $FW" >&2
        invalidate "jc-cursor-capture-${FW}"
    fi
    echo "$cursor" > "${OUT_DIR}/jc-cursor-${FW}.txt"
done

# ---- step 4a: SYN-cookie counter snapshot (pre).
# Copilot R3 #6: capture from the same node identity the post-run
# comparison will follow (current primary at the time of the snapshot).
# Mismatch between pre (always fw0) and post (current_primary) made the
# screen_engaged delta meaningless when fw0 wasn't primary.
SCREEN_PRE_FW=$(detect_active_primary "$PRIMARY" "$SECONDARY")
echo "$SCREEN_PRE_FW" > "${OUT_DIR}/screen-pre-fw.txt"
incus_exec "$SCREEN_PRE_FW" cli -c "show security screen statistics zone wan" \
    > "${OUT_DIR}/screen-pre.txt" 2>/dev/null || true

# ---- step 5: elephant launch (if N > 0). Background; let it run for
# SETTLE_BUDGET + DURATION + SLACK seconds total.
IPERF_DURATION=$((SETTLE_BUDGET + DURATION + SLACK))

if [[ "$N" -gt 0 ]]; then
    incus_exec "$SOURCE" sh -c \
        "$(mouse_elephant_start_cmd "$REP_TAG" "$ELEPHANT_TARGET_V4" "$ELEPHANT_PORT" \
                                    "$N" "$IPERF_DURATION")" \
        < /dev/null > /dev/null 2>&1 &
    IPERF_PID=$!
    incus_exec "$SOURCE" sh -c \
        "$(mouse_remote_job_start_cmd mpstat-settle "$REP_TAG" \
                                      mpstat 1 "$SETTLE_BUDGET")" \
        < /dev/null > /dev/null 2>&1 &
    SETTLE_MPSTAT_PID=$!

    # Wait the SETTLE_BUDGET, then snapshot iperf3.txt and run the
    # cwnd-settle gate. (Live tailing inside incus exec is hard to
    # plumb reliably; the budget is the gate.) The diagnostics artifact
    # records the final aggregate window and per-flow TCP spread so a
    # high-rate failure is attributable instead of just INVALID.
    sleep "$SETTLE_BUDGET"
    CWND_SETTLE_ELAPSED="$SETTLE_BUDGET"
    set +e
    incus_run file pull \
        "${INCUS_REMOTE}:${SOURCE}/tmp/iperf3-${REP_TAG}.txt" \
        "${OUT_DIR}/iperf3-settle.txt" 2>/dev/null
    pull_rc=$?
    wait "$SETTLE_MPSTAT_PID" 2>/dev/null
    incus_run file pull \
        "${INCUS_REMOTE}:${SOURCE}/tmp/mpstat-settle-${REP_TAG}.txt" \
        "${OUT_DIR}/mpstat-settle.txt" 2>/dev/null
    set -e
    SETTLE_MPSTAT_PID=""
    # Distinguish pull failure from a real cwnd-not-settled (Copilot R2 #1):
    # the cwnd-settle gate fires only when we actually have iperf3 output.
    if [[ $pull_rc -ne 0 || ! -s "${OUT_DIR}/iperf3-settle.txt" ]]; then
        invalidate "iperf3-settle-pull-failed"
    fi
    set +e
    python3 "${SCRIPT_DIR}/mouse_latency_orchestrate.py" \
        settle-diagnostics "${OUT_DIR}/iperf3-settle.txt" "$SHAPER_BPS" \
        --elapsed-sec "$CWND_SETTLE_ELAPSED" \
        --sample-index 0 \
        --out "${OUT_DIR}/cwnd-settle.json"
    settle_diag_rc=$?
    set -e
    SETTLE_PRIMARY=$(detect_active_primary "$PRIMARY" "$SECONDARY")
    incus_exec "$SETTLE_PRIMARY" cli -c "show class-of-service interface" \
        > "${OUT_DIR}/cos-interface-settle.txt" 2>/dev/null || true
    if [[ $settle_diag_rc -ne 0 ]]; then
        CWND_SETTLE_OK="false"
        invalidate "cwnd-not-settled"
    else
        CWND_SETTLE_OK="true"
    fi
fi

# ---- step 2 (deferred to here): start mpstat over the probe window only.
# R2 HIGH 6 fix had the killer-before-Average regression: starting mpstat
# at top-of-rep means we kill it before its `Average:` row prints. Now
# mpstat's count == DURATION, so it exits naturally just as the probe
# does and writes the Average: line.
incus_exec "$SOURCE" sh -c \
    "$(mouse_remote_job_start_cmd mpstat "$REP_TAG" mpstat 1 "$DURATION")" \
    < /dev/null > /dev/null 2>&1 &
MPSTAT_PID=$!

# ---- step 6: probe driver (M coroutines, closed-loop)
incus_exec "$SOURCE" python3 /tmp/mouse_latency_probe.py \
    --target "$MOUSE_TARGET_V4" --port "$MOUSE_PORT" \
    --concurrency "$M" --duration "$DURATION" \
    --payload-bytes 64 --connection-mode "$MOUSE_PROBE_CONNECTION_MODE" \
    --min-interval-ms "$MOUSE_PROBE_MIN_INTERVAL_MS" \
    --out "/tmp/probe-${REP_TAG}.json" \
    > "${OUT_DIR}/probe-stdout.log" 2>&1 || true

set +e
incus_run file pull \
    "${INCUS_REMOTE}:${SOURCE}/tmp/probe-${REP_TAG}.json" \
    "${OUT_DIR}/probe.json" 2>/dev/null
probe_pull_rc=$?
set -e
# Catch a missing/empty/malformed probe.json early (Copilot R2 #2)
# instead of letting the matrix wrapper silently treat the absence
# as "validity false" and lose attribution.
if [[ $probe_pull_rc -ne 0 ]]; then
    invalidate "probe-pull-failed"
fi
if [[ ! -s "${OUT_DIR}/probe.json" ]]; then
    invalidate "probe-missing"
fi
if ! python3 -c 'import json,sys; json.load(open(sys.argv[1]))' \
        "${OUT_DIR}/probe.json" 2>/dev/null; then
    invalidate "probe-invalid-json"
fi

# ---- step 8: elephant stop + collapse check
if [[ -n "${IPERF_PID:-}" ]]; then
    # Wait for iperf3 to finish naturally (it has a -t budget that
    # already includes settle + probe + slack). Capture exit status.
    set +e
    wait "$IPERF_PID"
    iperf_rc=$?
    set -e
    incus_run file pull \
        "${INCUS_REMOTE}:${SOURCE}/tmp/iperf3-${REP_TAG}.txt" \
        "${OUT_DIR}/iperf3.txt" 2>/dev/null || true
    if [[ $iperf_rc -ne 0 ]]; then
        echo "iperf3 exited rc=$iperf_rc" >&2
        invalidate "iperf3-rc${iperf_rc}"
    fi
    if [[ ! -s "${OUT_DIR}/iperf3.txt" ]]; then
        invalidate "iperf3-no-output"
    fi
    # Scope collapse detection to the probe window (R5 HIGH): rows
    # [SETTLE_BUDGET : SETTLE_BUDGET + DURATION] are the probe
    # period. Earlier rows are settle warmup; later rows are slack
    # post-probe. Anchoring on probe-start (--skip-front) avoids
    # the off-by-window error where "last N rows" would lose the
    # first DURATION seconds of probe and include SLACK seconds
    # of post-probe noise.
    set +e
    python3 "${SCRIPT_DIR}/mouse_latency_orchestrate.py" \
        check-collapse --skip-front "$SETTLE_BUDGET" --n-rows "$DURATION" \
        "${OUT_DIR}/iperf3.txt" "$SHAPER_BPS"
    collapse_rc=$?
    set -e
    case "$collapse_rc" in
        0) invalidate "elephant-collapsed" ;;
        1) : ;;  # not collapsed, ok
        *) invalidate "collapse-check-error-rc${collapse_rc}" ;;
    esac
fi

# ---- step 7: wait for mpstat to finish on its own count (so it
# writes an `Average:` row), then parse client-busy result.
wait "$MPSTAT_PID" 2>/dev/null || true
incus_run file pull "${INCUS_REMOTE}:${SOURCE}/tmp/mpstat-${REP_TAG}.txt" \
    "${OUT_DIR}/mpstat.txt" 2>/dev/null || true
# Missing or unparseable mpstat output → INVALID rather than silent
# pass (R2 HIGH 6 partial: v1 treated 0% as "fine"; that hid mpstat
# crashes / pull failures).
if [[ ! -s "${OUT_DIR}/mpstat.txt" ]]; then
    invalidate "mpstat-missing"
fi
mpstat_busy=$(awk '/^Average:.*all/ { print 100 - $NF; exit }' \
    "${OUT_DIR}/mpstat.txt")
if [[ -z "$mpstat_busy" ]]; then
    invalidate "mpstat-unparseable"
fi
if python3 -c "import sys; sys.exit(0 if float('${mpstat_busy}') > 80 else 1)"; then
    invalidate "client-saturated"
fi

# ---- step 9: journalctl HA-transition diff (plan §4.5 step 9).
HA_RE='cluster: primary transition|vrrp: transitioning to (MASTER|BACKUP)'
ha_seen=0
for FW in "$PRIMARY" "$SECONDARY"; do
    cursor=$(cat "${OUT_DIR}/jc-cursor-${FW}.txt" 2>/dev/null || true)
    if [[ -z "$cursor" ]]; then
        # Cursor was captured non-empty in step 4 (or we'd have
        # invalidated then). An empty cursor here means the file
        # got clobbered — treat as harness failure.
        invalidate "jc-cursor-missing-${FW}"
    fi
    set +e
    matches=$(incus_exec "$FW" journalctl --after-cursor="$cursor" -u xpfd 2>"${OUT_DIR}/jc-stderr-${FW}.txt")
    jc_rc=$?
    set -e
    if [[ $jc_rc -ne 0 ]]; then
        echo "journalctl on $FW failed (rc=$jc_rc)" >&2
        invalidate "jc-error"
    fi
    set +e
    hit=$(echo "$matches" | grep -iE "$HA_RE")
    gr_rc=$?
    set -e
    if [[ $gr_rc -gt 1 ]]; then
        invalidate "jc-grep-error"
    fi
    if [[ -n "$hit" ]]; then
        ha_seen=1
        {
            echo "HA transition on $FW:"
            echo "$hit"
        } >> "${OUT_DIR}/ha-transitions.log"
    fi
done
[[ $ha_seen -eq 1 ]] && invalidate "ha-transition"

# ---- step 9a: SYN-cookie counter snapshot (post). Follow whichever
# node is currently primary — if a transition happened in-window we
# already invalidated above, but for the no-transition case we want
# the screen counters from the same node we sampled in step 4a.
post_primary=$(detect_active_primary "$PRIMARY" "$SECONDARY")
incus_exec "$post_primary" cli -c "show security screen statistics zone wan" \
    > "${OUT_DIR}/screen-post.txt" 2>/dev/null || true
incus_exec "$post_primary" cli -c "show class-of-service interface" \
    > "${OUT_DIR}/cos-interface-post.txt" 2>/dev/null || true
screen_engaged="false"
if ! diff -q "${OUT_DIR}/screen-pre.txt" "${OUT_DIR}/screen-post.txt" \
        > /dev/null 2>&1; then
    screen_engaged="true"
fi

# ---- step 10: RG state poll review.
kill "$RG_POLL_PID" 2>/dev/null || true
wait "$RG_POLL_PID" 2>/dev/null || true

# Final RG state one-shot, compared to the initial snapshot from
# step 3 (Codex R6 MED: catches an in-window state change that
# slipped through gaps in the 1Hz polling — even if individual
# `cli` calls failed during the rep, the initial vs final pair
# is two extra independent samples).
incus_exec "$PRIMARY" cli -c "show chassis cluster status" \
    > "${OUT_DIR}/rg-state-final.txt" 2>/dev/null || true

initial_triples=$(python3 "${SCRIPT_DIR}/mouse_latency_orchestrate.py" \
    parse-cluster-state 0 < "${OUT_DIR}/rg-state-initial.txt" 2>/dev/null \
    | sort -u || true)
final_triples=$(python3 "${SCRIPT_DIR}/mouse_latency_orchestrate.py" \
    parse-cluster-state 0 < "${OUT_DIR}/rg-state-final.txt" 2>/dev/null \
    | sort -u || true)
if [[ -n "$initial_triples" && "$initial_triples" != "$final_triples" ]]; then
    {
        echo "initial vs final RG state mismatch:"
        diff <(echo "$initial_triples") <(echo "$final_triples") || true
    } > "${OUT_DIR}/rg-state-final-diff.log"
    invalidate "rg-state-initial-vs-final"
fi

# Exit codes: 0 = drift detected (INVALID), 1 = stable, 2 = no data (INVALID).
set +e
python3 "${SCRIPT_DIR}/mouse_latency_orchestrate.py" \
    rg-state-flapped "$RG_POLL_FILE" \
    > "${OUT_DIR}/rg-state-flap.log" 2>&1
rg_rc=$?
set -e
case "$rg_rc" in
    0) invalidate "rg-state-flap" ;;
    1) : ;;  # stable, ok
    2) invalidate "rg-poll-no-data" ;;
    *) invalidate "rg-poll-error-rc${rg_rc}" ;;
esac

# ---- step 11: manifest write
# Copilot D.4: emit via python3 -c json.dump so string fields are
# properly JSON-escaped and numeric fields are typed correctly.
# The env-var validation block at the top of the script enforces
# digits-only ports/bps and a whitelisted MOUSE_CLASS, but
# defensive escaping here costs nothing and keeps the manifest
# schema-stable if the validation ever drifts.
STARTED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
N="$N" M="$M" DURATION="$DURATION" STARTED_AT="$STARTED_AT" \
SCREEN_ENGAGED="$screen_engaged" HA_TRANSITION_SEEN="$ha_seen" \
MPSTAT_AVG_BUSY="${mpstat_busy:-0}" \
ELEPHANT_PORT="$ELEPHANT_PORT" MOUSE_PORT="$MOUSE_PORT" \
MOUSE_TARGET_V4="$MOUSE_TARGET_V4" ELEPHANT_TARGET_V4="$ELEPHANT_TARGET_V4" \
MOUSE_CLASS="$MOUSE_CLASS" MOUSE_COS_SURPLUS_SHARING="$MOUSE_COS_SURPLUS_SHARING" \
MOUSE_PROBE_CONNECTION_MODE="$MOUSE_PROBE_CONNECTION_MODE" \
MOUSE_PROBE_MIN_INTERVAL_MS="$MOUSE_PROBE_MIN_INTERVAL_MS" \
SHAPER_BPS="$SHAPER_BPS" SETTLE_BUDGET="$SETTLE_BUDGET" \
CWND_SETTLE_OK="$CWND_SETTLE_OK" CWND_SETTLE_ELAPSED="$CWND_SETTLE_ELAPSED" \
python3 -c '
import json, os
settle_raw = os.environ["CWND_SETTLE_OK"]
if settle_raw == "true":
    settle_ok = True
elif settle_raw == "false":
    settle_ok = False
else:
    settle_ok = None
manifest = {
    "N": int(os.environ["N"]),
    "M": int(os.environ["M"]),
    "duration_s": int(os.environ["DURATION"]),
    "started_at": os.environ["STARTED_AT"],
    "screen_engaged": os.environ["SCREEN_ENGAGED"].lower() == "true",
    "ha_transition_seen": int(os.environ["HA_TRANSITION_SEEN"]),
    "mpstat_avg_busy": os.environ["MPSTAT_AVG_BUSY"],
    "elephant_port": int(os.environ["ELEPHANT_PORT"]),
    "mouse_port": int(os.environ["MOUSE_PORT"]),
    # #8259: the gate cannot attribute its verdict when these are equal.
    "mouse_target": os.environ["MOUSE_TARGET_V4"],
    "elephant_target": os.environ["ELEPHANT_TARGET_V4"],
    "mouse_class": os.environ["MOUSE_CLASS"],
    "cos_surplus_sharing": os.environ["MOUSE_COS_SURPLUS_SHARING"] == "1",
    "mouse_probe_connection_mode": os.environ["MOUSE_PROBE_CONNECTION_MODE"],
    "mouse_probe_min_interval_ms": float(os.environ["MOUSE_PROBE_MIN_INTERVAL_MS"]),
    "shaper_bps": int(os.environ["SHAPER_BPS"]),
    "settle_budget_s": int(os.environ["SETTLE_BUDGET"]),
    "cwnd_settle_ok": settle_ok,
    "cwnd_settle_elapsed_s": int(os.environ["CWND_SETTLE_ELAPSED"]),
}
print(json.dumps(manifest, indent=2))
' > "${OUT_DIR}/manifest.json"

echo "REP OK"
