#!/usr/bin/env bash
#
# step2-sched-switch-capture.sh — #821 P1 sister harness.
#
# Composes step1-capture.sh with a concurrent `perf record` on
# sched:sched_switch / sched_stat_runtime / sched_wakeup targeting
# the xpf-userspace worker TIDs, then dispatches the step2 reducer
# and classifier to emit a 12-block off-CPU histogram correlated
# against step1's shape[3..=6] via Spearman rho + T3 verdict.
#
# Usage:
#   step2-sched-switch-capture.sh <port> <direction> <cos-state> [--smoke-only]
#
#     port        5201 | 5202   (load-bearing cells per #819 §6)
#     direction   fwd
#     cos-state   with-cos
#     --smoke-only   run G8 preflight and exit 0 iff all 4 checks pass
#
# See docs/pr/821-p1-sched-switch-capture/plan.md.
#
# G8 preflight (§5) runs inline as step 0:
#   1. kernel.perf_event_paranoid <= 1 on the guest
#   2. Each tracepoint present (individual grep per name — closes MED-5)
#   3. `perf record` privilege smoke against one worker TID
#   4. `perf script` parseability on the smoke sample

set -euo pipefail

usage() {
	cat >&2 <<EOF
usage: $0 <port> <direction> <cos-state> [--smoke-only]
  port        5201 or 5202 (load-bearing cells only)
  direction   fwd
  cos-state   with-cos
  --smoke-only   run G8 preflight, exit 0 iff all checks pass
EOF
	exit 2
}

if [[ $# -lt 3 || $# -gt 4 ]]; then
	usage
fi

PORT="$1"
DIR="$2"
COS="$3"
SMOKE_ONLY=0
if [[ $# -eq 4 ]]; then
	if [[ "$4" == "--smoke-only" ]]; then
		SMOKE_ONLY=1
	else
		usage
	fi
fi

case "$PORT" in
	5201|5202|5203) ;;
	*) echo "error: port must be 5201, 5202, or 5203 (5203 for negative control), got '$PORT'" >&2; exit 2 ;;
esac
if [[ "$DIR" != "fwd" ]]; then
	echo "error: direction must be 'fwd', got '$DIR'" >&2; exit 2
fi
if [[ "$COS" != "with-cos" && "$COS" != "no-cos" ]]; then
	echo "error: cos-state must be 'with-cos' or 'no-cos', got '$COS'" >&2; exit 2
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# #13070 (D10-15): the shared incus wrapper replaces bare `incus exec`
# (same command shape, plus the sg fallback for operators outside
# incus-admin).
# shellcheck source=cos-apply-lib.sh
source "${SCRIPT_DIR}/cos-apply-lib.sh"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

FW="loss:xpf-userspace-fw0"

STEP1_OUTDIR="$REPO_ROOT/docs/pr/line-rate-investigation/step1-evidence/$COS/p${PORT}-${DIR}"
STEP2_OUTDIR="$REPO_ROOT/docs/pr/819-step2-discriminator-design/evidence/p${PORT}-${DIR}-${COS}/sched-switch"

log() { echo "[$(date +%H:%M:%S)] $*" >&2; }

# Pyshell review MED M1: clean up background children on SIGINT/SIGTERM.
# These PID holders are populated once we launch step1-capture.sh and
# `perf record` further down.  `exit 130` follows POSIX SIGINT convention.
STEP1_PID=""
PERF_PID=""
cleanup_on_signal() {
	if [[ -n "${STEP1_PID:-}" ]]; then
		kill "$STEP1_PID" 2>/dev/null || true
	fi
	if [[ -n "${PERF_PID:-}" ]]; then
		kill "$PERF_PID" 2>/dev/null || true
	fi
	# The host-side `incus exec` we backgrounded does NOT terminate the
	# remote `perf record` when we kill it; stop it explicitly inside
	# the guest.  pkill is a no-op if perf is already gone.
	incus_exec "$FW" pkill -TERM perf 2>/dev/null || true
	exit 130
}
trap cleanup_on_signal INT TERM

# -- G8 preflight -----------------------------------------------------------

g8_preflight() {
	local rc=0

	log "G8.1 check kernel.perf_event_paranoid on $FW"
	local paranoid
	paranoid=$(incus_exec "$FW" sysctl -n kernel.perf_event_paranoid 2>/dev/null || echo 999)
	if [[ "$paranoid" =~ ^-?[0-9]+$ ]] && [[ "$paranoid" -le 1 ]]; then
		log "  perf_event_paranoid=$paranoid (OK, <= 1)"
	else
		echo "G8.1 FAIL: perf_event_paranoid=$paranoid > 1 — run:" >&2
		echo "  incus exec $FW -- sysctl -w kernel.perf_event_paranoid=1" >&2
		rc=1
	fi

	log "G8.2 check tracepoint surface on $FW (each name grepped individually)"
	for tp in sched:sched_switch sched:sched_stat_runtime sched:sched_wakeup; do
		# Plan §5 pattern: `grep -qE '${tp//:/\s*:\s*}'` — tolerate
		# whitespace around the colon (some perf list outputs format
		# "sched : sched_switch" at column widths).  LOW-6 fix.
		local tp_re="${tp//:/\\s*:\\s*}"
		if incus_exec "$FW" bash -c "perf list '$tp' 2>/dev/null | grep -qE '$tp_re'"; then
			log "  tracepoint $tp present"
		else
			echo "G8.2 FAIL: $tp not found — bpftrace fallback NOT in #821 scope; HARD STOP" >&2
			rc=1
		fi
	done

	log "G8.3 perf record privilege smoke on $FW"
	# LOW-6: keep perf-record stderr visible so plan §5 "command 3 prints
	# perf stderr" is actually satisfied.  We pipe the subshell's combined
	# stdout+stderr through sed for indentation.  `perf record` itself is
	# run WITHOUT the blanket `>/dev/null 2>&1` redirection.
	if incus_exec "$FW" bash -c '
		set -e
		TID=$(ps -eLo tid,comm | awk "\$2==\"xpf-userspace-w\"{print \$1;exit}")
		if [ -z "$TID" ]; then
			echo "no xpf-userspace-w worker TID found on guest" >&2
			exit 1
		fi
		rm -f /tmp/smoke.data
		# Keep perf stderr visible; it is valuable context on failure.
		perf record -e sched:sched_switch -t "$TID" -o /tmp/smoke.data -- sleep 1
		test -s /tmp/smoke.data
	' 2>&1 | sed "s|^|  |"; then
		log "  perf record smoke OK"
	else
		echo "G8.3 FAIL: perf record smoke — dumping ps -eLo:" >&2
		incus_exec "$FW" ps -eLo tid,pid,comm 2>&1 | grep -E 'xpf-userspace' | sed 's|^|  |' >&2 || true
		rc=1
	fi

	log "G8.4 perf script parseability"
	if incus_exec "$FW" bash -c 'perf script -i /tmp/smoke.data 2>/dev/null | head -5 | grep -q sched_switch'; then
		log "  perf script parses sched_switch OK"
	else
		echo "G8.4 FAIL: perf script output did not contain sched_switch" >&2
		incus_exec "$FW" perf script -i /tmp/smoke.data 2>&1 | head -20 | sed 's|^|  |' >&2 || true
		rc=1
	fi

	return "$rc"
}

g8_preflight
if [[ "$SMOKE_ONLY" -eq 1 ]]; then
	log "--smoke-only: G8 preflight passed, exiting 0"
	exit 0
fi

# -- step 1: prepare STEP2 output dir ---------------------------------------

log "mkdir -p $STEP2_OUTDIR"
mkdir -p "$STEP2_OUTDIR"

# -- step 2: launch step1-capture.sh in background --------------------------

# HIGH-1: drop any stale rendezvous file so the poll below can ONLY
# succeed when the NEW run writes it.  Otherwise a leftover from a
# previous capture makes us attach `perf record -t` to stale TIDs.
rm -f "$STEP1_OUTDIR/worker-tids.txt"

log "launching step1-capture.sh $PORT $DIR $COS in background"
# STEP1_SKIP_PERF_STAT=1: step1's per-thread perf stat conflicts with
# our perf record on the same TIDs (exceeds per-task event limit,
# EINVAL). step1 handles this env var and emits an empty perf-stat.txt
# placeholder for downstream consumers.
STEP1_SKIP_PERF_STAT=1 "$SCRIPT_DIR/step1-capture.sh" "$PORT" "$DIR" "$COS" > "$STEP2_OUTDIR/step1-capture.log" 2>&1 &
STEP1_PID=$!
log "  step1-capture.sh PID=$STEP1_PID"

# -- step 3: rendezvous on worker-tids.txt ----------------------------------

log "waiting for $STEP1_OUTDIR/worker-tids.txt (timeout 60 s)"
RENDEZVOUS_DEADLINE=$(( $(date +%s) + 60 ))
WORKER_TIDS=""
while true; do
	if [[ -s "$STEP1_OUTDIR/worker-tids.txt" ]]; then
		WORKER_TIDS="$(tr -d '\n' < "$STEP1_OUTDIR/worker-tids.txt")"
		if [[ -n "$WORKER_TIDS" ]]; then
			break
		fi
	fi
	if [[ $(date +%s) -ge $RENDEZVOUS_DEADLINE ]]; then
		echo "ERROR: worker-tids.txt did not appear within 60 s" >&2
		echo "SUSPECT: rendezvous timeout" > "$STEP2_OUTDIR/verdict.txt"
		# Let step1-capture.sh finish its own bail.
		wait "$STEP1_PID" || true
		exit 1
	fi
	# Also bail early if step1 already failed.
	if ! kill -0 "$STEP1_PID" 2>/dev/null; then
		echo "ERROR: step1-capture.sh exited before worker-tids.txt appeared" >&2
		echo "SUSPECT: step1 early exit" > "$STEP2_OUTDIR/verdict.txt"
		wait "$STEP1_PID" || true
		exit 1
	fi
	sleep 0.5
done
log "  worker TIDs: $WORKER_TIDS"

# -- step 4: perf window centering ------------------------------------------

# Let step1's samplers fire the first (cold) snapshot before we start perf.
sleep 0.5
# #823: read timestamps from the GUEST, not the host. Host and guest
# clocks in the incus VM can drift tens of seconds apart (unsynced
# NTP). step1's sampler uses the guest's `date +%s`; we must match.
PERF_START_NS="$(incus_exec "$FW" date +%s%N)"
log "PERF_START_NS=$PERF_START_NS (guest clock)"

# -- step 5: perf record -----------------------------------------------------

log "spawning perf record on $FW (60 s)"
# HIGH-3 (Round-2 addendum): `-k CLOCK_REALTIME` was rejected on this
# kernel's perf with EINVAL ("Failure to open event... error 22").
# Fallback: use perf's default CLOCK_MONOTONIC and measure the
# mono→wall offset on the guest just before spawn. The offset is a
# rigorous one-shot clock conversion (same math NTP uses), NOT
# inferred from first-event latency. Reducer receives the offset
# via --mono-wall-offset-ns and applies it: t_wall = t_mono + offset.
MONO_WALL_OFFSET_NS="$(incus_exec "$FW" python3 -c \
	'import time; print(time.time_ns() - time.clock_gettime_ns(time.CLOCK_MONOTONIC))')"
log "MONO_WALL_OFFSET_NS=$MONO_WALL_OFFSET_NS"
incus_exec "$FW" bash -c "
	set -e
	rm -f /tmp/sched-switch.perf.data
	perf record \\
	    -e sched:sched_switch \\
	    -e sched:sched_stat_runtime \\
	    -e sched:sched_wakeup \\
	    -t '$WORKER_TIDS' \\
	    --call-graph=fp \\
	    -o /tmp/sched-switch.perf.data \\
	    -- sleep 60
" > "$STEP2_OUTDIR/perf-record.log" 2>&1 &
PERF_PID=$!
log "  perf record PID=$PERF_PID"

# -- step 6: wait for both ---------------------------------------------------

STEP1_RC=0
PERF_RC=0
wait "$STEP1_PID" || STEP1_RC=$?
wait "$PERF_PID"  || PERF_RC=$?

if [[ "$STEP1_RC" -ne 0 ]]; then
	echo "ERROR: step1-capture.sh exited rc=$STEP1_RC" >&2
	tail -n 20 "$STEP2_OUTDIR/step1-capture.log" >&2 || true
	echo "SUSPECT: step1 rc=$STEP1_RC" > "$STEP2_OUTDIR/verdict.txt"
	exit 1
fi
if [[ "$PERF_RC" -ne 0 ]]; then
	echo "ERROR: perf record exited rc=$PERF_RC" >&2
	tail -n 20 "$STEP2_OUTDIR/perf-record.log" >&2 || true
	echo "SUSPECT: perf rc=$PERF_RC" > "$STEP2_OUTDIR/verdict.txt"
	exit 1
fi

# Copy step1 artifacts into the step2 evidence tree for self-containment.
for f in worker-tids.txt flow_steer_cold.json flow_steer_samples.jsonl; do
	if [[ -f "$STEP1_OUTDIR/$f" ]]; then
		cp "$STEP1_OUTDIR/$f" "$STEP2_OUTDIR/$f"
	fi
done

# -- step 7: pull perf artifacts --------------------------------------------

log "pulling perf.data and rendering perf-script.txt"
incus file pull "$FW/tmp/sched-switch.perf.data" "$STEP2_OUTDIR/perf.data"
# `--ns` forces nanosecond-resolution timestamps so the reducer sees
# full precision (default `perf script` format keeps microseconds).
# Combined with `-k CLOCK_REALTIME` from perf-record, timestamps are
# absolute unix wall-clock ns.
incus_exec "$FW" perf script --ns -i /tmp/sched-switch.perf.data > "$STEP2_OUTDIR/perf-script.txt"

# -- step 8: step1 histogram classifier in single-cell scope ----------------

log "invoking step1-histogram-classify.py --only-cell $COS/p${PORT}-${DIR}"
python3 "$SCRIPT_DIR/step1-histogram-classify.py" \
	--evidence-root "$REPO_ROOT/docs/pr/line-rate-investigation/step1-evidence" \
	--only-cell "$COS/p${PORT}-${DIR}"

if [[ ! -s "$STEP1_OUTDIR/hist-blocks.jsonl" ]]; then
	echo "ERROR: hist-blocks.jsonl not produced at $STEP1_OUTDIR/hist-blocks.jsonl" >&2
	echo "SUSPECT: histogram classify" > "$STEP2_OUTDIR/verdict.txt"
	exit 1
fi

# -- step 9: reducer ---------------------------------------------------------

log "running step2 reducer"
# HIGH-2: reducer returns exit 5 on drift halt (still emits JSONL with
# suspect_reason sentinel for forensics).  Accept exit 0 (normal) and
# exit 5 (drift halt, intentional); any other non-zero is a real error.
REDUCER_RC=0
python3 "$SCRIPT_DIR/step2-sched-switch-reduce.py" \
	--perf-script "$STEP2_OUTDIR/perf-script.txt" \
	--step1-cold "$STEP1_OUTDIR/flow_steer_cold.json" \
	--step1-samples "$STEP1_OUTDIR/flow_steer_samples.jsonl" \
	--worker-tids "$WORKER_TIDS" \
	--perf-start-ns "$PERF_START_NS" \
	--mono-wall-offset-ns "$MONO_WALL_OFFSET_NS" \
	> "$STEP2_OUTDIR/off-cpu-hist-by-block.jsonl" || REDUCER_RC=$?
if [[ "$REDUCER_RC" -eq 5 ]]; then
	log "reducer reported drift halt (rc=5); classifier will emit SUSPECT"
elif [[ "$REDUCER_RC" -ne 0 ]]; then
	echo "ERROR: reducer exited rc=$REDUCER_RC" >&2
	echo "SUSPECT: reducer rc=$REDUCER_RC" > "$STEP2_OUTDIR/verdict.txt"
	exit 1
fi

# -- step 10: classifier -----------------------------------------------------

log "running step2 classifier"
python3 "$SCRIPT_DIR/step2-sched-switch-classify.py" \
	--hist-blocks "$STEP1_OUTDIR/hist-blocks.jsonl" \
	--off-cpu "$STEP2_OUTDIR/off-cpu-hist-by-block.jsonl" \
	--cell "p${PORT}-${DIR}-${COS}" \
	--out "$STEP2_OUTDIR/correlation-report.md"

# -- step 11: summary log line ----------------------------------------------

VERDICT="UNKNOWN"
SUSPECT_REASON=""
if [[ -s "$STEP2_OUTDIR/correlation-report.meta.json" ]]; then
	# Extract verdict + optional suspect_reason without a python dep.
	VERDICT=$(jq -r '.verdict // "UNKNOWN"' "$STEP2_OUTDIR/correlation-report.meta.json" 2>/dev/null || echo UNKNOWN)
	SUSPECT_REASON=$(jq -r '.suspect_reason // empty' "$STEP2_OUTDIR/correlation-report.meta.json" 2>/dev/null || echo "")
fi
# HIGH-2: surface SUSPECT in the summary so operators and CI notice
# capture-invalid runs without opening the meta.json.
if [[ -n "$SUSPECT_REASON" ]]; then
	echo "[$(date +%H:%M:%S)] step2-sched-switch COMPLETE cell=p${PORT}-${DIR}-${COS} outdir=$STEP2_OUTDIR verdict=$VERDICT suspect_reason=$SUSPECT_REASON"
else
	echo "[$(date +%H:%M:%S)] step2-sched-switch COMPLETE cell=p${PORT}-${DIR}-${COS} outdir=$STEP2_OUTDIR verdict=$VERDICT"
fi
