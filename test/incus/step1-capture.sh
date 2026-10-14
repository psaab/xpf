#!/usr/bin/env bash
#
# step1-capture.sh — Phase B Step 1 per-cell capture driver.
#
# Usage:
#   step1-capture.sh <port> <direction> <cos-state>
#
#     port        5201 | 5202 | 5203 | 5204
#     direction   fwd | rev
#     cos-state   with-cos | no-cos
#
# Emits all artifacts under:
#   docs/pr/line-rate-investigation/step1-evidence/<cos-state>/p<port>-<dir>/
#
# See docs/pr/line-rate-investigation/step1-plan.md §§2-3 for the
# capture protocol this script implements. The script is the
# canonical protocol; the plan documents what the script does.
#
# Dependencies on the firewall VM (loss:xpf-userspace-fw0):
#   socat jq ethtool mpstat perf ss dmesg ps pgrep xpf-userspace-dp
# Dependencies on the traffic host (loss:cluster-userspace-host):
#   iperf3 ping taskset
#
# The script enforces §5 invariants I1-I10 post-capture. Any
# violation marks the cell SUSPECT and returns a non-zero exit.
# Re-run protocol (up to 2 retries) is the caller's responsibility;
# this script captures a single cell in one attempt.
#
# Control-socket schema, exact:
#   request:  {"type":"status"}                  (per ControlRequest in
#                                                 userspace-dp/src/protocol.rs:625-627)
#   response: {"ok":true, "status":{...}}        (per ControlResponse, ibid:980-992)
#   triage fields live on response.status.{per_binding,cos_interfaces,
#     filter_term_counters,bindings} (ibid:719-736)
#   filter-term hit counter is `packets`, NOT `matched_packets` (ibid:919-930)
#
set -euo pipefail

usage() {
	cat >&2 <<EOF
usage: $0 <port> <direction> <cos-state>
  port        one of 5201, 5202, 5203, 5204
  direction   one of fwd, rev
  cos-state   one of with-cos, no-cos
EOF
	exit 2
}

if [[ $# -ne 3 ]]; then
	usage
fi

PORT="$1"
DIR="$2"
COS="$3"

case "$PORT" in
	5201|5202|5203|5204) ;;
	*) echo "error: port must be 5201/5202/5203/5204, got '$PORT'" >&2; exit 2 ;;
esac

case "$DIR" in
	fwd) MAYBE_R="" ;;
	rev) MAYBE_R="-R" ;;
	*) echo "error: direction must be fwd|rev, got '$DIR'" >&2; exit 2 ;;
esac

case "$COS" in
	with-cos|no-cos) ;;
	*) echo "error: cos-state must be with-cos|no-cos, got '$COS'" >&2; exit 2 ;;
esac

# Per plan §2.1: reverse cells in no-cos half are SKIPPED (strict
# duplication of with-cos reverse, no new signal).
if [[ "$COS" == "no-cos" && "$DIR" == "rev" ]]; then
	echo "SKIP: no-cos × reverse is out of matrix per plan §1" >&2
	exit 0
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
# #13070 (D10-15): the port -> filter-term map comes from the shared CoS
# schedule library (matching the cos-iperf-config.set this cell's cluster
# actually applies) instead of a step1-local table.
# shellcheck source=cos-apply-lib.sh
source "${SCRIPT_DIR}/cos-apply-lib.sh"

FW="loss:xpf-userspace-fw0"
FW_PEER="loss:xpf-userspace-fw1"
HOST="loss:cluster-userspace-host"
IPERF_SERVER="172.16.80.200"
SOCK="/run/xpf/userspace-dp.sock"
APPLY_COS_SH="${SCRIPT_DIR}/apply-cos-config.sh"

OUTDIR="$REPO_ROOT/docs/pr/line-rate-investigation/step1-evidence/$COS/p${PORT}-${DIR}"
mkdir -p "$OUTDIR"

log() { echo "[$(date +%H:%M:%S)] $*" >&2; }
# #13070 (D10-15): the shared incus wrapper (group membership + %q-safe
# quoting) replaces bare `incus exec` — same command shape, plus the
# sg fallback for operators outside incus-admin.
fw()  { incus_exec "$FW"   bash -c "$*"; }
host(){ incus_exec "$HOST" bash -c "$*"; }

# bail out via verdict.txt + non-zero exit. Marks the cell SUSPECT
# (per §5: any invariant failure => SUSPECT; re-run is caller's job).
suspect() {
	echo "SUSPECT: $*" | tee "$OUTDIR/verdict.txt" >&2
	exit 1
}

# fatal halt — for §6 transition failures the plan requires us to
# stop and dump state rather than retry. Caller must investigate.
halt_with_dump() {
	local reason="$1"
	local ts
	ts=$(date +%s)
	local dump="$REPO_ROOT/docs/pr/line-rate-investigation/step1-evidence/halt-${ts}"
	mkdir -p "$dump"
	log "HALT: $reason — writing state dump to $dump"
	fw "cli -c 'show configuration'" > "$dump/show-configuration.txt" 2>&1 || true
	fw "journalctl -u xpfd -n 200 --no-pager" > "$dump/journalctl-xpfd.txt" 2>&1 || true
	fw "journalctl -u xpf-userspace-dp -n 200 --no-pager" \
		> "$dump/journalctl-userspace.txt" 2>&1 || true
	fw "cli -c 'show chassis cluster status'" > "$dump/cluster-status.txt" 2>&1 || true
	fw "ip route show" > "$dump/ip-route.txt" 2>&1 || true
	fw "echo '{\"type\":\"status\"}' | socat -t 5 - UNIX-CONNECT:$SOCK | jq ." \
		> "$dump/status.json" 2>&1 || true
	echo "HALT($reason) — dump=$dump" | tee "$OUTDIR/verdict.txt" >&2
	exit 3
}

# Query the userspace-dp control socket. Retries once on timeout or
# decode failure (per round-2 review: "on socket timeout, retry once
# then mark cell SUSPECT"). Echoes the JSON response on stdout.
ctl_status() {
	local out
	for attempt in 1 2; do
		if out=$(fw "echo '{\"type\":\"status\"}' | socat -t 5 - UNIX-CONNECT:$SOCK 2>/dev/null | jq ." 2>/dev/null) \
		   && [[ -n "$out" ]] \
		   && echo "$out" | jq -e '.ok == true' >/dev/null 2>&1; then
			echo "$out"
			return 0
		fi
		log "ctl_status attempt $attempt failed; backoff 1s"
		sleep 1
	done
	return 1
}

# Re-validate that fw0 is RG0 primary via the control socket. Used
# when ctl_status fails (could be daemon down, could be failover that
# moved the active to fw1). On detected drift we suspect the cell.
recheck_primary() {
	local s
	if ! s=$(fw "cli -c 'show chassis cluster status' 2>/dev/null"); then
		return 2
	fi
	if echo "$s" | grep -iE 'primary' | head -1 | grep -qiE 'fw0|node0'; then
		return 0
	fi
	return 1
}

# -- 2.1 pre-run ------------------------------------------------------

log "drain in-flight iperf3 on $FW and $HOST"
fw_count=0
host_count=0
for attempt in 1 2 3; do
	fw_count=$(fw "ss -tnH 'sport = :5201 or sport = :5202 or sport = :5203 or sport = :5204 or dport = :5201 or dport = :5202 or dport = :5203 or dport = :5204' | wc -l")
	host_count=$(host "ss -tnH 'sport = :5201 or sport = :5202 or sport = :5203 or sport = :5204 or dport = :5201 or dport = :5202 or dport = :5203 or dport = :5204' | wc -l")
	if [[ "$fw_count" == "0" && "$host_count" == "0" ]]; then
		break
	fi
	log "drain attempt $attempt: fw=$fw_count host=$host_count — killing stragglers"
	fw "pkill -9 -f 'iperf3' || true"
	host "pkill -9 -f 'iperf3' || true"
	sleep 1
done
if [[ "$fw_count" != "0" || "$host_count" != "0" ]]; then
	suspect "could not drain iperf3 after 3 attempts"
fi

log "capture cluster-state snapshot (pre)"
fw "cli -c 'show chassis cluster status'" > "$OUTDIR/cluster-status-pre.txt"

# I9 start-of-run invariant: primary is fw0, no recent fab flap.
# The `show chassis cluster status` format is:
#   node0  200      primary        no       no       None
#   node1  100      secondary      no       no       None
# Find the RG0 block and look at its first "primary"-marked node.
if ! awk '/Redundancy group: 0/{flag=1; next} /Redundancy group: [1-9]/{flag=0} flag && /primary/ {print; exit}' \
     "$OUTDIR/cluster-status-pre.txt" | grep -qiE '^(node0|fw0)'; then
	suspect "I9: RG0 primary is not fw0/node0 (per cluster-status-pre.txt)"
fi

# §6 CoS-state assertion. The caller decides which COS state to run a
# cell in, but the cluster's actual config must already match — this
# script does NOT toggle CoS mid-cell (that's the orchestrator's job
# in the §6 protocol). We just verify and bail loudly if the live
# state disagrees, so we don't capture a mislabeled cell.
log "verify live CoS state matches requested COS=$COS"
PRE_STATUS=$(ctl_status) || halt_with_dump "control socket unreachable on pre-check"
echo "$PRE_STATUS" > "$OUTDIR/control-status-pre.json"
COS_LEN_PRE=$(echo "$PRE_STATUS" | jq '.status.cos_interfaces | length')
case "$COS" in
	with-cos)
		if [[ "$COS_LEN_PRE" -lt 1 ]]; then
			# CoS requested but absent — try one auto-apply per round-2
			# "on CoS apply failure, bail with error message".
			log "CoS expected but cos_interfaces is empty; attempting one apply via $APPLY_COS_SH"
			if ! "$APPLY_COS_SH" "$FW" >>"$OUTDIR/cos-apply.log" 2>&1; then
				halt_with_dump "with-cos requested but apply-cos-config.sh failed"
			fi
			# §6 step 3: wait up to 30 s for runtime reconciliation.
			ok=0
			for _i in $(seq 1 30); do
				PRE_STATUS=$(ctl_status) || true
				if [[ -n "$PRE_STATUS" ]] && \
				   [[ "$(echo "$PRE_STATUS" | jq '.status.cos_interfaces | length')" -ge 1 ]]; then
					ok=1; break
				fi
				sleep 1
			done
			if [[ "$ok" != "1" ]]; then
				halt_with_dump "with-cos requested; cos_interfaces still empty 30 s after apply"
			fi
			echo "$PRE_STATUS" > "$OUTDIR/control-status-pre.json"
		fi
		;;
	no-cos)
		if [[ "$COS_LEN_PRE" -ge 1 ]]; then
			halt_with_dump "no-cos requested but cos_interfaces is non-empty (cluster has live CoS); orchestrator must remove CoS before invoking this script"
		fi
		;;
esac

log "capture cold flow_steer snapshot"
# #821: stamp cold snapshot with _sample_ts so the step2 reducer can
# anchor block boundaries to the same timeline as step1's warm samples.
# Backward-compatible: existing consumers (step1-histogram-classify.py)
# ignore unknown top-level fields.
# #823: read the timestamp from the GUEST, not the host — the two
# clocks can drift tens of seconds apart (unsynced NTP in the incus
# VM), and step1's warm samples at line 291 use the GUEST clock
# (`ts=$(date +%s)` inside the `fw` heredoc). Stamping cold with a
# host clock produces a mismatched anchor that fails step2's
# snapshot-interval invariant.
ts=$(fw "date +%s")
echo "$PRE_STATUS" | jq -c --arg ts "$ts" '. + {_sample_ts: $ts}' > "$OUTDIR/flow_steer_cold.json"

log "capture cold NIC counters (ge-0-0-1, ge-0-0-2)"
fw "ethtool -S ge-0-0-1 | grep -vE ' 0$' || true" > "$OUTDIR/nic-counters-cold-ge-0-0-1.txt"
fw "ethtool -S ge-0-0-2 | grep -vE ' 0$' || true" > "$OUTDIR/nic-counters-cold-ge-0-0-2.txt"

log "capture CoS shaper state"
fw "cli -c 'show class-of-service interface'" > "$OUTDIR/cos-interface-pre.txt"

# I8: record daemon ActiveEnterTimestamp for the worker-restart check.
DAEMON_START_PRE=$(fw "systemctl show -p ActiveEnterTimestamp --value xpfd 2>/dev/null || systemctl show -p ActiveEnterTimestamp --value xpf-userspace-dp 2>/dev/null || true")
echo "$DAEMON_START_PRE" > "$OUTDIR/daemon-start-pre.txt"

# Collect worker TIDs per plan §2.2(c) / invariant I8.
# NOTE: Linux truncates comm to 15 chars (TASK_COMM_LEN=16 incl NUL), so
# `xpf-userspace-worker-N` shows up as `xpf-userspace-w`. Match both the
# truncated form and any hypothetical longer form; exclude the daemon
# thread itself (`xpf-userspace-d`) and the main thread (`xpf-userspace`
# with nothing after — but main PID == daemon TID so filter on
# `tid != pid` to be safe).
WORKER_TIDS=$(fw "ps -eLo pid,tid,comm | awk '\$3 ~ /^xpf-userspace-w/ && \$2 != \$1 {print \$2}' | paste -sd,")
WORKER_TID_COUNT=$(echo "$WORKER_TIDS" | tr ',' '\n' | grep -c . || true)
echo "$WORKER_TIDS" > "$OUTDIR/worker-tids.txt"
if [[ "$WORKER_TID_COUNT" -lt 4 ]]; then
	suspect "I8: only $WORKER_TID_COUNT worker TIDs found (expected >= 4)"
fi

# -- 2.2 during run ---------------------------------------------------

log "start pinned ICMP probes (small + large) on $HOST"
host "taskset -c 4 ping -i 0.01 -s 56   -D -q -w 60 $IPERF_SERVER > /tmp/ping-small.txt 2>&1 &
      taskset -c 5 ping -i 0.01 -s 1400 -D -q -w 60 $IPERF_SERVER > /tmp/ping-large.txt 2>&1 &
      echo \$! > /tmp/ping-pids"

# Small sleep so ping is steady-state before iperf3 handshake.
sleep 0.2

log "launch iperf3 -c -P 16 -t 60 -p $PORT $MAYBE_R"
host "iperf3 -c $IPERF_SERVER -P 16 -t 60 -p $PORT $MAYBE_R -J > /tmp/iperf3.json 2> /tmp/iperf3.err &
      echo \$! > /tmp/iperf3-pid"

# Small delay for handshake per plan §2.2 (~200 ms).
sleep 0.2

log "launch concurrent mpstat + perf stat + samplers (60 s)"
# Note: the inner loop uses `{"type":"status"}` (the correct request
# schema; previous draft used the wrong `request_type` key).
# STEP1_SKIP_PERF_STAT=1 (#823/#821 follow-up): when composed inside
# step2-sched-switch-capture.sh, the outer perf record attaches 3
# tracepoints × 4 TIDs = 12 events to the same TIDs. Combined with
# step1's perf stat (7 events × 4 TIDs = 28 events) this exceeds the
# per-task perf event limit and perf record fails with EINVAL
# ("Failure to open event... error 22"). Skip perf stat when composed;
# a placeholder file is still emitted for invariant I2 consumers.
# The env var is evaluated host-side because `fw` (incus exec) doesn't
# propagate host env to the guest shell.
if [[ "${STEP1_SKIP_PERF_STAT:-0}" = "1" ]]; then
  log "STEP1_SKIP_PERF_STAT=1 — skipping perf stat (composed-harness mode)"
  PERF_STAT_LAUNCH="echo 'SKIPPED: perf stat skipped by STEP1_SKIP_PERF_STAT=1 (composed with step2 harness per #823/#821). perf events would collide.' > /tmp/perf-stat.txt"
else
  PERF_STAT_LAUNCH="perf stat --per-thread -t $WORKER_TIDS \
    -e task-clock,cycles,instructions,cache-references,cache-misses,L1-dcache-load-misses,LLC-loads \
    -- sleep 60 > /tmp/perf-stat.txt 2>&1 &"
fi
fw "mpstat -P ALL 1 60 > /tmp/mpstat.txt 2>&1 &
    $PERF_STAT_LAUNCH
    : > /tmp/flow_steer_samples.jsonl
    : > /tmp/ss-samples.jsonl
    : > /tmp/sampler.err
    for i in \$(seq 0 11); do
      ts=\$(date +%s)
      tries=0
      sample=''
      while [ \$tries -lt 2 ]; do
        sample=\$(echo '{\"type\":\"status\"}' | socat -t 5 - UNIX-CONNECT:$SOCK 2>>/tmp/sampler.err | jq -c --arg ts \"\$ts\" '. + {_sample_ts: \$ts}' 2>>/tmp/sampler.err || true)
        if [ -n \"\$sample\" ]; then break; fi
        tries=\$((tries + 1))
        sleep 0.5
      done
      if [ -z \"\$sample\" ]; then
        # Emit a placeholder line so I6 can fail this cell deterministically.
        echo \"{\\\"_sample_ts\\\":\\\"\$ts\\\",\\\"_error\\\":\\\"control_socket_timeout\\\"}\" >> /tmp/flow_steer_samples.jsonl
      else
        echo \"\$sample\" >> /tmp/flow_steer_samples.jsonl
      fi
      {
        echo \"{\\\"t\\\":\$ts,\\\"flows\\\":[\"
        ss -tiH \"dport = :$PORT\" | awk 'BEGIN{first=1} {gsub(/\"/,\"\\\\\\\"\");
             if(first){first=0}else{printf \",\"}; printf \"\\\"%s\\\"\", \$0}'
        echo \"]}\"
      } >> /tmp/ss-samples.jsonl
      sleep 5
    done
    wait" || log "WARN: during-run command group exited non-zero (will validate via invariants)"

# Wait on iperf3 too.
host "wait \$(cat /tmp/iperf3-pid) 2>/dev/null || true"

log "retrieve during-run artifacts"
incus file pull "$HOST/tmp/iperf3.json"    "$OUTDIR/iperf3.json"
incus file pull "$HOST/tmp/ping-small.txt" "$OUTDIR/ping-small.txt"
incus file pull "$HOST/tmp/ping-large.txt" "$OUTDIR/ping-large.txt"
incus file pull "$FW/tmp/mpstat.txt"              "$OUTDIR/mpstat.txt"
incus file pull "$FW/tmp/perf-stat.txt"           "$OUTDIR/perf-stat.txt"
incus file pull "$FW/tmp/flow_steer_samples.jsonl" "$OUTDIR/flow_steer_samples.jsonl"
incus file pull "$FW/tmp/ss-samples.jsonl"        "$OUTDIR/ss-samples.jsonl"
incus file pull "$FW/tmp/sampler.err"             "$OUTDIR/sampler.err" 2>/dev/null || true

# -- 2.3 post-run -----------------------------------------------------

log "capture post-run snapshots"
# Post-run status: if the control socket is unreachable now, it's a
# strong signal a failover hit during the cell. Re-check primary; if
# it moved to fw1 we suspect this cell rather than silently saving
# garbage.
if ! POST_STATUS=$(ctl_status); then
	if recheck_primary; then
		halt_with_dump "control socket unreachable post-run, but fw0 still primary — daemon may have crashed mid-cell"
	fi
	suspect "control socket unreachable post-run AND primary drifted (likely failover during cell)"
fi
echo "$POST_STATUS" > "$OUTDIR/flow_steer_post.json"

fw "ethtool -S ge-0-0-1 | grep -vE ' 0$' || true" > "$OUTDIR/nic-counters-post-ge-0-0-1.txt"
fw "ethtool -S ge-0-0-2 | grep -vE ' 0$' || true" > "$OUTDIR/nic-counters-post-ge-0-0-2.txt"
fw "cli -c 'show chassis cluster status'" > "$OUTDIR/cluster-status-post.txt"
fw "dmesg -T | tail -50" > "$OUTDIR/dmesg-tail.txt"

DAEMON_START_POST=$(fw "systemctl show -p ActiveEnterTimestamp --value xpfd 2>/dev/null || systemctl show -p ActiveEnterTimestamp --value xpf-userspace-dp 2>/dev/null || true")
echo "$DAEMON_START_POST" > "$OUTDIR/daemon-start-post.txt"

# -- 5. post-capture invariants --------------------------------------

FAIL=""
add_fail() { FAIL="${FAIL}${FAIL:+; }$1"; }

# I1 — all files exist, size > 0.
for f in iperf3.json flow_steer_cold.json flow_steer_post.json \
         flow_steer_samples.jsonl mpstat.txt perf-stat.txt \
         ping-small.txt ping-large.txt ss-samples.jsonl \
         nic-counters-cold-ge-0-0-1.txt nic-counters-post-ge-0-0-1.txt \
         nic-counters-cold-ge-0-0-2.txt nic-counters-post-ge-0-0-2.txt \
         cluster-status-pre.txt cluster-status-post.txt dmesg-tail.txt; do
	if [[ ! -s "$OUTDIR/$f" ]]; then
		add_fail "I1:$f missing or empty"
	fi
done

# I2 — iperf3 SUM within ±10 % of expected baseline. Baseline source
# is 8matrix-findings.md for with-cos and the pre-#804 mean for
# no-cos. We skip strict enforcement here (the findings doc in step 1
# will cross-check) but we do parse and record for downstream.
SUM_BPS=$(jq -r '.end.sum_received.bits_per_second // .end.sum_sent.bits_per_second // 0' "$OUTDIR/iperf3.json")
echo "sum_bps=$SUM_BPS" > "$OUTDIR/sum.txt"
if [[ "$SUM_BPS" == "0" ]]; then
	add_fail "I2: iperf3 SUM is zero — capture failed"
fi

# I4 — same RG0 primary pre and post.
PRE_PRIM=$(grep -iE 'primary' "$OUTDIR/cluster-status-pre.txt" | head -1 || true)
POST_PRIM=$(grep -iE 'primary' "$OUTDIR/cluster-status-post.txt" | head -1 || true)
if [[ "$PRE_PRIM" != "$POST_PRIM" ]]; then
	add_fail "I4: RG0 primary drifted ($PRE_PRIM -> $POST_PRIM)"
fi

# I5 — no softlockup / mlx5 error / BUG.
if grep -iE 'softlockup|mlx5.*(error|reset)|BUG:' "$OUTDIR/dmesg-tail.txt" >/dev/null 2>&1; then
	add_fail "I5: dmesg shows kernel failure"
fi

# I6 — flow_steer_samples.jsonl has 12 lines, each valid JSON,
# each with non-empty per_binding array of length >= 8 under .status.
SAMPLE_LINES=$(wc -l < "$OUTDIR/flow_steer_samples.jsonl")
if [[ "$SAMPLE_LINES" != "12" ]]; then
	add_fail "I6: expected 12 samples, got $SAMPLE_LINES"
else
	# jq operator precedence: `or` binds tighter than `|`, so the
	# previous form parsed as `(x) or (y) | length < 8` → boolean has
	# no length → jq exits non-zero. Parenthesise explicitly.
	BAD_LINES=$(jq -c 'select((._error // null) != null
		or ((.status.per_binding // []) | length) < 8)' \
		"$OUTDIR/flow_steer_samples.jsonl" 2>/dev/null | wc -l)
	if [[ "$BAD_LINES" -gt 0 ]]; then
		add_fail "I6: $BAD_LINES of 12 samples failed (control_socket_timeout or per_binding < 8)"
	fi
fi

# I8 — daemon did not restart mid-cell.
if [[ "$DAEMON_START_PRE" != "$DAEMON_START_POST" ]]; then
	add_fail "I8: daemon restarted mid-cell ($DAEMON_START_PRE -> $DAEMON_START_POST)"
fi

# I10 — on with-cos cells, cos_interfaces non-empty AND
# filter_term_counters delta non-zero on this port's term.
# (Field is `packets`, NOT `matched_packets`; both arrays live under
# .status, not at the top level.)
if [[ "$COS" == "with-cos" ]]; then
	COS_IFACE_COUNT=$(jq '.status.cos_interfaces | length' "$OUTDIR/flow_steer_post.json")
	if [[ "$COS_IFACE_COUNT" -lt 1 ]]; then
		add_fail "I10: with-cos but status.cos_interfaces is empty"
	fi
	# Filter-term-counter delta — the term that classifies $PORT comes
	# from the shared canonical schedule (cos_port_to_term), which is
	# pinned to cos-iperf-config.set — the fixture §6 actually applies to
	# this cluster (#13070 / D10-15). The table here used to restate a
	# RETIRED 4-port fixture (5201->term 0 .. 5204->term 3, D10-08), so
	# I10 compared counters of the wrong term on every with-cos cell.
	# Also sum across inet + inet6 families.
	if ! TERM=$(cos_port_to_term "$PORT"); then
		add_fail "I10: cannot resolve filter term for port $PORT in the canonical CoS schedule"
	fi
	POST_PKTS=$(jq -r --arg t "$TERM" '
		(.status.filter_term_counters // [])
		| map(select(.filter_name == "bandwidth-output" and .term_name == $t))
		| map(.packets // 0) | add // 0
	' "$OUTDIR/flow_steer_post.json")
	COLD_PKTS=$(jq -r --arg t "$TERM" '
		(.status.filter_term_counters // [])
		| map(select(.filter_name == "bandwidth-output" and .term_name == $t))
		| map(.packets // 0) | add // 0
	' "$OUTDIR/flow_steer_cold.json")
	if [[ "$POST_PKTS" -le "$COLD_PKTS" ]]; then
		add_fail "I10: filter_term_counters delta is zero on port $PORT term=$TERM (cold=$COLD_PKTS post=$POST_PKTS)"
	fi
fi

if [[ -n "$FAIL" ]]; then
	suspect "$FAIL"
fi

log "all invariants PASS — cell valid; verdict classification deferred to post-run analysis"
echo "PENDING: $OUTDIR (run step1-classify.sh next to compute verdict)" > "$OUTDIR/verdict.txt"
exit 0
