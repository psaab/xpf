#!/usr/bin/env bash
# #10023: non-mutating fine-grained cut recorder.
#
# The script only starts temporary recorders in /tmp on the loss cluster and
# pulls their output back. It does not deploy binaries, change configuration,
# move an RG, or stop xpfd. To observe a cut, run it under the #1875 lock in
# one cell and invoke the cut driver from the same cell or a coordinated
# second terminal; the journal/tcpdump/ss files share one run directory.
set -euo pipefail

REMOTE="${XPF_INCUS_REMOTE:-loss}"
FW0_VM="${XPF_FW0_VM:-xpf-userspace-fw0}"
FW1_VM="${XPF_FW1_VM:-xpf-userspace-fw1}"
HOST_VM="${XPF_LAN_HOST_VM:-cluster-userspace-host}"
TARGET="${XPF_IPERF_TARGET:-172.16.80.200}"
DURATION=60
INTERVAL=0.1
PARALLEL=4
BITRATE_PER_STREAM="${XPF_IPERF_BITRATE:-25M}"
TCPDUMP_COUNT="${XPF_TCPDUMP_COUNT:-0}"
ARTIFACT_DIR=""

usage() {
	cat >&2 <<'EOF'
Usage: cut_stall_sampler.sh [options]

Starts an iperf3 -P4 -J --json-stream recorder at 100ms, a
100ms timestamped ping, client ss -tin snapshots, and journal/tcpdump
recorders on both loss firewalls. It never deploys or changes cluster state.

  --duration SEC       iperf duration (default: 60)
  --interval SEC       sample interval, must be < 0.2 (default: 0.1)
  --parallel N         iperf parallel streams (default: 4)
  --bitrate RATE       per-stream TCP pacing (default: 25M; ~100M SUM)
  --tcpdump-count N    optional max packets per firewall pcap (default: 0 = time-bound)
  --target IPV4        target (default: 172.16.80.200)
  --out DIR            local artifact directory
  --help               show this help
EOF
	exit 2
}

while [[ $# -gt 0 ]]; do
	case "$1" in
	--duration) [[ $# -ge 2 ]] || usage; DURATION="$2"; shift ;;
	--interval) [[ $# -ge 2 ]] || usage; INTERVAL="$2"; shift ;;
	--parallel) [[ $# -ge 2 ]] || usage; PARALLEL="$2"; shift ;;
	--bitrate) [[ $# -ge 2 ]] || usage; BITRATE_PER_STREAM="$2"; shift ;;
	--tcpdump-count) [[ $# -ge 2 ]] || usage; TCPDUMP_COUNT="$2"; shift ;;
	--target) [[ $# -ge 2 ]] || usage; TARGET="$2"; shift ;;
	--out) [[ $# -ge 2 ]] || usage; ARTIFACT_DIR="$2"; shift ;;
	--help|-h) usage ;;
	*) echo "unknown option: $1" >&2; usage ;;
	esac
	shift
done
[[ -n "$BITRATE_PER_STREAM" ]] || { echo "bitrate must not be empty" >&2; exit 2; }
[[ "$TCPDUMP_COUNT" =~ ^[0-9]+$ ]] || { echo "tcpdump-count must be zero or a positive integer" >&2; exit 2; }

[[ "$DURATION" =~ ^[1-9][0-9]*$ ]] || { echo "duration must be a positive integer" >&2; exit 2; }
[[ "$PARALLEL" =~ ^[1-9][0-9]*$ ]] || { echo "parallel must be a positive integer" >&2; exit 2; }
[[ "$INTERVAL" =~ ^0?\.[0-9]+$ ]] || { echo "interval must be decimal seconds, e.g. 0.1" >&2; exit 2; }
awk -v interval="$INTERVAL" 'BEGIN { exit !(interval > 0 && interval < 0.2) }' \
	|| { echo "interval must be >0 and <0.2 seconds" >&2; exit 2; }

command -v sg >/dev/null || { echo "missing sg" >&2; exit 2; }
command -v incus >/dev/null || { echo "missing incus" >&2; exit 2; }
command -v timeout >/dev/null || { echo "missing timeout" >&2; exit 2; }

if [[ -z "$ARTIFACT_DIR" ]]; then
	ARTIFACT_DIR="/tmp/cut-stall-10023-$(date -u +%Y%m%dT%H%M%SZ)-$$-$RANDOM"
fi
if [[ "$ARTIFACT_DIR" == "/" || -z "$(basename -- "$ARTIFACT_DIR")" ]]; then
	echo "--out must name a directory below root" >&2
	exit 2
fi
if [[ -e "$ARTIFACT_DIR" && ! -d "$ARTIFACT_DIR" ]]; then
	echo "--out must be a directory" >&2
	exit 2
fi
mkdir -p -- "$ARTIFACT_DIR"
ARTIFACT_DIR="$(cd -- "$ARTIFACT_DIR" && pwd -P)"
[[ "$ARTIFACT_DIR" != "/" ]] || { echo "--out must not resolve to /" >&2; exit 2; }

TCPDUMP_LIMIT=""
if (( TCPDUMP_COUNT > 0 )); then
	TCPDUMP_LIMIT="-c $TCPDUMP_COUNT"
fi

# The remote name is independent of --out's basename.  It is unique even for
# same-second concurrent invocations and is never reused after an abort.
RUN_ID="cut-stall-10023-$(date -u +%Y%m%dT%H%M%SZ)-$$-$RANDOM-$RANDOM"
REMOTE_ROOT="/tmp/$RUN_ID"
REMOTE_PREFIX="${REMOTE}:"
FW0="${REMOTE_PREFIX}${FW0_VM}"
FW1="${REMOTE_PREFIX}${FW1_VM}"
HOST="${REMOTE_PREFIX}${HOST_VM}"

q() { printf '%q' "$1"; }
run_vm() {
	local vm="$1"
	shift
	sg incus-admin -c "incus exec ${vm} -- bash -lc $(printf %q "$*")"
}
pull_vm_file() {
	local vm="$1" remote_file="$2" local_file="$3"
	mkdir -p -- "$(dirname -- "$local_file")"
	# vm already includes the Incus remote (loss:instance); Incus file paths
	# use the instance/path form, not a second colon.
	sg incus-admin -c "incus file pull ${vm}${remote_file} $(printf %q "$local_file")"
}

REMOTE_PREPARED_HOST=0
REMOTE_PREPARED_FW0=0
REMOTE_PREPARED_FW1=0
remote_prepare() {
	local vm="$1"
	# Refuse an existing path.  This avoids deleting another invocation's
	# records and establishes ownership only after mkdir succeeds.
	run_vm "$vm" "if [[ -e $(q "$REMOTE_ROOT") ]]; then echo 'remote run directory exists; refusing collision' >&2; exit 2; fi; mkdir -- $(q "$REMOTE_ROOT")"
	case "$vm" in
	"$HOST") REMOTE_PREPARED_HOST=1 ;;
	"$FW0") REMOTE_PREPARED_FW0=1 ;;
	"$FW1") REMOTE_PREPARED_FW1=1 ;;
	esac
}

# Temporary paths are per-run and the cleanup trap only targets our recorded
# PIDs.  It never removes a path or kills a process selected by a broad name.
iperf_pid="$REMOTE_ROOT/iperf.pid"
iperf_status="$REMOTE_ROOT/iperf.status"
ping_pid="$REMOTE_ROOT/ping.pid"
ping_status="$REMOTE_ROOT/ping.status"
ss_pid="$REMOTE_ROOT/ss.pid"
ss_status="$REMOTE_ROOT/ss.status"
client_tcpdump_pid="$REMOTE_ROOT/client-tcpdump.pid"
client_tcpdump_status="$REMOTE_ROOT/client-tcpdump.status"
fw0_tcpdump_pid="$REMOTE_ROOT/fw0-tcpdump.pid"
fw0_tcpdump_status="$REMOTE_ROOT/fw0-tcpdump.status"
fw1_tcpdump_pid="$REMOTE_ROOT/fw1-tcpdump.pid"
fw1_tcpdump_status="$REMOTE_ROOT/fw1-tcpdump.status"
fw0_journal_pid="$REMOTE_ROOT/fw0-journal.pid"
fw0_journal_status="$REMOTE_ROOT/fw0-journal.status"
fw1_journal_pid="$REMOTE_ROOT/fw1-journal.pid"
fw1_journal_status="$REMOTE_ROOT/fw1-journal.status"

cleanup_remote() {
	local vm="$1" prepared="$2"
	(( prepared )) || return 0
	# Every path below is inside the owned run directory.  Validate PID content
	# before passing it to kill; no recursive deletion is needed for cleanup.
	run_vm "$vm" "for f in $(q "$iperf_pid") $(q "$ping_pid") $(q "$ss_pid") $(q "$client_tcpdump_pid") $(q "$fw0_tcpdump_pid") $(q "$fw1_tcpdump_pid") $(q "$fw0_journal_pid") $(q "$fw1_journal_pid"); do if [[ -s \"\$f\" ]]; then p=\$(cat \"\$f\"); if [[ \"\$p\" =~ ^[0-9]+\$ ]]; then kill -TERM \"\$p\" 2>/dev/null || true; fi; fi; done; sleep 0.2" >/dev/null 2>&1 || true
}
cleanup() {
	cleanup_remote "$HOST" "$REMOTE_PREPARED_HOST" || true
	cleanup_remote "$FW0" "$REMOTE_PREPARED_FW0" || true
	cleanup_remote "$FW1" "$REMOTE_PREPARED_FW1" || true
}
trap cleanup EXIT

remote_prepare "$HOST"
remote_prepare "$FW0"
remote_prepare "$FW1"

# Local validation above is not enough: timeout is invoked inside each VM.
for vm in "$HOST" "$FW0" "$FW1"; do
	run_vm "$vm" "command -v timeout >/dev/null"
done

failures=()
START_UTC="$(date -u +%FT%TZ)"
cat >"$ARTIFACT_DIR/metadata.txt" <<EOF
issue=10023
run_id=$RUN_ID
start_utc=$START_UTC
remote=$REMOTE
fw0=$FW0
fw1=$FW1
host=$HOST
remote_root=$REMOTE_ROOT
clock_offsets=clock-offsets.txt
firewall_capture=timeout $((DURATION + 5)) tcpdump -i any -nn -s 96 $TCPDUMP_LIMIT -U -w tcpdump.pcap host $TARGET and tcp port 5201
client_capture=timeout $((DURATION + 5)) tcpdump -i any -nn -s 96 $TCPDUMP_LIMIT -U -w client-tcpdump.pcap host $TARGET and tcp port 5201
iperf_bitrate_per_stream=$BITRATE_PER_STREAM
tcpdump_timeout_sec=$((DURATION + 5))
tcpdump_count=$TCPDUMP_COUNT
iperf_command=iperf3 -c $TARGET -P $PARALLEL -b $BITRATE_PER_STREAM -t $DURATION -i $INTERVAL -J --json-stream --forceflush
ping_command=ping -n -D -i $INTERVAL -w $DURATION $TARGET
ss_command=ss -tin dst $TARGET:5201
EOF

record_clock_sample() {
	local phase="$1" overall_before_wall overall_before_uptime overall_after_wall overall_after_uptime
	{
		printf '[%s]\n' "$phase"
		overall_before_wall="$(date +%s.%N)"
		overall_before_uptime="$(awk '{print $1}' /proc/uptime)"
		printf 'deploy_host_before_wall=%s\ndeploy_host_before_uptime=%s\n' \
			"$overall_before_wall" "$overall_before_uptime"
		for spec in "fw0:$FW0" "fw1:$FW1" "lan:$HOST"; do
			local name="${spec%%:*}" vm="${spec#*:}"
			local host_before_wall host_before_uptime host_after_wall host_after_uptime
			local node_wall node_uptime
			host_before_wall="$(date +%s.%N)"
			host_before_uptime="$(awk '{print $1}' /proc/uptime)"
			if node_wall="$(run_vm "$vm" 'date +%s.%N')"; then
				printf '%s_wall=%s\n' "$name" "$node_wall"
			else
				printf '%s_wall=ERROR\n' "$name"
				failures+=("clock-$phase-$name-wall")
			fi
			if node_uptime="$(run_vm "$vm" "awk '{print \$1}' /proc/uptime")"; then
				printf '%s_uptime=%s\n' "$name" "$node_uptime"
			else
				printf '%s_uptime=ERROR\n' "$name"
				failures+=("clock-$phase-$name-uptime")
			fi
			host_after_wall="$(date +%s.%N)"
			host_after_uptime="$(awk '{print $1}' /proc/uptime)"
			printf '%s_host_before_wall=%s\n%s_host_before_uptime=%s\n' \
				"$name" "$host_before_wall" "$name" "$host_before_uptime"
			printf '%s_host_after_wall=%s\n%s_host_after_uptime=%s\n' \
				"$name" "$host_after_wall" "$name" "$host_after_uptime"
		done
		overall_after_wall="$(date +%s.%N)"
		overall_after_uptime="$(awk '{print $1}' /proc/uptime)"
		printf 'deploy_host_after_wall=%s\ndeploy_host_after_uptime=%s\n' \
			"$overall_after_wall" "$overall_after_uptime"
	} >>"$ARTIFACT_DIR/clock-offsets.txt"
}
record_clock_sample start

start_async() {
	local vm="$1" pid_file="$2" status_file="$3" command="$4"
	local wrapped="$command; rc=\$?; printf '%s\\n' \"\$rc\" >$(q "$status_file")"
	run_vm "$vm" "nohup bash -lc $(q "$wrapped") >/dev/null 2>&1 < /dev/null & echo \$! >$(q "$pid_file")"
}

# Journald output includes daemon/systemd transitions, helper lifecycle,
# session-sync/barrier readiness, and VRRP/ARP messages. The timeout bounds
# capture even when no cut driver is run.
start_async "$FW0" "$fw0_journal_pid" "$fw0_journal_status" \
	"timeout $((DURATION + 5)) journalctl -f -u xpfd -o short-iso --since '-1 second' >$(q "$REMOTE_ROOT/fw0-journal.log") 2>$(q "$REMOTE_ROOT/fw0-journal.stderr")"
start_async "$FW1" "$fw1_journal_pid" "$fw1_journal_status" \
	"timeout $((DURATION + 5)) journalctl -f -u xpfd -o short-iso --since '-1 second' >$(q "$REMOTE_ROOT/fw1-journal.log") 2>$(q "$REMOTE_ROOT/fw1-journal.stderr")"

start_async "$FW0" "$fw0_tcpdump_pid" "$fw0_tcpdump_status" \
	"timeout $((DURATION + 5)) tcpdump -i any -nn -s 96 $TCPDUMP_LIMIT -U -w $(q "$REMOTE_ROOT/fw0-tcpdump.pcap") $(q "host $TARGET and tcp port 5201") >$(q "$REMOTE_ROOT/fw0-tcpdump.stderr") 2>&1"
start_async "$FW1" "$fw1_tcpdump_pid" "$fw1_tcpdump_status" \
	"timeout $((DURATION + 5)) tcpdump -i any -nn -s 96 $TCPDUMP_LIMIT -U -w $(q "$REMOTE_ROOT/fw1-tcpdump.pcap") $(q "host $TARGET and tcp port 5201") >$(q "$REMOTE_ROOT/fw1-tcpdump.stderr") 2>&1"

# AF_XDP owns the firewall dataplane queues, so the firewall kernel ``any``
# device may not see forwarded packets. Capture the same filter on the client
# VM as the packet-level source of truth for TCP ACK/RTO timing.
start_async "$HOST" "$client_tcpdump_pid" "$client_tcpdump_status" \
	"timeout $((DURATION + 5)) tcpdump -i any -nn -s 96 $TCPDUMP_LIMIT -U -w $(q "$REMOTE_ROOT/client-tcpdump.pcap") $(q "host $TARGET and tcp port 5201") >$(q "$REMOTE_ROOT/client-tcpdump.stderr") 2>&1"

# iperf3 3.20's line-delimited JSON mode exposes every stream's 100ms
# interval (including cwnd/retransmits), unlike the historical -i1 text
# recorder. Pacing each stream to 25M keeps the bounded snaplen capture from
# perturbing the dataplane. Keep stderr separate so a failed start cannot look
# like data.
iperf_cmd="set -o pipefail; iperf3 -c $(q "$TARGET") -P $(q "$PARALLEL") -b $(q "$BITRATE_PER_STREAM") -t $(q "$DURATION") -i $(q "$INTERVAL") -J --json-stream --forceflush >$(q "$REMOTE_ROOT/iperf.jsonl") 2>$(q "$REMOTE_ROOT/iperf.stderr")"
start_async "$HOST" "$iperf_pid" "$iperf_status" "$iperf_cmd"

# A matching sub-200ms ICMP stream distinguishes a dataplane/VRRP outage from
# a TCP-only RTO collapse. ``-w`` bounds the probe to this run.
ping_cmd="ping -n -D -i $(q "$INTERVAL") -w $(q "$DURATION") $(q "$TARGET") >$(q "$REMOTE_ROOT/ping.log") 2>$(q "$REMOTE_ROOT/ping.stderr")"
start_async "$HOST" "$ping_pid" "$ping_status" "$ping_cmd"

# Sample ss until the iperf process exits. Each block starts with an epoch
# marker and ends with a delimiter, making the output parseable despite ss's
# multi-line format. Do not swallow ss errors: its status is part of the gate.
ss_loop="set -euo pipefail; pid=\$(cat $(q "$iperf_pid") 2>/dev/null || true); while [[ -n \"\$pid\" ]] && kill -0 \"\$pid\" 2>/dev/null; do printf 'sample_epoch=%s\\n' \"\$(date +%s.%N)\"; ss -tin dst $(q "$TARGET:5201"); printf '%s\\n' ---; sleep $(q "$INTERVAL"); done"
start_async "$HOST" "$ss_pid" "$ss_status" "set -o pipefail; $ss_loop >$(q "$REMOTE_ROOT/ss.log") 2>$(q "$REMOTE_ROOT/ss.stderr")"

wait_for_status() {
	local vm="$1" status_file="$2" label="$3" limit="$4"
	if ! run_vm "$vm" "deadline=\$((\$(date +%s)+$limit)); while [[ ! -s $(q "$status_file") && \$(date +%s) -lt \$deadline ]]; do sleep 0.2; done; [[ -s $(q "$status_file") ]]"; then
		failures+=("$label-status-timeout")
	fi
}

# Wait for iperf first, then for every recorder's own wrapper status. Missing
# or failed recorder statuses are retained as incomplete evidence below.
wait_for_status "$HOST" "$iperf_status" iperf "$((DURATION + 30))"
wait_for_status "$HOST" "$ping_status" ping 30
wait_for_status "$HOST" "$ss_status" ss 30
wait_for_status "$HOST" "$client_tcpdump_status" client-tcpdump 30
wait_for_status "$FW0" "$fw0_tcpdump_status" fw0-tcpdump 30
wait_for_status "$FW1" "$fw1_tcpdump_status" fw1-tcpdump 30
wait_for_status "$FW0" "$fw0_journal_status" fw0-journal 30
wait_for_status "$FW1" "$fw1_journal_status" fw1-journal 30

# Close anything that outlived its bounded wait, then let file writers flush.
cleanup_remote "$HOST" "$REMOTE_PREPARED_HOST" || true
cleanup_remote "$FW0" "$REMOTE_PREPARED_FW0" || true
cleanup_remote "$FW1" "$REMOTE_PREPARED_FW1" || true
sleep 1
record_clock_sample end

pull_artifact() {
	local label="$1" vm="$2" remote_file="$3" local_file="$4"
	if ! pull_vm_file "$vm" "$remote_file" "$local_file" 2>/dev/null; then
		failures+=("$label-pull")
	fi
}
pull_artifact iperf-json "$HOST" "$REMOTE_ROOT/iperf.jsonl" "$ARTIFACT_DIR/iperf.jsonl"
pull_artifact iperf-stderr "$HOST" "$REMOTE_ROOT/iperf.stderr" "$ARTIFACT_DIR/iperf.stderr"
pull_artifact iperf-status "$HOST" "$iperf_status" "$ARTIFACT_DIR/iperf.status"
pull_artifact ping-log "$HOST" "$REMOTE_ROOT/ping.log" "$ARTIFACT_DIR/ping.log"
pull_artifact ping-stderr "$HOST" "$REMOTE_ROOT/ping.stderr" "$ARTIFACT_DIR/ping.stderr"
pull_artifact ping-status "$HOST" "$ping_status" "$ARTIFACT_DIR/ping.status"
pull_artifact ss-log "$HOST" "$REMOTE_ROOT/ss.log" "$ARTIFACT_DIR/ss.log"
pull_artifact ss-stderr "$HOST" "$REMOTE_ROOT/ss.stderr" "$ARTIFACT_DIR/ss.stderr"
pull_artifact ss-status "$HOST" "$ss_status" "$ARTIFACT_DIR/ss.status"
pull_artifact client-pcap "$HOST" "$REMOTE_ROOT/client-tcpdump.pcap" "$ARTIFACT_DIR/client-tcpdump.pcap"
pull_artifact client-pcap-stderr "$HOST" "$REMOTE_ROOT/client-tcpdump.stderr" "$ARTIFACT_DIR/client-tcpdump.stderr"
pull_artifact client-pcap-status "$HOST" "$client_tcpdump_status" "$ARTIFACT_DIR/client-tcpdump.status"
pull_artifact fw0-journal "$FW0" "$REMOTE_ROOT/fw0-journal.log" "$ARTIFACT_DIR/fw0-journal.log"
pull_artifact fw0-journal-stderr "$FW0" "$REMOTE_ROOT/fw0-journal.stderr" "$ARTIFACT_DIR/fw0-journal.stderr"
pull_artifact fw0-journal-status "$FW0" "$fw0_journal_status" "$ARTIFACT_DIR/fw0-journal.status"
pull_artifact fw0-pcap "$FW0" "$REMOTE_ROOT/fw0-tcpdump.pcap" "$ARTIFACT_DIR/fw0-tcpdump.pcap"
pull_artifact fw0-pcap-stderr "$FW0" "$REMOTE_ROOT/fw0-tcpdump.stderr" "$ARTIFACT_DIR/fw0-tcpdump.stderr"
pull_artifact fw0-pcap-status "$FW0" "$fw0_tcpdump_status" "$ARTIFACT_DIR/fw0-tcpdump.status"
pull_artifact fw1-journal "$FW1" "$REMOTE_ROOT/fw1-journal.log" "$ARTIFACT_DIR/fw1-journal.log"
pull_artifact fw1-journal-stderr "$FW1" "$REMOTE_ROOT/fw1-journal.stderr" "$ARTIFACT_DIR/fw1-journal.stderr"
pull_artifact fw1-journal-status "$FW1" "$fw1_journal_status" "$ARTIFACT_DIR/fw1-journal.status"
pull_artifact fw1-pcap "$FW1" "$REMOTE_ROOT/fw1-tcpdump.pcap" "$ARTIFACT_DIR/fw1-tcpdump.pcap"
pull_artifact fw1-pcap-stderr "$FW1" "$REMOTE_ROOT/fw1-tcpdump.stderr" "$ARTIFACT_DIR/fw1-tcpdump.stderr"
pull_artifact fw1-pcap-status "$FW1" "$fw1_tcpdump_status" "$ARTIFACT_DIR/fw1-tcpdump.status"

require_nonempty() {
	local label="$1" path="$2"
	[[ -s "$path" ]] || failures+=("$label-empty-or-missing")
}
require_present() {
	local label="$1" path="$2"
	[[ -e "$path" ]] || failures+=("$label-missing")
}
require_pcap() {
	local label="$1" path="$2" size
	if [[ ! -f "$path" ]]; then
		failures+=("$label-missing")
		return
	fi
	size="$(stat -c '%s' "$path")"
	(( size >= 24 )) || failures+=("$label-short-pcap")
}
require_firewall_pcap() {
	local label="$1" path="$2" stderr="$3" size stderr_text
	if [[ ! -f "$path" ]]; then
		failures+=("$label-missing")
		return
	fi
	size="$(stat -c '%s' "$path")"
	if (( size < 24 )); then
		failures+=("$label-short-pcap")
	fi
	if [[ ! -e "$stderr" ]]; then
		failures+=("$label-stderr-missing")
	elif (( size == 24 )); then
		if [[ ! -s "$stderr" ]]; then
			failures+=("$label-stderr-empty")
		else
			stderr_text="$(<"$stderr")"
			case "$stderr_text" in
			*"packets captured"*|*"packets received by filter"*) ;;
			*) failures+=("$label-stderr-no-packet-footer") ;;
			esac
		fi
	fi
}
check_status() {
	local label="$1" path="$2" allowed="$3" value
	if [[ ! -s "$path" ]]; then
		failures+=("$label-status-missing")
		return
	fi
	value="$(<"$path")"
	case ",$allowed," in
	*,"$value",*) ;;
	*) failures+=("$label-status-$value") ;;
	esac
}

# Required data must be present and non-empty. Stderr files may be empty for
# recorders whose command writes only stdout, but must exist. AF_XDP firewall
# pcaps may intentionally contain only their 24-byte pcap header; in that case
# require_firewall_pcap also requires a non-empty tcpdump packet-count footer.
require_nonempty iperf-json "$ARTIFACT_DIR/iperf.jsonl"
require_present iperf-stderr "$ARTIFACT_DIR/iperf.stderr"
require_nonempty ping-log "$ARTIFACT_DIR/ping.log"
require_present ping-stderr "$ARTIFACT_DIR/ping.stderr"
require_nonempty ss-log "$ARTIFACT_DIR/ss.log"
require_present ss-stderr "$ARTIFACT_DIR/ss.stderr"
require_pcap client-pcap "$ARTIFACT_DIR/client-tcpdump.pcap"
if [[ -f "$ARTIFACT_DIR/client-tcpdump.pcap" ]] &&
	(( $(stat -c '%s' "$ARTIFACT_DIR/client-tcpdump.pcap") <= 24 )); then
	failures+=(client-pcap-empty)
fi
require_present client-pcap-stderr "$ARTIFACT_DIR/client-tcpdump.stderr"
require_nonempty fw0-journal "$ARTIFACT_DIR/fw0-journal.log"
require_present fw0-journal-stderr "$ARTIFACT_DIR/fw0-journal.stderr"
require_firewall_pcap fw0-pcap "$ARTIFACT_DIR/fw0-tcpdump.pcap" "$ARTIFACT_DIR/fw0-tcpdump.stderr"
require_nonempty fw1-journal "$ARTIFACT_DIR/fw1-journal.log"
require_present fw1-journal-stderr "$ARTIFACT_DIR/fw1-journal.stderr"
require_firewall_pcap fw1-pcap "$ARTIFACT_DIR/fw1-tcpdump.pcap" "$ARTIFACT_DIR/fw1-tcpdump.stderr"
check_status iperf "$ARTIFACT_DIR/iperf.status" 0
check_status ping "$ARTIFACT_DIR/ping.status" 0
check_status ss "$ARTIFACT_DIR/ss.status" 0
check_status client-tcpdump "$ARTIFACT_DIR/client-tcpdump.status" '0,124'
check_status fw0-tcpdump "$ARTIFACT_DIR/fw0-tcpdump.status" '0,124'
check_status fw1-tcpdump "$ARTIFACT_DIR/fw1-tcpdump.status" '0,124'
check_status fw0-journal "$ARTIFACT_DIR/fw0-journal.status" '0,124'
check_status fw1-journal "$ARTIFACT_DIR/fw1-journal.status" '0,124'

END_UTC="$(date -u +%FT%TZ)"
printf 'end_utc=%s\n' "$END_UTC" >>"$ARTIFACT_DIR/metadata.txt"
status="$(cat "$ARTIFACT_DIR/iperf.status" 2>/dev/null || printf 'missing')"
printf 'iperf_exit_status=%s\n' "$status" >>"$ARTIFACT_DIR/metadata.txt"
printf 'artifacts=%s\n' "$(printf '%s\n' "$ARTIFACT_DIR"/* | wc -l)" >>"$ARTIFACT_DIR/metadata.txt"
if ((${#failures[@]})); then
	printf 'failures=%s\n' "${failures[*]}" >>"$ARTIFACT_DIR/metadata.txt"
	printf 'sampler incomplete; artifacts remain in %s (failures: %s)\n' "$ARTIFACT_DIR" "${failures[*]}" >&2
	exit 1
fi
printf 'sampler complete: %s\n' "$ARTIFACT_DIR"
