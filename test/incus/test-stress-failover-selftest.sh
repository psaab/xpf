#!/usr/bin/env bash
# Hermetic RG1-owner and iperf-log regression cells for #12199.
# No Incus, cluster, network, or live log access: all external calls are mocked.
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
STRESS_OWNER_TIMEOUT=2
STRESS_OWNER_INTERVAL=1
# shellcheck source=test/incus/stress-failover-lib.sh
source "${SCRIPT_DIR}/stress-failover-lib.sh"

PASS=0
FAIL=0
ERRORS=()
SELFTEST_PASS=0
SELFTEST_FAIL=0

info() { printf 'INFO: %s\n' "$*"; }
pass() { printf '  PASS  %s\n' "$*"; PASS=$((PASS + 1)); }
fail() { printf '  FAIL  %s\n' "$*"; FAIL=$((FAIL + 1)); ERRORS+=("$*"); }
ok() { printf 'PASS: %s\n' "$*"; SELFTEST_PASS=$((SELFTEST_PASS + 1)); }
bad() { printf 'FAIL: %s\n' "$*" >&2; SELFTEST_FAIL=$((SELFTEST_FAIL + 1)); }

TMP_DIR=$(mktemp -d)
trap 'rm -rf "$TMP_DIR"' EXIT
export MOCK_STATUS_CALLS="${TMP_DIR}/status-calls"
: > "$MOCK_STATUS_CALLS"
FW0=fw0
FW1=fw1
CLUSTER_LAN_HOST=lan
IPERF_STREAMS=8
LOG=/tmp/fixture-iperf.log
MOCK_STATUS_MODE=steady
MOCK_LOG_MODE=empty
MOCK_REQUEST_MODE=success

# A FormatStatus-shaped fixture. Status query output on fw0 starts with node0;
# output on fw1 starts with node1. RG0/RG2 are present to pin RG scoping.
mock_status() {
	local rg1_owner="$1" local_node="$2" rg0_owner="${3:-node0}"
	local rg node0_state node1_state
	for rg in 0 1 2; do
		if [[ "$rg" == 1 ]]; then
			if [[ "$rg1_owner" == node0 ]]; then node0_state=primary; node1_state=secondary
			else node0_state=secondary; node1_state=primary; fi
		elif [[ "$rg0_owner" == node0 ]]; then
			node0_state=primary; node1_state=secondary
		else
			node0_state=secondary; node1_state=primary
		fi
		printf 'Redundancy group: %s , Failover count: 0\n' "$rg"
		if [[ "$local_node" == node0 ]]; then
			printf 'node0   200       %-14s no       no       None\n' "$node0_state"
			printf '  Takeover ready: yes\n'
			printf 'node1   100       %-14s no       no       None\n' "$node1_state"
		else
			printf 'node1   100       %-14s no       no       None\n' "$node1_state"
			printf '  Takeover ready: yes\n'
			printf 'node0   200       %-14s no       no       None\n' "$node0_state"
		fi
		printf '\n'
	done
}

mock_log() {
	local streams="${1:-8}" mode="${2:-healthy}" rate i
	for ((i = 1; i <= streams; i++)); do
		rate='8.00 Gbits/sec'
		if [[ "$mode" == dead && $i -eq 3 ]]; then rate='0.00 bits/sec'; fi
		printf '[  %d] 0.00-1.00 sec 1.00 GBytes %s\n' "$i" "$rate"
	done
	printf '[SUM] 0.00-1.00 sec 8.00 GBytes 8.00 Gbits/sec\n'
}

# File-backed status-call indexing survives the command substitutions in the
# poller. The default mock is an unchanged node0 owner, which must FAIL a
# node1-expected poll rather than manufacture a successful move.
incus() {
	local args="$*" node call_count owner
	[[ "$1" == exec ]] || { printf 'unexpected incus call: %s\n' "$args" >&2; return 90; }
	shift
	node="$1"
	if [[ "$args" == *'show chassis cluster status'* ]]; then
		printf '%s\n' "$node" >> "$MOCK_STATUS_CALLS"
		call_count=$(wc -l < "$MOCK_STATUS_CALLS")
		case "$MOCK_STATUS_MODE" in
		unchanged) owner=node0 ;;
		transition)
			if (( call_count <= 2 )); then owner=node0; else owner=node1; fi
			;;
		blind) return 1 ;;
		*) owner=node0 ;;
		esac
		if [[ "$node" == "$FW0" ]]; then mock_status "$owner" node0
		elif [[ "$node" == "$FW1" ]]; then mock_status "$owner" node1
		else printf 'unknown fixture node: %s\n' "$node" >&2; return 91
		fi
		return 0
	fi
	if [[ "$node" == "$CLUSTER_LAN_HOST" && "$args" == *' tail '* ]]; then
		case "$MOCK_LOG_MODE" in
		empty) return 0 ;;
		short) mock_log 3 healthy ;;
		dead) mock_log 8 dead ;;
		healthy) mock_log 8 healthy ;;
		*) printf 'unknown log fixture: %s\n' "$MOCK_LOG_MODE" >&2; return 92 ;;
		esac
		return 0
	fi
	if [[ "$args" == *'request chassis cluster failover'* ]]; then
		if [[ "$MOCK_REQUEST_MODE" == fail ]]; then
			printf 'error: failover request refused\n' >&2
			return 1
		fi
		return 0
	fi
	printf 'unexpected mocked incus command: %s\n' "$args" >&2
	return 93
}

# Avoid wall-clock delays while preserving the poller's elapsed-time budget.
sleep() { SECONDS=$((SECONDS + ${1%%.*})); }

# (a) Empty tail must FAIL, never `all streams alive ()`.
PASS=0; FAIL=0; MOCK_LOG_MODE=empty
if check_streams 'empty-tail fixture' >"${TMP_DIR}/empty.out" 2>&1; then rc=0; else rc=$?; fi
if [[ "$rc" -eq 1 && "$FAIL" -eq 1 && "$PASS" -eq 0 &&
	$(<"${TMP_DIR}/empty.out") == *'short stream read (0/8 rows'* &&
	$(<"${TMP_DIR}/empty.out") != *'all streams alive'* ]]; then
	ok 'empty-tail stream snapshot FAILs closed'
else
	bad "empty-tail stream snapshot did not FAIL closed (rc=$rc, output=$(<"${TMP_DIR}/empty.out"))"
fi

# Short but non-empty tails are also blind; exact stream count is required.
PASS=0; FAIL=0; MOCK_LOG_MODE=short
if check_streams 'short-tail fixture' >"${TMP_DIR}/short.out" 2>&1; then rc=0; else rc=$?; fi
if [[ "$rc" -eq 1 && "$FAIL" -eq 1 && "$PASS" -eq 0 &&
	$(<"${TMP_DIR}/short.out") == *'short stream read (3/8 rows'* ]]; then
	ok 'short stream snapshot FAILs rather than treating missing rows as alive'
else
	bad "short stream snapshot result unexpected (rc=$rc, output=$(<"${TMP_DIR}/short.out"))"
fi

# Positive control: a full set of live stream rows passes.
PASS=0; FAIL=0; MOCK_LOG_MODE=healthy
if check_streams 'healthy fixture' >"${TMP_DIR}/healthy.out" 2>&1; then rc=0; else rc=$?; fi
if [[ "$rc" -eq 0 && "$PASS" -eq 1 && "$FAIL" -eq 0 &&
	$(<"${TMP_DIR}/healthy.out") == *'all streams alive'* ]]; then
	ok 'complete healthy stream snapshot passes'
else
	bad "healthy stream snapshot result unexpected (rc=$rc, output=$(<"${TMP_DIR}/healthy.out"))"
fi

# A complete read with a dead stream remains a measured FAIL.
PASS=0; FAIL=0; MOCK_LOG_MODE=dead
if check_streams 'dead-stream fixture' >"${TMP_DIR}/dead.out" 2>&1; then rc=0; else rc=$?; fi
if [[ "$rc" -eq 1 && "$FAIL" -eq 1 && "$PASS" -eq 0 &&
	$(<"${TMP_DIR}/dead.out") == *'1/8 streams dead'* ]]; then
	ok 'complete snapshot with a dead stream FAILs'
else
	bad "dead-stream snapshot result unexpected (rc=$rc, output=$(<"${TMP_DIR}/dead.out"))"
fi

# Both independently captured FormatStatus shapes must agree on the owner.
status_fw0_node0=$(mock_status node0 node0)
status_fw1_node1=$(mock_status node0 node1)
if stress_rg1_owner_verdict node0 "$status_fw0_node0" "$status_fw1_node1"; then
	ok 'both node queries prove the expected RG1 owner'
else
	bad 'both node queries rejected the expected RG1 owner'
fi

# A real RG1 split while RG0 changes independently: only RG1 decides the result.
status_fw0_node0=$(mock_status node1 node0 node1)
status_fw1_node1=$(mock_status node1 node1 node1)
if stress_rg1_owner_verdict node1 "$status_fw0_node0" "$status_fw1_node1"; then
	ok 'RG1 owner verdict is scoped to RG1, not RG0'
else
	bad 'RG0 state contaminated RG1 owner verdict'
fi

# Unchanged, valid node0-primary fixtures MUST FAIL a node1-expected move.
status_fw0_node0=$(mock_status node0 node0)
status_fw1_node1=$(mock_status node0 node1)
if stress_rg1_owner_verdict node1 "$status_fw0_node0" "$status_fw1_node1" >"${TMP_DIR}/unchanged-verdict.out"; then
	bad 'unchanged RG1 owner passed the node1 ownership verdict'
else
	ok 'unchanged RG1 owner fails the node1 ownership verdict'
fi
if stress_rg1_owner_verdict node1 '' '' >"${TMP_DIR}/blind-verdict.out"; then
	bad 'empty status queries passed the ownership verdict'
else
	if [[ $(<"${TMP_DIR}/blind-verdict.out") == *'BLIND'* ]]; then
		ok 'empty status queries are blind, not a healthy owner'
	else
		bad 'empty status queries lacked a blind-evidence reason'
	fi
fi

# Bounded-poll no-op fixture: node0 remains primary in BOTH node queries.
# It must time out as FAIL and must have queried both nodes on every attempt.
PASS=0; FAIL=0; MOCK_STATUS_MODE=unchanged; : > "$MOCK_STATUS_CALLS"
STRESS_OWNER_TIMEOUT=2; STRESS_OWNER_INTERVAL=1; SECONDS=0
if wait_rg1_owner node1 'unchanged-status fixture' >"${TMP_DIR}/unchanged-poll.out" 2>&1; then rc=0; else rc=$?; fi
call_count=$(wc -l < "$MOCK_STATUS_CALLS")
if [[ "$rc" -eq 1 && "$FAIL" -eq 1 && "$PASS" -eq 0 && "$call_count" -eq 6 &&
	$(<"${TMP_DIR}/unchanged-poll.out") == *'RG1 did not move'* ]]; then
	ok 'unchanged-status bounded poll FAILs after querying both nodes on each attempt'
else
	bad "unchanged-status poll result unexpected (rc=$rc, reads=$call_count, output=$(<"${TMP_DIR}/unchanged-poll.out"))"
fi

# Positive control: transition on the second bounded poll is observed from both nodes.
PASS=0; FAIL=0; MOCK_STATUS_MODE=transition; : > "$MOCK_STATUS_CALLS"
STRESS_OWNER_TIMEOUT=4; SECONDS=0
if wait_rg1_owner node1 'settling-status fixture' >"${TMP_DIR}/settled-poll.out" 2>&1; then rc=0; else rc=$?; fi
call_count=$(wc -l < "$MOCK_STATUS_CALLS")
if [[ "$rc" -eq 0 && "$PASS" -eq 1 && "$FAIL" -eq 0 && "$call_count" -eq 4 &&
	$(<"${TMP_DIR}/settled-poll.out") == *'settled on node1'* ]]; then
	ok 'bounded poll accepts a move observed on both nodes'
else
	bad "settling-status poll result unexpected (rc=$rc, reads=$call_count, output=$(<"${TMP_DIR}/settled-poll.out"))"
fi

# CLI refusal output is stderr in production; the request wrapper preserves it
# in the transcript but leaves the authoritative owner poll to decide outcome.
MOCK_REQUEST_MODE=fail
if stress_request fw0 'request chassis cluster failover redundancy-group 1' >"${TMP_DIR}/request-fail.out" 2>&1; then rc=0; else rc=$?; fi
if [[ "$rc" -eq 0 && $(<"${TMP_DIR}/request-fail.out") == *'returned 1'* &&
	$(<"${TMP_DIR}/request-fail.out") == *'failover request refused'* ]]; then
	ok 'request refusal and stderr text are retained for diagnosis'
else
	bad "request refusal was not retained (rc=$rc, output=$(<"${TMP_DIR}/request-fail.out"))"
fi
MOCK_REQUEST_MODE=success
if stress_request fw0 'request chassis cluster failover redundancy-group 1' >"${TMP_DIR}/request-ok.out" 2>&1; then rc=0; else rc=$?; fi
if [[ "$rc" -eq 0 && ! -s "${TMP_DIR}/request-ok.out" ]]; then
	ok 'silent successful request does not add noisy transcript output'
else
	bad "successful request result unexpected (rc=$rc, output=$(<"${TMP_DIR}/request-ok.out"))"
fi

# Whole-script one-cycle fixture: the phase-3 loop, its two owner polls, and
# the post-loop RG1-back assertion must keep working together. `incus` and
# `sleep` are PATH mocks; the lock marker is a private ancestor witness, so
# cluster-cell.sh does not acquire the shared live-cluster lock.
whole_dir="${TMP_DIR}/whole-script"
mkdir -p "$whole_dir/bin"
mock_status node0 node0 > "$whole_dir/status.txt"
mock_log 8 healthy > "$whole_dir/iperf.log"
cat > "$whole_dir/bin/incus" <<'MOCK_INCUS'
#!/usr/bin/env bash
if [[ "${1:-}" == list ]]; then exit 0; fi
if [[ "${1:-}" == info ]]; then printf 'Status: RUNNING\n'; exit 0; fi
if [[ "${1:-}" != exec ]]; then
	printf 'unexpected fixture incus call: %s\n' "$*" >&2
	exit 90
fi
shift
node="$1"
shift
args="$*"
case "$args" in
	*"show chassis cluster status"*)
		printf '%s\n' "$node" >> "${WHOLE_STATUS_CALLS:?}"
		cat "${WHOLE_STATUS_FILE:?}"
		;;
	*"show security flow session destination-prefix"*)
		for id in 1 2 3 4 5 6 7 8; do printf 'Session ID: %s\n' "$id"; done
		;;
	*"pgrep -x iperf3"*|*"ping "*|*"pkill -9 iperf3"*|*"bash -c"*|*"request chassis cluster"*)
		exit 0
		;;
	*"tail "*|*"grep "*)
		cat "${WHOLE_IPERF_LOG:?}"
		;;
	*)
		printf 'unhandled fixture incus command: %s\n' "$args" >&2
		exit 91
		;;
esac
MOCK_INCUS
cat > "$whole_dir/bin/sleep" <<'MOCK_SLEEP'
#!/usr/bin/env bash
exit 0
MOCK_SLEEP
chmod +x "$whole_dir/bin/incus" "$whole_dir/bin/sleep"
: > "$whole_dir/status-calls"
whole_harness="${STRESS_FAILOVER_HARNESS:-${SCRIPT_DIR}/test-stress-failover.sh}"
whole_lock="${whole_dir}/cluster.lock"
if env \
	PATH="$whole_dir/bin:$PATH" \
	BPFRX_CLUSTER_ENV="" \
	FW0=fw0 FW1=fw1 CLUSTER_LAN_HOST=lan \
	TOTAL_CYCLES=1 FAILOVER_INTERVAL=2 IPERF_STREAMS=8 \
	STRESS_OWNER_TIMEOUT=0 STRESS_OWNER_INTERVAL=1 \
	XPF_CLUSTER_LOCK="$whole_lock" XPF_CLUSTER_LOCK_HELD="$whole_lock:$$" \
	WHOLE_STATUS_CALLS="$whole_dir/status-calls" \
	WHOLE_STATUS_FILE="$whole_dir/status.txt" \
	WHOLE_IPERF_LOG="$whole_dir/iperf.log" \
	bash "$whole_harness" > "$whole_dir/run.out" 2>&1; then
	whole_rc=0
else
	whole_rc=$?
fi
whole_reads=$(wc -l < "$whole_dir/status-calls")
if [[ "$whole_rc" -eq 1 && "$whole_reads" -eq 8 &&
	$(<"$whole_dir/run.out") == *'cycle 1 failover: RG1 did not move'* &&
	$(<"$whole_dir/run.out") == *'all streams alive'* &&
	$(<"$whole_dir/run.out") == *'iperf3 throughput: 8.0000 Gbps'* &&
	$(<"$whole_dir/run.out") != *'all 1 failover cycles completed'* ]]; then
	ok 'whole harness rejects an unchanged owner while healthy traffic and final SUM pass'
else
	bad "whole harness fixture result unexpected (rc=$whole_rc, status_reads=$whole_reads, output=$(<"$whole_dir/run.out"))"
fi

printf '%s\n' '----------------------------------------'
printf 'stress failover selftest: %d passed, %d failed\n' "$SELFTEST_PASS" "$SELFTEST_FAIL"
[[ "$SELFTEST_FAIL" -eq 0 ]]
