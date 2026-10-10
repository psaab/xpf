#!/usr/bin/env bash
#
# test/incus/stress-failover-lib.sh — ownership + stream oracles for the
# rapid failover stress gate (#12199). Sourced by test-stress-failover.sh
# AND its hermetic selftest; pure functions only, no incus/cluster calls
# except through the caller-provided `incus` function/command.
#
# The stress gate historically verified ownership PREFLIGHT-ONLY and issued
# every loop transfer fire-and-forget (`|| true`), so repeated refusals or
# no-ops reported as completed cycles. check_streams passed an unreadable
# log: `grep -c` yields 0 on missing rows, and 0 dead reads as all-alive.
# This lib makes both observations fail-closed.

# Bounded-poll budget for a single RG1 move. Overridable for the hermetic
# selftest (which stubs `sleep` and advances SECONDS instantly).
STRESS_OWNER_TIMEOUT="${STRESS_OWNER_TIMEOUT:-30}"
STRESS_OWNER_INTERVAL="${STRESS_OWNER_INTERVAL:-2}"

# stress_rg1_owner_verdict <node0|node1> <fw0-status> <fw1-status>
#
# Pure: both node queries must independently show the expected RG1 owner as
# `primary` and the peer as `secondary`. Prints a reason on stdout and
# returns 1 unless settled; returns 0 with no output when settled.
#
# Parse contract (pinned by status_layout_contract_8206_test.go): the header
# is `Redundancy group: N , Failover count: M`; node rows are column-0 with
# the node token in $1 and the state in $3; sub-lines are indented.
stress_parse_rg1_status() {
	printf '%s\n' "$1" | awk '
		/^Redundancy group:[[:space:]]/ {
			inrg = ($3 == 1)
			next
		}
		inrg && $1 == "node0" { n0 = tolower($3); n0_count++ }
		inrg && $1 == "node1" { n1 = tolower($3); n1_count++ }
		END {
			if (n0_count != 1 || n1_count != 1) {
				print "BLIND"
				exit
			}
			print n0 " " n1
		}'
}

stress_rg1_owner_verdict() {
	local expected="$1" s0="$2" s1="$3"
	local r0 r1 wanted0 wanted1
	case "$expected" in
	node0) wanted0=primary; wanted1=secondary ;;
	node1) wanted0=secondary; wanted1=primary ;;
	*) printf 'invalid expected RG1 owner: %s\n' "$expected"; return 1 ;;
	esac
	r0=$(stress_parse_rg1_status "$s0")
	r1=$(stress_parse_rg1_status "$s1")
	if [[ "$r0" == "$wanted0 $wanted1" && "$r1" == "$wanted0 $wanted1" ]]; then
		return 0
	fi
	printf 'expected %s primary for RG1 (fw0 query: %s; fw1 query: %s)\n' "$expected" "$r0" "$r1"
	return 1
}

# stress_request <instance> <cli-command...>
#
# Issue one failover request and REPORT its outcome without aborting: rc and
# combined output are captured (cli errors go to stderr with exit 1, so
# `2>&1` carries the refusal text into the transcript). A failure is logged
# as info, not verdict — the bounded owner poll below is authoritative for
# whether the RG moved; a refused request that still converges (peer-side
# reset, operator action) must not fail the gate, and a silent exit-0
# no-op must not pass it.
stress_request() {
	local inst="$1"; shift
	local output rc=0
	if output=$(incus exec "$inst" -- cli -c "$*" 2>&1); then
		rc=0
	else
		rc=$?
	fi
	if (( rc != 0 )); then
		info "request to ${inst} returned ${rc}: ${output:-<no output>}"
	elif [[ -n "${output//[[:space:]]/}" ]]; then
		info "request to ${inst}: ${output}"
	fi
	return 0
}

# wait_rg1_owner <node0|node1> <label>
#
# Bounded-poll BOTH nodes until both queries agree the expected node owns
# RG1. pass() on settle; fail() when the deadline expires or every read is
# blind. Returns 0 on settle, 1 otherwise. Requires FW0/FW1 from the
# caller (cluster-env.sh in the gate; fixtures in the selftest).
wait_rg1_owner() {
	local expected="$1" label="$2"
	local start s0 s1 reason=""
	start=$SECONDS
	while :; do
		s0=$(incus exec "$FW0" -- cli -c 'show chassis cluster status' 2>/dev/null || true)
		s1=$(incus exec "$FW1" -- cli -c 'show chassis cluster status' 2>/dev/null || true)
		if reason=$(stress_rg1_owner_verdict "$expected" "$s0" "$s1"); then
			pass "${label}: RG1 settled on ${expected} (both node queries)"
			return 0
		fi
		if (( SECONDS - start >= STRESS_OWNER_TIMEOUT )); then
			break
		fi
		sleep "$STRESS_OWNER_INTERVAL"
	done
	fail "${label}: RG1 did not move (${reason:-owner poll blind for ${STRESS_OWNER_TIMEOUT}s})"
	return 1
}

# check_streams <label>
#
# Fail-closed stream oracle: fewer than IPERF_STREAMS per-stream rows in
# the tail is a short read (transient unreadable log), not an all-alive
# snapshot — FAIL rather than pass. `grep -c` yields 0 on missing rows,
# which is exactly how the old oracle printed `all streams alive ()`.
check_streams() {
	local label="$1"
	local tail_lines=$(( IPERF_STREAMS * 2 + 5 ))
	local per_stream
	per_stream=$(incus exec "$CLUSTER_LAN_HOST" -- \
		tail -${tail_lines} "$LOG" 2>/dev/null \
		| grep -E '^\[  [0-9]|^\[ [0-9][0-9]' | tail -"$IPERF_STREAMS")
	local rows dead sum bps
	rows=$(printf '%s\n' "$per_stream" | grep -cE '^\[  [0-9]|^\[ [0-9][0-9]' || true)
	if [[ "$rows" -lt "$IPERF_STREAMS" ]]; then
		fail "$label: short stream read (${rows}/${IPERF_STREAMS} rows — log tail unreadable, not all-alive)"
		return 1
	fi
	dead=$(printf '%s\n' "$per_stream" | grep -c "0.00 bits/sec" || true)
	sum=$(incus exec "$CLUSTER_LAN_HOST" -- \
		tail -${tail_lines} "$LOG" 2>/dev/null \
		| grep 'SUM' | tail -1 || true)
	bps=$(echo "$sum" | grep -oiE "[0-9.]+ [MG]bits/sec" | head -1)
	if [[ "$dead" -gt 0 ]]; then
		fail "$label: $dead/$IPERF_STREAMS streams dead ($bps)"
		return 1
	else
		pass "$label: all streams alive ($bps)"
		return 0
	fi
}
