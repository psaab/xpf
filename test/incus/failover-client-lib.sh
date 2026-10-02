#!/usr/bin/env bash
#
# Helpers for the main iperf3 client in test-failover.sh. Its PID is recorded
# separately from the pool-mode client so a second iperf3 process cannot mask
# loss of the stream being measured.

# failover_start_main_iperf <duration> <target> <port> <streams> <log> <pidfile>
#   The client runs under timeout(1) with a wall clock of duration +
#   FAILOVER_IPERF_TIMEOUT_MARGIN (default 30s). --connect-timeout covers the
#   connect only, and a flaky far end can hang the final control exchange
#   forever (#11861). The pidfile records the timeout supervisor, whose cmdline
#   still carries the iperf3 match keys for failover_main_iperf_running.
failover_start_main_iperf() {
	local duration="$1" target="$2" port="$3" streams="$4" log="$5" pidfile="$6"
	local margin="${FAILOVER_IPERF_TIMEOUT_MARGIN:-30}"
	case "$margin" in ''|*[!0-9]*) margin=30 ;; esac
	local wall=$(( duration + margin ))
	incus exec "$CLUSTER_LAN_HOST" -- bash -c '
		timeout -k 5 "$7" iperf3 --forceflush --connect-timeout 5000 -i 1 -t "$1" -c "$2" -p "$3" -P "$4" >"$5" 2>&1 &
		echo "$!" > "$6"
	' _ "$duration" "$target" "$port" "$streams" "$log" "$pidfile" "$wall"
}

# failover_stop_main_iperf <pidfile> <target> <port> <streams>
#   Stop only the client supervisor recorded by failover_start_main_iperf.
failover_stop_main_iperf() {
	incus exec "$CLUSTER_LAN_HOST" -- bash -c '
		pid=$(cat "$1" 2>/dev/null) || exit 0
		case "$pid" in ""|*[!0-9]*) exit 0 ;; esac
		matches_iperf() {
			local proc_pid="$1" cmdline
			cmdline=$(tr "\000" " " <"/proc/$proc_pid/cmdline" 2>/dev/null) || return 1
			[[ "$cmdline" == *iperf3* && "$cmdline" == *"-c $2"* && "$cmdline" == *"-p $3"* && "$cmdline" == *"-P $4"* ]]
		}
		matches_client() {
			local cmdline
			cmdline=$(tr "\000" " " <"/proc/$pid/cmdline" 2>/dev/null) || return 1
			[[ "$cmdline" == *timeout*iperf3*"-c $2"*"-p $3"*"-P $4"* ]]
		}
		matches_client || exit 0
		children=$(pgrep -P "$pid" 2>/dev/null || true)
		pkill -TERM -P "$pid" 2>/dev/null || true
		kill -TERM "$pid" 2>/dev/null || true
		for _ in {1..5}; do
			alive=0
			if matches_client; then alive=1; fi
			for child in $children; do
				if matches_iperf "$child" "$2" "$3" "$4"; then alive=1; fi
			done
			(( alive == 0 )) && exit 0
			sleep 1
		done
		for child in $children; do
			if matches_iperf "$child" "$2" "$3" "$4"; then
				kill -KILL "$child" 2>/dev/null || true
			fi
		done
		matches_client && kill -KILL "$pid" 2>/dev/null || true
	' _ "$1" "$2" "$3" "$4" &>/dev/null
}

# failover_main_iperf_running <pidfile> <target> <port> <streams>
failover_main_iperf_running() {
	incus exec "$CLUSTER_LAN_HOST" -- bash -c '
		pid=$(cat "$1" 2>/dev/null) || exit 1
		case "$pid" in ""|*[!0-9]*) exit 1 ;; esac
		kill -0 "$pid" 2>/dev/null || exit 1
		cmdline=$(tr "\000" " " <"/proc/$pid/cmdline" 2>/dev/null) || exit 1
		[[ "$cmdline" == *iperf3* && "$cmdline" == *"-c $2"* && "$cmdline" == *"-p $3"* && "$cmdline" == *"-P $4"* ]]
	' _ "$1" "$2" "$3" "$4" &>/dev/null
}
# failover_wait_main_iperf_result <log> <timeout>
#   Wait up to timeout seconds for the client to flush its final result. The
#   control process can exit before its final control exchange reaches the log.
failover_wait_main_iperf_result() {
	local log="$1" timeout="$2"
	incus exec "$CLUSTER_LAN_HOST" -- bash -c '
		log=$1
		remaining=$2
		while (( remaining > 0 )); do
			if grep -Eq "iperf Done|\\[SUM\\].*sender" "$log" 2>/dev/null; then
				exit 0
			fi
			sleep 1
			remaining=$((remaining - 1))
		done
		grep -Eq "iperf Done|\\[SUM\\].*sender" "$log" 2>/dev/null
	' _ "$log" "$timeout" &>/dev/null
}
