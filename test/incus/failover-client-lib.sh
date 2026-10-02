#!/usr/bin/env bash
#
# Helpers for the main iperf3 client in test-failover.sh. Its PID is recorded
# separately from the pool-mode client so a second iperf3 process cannot mask
# loss of the stream being measured.

# failover_start_main_iperf <duration> <target> <port> <streams> <log> <pidfile>
failover_start_main_iperf() {
	local duration="$1" target="$2" port="$3" streams="$4" log="$5" pidfile="$6"
	incus exec "$CLUSTER_LAN_HOST" -- bash -c '
		iperf3 --forceflush --connect-timeout 5000 -i 1 -t "$1" -c "$2" -p "$3" -P "$4" >"$5" 2>&1 &
		echo "$!" > "$6"
	' _ "$duration" "$target" "$port" "$streams" "$log" "$pidfile"
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
