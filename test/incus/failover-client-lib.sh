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
		timeout -k 5 "$7" iperf3 --json-stream --forceflush --connect-timeout 5000 -t "$1" -c "$2" -p "$3" -P "$4" >"$5" 2>&1 &
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
# The client emits JSON Lines. Keep these Python snippets shared by the pure
# local predicates and the remote helpers so fixture tests exercise the same
# parsing rules as the live wait/retry path.
FAILOVER_JSON_STREAM_COMPLETION_CHECK='
import json
import sys

def reject_constant(value):
    raise ValueError("non-standard JSON constant: " + value)

try:
    with open(sys.argv[1], encoding="utf-8") as stream:
        text = stream.read()
except (OSError, UnicodeError):
    raise SystemExit(1)

def completed(value):
    return isinstance(value, dict) and value.get("event") != "error" and (
        value.get("event") == "end" or value.get("completed") is True
    )

try:
    document = json.loads(text, parse_constant=reject_constant)
except (json.JSONDecodeError, ValueError):
    document = None
else:
    if completed(document):
        raise SystemExit(0)
    raise SystemExit(1)

found = False
for line in text.splitlines():
    if not line.strip():
        continue
    try:
        event = json.loads(line, parse_constant=reject_constant)
    except (json.JSONDecodeError, ValueError):
        raise SystemExit(1)
    if isinstance(event, dict) and event.get("event") == "error":
        raise SystemExit(1)
    found = completed(event) or found
raise SystemExit(0 if found else 1)
'

FAILOVER_JSON_STREAM_CONNECT_ERROR_CHECK='
import json
import sys

def reject_constant(value):
    raise ValueError("non-standard JSON constant: " + value)

try:
    with open(sys.argv[1], encoding="utf-8") as stream:
        for line in stream:
            if not line.strip():
                continue
            try:
                event = json.loads(line, parse_constant=reject_constant)
            except (json.JSONDecodeError, ValueError):
                raise SystemExit(1)
            if isinstance(event, dict) and event.get("event") == "error":
                error_data = event.get("data")
                if (
                    isinstance(error_data, str)
                    and "unable to connect" in error_data.lower()
                ):
                    raise SystemExit(0)
except (OSError, UnicodeError):
    raise SystemExit(1)
raise SystemExit(1)
'

# failover_json_stream_completed <local-log>
#   Testable, local predicate shared by the remote result waiter.
failover_json_stream_completed() {
	python3 -c "$FAILOVER_JSON_STREAM_COMPLETION_CHECK" "$1" >/dev/null 2>&1
}

# failover_json_stream_connect_error <local-log>
#   True only when a valid error event carries the captured connect-failure signal.
failover_json_stream_connect_error() {
	python3 -c "$FAILOVER_JSON_STREAM_CONNECT_ERROR_CHECK" "$1" >/dev/null 2>&1
}

# failover_main_iperf_connect_failed <remote-log>
#   Check the captured connection-failure signal on the LAN host.
failover_main_iperf_connect_failed() {
	incus exec "$CLUSTER_LAN_HOST" -- python3 -c \
		"$FAILOVER_JSON_STREAM_CONNECT_ERROR_CHECK" "$1" >/dev/null 2>&1
}

# failover_main_iperf_result_complete <remote-log>
#   Check completion once without waiting; a missing marker remains false.
failover_main_iperf_result_complete() {
	incus exec "$CLUSTER_LAN_HOST" -- python3 -c \
		"$FAILOVER_JSON_STREAM_COMPLETION_CHECK" "$1" >/dev/null 2>&1
}

# failover_wait_main_iperf_result <log> <timeout>
#   Wait up to timeout seconds for a valid JSON completion event. A missing
#   end marker, malformed/truncated line, or unreadable log never implies
#   completion; expiry is a VOID for the caller to report.
failover_wait_main_iperf_result() {
	local log="$1" wait_seconds="$2"
	incus exec "$CLUSTER_LAN_HOST" -- bash -c '
		log=$1
		checker=$2
		remaining=$3
		while (( remaining > 0 )); do
			if python3 -c "$checker" "$log" >/dev/null 2>&1; then
				exit 0
			fi
			sleep 1
			remaining=$((remaining - 1))
		done
		python3 -c "$checker" "$log" >/dev/null 2>&1
	' _ "$log" "$FAILOVER_JSON_STREAM_COMPLETION_CHECK" "$wait_seconds" &>/dev/null
}
