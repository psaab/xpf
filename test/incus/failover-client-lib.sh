#!/usr/bin/env bash
#
# Helpers for the main iperf3 client in test-failover.sh. Its PID is recorded
# separately from the pool-mode client so a second iperf3 process cannot mask
# loss of the stream being measured.

# failover_start_main_iperf <duration> <target> <port> <streams> <log> <pidfile> [interval]
#   Optional interval preserves the default client command exactly when absent.
#   The client runs under timeout(1) with a wall clock of duration +
#   FAILOVER_IPERF_TIMEOUT_MARGIN (default 30s). --connect-timeout covers the
#   connect only, and a flaky far end can hang the final control exchange
#   forever (#11861). The pidfile records the timeout supervisor, whose cmdline
#   still carries the iperf3 match keys for failover_main_iperf_running.
failover_start_main_iperf() {
	local duration="$1" target="$2" port="$3" streams="$4" log="$5" pidfile="$6"
	local margin="${FAILOVER_IPERF_TIMEOUT_MARGIN:-30}"
	local interval="${7:-}"
	case "$margin" in ''|*[!0-9]*) margin=30 ;; esac
	local wall=$(( duration + margin ))
	incus exec "$CLUSTER_LAN_HOST" -- bash -c '
		interval_args=()
		if [[ -n "$8" ]]; then interval_args=(-i "$8"); fi
		timeout -k 5 "$7" iperf3 --json-stream --forceflush --connect-timeout 5000 "${interval_args[@]}" -t "$1" -c "$2" -p "$3" -P "$4" >"$5" 2>&1 &
		echo "$!" > "$6"
	' _ "$duration" "$target" "$port" "$streams" "$log" "$pidfile" "$wall" "$interval"
}

# #19123: the readings that bound a fast-takeover crash on iperf3's interval
# clock (iperf3_sum_parse.py measured_window). Every one is a CLOCK_MONOTONIC
# reading: a realtime clock can step between two readings, a monotonic one
# cannot, and a boot id names the boot it counts from. Each costs a python3
# start on the host it reads; without python3 a reading is missing and the
# parser takes no bounded window.

# failover_mono_now -- this host's CLOCK_MONOTONIC, seconds.
failover_mono_now() {
	python3 -I -c 'import time; print("%.6f" % time.clock_gettime(time.CLOCK_MONOTONIC))'
}

# failover_mono_reading <instance> [samples]
#   "<offset> <rtt> <at> <boot_id>": the instance's CLOCK_MONOTONIC minus
#   this host's, from the least-RTT of <samples> (default 3) round trips.
#   <at> is this host's CLOCK_MONOTONIC at that round trip's midpoint, where
#   the offset is right to +/-rtt/2; <boot_id> is the instance's. Exits
#   nonzero when no round trip answered.
failover_mono_reading() {
	python3 -I - "$1" "${2:-3}" <<'PY'
import subprocess
import sys
import time

instance, samples = sys.argv[1], int(sys.argv[2])
probe = (
    "import time; "
    "print('%.6f' % time.clock_gettime(time.CLOCK_MONOTONIC), "
    "open('/proc/sys/kernel/random/boot_id').read().strip())"
)
best = None
for _ in range(samples):
    sent = time.clock_gettime(time.CLOCK_MONOTONIC)
    try:
        out = subprocess.run(
            ["timeout", "10", "incus", "exec", instance, "--", "python3", "-I", "-c", probe],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, timeout=15,
        ).stdout.split()
    except (OSError, subprocess.SubprocessError):
        continue
    back = time.clock_gettime(time.CLOCK_MONOTONIC)
    if len(out) != 2:
        continue
    try:
        remote = float(out[0])
    except ValueError:
        continue
    rtt, mid = back - sent, (sent + back) / 2
    if best is None or rtt < best[1]:
        best = (remote - mid, rtt, mid, out[1])
if best is None:
    sys.exit(1)
print("%.6f %.6f %.6f %s" % best)
PY
}

# failover_arrival_launch <log>
#   On the LAN host, make <log>.arrivals hold one line,
#   "launch<TAB><CLOCK_MONOTONIC><TAB><boot_id>", read BEFORE the client
#   starts: iperf3 starts its interval clock later, so this bounds the clock's
#   zero from below. Call it just before failover_start_main_iperf. The file
#   is emptied first, so a failed reading leaves no stale launch line. Best
#   effort: it never fails the caller (test-failover runs under set -e).
failover_arrival_launch() {
	incus exec "$CLUSTER_LAN_HOST" -- bash -c '
		: >"$1.arrivals"
		python3 -I - "$1.arrivals" <<"PY" 2>/dev/null
import sys, time
stamp = time.clock_gettime(time.CLOCK_MONOTONIC)
boot = open("/proc/sys/kernel/random/boot_id").read().strip()
with open(sys.argv[1], "w") as out:
    out.write("launch\t%.6f\t%s\n" % (stamp, boot))
PY
	' _ "$1" &>/dev/null || :
}

# failover_start_arrival_stamper <log> <pidfile>
#   Appends every line the main client writes to <log> to <log>.arrivals as
#   "<CLOCK_MONOTONIC><TAB><line>", stamped on the LAN host as it is read.
#   iperf3 emits an interval line only after that interval's end, so
#   stamp - end bounds the interval clock's zero from above
#   (iperf3_sum_parse.py arrival_zero_bounds). tail follows the file by
#   inotify (-s 0.1 caps the poll fallback) and exits with the client
#   supervisor in <pidfile>; one python3 reader stamps the lines. Best
#   effort, like failover_arrival_launch.
failover_start_arrival_stamper() {
	incus exec "$CLUSTER_LAN_HOST" -- bash -c '
		pid=$(cat "$2" 2>/dev/null) || exit 0
		case "$pid" in ""|*[!0-9]*) exit 0 ;; esac
		{ tail -s 0.1 --pid="$pid" -n +1 -F "$1" 2>/dev/null | python3 -I -c "
import sys, time
for line in iter(sys.stdin.readline, \"\"):
    sys.stdout.write(\"%.6f\t%s\" % (time.clock_gettime(time.CLOCK_MONOTONIC), line))
    sys.stdout.flush()
" >>"$1.arrivals"; } </dev/null >/dev/null 2>&1 &
	' _ "$1" "$2" &>/dev/null || :
}

# failover_peer_lost_mono <instance> <offset> <boot_id> <dispatch>
#   The journal's CLOCK_MONOTONIC receipt stamp of <instance>'s first xpfd
#   "marking peer lost" entry on boot <boot_id> from 1 s before <dispatch>
#   (this host's CLOCK_MONOTONIC, mapped through <offset> as read by
#   failover_mono_reading; the second covers the mapping's error) to 5 s
#   after it (the detection ceiling), as "<CLOCK_MONOTONIC> <boot_id>";
#   nothing when there is none. The window is on <instance>'s own monotonic
#   clock, so its realtime skew does not matter. Reads the whole journal so
#   nothing is cut off mid-pipe; never fails the caller.
failover_peer_lost_mono() {
	timeout 30 incus exec "$1" -- journalctl -u xpfd --no-pager -o json --since -30min 2>/dev/null |
		python3 -I -c '
import json, sys
offset, boot, dispatch = float(sys.argv[1]), sys.argv[2].replace("-", "").lower(), float(sys.argv[3])
floor, ceiling, found = dispatch + offset - 1, dispatch + offset + 5, None
for row in sys.stdin:
    if found is not None:
        continue
    try:
        entry = json.loads(row)
        mono = int(entry["__MONOTONIC_TIMESTAMP"]) / 1e6
        entry_boot = str(entry["_BOOT_ID"]).replace("-", "").lower()
    except (ValueError, KeyError, TypeError):
        continue
    message = entry.get("MESSAGE")
    if entry_boot == boot and floor <= mono <= ceiling and isinstance(message, str) \
            and "cluster: peer heartbeat timeout, marking peer lost" in message:
        found = "%.6f %s" % (mono, entry_boot)
if found is not None:
    print(found)
' "$2" "$3" "$4" 2>/dev/null || :
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

# failover_pool_probe_verdict <probe-log-text>
#   Scores the #8280 post-failback pool-mode iperf3 probe (#18567). Prints
#   `pass` when the client finished (`iperf Done`), `busy` when the server
#   answered "the server is busy", and `fail` otherwise. A busy reply crossed
#   the firewall on the probe's own TCP control connection, so the pool-NAT
#   handshake worked, but the probe measured nothing: the caller reports it
#   as VOID, never as the #8341 data-path FAIL and never as a PASS.
failover_pool_probe_verdict() {
	local log="$1"
	if grep -q 'iperf Done' <<<"$log"; then
		echo pass
	elif grep -q 'the server is busy' <<<"$log"; then
		echo busy
	else
		echo fail
	fi
}
