#!/usr/bin/env bash
# Hermetic JSON-stream client checks; the incus function below executes only
# the client lib's remote shell locally, with a fake iperf3 executable.
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=test/incus/failover-client-lib.sh
source "${SCRIPT_DIR}/failover-client-lib.sh"

PASS=0
FAIL=0
ok() { echo "PASS: $1"; PASS=$((PASS + 1)); }
bad() { echo "FAIL: $1" >&2; FAIL=$((FAIL + 1)); }

TMP_DIR=$(mktemp -d)
trap 'failover_stop_main_iperf "$TMP_DIR/main.pid" 192.0.2.1 5211 8 || true; failover_stop_main_iperf "$TMP_DIR/pool.pid" 192.0.2.1 5210 2 || true; rm -rf "$TMP_DIR"' EXIT

CONNECT_ERROR_FIXTURE="${SCRIPT_DIR}/failover-client-connect-error.jsonl"
if failover_json_stream_connect_error "$CONNECT_ERROR_FIXTURE"; then
	ok "captured iperf3 error event selects the startup retry path"
else
	bad "captured iperf3 error event selects the startup retry path"
fi

CLUSTER_LAN_HOST=local-test
incus() {
	[[ "$1" == exec && "$2" == "$CLUSTER_LAN_HOST" && "$3" == -- ]] || return 90
	shift 3
	"$@"
}
if failover_main_iperf_connect_failed "$CONNECT_ERROR_FIXTURE"; then
	ok "remote retry wrapper parses the captured JSON failure event"
else
	bad "remote retry wrapper parses the captured JSON failure event"
fi
if failover_json_stream_completed "$CONNECT_ERROR_FIXTURE"; then
	bad "failed connect with event:end is not successful completion"
else
	ok "failed connect with event:end is not successful completion"
fi
if failover_main_iperf_result_complete "$CONNECT_ERROR_FIXTURE"; then
	bad "failed connect with event:end is not rejoin/manual survival evidence"
else
	ok "failed connect with event:end is not rejoin/manual survival evidence"
fi

cat >"$TMP_DIR/healthy-completed.jsonl" <<'JSON'
{"event":"start","data":{"test_start":{"duration":120}}}
{"event":"interval","data":{"sum":{"start":0,"end":1,"bits_per_second":8000000000}}}
{"event":"end","data":{}}
JSON
if failover_json_stream_completed "$TMP_DIR/healthy-completed.jsonl"; then
	ok "healthy JSON event:end completes the result waiter"
else
	bad "healthy JSON event:end completes the result waiter"
fi
if failover_main_iperf_result_complete "$TMP_DIR/healthy-completed.jsonl"; then
	ok "healthy JSON event:end is rejoin/manual survival evidence"
else
	bad "healthy JSON event:end is rejoin/manual survival evidence"
fi
if grep -Eq 'iperf Done|\[SUM\].*sender' "$TMP_DIR/healthy-completed.jsonl"; then
	bad "legacy text-only waiter misses healthy completed JSON stream (RED-before)"
else
	ok "legacy text-only waiter misses healthy completed JSON stream (RED-before)"
fi

cat >"$TMP_DIR/healthy.jsonl" <<'JSON'
{"event":"start","data":{"test_start":{"duration":120}}}
{"event":"interval","data":{"sum":{"start":0,"end":1,"bits_per_second":8000000000}}}
JSON
if failover_json_stream_connect_error "$TMP_DIR/healthy.jsonl"; then
	bad "healthy JSON stream start does not trigger a retry"
else
	ok "healthy JSON stream start does not trigger a retry"
fi
if failover_main_iperf_connect_failed "$TMP_DIR/healthy.jsonl"; then
	bad "remote retry wrapper does not retry a healthy stream start"
else
	ok "remote retry wrapper does not retry a healthy stream start"
fi

printf '%s\n' '{"event":"error","data":"unable to open local socket"}' \
	>"$TMP_DIR/unrelated-error.jsonl"
if failover_json_stream_connect_error "$TMP_DIR/unrelated-error.jsonl"; then
	bad "unrelated JSON error event does not trigger a retry"
else
	ok "unrelated JSON error event does not trigger a retry"
fi
if failover_main_iperf_connect_failed "$TMP_DIR/unrelated-error.jsonl"; then
	bad "remote retry wrapper ignores unrelated JSON error events"
else
	ok "remote retry wrapper ignores unrelated JSON error events"
fi
if failover_json_stream_completed "$TMP_DIR/healthy.jsonl"; then
	bad "healthy stream without end event remains incomplete"
else
	ok "healthy stream without end event remains incomplete"
fi

cat >"$TMP_DIR/truncated.jsonl" <<'JSON'
{"event":"end"
JSON
if failover_json_stream_completed "$TMP_DIR/truncated.jsonl"; then
	bad "truncated JSON end line is not completion evidence"
else
	ok "truncated JSON end line is not completion evidence"
fi

printf '%s\n' '{"event":"end","nonstandard":NaN}' >"$TMP_DIR/nonstandard.jsonl"
if failover_json_stream_completed "$TMP_DIR/nonstandard.jsonl"; then
	bad "non-standard JSON constants do not count as valid completion"
else
	ok "non-standard JSON constants do not count as valid completion"
fi

printf '%s\n' '{"event":"error","data":"unable to connect","nonstandard":NaN}' \
	>"$TMP_DIR/nonstandard-error.jsonl"
if failover_json_stream_connect_error "$TMP_DIR/nonstandard-error.jsonl"; then
	bad "non-standard JSON error event does not trigger a retry"
else
	ok "non-standard JSON error event does not trigger a retry"
fi

printf '%s\n' '{"completed":true,"observed_end_sec":120}' >"$TMP_DIR/metrics.json"
if failover_json_stream_completed "$TMP_DIR/metrics.json"; then
	ok "validated metrics completed flag is accepted"
else
	bad "validated metrics completed flag is accepted"
fi

COMMAND_SHAPE_OK=0
incus() {
	[[ "$1" == exec && "$2" == "$CLUSTER_LAN_HOST" && "$3" == -- ]] || return 90
	local command="$6"
	if [[ "$command" == *"iperf3 --json-stream --forceflush --connect-timeout 5000 -t"* &&
	      "$command" == *"-p \"\$3\" -P \"\$4\""* &&
	      "$command" != *"-i 1"* ]]; then
		COMMAND_SHAPE_OK=1
	fi
	shift 3
	"$@"
}

mkdir -p "$TMP_DIR/bin"
cat >"$TMP_DIR/bin/iperf3" <<'MOCK'
#!/usr/bin/env bash
[[ " $* " == *" --json-stream "* && " $* " == *" --forceflush "* && " $* " != *" -i 1 "* ]] || exit 90
sleep 60 &
child=$!
trap 'kill "$child" 2>/dev/null || true; wait "$child" 2>/dev/null || true' TERM EXIT
wait "$child"
MOCK
chmod +x "$TMP_DIR/bin/iperf3"
PATH="${TMP_DIR}/bin:${PATH}"
export PATH
CLUSTER_LAN_HOST=local-test
export FAILOVER_IPERF_TIMEOUT_MARGIN=30

failover_start_main_iperf 60 192.0.2.1 5211 8 "$TMP_DIR/main.log" "$TMP_DIR/main.pid"
main_pid=$(cat "$TMP_DIR/main.pid" 2>/dev/null || true)
if [[ "$COMMAND_SHAPE_OK" == 1 && "$main_pid" =~ ^[0-9]+$ ]] &&
   failover_main_iperf_running "$TMP_DIR/main.pid" 192.0.2.1 5211 8; then
	ok "JSON client command shape and main process identity are preserved"
else
	bad "JSON client command shape and main process identity are preserved"
fi

failover_start_main_iperf 60 192.0.2.1 5210 2 "$TMP_DIR/pool.log" "$TMP_DIR/pool.pid"
pool_pid=$(cat "$TMP_DIR/pool.pid" 2>/dev/null || true)
if [[ "$pool_pid" =~ ^[0-9]+$ ]] &&
   ! failover_main_iperf_running "$TMP_DIR/pool.pid" 192.0.2.1 5211 8; then
	ok "main process identification rejects a second client tuple"
else
	bad "main process identification rejects a second client tuple"
fi

failover_stop_main_iperf "$TMP_DIR/main.pid" 192.0.2.1 5211 8
if ! failover_main_iperf_running "$TMP_DIR/main.pid" 192.0.2.1 5211 8 &&
   kill -0 "$pool_pid" 2>/dev/null; then
	ok "termination stops only the tracked main JSON client"
else
	bad "termination stops only the tracked main JSON client"
fi
failover_stop_main_iperf "$TMP_DIR/pool.pid" 192.0.2.1 5210 2
if ! kill -0 "$pool_pid" 2>/dev/null; then
	ok "separate client termination remains scoped to its pidfile"
else
	bad "separate client termination remains scoped to its pidfile"
fi

echo "----------------------------------------"
echo "failover client selftest: $PASS passed, $FAIL failed"
[[ $FAIL -eq 0 ]]
