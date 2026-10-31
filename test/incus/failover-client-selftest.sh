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
	if [[ "$command" == *"interval_args=()"* &&
	      "$command" == *'interval_args=(-i "$8")'* &&
	      "$command" == *"iperf3 --json-stream --forceflush --connect-timeout 5000 "* &&
	      "$command" == *'-t "$1" -c "$2" -p "$3" -P "$4"'* ]]; then
		COMMAND_SHAPE_OK=1
	fi
	shift 3
	"$@"
}

mkdir -p "$TMP_DIR/bin"
cat >"$TMP_DIR/bin/iperf3" <<'MOCK'
#!/usr/bin/env bash
[[ " $* " == *" --json-stream "* && " $* " == *" --forceflush "* ]] || exit 90
case " $* " in
	*" -p 5211 "*) args_file="${MOCK_ARGS_DIR}/main.args" ;;
	*" -p 5212 "*) args_file="${MOCK_ARGS_DIR}/interval.args" ;;
	*" -p 5210 "*) args_file="${MOCK_ARGS_DIR}/pool.args" ;;
	*) exit 91 ;;
esac
printf ' %s' "$@" >"$args_file"
printf '\n' >>"$args_file"
sleep 60 &
child=$!
trap 'kill "$child" 2>/dev/null || true; wait "$child" 2>/dev/null || true' TERM EXIT
wait "$child"
MOCK
chmod +x "$TMP_DIR/bin/iperf3"
PATH="${TMP_DIR}/bin:${PATH}"
export PATH
CLUSTER_LAN_HOST=local-test
MOCK_ARGS_DIR="$TMP_DIR"
export MOCK_ARGS_DIR
export FAILOVER_IPERF_TIMEOUT_MARGIN=30

failover_start_main_iperf 60 192.0.2.1 5211 8 "$TMP_DIR/main.log" "$TMP_DIR/main.pid"
main_pid=$(cat "$TMP_DIR/main.pid" 2>/dev/null || true)
if [[ "$COMMAND_SHAPE_OK" == 1 && "$main_pid" =~ ^[0-9]+$ ]] &&
   failover_main_iperf_running "$TMP_DIR/main.pid" 192.0.2.1 5211 8; then
	ok "JSON client command shape and main process identity are preserved"
else
	bad "JSON client command shape and main process identity are preserved"
fi
if ! grep -qE '(^| )-i( |$)' "$TMP_DIR/main.args"; then
	ok "omitted interval keeps the existing iperf3 command unchanged"
else
	bad "omitted interval keeps the existing iperf3 command unchanged"
fi

failover_start_main_iperf 60 192.0.2.1 5212 2 "$TMP_DIR/interval.log" "$TMP_DIR/interval.pid" 0.1
interval_pid=$(cat "$TMP_DIR/interval.pid" 2>/dev/null || true)
if [[ "$interval_pid" =~ ^[0-9]+$ ]] &&
   failover_main_iperf_running "$TMP_DIR/interval.pid" 192.0.2.1 5212 2 &&
   grep -qE '(^| )-i 0\.1( |$)' "$TMP_DIR/interval.args"; then
	ok "tracked client passes the configured 100-ms interval"
else
	bad "tracked client passes the configured 100-ms interval"
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
failover_stop_main_iperf "$TMP_DIR/interval.pid" 192.0.2.1 5212 2
if ! failover_main_iperf_running "$TMP_DIR/main.pid" 192.0.2.1 5211 8 &&
   ! failover_main_iperf_running "$TMP_DIR/interval.pid" 192.0.2.1 5212 2 &&
   kill -0 "$pool_pid" 2>/dev/null; then
	ok "termination stops only the tracked main JSON clients"
else
	bad "termination stops only the tracked main JSON clients"
fi
failover_stop_main_iperf "$TMP_DIR/pool.pid" 192.0.2.1 5210 2
if ! kill -0 "$pool_pid" 2>/dev/null; then
	ok "separate client termination remains scoped to its pidfile"
else
	bad "separate client termination remains scoped to its pidfile"
fi


# #18567: the post-failback pool probe verdict and its port.
for cell in \
	"pass|[  5]   0.00-2.00   sec  1.2 GBytes  5.1 Gbits/sec  receiver
iperf Done." \
	"busy|iperf3: error - the server is busy running a test. try again later" \
	"fail|iperf3: error - unable to connect to server - server may have stopped running or not be running: Connection timed out" \
	"fail|[  5]   0.00-1.00   sec   640 KBytes  5.24 Mbits/sec  receiver
[  5]   1.00-2.00   sec  0.00 Bytes  0.00 bits/sec" \
	"fail|" ; do
	want=${cell%%|*}
	got=$(failover_pool_probe_verdict "${cell#*|}")
	if [[ "$got" == "$want" ]]; then
		ok "pool probe verdict: ${want} for '${cell#*|}'"
	else
		bad "pool probe verdict: want ${want}, got ${got} for '${cell#*|}'"
	fi
done
# A client killed by timeout(1) prints interval and receiver lines but no
# "iperf Done"; the fixture above pins that it scores fail, not pass.
TF="${SCRIPT_DIR}/test-failover.sh"
# shellcheck disable=SC2016 # the patterns match the script's literal ${...}
{
	pool_port=$(sed -n 's/^POOL_PORT="${POOL_PORT:-\([0-9]*\)}"$/\1/p' "$TF")
	post_port=$(sed -n 's/^POOL_POST_PORT="${POOL_POST_PORT:-\([0-9]*\)}"$/\1/p' "$TF")
	main_port=$(sed -n 's/^IPERF_PORT="${IPERF_PORT:-\([0-9]*\)}"$/\1/p' "$TF")
	post_assigns=$(grep -c '^[[:space:]]*POOL_POST_PORT=' "$TF")
	phase1b_on_pool=$(grep -c -- '-p ${POOL_PORT} -P 2 > /tmp/iperf3-pool-8280.log' "$TF")
	probe_on_post=$(grep -c -- '-p ${POOL_POST_PORT} > /tmp/iperf3-pool-8280-post.log' "$TF")
}
if [[ -z "$pool_port" || -z "$post_port" || -z "$main_port" ]]; then
	bad "could not read the POOL_PORT / POOL_POST_PORT / IPERF_PORT defaults from test-failover.sh (got '${pool_port}' '${post_port}' '${main_port}'): the port cell is not measuring anything"
elif [[ "$post_assigns" == 1 && "$phase1b_on_pool" == 1 && "$probe_on_post" == 1 &&
      "$pool_port" != "$post_port" && "$main_port" != "$post_port" ]]; then
	ok "the post-failback pool probe uses its own port (${post_port}; Phase 1b runs on POOL_PORT ${pool_port}, the main client on ${main_port})"
else
	bad "the post-failback pool probe must not share a running client's port (POOL_PORT=${pool_port} IPERF_PORT=${main_port} POOL_POST_PORT=${post_port}; POOL_POST_PORT assignments=${post_assigns}, Phase 1b on POOL_PORT=${phase1b_on_pool}, probe on POOL_POST_PORT=${probe_on_post})"
fi
# The caller must route each verdict to the right counter: busy is a VOID,
# anything else that is not pass is the #8341 FAIL. Pinned on the script text,
# because the arms run only on a live cluster.
tf_case=$(awk '/case "\$\(failover_pool_probe_verdict "\$pool_log"\)" in/,/^[[:space:]]*esac/' "${SCRIPT_DIR}/test-failover.sh")
if grep -Pzq 'pass\)\n\s*pass "a pool-mode TCP flow connects' <<<"$tf_case" &&
   grep -Pzq 'busy\)\n\s*void "a pool-mode TCP flow was NOT MEASURED' <<<"$tf_case" &&
   grep -Pzq 'fail\)\n\s*fail "a pool-mode TCP flow did not complete' <<<"$tf_case" &&
   grep -Pzq '\*\)\n\s*fail "the pool probe verdict helper returned an unrecognised' <<<"$tf_case"; then
	ok "test-failover routes pool probe verdicts: pass->pass, busy->void, fail->fail, other->fail(unrecognised)"
else
	bad "test-failover must route pool probe verdicts: pass->pass, busy->void, fail->fail, other->fail(unrecognised)"
fi
# A probe whose launch failed must be a VOID, never scored from a previous
# run's log: both launch steps record failure and the first branch checks it.
# shellcheck disable=SC2016 # the patterns match the script's literal text
if grep -q -- '-- rm -f /tmp/iperf3-pool-8280-post.log || pool_probe_started=0$' "$TF" &&
   grep -q -- '/tmp/iperf3-pool-8280-post.log 2>&1 &" || pool_probe_started=0$' "$TF" &&
   grep -Pzq 'if \[\[ "\$pool_probe_started" != 1 \]\]; then\n\s*void "#8280/#8341: the post-failback pool probe could not be started' "$TF"; then
	ok "a pool probe that failed to launch is a VOID, not scored from a stale log"
else
	bad "a pool probe that failed to launch must be a VOID, not scored from a stale log"
fi

echo "----------------------------------------"
echo "failover client selftest: $PASS passed, $FAIL failed"
[[ $FAIL -eq 0 ]]
