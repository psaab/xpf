#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
TMP_DIR="$(mktemp -d "${ROOT}/.ha-assurance-selftest.XXXXXX")"
trap 'rm -rf "$TMP_DIR"' EXIT
OUT="${TMP_DIR}/stdout"
ERR="${TMP_DIR}/stderr"
GATE_ERR="${TMP_DIR}/gate-stderr"
ACCESSOR_OUT="${TMP_DIR}/accessor-stdout"
ACCESSOR_ERR="${TMP_DIR}/accessor-stderr"
LOCAL_IPERF_METRICS="${TMP_DIR}/metrics.json"
ARTIFACT_DIR="${TMP_DIR}/artifacts"
BPFRX_CLUSTER_ENV="${ROOT}/test/incus/loss-userspace-cluster.env"
HA_ASSURANCE_SOURCE_ONLY=1
export ARTIFACT_DIR BPFRX_CLUSTER_ENV HA_ASSURANCE_SOURCE_ONLY
# Source the actual legacy consumers and their actual shared gate without
# entering the script's runtime path (which would query a cluster).
# shellcheck disable=SC1091
source "${ROOT}/scripts/userspace-ha-failover-validation.sh"
unset HA_ASSURANCE_SOURCE_ONLY
LOCAL_IPERF_METRICS="${TMP_DIR}/metrics.json"

IPERF_DURATION=60
IPERF_COMPLETION_GRACE_SEC=2

fail_test() {
	printf 'FAIL ha-assurance-selftest: %s\n' "$*" >&2
	exit 1
}

assert_eq() {
	local actual="$1"
	local expected="$2"
	local context="$3"
	[[ "$actual" == "$expected" ]] || fail_test "${context}: expected '${expected}', got '${actual}'"
}

assert_contains() {
	local text="$1"
	local needle="$2"
	local context="$3"
	[[ "$text" == *"$needle"* ]] || fail_test "${context}: missing '${needle}'"
}

assert_not_contains() {
	local text="$1"
	local needle="$2"
	local context="$3"
	[[ "$text" != *"$needle"* ]] || fail_test "${context}: unexpectedly contains '${needle}'"
}

reset_verdict() {
	FAILED=0
	VOIDS=0
	METRIC_RESULT=""
	: >"${OUT}"
	: >"${ERR}"
	: >"${GATE_ERR}"
}

write_metrics() {
	python3 - "${LOCAL_IPERF_METRICS}" "$@" <<'PY'
import json
import pathlib
import sys

metrics = {
    "ok": True,
    "error": "",
    "interval_gbps": [1.0],
    "avg_gbps": 1.0,
    "zero_intervals_total": 1,
    "stream_zero_intervals_total": 0,
    "zero_streams_total": 0,
    "retransmits": 7,
    "collapse_detected": False,
    "collapse_reason": "",
    "completed": True,
    "observed_end_sec": 60.0,
}
for argument in sys.argv[2:]:
    if argument.startswith("omit:"):
        del metrics[argument[5:]]
        continue
    name, separator, raw_value = argument.partition("=")
    if not separator:
        raise SystemExit(f"invalid fixture override: {argument}")
    metrics[name] = json.loads(raw_value)
pathlib.Path(sys.argv[1]).write_text(json.dumps(metrics), encoding="utf-8")
PY
}

write_raw_avg() {
	printf '{"ok":true,"error":"","interval_gbps":[1.0],"avg_gbps":%s,"zero_intervals_total":0,"stream_zero_intervals_total":0,"zero_streams_total":0,"retransmits":0,"collapse_detected":false,"collapse_reason":"","completed":true,"observed_end_sec":60}\n' "$1" >"${LOCAL_IPERF_METRICS}"
}

write_raw_interval() {
	printf '{"ok":true,"error":"","interval_gbps":[%s],"avg_gbps":1.0,"zero_intervals_total":0,"stream_zero_intervals_total":0,"zero_streams_total":0,"retransmits":0,"collapse_detected":false,"collapse_reason":"","completed":true,"observed_end_sec":60}\n' "$1" >"${LOCAL_IPERF_METRICS}"
}

assert_helper_status() {
	local expected="$1"
	shift
	local actual
	: >"${OUT}"
	: >"${ERR}"
	if "$@" >"${OUT}" 2>"${ERR}"; then
		actual=0
	else
		actual=$?
	fi
	if [[ "$actual" != "$expected" ]]; then
		fail_test "$* status: expected ${expected}, got ${actual}; stdout=$(<"${OUT}"); stderr=$(<"${ERR}")"
	fi
}

assert_helper_value() {
	local expected="$1"
	shift
	assert_helper_status 0 "$@"
	assert_eq "$(<"${OUT}")" "$expected" "$* value"
}

write_interface_snapshot() {
	python3 - "$1" "$2" "$3" "$4" <<'PY'
import pathlib
import sys

path, interface, rx, tx = sys.argv[1:]
columns = ["0"] * 20
columns[10] = rx
columns[11] = tx
columns[19] = interface
pathlib.Path(path).write_text(
    "Userspace bindings:" + chr(10) + "Slot Queue Header" + chr(10) + " ".join(columns) + chr(10),
    encoding="utf-8",
)
PY
}

run_gate_reject() {
	local expected_reason="$1"
	local gate_output gate_status
	if gate_output="$(ha_metrics_gate "${LOCAL_IPERF_METRICS}" 2>"${GATE_ERR}")"; then
		gate_status=0
	else
		gate_status=$?
	fi
	assert_eq "$gate_status" 2 "gate status for ${expected_reason}"
	assert_eq "$gate_output" "" "gate stdout on VOID"
	assert_contains "$(<"${GATE_ERR}")" "$expected_reason" "gate reason"
}

run_whole_run_consumer() {
	validate_whole_run_metrics >"${OUT}" 2>"${ERR}"
}

assert_void_consumer() {
	local expected_reason="$1"
	reset_verdict
	run_gate_reject "$expected_reason"
	run_whole_run_consumer
	assert_eq "$FAILED" 0 "${expected_reason}: no measured metric FAIL"
	assert_eq "$VOIDS" 1 "${expected_reason}: one VOID cause"
	assert_eq "$(<"${OUT}")" "" "${expected_reason}: no metric verdict output"
	assert_contains "$(<"${ERR}")" 'VOID iperf3 metrics:' "${expected_reason}: consumer VOID status"
	assert_contains "$(<"${ERR}")" "$expected_reason" "${expected_reason}: consumer VOID reason"
	if legacy_verdict_status; then
		fail_test "${expected_reason}: VOID-only final status returned PASS"
	else
		assert_eq "$?" 77 "${expected_reason}: VOID-only exit status"
	fi
}

assert_all_whole_run_accessors_void() {
	local accessor status
	local -a accessors=(
		count_zero_intervals
		count_stream_zero_intervals
		count_zero_streams
		extract_sender_throughput
		extract_retransmits
		iperf_collapse_detected
		iperf_collapse_reason
		iperf_completed_local
		iperf_effectively_completed_local
	)
	for accessor in "${accessors[@]}"; do
		: >"${ACCESSOR_OUT}"
		: >"${ACCESSOR_ERR}"
		if "$accessor" >"${ACCESSOR_OUT}" 2>"${ACCESSOR_ERR}"; then
			status=0
		else
			status=$?
		fi
		assert_eq "$status" 2 "${accessor} gate status"
		assert_eq "$(<"${ACCESSOR_OUT}")" "" "${accessor} stdout on VOID"
		assert_contains "${IPERF_METRICS_GATE_REASON}" "metrics ok=false" "${accessor} gate reason"
	done
}

printf 'M2.4 (1/8) ok:false fail-closed + sticky FAIL\n'
write_metrics 'ok=false' 'error="metrics_parse_failed"' 'zero_intervals_total=0' 'collapse_detected=false' 'completed=true'
reset_verdict
run_gate_reject 'metrics ok=false: metrics_parse_failed'
assert_all_whole_run_accessors_void
fail 'prior measured FAIL' 2>>"${ERR}"
run_whole_run_consumer
assert_eq "$FAILED" 1 'ok:false must preserve prior measured FAIL'
assert_eq "$VOIDS" 1 'ok:false ordinary VOID count'
assert_eq "$(<"${OUT}")" "" 'ok:false suppresses all metric comparisons'
assert_contains "$(<"${ERR}")" 'VOID iperf3 metrics: metrics ok=false: metrics_parse_failed' 'ok:false VOID evidence'
if legacy_verdict_status; then
	fail_test 'FAIL followed by metrics VOID returned PASS'
else
	assert_eq "$?" 1 'FAIL followed by metrics VOID must remain FAIL'
fi

printf 'M2.4 (2/8) truncated JSON is rule-1 VOID\n'
reset_verdict
printf '{"ok":true,"interval_gbps":[' >"${LOCAL_IPERF_METRICS}"
assert_void_consumer 'invalid JSON'

printf 'M2.4 (3/8) missing metrics file is rule-1 VOID\n'
reset_verdict
LOCAL_IPERF_METRICS="${TMP_DIR}/missing-metrics.json"
assert_void_consumer "metrics file ${LOCAL_IPERF_METRICS}: absent"
LOCAL_IPERF_METRICS="${TMP_DIR}/metrics.json"

printf 'M2.4 (4/8) ok:true with empty intervals is rule-4 VOID\n'
write_metrics 'interval_gbps=[]' 'zero_intervals_total=0' 'collapse_detected=false' 'completed=true'
assert_void_consumer 'no full iperf3 intervals'

printf 'M2.4 (5/8) non-empty error is rule-3 VOID\n'
write_metrics 'error="producer reported an error"'
assert_void_consumer 'metrics error: producer reported an error'

printf 'M2.4 (6/8) wrong scalar types, omissions, and N12 JSON numbers\n'
write_metrics 'avg_gbps="0"'
assert_void_consumer 'metrics field avg_gbps: malformed'
write_metrics 'omit:collapse_detected'
assert_void_consumer 'metrics field collapse_detected: absent'
for field in avg_gbps zero_intervals_total stream_zero_intervals_total zero_streams_total retransmits observed_end_sec; do
	write_metrics "${field}=true"
	assert_void_consumer "metrics field ${field}: malformed"
done
write_metrics 'zero_intervals_total=0.0'
assert_void_consumer 'metrics field zero_intervals_total: malformed'
for constant in NaN Infinity -Infinity; do
	write_raw_avg "$constant"
	assert_void_consumer 'invalid JSON'
done
write_raw_avg '1e999'
assert_void_consumer 'metrics JSON: non-finite number at $.avg_gbps'
write_metrics 'interval_gbps=[true]'
assert_void_consumer 'metrics field interval_gbps[0]: malformed'
for constant in NaN Infinity -Infinity; do
	write_raw_interval "$constant"
	assert_void_consumer 'invalid JSON'
done
write_raw_interval '1e999'
assert_void_consumer 'metrics JSON: non-finite number at $.interval_gbps[0]'
write_metrics 'avg_gbps=1' 'observed_end_sec=60.25'
if ! gate_output="$(ha_metrics_gate "${LOCAL_IPERF_METRICS}" 2>"${GATE_ERR}")"; then
	fail_test "finite JSON integer/decimal fields rejected: $(<"${GATE_ERR}")"
fi
assert_contains "$gate_output" 'avg_gbps=1' 'finite integer average'
assert_contains "$gate_output" 'observed_end_sec=60.25' 'finite decimal observed end'

printf 'M2.4 (7/8) legacy threshold and completion boundary parity\n'
check_boundary() {
	local failed="$1"
	local output_text="$2"
	shift 2
	reset_verdict
	write_metrics "$@"
	run_whole_run_consumer
	assert_eq "$VOIDS" 0 "boundary ${output_text}: no VOID"
	assert_eq "$FAILED" "$failed" "boundary ${output_text}: measured status"
	assert_contains "$(<"${OUT}")"$'\n'"$(<"${ERR}")" "$output_text" "boundary output"
}
check_boundary 0 'PASS  1 zero-throughput intervals' 'zero_intervals_total=1'
check_boundary 0 'PASS  2 zero-throughput intervals' 'zero_intervals_total=2'
check_boundary 1 'FAIL  3 zero-throughput intervals' 'zero_intervals_total=3'
check_boundary 0 'PASS  -1 per-stream zero-throughput intervals' 'stream_zero_intervals_total=-1'
check_boundary 0 'PASS  0 per-stream zero-throughput intervals' 'stream_zero_intervals_total=0'
check_boundary 1 'FAIL  1 per-stream zero-throughput intervals' 'stream_zero_intervals_total=1' 'zero_streams_total=1'
check_boundary 1 'FAIL  sender throughput too low: 0.999 Gbps' 'avg_gbps=0.999'
check_boundary 0 'PASS  sender throughput 1.000 Gbps' 'avg_gbps=1.0'
check_boundary 0 'PASS  sender throughput 1.001 Gbps' 'avg_gbps=1.001'
check_boundary 1 'FAIL  iperf3 interval collapse detected' 'collapse_detected=true' 'collapse_reason="fixture collapse"'
check_boundary 0 'PASS  iperf3 interval collapse not detected' 'collapse_detected=false'
check_boundary 0 'PASS  iperf3 completed successfully' 'completed=true'
check_boundary 0 'PASS  iperf3 data transfer completed with adequate throughput' 'completed=false' 'observed_end_sec=58' 'avg_gbps=1.0'

write_metrics 'completed=false' 'observed_end_sec=58'
if iperf_effectively_completed_local; then
	fallback_status=0
else
	fallback_status=$?
fi
assert_eq "$fallback_status" 0 'observed-end fallback at duration minus grace'
write_metrics 'completed=false' 'observed_end_sec=57'
if iperf_effectively_completed_local; then
	fallback_status=0
else
	fallback_status=$?
fi
assert_eq "$fallback_status" 1 'observed-end fallback below duration minus grace'

printf 'M2.4 (8/8) recent-stream blind markers are VOID, valid intervals compare\n'
RECENT_FIXTURE=""
run_host() { printf '%s' "$RECENT_FIXTURE"; }
assert_blind_recent() {
	local description="$1"
	local marker_output marker_status
	if marker_output="$(recent_dead_streams 2>"${GATE_ERR}")"; then
		marker_status=0
	else
		marker_status=$?
	fi
	assert_eq "$marker_status" 2 "${description}: blind marker status"
	assert_eq "$marker_output" "" "${description}: blind marker stdout"
	reset_verdict
	validate_recent_dead_streams "recent selftest" >"${OUT}" 2>"${ERR}"
	assert_eq "$FAILED" 0 "${description}: blind evidence is not FAIL"
	assert_eq "$VOIDS" 1 "${description}: one VOID cause"
	assert_eq "$(<"${OUT}")" "" "${description}: comparison suppressed"
	assert_contains "$(<"${ERR}")" 'VOID recent selftest: recent iperf3 interval evidence is blind' "${description}: consumer VOID"
}
assert_blind_recent 'empty event stream'
RECENT_VALID='{"event":"interval","data":{"sum":{"start":0,"end":1,"bits_per_second":1000},"streams":[{"socket":1,"bits_per_second":1000},{"socket":2,"bits_per_second":1000},{"socket":3,"bits_per_second":1000},{"socket":4,"bits_per_second":1000}]}}'
RECENT_FIXTURE='not json'
assert_blind_recent 'malformed JSON line'
RECENT_FIXTURE='{"event":"interval","data":{"sum":{},"streams":[]}}'
assert_blind_recent 'malformed interval event'
RECENT_FIXTURE='{"event":"interval","data":{"sum":{"bits_per_second":1000},"streams":[]}}'
assert_blind_recent 'empty interval stream list'
RECENT_FIXTURE="${RECENT_VALID}"$'\ntruncated'
assert_blind_recent 'valid event followed by malformed line'
RECENT_FIXTURE="$RECENT_VALID"
reset_verdict
validate_recent_dead_streams 'recent selftest' >"${OUT}" 2>"${ERR}"
assert_eq "$FAILED" 0 'valid interval measured status'
assert_eq "$VOIDS" 0 'valid interval no VOID'
assert_contains "$(<"${OUT}")" 'PASS  recent selftest: all 4 streams carrying traffic' 'valid interval comparison'
validate_recent_preflight_metrics 1 >"${OUT}" 2>"${ERR}"
assert_eq "$FAILED" 0 'valid preflight interval measured status'
assert_eq "$VOIDS" 0 'valid preflight interval no VOID'
assert_contains "$(<"${OUT}")" 'PASS  steady-state preflight: 0 zero-throughput intervals' 'valid preflight comparison'

printf 'N6 gate count handoff equals fixture interval_gbps length\n'
write_metrics 'interval_gbps=[0.25,1.25,2.5]'
if ! gate_output="$(ha_metrics_gate "${LOCAL_IPERF_METRICS}" 2>"${GATE_ERR}")"; then
	fail_test "N6 valid fixture rejected: $(<"${GATE_ERR}")"
fi
# This eval is the documented M1 caller transport: use stdout only on status 0.
eval "$gate_output"
fixture_count="$(python3 - "${LOCAL_IPERF_METRICS}" <<'PY'
import json
import pathlib
import sys
print(len(json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))["interval_gbps"]))
PY
)"
assert_eq "$full_interval_count" "$fixture_count" 'N6 full_interval_count handoff'
evidence_note="json-stream avg_gbps from ${LOCAL_IPERF_METRICS}; ${full_interval_count} full intervals"
assert_contains "$evidence_note" "; ${fixture_count} full intervals" 'N6 evidence-note interval count'
printf 'Shared pure HA helper API fixtures\n'

printf 'Full production renderer goldens feed the shell parser API\n'
STATISTICS_GOLDEN="${ROOT}/pkg/grpcapi/testdata/show_chassis_cluster_data_plane_statistics_11581.golden"
INTERFACES_GOLDEN="${ROOT}/pkg/grpcapi/testdata/show_chassis_cluster_data_plane_interfaces_11581.golden"
STATISTICS_RENDERED="${TMP_DIR}/production-statistics.txt"
INTERFACES_RENDERED="${TMP_DIR}/production-interfaces.txt"
python3 - "$STATISTICS_GOLDEN" "$INTERFACES_GOLDEN" \
	"$STATISTICS_RENDERED" "$INTERFACES_RENDERED" <<'PY'
import pathlib
import sys

statistics_golden, interfaces_golden, statistics_out, interfaces_out = map(pathlib.Path, sys.argv[1:])
for source, output, method in (
    (statistics_golden, statistics_out, "Server.showChassisClusterDataPlaneStatistics"),
    (interfaces_golden, interfaces_out, "Server.showChassisClusterDataPlaneInterfaces"),
):
    lines = source.read_text(encoding="utf-8").splitlines()
    expected = [
        f"# #11581 full-renderer fixture: {method}",
        "# transcript:",
        "# consumer: test/incus/ha-assurance-selftest.sh (assertion-groups slice)",
    ]
    if len(lines) < 4 or lines[0] != expected[0] or not lines[1].startswith(expected[1]) or lines[2] != expected[2]:
        raise SystemExit(f"{source}: missing or incorrect full-renderer producer/consumer header")
    output.write_text("\n".join(lines[3:]) + "\n", encoding="utf-8")
PY
assert_helper_value 321 ha_sync_stats_value "${STATISTICS_RENDERED}" 'Session create' sent
assert_helper_value 321 ha_sync_stats_value "${STATISTICS_RENDERED}" 'Session create' received
assert_helper_value 0 ha_status_summary_value "${STATISTICS_RENDERED}" 'Session delta pending'
assert_helper_value 5 ha_status_summary_value "${STATISTICS_RENDERED}" 'Session delta drained'
assert_helper_status 0 ha_session_sync_idle_sample fw0 fw1 "${STATISTICS_RENDERED}" "${STATISTICS_RENDERED}"
assert_helper_value 18 ha_status_summary_value "${STATISTICS_RENDERED}" 'Session misses'
assert_helper_value 9000 ha_interface_packets_value "${INTERFACES_RENDERED}" 'ge-[0-9]+-0-1' rx
assert_helper_value 2600 ha_interface_packets_value "${INTERFACES_RENDERED}" 'ge-[0-9]+-0-2' tx
assert_helper_value 4800 ha_status_fabric_tx_packets "${INTERFACES_RENDERED}"

SYNC_SOURCE="${TMP_DIR}/sync-source.txt"
SYNC_TARGET="${TMP_DIR}/sync-target.txt"
cat >"${SYNC_SOURCE}" <<'EOF'
Services Synchronized:
Service Sent Received
Session create 5 5

Session delta pending: 0
Session delta drained: 12
EOF
cat >"${SYNC_TARGET}" <<'EOF'
Services Synchronized:
Service Sent Received
Session create 5 5

Session delta pending: 0
Session delta drained: 19
EOF
assert_helper_value 0 ha_status_summary_value "${SYNC_TARGET}" 'Session delta pending'
assert_helper_value 19 ha_status_summary_value "${SYNC_TARGET}" 'Session delta drained'
assert_helper_status 2 ha_status_summary_value "${SYNC_TARGET}" 'Missing label'
assert_helper_value 5 ha_sync_stats_value "${SYNC_SOURCE}" 'Session create' sent
assert_helper_value 5 ha_sync_stats_value "${SYNC_TARGET}" 'Session create' received
assert_helper_status 0 ha_session_sync_idle_sample fw0 fw1 "${SYNC_SOURCE}" "${SYNC_TARGET}"

SYNC_REVERSE_SOURCE="${TMP_DIR}/sync-reverse-source.txt"
SYNC_REVERSE_TARGET="${TMP_DIR}/sync-reverse-target.txt"
cat >"${SYNC_REVERSE_SOURCE}" <<'EOF'
Services Synchronized:
Session create 7 7

Session delta pending: 0
Session delta drained: 0
EOF
cat >"${SYNC_REVERSE_TARGET}" <<'EOF'
Services Synchronized:
Session create 7 7

Session delta pending: 0
Session delta drained: 0
EOF
assert_helper_status 0 ha_session_sync_idle_sample fw1 fw0 "${SYNC_REVERSE_SOURCE}" "${SYNC_REVERSE_TARGET}"
SYNC_NOT_IDLE="${TMP_DIR}/sync-not-idle.txt"
cat >"${SYNC_NOT_IDLE}" <<'EOF'
Services Synchronized:
Session create 4 5

Session delta pending: 1
Session delta drained: 0
EOF
assert_helper_status 1 ha_session_sync_idle_sample fw0 fw1 "${SYNC_SOURCE}" "${SYNC_NOT_IDLE}"
SYNC_MISSING_DRAINED="${TMP_DIR}/sync-missing-drained.txt"
cat >"${SYNC_MISSING_DRAINED}" <<'EOF'
Services Synchronized:
Session create 5 5

Session delta pending: 0
EOF
assert_helper_status 2 ha_session_sync_idle_sample fw0 fw1 "${SYNC_SOURCE}" "${SYNC_MISSING_DRAINED}"

assert_helper_value 5 ha_nondecreasing_delta 10 15
assert_helper_status 2 ha_nondecreasing_delta 15 10
assert_helper_status 2 ha_nondecreasing_delta malformed 10

INTERFACES="${TMP_DIR}/interfaces.txt"
write_interface_snapshot "${INTERFACES}" ge-0-0-2 5 7
assert_helper_value 5 ha_interface_packets_value "${INTERFACES}" 'ge-[0-9]+-0-2' rx
assert_helper_value 7 ha_interface_packets_value "${INTERFACES}" 'ge-[0-9]+-0-2' tx
assert_helper_status 2 ha_interface_packets_value "${INTERFACES}" 'ge-[0-9]+-0-1' rx
MALFORMED_INTERFACES="${TMP_DIR}/malformed-interfaces.txt"
printf 'Userspace bindings:\nheader\nshort row\n' >"${MALFORMED_INTERFACES}"
assert_helper_status 2 ha_interface_packets_value "${MALFORMED_INTERFACES}" 'ge-[0-9]+-0-2' tx

FABRIC_INTERFACES="${TMP_DIR}/fabric-interfaces.txt"
python3 - "${FABRIC_INTERFACES}" <<'PY'
import pathlib
import sys
row = ["0"] * 20
row[10] = "8"
row[11] = "13"
row[19] = "ge-0-0-0"
pathlib.Path(sys.argv[1]).write_text(
    "Userspace fabric links:\nSlot Parent State\n0 ge-0-0-0 up\n\n"
    "Userspace bindings:\nSlot Queue Header\n" + " ".join(row) + "\n",
    encoding="utf-8",
)
PY
assert_helper_value 13 ha_status_fabric_tx_packets "${FABRIC_INTERFACES}"
assert_helper_status 2 ha_status_fabric_tx_packets "${TMP_DIR}/missing-fabric.txt"

STANDBY_STATUS="${TMP_DIR}/standby-status.txt"
cat >"${STANDBY_STATUS}" <<'EOF'
Enabled: true
Forwarding armed: true
rg1 active=false
Ready bindings: 2/8
EOF
assert_helper_status 0 ha_standby_status_verdict "${STANDBY_STATUS}" 1
cat >"${STANDBY_STATUS}" <<'EOF'
Enabled: true
Forwarding armed: true
rg1 active=true
Ready bindings: 2/8
EOF
assert_helper_status 1 ha_standby_status_verdict "${STANDBY_STATUS}" 1
cat >"${STANDBY_STATUS}" <<'EOF'
Enabled: true
rg1 active=false
Ready bindings: 2/8
EOF
assert_helper_status 2 ha_standby_status_verdict "${STANDBY_STATUS}" 1

assert_helper_status 0 ha_ttl_output_verdict 1 'Time exceeded: Hop limit'
assert_helper_status 1 ha_ttl_output_verdict 0 '64 bytes from 1.1.1.1: icmp_seq=1 ttl=64'
assert_helper_status 2 ha_ttl_output_verdict 2 'ping exited with status 2'
assert_helper_status 2 ha_ttl_output_verdict 1 ''
PING_GOOD='1 packets transmitted, 1 received, 0% packet loss'
PING_ZERO='2 packets transmitted, 0 received, 100% packet loss'
assert_helper_status 0 ha_ping_reply_verdict 0 "${PING_GOOD}"
assert_helper_status 1 ha_ping_reply_verdict 1 "${PING_ZERO}"
assert_helper_status 2 ha_ping_reply_verdict 1 'ping output without a count'
assert_helper_status 0 ha_target_reachability_verdict 0 "64 bytes from 172.16.80.200\n${PING_GOOD}" 127 ''
assert_helper_status 0 ha_target_reachability_verdict 1 "${PING_ZERO}" 0 ''
assert_helper_status 1 ha_target_reachability_verdict 1 "${PING_ZERO}" 1 'Connection refused'
assert_helper_status 1 ha_target_reachability_verdict 1 "${PING_ZERO}" 124 ''
assert_helper_status 2 ha_target_reachability_verdict 1 '' 0 ''

assert_helper_status 0 ha_external_ping_verdict 0 '64 bytes from 1.1.1.1: icmp_seq=1 ttl=56'
assert_helper_status 1 ha_external_ping_verdict 1 '4 packets transmitted, 0 received, 100% packet loss'
assert_helper_status 2 ha_external_ping_verdict 2 'ping exited with status 2'
assert_helper_status 2 ha_external_ping_verdict 1 ''
RECENT_JSON="${TMP_DIR}/recent-metrics.jsonl"
cat >"$RECENT_JSON" <<'JSON'
{"event":"interval","data":{"sum":{"start":0,"end":1,"bits_per_second":0},"streams":[{"socket":1,"bits_per_second":0},{"socket":2,"bits_per_second":100}]}}
{"event":"interval","data":{"sum":{"start":1,"end":2,"bits_per_second":100},"streams":[{"socket":1,"bits_per_second":50},{"socket":2,"bits_per_second":100}]}}
JSON
assert_helper_value 2 ha_recent_interval_metric "$RECENT_JSON" 2 zero_intervals 2
assert_helper_value 1 ha_recent_interval_metric "$RECENT_JSON" 2 stream_zero_intervals 2
assert_helper_value 1 ha_recent_interval_metric "$RECENT_JSON" 2 zero_streams 2
assert_helper_value 0 ha_recent_interval_metric "$RECENT_JSON" 1 dead_streams 2
assert_helper_status 2 ha_recent_interval_metric "$RECENT_JSON" 3 dead_streams 2
printf '{"event":"interval","data":{"sum":{},"streams":[]}}\n' >"${TMP_DIR}/recent-malformed.jsonl"
assert_helper_status 2 ha_recent_interval_metric "${TMP_DIR}/recent-malformed.jsonl" 1 dead_streams 2
printf 'not json\n' >"${TMP_DIR}/recent-truncated.jsonl"
assert_helper_status 2 ha_recent_interval_metric "${TMP_DIR}/recent-truncated.jsonl" 1 dead_streams 2
printf '%s\n' '{"event":"interval","data":{"sum":{"start":0,"end":1,"bits_per_second":1},"streams":[{"socket":1,"bits_per_second":1}]}}' \
	>"${TMP_DIR}/recent-missing-stream.jsonl"
assert_helper_status 2 ha_recent_interval_metric "${TMP_DIR}/recent-missing-stream.jsonl" 1 dead_streams 2
printf '%s\n' '{"event":"interval","data":{"sum":{"start":0,"end":1,"bits_per_second":1},"streams":[{"socket":1,"bits_per_second":1},{"socket":1,"bits_per_second":1}]}}' \
	>"${TMP_DIR}/recent-duplicate-stream.jsonl"
assert_helper_status 2 ha_recent_interval_metric "${TMP_DIR}/recent-duplicate-stream.jsonl" 1 dead_streams 2
assert_helper_status 2 ha_recent_interval_metric "${TMP_DIR}/recent-missing.jsonl" 1 dead_streams 2
printf '%s\n' '{"event":"interval","data":{"sum":{"start":0,"end":1,"bits_per_second":1e999},"streams":[{"socket":1,"bits_per_second":1},{"socket":2,"bits_per_second":1}]}}' \
	>"${TMP_DIR}/recent-nonfinite.jsonl"
assert_helper_status 2 ha_recent_interval_metric "${TMP_DIR}/recent-nonfinite.jsonl" 1 dead_streams 2
printf '%s\n' '{"event":"interval","event":"end","data":{}}' >"${TMP_DIR}/recent-duplicate-member.jsonl"
assert_helper_status 2 ha_recent_interval_metric "${TMP_DIR}/recent-duplicate-member.jsonl" 1 dead_streams 2
printf '%s\n' '{"event":"interval","data":{"sum":{"start":0,"end":1,"bits_per_second":true},"streams":[{"socket":1,"bits_per_second":1},{"socket":2,"bits_per_second":1}]}}' \
	>"${TMP_DIR}/recent-bool-number.jsonl"
assert_helper_status 2 ha_recent_interval_metric "${TMP_DIR}/recent-bool-number.jsonl" 1 dead_streams 2

ROUTE_GOOD='172.16.80.200 dev eth0 src 10.0.0.1'
ROUTE_LOCAL='local 172.16.80.200 dev lo src 172.16.80.200'
assert_helper_value eth0 ha_route_device "${ROUTE_GOOD}"
assert_helper_status 0 ha_route_lookup_verdict 0 "${ROUTE_GOOD}"
assert_helper_status 1 ha_route_lookup_verdict 0 "${ROUTE_LOCAL}"
assert_helper_status 2 ha_route_lookup_verdict 1 'route query failed'
assert_helper_status 2 ha_route_lookup_verdict 0 'unparseable route output'
ROUTE_DEVICE_MISSING='172.16.80.200 src 10.0.0.1'
ROUTE_DEVICE_DUPLICATE='172.16.80.200 dev eth0 src 10.0.0.1 dev eth1'
ROUTE_DEVICE_MULTILINE=$'172.16.80.200 dev eth0\n172.16.80.200 dev eth1'
ROUTE_DEVICE_NAME_MISSING='172.16.80.200 dev'
ROUTE_DEVICE_NAME_MALFORMED='172.16.80.200 dev eth/0'
for route in "$ROUTE_DEVICE_MISSING" "$ROUTE_DEVICE_DUPLICATE" "$ROUTE_DEVICE_MULTILINE" "$ROUTE_DEVICE_NAME_MISSING" "$ROUTE_DEVICE_NAME_MALFORMED"; do
	assert_helper_status 2 ha_route_device "$route"
	assert_eq "$(<"${OUT}")" "" 'invalid route has no device stdout'
done
NEIGHBOR_V4='172.16.80.200 dev eth0 lladdr aa:bb:cc:dd:ee:ff REACHABLE'
NEIGHBOR_V6='2001:559:8585:80::200 dev eth0 lladdr aa:bb:cc:dd:ee:ff STALE'
assert_helper_status 0 ha_neighbor_identity_verdict eth0 "${NEIGHBOR_V4}" eth0 "${NEIGHBOR_V6}"
assert_helper_status 0 ha_neighbor_identity_verdict eth0 '172.16.80.200 lladdr aa:bb:cc:dd:ee:ff REACHABLE' eth0 '2001:559:8585:80::200 lladdr aa:bb:cc:dd:ee:ff STALE'
assert_helper_status 1 ha_neighbor_identity_verdict eth0 "${NEIGHBOR_V4}" eth0 '2001:559:8585:80::200 dev eth0 lladdr 00:11:22:33:44:55 REACHABLE'
assert_helper_status 1 ha_neighbor_identity_verdict eth0 "${NEIGHBOR_V4}" eth0 '2001:559:8585:80::200 dev eth1 lladdr aa:bb:cc:dd:ee:ff REACHABLE'
assert_helper_status 1 ha_neighbor_identity_verdict eth0 "${NEIGHBOR_V4}" eth0 '2001:559:8585:80::200 dev eth0 INCOMPLETE'
assert_helper_status 2 ha_neighbor_identity_verdict eth0 "${NEIGHBOR_V4}" eth0 ''
assert_helper_status 2 ha_neighbor_identity_verdict eth0 "${NEIGHBOR_V4}" eth0 '2001:559:8585:80::200 dev eth0 lladdr aa:bb:cc:dd:ee:ff UNKNOWN'


write_ha_status_snapshot() {
	local path="$1" phase="$2" node="$3" rg="$4"
	local session="$5" neighbor="$6" route="$7" denied="$8"
	local kernel="${9:-0}" noframe="${10:-0}" pending="${11:-0}" outstanding="${12:-0}"
	{
		printf 'HA capture identity: slice=manual-rg1-failback phase=%s node=%s rg=%s\n' "$phase" "$node" "$rg"
		printf 'Session misses: %s\nNeighbor misses: %s\nRoute misses: %s\nPolicy denied packets: %s\n' \
			"$session" "$neighbor" "$route" "$denied"
		printf 'Kernel RX dropped: %s\nDirect TX no-frame fb: %s\nPending TX local: %s\nOutstanding TX: %s\n' \
			"$kernel" "$noframe" "$pending" "$outstanding"
	} >"$path"
}

write_ha_owner_snapshot() {
	local path="$1" phase="$2" node="$3" rg="$4" node0_role="$5" node1_role="$6"
	{
		printf 'HA capture identity: slice=manual-rg1-failback phase=%s node=%s rg=%s\n' "$phase" "$node" "$rg"
		printf 'Redundancy group: %s , Failover count: 1\n' "$rg"
		printf 'node0   200       %s        no       no       None\n' "$node0_role"
		printf 'node1   100       %s        no       no       None\n' "$node1_role"
	} >"$path"
}

write_ha_interface_snapshot() {
	python3 - "$@" <<'PY'
import pathlib
import sys

path, phase, node, rg, iface, rx, tx = sys.argv[1:]
row = ["0"] * 20
row[10], row[11], row[19] = rx, tx, iface
pathlib.Path(path).write_text(
    f"HA capture identity: slice=manual-rg1-failback phase={phase} node={node} rg={rg}\n"
    "Userspace bindings:\nSlot Queue Header\n" + " ".join(row) + "\n",
    encoding="utf-8",
)
PY
}

printf 'RG1 snapshot identity and exact owner evidence\n'
RG1_DIR="${TMP_DIR}/rg1-predicates"
mkdir -p "$RG1_DIR"
OWNER0="${RG1_DIR}/owner-node0.status"
OWNER1="${RG1_DIR}/owner-node1.status"
write_ha_owner_snapshot "$OWNER0" owner-poll-01 node0 1 primary secondary
write_ha_owner_snapshot "$OWNER1" owner-poll-01 node1 1 primary secondary
assert_helper_status 0 ha_snapshot_identity_verdict "$OWNER0" manual-rg1-failback owner-poll-01 node0 1
assert_helper_status 2 ha_snapshot_identity_verdict "$OWNER0" manual-rg1-failback phase-pre node0 1
assert_helper_status 0 ha_rg_owner_verdict node0 1 owner-poll-01 "$OWNER0" "$OWNER1"
write_ha_owner_snapshot "$OWNER1" owner-poll-01 node1 1 secondary primary
assert_helper_status 1 ha_rg_owner_verdict node0 1 owner-poll-01 "$OWNER0" "$OWNER1"
printf 'Redundancy group: 1 , Failover count: 1\nnode0 200 primary no no None\n' >>"$OWNER1"
assert_helper_status 2 ha_rg_owner_verdict node0 1 owner-poll-01 "$OWNER0" "$OWNER1"

printf 'Groups 1-4 paired counter budgets and fail-closed evidence\n'
PAIR_PRE0="${RG1_DIR}/phase-pre-node0.stats"
PAIR_PRE1="${RG1_DIR}/phase-pre-node1.stats"
PAIR_POST0="${RG1_DIR}/phase-post-node0.stats"
PAIR_POST1="${RG1_DIR}/phase-post-node1.stats"
write_ha_status_snapshot "$PAIR_PRE0" phase-pre node0 1 10 20 30 0
write_ha_status_snapshot "$PAIR_PRE1" phase-pre node1 1 100 200 300 0
write_ha_status_snapshot "$PAIR_POST0" phase-post node0 1 42 50 42 0
write_ha_status_snapshot "$PAIR_POST1" phase-post node1 1 132 230 320 0
assert_helper_status 0 ha_pair_counter_budget_verdict 64 'Session misses' manual-rg1-failback 1 phase-pre phase-post \
	"$PAIR_PRE0" "$PAIR_PRE1" "$PAIR_POST0" "$PAIR_POST1"
write_ha_status_snapshot "$PAIR_POST1" phase-post node1 1 133 231 321 0
assert_helper_status 1 ha_pair_counter_budget_verdict 64 'Session misses' manual-rg1-failback 1 phase-pre phase-post \
	"$PAIR_PRE0" "$PAIR_PRE1" "$PAIR_POST0" "$PAIR_POST1"
assert_helper_status 1 ha_pair_counter_budget_verdict 60 'Neighbor misses' manual-rg1-failback 1 phase-pre phase-post \
	"$PAIR_PRE0" "$PAIR_PRE1" "$PAIR_POST0" "$PAIR_POST1"
assert_helper_status 1 ha_pair_counter_budget_verdict 32 'Route misses' manual-rg1-failback 1 phase-pre phase-post \
	"$PAIR_PRE0" "$PAIR_PRE1" "$PAIR_POST0" "$PAIR_POST1"
assert_helper_status 0 ha_pair_counter_budget_verdict 0 'Policy denied packets' manual-rg1-failback 1 phase-pre phase-post \
	"$PAIR_PRE0" "$PAIR_PRE1" "$PAIR_POST0" "$PAIR_POST1"
assert_helper_status 0 ha_counter_at_most_verdict 64 64 'session miss delta'
assert_helper_status 1 ha_counter_at_most_verdict 65 64 'session miss delta'
assert_helper_status 2 ha_counter_at_most_verdict malformed 64 'session miss delta'
assert_helper_status 1 ha_counter_at_most_verdict 1 0 'policy denied delta'
write_ha_status_snapshot "$PAIR_POST1" phase-post node1 1 99 230 320 0
assert_helper_status 2 ha_pair_counter_budget_verdict 64 'Session misses' manual-rg1-failback 1 phase-pre phase-post \
	"$PAIR_PRE0" "$PAIR_PRE1" "$PAIR_POST0" "$PAIR_POST1"
assert_helper_status 2 ha_pair_counter_budget_verdict 64 'Missing metric' manual-rg1-failback 1 phase-pre phase-post \
	"$PAIR_PRE0" "$PAIR_PRE1" "$PAIR_POST0" "$PAIR_POST1"
assert_helper_status 2 ha_pair_counter_budget_verdict 64 'Session misses' manual-rg1-failback 1 phase-pre phase-post \
	"$PAIR_PRE0" "$PAIR_PRE1" "$PAIR_POST0" "$OWNER1"

printf 'Groups 5-6 exact mid-post and fabric trigger decisions\n'
WAN_PRE="${RG1_DIR}/wan-pre.interfaces"
WAN_MID="${RG1_DIR}/wan-mid.interfaces"
WAN_POST="${RG1_DIR}/wan-post.interfaces"
write_ha_interface_snapshot "$WAN_PRE" phase-pre node1 1 ge-0-0-2 10 100
write_ha_interface_snapshot "$WAN_MID" phase-mid node1 1 ge-0-0-2 10 150
write_ha_interface_snapshot "$WAN_POST" phase-post node1 1 ge-0-0-2 10 150
assert_helper_status 0 ha_snapshot_interface_budget_verdict 0 'ge-[0-9]+-0-2' tx 'standby WAN TX' \
	manual-rg1-failback 1 node1 phase-mid "$WAN_MID" phase-post "$WAN_POST"
write_ha_interface_snapshot "$WAN_POST" phase-post node1 1 ge-0-0-2 10 151
assert_helper_status 1 ha_snapshot_interface_budget_verdict 0 'ge-[0-9]+-0-2' tx 'standby WAN TX' \
	manual-rg1-failback 1 node1 phase-mid "$WAN_MID" phase-post "$WAN_POST"
assert_helper_status 2 ha_snapshot_interface_budget_verdict 0 'ge-[0-9]+-0-2' tx 'standby WAN TX' \
	manual-rg1-failback 1 node1 phase-pre "$WAN_MID" phase-post "$WAN_POST"
assert_helper_status 0 ha_fabric_activity_verdict 1 8 1 8 1
assert_helper_status 1 ha_fabric_activity_verdict 0 8 1 8 1
assert_helper_status 0 ha_fabric_activity_verdict 0 7 1 8 1
assert_helper_status 0 ha_transition_path_verdict 999 0 0 0 1000 1 32 32
assert_helper_status 0 ha_transition_path_verdict 1000 1 32 32 1000 1 32 32
for path_case in '1000 0 32 32' '1000 1 31 32' '1000 1 32 31'; do
	read -r lan fabric rx tx <<<"$path_case"
	assert_helper_status 1 ha_transition_path_verdict "$lan" "$fabric" "$rx" "$tx" 1000 1 32 32
done

printf 'Groups 7-8 RG readiness and exact ten-sample maxima\n'
STANDBY_ID="${RG1_DIR}/standby.status"
write_ha_status_snapshot "$STANDBY_ID" phase-post node1 1 0 0 0 0
{
	printf 'Enabled: true\nForwarding armed: true\nrg1 active=false\nReady bindings: 2/8\n'
} >>"$STANDBY_ID"
assert_helper_status 0 ha_rg_standby_status_verdict "$STANDBY_ID" manual-rg1-failback phase-post node1 1
for predicate in enabled armed active ready; do
	write_ha_status_snapshot "$STANDBY_ID" phase-post node1 1 0 0 0 0
	case "$predicate" in
	enabled) printf 'Enabled: false\nForwarding armed: true\nrg1 active=false\nReady bindings: 2/8\n' >>"$STANDBY_ID" ;;
	armed) printf 'Enabled: true\nForwarding armed: false\nrg1 active=false\nReady bindings: 2/8\n' >>"$STANDBY_ID" ;;
	active) printf 'Enabled: true\nForwarding armed: true\nrg1 active=true\nReady bindings: 2/8\n' >>"$STANDBY_ID" ;;
	ready) printf 'Enabled: true\nForwarding armed: true\nrg1 active=false\nReady bindings: 0/8\n' >>"$STANDBY_ID" ;;
	esac
	assert_helper_status 1 ha_rg_standby_status_verdict "$STANDBY_ID" manual-rg1-failback phase-post node1 1
done
assert_helper_status 2 ha_rg_standby_status_verdict "$STANDBY_ID" manual-rg1-failback phase-pre node1 1

SAMPLE_STATS=()
SAMPLE_INTERFACES=()
for sample in $(seq -w 1 10); do
	stats="${RG1_DIR}/sample-${sample}-node0.stats"
	ifaces="${RG1_DIR}/sample-${sample}-node0.interfaces"
	value=$((100 + 10#$sample))
	write_ha_status_snapshot "$stats" "sample-${sample}" node0 1 0 0 0 0 "$value" "$value" "$value" "$value"
	write_ha_interface_snapshot "$ifaces" "sample-${sample}" node0 1 ge-0-0-1 "$value" "$value"
	SAMPLE_STATS+=("$stats")
	SAMPLE_INTERFACES+=("$ifaces")
done
assert_helper_value 110 ha_sample_window_max manual-rg1-failback 1 node0 'Kernel RX dropped' "${SAMPLE_STATS[@]}"
assert_helper_value 110 ha_sample_window_interface_max manual-rg1-failback 1 node0 'ge-[0-9]+-0-1' rx "${SAMPLE_INTERFACES[@]}"
SAMPLE_STATS[9]="${RG1_DIR}/missing-sample.stats"
assert_helper_status 2 ha_sample_window_max manual-rg1-failback 1 node0 'Kernel RX dropped' "${SAMPLE_STATS[@]}"
SAMPLE_STATS[9]="${RG1_DIR}/sample-09-node0.stats"
assert_helper_status 2 ha_sample_window_max manual-rg1-failback 1 node0 'Kernel RX dropped' "${SAMPLE_STATS[@]}"
REWIND_COUNTERS=(110 500 50 150 160 170 180 190 195 600)
REWIND_STATS=()
REWIND_INTERFACES=()
for rewind_index in "${!REWIND_COUNTERS[@]}"; do
	rewind_sample=$(printf 'sample-%02d' "$((rewind_index + 1))")
	rewind_stats="${RG1_DIR}/rewind-${rewind_sample}-node0.stats"
	rewind_ifaces="${RG1_DIR}/rewind-${rewind_sample}-node0.interfaces"
	rewind_value="${REWIND_COUNTERS[$rewind_index]}"
	write_ha_status_snapshot "$rewind_stats" "$rewind_sample" node0 1 0 0 0 0 "$rewind_value" "$rewind_value" "$rewind_value" "$rewind_value"
	write_ha_interface_snapshot "$rewind_ifaces" "$rewind_sample" node0 1 ge-0-0-1 "$rewind_value" "$rewind_value"
	REWIND_STATS+=("$rewind_stats")
	REWIND_INTERFACES+=("$rewind_ifaces")
done
assert_helper_status 2 ha_sample_window_max manual-rg1-failback 1 node0 'Kernel RX dropped' "${REWIND_STATS[@]}"
assert_contains "$(<"${ERR}")" 'rewound from 500 to 50' 'counter window rewind evidence'
assert_helper_status 2 ha_sample_window_interface_max manual-rg1-failback 1 node0 'ge-[0-9]+-0-1' rx "${REWIND_INTERFACES[@]}"
assert_contains "$(<"${ERR}")" 'rewound from 500 to 50' 'interface window rewind evidence'
assert_helper_value 500 ha_nondecreasing_delta 100 600
assert_helper_status 0 ha_nondecreasing_delta 100 612
assert_helper_status 1 ha_counter_at_most_verdict 513 512 'new-owner kernel RX dropped'

printf 'RG1 pre-max transition path trigger is exact\n'
assert_helper_status 0 ha_transition_path_verdict 999 0 0 0 1000 1 32 32
assert_helper_status 0 ha_transition_path_verdict 1000 1 32 32 1000 1 32 32
assert_helper_status 1 ha_transition_path_verdict 1000 0 32 32 1000 1 32 32
assert_helper_status 1 ha_transition_path_verdict 1000 1 31 32 1000 1 32 32
assert_helper_status 1 ha_transition_path_verdict 1000 1 32 31 1000 1 32 32

printf 'Gate-dominance same-function ordering grep\n'
python3 - "${ROOT}/scripts/userspace-ha-failover-validation.sh" "${ROOT}/test/incus/test-failover.sh" <<'PY'
import pathlib
import re
import sys

legacy_path, reached_path = map(pathlib.Path, sys.argv[1:])
legacy = legacy_path.read_text(encoding="utf-8")
accessors = {
    "count_zero_intervals": "zero_intervals_total",
    "count_stream_zero_intervals": "stream_zero_intervals_total",
    "count_zero_streams": "zero_streams_total",
    "extract_sender_throughput": "avg_gbps",
    "extract_retransmits": "retransmits",
    "iperf_collapse_detected": "collapse_detected",
    "iperf_collapse_reason": "collapse_reason",
    "iperf_completed_local": "completed",
    "iperf_effectively_completed_local": "observed_end_sec",
}
for name, scalar in accessors.items():
    match = re.search(rf"^{name}\(\) \{{\n(.*?)^\}}$", legacy, re.M | re.S)
    if not match:
        raise SystemExit(f"{legacy_path}: required legacy accessor {name} is absent")
    body = match.group(1)
    gate_at = body.find("legacy_metrics_gate")
    scalar_match = re.search(rf"\$\{{?{re.escape(scalar)}\}}?", body)
    scalar_at = scalar_match.start() if scalar_match else -1
    if gate_at < 0 or scalar_at < 0 or gate_at > scalar_at:
        raise SystemExit(f"{legacy_path}: {name} reads ${scalar} before legacy_metrics_gate")

reached = reached_path.read_text(encoding="utf-8")
start_marker = "# M1 JSON capture/gate fixture begin"
end_marker = "# M1 JSON capture/gate fixture end"
start = reached.find(start_marker)
end = reached.find(end_marker)
if start < 0 or end <= start:
    raise SystemExit(f"{reached_path}: missing reached JSON capture/gate block")
gate_block = reached[start:end]
gate_at = gate_block.find('ha_metrics_gate "$LOCAL_IPERF_METRICS"')
eval_at = gate_block.find('eval "$gate_output"')
if gate_at < 0 or eval_at < 0 or gate_at > eval_at:
    raise SystemExit(f"{reached_path}: gate must precede consumption of its scalar assignments")
post_gate = reached[end + len(end_marker):]
guard_at = post_gate.find('if [[ "$iperf_gate_ok" == true ]]; then')
if guard_at < 0:
    raise SystemExit(f"{reached_path}: no reached whole-run scalar guard follows the gate")
reached_scalars = (
    "zero_intervals_total", "stream_zero_intervals_total", "zero_streams_total",
    "retransmits", "avg_gbps", "collapse_detected", "collapse_reason",
    "completed", "observed_end_sec", "full_interval_count",
)
for scalar in reached_scalars:
    scalar_match = re.search(rf"\$\{{?{re.escape(scalar)}\}}?", post_gate)
    scalar_at = scalar_match.start() if scalar_match else -1
    if scalar_at < 0 or guard_at > scalar_at:
        raise SystemExit(f"{reached_path}: ${scalar} is absent or precedes the gate-success guard")
print(f"{legacy_path.name}: {len(accessors)} actual metrics accessors gate-dominated")
print(f"{reached_path.name}: reached gate precedes eval and all {len(reached_scalars)} guarded scalar reads")
PY

OBS_DIR="${TMP_DIR}/pre-failover-observation"
mkdir -p "$OBS_DIR"
OBS_EXTRACTED="${OBS_DIR}/observation.sh"
python3 - "${ROOT}/test/incus/test-failover.sh" "$OBS_EXTRACTED" <<'PY'
import pathlib
import re
import sys

text = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8")
blocks = []
for name in ("ha_preflight_json_metrics", "ha_pre_failover_observation"):
    match = re.search(rf"^{name}\(\) \{{$\n(.*?)^\}}$\n", text, re.M | re.S)
    if not match:
        raise SystemExit(f"cannot extract {name} for the set-e guard case")
    blocks.append(f"{name}() {{\n{match.group(1)}}}\n")
pathlib.Path(sys.argv[2]).write_text("".join(blocks), encoding="utf-8")
PY
OBS_OUT="${OBS_DIR}/stdout"
if PRE_FAILOVER_OBSERVE=0 HA_CAPTURE_DIR="$OBS_DIR" CLUSTER_LAN_HOST=stub-lan \
    bash -euo pipefail -c '
        source "$1"
        PASS=0; FAIL=1; VOID=0
        info() { :; }
        pass() { PASS=$((PASS + 1)); }
        fail() { FAIL=$((FAIL + 1)); }
        void() { VOID=$((VOID + 1)); }
        sleep() { :; }
        main_iperf_running() { return 0; }
        ha_external_sweep() { printf "SWEEP-CALLED %s\n" "$*"; }
        incus() { return 1; }
        ha_pre_failover_observation
        printf "LATER-CHECKS-RAN VOID=%s FAIL=%s\n" "$VOID" "$FAIL"
    ' _ "$OBS_EXTRACTED" >"$OBS_OUT" 2>&1; then
    OBS_RC=0
else
    OBS_RC=$?
fi
assert_eq "$OBS_RC" 0 'observation continues past metrics VOID under set -e'
assert_contains "$(<"$OBS_OUT")" 'SWEEP-CALLED pre-failure steady' 'later sweep runs after VOID'
OBS_STATE="$(<"$OBS_OUT")"
if [[ ! "$OBS_STATE" =~ LATER-CHECKS-RAN[[:space:]]VOID=[1-9][0-9]*[[:space:]]FAIL=1 ]]; then
	fail_test "later checks did not run with a recorded VOID and sticky FAIL: ${OBS_STATE}"
fi

OWNER_CELL="${TMP_DIR}/rg1-owner-status-cell.sh"
python3 - "${ROOT}/test/incus/test-failover.sh" "$OWNER_CELL" <<'PY'
import pathlib
import re
import sys

text = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8")
match = re.search(r"^ha_rg1_owner_status_cell\(\) \{\n.*?^\}\n", text, re.M | re.S)
if not match:
    raise SystemExit("cannot extract ha_rg1_owner_status_cell")
pathlib.Path(sys.argv[2]).write_text(match.group(0), encoding="utf-8")
PY
OWNER_RUNNER='
source "$1"
PASS=0 FAIL=0 VOID=0
pass() { PASS=$((PASS + 1)); }
fail() { FAIL=$((FAIL + 1)); }
void() { VOID=$((VOID + 1)); }
ha_rg1_owner_verdict() { printf "fixture owner evidence"; return "$OWNER_STATUS"; }
if ha_rg1_owner_status_cell fw0 phase-mid fixture; then RC=0; else RC=$?; fi
printf "RC=%s PASS=%s FAIL=%s VOID=%s\n" "$RC" "$PASS" "$FAIL" "$VOID"
'
OWNER_OUT="$(OWNER_STATUS=0 bash -euo pipefail -c "$OWNER_RUNNER" _ "$OWNER_CELL")"
assert_eq "$OWNER_OUT" 'RC=0 PASS=1 FAIL=0 VOID=0' 'RG1 owner wrapper PASS mapping'
OWNER_OUT="$(OWNER_STATUS=1 bash -euo pipefail -c "$OWNER_RUNNER" _ "$OWNER_CELL")"
assert_eq "$OWNER_OUT" 'RC=1 PASS=0 FAIL=1 VOID=0' 'RG1 owner wrapper measured FAIL status'
OWNER_OUT="$(OWNER_STATUS=2 bash -euo pipefail -c "$OWNER_RUNNER" _ "$OWNER_CELL")"
assert_eq "$OWNER_OUT" 'RC=2 PASS=0 FAIL=0 VOID=1' 'RG1 owner wrapper VOID status'
printf 'RG1 owner cell wrapper preserves PASS/FAIL/VOID status under set -e\n'

printf 'PASS ha-assurance-selftest: M2.4, RG1 Groups 1-8, N6/N12 pins, sticky FAIL, blind markers, gate dominance, set-e VOID guard\n'
