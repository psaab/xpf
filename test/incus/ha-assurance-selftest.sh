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

SAMPLED_WRAPPERS="${TMP_DIR}/sampled-wrappers.sh"
python3 - "${ROOT}/test/incus/test-failover.sh" "$SAMPLED_WRAPPERS" <<'PY'
import pathlib
import re
import sys

text = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8")
blocks = []
for name in (
    "ha_rg1_sampled_counter_delta",
    "ha_rg1_sampled_interface_delta",
    "ha_rg1_report_sample_max",
):
    match = re.search(rf"^{name}\(\) \{{\n.*?^\}}\n", text, re.M | re.S)
    if not match:
        raise SystemExit(f"cannot extract {name} for phase-pre rewind coverage")
    blocks.append(match.group(0))
pathlib.Path(sys.argv[2]).write_text("".join(blocks), encoding="utf-8")
PY
# Execute the actual consumers without sourcing test-failover.sh's destructive
# cluster runtime.
source "$SAMPLED_WRAPPERS"

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

PARSED_DURATION="$(TOTAL_CYCLES=1 IPERF_DURATION= BPFRX_CLUSTER_ENV="${ROOT}/test/incus/loss-userspace-cluster.env" \
	HA_ASSURANCE_SOURCE_ONLY=1 bash -c 'source "$1" --cycles 3; printf "%s" "$IPERF_DURATION"' _ \
	"${ROOT}/scripts/userspace-ha-failover-validation.sh")"
assert_eq "$PARSED_DURATION" 185 'default duration uses parsed cycle count'

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
    "stream_zero_intervals_outside_events_total": 0,
    "zero_streams_outside_events_total": 0,
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
	printf '{"ok":true,"error":"","interval_gbps":[1.0],"avg_gbps":%s,"zero_intervals_total":0,"stream_zero_intervals_total":0,"stream_zero_intervals_outside_events_total":0,"zero_streams_outside_events_total":0,"zero_streams_total":0,"retransmits":0,"collapse_detected":false,"collapse_reason":"","completed":true,"observed_end_sec":60}\n' "$1" >"${LOCAL_IPERF_METRICS}"
}

write_raw_interval() {
	printf '{"ok":true,"error":"","interval_gbps":[%s],"avg_gbps":1.0,"zero_intervals_total":0,"stream_zero_intervals_total":0,"stream_zero_intervals_outside_events_total":0,"zero_streams_outside_events_total":0,"zero_streams_total":0,"retransmits":0,"collapse_detected":false,"collapse_reason":"","completed":true,"observed_end_sec":60}\n' "$1" >"${LOCAL_IPERF_METRICS}"
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

run_fabric_path_consumer() {
	validate_phase_fabric_path 1 failover "$FW0" node0 "$FW1" node1 >"${OUT}" 2>"${ERR}"
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
for field in avg_gbps zero_intervals_total stream_zero_intervals_total stream_zero_intervals_outside_events_total zero_streams_outside_events_total retransmits observed_end_sec; do
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
check_boundary 1 'FAIL  iperf3 did not complete successfully' 'completed=false' 'observed_end_sec=2' 'avg_gbps=5.0'

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
assert_helper_status 0 ha_session_sync_idle_sample fw0 fw1 "${STATISTICS_RENDERED}" "${STATISTICS_RENDERED}" 321 321 0
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
Session delta dropped: 0
Session delta drained: 12
EOF
cat >"${SYNC_TARGET}" <<'EOF'
Services Synchronized:
Service Sent Received
Session create 5 5

Session delta pending: 0
Session delta dropped: 0
Session delta drained: 19
EOF
assert_helper_value 0 ha_status_summary_value "${SYNC_TARGET}" 'Session delta pending'
assert_helper_value 19 ha_status_summary_value "${SYNC_TARGET}" 'Session delta drained'
assert_helper_status 2 ha_status_summary_value "${SYNC_TARGET}" 'Missing label'
assert_helper_value 5 ha_sync_stats_value "${SYNC_SOURCE}" 'Session create' sent
assert_helper_value 5 ha_sync_stats_value "${SYNC_TARGET}" 'Session create' received
assert_helper_status 0 ha_session_sync_idle_sample fw0 fw1 "${SYNC_SOURCE}" "${SYNC_TARGET}" 5 5 0

SYNC_REVERSE_SOURCE="${TMP_DIR}/sync-reverse-source.txt"
SYNC_REVERSE_TARGET="${TMP_DIR}/sync-reverse-target.txt"
cat >"${SYNC_REVERSE_SOURCE}" <<'EOF'
Services Synchronized:
Session create 7 7

Session delta pending: 0
Session delta dropped: 0
Session delta drained: 0
EOF
cat >"${SYNC_REVERSE_TARGET}" <<'EOF'
Services Synchronized:
Session create 7 7

Session delta pending: 0
Session delta dropped: 0
Session delta drained: 0
EOF
assert_helper_status 0 ha_session_sync_idle_sample fw1 fw0 "${SYNC_REVERSE_SOURCE}" "${SYNC_REVERSE_TARGET}" 7 7 0
SYNC_NOT_IDLE="${TMP_DIR}/sync-not-idle.txt"
cat >"${SYNC_NOT_IDLE}" <<'EOF'
Services Synchronized:
Session create 4 5

Session delta pending: 1
Session delta dropped: 0
Session delta drained: 0
EOF
assert_helper_status 1 ha_session_sync_idle_sample fw0 fw1 "${SYNC_SOURCE}" "${SYNC_NOT_IDLE}" 5 5 0
SYNC_MISSING_DRAINED="${TMP_DIR}/sync-missing-drained.txt"
cat >"${SYNC_MISSING_DRAINED}" <<'EOF'
Services Synchronized:
Session create 5 5

Session delta pending: 0
Session delta dropped: 0
EOF
assert_helper_status 2 ha_session_sync_idle_sample fw0 fw1 "${SYNC_SOURCE}" "${SYNC_MISSING_DRAINED}" 5 5 0

# #16289: offset baselines. The tcp-cluster failure was source sent=15 vs
# target received=174 (delta 159 from a previous counting epoch) with
# pending=0: absolute equality can never hold, yet sync is caught up.
# Baseline-relative idle must judge the pair idle when nothing sent since
# the baseline is unreceived, and never idle while sends go unreceived.
SYNC_OFFSET_SOURCE="${TMP_DIR}/sync-offset-source.txt"
SYNC_OFFSET_TARGET="${TMP_DIR}/sync-offset-target.txt"
cat >"${SYNC_OFFSET_SOURCE}" <<'EOF'
Services Synchronized:
Session create 15 0

Session delta pending: 0
Session delta dropped: 0
Session delta drained: 12
EOF
cat >"${SYNC_OFFSET_TARGET}" <<'EOF'
Services Synchronized:
Session create 0 174

Session delta pending: 0
Session delta dropped: 0
Session delta drained: 19
EOF
# First sample only establishes the baseline: never idle by itself.
assert_helper_status 1 ha_session_sync_idle_sample fw0 fw1 "${SYNC_OFFSET_SOURCE}" "${SYNC_OFFSET_TARGET}" '' '' ''
# Static offset pair (the cell3.log evidence shape) is idle vs baseline.
assert_helper_status 0 ha_session_sync_idle_sample fw0 fw1 "${SYNC_OFFSET_SOURCE}" "${SYNC_OFFSET_TARGET}" 15 174 0
# Lockstep advance since baseline (15->74, 174->233) stays idle.
SYNC_OFFSET_SOURCE_LATE="${TMP_DIR}/sync-offset-source-late.txt"
SYNC_OFFSET_TARGET_LATE="${TMP_DIR}/sync-offset-target-late.txt"
cat >"${SYNC_OFFSET_SOURCE_LATE}" <<'EOF'
Services Synchronized:
Session create 74 0

Session delta pending: 0
Session delta dropped: 0
Session delta drained: 12
EOF
cat >"${SYNC_OFFSET_TARGET_LATE}" <<'EOF'
Services Synchronized:
Session create 0 233

Session delta pending: 0
Session delta dropped: 0
Session delta drained: 19
EOF
assert_helper_status 0 ha_session_sync_idle_sample fw0 fw1 "${SYNC_OFFSET_SOURCE_LATE}" "${SYNC_OFFSET_TARGET_LATE}" 15 174 0
# Received stalls while sent grows since baseline: not idle.
SYNC_OFFSET_TARGET_STALLED="${TMP_DIR}/sync-offset-target-stalled.txt"
cat >"${SYNC_OFFSET_TARGET_STALLED}" <<'EOF'
Services Synchronized:
Session create 0 174

Session delta pending: 0
Session delta dropped: 0
Session delta drained: 19
EOF
assert_helper_status 1 ha_session_sync_idle_sample fw0 fw1 "${SYNC_OFFSET_SOURCE_LATE}" "${SYNC_OFFSET_TARGET_STALLED}" 15 174 0
# Offset pair with pending nonzero: not idle even with equal deltas.
SYNC_OFFSET_TARGET_PENDING="${TMP_DIR}/sync-offset-target-pending.txt"
cat >"${SYNC_OFFSET_TARGET_PENDING}" <<'EOF'
Services Synchronized:
Session create 0 174

Session delta pending: 3
Session delta dropped: 0
Session delta drained: 19
EOF
assert_helper_status 1 ha_session_sync_idle_sample fw0 fw1 "${SYNC_OFFSET_SOURCE}" "${SYNC_OFFSET_TARGET_PENDING}" 15 174 0
# #16500 -> #18632: shrinking gap since baseline. In-flight creates at the
# first sample (baseline 20/17) are delivered (20/20): D falls 3 -> 0. That
# is a NEW FLOOR (verdict 4: re-baseline and restart the streak), not an
# idle sample, so a backlog still draining never reads idle. Received
# ahead at the baseline (20/22) then 22/22 is NOT idle any more: with the
# target read first, D cannot read below the floor through capture skew,
# so D rising -2 -> 0 means two creates are outstanding beyond the floor
# (the dropped sent == received escape would have masked them). A gap
# that grows since baseline (20/20 -> 25/20) stays not idle, and a new
# floor with pending nonzero still re-baselines.
SYNC_SHRINK_BASE_SOURCE="${TMP_DIR}/sync-shrink-base-source.txt"
SYNC_SHRINK_BASE_TARGET="${TMP_DIR}/sync-shrink-base-target.txt"
cat >"${SYNC_SHRINK_BASE_SOURCE}" <<'EOF'
Services Synchronized:
Session create 20 0

Session delta pending: 0
Session delta dropped: 0
Session delta drained: 12
EOF
cat >"${SYNC_SHRINK_BASE_TARGET}" <<'EOF'
Services Synchronized:
Session create 0 17

Session delta pending: 0
Session delta dropped: 0
Session delta drained: 19
EOF
SYNC_SHRUNK_SOURCE="${TMP_DIR}/sync-shrunk-source.txt"
SYNC_SHRUNK_TARGET="${TMP_DIR}/sync-shrunk-target.txt"
cat >"${SYNC_SHRUNK_SOURCE}" <<'EOF'
Services Synchronized:
Session create 20 0

Session delta pending: 0
Session delta dropped: 0
Session delta drained: 12
EOF
cat >"${SYNC_SHRUNK_TARGET}" <<'EOF'
Services Synchronized:
Session create 0 20

Session delta pending: 0
Session delta dropped: 0
Session delta drained: 19
EOF
assert_helper_status 4 ha_session_sync_idle_sample fw0 fw1 "${SYNC_SHRUNK_SOURCE}" "${SYNC_SHRUNK_TARGET}" 20 17 0
# The same pair re-baselined onto itself is idle at the floor.
assert_helper_status 0 ha_session_sync_idle_sample fw0 fw1 "${SYNC_SHRUNK_SOURCE}" "${SYNC_SHRUNK_TARGET}" 20 20 0
# Received ahead at the baseline, then sent catches up: 20/22 -> 22/22.
SYNC_AHEAD_BASE_SOURCE="${TMP_DIR}/sync-ahead-base-source.txt"
SYNC_AHEAD_BASE_TARGET="${TMP_DIR}/sync-ahead-base-target.txt"
cat >"${SYNC_AHEAD_BASE_SOURCE}" <<'EOF'
Services Synchronized:
Session create 20 0

Session delta pending: 0
Session delta dropped: 0
Session delta drained: 12
EOF
cat >"${SYNC_AHEAD_BASE_TARGET}" <<'EOF'
Services Synchronized:
Session create 0 22

Session delta pending: 0
Session delta dropped: 0
Session delta drained: 19
EOF
SYNC_AHEAD_SOURCE="${TMP_DIR}/sync-ahead-source.txt"
SYNC_AHEAD_TARGET="${TMP_DIR}/sync-ahead-target.txt"
cat >"${SYNC_AHEAD_SOURCE}" <<'EOF'
Services Synchronized:
Session create 22 0

Session delta pending: 0
Session delta dropped: 0
Session delta drained: 12
EOF
cat >"${SYNC_AHEAD_TARGET}" <<'EOF'
Services Synchronized:
Session create 0 22

Session delta pending: 0
Session delta dropped: 0
Session delta drained: 19
EOF
assert_helper_status 1 ha_session_sync_idle_sample fw0 fw1 "${SYNC_AHEAD_SOURCE}" "${SYNC_AHEAD_TARGET}" 20 22 0
# #18632 at the unit level, on the #18627 loss numbers (floor
# sent-received = -107439). Lockstep advance at the floor is idle. A
# baseline taken one BELOW the floor (the source-first capture race:
# 22048/129488 = -107440) reads every later floor sample as one create
# outstanding, which is why the callers read the target first. One create
# genuinely outstanding beyond the floor is not idle; a bulk sync mid-wait
# (received jumps, sent does not) is a new floor; pending > 0 at the floor
# is not idle.
SYNC_LOSS_SOURCE="${TMP_DIR}/sync-loss-source.txt"
SYNC_LOSS_TARGET="${TMP_DIR}/sync-loss-target.txt"
write_unit_sync_pair() {
	# $1=sent $2=received $3=pending
	printf 'Services Synchronized:\nSession create %s 0\n\nSession delta pending: 0\nSession delta dropped: 0\nSession delta drained: 0\n' "$1" >"${SYNC_LOSS_SOURCE}"
	printf 'Services Synchronized:\nSession create 0 %s\n\nSession delta pending: %s\nSession delta dropped: 0\nSession delta drained: 0\n' "$2" "$3" >"${SYNC_LOSS_TARGET}"
}
write_unit_sync_pair 22049 129488 0
assert_helper_status 0 ha_session_sync_idle_sample node0 node1 "${SYNC_LOSS_SOURCE}" "${SYNC_LOSS_TARGET}" 22047 129486 0
assert_helper_status 1 ha_session_sync_idle_sample node0 node1 "${SYNC_LOSS_SOURCE}" "${SYNC_LOSS_TARGET}" 22048 129488 0
write_unit_sync_pair 22050 129488 0
assert_helper_status 1 ha_session_sync_idle_sample node0 node1 "${SYNC_LOSS_SOURCE}" "${SYNC_LOSS_TARGET}" 22047 129486 0
write_unit_sync_pair 22049 131000 0
assert_helper_status 4 ha_session_sync_idle_sample node0 node1 "${SYNC_LOSS_SOURCE}" "${SYNC_LOSS_TARGET}" 22047 129486 0
write_unit_sync_pair 22049 129488 2
assert_helper_status 1 ha_session_sync_idle_sample node0 node1 "${SYNC_LOSS_SOURCE}" "${SYNC_LOSS_TARGET}" 22047 129486 0
# Gap grows since baseline: 20/20 -> 25/20 stays not idle.
SYNC_GROWN_SOURCE="${TMP_DIR}/sync-grown-source.txt"
SYNC_GROWN_TARGET="${TMP_DIR}/sync-grown-target.txt"
cat >"${SYNC_GROWN_SOURCE}" <<'EOF'
Services Synchronized:
Session create 25 0

Session delta pending: 0
Session delta dropped: 0
Session delta drained: 12
EOF
cat >"${SYNC_GROWN_TARGET}" <<'EOF'
Services Synchronized:
Session create 0 20

Session delta pending: 0
Session delta dropped: 0
Session delta drained: 19
EOF
assert_helper_status 1 ha_session_sync_idle_sample fw0 fw1 "${SYNC_GROWN_SOURCE}" "${SYNC_GROWN_TARGET}" 20 20 0
# Shrunk gap with pending nonzero stays not idle.
SYNC_SHRUNK_TARGET_PENDING="${TMP_DIR}/sync-shrunk-target-pending.txt"
cat >"${SYNC_SHRUNK_TARGET_PENDING}" <<'EOF'
Services Synchronized:
Session create 0 20

Session delta pending: 3
Session delta dropped: 0
Session delta drained: 19
EOF
assert_helper_status 4 ha_session_sync_idle_sample fw0 fw1 "${SYNC_SHRUNK_SOURCE}" "${SYNC_SHRUNK_TARGET_PENDING}" 20 17 0
# Counter rewind since baseline (daemon restart / epoch reset) is the
# distinct re-baseline verdict 3, never idle and never VOID.
assert_helper_status 3 ha_session_sync_idle_sample fw0 fw1 "${SYNC_SOURCE}" "${SYNC_TARGET}" 15 174 0
# Blind evidence stays VOID even on a rewound sample and even on the
# baseline-establishing sample (parse precedes every baseline branch).
assert_helper_status 2 ha_session_sync_idle_sample fw0 fw1 "${SYNC_SOURCE}" "${SYNC_MISSING_DRAINED}" 15 174 0
assert_helper_status 2 ha_session_sync_idle_sample fw0 fw1 "${SYNC_SOURCE}" "${SYNC_MISSING_DRAINED}" '' '' ''
# Malformed / half-empty baselines are VOID, and the old 4-arg and 6-arg
# (pre-#18632, no source-dropped baseline) shapes are gone.
assert_helper_status 2 ha_session_sync_idle_sample fw0 fw1 "${SYNC_OFFSET_SOURCE}" "${SYNC_OFFSET_TARGET}" malformed 174 0
assert_helper_status 2 ha_session_sync_idle_sample fw0 fw1 "${SYNC_OFFSET_SOURCE}" "${SYNC_OFFSET_TARGET}" 15 '' 0
assert_helper_status 2 ha_session_sync_idle_sample fw0 fw1 "${SYNC_OFFSET_SOURCE}" "${SYNC_OFFSET_TARGET}"
assert_helper_status 2 ha_session_sync_idle_sample fw0 fw1 "${SYNC_OFFSET_SOURCE}" "${SYNC_OFFSET_TARGET}" 15 174
assert_helper_status 2 ha_session_sync_idle_sample fw0 fw1 "${SYNC_OFFSET_SOURCE}" "${SYNC_OFFSET_TARGET}" 15 174 ''
assert_helper_status 2 ha_session_sync_idle_sample fw0 fw1 "${SYNC_OFFSET_SOURCE}" "${SYNC_OFFSET_TARGET}" '' '' 0
assert_helper_status 2 ha_session_sync_idle_sample fw0 fw1 "${SYNC_OFFSET_SOURCE}" "${SYNC_OFFSET_TARGET}" 15 174 x
# #18632 source side (AD seat): the source's helper delta buffer. A delta
# it still holds, or has dropped, never becomes a sent create, so neither
# D nor the target's pending count can see it. At the floor with source
# pending > 0 is not idle; a drop since the baseline is not idle (and the
# caller keeps the baseline, so it never recovers); a dropped counter
# below its baseline is a helper restart (rewind, 3); a source capture
# without the dropped line is blind (VOID).
SYNC_SRC_SIDE_SOURCE="${TMP_DIR}/sync-src-side-source.txt"
write_src_side_source() {
	# $1=sent $2=source pending $3=source dropped
	printf 'Services Synchronized:\nSession create %s 0\n\nSession delta pending: %s\nSession delta dropped: %s\nSession delta drained: 0\n' "$1" "$2" "$3" >"${SYNC_SRC_SIDE_SOURCE}"
}
write_unit_sync_pair 22049 129488 0
write_src_side_source 22049 0 4
assert_helper_status 0 ha_session_sync_idle_sample node0 node1 "${SYNC_SRC_SIDE_SOURCE}" "${SYNC_LOSS_TARGET}" 22047 129486 4
write_src_side_source 22049 2 4
assert_helper_status 1 ha_session_sync_idle_sample node0 node1 "${SYNC_SRC_SIDE_SOURCE}" "${SYNC_LOSS_TARGET}" 22047 129486 4
write_src_side_source 22049 0 5
assert_helper_status 1 ha_session_sync_idle_sample node0 node1 "${SYNC_SRC_SIDE_SOURCE}" "${SYNC_LOSS_TARGET}" 22047 129486 4
assert_contains "$(<"${ERR}")" 'the source dropped 1 session delta(s) since the baseline' 'source drop diagnostic'
# A drop wins over a new floor: the baseline must not move onto it.
write_unit_sync_pair 22049 131000 0
assert_helper_status 1 ha_session_sync_idle_sample node0 node1 "${SYNC_SRC_SIDE_SOURCE}" "${SYNC_LOSS_TARGET}" 22047 129486 4
write_unit_sync_pair 22049 129488 0
write_src_side_source 22049 0 3
assert_helper_status 3 ha_session_sync_idle_sample node0 node1 "${SYNC_SRC_SIDE_SOURCE}" "${SYNC_LOSS_TARGET}" 22047 129486 4
printf 'Services Synchronized:\nSession create 22049 0\n\nSession delta pending: 0\nSession delta drained: 0\n' >"${SYNC_SRC_SIDE_SOURCE}"
assert_helper_status 2 ha_session_sync_idle_sample node0 node1 "${SYNC_SRC_SIDE_SOURCE}" "${SYNC_LOSS_TARGET}" 22047 129486 4
assert_helper_status 2 ha_session_sync_idle_sample node0 node1 "${SYNC_SRC_SIDE_SOURCE}" "${SYNC_LOSS_TARGET}" '' '' ''

# #16289 stateful wait loops: an observed unreceived send must NOT be
# absorbed by re-baselining. Both production wait loops are extracted
# verbatim and driven offline (stubbed capture/sleep/pass/fail/void):
# 15/174 -> 16/174 repeated must never idle; only 16/175 idles. The old
# re-baseline-on-every-non-idle loop absorbed the 16 and PASSed.
LOOP_DIR="${TMP_DIR}/sync-idle-loops"
mkdir -p "$LOOP_DIR"
LOOP_HELPERS="${LOOP_DIR}/wait-loops.sh"
python3 - "${ROOT}/test/incus/test-failover.sh" "${ROOT}/scripts/userspace-ha-failover-validation.sh" "$LOOP_HELPERS" <<'PY'
import pathlib
import re
import sys

failover_text = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8")
userspace_text = pathlib.Path(sys.argv[2]).read_text(encoding="utf-8")
blocks = []
for text, name in (
    (failover_text, "ha_wait_for_session_sync_idle"),
    (userspace_text, "wait_for_session_sync_idle"),
    (userspace_text, "node_name"),
    (userspace_text, "vm_artifact_suffix"),
    (userspace_text, "sync_snapshot_path"),
    (userspace_text, "capture_sync_snapshot"),
):
    match = re.search(rf"^{name}\(\) \{{\n.*?^\}}\n", text, re.M | re.S)
    if not match:
        raise SystemExit(f"cannot extract {name} for #16289 loop coverage")
    blocks.append(match.group(0))
pathlib.Path(sys.argv[3]).write_text("".join(blocks), encoding="utf-8")
PY

write_sync_fixture() {
	# $1=path $2=sent $3=received $4=pending
	cat >"$1" <<EOF
Services Synchronized:
Session create $2 $3

Session delta pending: $4
Session delta dropped: 0
Session delta drained: 0
EOF
}

LOOP_RUNNER_FILE="${LOOP_DIR}/runner.sh"
cat >"${LOOP_RUNNER_FILE}" <<'RUNNER_EOF'
IFS="," read -r -a SEQ <<< "$SEQ_CSV"
source "$1"
source "$2"
PASS=0 FAIL=0 VOID=0
printf '0\n' > "${SEQ_INDEX_FILE}"
printf '0\n' > "${SEQ_CALLS_FILE}"
pass() { PASS=$((PASS + 1)); printf "PASS-MARK %s\n" "$*"; }
fail() { FAIL=$((FAIL + 1)); printf "FAIL-MARK %s\n" "$*"; }
void() { VOID=$((VOID + 1)); printf "VOID-MARK %s\n" "$*"; }
sleep() { :; }
run_vm() { :; }
write_runner_fixture() {
	# $1=path $2=sent $3=received $4=pending [$5=dropped]
	cat >"$1" <<EOF
Services Synchronized:
Session create $2 $3

Session delta pending: $4
Session delta dropped: ${5:-0}
Session delta drained: 0
EOF
}
write_seq_pair() {
	# Index/calls live in files: captures run inside $(...) subshells in
	# the failover loop, so shell variables would reset every attempt.
	# A pair is sent/received/target-pending[/source-pending/source-dropped].
	local idx pair sent recv pending src_pending src_dropped calls
	idx="$(cat "${SEQ_INDEX_FILE}")"
	pair="${SEQ[$idx]}"
	IFS=/ read -r sent recv pending src_pending src_dropped <<< "$pair"
	write_runner_fixture "$SEQ_SOURCE" "$sent" 0 "${src_pending:-0}" "${src_dropped:-0}"
	write_runner_fixture "$SEQ_TARGET" 0 "$recv" "$pending"
	if (( idx < ${#SEQ[@]} - 1 )); then printf '%s\n' "$((idx + 1))" > "${SEQ_INDEX_FILE}"; fi
	calls="$(cat "${SEQ_CALLS_FILE}")"; printf '%s\n' "$((calls + 1))" > "${SEQ_CALLS_FILE}"
}
ha_capture_sync_stats() {
	# #18632: the failover loop captures TARGET then source per attempt;
	# advance the sequence only on the target capture (one pair per
	# attempt). Capture timing itself is exercised by the timeline cells.
	local label="$1" node_id="$2"
	if [[ "$node_id" == "$SEQ_TARGET_ID" ]]; then write_seq_pair; printf "%s\n" "$SEQ_TARGET"; else printf "%s\n" "$SEQ_SOURCE"; fi
}
capture_sync_snapshot() {
	# #18632: the userspace loop captures TARGET then source per
	# iteration; advance only on the target capture (one pair per
	# iteration).
	local label="$2" path
	path="$(sync_snapshot_path "$label" "$1")"
	if [[ "$1" == "$TARGET_VM" ]]; then write_seq_pair; cp "$SEQ_TARGET" "$path"; else cp "$SEQ_SOURCE" "$path"; fi
}
run_failover_loop() {
	SEQ_TARGET_ID=node1
	if ha_wait_for_session_sync_idle loop node0 fw0 node1 fw1; then printf "LOOPRC=0\n"; else printf "LOOPRC=%s\n" "$?"; fi
	printf "VERDICTS PASS=%s FAIL=%s VOID=%s CALLS=%s\n" "$PASS" "$FAIL" "$VOID" "$(cat "${SEQ_CALLS_FILE}")"
}
run_userspace_loop() {
	SOURCE_VM="$FW0" TARGET_VM="$FW1"
	if wait_for_session_sync_idle loop; then printf "LOOPRC=0\n"; else printf "LOOPRC=%s\n" "$?"; fi
	printf "VERDICTS PASS=%s FAIL=%s VOID=%s CALLS=%s\n" "$PASS" "$FAIL" "$VOID" "$(cat "${SEQ_CALLS_FILE}")"
}
# #18632: an unknown helper verdict must VOID in both loops.
if [[ -n "${FORCE_SAMPLE_RC:-}" ]]; then
	ha_session_sync_idle_sample() { return "$FORCE_SAMPLE_RC"; }
fi
case "$3" in
failover) run_failover_loop ;;
userspace) run_userspace_loop ;;
*) printf "unknown loop %s\n" "$3" >&2; exit 2 ;;
esac
RUNNER_EOF

run_sync_loop_case() {
	# $1=loop(failover|userspace) $2=timeout $3=expected full output $4=context; rest: sent/recv/pending sequence
	local loop="$1" timeout="$2" expected="$3" context="$4"
	shift 4
	local seq_csv out
	seq_csv="$(IFS=,; printf '%s' "$*")"
	cp "${ROOT}/test/incus/ha-assurance-lib.sh" "$LOOP_DIR/lib.sh"
	out="$(SEQ_CSV="$seq_csv" SESSION_SYNC_IDLE_TIMEOUT="$timeout" SESSION_SYNC_IDLE_STABLE_SAMPLES=3 \
		SEQ_SOURCE="${LOOP_DIR}/seq-source.txt" SEQ_TARGET="${LOOP_DIR}/seq-target.txt" SEQ_INDEX_FILE="${LOOP_DIR}/seq-index" SEQ_CALLS_FILE="${LOOP_DIR}/seq-calls" \
		ARTIFACT_DIR="$LOOP_DIR" SOURCE_NODE=0 TARGET_NODE=1 FW0=fw0 FW1=fw1 SEQ_EXPORT=1 FORCE_SAMPLE_RC="${FORCE_SAMPLE_RC:-}" \
		bash -euo pipefail "$LOOP_RUNNER_FILE" "$LOOP_DIR/lib.sh" "$LOOP_HELPERS" "$loop" 2>&1)"
	# The failover timeout reports its elapsed seconds; normalise them.
	out="$(sed -E 's/attempts \([0-9]+s(;|\))/attempts (Ns\1/' <<< "$out")"
	assert_eq "$out" "$expected" "$context"
}

# Stuck: baseline 15/174, one unreceived send 16/174 repeated forever.
# Timeout 8 = baseline + 6 stuck repeats + FAIL; never PASS.
run_sync_loop_case failover 8 'session sync node0->node1 baseline: source sent=15, target received=174, pending=0
session sync node0->node1 not idle: source sent=16 (baseline 15), target received=174 (baseline 174), outstanding beyond floor=1, pending=0
session sync node0->node1 not idle: source sent=16 (baseline 15), target received=174 (baseline 174), outstanding beyond floor=1, pending=0
session sync node0->node1 not idle: source sent=16 (baseline 15), target received=174 (baseline 174), outstanding beyond floor=1, pending=0
session sync node0->node1 not idle: source sent=16 (baseline 15), target received=174 (baseline 174), outstanding beyond floor=1, pending=0
session sync node0->node1 not idle: source sent=16 (baseline 15), target received=174 (baseline 174), outstanding beyond floor=1, pending=0
session sync node0->node1 not idle: source sent=16 (baseline 15), target received=174 (baseline 174), outstanding beyond floor=1, pending=0
session sync node0->node1 not idle: source sent=16 (baseline 15), target received=174 (baseline 174), outstanding beyond floor=1, pending=0
FAIL-MARK loop: session sync did not become idle within 8 attempts (Ns; 0 of 3 samples at the floor) (node0->node1)
LOOPRC=1
VERDICTS PASS=0 FAIL=1 VOID=0 CALLS=8' 'failover loop: unreceived send is never absorbed' '15/174/0' '16/174/0'
run_sync_loop_case userspace 8 'FAIL-MARK loop: session sync did not become idle before timeout (source_sent=16 target_recv=174 target_delta_pending=0 target_delta_drained=0)
LOOPRC=1
VERDICTS PASS=0 FAIL=1 VOID=0 CALLS=8' 'userspace loop: unreceived send is never absorbed' '15/174/0' '16/174/0'
# Catch-up: 15/174 -> 16/174 -> 16/175 x3 idle samples -> PASS at sample 5.
run_sync_loop_case failover 30 'session sync node0->node1 baseline: source sent=15, target received=174, pending=0
session sync node0->node1 not idle: source sent=16 (baseline 15), target received=174 (baseline 174), outstanding beyond floor=1, pending=0
PASS-MARK loop: session sync idle (node0->node1, 3 samples at the floor)
LOOPRC=0
VERDICTS PASS=1 FAIL=0 VOID=0 CALLS=5' 'failover loop: received catch-up idles' '15/174/0' '16/174/0' '16/175/0'
run_sync_loop_case userspace 30 'PASS-MARK loop: session sync idle (source_sent=16 target_recv=175 target_delta_pending=0 target_delta_drained=0)
LOOPRC=0
VERDICTS PASS=1 FAIL=0 VOID=0 CALLS=5' 'userspace loop: received catch-up idles' '15/174/0' '16/174/0' '16/175/0'
# Rewind-only re-baseline: 15/174 -> restart 2/3 -> 2/3 x3 -> PASS sample 5.
run_sync_loop_case failover 30 'session sync node0->node1 baseline: source sent=15, target received=174, pending=0
session sync node0->node1 not idle: counters rewound since baseline (source sent=2 baseline=15, target received=3 baseline=174, pending=0); re-baseline required
PASS-MARK loop: session sync idle (node0->node1, 3 samples at the floor)
LOOPRC=0
VERDICTS PASS=1 FAIL=0 VOID=0 CALLS=5' 'failover loop: rewind re-baselines then idles' '15/174/0' '2/3/0'
run_sync_loop_case userspace 30 'PASS-MARK loop: session sync idle (source_sent=2 target_recv=3 target_delta_pending=0 target_delta_drained=0)
LOOPRC=0
VERDICTS PASS=1 FAIL=0 VOID=0 CALLS=5' 'userspace loop: rewind re-baselines then idles' '15/174/0' '2/3/0'
# First sample establishes the baseline (minimum 4 samples to PASS).
run_sync_loop_case failover 30 'session sync node0->node1 baseline: source sent=15, target received=174, pending=0
PASS-MARK loop: session sync idle (node0->node1, 3 samples at the floor)
LOOPRC=0
VERDICTS PASS=1 FAIL=0 VOID=0 CALLS=4' 'failover loop: first sample is never idle alone' '15/174/0'
run_sync_loop_case userspace 30 'PASS-MARK loop: session sync idle (source_sent=15 target_recv=174 target_delta_pending=0 target_delta_drained=0)
LOOPRC=0
VERDICTS PASS=1 FAIL=0 VOID=0 CALLS=4' 'userspace loop: first sample is never idle alone' '15/174/0'
# #16500 -> #18632 shrinking gap: baseline 20/17 with 3 in flight,
# delivered to 20/20 (repeated). Sample 2 is a NEW FLOOR (re-baseline,
# streak restarts), then 3 idle samples -> PASS at sample 5.
run_sync_loop_case failover 30 'session sync node0->node1 baseline: source sent=20, target received=17, pending=0
session sync node0->node1 new floor: source sent=20, target received=20 is 3 below the baseline (sent=20 received=17), pending=0; re-baseline
PASS-MARK loop: session sync idle (node0->node1, 3 samples at the floor)
LOOPRC=0
VERDICTS PASS=1 FAIL=0 VOID=0 CALLS=5' 'failover loop: shrinking in-flight gap re-baselines then idles' '20/17/0' '20/20/0'
run_sync_loop_case userspace 30 'PASS-MARK loop: session sync idle (source_sent=20 target_recv=20 target_delta_pending=0 target_delta_drained=0)
LOOPRC=0
VERDICTS PASS=1 FAIL=0 VOID=0 CALLS=5' 'userspace loop: shrinking in-flight gap re-baselines then idles' '20/17/0' '20/20/0'
# #18632: a backlog still DRAINING never reads idle. Sent holds at 30
# while received climbs 20, 21, ... one per sample: every sample is a new
# floor, so the streak never builds; timeout 8 FAILs. (The old fixed
# baseline read 21, 22, 23 as idle and PASSed with 7 still outstanding.)
run_sync_loop_case failover 8 'session sync node0->node1 baseline: source sent=30, target received=20, pending=0
session sync node0->node1 new floor: source sent=30, target received=21 is 1 below the baseline (sent=30 received=20), pending=0; re-baseline
session sync node0->node1 new floor: source sent=30, target received=22 is 1 below the baseline (sent=30 received=21), pending=0; re-baseline
session sync node0->node1 new floor: source sent=30, target received=23 is 1 below the baseline (sent=30 received=22), pending=0; re-baseline
session sync node0->node1 new floor: source sent=30, target received=24 is 1 below the baseline (sent=30 received=23), pending=0; re-baseline
session sync node0->node1 new floor: source sent=30, target received=25 is 1 below the baseline (sent=30 received=24), pending=0; re-baseline
session sync node0->node1 new floor: source sent=30, target received=26 is 1 below the baseline (sent=30 received=25), pending=0; re-baseline
session sync node0->node1 new floor: source sent=30, target received=27 is 1 below the baseline (sent=30 received=26), pending=0; re-baseline
FAIL-MARK loop: session sync did not become idle within 8 attempts (Ns; 0 of 3 samples at the floor) (node0->node1)
LOOPRC=1
VERDICTS PASS=0 FAIL=1 VOID=0 CALLS=8' 'failover loop: a draining backlog never reads idle' '30/20/0' '30/21/0' '30/22/0' '30/23/0' '30/24/0' '30/25/0' '30/26/0' '30/27/0'
run_sync_loop_case userspace 8 'FAIL-MARK loop: session sync did not become idle before timeout (source_sent=30 target_recv=27 target_delta_pending=0 target_delta_drained=0)
LOOPRC=1
VERDICTS PASS=0 FAIL=1 VOID=0 CALLS=8' 'userspace loop: a draining backlog never reads idle' '30/20/0' '30/21/0' '30/22/0' '30/23/0' '30/24/0' '30/25/0' '30/26/0' '30/27/0'
# #18632: a new floor mid-streak RESTARTS the streak. Two idle samples
# at 20/20, then 20/21 (a bulk frame or a delivered in-flight create):
# the earlier "idle" samples sat above the real floor, so they do not
# count. PASS needs 3 more samples at the new floor: sample 7, not 5.
run_sync_loop_case failover 30 'session sync node0->node1 baseline: source sent=20, target received=20, pending=0
session sync node0->node1 new floor: source sent=20, target received=21 is 1 below the baseline (sent=20 received=20), pending=0; re-baseline
PASS-MARK loop: session sync idle (node0->node1, 3 samples at the floor)
LOOPRC=0
VERDICTS PASS=1 FAIL=0 VOID=0 CALLS=7' 'failover loop: a new floor mid-streak restarts the streak' '20/20/0' '20/20/0' '20/20/0' '20/21/0'
run_sync_loop_case userspace 30 'PASS-MARK loop: session sync idle (source_sent=20 target_recv=21 target_delta_pending=0 target_delta_drained=0)
LOOPRC=0
VERDICTS PASS=1 FAIL=0 VOID=0 CALLS=7' 'userspace loop: a new floor mid-streak restarts the streak' '20/20/0' '20/20/0' '20/20/0' '20/21/0'
# #18632 source side: the source drops a session delta after the floor
# (dropped 0 -> 1). Every later sample stays not idle (the baseline keeps
# the old dropped count), so the wait FAILs at its timeout.
run_sync_loop_case failover 5 'session sync node0->node1 baseline: source sent=20, target received=20, pending=0
session sync node0->node1 not idle: the source dropped 1 session delta(s) since the baseline (dropped=1 baseline=0); a dropped delta never becomes a sent create
session sync node0->node1 not idle: the source dropped 1 session delta(s) since the baseline (dropped=1 baseline=0); a dropped delta never becomes a sent create
session sync node0->node1 not idle: the source dropped 1 session delta(s) since the baseline (dropped=1 baseline=0); a dropped delta never becomes a sent create
session sync node0->node1 not idle: the source dropped 1 session delta(s) since the baseline (dropped=1 baseline=0); a dropped delta never becomes a sent create
FAIL-MARK loop: session sync did not become idle within 5 attempts (Ns; 0 of 3 samples at the floor) (node0->node1)
LOOPRC=1
VERDICTS PASS=0 FAIL=1 VOID=0 CALLS=5' 'failover loop: a source delta drop is never absorbed' '20/20/0/0/0' '20/20/0/0/1'
run_sync_loop_case userspace 5 'FAIL-MARK loop: session sync did not become idle before timeout (source_sent=20 target_recv=20 target_delta_pending=0 target_delta_drained=0)
LOOPRC=1
VERDICTS PASS=0 FAIL=1 VOID=0 CALLS=5' 'userspace loop: a source delta drop is never absorbed' '20/20/0/0/0' '20/20/0/0/1'
# #18632 source side: a delta the source still holds keeps the pair not
# idle until it drains (source pending 2, 2, then 0 x3): PASS at sample 6.
run_sync_loop_case failover 30 'session sync node0->node1 baseline: source sent=20, target received=20, pending=0
session sync node0->node1 not idle: at the floor, but the source holds 2 undrained session delta(s)
session sync node0->node1 not idle: at the floor, but the source holds 2 undrained session delta(s)
PASS-MARK loop: session sync idle (node0->node1, 3 samples at the floor)
LOOPRC=0
VERDICTS PASS=1 FAIL=0 VOID=0 CALLS=6' 'failover loop: an undrained source delta holds the wait until it drains' '20/20/0/2/0' '20/20/0/2/0' '20/20/0/2/0' '20/20/0/0/0'
run_sync_loop_case userspace 30 'PASS-MARK loop: session sync idle (source_sent=20 target_recv=20 target_delta_pending=0 target_delta_drained=0)
LOOPRC=0
VERDICTS PASS=1 FAIL=0 VOID=0 CALLS=6' 'userspace loop: an undrained source delta holds the wait until it drains' '20/20/0/2/0' '20/20/0/2/0' '20/20/0/2/0' '20/20/0/0/0'
# #18632 (AC seat): an UNKNOWN helper verdict VOIDs in BOTH loops.
FORCE_SAMPLE_RC=7 run_sync_loop_case failover 5 'VOID-MARK loop: session sync sample verdict 7 unknown (node0->node1)
LOOPRC=2
VERDICTS PASS=0 FAIL=0 VOID=1 CALLS=1' 'failover loop: an unknown verdict is VOID' '20/20/0'
FORCE_SAMPLE_RC=7 run_sync_loop_case userspace 5 'VOID-MARK loop: session sync sample verdict 7 unknown: 
LOOPRC=0
VERDICTS PASS=0 FAIL=0 VOID=1 CALLS=1' 'userspace loop: an unknown verdict is VOID' '20/20/0'
# #18632: the N floor samples need NOT be consecutive. An above-floor
# sample (a create landing between the reads) neither counts nor resets
# the count: floor, above, floor, above, floor -> PASS at sample 6 (a
# consecutive rule would need samples 6-8).
run_sync_loop_case failover 30 'session sync node0->node1 baseline: source sent=20, target received=20, pending=0
session sync node0->node1 not idle: source sent=21 (baseline 20), target received=20 (baseline 20), outstanding beyond floor=1, pending=0
session sync node0->node1 not idle: source sent=22 (baseline 20), target received=21 (baseline 20), outstanding beyond floor=1, pending=0
PASS-MARK loop: session sync idle (node0->node1, 3 samples at the floor)
LOOPRC=0
VERDICTS PASS=1 FAIL=0 VOID=0 CALLS=6' 'failover loop: floor samples need not be consecutive' '20/20/0' '20/20/0' '21/20/0' '21/21/0' '22/21/0' '22/22/0'
run_sync_loop_case userspace 30 'PASS-MARK loop: session sync idle (source_sent=22 target_recv=22 target_delta_pending=0 target_delta_drained=0)
LOOPRC=0
VERDICTS PASS=1 FAIL=0 VOID=0 CALLS=6' 'userspace loop: floor samples need not be consecutive' '20/20/0' '20/20/0' '21/20/0' '21/21/0' '22/21/0' '22/22/0'
# #18632 LIVE REPLAY: the 30 samples of loss run 2's "before fw0 crash"
# wait (0.0.26680, mirror sweep ~4 creates/s), read target first. Floor
# readings came in pairs and never 3 in a row, so the consecutive rule
# FAILed this healthy pair; counting floor samples PASSes at sample 8.
run_sync_loop_case failover 30 'session sync node0->node1 baseline: source sent=51312, target received=68284, pending=0
session sync node0->node1 not idle: source sent=51323 (baseline 51312), target received=68292 (baseline 68284), outstanding beyond floor=3, pending=0
session sync node0->node1 not idle: source sent=51332 (baseline 51312), target received=68301 (baseline 68284), outstanding beyond floor=3, pending=0
session sync node0->node1 not idle: source sent=51356 (baseline 51312), target received=68326 (baseline 68284), outstanding beyond floor=2, pending=0
session sync node0->node1 not idle: source sent=51365 (baseline 51312), target received=68333 (baseline 68284), outstanding beyond floor=4, pending=0
PASS-MARK loop: session sync idle (node0->node1, 3 samples at the floor)
LOOPRC=0
VERDICTS PASS=1 FAIL=0 VOID=0 CALLS=8' 'failover loop: the loss run-2 sweep sequence PASSes by sample 8' '51312/68284/0/0/0' '51323/68292/0/0/0' '51332/68301/0/0/0' '51337/68309/0/0/0' '51347/68319/0/0/0' '51356/68326/0/0/0' '51365/68333/0/0/0' '51370/68342/0/0/0' '51387/68359/0/0/0' '51395/68364/0/0/0' '51404/68376/0/0/0' '51412/68384/0/0/0' '51421/68390/0/0/0' '51439/68404/0/0/0' '51442/68414/0/0/0' '51450/68422/0/0/0' '51459/68427/0/0/0' '51471/68438/0/0/0' '51474/68446/0/0/0' '51482/68454/0/0/0' '51494/68464/0/0/0' '51503/68469/0/0/0' '51506/68478/0/0/0' '51514/68486/0/0/0' '51526/68493/0/0/0' '51535/68502/0/0/0' '51539/68511/0/0/0' '51551/68523/0/0/0' '51565/68532/0/0/0' '51568/68540/0/0/0'
run_sync_loop_case userspace 30 'PASS-MARK loop: session sync idle (source_sent=51370 target_recv=68342 target_delta_pending=0 target_delta_drained=0)
LOOPRC=0
VERDICTS PASS=1 FAIL=0 VOID=0 CALLS=8' 'userspace loop: the loss run-2 sweep sequence PASSes by sample 8' '51312/68284/0/0/0' '51323/68292/0/0/0' '51332/68301/0/0/0' '51337/68309/0/0/0' '51347/68319/0/0/0' '51356/68326/0/0/0' '51365/68333/0/0/0' '51370/68342/0/0/0' '51387/68359/0/0/0' '51395/68364/0/0/0' '51404/68376/0/0/0' '51412/68384/0/0/0' '51421/68390/0/0/0' '51439/68404/0/0/0' '51442/68414/0/0/0' '51450/68422/0/0/0' '51459/68427/0/0/0' '51471/68438/0/0/0' '51474/68446/0/0/0' '51482/68454/0/0/0' '51494/68464/0/0/0' '51503/68469/0/0/0' '51506/68478/0/0/0' '51514/68486/0/0/0' '51526/68493/0/0/0' '51535/68502/0/0/0' '51539/68511/0/0/0' '51551/68523/0/0/0' '51565/68532/0/0/0' '51568/68540/0/0/0'
# #18632: the LATEST sample must be one of the counted. The count reaches
# N-1 (2), then a create is lost and D never returns to the floor: no
# later sample can complete the count, so the wait FAILs ("2 of 3").
run_sync_loop_case failover 8 'session sync node0->node1 baseline: source sent=20, target received=20, pending=0
session sync node0->node1 not idle: source sent=21 (baseline 20), target received=20 (baseline 20), outstanding beyond floor=1, pending=0
session sync node0->node1 not idle: source sent=21 (baseline 20), target received=20 (baseline 20), outstanding beyond floor=1, pending=0
session sync node0->node1 not idle: source sent=21 (baseline 20), target received=20 (baseline 20), outstanding beyond floor=1, pending=0
session sync node0->node1 not idle: source sent=21 (baseline 20), target received=20 (baseline 20), outstanding beyond floor=1, pending=0
session sync node0->node1 not idle: source sent=21 (baseline 20), target received=20 (baseline 20), outstanding beyond floor=1, pending=0
FAIL-MARK loop: session sync did not become idle within 8 attempts (Ns; 2 of 3 samples at the floor) (node0->node1)
LOOPRC=1
VERDICTS PASS=0 FAIL=1 VOID=0 CALLS=8' 'failover loop: a loss after N-1 floor samples is never completed' '20/20/0' '20/20/0' '20/20/0' '21/20/0'
run_sync_loop_case userspace 8 'FAIL-MARK loop: session sync did not become idle before timeout (source_sent=21 target_recv=20 target_delta_pending=0 target_delta_drained=0)
LOOPRC=1
VERDICTS PASS=0 FAIL=1 VOID=0 CALLS=8' 'userspace loop: a loss after N-1 floor samples is never completed' '20/20/0' '20/20/0' '20/20/0' '21/20/0'
# #18632: a sample at the floor with the target's delta queue pending is
# never counted: pending 3 throughout -> FAIL ("0 of 3").
run_sync_loop_case failover 5 'session sync node0->node1 baseline: source sent=20, target received=20, pending=0
session sync node0->node1 not idle: source sent=20 (baseline 20), target received=20 (baseline 20), outstanding beyond floor=0, pending=3
session sync node0->node1 not idle: source sent=20 (baseline 20), target received=20 (baseline 20), outstanding beyond floor=0, pending=3
session sync node0->node1 not idle: source sent=20 (baseline 20), target received=20 (baseline 20), outstanding beyond floor=0, pending=3
session sync node0->node1 not idle: source sent=20 (baseline 20), target received=20 (baseline 20), outstanding beyond floor=0, pending=3
FAIL-MARK loop: session sync did not become idle within 5 attempts (Ns; 0 of 3 samples at the floor) (node0->node1)
LOOPRC=1
VERDICTS PASS=0 FAIL=1 VOID=0 CALLS=5' 'failover loop: a pending sample at the floor is never counted' '20/20/0' '20/20/3'
run_sync_loop_case userspace 5 'FAIL-MARK loop: session sync did not become idle before timeout (source_sent=20 target_recv=20 target_delta_pending=3 target_delta_drained=0)
LOOPRC=1
VERDICTS PASS=0 FAIL=1 VOID=0 CALLS=5' 'userspace loop: a pending sample at the floor is never counted' '20/20/0' '20/20/3'
# #18632: received ahead at the baseline (20/22) then 22/22 repeated is
# NOT idle any more. With the target read first, capture skew cannot put
# D below the floor, so D rising from -2 to 0 is two creates outstanding
# beyond it; the dropped (sent == received) escape masked exactly this.
run_sync_loop_case failover 4 'session sync node0->node1 baseline: source sent=20, target received=22, pending=0
session sync node0->node1 not idle: source sent=22 (baseline 20), target received=22 (baseline 22), outstanding beyond floor=2, pending=0
session sync node0->node1 not idle: source sent=22 (baseline 20), target received=22 (baseline 22), outstanding beyond floor=2, pending=0
session sync node0->node1 not idle: source sent=22 (baseline 20), target received=22 (baseline 22), outstanding beyond floor=2, pending=0
FAIL-MARK loop: session sync did not become idle within 4 attempts (Ns; 0 of 3 samples at the floor) (node0->node1)
LOOPRC=1
VERDICTS PASS=0 FAIL=1 VOID=0 CALLS=4' 'failover loop: counters meeting above the floor are outstanding' '20/22/0' '22/22/0'
run_sync_loop_case userspace 4 'FAIL-MARK loop: session sync did not become idle before timeout (source_sent=22 target_recv=22 target_delta_pending=0 target_delta_drained=0)
LOOPRC=1
VERDICTS PASS=0 FAIL=1 VOID=0 CALLS=4' 'userspace loop: counters meeting above the floor are outstanding' '20/22/0' '22/22/0'
# #16500 growing gap never idles: 20/20 -> 25/20 repeated -> timeout.
run_sync_loop_case failover 8 'session sync node0->node1 baseline: source sent=20, target received=20, pending=0
session sync node0->node1 not idle: source sent=25 (baseline 20), target received=20 (baseline 20), outstanding beyond floor=5, pending=0
session sync node0->node1 not idle: source sent=25 (baseline 20), target received=20 (baseline 20), outstanding beyond floor=5, pending=0
session sync node0->node1 not idle: source sent=25 (baseline 20), target received=20 (baseline 20), outstanding beyond floor=5, pending=0
session sync node0->node1 not idle: source sent=25 (baseline 20), target received=20 (baseline 20), outstanding beyond floor=5, pending=0
session sync node0->node1 not idle: source sent=25 (baseline 20), target received=20 (baseline 20), outstanding beyond floor=5, pending=0
session sync node0->node1 not idle: source sent=25 (baseline 20), target received=20 (baseline 20), outstanding beyond floor=5, pending=0
session sync node0->node1 not idle: source sent=25 (baseline 20), target received=20 (baseline 20), outstanding beyond floor=5, pending=0
FAIL-MARK loop: session sync did not become idle within 8 attempts (Ns; 0 of 3 samples at the floor) (node0->node1)
LOOPRC=1
VERDICTS PASS=0 FAIL=1 VOID=0 CALLS=8' 'failover loop: growing gap never idles' '20/20/0' '25/20/0'
run_sync_loop_case userspace 8 'FAIL-MARK loop: session sync did not become idle before timeout (source_sent=25 target_recv=20 target_delta_pending=0 target_delta_drained=0)
LOOPRC=1
VERDICTS PASS=0 FAIL=1 VOID=0 CALLS=8' 'userspace loop: growing gap never idles' '20/20/0' '25/20/0'

# #18632 TIMELINE cells: capture ORDER is the fix, so the counters must be
# a function of WHEN each capture reads them, not a canned pair. A virtual
# clock (tenths of a second) advances 5 per capture and 10 per sleep, so
# attempt k reads at 20(k-1) and 20(k-1)+5. Each event "E:R" is one
# create counted as sent at E and as received at R ("never" = lost). The
# source reads sent = base + #(E <= now); the target reads received =
# base + #(R <= now). ORDER records T/S per capture, one word per attempt.
TIMELINE_RUNNER_FILE="${LOOP_DIR}/timeline-runner.sh"
cat >"${TIMELINE_RUNNER_FILE}" <<'RUNNER_EOF'
source "$1"
source "$2"
PASS=0 FAIL=0 VOID=0
printf '0\n' >"${TL_CLOCK_FILE}"
: >"${TL_ORDER_FILE}"
printf '0\n' >"${TL_CAPTURES_FILE}"
pass() { PASS=$((PASS + 1)); printf "PASS-MARK %s\n" "$*"; }
fail() { FAIL=$((FAIL + 1)); printf "FAIL-MARK %s\n" "$*"; }
void() { VOID=$((VOID + 1)); printf "VOID-MARK %s\n" "$*"; }
run_vm() { :; }
sleep() {
	printf '%s\n' "$(( $(cat "${TL_CLOCK_FILE}") + 10 ))" >"${TL_CLOCK_FILE}"
	printf ' ' >>"${TL_ORDER_FILE}"
}
tl_capture() {
	# $1=role (S|T) $2=path
	local now sent="$TL_SENT_BASE" received="$TL_RECV_BASE" ev enq rcv n
	local -a events=()
	now="$(cat "${TL_CLOCK_FILE}")"
	IFS="," read -r -a events <<< "$TL_EVENTS"
	for ev in "${events[@]}"; do
		[[ -n "$ev" ]] || continue
		enq="${ev%%:*}"; rcv="${ev#*:}"
		if (( enq <= now )); then sent=$((sent + 1)); fi
		if [[ "$rcv" != never ]] && (( rcv <= now )); then received=$((received + 1)); fi
	done
	if [[ "$1" == S ]]; then
		printf 'Services Synchronized:\nSession create %s 0\n\nSession delta pending: 0\nSession delta dropped: 0\nSession delta drained: 0\n' "$sent" >"$2"
	else
		printf 'Services Synchronized:\nSession create 0 %s\n\nSession delta pending: 0\nSession delta dropped: 0\nSession delta drained: 0\n' "$received" >"$2"
	fi
	printf '%s' "$1" >>"${TL_ORDER_FILE}"
	printf '%s\n' "$(( now + 5 ))" >"${TL_CLOCK_FILE}"
	n="$(cat "${TL_CAPTURES_FILE}")"; printf '%s\n' "$((n + 1))" >"${TL_CAPTURES_FILE}"
}
ha_capture_sync_stats() {
	# Runs inside $(...) in the failover loop: all state lives in files.
	local label="$1" node_id="$2" path role=T n
	n="$(cat "${TL_CAPTURES_FILE}")"
	path="${TL_DIR}/capture-${n}.txt"
	if [[ "$node_id" == node0 ]]; then role=S; fi
	tl_capture "$role" "$path"
	printf '%s\n' "$path"
}
capture_sync_snapshot() {
	local path role=T
	path="$(sync_snapshot_path "$2" "$1")"
	if [[ "$1" == "$SOURCE_VM" ]]; then role=S; fi
	tl_capture "$role" "$path"
}
case "$3" in
failover)
	if ha_wait_for_session_sync_idle loop node0 fw0 node1 fw1 2>/dev/null; then rc=0; else rc=$?; fi ;;
userspace)
	SOURCE_VM="$FW0" TARGET_VM="$FW1"
	if wait_for_session_sync_idle loop 2>/dev/null; then rc=0; else rc=$?; fi ;;
*) printf "unknown loop %s\n" "$3" >&2; exit 2 ;;
esac
printf 'TIMELINE rc=%s PASS=%s FAIL=%s VOID=%s ORDER=%s\n' "$rc" "$PASS" "$FAIL" "$VOID" "$(cat "${TL_ORDER_FILE}")"
RUNNER_EOF

run_timeline_case() {
	# $1=loop $2=timeout $3=events csv $4=expected TIMELINE line $5=context
	local out tl_dir="${LOOP_DIR}/timeline-$1"
	rm -rf "$tl_dir"; mkdir -p "$tl_dir"
	cp "${ROOT}/test/incus/ha-assurance-lib.sh" "$LOOP_DIR/lib.sh"
	out="$(TL_EVENTS="$3" TL_SENT_BASE=22047 TL_RECV_BASE=129487 TL_DIR="$tl_dir" \
		TL_CLOCK_FILE="$tl_dir/clock" TL_ORDER_FILE="$tl_dir/order" TL_CAPTURES_FILE="$tl_dir/captures" \
		SESSION_SYNC_IDLE_TIMEOUT="$2" SESSION_SYNC_IDLE_STABLE_SAMPLES=3 \
		ARTIFACT_DIR="$tl_dir" SOURCE_NODE=0 TARGET_NODE=1 FW0=fw0 FW1=fw1 \
		bash -euo pipefail "$TIMELINE_RUNNER_FILE" "$LOOP_DIR/lib.sh" "$LOOP_HELPERS" "$1" 2>&1 | grep '^TIMELINE')"
	assert_eq "$out" "$4" "$5"
}
for tl_loop in failover userspace; do
	# Quiet pair: the floor is the first sample, PASS on attempt 4.
	run_timeline_case "$tl_loop" 30 '' \
		'TIMELINE rc=0 PASS=1 FAIL=0 VOID=0 ORDER=TS TS TS TS' \
		"${tl_loop} timeline: quiet pair idles, target read first"
	# THE #18632 SHAPE: a create sent at 0.2 s and received at 0.3 s, i.e.
	# BETWEEN the first attempt's two reads. Target-first reads it as sent
	# but not yet received (D one high), attempt 2 is a new floor, and the
	# wait PASSes on attempt 5. Source-first read it as received but not
	# sent: a baseline one BELOW the floor, then FAIL for the whole wait.
	run_timeline_case "$tl_loop" 30 '2:3' \
		'TIMELINE rc=0 PASS=1 FAIL=0 VOID=0 ORDER=TS TS TS TS TS' \
		"${tl_loop} timeline: a create between the first two reads cannot lock in a phantom deficit"
	# POSITIVE CONTROL for loss: a create sent at 2.5 s (attempt 2) and
	# NEVER received. D stays one above the floor forever: FAIL, never
	# PASS. A baseline allowed to move UP would absorb it and PASS.
	run_timeline_case "$tl_loop" 8 '25:never' \
		'TIMELINE rc=1 PASS=0 FAIL=1 VOID=0 ORDER=TS TS TS TS TS TS TS TS ' \
		"${tl_loop} timeline: a lost create is never absorbed"
	# Loss AFTER the streak began: attempt 1 is inflated (a create at
	# 0.2 s), attempt 2 a new floor, attempt 3 idle (streak 1), then a
	# create sent at 6.5 s is never received, among delivered creates at
	# 6.1 s and 8.3 s: still FAIL.
	run_timeline_case "$tl_loop" 10 '2:3,61:62,65:never,83:84' \
		'TIMELINE rc=1 PASS=0 FAIL=1 VOID=0 ORDER=TS TS TS TS TS TS TS TS TS TS ' \
		"${tl_loop} timeline: a create lost mid-streak among delivered creates is never absorbed"
	# KNOWN BLIND SPOT, PINNED (AC and AD seats): drain plus loss. Two
	# creates sent at 0.1 s and 0.2 s, received at 1.5 s, are in flight at
	# the first sample; a third sent at 1.0 s is never received. When the
	# two land, D falls to one above the true floor; that becomes the new
	# floor and the wait PASSes with the lost create absorbed. The
	# pre-#18632 fixed baseline PASSes it too; closing it needs a
	# per-create epoch, not counters. This cell pins the limitation, so a
	# change to it is a deliberate, reviewed one.
	run_timeline_case "$tl_loop" 30 '1:15,2:15,10:never' \
		'TIMELINE rc=0 PASS=1 FAIL=0 VOID=0 ORDER=TS TS TS TS TS' \
		"${tl_loop} timeline: KNOWN LIMIT a create lost while others are still in flight is absorbed"
	# Its control without the lost create, and its sibling with the loss
	# AFTER the two landed (3.0 s; attempt 2 already saw the true floor),
	# which is NOT absorbed: FAIL.
	run_timeline_case "$tl_loop" 30 '1:15,2:15' \
		'TIMELINE rc=0 PASS=1 FAIL=0 VOID=0 ORDER=TS TS TS TS TS' \
		"${tl_loop} timeline: two creates in flight at the first sample land, then idle"
	run_timeline_case "$tl_loop" 8 '1:15,2:15,30:never' \
		'TIMELINE rc=1 PASS=0 FAIL=1 VOID=0 ORDER=TS TS TS TS TS TS TS TS ' \
		"${tl_loop} timeline: a create lost after the true floor was seen is never absorbed"
done
printf '#18632 target-first capture + downward-only floor: phantom deficit cleared, lost create FAILs\n'
printf '#16500 shrinking-gap samples idle; growing gap never idles\n'
printf '#16289 stateful wait loops keep outstanding deltas until received\n'

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

# #18686: the standby parser is fed the production renderer's golden, not
# hand-written lines. The fixtures this replaced put `rg1 active=false` on a
# line of its own, which matched the parser and never the product: the
# summary joins every group onto ONE `HA groups:` line. Against real
# captures the verdict was therefore VOID on every run. The golden carries
# `rg0 active=true` and `rg1 active=false` on that one line, so selecting
# the RG out of the line is what these rows prove. The real-capture rows
# are in the Group 7 block below.
assert_helper_status 0 ha_standby_status_verdict "${STATISTICS_RENDERED}" 1
assert_helper_status 1 ha_standby_status_verdict "${STATISTICS_RENDERED}" 0
assert_contains "$(<"${ERR}")" 'rg0 is active' 'golden standby status selects rg0 out of the HA groups line'

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

# #18558: the WAN-address duplicate check. The probe lines below are the
# shape ha_wan_claim_probe prints. The foreign MAC is the lab device that
# answered for tcp's 172.16.50.10 on every one of 512 probes, and the
# "probe" flag reflects the measured fact that the lab gateway and that device
# both answer an RFC 5227 probe addressed to us with target IP 0.0.0.0
# (2026-10-31).
OWN=02:bf:72:17:
GWP=$'reply 172.16.50.1 00:10:db:ff:10:01 probe'
CLAIM_CLEAN=$'iface ge-0-0-2.50 02:bf:72:17:01:00\n'"$GWP"$'\n'"$GWP"
CLAIM_DUP=$'iface ge-0-0-2.50 02:bf:72:17:01:00\nreply 172.16.50.10 18:e8:29:2c:13:7a probe\n'"$GWP"$'\nreply 172.16.50.10 18:E8:29:2C:13:7A probe'
CLAIM_PEER=$'iface ge-7-0-2.50 02:bf:72:17:01:01\nreply 172.16.50.10 02:bf:72:17:01:00 probe\n'"$GWP"
CLAIM_OTHER_CLUSTER=$'iface ge-0-0-2.50 02:bf:72:17:01:00\nreply 172.16.50.10 02:bf:72:18:01:00 probe\n'"$GWP"
CLAIM_OTHER_AND_FOREIGN=$'iface ge-0-0-2.50 02:bf:72:17:01:00\nreply 172.16.50.10 18:e8:29:2c:13:7a probe\nreply 172.16.50.10 02:bf:72:16:01:00 probe\n'"$GWP"
CLAIM_PHYS=$'iface ge-0-0-2.50 02:bf:72:17:01:00\nreply 172.16.50.10 10:66:6a:f6:c3:d2 probe\n'"$GWP"
CLAIM_GW_OTHER=$'iface ge-0-0-2.50 02:bf:72:17:01:00\nreply 172.16.50.1 00:10:db:ff:10:01 other'
CLAIM_DRIFT=$'iface ge-0-0-2.50 02:bf:72:18:01:00\n'"$GWP"
CLAIM_NORETH=$'iface ge-0-0-2.50 10:66:6a:f6:c3:d2\n'"$GWP"
CLAIM_BLIND=$'iface ge-0-0-2.50 02:bf:72:17:01:00'
CLAIM_DUP_BLIND=$'iface ge-0-0-2.50 02:bf:72:17:01:00\nreply 172.16.50.10 18:e8:29:2c:13:7a probe'
wcv() { ha_wan_claim_verdict "$@"; }
# Only the gateway answered, or our own RETH MAC (either node): unique.
assert_helper_status 0 wcv "$OWN" 172.16.50.10 172.16.50.1 "$CLAIM_CLEAN"
assert_helper_status 0 wcv "$OWN" 172.16.50.10 172.16.50.1 "$CLAIM_PEER"
# A non-xpf MAC answers for the address: duplicate. Upper and lower case are
# one MAC, so it is named exactly once in ANY case.
assert_helper_status 1 wcv "$OWN" 172.16.50.10 172.16.50.1 "$CLAIM_DUP"
assert_contains "$(<"${ERR}")" '172.16.50.10 is also answered for by 18:e8:29:2c:13:7a, a duplicate' \
	'duplicate WAN claim names the foreign MAC'
assert_eq "$(grep -io '18:e8:29:2c:13:7a' "${ERR}" | wc -l)" 1 'duplicate WAN claim names the MAC once, case-insensitively'
# Another xpf cluster's RETH MAC is an XPF defect (status 3), never the
# excusable status 1, and it wins over a co-present foreign claimant.
assert_helper_status 3 wcv "$OWN" 172.16.50.10 172.16.50.1 "$CLAIM_OTHER_CLUSTER"
assert_contains "$(<"${ERR}")" 'another xpf cluster (cluster-id 24, 02:bf:72:18:01:00)' \
	'other-cluster claim names the other cluster id'
assert_helper_status 3 wcv "$OWN" 172.16.50.10 172.16.50.1 "$CLAIM_OTHER_AND_FOREIGN"
assert_contains "$(<"${ERR}")" 'cluster-id 22' 'xpf claim wins over the foreign one and names cluster 22'
# A physical (non-RETH) MAC of one of OUR nodes is own once listed; unlisted
# it would be foreign.
assert_helper_status 0 wcv "$OWN" 172.16.50.10 172.16.50.1 "$CLAIM_PHYS"$'\nown 10:66:6a:f6:c3:d2'
assert_helper_status 0 wcv "$OWN" 172.16.50.10 172.16.50.1 "$CLAIM_PHYS"$'\nown 10:66:6A:F6:C3:D2'
assert_helper_status 1 wcv "$OWN" 172.16.50.10 172.16.50.1 "$CLAIM_PHYS"
# The gateway control counts only an answer to OUR probe.
assert_helper_status 2 wcv "$OWN" 172.16.50.10 172.16.50.1 "$CLAIM_GW_OTHER"
# A foreign claim is positive evidence even when the gateway was silent.
assert_helper_status 1 wcv "$OWN" 172.16.50.10 172.16.50.1 "$CLAIM_DUP_BLIND"
# Identity: conf vs live RETH MAC disagree -> VOID; no conf -> the live
# RETH MAC decides; neither -> VOID.
assert_helper_status 2 wcv "$OWN" 172.16.50.10 172.16.50.1 "$CLAIM_DRIFT"
assert_contains "$(<"${ERR}")" 'live RETH MAC says 02:bf:72:18:' 'conf/live cluster-id drift is named'
assert_helper_status 0 wcv '' 172.16.50.10 172.16.50.1 "$CLAIM_CLEAN"
assert_helper_status 1 wcv '' 172.16.50.10 172.16.50.1 "$CLAIM_DUP"
assert_helper_status 0 wcv "$OWN" 172.16.50.10 172.16.50.1 "$CLAIM_NORETH"
assert_helper_status 2 wcv '' 172.16.50.10 172.16.50.1 "$CLAIM_NORETH"
# No gateway answer and no claimant: the probe heard nothing, so VOID.
assert_helper_status 2 wcv "$OWN" 172.16.50.10 172.16.50.1 "$CLAIM_BLIND"
assert_helper_status 2 wcv "$OWN" 172.16.50.10 172.16.50.1 ''
assert_helper_status 2 wcv 02:bf:72:17 172.16.50.10 172.16.50.1 "$CLAIM_CLEAN"
assert_helper_status 2 wcv "$OWN" 172.16.50.1 172.16.50.1 "$CLAIM_CLEAN"
assert_helper_status 2 wcv "$OWN" 172.16.50.10 172.16.50.1

# The conf's cluster-id gives the prefix (tcp is 23 = 0x17).
printf 'chassis {\n    cluster {\n        cluster-id 23;\n    }\n}\n' >"${TMP_DIR}/claim-23.conf"
printf 'chassis {\n    cluster {\n        cluster-id 300;\n    }\n}\n' >"${TMP_DIR}/claim-300.conf"
printf 'chassis { }\n' >"${TMP_DIR}/claim-none.conf"
assert_helper_value '02:bf:72:17:' ha_wan_own_mac_prefix "${TMP_DIR}/claim-23.conf"
assert_helper_status 2 ha_wan_own_mac_prefix "${TMP_DIR}/claim-300.conf"
assert_helper_status 2 ha_wan_own_mac_prefix "${TMP_DIR}/claim-none.conf"
assert_helper_status 2 ha_wan_own_mac_prefix "${TMP_DIR}/claim-missing.conf"

# ha_wan_claim_check drives the probe, the node-MAC collection and the
# verdict. Both helpers are stubbed; they run inside command substitutions, so
# they record their argv in files.
ha_wan_claim_probe_real="$(declare -f ha_wan_claim_probe)"
ha_wan_node_macs_real="$(declare -f ha_wan_node_macs)"
CLAIM_STUB_OUT="" CLAIM_STUB_RC=0 CLAIM_STUB_OWN=""
ha_wan_claim_probe() { printf '%s' "$*" >"${TMP_DIR}/claim-stub-args"; printf '%s\n' "$CLAIM_STUB_OUT"; return "$CLAIM_STUB_RC"; }
ha_wan_node_macs() { printf '%s\n' "$1" >>"${TMP_DIR}/claim-stub-nodes"; [[ -n "$CLAIM_STUB_OWN" ]] && printf 'own %s\n' "$CLAIM_STUB_OWN"; return 0; }
claim_check_case() { # <expected-status> <reason-substring> <conf> <stub-out> <stub-rc> [own-mac]
	CLAIM_STUB_OUT="$4" CLAIM_STUB_RC="$5" CLAIM_STUB_OWN="${6:-}"
	rm -f "${TMP_DIR}/claim-stub-args" "${TMP_DIR}/claim-stub-nodes"
	if ! ha_wan_claim_check "$3" 172.16.50.10 172.16.50.1 tcp:fw0 tcp:fw1; then
		fail_test "ha_wan_claim_check returned nonzero (it must always return 0)"
	fi
	assert_eq "$HA_WAN_CLAIM_STATUS" "$1" "ha_wan_claim_check status for ${2}"
	assert_contains "$HA_WAN_CLAIM_REASON" "$2" "ha_wan_claim_check reason for ${2}"
}
claim_check_case 1 'also answered for by 18:e8:29:2c:13:7a' "${TMP_DIR}/claim-23.conf" "$CLAIM_DUP" 0
assert_eq "$(<"${TMP_DIR}/claim-stub-args")" '172.16.50.10 172.16.50.1 tcp:fw0 tcp:fw1' 'claim check passes address, gateway and nodes to the probe'
assert_eq "$(tr '\n' ' ' <"${TMP_DIR}/claim-stub-nodes")" 'tcp:fw0 tcp:fw1 ' 'claim check collects own MACs from BOTH nodes'
claim_check_case 0 '' "${TMP_DIR}/claim-23.conf" "$CLAIM_CLEAN" 0
claim_check_case 0 '' "${TMP_DIR}/claim-23.conf" "$CLAIM_PHYS" 0 10:66:6a:f6:c3:d2
claim_check_case 2 'did not answer the same probe' "${TMP_DIR}/claim-23.conf" "$CLAIM_BLIND" 0
claim_check_case 2 'holds 172.16.50.10' "${TMP_DIR}/claim-23.conf" '' 2
claim_check_case 2 'no cluster identity' "${TMP_DIR}/claim-none.conf" "$CLAIM_NORETH" 0
claim_check_case 2 'live RETH MAC says' "${TMP_DIR}/claim-23.conf" "$CLAIM_DRIFT" 0
claim_check_case 3 'cluster-id 24' "${TMP_DIR}/claim-23.conf" "$CLAIM_OTHER_CLUSTER" 0
eval "$ha_wan_claim_probe_real"
eval "$ha_wan_node_macs_real"

# #18580: a reply naming the probing interface's own MAC is the wrong-field
# shape (target MAC printed instead of sender). It must VOID, never PASS.
CLAIM_WRONGFIELD=$'iface ge-0-0-2.50 02:bf:72:17:01:00\nreply 172.16.50.10 02:bf:72:17:01:00 probe\nreply 172.16.50.1 02:bf:72:17:01:00 probe'
assert_helper_status 2 wcv "$OWN" 172.16.50.10 172.16.50.1 "$CLAIM_WRONGFIELD"
assert_contains "$(<"${ERR}")" 'probe read the wrong field' 'a wrong-field WAN probe is VOID, never a PASS'
# Our own MAC is VOID whatever the reply's target fields say: an ETH_P_ARP
# socket never sees our own transmitted replies, so the flag cannot excuse it.
CLAIM_SELF_OTHER=$'iface ge-0-0-2.50 02:bf:72:17:01:00\n'"$GWP"$'\nreply 172.16.50.10 02:bf:72:17:01:00 other'
assert_helper_status 2 wcv "$OWN" 172.16.50.10 172.16.50.1 "$CLAIM_SELF_OTHER"
assert_contains "$(<"${ERR}")" 'probe read the wrong field' 'our own MAC in a reply is VOID even when it is not flagged as our probe'
# Replies without the probe's iface line: the guard above cannot run, so VOID.
CLAIM_NOIFACE="$GWP"$'\nreply 172.16.50.10 18:e8:29:2c:13:7a probe'
assert_helper_status 2 wcv "$OWN" 172.16.50.10 172.16.50.1 "$CLAIM_NOIFACE"
assert_contains "$(<"${ERR}")" 'without the probe interface line' 'replies without the probe iface line are VOID, never judged'

# #18580: the REAL ha_wan_claim_probe, run hermetically in three
# unprivileged netns on one bridge: "fw" holds the WAN address with a RETH
# MAC, "x" is a foreign host also holding it, "gw" is the gateway. The probe
# must report three rounds from each, flag them as answers to OUR probe,
# never report fw's own MAC, and refuse when no node holds the address. A
# second run has the gateway answer only with UNSOLICITED broadcast replies,
# which must be flagged "other" and cannot satisfy the control. SKIP where
# user namespaces are unavailable.
WAN_NETNS_OUT="${TMP_DIR}/wan-netns.out"
if unshare -rnm true 2>/dev/null; then
	declare -f ha_wan_claim_probe >"${TMP_DIR}/wan-probe-fn.sh"
	unshare -rnm bash -c '
		set -u
		export PATH=/usr/sbin:/sbin:$PATH
		mount -t tmpfs none /run && mkdir -p /run/netns
		ip link add name br0 type bridge && ip link set br0 up
		mk() {
			ip netns add "$1"
			ip link add name "$1-br" type veth peer name "$1-in"
			ip link set "$1-in" netns "$1"
			ip link set "$1-br" master br0 up
			ip netns exec "$1" ip link set lo up
			ip netns exec "$1" ip link set "$1-in" address "$2" up
			ip netns exec "$1" ip addr add "$3" dev "$1-in"
		}
		mk peer 02:bf:72:17:01:01 169.254.1.2/32
		mk fw 02:bf:72:17:01:00 172.16.50.10/24
		mk x 18:e8:29:2c:13:7a 172.16.50.10/24
		mk gw 00:10:db:ff:10:01 172.16.50.1/24
		sleep 1
		# tcp:fw0 is the peer (does not hold the address), tcp:fw1 the owner:
		# the probe must try past the first node.
		incus() {
			local node="$2"
			shift 3
			case "$node" in
			tcp:fw0) ip netns exec peer "$@" ;;
			*) ip netns exec fw "$@" ;;
			esac
		}
		source "$1"
		ha_wan_claim_probe 172.16.50.10 172.16.50.1 tcp:fw0 tcp:fw1
		echo "PROBE_RC $?"
		ha_wan_claim_probe 172.16.50.99 172.16.50.1 tcp:fw0 tcp:fw1 >/dev/null
		echo "UNHELD_RC $?"
		ip netns exec x ip addr del 172.16.50.10/24 dev x-in
		ip netns exec gw ip addr del 172.16.50.1/24 dev gw-in
		ip netns exec gw python3 -c "
import socket, struct, time
s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW); s.bind((\"gw-in\", 0))
m = bytes.fromhex(\"0010dbff1001\")
f = b\"\xff\" * 6 + m + b\"\x08\x06\" + struct.pack(\"!HHBBH6s4s6s4s\", 1, 0x800, 6, 4, 2, m, socket.inet_aton(\"172.16.50.1\"), b\"\xff\" * 6, socket.inet_aton(\"172.16.50.1\")) + bytes(18)
end = time.time() + 4.5
while time.time() < end:
    s.send(f); time.sleep(0.2)
" &
		sleep 0.3
		ha_wan_claim_probe 172.16.50.10 172.16.50.1 tcp:fw0 tcp:fw1 | sed "s/^/UNSOL /"
		wait
		# ASKED: the gateway asks who-has the WAN address while the probe
		# runs, so fw'"'"'s own kernel sends ARP replies carrying fw'"'"'s MAC.
		# The probe must never hear them (its socket is ETH_P_ARP-bound);
		# the gateway counts them as the positive control.
		ip netns exec gw python3 -c "
import select, socket, struct, time
tx = socket.socket(socket.AF_PACKET, socket.SOCK_RAW); tx.bind((\"gw-in\", 0))
rx = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0806)); rx.bind((\"gw-in\", 0x0806))
m = bytes.fromhex(\"0010dbff1001\")
f = b\"\xff\" * 6 + m + b\"\x08\x06\" + struct.pack(\"!HHBBH6s4s6s4s\", 1, 0x800, 6, 4, 1, m, socket.inet_aton(\"172.16.50.1\"), bytes(6), socket.inet_aton(\"172.16.50.10\")) + bytes(18)
n = 0
end = time.time() + 4.5
while time.time() < end:
    tx.send(f)
    stop = time.time() + 0.2
    while (left := stop - time.time()) > 0 and select.select([rx], [], [], left)[0]:
        r = rx.recv(2048)
        if r[20:22] == b\"\x00\x02\" and r[22:28] == bytes.fromhex(\"02bf72170100\") and r[28:32] == socket.inet_aton(\"172.16.50.10\"):
            n += 1
print(\"ASKED_CONTROL\", n, flush=True)
" &
		sleep 0.3
		ha_wan_claim_probe 172.16.50.10 172.16.50.1 tcp:fw0 tcp:fw1 | sed "s/^/ASKED /"
		wait
	' _ "${TMP_DIR}/wan-probe-fn.sh" >"$WAN_NETNS_OUT" 2>&1 || true
	assert_contains "$(<"$WAN_NETNS_OUT")" 'PROBE_RC 0' 'wan netns: the real probe runs'
	assert_contains "$(<"$WAN_NETNS_OUT")" 'iface fw-in 02:bf:72:17:01:00' 'wan netns: the probe reports its own interface'
	assert_eq "$(grep -c '^reply 172.16.50.10 18:e8:29:2c:13:7a probe$' "$WAN_NETNS_OUT")" 3 \
		'wan netns: the foreign holder answers each of three rounds, sender MAC parsed, flagged as our probe'
	assert_eq "$(grep -c '^reply 172.16.50.1 00:10:db:ff:10:01 probe$' "$WAN_NETNS_OUT")" 3 \
		'wan netns: the gateway control answers each of three rounds'
	assert_eq "$(grep -c '^reply .* 02:bf:72:17:01:00 ' "$WAN_NETNS_OUT")" 0 'wan netns: no reply ever names the prober itself'
	assert_contains "$(<"$WAN_NETNS_OUT")" 'UNHELD_RC 2' 'wan netns: a probe on nodes that do not hold the address refuses (status 2)'
	assert_eq "$(grep -c '^UNSOL reply 172.16.50.1 00:10:db:ff:10:01 probe$' "$WAN_NETNS_OUT")" 0 \
		'wan netns: an unsolicited broadcast gateway reply is never flagged as an answer to our probe'
	_unsol_other=$(grep -c '^UNSOL reply 172.16.50.1 00:10:db:ff:10:01 other$' "$WAN_NETNS_OUT" || true)
	(( _unsol_other >= 1 )) || fail_test 'wan netns: the unsolicited gateway replies were not heard at all (the flag cell measured nothing)'
	# The ASKED phase: fw's kernel answered (control), and the probe never
	# heard those replies, so the self-MAC guard's ETH_P_ARP premise holds.
	_asked=$(sed -n 's/^ASKED_CONTROL //p' "$WAN_NETNS_OUT")
	[[ "${_asked:-0}" =~ ^[0-9]+$ ]] && (( _asked >= 1 )) \
		|| fail_test "wan netns: fw's kernel never answered the gateway's who-has (the ASKED cell measured nothing): ${_asked:-<none>}"
	assert_eq "$(grep -c '^ASKED reply 172.16.50.10 02:bf:72:17:01:00 ' "$WAN_NETNS_OUT")" 0 \
		"wan netns: the probe never hears fw's own kernel replies for the WAN address (ETH_P_ARP-bound)"
	assert_helper_status 1 wcv "$OWN" 172.16.50.10 172.16.50.1 "$(grep -v '^UNSOL\|^ASKED\|_RC' "$WAN_NETNS_OUT")"
	assert_contains "$(<"${ERR}")" 'also answered for by 18:e8:29:2c:13:7a' 'wan netns: the real probe output convicts the foreign holder'
	assert_helper_status 2 wcv "$OWN" 172.16.50.10 172.16.50.1 "$(sed -n 's/^UNSOL //p' "$WAN_NETNS_OUT")"
	printf 'netns WAN claim probe cell ran\n'
else
	printf 'SKIP netns WAN claim probe cell: unprivileged user/net namespaces unavailable\n'
fi

# The external IPv4 verdict: a FAIL becomes VOID only beside a NON-xpf claim.
PING_LOST='4 packets transmitted, 0 received, 100% packet loss'
PING_OK='64 bytes from 1.1.1.1: icmp_seq=1 ttl=56'
DUP_REASON='wan claim: 172.16.50.10 is also answered for by 18:e8:29:2c:13:7a'
XPF_REASON='wan claim: 172.16.50.10 is also answered for by another xpf cluster (cluster-id 24, 02:bf:72:18:01:00)'
assert_helper_status 2 ha_external_ping_claim_verdict 1 "$PING_LOST" 1 "$DUP_REASON"
assert_contains "$(<"${ERR}")" 'not attributable to the firewall: wan claim: 172.16.50.10' \
	'claim-voided external ping keeps the claimant in its reason'
assert_contains "$(<"${ERR}")" 'valid capture contains no bytes' \
	'claim-voided external ping keeps the ping reason'
assert_helper_status 1 ha_external_ping_claim_verdict 1 "$PING_LOST" 3 "$XPF_REASON"
assert_contains "$(<"${ERR}")" 'another xpf cluster (cluster-id 24' 'an xpf claim keeps the FAIL and says why'
assert_helper_status 1 ha_external_ping_claim_verdict 1 "$PING_LOST" 0 ''
assert_helper_status 1 ha_external_ping_claim_verdict 1 "$PING_LOST" 2 'wan claim: gateway silent'
assert_helper_status 1 ha_external_ping_claim_verdict 1 "$PING_LOST" '' ''
assert_helper_status 0 ha_external_ping_claim_verdict 0 "$PING_OK" 1 "$DUP_REASON"
assert_helper_status 2 ha_external_ping_claim_verdict 2 'ping exited with status 2' 1 "$DUP_REASON"
assert_helper_status 2 ha_external_ping_claim_verdict 1 "$PING_LOST" 1

# Wiring: the REAL ha_external_sweep / ha_emit_verdict (test-failover.sh) and
# wan_claim_cell (test-connectivity.sh), extracted by name and run against
# stubs, so a call that is dropped, reordered or re-routed fails a cell.
CLAIM_WIRING="${TMP_DIR}/claim-wiring.sh"
python3 - "${ROOT}/test/incus/test-failover.sh" "${ROOT}/test/incus/test-connectivity.sh" "$CLAIM_WIRING" <<'PY'
import pathlib
import re
import sys

tf = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8")
tc = pathlib.Path(sys.argv[2]).read_text(encoding="utf-8")
blocks = []
for text, name in ((tf, "ha_emit_verdict"), (tf, "ha_external_sweep"), (tc, "wan_claim_cell")):
    match = re.search(rf"^{name}\(\) \{{\n.*?^\}}\n", text, re.M | re.S)
    if not match:
        raise SystemExit(f"cannot extract {name} for #18558 wiring coverage")
    blocks.append(match.group(0))
match = re.search(r"^test_cluster\(\) \{\n.*?^\}\n", tc, re.M | re.S)
if not match:
    raise SystemExit("cannot extract test_cluster for #18558 wiring coverage")
pathlib.Path(sys.argv[3]).write_text("".join(blocks), encoding="utf-8")
# #18580: test_cluster goes to its own file and is RUN for the reachability
# count below; counting call text let a call in a dead branch or after an
# early return survive.
pathlib.Path(sys.argv[3] + ".test_cluster").write_text(match.group(0), encoding="utf-8")
PY
claim_wiring_run() { # <v4-rc> <v4-out> <v6-rc> <v6-out> <claim-status> -> "V4=.. V6=.. CALLED=.."
	(
		S_V4_RC="$1" S_V4_OUT="$2" S_V6_RC="$3" S_V6_OUT="$4" S_CLAIM="$5"
		W_LOG="" CALLED=0
		pass() { W_LOG+="PASS|$*"$'\n'; }
		fail() { W_LOG+="FAIL|$*"$'\n'; }
		void() { W_LOG+="VOID|$*"$'\n'; }
		info() { :; }
		main_iperf_running() { return 0; }
		ha_external_ping_capture() {
			if [[ "$1" == 6 ]]; then
				HA_EXTERNAL_RC="$S_V6_RC" HA_EXTERNAL_OUTPUT="$S_V6_OUT"
			else
				HA_EXTERNAL_RC="$S_V4_RC" HA_EXTERNAL_OUTPUT="$S_V4_OUT"
			fi
		}
		ha_wan_claim_check() { CALLED=1; HA_WAN_CLAIM_STATUS="$S_CLAIM"; HA_WAN_CLAIM_REASON="wan claim: stub status ${S_CLAIM}"; }
		# shellcheck disable=SC1090
		source "$CLAIM_WIRING"
		EXTERNAL_V4_TARGET=1.1.1.1 EXTERNAL_V6_TARGET=2606:4700:4700::1111
		CLUSTER_CONF=/nonexistent WAN_VIP4=172.16.50.10 WAN_GW4=172.16.50.1 FW0=tcp:fw0 FW1=tcp:fw1
		ha_external_sweep wiring
		v4=$(grep 'external IPv4' <<<"$W_LOG" | cut -d'|' -f1)
		v6=$(grep 'external IPv6' <<<"$W_LOG" | cut -d'|' -f1)
		printf 'V4=%s V6=%s CALLED=%s\n' "$v4" "$v6" "$CALLED"
	)
}
assert_eq "$(claim_wiring_run 1 "$PING_LOST" 0 "$PING_OK" 1)" 'V4=VOID V6=PASS CALLED=1' \
	'sweep: failing IPv4 runs the claim check, and a foreign claim VOIDs it'
assert_eq "$(claim_wiring_run 1 "$PING_LOST" 1 "$PING_LOST" 1)" 'V4=VOID V6=FAIL CALLED=1' \
	'sweep: IPv6 is never converted by the IPv4 address claim'
assert_eq "$(claim_wiring_run 0 "$PING_OK" 0 "$PING_OK" 1)" 'V4=PASS V6=PASS CALLED=0' \
	'sweep: a passing IPv4 sweep does not pay for the claim probe'
assert_eq "$(claim_wiring_run 1 "$PING_LOST" 0 "$PING_OK" 0)" 'V4=FAIL V6=PASS CALLED=1' \
	'sweep: a unique address leaves the IPv4 FAIL standing'
assert_eq "$(claim_wiring_run 1 "$PING_LOST" 0 "$PING_OK" 3)" 'V4=FAIL V6=PASS CALLED=1' \
	'sweep: another xpf cluster claiming the address leaves the FAIL standing'
claim_cell_run() { # <claim-status> -> PASS|FAIL|VOID
	(
		W_LOG=""
		pass() { W_LOG+="PASS|$*"$'\n'; }
		fail() { W_LOG+="FAIL|$*"$'\n'; }
		void() { W_LOG+="VOID|$*"$'\n'; }
		S_CLAIM="$1"
		# shellcheck disable=SC1090
		source "$CLAIM_WIRING"
		ha_wan_claim_check() { HA_WAN_CLAIM_STATUS="$S_CLAIM"; HA_WAN_CLAIM_REASON="wan claim: stub"; }
		CLUSTER_CONF=/nonexistent WAN_VIP4=172.16.50.10 WAN_GW4=172.16.50.1 FW0=tcp:fw0 FW1=tcp:fw1
		wan_claim_cell
		printf '%s\n' "${W_LOG%%|*}"
	)
}
assert_eq "$(claim_cell_run 0)" PASS 'test-connectivity claim cell: unique address PASSes'
assert_eq "$(claim_cell_run 1)" FAIL 'test-connectivity claim cell: a non-xpf claimant FAILs'
assert_eq "$(claim_cell_run 3)" FAIL 'test-connectivity claim cell: another xpf cluster FAILs'
assert_eq "$(claim_cell_run 2)" VOID 'test-connectivity claim cell: an unmeasured probe is VOID'
# #18580: reachability, not text. Run the extracted test_cluster with every
# helper it calls failing as an unknown command does (command_not_found_handle
# returns 127, as bash itself would), incus refused and the firewall nodes
# "running", and count real invocations of the cell. Run it with the LAN host
# running and with it stopped: the cell must be reached once in each, so a
# call moved into either branch of the LAN-host check, into a dead branch or
# after an early return is caught.
reach_count() { # <wiring-file> <cell> <lan-running|lan-stopped>
	(
		set +eu
		CALLS="${TMP_DIR}/reach-calls-${2}-${3}"
		: >"$CALLS"
		# shellcheck disable=SC1090
		source "$1"
		command_not_found_handle() { return 127; }
		incus() { return 1; }
		LAN_STATE="$3"
		instance_running() {
			[[ "$1" == "$FW0" || "$1" == "$FW1" ]] && return 0
			[[ "$1" == "$CLUSTER_LAN_HOST" && "$LAN_STATE" == lan-running ]]
		}
		wan_claim_cell() { printf 'wan_claim_cell\n' >>"$CALLS"; }
		iperf_target_claim_cell() { printf 'iperf_target_claim_cell\n' >>"$CALLS"; }
		FW0=loss:fw0 FW1=loss:fw1 CLUSTER_LAN_HOST=loss:lan CLUSTER_CONF=/nonexistent PROJECT_ROOT="$ROOT"
		test_cluster >/dev/null 2>&1
		grep -cxF "$2" "$CALLS"
	)
}
for lan_state in lan-running lan-stopped; do
	assert_eq "$(reach_count "${CLAIM_WIRING}.test_cluster" wan_claim_cell "$lan_state")" 1 \
		"test-connectivity test_cluster reaches wan_claim_cell exactly once (${lan_state})"
done
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
# #16307: `ip route get` may append a trailing `cache` continuation line
# (optionally flagged) for the one route entry; both parsers must accept
# it, while a second route line or a non-trailing cache line stays VOID.
ROUTE_CACHE=$'172.16.80.211 via 10.0.63.1 dev eth0 src 10.0.63.102 uid 0\n    cache'
ROUTE_CACHE_FLAGS=$'172.16.80.211 via 10.0.63.1 dev eth0 src 10.0.63.102 uid 0\n    cache <mc>'
ROUTE_CACHE6=$'2001:559:8585:80::211 via fe80::1 dev eth0 src 2001:db8::1\n    cache'
ROUTE_CACHE_LOCAL=$'local 172.16.80.211 dev lo src 172.16.80.211\n    cache'
for route in "$ROUTE_CACHE" "$ROUTE_CACHE_FLAGS" "$ROUTE_CACHE6"; do
	assert_helper_value eth0 ha_route_device "$route"
	assert_helper_status 0 ha_route_lookup_verdict 0 "$route"
done
assert_helper_status 1 ha_route_lookup_verdict 0 "$ROUTE_CACHE_LOCAL"
assert_helper_status 2 ha_route_lookup_verdict 0 $'cache\n172.16.80.211 dev eth0 src 10.0.63.102'
assert_helper_status 2 ha_route_device $'cache\n172.16.80.211 dev eth0 src 10.0.63.102'
assert_helper_status 2 ha_route_lookup_verdict 0 "${ROUTE_CACHE}"$'\n172.16.80.200 dev eth1'
assert_helper_status 2 ha_route_device "${ROUTE_CACHE}"$'\n172.16.80.200 dev eth1'
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
fabric_row = ["0"] * 20
fabric_row[10], fabric_row[11], fabric_row[19] = rx, tx, "ge-0-0-0"
pathlib.Path(path).write_text(
    f"HA capture identity: slice=manual-rg1-failback phase={phase} node={node} rg={rg}\n"
    "Userspace fabric links:\nSlot Parent State\n0 ge-0-0-0 up\n\n"
    "Userspace bindings:\nSlot Queue Header\n" + " ".join(row) + "\n" + " ".join(fabric_row) + "\n",
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
# An untargeted manual failover parks the old owner in secondary-hold
# (Manual yes) until reset; that is the correct non-committal end-state,
# not an unsettled stall (#18503).
write_ha_owner_snapshot "$OWNER1" owner-poll-01 node1 1 primary secondary-hold
assert_helper_status 0 ha_rg_owner_verdict node0 1 owner-poll-01 "$OWNER0" "$OWNER1"
write_ha_owner_snapshot "$OWNER1" owner-poll-01 node1 1 primary primary
assert_helper_status 1 ha_rg_owner_verdict node0 1 owner-poll-01 "$OWNER0" "$OWNER1"
write_ha_owner_snapshot "$OWNER0" owner-poll-01 node0 1 secondary secondary-hold
write_ha_owner_snapshot "$OWNER1" owner-poll-01 node1 1 secondary secondary-hold
assert_helper_status 1 ha_rg_owner_verdict node0 1 owner-poll-01 "$OWNER0" "$OWNER1"
write_ha_owner_snapshot "$OWNER0" owner-poll-01 node0 1 primary secondary
write_ha_owner_snapshot "$OWNER1" owner-poll-01 node1 1 primary secondary
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

rewind_failures=()
PRE_FIRST_REWIND_SHAPE_ONE=(50 110 150 200 250 300 350 450 500 600)
PRE_FIRST_REWIND_SHAPE_TWO=(50 600 600 600 600 600 600 600 600 600)
PRE_FIRST_REWIND_SHAPE_THREE=(110 500 50 150 160 170 180 190 195 600)
for rewind_case in shape-one shape-two shape-three; do
	case "$rewind_case" in
	shape-one)
		rewind_baseline=100
		rewind_expected='rewound from 100 to 50 at sample-01'
		rewind_values=("${PRE_FIRST_REWIND_SHAPE_ONE[@]}")
		;;
	shape-two)
		rewind_baseline=500
		rewind_expected='rewound from 500 to 50 at sample-01'
		rewind_values=("${PRE_FIRST_REWIND_SHAPE_TWO[@]}")
		;;
	shape-three)
		rewind_baseline=100
		rewind_expected='rewound from 500 to 50 at sample-03'
		rewind_values=("${PRE_FIRST_REWIND_SHAPE_THREE[@]}")
		;;
	esac
	rewind_pre_stats="${RG1_DIR}/${rewind_case}-phase-pre.stats"
	rewind_pre_interfaces="${RG1_DIR}/${rewind_case}-phase-pre.interfaces"
	write_ha_status_snapshot "$rewind_pre_stats" phase-pre node0 1 0 0 0 0 \
		"$rewind_baseline" "$rewind_baseline" "$rewind_baseline" "$rewind_baseline"
	write_ha_interface_snapshot "$rewind_pre_interfaces" phase-pre node0 1 ge-0-0-1 \
		"$rewind_baseline" "$rewind_baseline"
	rewind_stats=()
	rewind_interfaces=()
	for rewind_index in "${!rewind_values[@]}"; do
		rewind_sample=$(printf 'sample-%02d' "$((rewind_index + 1))")
		rewind_stats_path="${RG1_DIR}/${rewind_case}-${rewind_sample}-node0.stats"
		rewind_interfaces_path="${RG1_DIR}/${rewind_case}-${rewind_sample}-node0.interfaces"
		rewind_value="${rewind_values[$rewind_index]}"
		write_ha_status_snapshot "$rewind_stats_path" "$rewind_sample" node0 1 0 0 0 0 \
			"$rewind_value" "$rewind_value" "$rewind_value" "$rewind_value"
		write_ha_interface_snapshot "$rewind_interfaces_path" "$rewind_sample" node0 1 ge-0-0-1 \
			"$rewind_value" "$rewind_value"
		rewind_stats+=("$rewind_stats_path")
		rewind_interfaces+=("$rewind_interfaces_path")
	done
	if ha_rg1_sampled_counter_delta node0 'Kernel RX dropped' "$rewind_pre_stats" \
		"${rewind_stats[@]}" >"${OUT}" 2>"${ERR}"; then
		rewind_status=0
	else
		rewind_status=$?
	fi
	if [[ "$rewind_status" != 2 ]]; then
		rewind_failures+=("${rewind_case} counter expected rc=2, got rc=${rewind_status}, delta=$(<"${OUT}")")
	elif [[ "$(<"${ERR}")" != *"$rewind_expected"* ]]; then
		rewind_failures+=("${rewind_case} counter rc=2 without expected rewind evidence: $(<"${ERR}")")
	fi
	if ha_rg1_sampled_interface_delta node0 'ge-[0-9]+-0-1' rx "$rewind_pre_interfaces" \
		"${rewind_interfaces[@]}" >"${OUT}" 2>"${ERR}"; then
		rewind_status=0
	else
		rewind_status=$?
	fi
	if [[ "$rewind_status" != 2 ]]; then
		rewind_failures+=("${rewind_case} interface expected rc=2, got rc=${rewind_status}, delta=$(<"${OUT}")")
	elif [[ "$(<"${ERR}")" != *"$rewind_expected"* ]]; then
		rewind_failures+=("${rewind_case} interface rc=2 without expected rewind evidence: $(<"${ERR}")")
	fi
done
if (( ${#rewind_failures[@]} != 0 )); then
	fail_test "${rewind_failures[*]}"
fi
printf 'Groups 7-8 RG readiness and exact ten-sample maxima\n'
# #18686: Group 7's rows are the REAL capture test-failover took on tcp
# (test-failover-ha-2269141, `show chassis cluster data-plane statistics` on
# the former owner at phase=mid), each row changing exactly ONE line of it.
# The hand-written fixtures these replaced matched the parser rather than the
# product, which is how the verdict stayed VOID on every live run.
STANDBY_REAL_STATS="${ROOT}/test/fixtures/ha-assurance/rg1-failback-mid-node1-18686.stats"
STANDBY_REAL_STATUS="${ROOT}/test/fixtures/ha-assurance/rg1-failback-mid-node1-18686.status"
STANDBY_ID="${RG1_DIR}/standby.stats"
STANDBY_HA_GROUPS='  HA groups:                 rg0 active=true watchdog=136578; rg1 active=false watchdog=136578; rg2 active=true watchdog=136578'

# derive_standby <dst> [<old> <new>]...: the real capture with each <old>
# line-fragment replaced by <new>. Each <old> must occur exactly once, so a
# fixture that drifts fails here instead of turning a row into a no-op.
derive_standby() {
	python3 - "$STANDBY_REAL_STATS" "$@" <<'PY'
import pathlib
import sys

source, destination, *pairs = sys.argv[1:]
text = pathlib.Path(source).read_text(encoding="utf-8")
for old, new in zip(pairs[0::2], pairs[1::2]):
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"derive_standby: {old!r} occurs {count} times in {source}")
    text = text.replace(old, new, 1)
pathlib.Path(destination).write_text(text, encoding="utf-8")
PY
}

# standby_row <rc> <stderr substring or ''> <row> <file> [<phase>]
standby_row() {
	local expected="$1" needle="$2" row="$3" file="$4" phase="${5:-mid}"
	assert_helper_status "$expected" ha_rg_standby_status_verdict "$file" manual-rg1-failback "$phase" node1 1
	if [[ -n "$needle" ]]; then
		assert_contains "$(<"${ERR}")" "$needle" "Group 7 row ${row}"
	fi
}

derive_standby "$STANDBY_ID"
standby_row 0 '' 'PASS real capture (enabled, armed, rg1 inactive, 30/30 ready)' "$STANDBY_ID"

derive_standby "$STANDBY_ID" '  Enabled:                   true' '  Enabled:                   false'
standby_row 1 'Enabled is not true' 'FAIL enabled=false' "$STANDBY_ID"
derive_standby "$STANDBY_ID" '  Forwarding armed:          true' '  Forwarding armed:          false'
standby_row 1 'Forwarding armed is not true' 'FAIL armed=false' "$STANDBY_ID"
derive_standby "$STANDBY_ID" 'rg1 active=false' 'rg1 active=true'
standby_row 1 'rg1 is active' 'FAIL rg1 active' "$STANDBY_ID"
derive_standby "$STANDBY_ID" '  Ready bindings:            30/30' '  Ready bindings:            0/30'
standby_row 1 'no ready bindings' 'FAIL no ready bindings' "$STANDBY_ID"

derive_standby "$STANDBY_ID" $'  Enabled:                   true\n' ''
standby_row 2 'Enabled field missing' 'VOID Enabled missing' "$STANDBY_ID"
derive_standby "$STANDBY_ID" 'rg1 active=false watchdog=136578; ' ''
standby_row 2 'rg1 active field missing' 'VOID rg1 entry missing' "$STANDBY_ID"
derive_standby "$STANDBY_ID" "${STANDBY_HA_GROUPS}"$'\n' ''
standby_row 2 'HA groups field missing' 'VOID HA groups line missing' "$STANDBY_ID"
derive_standby "$STANDBY_ID" 'rg1 active=false watchdog=136578' \
	'rg1 active=false watchdog=136578; rg1 active=true watchdog=136578'
standby_row 2 'rg1 active field ambiguous' 'VOID rg1 entry ambiguous' "$STANDBY_ID"
derive_standby "$STANDBY_ID" "${STANDBY_HA_GROUPS}" "${STANDBY_HA_GROUPS}"$'\n'"${STANDBY_HA_GROUPS}"
standby_row 2 'HA groups field ambiguous' 'VOID HA groups line ambiguous' "$STANDBY_ID"
derive_standby "$STANDBY_ID" 'rg1 active=false' 'rg1 active=maybe'
standby_row 2 'rg1 active field malformed' 'VOID rg1 entry malformed' "$STANDBY_ID"
# The id is a whole token: an rg10 entry is neither rg1 nor an rg1 duplicate.
derive_standby "$STANDBY_ID" 'rg2 active=true watchdog=136578' \
	'rg2 active=true watchdog=136578; rg10 active=true watchdog=136578'
standby_row 0 '' 'PASS rg10 is not rg1' "$STANDBY_ID"
# The capture Group 7 used to be handed: no readiness fields at all.
standby_row 2 'this looks like a `show chassis cluster status` capture' 'VOID .status passed by mistake' \
	"$STANDBY_REAL_STATUS"
# Identity: a capture from another phase is never judged.
derive_standby "$STANDBY_ID"
standby_row 2 'phase' 'VOID identity phase mismatch' "$STANDBY_ID" phase-post

printf 'Group 7 call site is handed the data-plane statistics capture (#18686)\n'
if ! python3 - "${ROOT}/test/incus/test-failover.sh" <<'PY'; then
import pathlib
import re
import sys

text = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8")
calls = re.findall(r'ha_rg_standby_status_verdict "([^"]+)" \\\n\s*(\S+) (\S+) (\S+) (\S+)\n', text)
want = ("${RG1_STATS[mid:node1]}", "manual-rg1-failback", "mid", "node1", "1")
if calls != [want]:
    raise SystemExit(f"Group 7 call sites are {calls}, want exactly [{want}]")
# RG1_STATS must name the data-plane statistics capture.
binding = re.search(r'RG1_STATS\["\$\{phase\}:\$\{node_id\}"\]="\$\{base\}\.stats"\n', text)
capture = re.search(r"ha_capture_cli \"\$node\" 'show chassis cluster data-plane statistics' \\\n"
                    r'\s*manual-rg1-failback "\$phase" "\$node_id" 1 "\$\{RG1_STATS\["\$\{phase\}:\$\{node_id\}"\]\}"', text)
if not binding or not capture:
    raise SystemExit("RG1_STATS is no longer the `show chassis cluster data-plane statistics` capture")
PY
	fail_test 'Group 7 must be handed RG1_STATS[mid:node1], the data-plane statistics capture'
fi

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
assert_helper_value 110 ha_sample_window_max manual-rg1-failback 1 node0 'Kernel RX dropped' "${SAMPLE_STATS[@]}" 100
assert_helper_value 110 ha_sample_window_interface_max manual-rg1-failback 1 node0 'ge-[0-9]+-0-1' rx "${SAMPLE_INTERFACES[@]}" 100
MONOTONIC_PRE_STATS="${RG1_DIR}/monotonic-phase-pre-node0.stats"
MONOTONIC_PRE_INTERFACES="${RG1_DIR}/monotonic-phase-pre-node0.interfaces"
write_ha_status_snapshot "$MONOTONIC_PRE_STATS" phase-pre node0 1 0 0 0 0 100
write_ha_interface_snapshot "$MONOTONIC_PRE_INTERFACES" phase-pre node0 1 ge-0-0-1 100 100
assert_helper_value 10 ha_rg1_sampled_counter_delta node0 'Kernel RX dropped' \
	"$MONOTONIC_PRE_STATS" "${SAMPLE_STATS[@]}"
assert_helper_value 10 ha_rg1_sampled_interface_delta node0 'ge-[0-9]+-0-1' rx \
	"$MONOTONIC_PRE_INTERFACES" "${SAMPLE_INTERFACES[@]}"
EQUAL_PRE_STATS="${RG1_DIR}/equal-phase-pre-node0.stats"
EQUAL_PRE_INTERFACES="${RG1_DIR}/equal-phase-pre-node0.interfaces"
write_ha_status_snapshot "$EQUAL_PRE_STATS" phase-pre node0 1 0 0 0 0 101
write_ha_interface_snapshot "$EQUAL_PRE_INTERFACES" phase-pre node0 1 ge-0-0-1 101 101
assert_helper_value 9 ha_rg1_sampled_counter_delta node0 'Kernel RX dropped' \
	"$EQUAL_PRE_STATS" "${SAMPLE_STATS[@]}"
assert_helper_value 9 ha_rg1_sampled_interface_delta node0 'ge-[0-9]+-0-1' rx \
	"$EQUAL_PRE_INTERFACES" "${SAMPLE_INTERFACES[@]}"
report_output=$(
	(
		info() { printf 'INFO %s\n' "$*"; }
		void() { printf 'VOID %s\n' "$*"; }
		ha_rg1_report_sample_max "Pending TX local" node0 "Kernel RX dropped" \
			"$MONOTONIC_PRE_STATS" "${SAMPLE_STATS[@]}"
	)
)
assert_contains "$report_output" 'INFO RG1 Group 8 report-only Pending TX local max (node0): 110' \
	'report-only sampled maximum uses phase-pre baseline'
report_output=$(
	(
		info() { printf 'INFO %s\n' "$*"; }
		void() { printf 'VOID %s\n' "$*"; }
		ha_rg1_report_sample_max "Pending TX local" node0 "Kernel RX dropped" \
			"$rewind_pre_stats" "${rewind_stats[@]}"
	)
)
assert_contains "$report_output" 'VOID RG1 Group 8 report-only Pending TX local max unavailable (node0):' \
	'report-only sampled maximum rejects sample-window rewind'
assert_contains "$report_output" 'rewound from 500 to 50 at sample-03' \
	'report-only sampled maximum identifies intermediate rewind'
SAMPLE_STATS[9]="${RG1_DIR}/missing-sample.stats"
assert_helper_status 2 ha_sample_window_max manual-rg1-failback 1 node0 'Kernel RX dropped' "${SAMPLE_STATS[@]}" 100
SAMPLE_STATS[9]="${RG1_DIR}/sample-09-node0.stats"
assert_helper_status 2 ha_sample_window_max manual-rg1-failback 1 node0 'Kernel RX dropped' "${SAMPLE_STATS[@]}" 100
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
assert_helper_status 2 ha_sample_window_max manual-rg1-failback 1 node0 'Kernel RX dropped' "${REWIND_STATS[@]}" 100
assert_contains "$(<"${ERR}")" 'rewound from 500 to 50' 'counter window rewind evidence'
assert_helper_status 2 ha_sample_window_interface_max manual-rg1-failback 1 node0 'ge-[0-9]+-0-1' rx "${REWIND_INTERFACES[@]}" 100
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
    "stream_zero_intervals_outside_events_total", "zero_streams_outside_events_total",
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

# #18576: an iperf target answered for by two hosts. The shapes are what the
# off-firewall probe prints. The DUP set is what an off-firewall vantage
# (tcp:xpf-tcp-target) heard for loss's 172.16.80.200 (2026-10-31); "probe"
# marks a reply addressed to us with target IP 0.0.0.0. "fw" lines carry the
# node's role: owner = holds the control (WAN_GW80_4), peer = does not.
KNOWN200='10:66:6a:8b:91:a4 f6:f0:06:10:77:d5'
CMAC=10:66:6a:8b:91:a4
XMAC=f6:f0:06:10:77:d5
CTL=$'reply 172.16.80.8 02:bf:72:16:01:00 probe'
OWNER_SELF=$'fw loss:fw0 before '"$CMAC"$' REACHABLE owner\nfw loss:fw0 after '"$CMAC"$' REACHABLE owner'
TGT_ONE=$'iface eth0 10:66:6a:5c:f2:b8\nself 10:66:6a:5c:f2:b8\n'"$CTL"$'\nfw tcp:fw0 before 10:66:6a:5c:f2:b8 REACHABLE owner\nfw tcp:fw0 after 10:66:6a:5c:f2:b8 REACHABLE owner'
TGT_DUP=$'iface eth0 10:66:6a:5c:f2:b8\nreply 172.16.80.200 '"$CMAC"$' probe\nreply 172.16.80.200 '"$XMAC"$' probe\nreply 172.16.80.200 F6:F0:06:10:77:D5 probe\n'"$CTL"
TGT_SELFDUP=$'iface eth0 '"$CMAC"$'\nself '"$CMAC"$'\nreply 172.16.80.200 '"$XMAC"$' probe\n'"$CTL"
TGT_THIRD="$TGT_SELFDUP"$'\nreply 172.16.80.200 aa:bb:cc:dd:ee:ff probe'
TGT_RETH=$'iface eth0 '"$CMAC"$'\nself '"$CMAC"$'\nreply 172.16.80.200 02:bf:72:16:01:00 probe\n'"$CTL"
TGT_OTHER=$'iface eth0 '"$CMAC"$'\nreply 172.16.80.201 10:66:6a:8b:91:a5 probe\n'"$CTL"
TGT_SELF_NOCTL=$'iface eth0 '"$CMAC"$'\nself '"$CMAC"
TGT_SELF_CTL_OTHER=$'iface eth0 '"$CMAC"$'\nself '"$CMAC"$'\nreply 172.16.80.8 02:bf:72:16:01:00 other'
TGT_WRONGFIELD=$'iface eth0 '"$CMAC"$'\nself '"$CMAC"$'\nreply 172.16.80.200 '"$CMAC"$' probe\nreply 172.16.80.8 '"$CMAC"$' probe'
TGT_SELF_ONLY=$'iface eth0 '"$CMAC"$'\nself '"$CMAC"$'\n'"$CTL"
TGT_X_ONLY=$'iface eth0 '"$CMAC"$'\nreply 172.16.80.200 '"$XMAC"$' probe\n'"$CTL"
tcv() { ha_target_claim_verdict "$@"; }
assert_helper_status 0 tcv 172.16.80.210 172.16.80.8 '' "$TGT_ONE"
assert_contains "$(<"${OUT}")" 'answered for only by 10:66:6a:5c:f2:b8' 'unique target names its one holder'
# Status 4: exactly the known set, the vantage holds the target, and the RG
# owner resolves it to that vantage before AND after (the same-run control).
assert_helper_status 4 tcv 172.16.80.200 172.16.80.8 "$KNOWN200" "$TGT_SELFDUP"$'\n'"$OWNER_SELF"
assert_contains "$(<"${ERR}")" 'EXCUSED #18576' 'the excused state is labelled with its issue'
assert_contains "$(<"${ERR}")" 'expires when one holder drops it' 'the excused state names its expiry'
assert_helper_status 4 tcv 172.16.80.200 172.16.80.8 'self f6:f0:06:10:77:d5' "$TGT_SELFDUP"$'\n'"$OWNER_SELF"
# A recreated container (new volatile hwaddr) still matches through "self".
RECREATED="${TGT_SELFDUP//$CMAC/10:66:6a:00:00:01}"$'\n'"${OWNER_SELF//$CMAC/10:66:6a:00:00:01}"
assert_helper_status 4 tcv 172.16.80.200 172.16.80.8 'SELF F6:F0:06:10:77:D5' "$RECREATED"
# E1: the known set answers but the RG owner already resolves to the OTHER
# holder: never excused; this run's v4 iperf numbers are invalid.
assert_helper_status 2 tcv 172.16.80.200 172.16.80.8 "$KNOWN200" \
	"$TGT_SELFDUP"$'\nfw loss:fw0 before '"$XMAC"$' REACHABLE owner\nfw loss:fw0 after '"$XMAC"$' REACHABLE owner'
assert_contains "$(<"${ERR}")" "v4 iperf numbers measured the wrong host" 'E1: owner on the other holder invalidates the run'
# Known set but the owner's choice is not established (no entry, or it only
# appears mid-window): VOID, not excused and not a FAIL.
assert_helper_status 2 tcv 172.16.80.200 172.16.80.8 "$KNOWN200" "$TGT_SELFDUP"
assert_contains "$(<"${ERR}")" 'not certifiable' 'no owner view is not certifiable'
assert_helper_status 2 tcv 172.16.80.200 172.16.80.8 "$KNOWN200" \
	"$TGT_SELFDUP"$'\nfw loss:fw0 before - NONE owner\nfw loss:fw0 after '"$CMAC"$' REACHABLE owner'
# Known set heard from a vantage that does not hold the target: no self, so
# the excuse cannot be granted.
assert_helper_status 2 tcv 172.16.80.200 172.16.80.8 "$KNOWN200" "$TGT_DUP"$'\n'"$OWNER_SELF"
assert_contains "$(<"${ERR}")" 'the vantage does not hold it' 'the excuse requires the self line'
# Two holders and no documented set: FAIL naming both, each once in any case.
assert_helper_status 1 tcv 172.16.80.200 172.16.80.8 '' "$TGT_SELFDUP"
assert_contains "$(<"${ERR}")" 'more than one host (10:66:6a:8b:91:a4 f6:f0:06:10:77:d5)' \
	'dual-held target names both holders'
assert_helper_status 1 tcv 172.16.80.200 172.16.80.8 '' "$TGT_DUP"
assert_eq "$(grep -io 'f6:f0:06:10:77:d5' "${ERR}" | wc -l)" 1 'dual-held target names each holder once, case-insensitively'
# Any other set FAILs: a third MAC (1), or an xpf RETH MAC (3, product).
assert_helper_status 1 tcv 172.16.80.200 172.16.80.8 "$KNOWN200" "$TGT_THIRD"$'\n'"$OWNER_SELF"
assert_helper_status 3 tcv 172.16.80.200 172.16.80.8 "$KNOWN200" "$TGT_RETH"$'\n'"$OWNER_SELF"
assert_contains "$(<"${ERR}")" 'xpf RETH MAC (02:bf:72:16:01:00)' 'an xpf RETH holder is a product failure'
assert_helper_status 1 tcv 172.16.80.200 172.16.80.8 'f6:f0:06:10:77:d5' "$TGT_SELFDUP"
# E2: only the external box answers (the container lost its alias): never a
# PASS; the v4 target is misplaced.
assert_helper_status 2 tcv 172.16.80.200 172.16.80.8 '' "$TGT_X_ONLY"
assert_contains "$(<"${ERR}")" 'not by the intended holder' 'E2: a holder that is not the vantage is misplaced'
assert_helper_status 2 tcv 172.16.80.200 172.16.80.8 "$KNOWN200" "$TGT_X_ONLY"
# The expiry: one holder (the container) while the known set is still
# configured is a certifiable run, so it PASSes, and the reason tells the
# operator to delete the stale line. The excuse is owner-gated, so a stale set
# can only ever re-excuse the identical benign state.
assert_helper_status 0 tcv 172.16.80.200 172.16.80.8 "$KNOWN200" "$TGT_SELF_ONLY"$'\n'"$OWNER_SELF"
assert_contains "$(<"${OUT}")" 'configured but not observed: delete IPERF_TARGET4_KNOWN_HOLDERS (#18576)' \
	'a stale known set tells the operator to delete it'
assert_helper_status 0 tcv 172.16.80.200 172.16.80.8 'self f6:f0:06:10:77:d5' "$TGT_SELF_ONLY"
assert_contains "$(<"${OUT}")" 'delete IPERF_TARGET4_KNOWN_HOLDERS' 'the delete note survives the self token'
assert_helper_status 0 tcv 172.16.80.200 172.16.80.8 '' "$TGT_SELF_ONLY"
assert_not_contains_delete=$(grep -c 'delete IPERF_TARGET4_KNOWN_HOLDERS' "${OUT}" || true)
assert_eq "$assert_not_contains_delete" 0 'no delete note without a configured set'
assert_helper_status 0 tcv 172.16.80.200 172.16.80.8 '' "$TGT_SELF_ONLY"$'\n'"$OWNER_SELF"
# A lone holder needs the control, answered to OUR probe.
assert_helper_status 2 tcv 172.16.80.200 172.16.80.8 '' "$TGT_SELF_NOCTL"
assert_contains "$(<"${ERR}")" 'control 172.16.80.8 did not answer' 'a lone holder without the control is VOID, not PASS'
assert_helper_status 2 tcv 172.16.80.200 172.16.80.8 '' "$TGT_SELF_CTL_OTHER"
# A reply naming the prober's own MAC means the probe read the wrong field.
assert_helper_status 2 tcv 172.16.80.200 172.16.80.8 "$KNOWN200" "$TGT_WRONGFIELD"
assert_contains "$(<"${ERR}")" "names the prober's own MAC" 'a wrong-field probe is VOID, never a PASS'
# The RG OWNER's entry: FAILED, a REACHABLE entry on an unclaimed MAC, or a
# change between two present snapshots is a product neighbor fault.
assert_helper_status 1 tcv 172.16.80.200 172.16.80.8 '' \
	"$TGT_SELF_ONLY"$'\nfw loss:fw0 before - FAILED owner\nfw loss:fw0 after - FAILED owner'
assert_contains "$(<"${ERR}")" 'FAILED (before)' 'a FAILED owner entry is a product neighbor fault'
for st in REACHABLE DELAY PROBE PERMANENT; do
	assert_helper_status 1 tcv 172.16.80.200 172.16.80.8 '' \
		"$TGT_SELF_ONLY"$'\nfw loss:fw0 before - NONE owner\nfw loss:fw0 after 11:22:33:44:55:66 '"$st"$' owner'
done
assert_helper_status 1 tcv 172.16.80.200 172.16.80.8 "$KNOWN200" \
	"$TGT_SELFDUP"$'\nfw loss:fw0 before '"$CMAC"$' REACHABLE owner\nfw loss:fw0 after '"$XMAC"$' STALE owner'
assert_contains "$(<"${ERR}")" "changed from $CMAC to $XMAC" 'an owner flip during the probe is reported'
# E3-E5: none of these is a product fault. An entry appearing mid-window, a
# FAILED entry on the PEER, and a STALE owner entry on an old MAC (container
# recreate) are judged only by the owner rules, which re-validate on use.
assert_helper_status 0 tcv 172.16.80.200 172.16.80.8 '' \
	"$TGT_SELF_ONLY"$'\nfw loss:fw0 before - NONE owner\nfw loss:fw0 after '"$CMAC"$' REACHABLE owner'
assert_helper_status 4 tcv 172.16.80.200 172.16.80.8 "$KNOWN200" \
	"$TGT_SELFDUP"$'\n'"$OWNER_SELF"$'\nfw loss:fw1 before - FAILED peer\nfw loss:fw1 after 11:22:33:44:55:66 REACHABLE peer'
assert_helper_status 2 tcv 172.16.80.200 172.16.80.8 '' \
	"$TGT_SELF_ONLY"$'\nfw loss:fw0 before 10:66:6a:00:00:09 STALE owner\nfw loss:fw0 after 10:66:6a:00:00:09 STALE owner'
assert_contains "$(<"${ERR}")" "names another MAC" 'E5: a STALE owner entry on an old MAC is not a FAIL, but not a PASS either'
# Seat X's false PASS: only self answers, no known set, and the owner is
# still STALE on the external box. Its next v4 packet goes there: VOID.
assert_helper_status 2 tcv 172.16.80.200 172.16.80.8 '' \
	"$TGT_SELF_ONLY"$'\nfw loss:fw0 before '"$XMAC"$' STALE owner\nfw loss:fw0 after '"$XMAC"$' STALE owner'
assert_contains "$(<"${ERR}")" "entries $XMAC" 'a lone holder with the owner on another MAC is not certifiable'
# The owner gate: exactly one owner, the same node in both snapshots.
assert_helper_status 2 tcv 172.16.80.200 172.16.80.8 "$KNOWN200" \
	"$TGT_SELFDUP"$'\n'"$OWNER_SELF"$'\nfw loss:fw1 before '"$XMAC"$' REACHABLE owner\nfw loss:fw1 after '"$XMAC"$' REACHABLE owner'
assert_contains "$(<"${ERR}")" 'not one stable node' 'a dual-active owner pair is never excused'
assert_helper_status 2 tcv 172.16.80.200 172.16.80.8 "$KNOWN200" \
	"$TGT_SELFDUP"$'\nfw loss:fw0 before '"$CMAC"$' REACHABLE owner\nfw loss:fw0 after '"$CMAC"$' REACHABLE peer\nfw loss:fw1 before - NONE peer\nfw loss:fw1 after '"$XMAC"$' REACHABLE owner'
assert_contains "$(<"${ERR}")" 'not one stable node' 'ownership moving mid-probe is never excused'
# Q02: the owner TAG decides which node is judged, not node order. fw0 is a
# peer on the container, fw1 owns and resolves to the external box: E1.
assert_helper_status 2 tcv 172.16.80.200 172.16.80.8 "$KNOWN200" \
	"$TGT_SELFDUP"$'\nfw loss:fw0 before '"$CMAC"$' REACHABLE peer\nfw loss:fw0 after '"$CMAC"$' REACHABLE peer\nfw loss:fw1 before '"$XMAC"$' REACHABLE owner\nfw loss:fw1 after '"$XMAC"$' REACHABLE owner'
assert_contains "$(<"${ERR}")" 'RG owner loss:fw1' 'Q02: the tagged owner, not the first node, is judged'
assert_contains "$(<"${ERR}")" "measured the wrong host" 'Q02: the owner on the external box invalidates the run'
# Q01: an excuse needs BOTH snapshots; a missing after-snapshot is VOID.
assert_helper_status 2 tcv 172.16.80.200 172.16.80.8 "$KNOWN200" \
	"$TGT_SELFDUP"$'\nfw loss:fw0 before '"$CMAC"$' REACHABLE owner'
assert_contains "$(<"${ERR}")" 'not one stable node' 'Q01: a missing after-snapshot is never excused'
# The excuse needs the owner on the container AFTER the probe too: an entry
# that vanished during the probe (owner unchanged) is not certifiable.
assert_helper_status 2 tcv 172.16.80.200 172.16.80.8 "$KNOWN200" \
	"$TGT_SELFDUP"$'\nfw loss:fw0 before '"$CMAC"$' REACHABLE owner\nfw loss:fw0 after - NONE owner'
assert_contains "$(<"${ERR}")" 'not certifiable' 'an owner entry vanishing mid-probe is never excused'
assert_helper_status 2 tcv 172.16.80.200 172.16.80.8 "$KNOWN200" \
	"$TGT_SELFDUP"$'\nfw loss:fw0 before 10:66:6a:00:00:09 STALE owner\nfw loss:fw0 after 10:66:6a:00:00:09 STALE owner'
assert_contains "$(<"${ERR}")" 'not certifiable' 'a stale owner entry on an old MAC is not certifiable, not a FAIL'
# Replies for OTHER addresses are not claims on the target; nobody = VOID.
assert_helper_status 2 tcv 172.16.80.200 172.16.80.8 "$KNOWN200" "$TGT_OTHER"
assert_contains "$(<"${ERR}")" 'nobody answered ARP for 172.16.80.200 although control' 'an unheld target with a live control is VOID'
assert_helper_status 2 tcv 172.16.80.200 172.16.80.8 '' ''
assert_helper_status 2 tcv '' 172.16.80.8 '' "$TGT_DUP"
assert_helper_status 2 tcv 172.16.80.200 172.16.80.200 '' "$TGT_DUP"
assert_helper_status 2 tcv 172.16.80.200 172.16.80.8 ''
# ha_target_claim_check: probe and firewall snapshots stubbed; argv must reach
# them unchanged and the snapshots must bracket the probe.
ha_target_claim_probe_real="$(declare -f ha_target_claim_probe)"
ha_target_fw_neigh_real="$(declare -f ha_target_fw_neigh)"
TGT_STUB_OUT="" TGT_STUB_RC=0
ha_target_claim_probe() { printf 'probe %s\n' "$*" >>"${TMP_DIR}/tgt-stub-calls"; printf '%s\n' "$TGT_STUB_OUT"; return "$TGT_STUB_RC"; }
ha_target_fw_neigh() { printf 'neigh %s\n' "$*" >>"${TMP_DIR}/tgt-stub-calls"; local p="$1" n r=owner; shift 3; for n in "$@"; do printf 'fw %s %s 10:66:6a:8b:91:a4 REACHABLE %s\n' "$n" "$p" "$r"; r=peer; done; }
tgt_check_case() { # <expected-status> <reason-substring> <stub-out> <stub-rc> [known]
	TGT_STUB_OUT="$3" TGT_STUB_RC="$4"
	rm -f "${TMP_DIR}/tgt-stub-calls"
	if ! ha_target_claim_check loss:mouse 172.16.80.200 172.16.80.8 "${5:-}" loss:fw0 loss:fw1; then
		fail_test "ha_target_claim_check returned nonzero (it must always return 0)"
	fi
	assert_eq "$HA_TARGET_CLAIM_STATUS" "$1" "ha_target_claim_check status for ${2}"
	assert_contains "$HA_TARGET_CLAIM_REASON" "$2" "ha_target_claim_check reason for ${2}"
}
tgt_check_case 4 'EXCUSED #18576' "$TGT_SELFDUP" 0 "$KNOWN200"
assert_eq "$(tr '\n' '|' <"${TMP_DIR}/tgt-stub-calls")" \
	'neigh before 172.16.80.200 172.16.80.8 loss:fw0 loss:fw1|probe loss:mouse 172.16.80.200 172.16.80.8|neigh after 172.16.80.200 172.16.80.8 loss:fw0 loss:fw1|' \
	'target claim check snapshots both firewalls before and after an off-firewall probe'
tgt_check_case 1 'more than one host' "$TGT_SELFDUP" 0
tgt_check_case 0 'answered for only by' "$TGT_SELF_ONLY" 0
tgt_check_case 3 'xpf RETH MAC' "$TGT_RETH" 0 "$KNOWN200"
tgt_check_case 2 'not on-link' '' 3
tgt_check_case 2 'could not run (status 1)' '' 1
eval "$ha_target_claim_probe_real"
eval "$ha_target_fw_neigh_real"

# The REAL probe, run hermetically: three unprivileged netns on one bridge.
# "c" is the vantage and holds the target (loss's container), "x" is a
# second holder, and "fw" holds the control address and carries a cached
# neighbor entry for the target. The probe must report both holders and the
# control, three rounds each, and must not move fw's entry. SKIP where user
# namespaces are unavailable.
TGT_NETNS_OUT="${TMP_DIR}/tgt-netns.out"
if unshare -rnm true 2>/dev/null; then
	declare -f ha_target_claim_probe >"${TMP_DIR}/tgt-probe-fn.sh"
	unshare -rnm bash -c '
		set -u
		export PATH=/usr/sbin:/sbin:$PATH
		mount -t tmpfs none /run && mkdir -p /run/netns
		ip link add name br0 type bridge && ip link set br0 up
		mk() {
			ip netns add "$1"
			ip link add name "$1-br" type veth peer name "$1-in"
			ip link set "$1-in" netns "$1"
			ip link set "$1-br" master br0 up
			ip netns exec "$1" ip link set lo up
			ip netns exec "$1" ip link set "$1-in" address "$2" up
			ip netns exec "$1" ip addr add "$3" dev "$1-in"
		}
		mk fw 02:bf:72:16:01:00 172.16.80.8/24
		mk c 10:66:6a:8b:91:a4 172.16.80.200/24
		mk x f6:f0:06:10:77:d5 172.16.80.200/24
		sleep 1
		ip netns exec fw ip neigh replace 172.16.80.200 lladdr 10:66:6a:8b:91:a4 dev fw-in nud stale
		incus() { shift 3; ip netns exec c "$@"; }
		source "$1"
		echo "FW_BEFORE $(ip netns exec fw ip neigh show 172.16.80.200 | awk "{print \$5}")"
		ha_target_claim_probe xpf-mouse-target 172.16.80.200 172.16.80.8
		echo "PROBE_RC $?"
		echo "FW_AFTER $(ip netns exec fw ip neigh show 172.16.80.200 | awk "{print \$5}")"
		# A control heard only as UNSOLICITED broadcast replies (fw no longer
		# holds .8 but announces it) must be flagged "other", never "probe".
		ip netns exec fw ip addr del 172.16.80.8/24 dev fw-in
		ip netns exec fw python3 -c "
import socket, struct, time
s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW); s.bind((\"fw-in\", 0))
m = bytes.fromhex(\"02bf72160100\")
f = b\"\xff\" * 6 + m + b\"\x08\x06\" + struct.pack(\"!HHBBH6s4s6s4s\", 1, 0x800, 6, 4, 2, m, socket.inet_aton(\"172.16.80.8\"), b\"\xff\" * 6, socket.inet_aton(\"172.16.80.8\")) + bytes(18)
end = time.time() + 4.5
while time.time() < end:
    s.send(f); time.sleep(0.2)
" &
		sleep 0.3
		ha_target_claim_probe xpf-mouse-target 172.16.80.200 172.16.80.8 | sed "s/^/UNSOL /"
		wait
		# A target reached only via a gateway is not on-link: status 3, no probe.
		ip netns exec c ip route add default via 172.16.80.8
		ha_target_claim_probe xpf-mouse-target 10.9.9.9 172.16.80.8 >/dev/null
		echo "OFFLINK_RC $?"
	' _ "${TMP_DIR}/tgt-probe-fn.sh" >"$TGT_NETNS_OUT" 2>&1 || true
	assert_contains "$(<"$TGT_NETNS_OUT")" 'PROBE_RC 0' 'netns: the real probe runs'
	assert_contains "$(<"$TGT_NETNS_OUT")" 'self 10:66:6a:8b:91:a4' 'netns: a vantage holding the target reports itself'
	assert_eq "$(grep -c '^reply 172.16.80.200 f6:f0:06:10:77:d5 probe$' "$TGT_NETNS_OUT")" 3 \
		'netns: the second holder answers each of three rounds, sender MAC parsed, flagged as our probe'
	assert_eq "$(grep -c '^reply 172.16.80.8 02:bf:72:16:01:00 probe$' "$TGT_NETNS_OUT")" 3 \
		'netns: the control answers each of three rounds'
	assert_eq "$(grep -c '10:66:6a:8b:91:a4 probe$' "$TGT_NETNS_OUT")" 0 'netns: no reply ever names the prober itself'
	assert_contains "$(<"$TGT_NETNS_OUT")" 'FW_AFTER 10:66:6a:8b:91:a4' \
		"netns: probing from the target's holder leaves the firewall's entry where it was"
	assert_contains "$(<"$TGT_NETNS_OUT")" 'OFFLINK_RC 3' 'netns: an off-link (via-gateway) target is refused, status 3'
	assert_eq "$(grep -c '^UNSOL reply 172.16.80.8 02:bf:72:16:01:00 probe$' "$TGT_NETNS_OUT")" 0 \
		'netns: an unsolicited broadcast reply for the control is never flagged as an answer to our probe'
	assert_ne_zero_unsol=$(grep -c '^UNSOL reply 172.16.80.8 02:bf:72:16:01:00 other$' "$TGT_NETNS_OUT" || true)
	if (( assert_ne_zero_unsol < 1 )); then
		fail_test 'netns: the unsolicited control replies were not heard at all (the flag cell measured nothing)'
	fi
	assert_helper_status 2 tcv 172.16.80.200 172.16.80.8 "$KNOWN200" "$(<"$TGT_NETNS_OUT")"
	assert_helper_status 2 tcv 172.16.80.200 172.16.80.8 'self f6:f0:06:10:77:d5' "$(<"$TGT_NETNS_OUT")"
	assert_helper_status 1 tcv 172.16.80.200 172.16.80.8 '' "$(<"$TGT_NETNS_OUT")"
	printf 'netns target-claim probe cell ran\n'
else
	printf 'SKIP netns target-claim probe cell: unprivileged user/net namespaces unavailable\n'
fi
# Wiring: the REAL iperf_target_claim_cell and test_cluster
# (test-connectivity.sh), extracted by name and run against stubs.
TGT_WIRING="${TMP_DIR}/target-claim-wiring.sh"
python3 - "${ROOT}/test/incus/test-connectivity.sh" "$TGT_WIRING" <<'PY'
import pathlib
import re
import sys

tc = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8")
blocks = []
for name in ("assurance_verdict", "iperf_target_claim_cell", "test_cluster"):
    match = re.search(rf"^{name}\(\) \{{\n.*?^\}}\n", tc, re.M | re.S)
    if not match:
        raise SystemExit(f"cannot extract {name} for #18576 wiring coverage")
    blocks.append(match.group(0))
pathlib.Path(sys.argv[2]).write_text("".join(blocks), encoding="utf-8")
PY
tgt_cell_run() { # <check-status> -> PASS|FAIL|VOID|SKIP
	(
		W_LOG="" S_TGT="$1"
		skip() { W_LOG+="SKIP|$*"$'\n'; }
		pass() { W_LOG+="PASS|$*"$'\n'; }
		fail() { W_LOG+="FAIL|$*"$'\n'; }
		void() { W_LOG+="VOID|$*"$'\n'; }
		# shellcheck disable=SC1090
		source "$TGT_WIRING"
		ha_target_claim_check() { printf '%s' "$*" >"${TMP_DIR}/tgt-cell-args"; HA_TARGET_CLAIM_STATUS="$S_TGT"; HA_TARGET_CLAIM_REASON="target claim: stub"; }
		MOUSE_TARGET_REF=loss:xpf-mouse-target IPERF_TARGET4=172.16.80.200 WAN_GW80_4=172.16.80.8 FW0=loss:fw0 FW1=loss:fw1
		IPERF_TARGET4_KNOWN_HOLDERS="10:66:6a:8b:91:a4 f6:f0:06:10:77:d5"
		iperf_target_claim_cell
		printf '%s\n' "${W_LOG%%|*}"
	)
}
assert_eq "$(tgt_cell_run 0)" PASS 'iperf target cell: one holder PASSes'
assert_eq "$(tgt_cell_run 1)" FAIL 'iperf target cell: two holders FAIL'
assert_eq "$(tgt_cell_run 3)" FAIL 'iperf target cell: an xpf RETH holder (status 3) FAILs'
assert_eq "$(tgt_cell_run 2)" VOID 'iperf target cell: an uncertifiable or unmeasured probe is VOID'
assert_eq "$(tgt_cell_run 4)" SKIP 'iperf target cell: the excused known duplicate (status 4) is a SKIP, never VOID or PASS'
assert_eq "$(<"${TMP_DIR}/tgt-cell-args")" 'loss:xpf-mouse-target 172.16.80.200 172.16.80.8 10:66:6a:8b:91:a4 f6:f0:06:10:77:d5 loss:fw0 loss:fw1' \
	'iperf target cell probes IPERF_TARGET4 from the off-firewall target container, WAN_GW80_4 as control, both nodes'
# Reachability, not text (#18580's reach_count above): the cell must be
# reached once with the LAN host running and once with it stopped.
for lan_state in lan-running lan-stopped; do
	assert_eq "$(reach_count "$TGT_WIRING" iperf_target_claim_cell "$lan_state")" 1 \
		"test-connectivity test_cluster reaches iperf_target_claim_cell exactly once (${lan_state})"
done

printf 'PASS ha-assurance-selftest: M2.4, RG1 Groups 1-8, N6/N12 pins, sticky FAIL, blind markers, gate dominance, set-e VOID guard\n'

printf 'Fabric-path blind counters produce VOID under set -e\n'
PHASE_DIR="${TMP_DIR}/phase-fabric-void"
mkdir -p "$PHASE_DIR"
ARTIFACT_DIR="$PHASE_DIR"
write_ha_status_snapshot "$(cycle_stats_path 1 failover-pre "$FW0")" failover-pre node0 1 10 20 30 0
write_ha_status_snapshot "$(cycle_stats_path 1 failover-post "$FW0")" failover-post node0 1 10 20 30 0
write_ha_status_snapshot "$(cycle_stats_path 1 failover-pre "$FW1")" failover-pre node1 1 10 20 30 0
write_ha_status_snapshot "$(cycle_stats_path 1 failover-post "$FW1")" failover-post node1 1 10 20 30 0
write_ha_interface_snapshot "$(cycle_interfaces_path 1 failover "$FW0")" failover node0 1 ge-0-0-2 10 10
write_ha_interface_snapshot "$(cycle_interfaces_path 1 failover-post "$FW0")" failover-post node0 1 ge-0-0-2 10 10
write_ha_interface_snapshot "$(cycle_interfaces_path 1 failover "$FW1")" failover node1 1 ge-0-0-2 10 10
write_ha_interface_snapshot "$(cycle_interfaces_path 1 failover-post "$FW1")" failover-post node1 1 ge-0-0-2 10 10
sed -i '/^Session misses:/d' "$(cycle_stats_path 1 failover-post "$FW0")"
reset_verdict
if run_fabric_path_consumer; then
	fabric_path_status=0
else
	fabric_path_status=$?
fi
assert_eq "$fabric_path_status" 0 'blind fabric-path counters return normally'
assert_eq "$FAILED" 0 'blind fabric-path counters are not FAIL'
assert_eq "$VOIDS" 1 'blind fabric-path counters increment VOID'
assert_contains "$(<"${ERR}")" 'VOID status summary' 'fabric-path VOID diagnostic'
assert_contains "$(<"${ERR}")" 'cycle 1 failover: node0: unable to read post Session misses' 'fabric-path VOID context'
