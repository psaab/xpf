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
assert_helper_status 0 ha_session_sync_idle_sample fw0 fw1 "${STATISTICS_RENDERED}" "${STATISTICS_RENDERED}" 321 321
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
assert_helper_status 0 ha_session_sync_idle_sample fw0 fw1 "${SYNC_SOURCE}" "${SYNC_TARGET}" 5 5

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
assert_helper_status 0 ha_session_sync_idle_sample fw1 fw0 "${SYNC_REVERSE_SOURCE}" "${SYNC_REVERSE_TARGET}" 7 7
SYNC_NOT_IDLE="${TMP_DIR}/sync-not-idle.txt"
cat >"${SYNC_NOT_IDLE}" <<'EOF'
Services Synchronized:
Session create 4 5

Session delta pending: 1
Session delta drained: 0
EOF
assert_helper_status 1 ha_session_sync_idle_sample fw0 fw1 "${SYNC_SOURCE}" "${SYNC_NOT_IDLE}" 5 5
SYNC_MISSING_DRAINED="${TMP_DIR}/sync-missing-drained.txt"
cat >"${SYNC_MISSING_DRAINED}" <<'EOF'
Services Synchronized:
Session create 5 5

Session delta pending: 0
EOF
assert_helper_status 2 ha_session_sync_idle_sample fw0 fw1 "${SYNC_SOURCE}" "${SYNC_MISSING_DRAINED}" 5 5

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
Session delta drained: 12
EOF
cat >"${SYNC_OFFSET_TARGET}" <<'EOF'
Services Synchronized:
Session create 0 174

Session delta pending: 0
Session delta drained: 19
EOF
# First sample only establishes the baseline: never idle by itself.
assert_helper_status 1 ha_session_sync_idle_sample fw0 fw1 "${SYNC_OFFSET_SOURCE}" "${SYNC_OFFSET_TARGET}" '' ''
# Static offset pair (the cell3.log evidence shape) is idle vs baseline.
assert_helper_status 0 ha_session_sync_idle_sample fw0 fw1 "${SYNC_OFFSET_SOURCE}" "${SYNC_OFFSET_TARGET}" 15 174
# Lockstep advance since baseline (15->74, 174->233) stays idle.
SYNC_OFFSET_SOURCE_LATE="${TMP_DIR}/sync-offset-source-late.txt"
SYNC_OFFSET_TARGET_LATE="${TMP_DIR}/sync-offset-target-late.txt"
cat >"${SYNC_OFFSET_SOURCE_LATE}" <<'EOF'
Services Synchronized:
Session create 74 0

Session delta pending: 0
Session delta drained: 12
EOF
cat >"${SYNC_OFFSET_TARGET_LATE}" <<'EOF'
Services Synchronized:
Session create 0 233

Session delta pending: 0
Session delta drained: 19
EOF
assert_helper_status 0 ha_session_sync_idle_sample fw0 fw1 "${SYNC_OFFSET_SOURCE_LATE}" "${SYNC_OFFSET_TARGET_LATE}" 15 174
# Received stalls while sent grows since baseline: not idle.
SYNC_OFFSET_TARGET_STALLED="${TMP_DIR}/sync-offset-target-stalled.txt"
cat >"${SYNC_OFFSET_TARGET_STALLED}" <<'EOF'
Services Synchronized:
Session create 0 174

Session delta pending: 0
Session delta drained: 19
EOF
assert_helper_status 1 ha_session_sync_idle_sample fw0 fw1 "${SYNC_OFFSET_SOURCE_LATE}" "${SYNC_OFFSET_TARGET_STALLED}" 15 174
# Offset pair with pending nonzero: not idle even with equal deltas.
SYNC_OFFSET_TARGET_PENDING="${TMP_DIR}/sync-offset-target-pending.txt"
cat >"${SYNC_OFFSET_TARGET_PENDING}" <<'EOF'
Services Synchronized:
Session create 0 174

Session delta pending: 3
Session delta drained: 19
EOF
assert_helper_status 1 ha_session_sync_idle_sample fw0 fw1 "${SYNC_OFFSET_SOURCE}" "${SYNC_OFFSET_TARGET_PENDING}" 15 174
# #16500: shrinking gap since baseline. In-flight creates at the first
# sample (baseline 20/17) are delivered (20/20): gap 3 -> 0, caught up,
# idle. Non-atomic captures can leave received ahead at the baseline
# (20/22) and then static (22/22): gap -2 throughout, idle. A gap that
# grows since baseline (20/20 -> 25/20) and a shrunk gap with pending
# nonzero stay not idle.
SYNC_SHRINK_BASE_SOURCE="${TMP_DIR}/sync-shrink-base-source.txt"
SYNC_SHRINK_BASE_TARGET="${TMP_DIR}/sync-shrink-base-target.txt"
cat >"${SYNC_SHRINK_BASE_SOURCE}" <<'EOF'
Services Synchronized:
Session create 20 0

Session delta pending: 0
Session delta drained: 12
EOF
cat >"${SYNC_SHRINK_BASE_TARGET}" <<'EOF'
Services Synchronized:
Session create 0 17

Session delta pending: 0
Session delta drained: 19
EOF
SYNC_SHRUNK_SOURCE="${TMP_DIR}/sync-shrunk-source.txt"
SYNC_SHRUNK_TARGET="${TMP_DIR}/sync-shrunk-target.txt"
cat >"${SYNC_SHRUNK_SOURCE}" <<'EOF'
Services Synchronized:
Session create 20 0

Session delta pending: 0
Session delta drained: 12
EOF
cat >"${SYNC_SHRUNK_TARGET}" <<'EOF'
Services Synchronized:
Session create 0 20

Session delta pending: 0
Session delta drained: 19
EOF
assert_helper_status 0 ha_session_sync_idle_sample fw0 fw1 "${SYNC_SHRUNK_SOURCE}" "${SYNC_SHRUNK_TARGET}" 20 17
# Received ahead at baseline by non-atomic capture: 20/22 -> 22/22.
SYNC_AHEAD_BASE_SOURCE="${TMP_DIR}/sync-ahead-base-source.txt"
SYNC_AHEAD_BASE_TARGET="${TMP_DIR}/sync-ahead-base-target.txt"
cat >"${SYNC_AHEAD_BASE_SOURCE}" <<'EOF'
Services Synchronized:
Session create 20 0

Session delta pending: 0
Session delta drained: 12
EOF
cat >"${SYNC_AHEAD_BASE_TARGET}" <<'EOF'
Services Synchronized:
Session create 0 22

Session delta pending: 0
Session delta drained: 19
EOF
SYNC_AHEAD_SOURCE="${TMP_DIR}/sync-ahead-source.txt"
SYNC_AHEAD_TARGET="${TMP_DIR}/sync-ahead-target.txt"
cat >"${SYNC_AHEAD_SOURCE}" <<'EOF'
Services Synchronized:
Session create 22 0

Session delta pending: 0
Session delta drained: 12
EOF
cat >"${SYNC_AHEAD_TARGET}" <<'EOF'
Services Synchronized:
Session create 0 22

Session delta pending: 0
Session delta drained: 19
EOF
assert_helper_status 0 ha_session_sync_idle_sample fw0 fw1 "${SYNC_AHEAD_SOURCE}" "${SYNC_AHEAD_TARGET}" 20 22
# Gap grows since baseline: 20/20 -> 25/20 stays not idle.
SYNC_GROWN_SOURCE="${TMP_DIR}/sync-grown-source.txt"
SYNC_GROWN_TARGET="${TMP_DIR}/sync-grown-target.txt"
cat >"${SYNC_GROWN_SOURCE}" <<'EOF'
Services Synchronized:
Session create 25 0

Session delta pending: 0
Session delta drained: 12
EOF
cat >"${SYNC_GROWN_TARGET}" <<'EOF'
Services Synchronized:
Session create 0 20

Session delta pending: 0
Session delta drained: 19
EOF
assert_helper_status 1 ha_session_sync_idle_sample fw0 fw1 "${SYNC_GROWN_SOURCE}" "${SYNC_GROWN_TARGET}" 20 20
# Shrunk gap with pending nonzero stays not idle.
SYNC_SHRUNK_TARGET_PENDING="${TMP_DIR}/sync-shrunk-target-pending.txt"
cat >"${SYNC_SHRUNK_TARGET_PENDING}" <<'EOF'
Services Synchronized:
Session create 0 20

Session delta pending: 3
Session delta drained: 19
EOF
assert_helper_status 1 ha_session_sync_idle_sample fw0 fw1 "${SYNC_SHRUNK_SOURCE}" "${SYNC_SHRUNK_TARGET_PENDING}" 20 17
# Counter rewind since baseline (daemon restart / epoch reset) is the
# distinct re-baseline verdict 3, never idle and never VOID.
assert_helper_status 3 ha_session_sync_idle_sample fw0 fw1 "${SYNC_SOURCE}" "${SYNC_TARGET}" 15 174
# Blind evidence stays VOID even on a rewound sample and even on the
# baseline-establishing sample (parse precedes every baseline branch).
assert_helper_status 2 ha_session_sync_idle_sample fw0 fw1 "${SYNC_SOURCE}" "${SYNC_MISSING_DRAINED}" 15 174
assert_helper_status 2 ha_session_sync_idle_sample fw0 fw1 "${SYNC_SOURCE}" "${SYNC_MISSING_DRAINED}" '' ''
# Malformed / half-empty baselines are VOID, and the old 4-arg shape is gone.
assert_helper_status 2 ha_session_sync_idle_sample fw0 fw1 "${SYNC_OFFSET_SOURCE}" "${SYNC_OFFSET_TARGET}" malformed 174
assert_helper_status 2 ha_session_sync_idle_sample fw0 fw1 "${SYNC_OFFSET_SOURCE}" "${SYNC_OFFSET_TARGET}" 15 ''
assert_helper_status 2 ha_session_sync_idle_sample fw0 fw1 "${SYNC_OFFSET_SOURCE}" "${SYNC_OFFSET_TARGET}"

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
	cat >"$1" <<EOF
Services Synchronized:
Session create $2 $3

Session delta pending: $4
Session delta drained: 0
EOF
}
write_seq_pair() {
	# Index/calls live in files: captures run inside $(...) subshells in
	# the failover loop, so shell variables would reset every attempt.
	local idx pair sent rest recv pending calls
	idx="$(cat "${SEQ_INDEX_FILE}")"
	pair="${SEQ[$idx]}"
	sent="${pair%%/*}"; rest="${pair#*/}"; recv="${rest%%/*}"; pending="${rest#*/}"
	write_runner_fixture "$SEQ_SOURCE" "$sent" 0 0
	write_runner_fixture "$SEQ_TARGET" 0 "$recv" "$pending"
	if (( idx < ${#SEQ[@]} - 1 )); then printf '%s\n' "$((idx + 1))" > "${SEQ_INDEX_FILE}"; fi
	calls="$(cat "${SEQ_CALLS_FILE}")"; printf '%s\n' "$((calls + 1))" > "${SEQ_CALLS_FILE}"
}
ha_capture_sync_stats() {
	# Failover loop captures source then target per attempt; advance
	# the sequence only on the source capture (one pair per attempt).
	local label="$1" node_id="$2"
	if [[ "$node_id" == "$SEQ_SOURCE_ID" ]]; then write_seq_pair; printf "%s\n" "$SEQ_SOURCE"; else printf "%s\n" "$SEQ_TARGET"; fi
}
capture_sync_snapshot() {
	# Userspace loop captures source then target per iteration; advance
	# only on the source capture (one pair per iteration).
	local label="$2" path
	path="$(sync_snapshot_path "$label" "$1")"
	if [[ "$1" == "$SOURCE_VM" ]]; then write_seq_pair; cp "$SEQ_SOURCE" "$path"; else cp "$SEQ_TARGET" "$path"; fi
}
run_failover_loop() {
	SEQ_SOURCE_ID=node0
	if ha_wait_for_session_sync_idle loop node0 fw0 node1 fw1; then printf "LOOPRC=0\n"; else printf "LOOPRC=%s\n" "$?"; fi
	printf "VERDICTS PASS=%s FAIL=%s VOID=%s CALLS=%s\n" "$PASS" "$FAIL" "$VOID" "$(cat "${SEQ_CALLS_FILE}")"
}
run_userspace_loop() {
	SOURCE_VM="$FW0" TARGET_VM="$FW1"
	if wait_for_session_sync_idle loop; then printf "LOOPRC=0\n"; else printf "LOOPRC=%s\n" "$?"; fi
	printf "VERDICTS PASS=%s FAIL=%s VOID=%s CALLS=%s\n" "$PASS" "$FAIL" "$VOID" "$(cat "${SEQ_CALLS_FILE}")"
}
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
		ARTIFACT_DIR="$LOOP_DIR" SOURCE_NODE=0 TARGET_NODE=1 FW0=fw0 FW1=fw1 SEQ_EXPORT=1 \
		bash -euo pipefail "$LOOP_RUNNER_FILE" "$LOOP_DIR/lib.sh" "$LOOP_HELPERS" "$loop" 2>&1)"
	assert_eq "$out" "$expected" "$context"
}

# Stuck: baseline 15/174, one unreceived send 16/174 repeated forever.
# Timeout 8 = baseline + 6 stuck repeats + FAIL; never PASS.
run_sync_loop_case failover 8 'session sync node0->node1 baseline: source sent=15, target received=174, pending=0
session sync node0->node1 not idle: source sent=16 (baseline 15), target received=174 (baseline 174), pending=0
session sync node0->node1 not idle: source sent=16 (baseline 15), target received=174 (baseline 174), pending=0
session sync node0->node1 not idle: source sent=16 (baseline 15), target received=174 (baseline 174), pending=0
session sync node0->node1 not idle: source sent=16 (baseline 15), target received=174 (baseline 174), pending=0
session sync node0->node1 not idle: source sent=16 (baseline 15), target received=174 (baseline 174), pending=0
session sync node0->node1 not idle: source sent=16 (baseline 15), target received=174 (baseline 174), pending=0
session sync node0->node1 not idle: source sent=16 (baseline 15), target received=174 (baseline 174), pending=0
FAIL-MARK loop: session sync did not become idle within 8s (node0->node1)
LOOPRC=1
VERDICTS PASS=0 FAIL=1 VOID=0 CALLS=8' 'failover loop: unreceived send is never absorbed' '15/174/0' '16/174/0'
run_sync_loop_case userspace 8 'FAIL-MARK loop: session sync did not become idle before timeout (source_sent=16 target_recv=174 target_delta_pending=0 target_delta_drained=0)
LOOPRC=1
VERDICTS PASS=0 FAIL=1 VOID=0 CALLS=8' 'userspace loop: unreceived send is never absorbed' '15/174/0' '16/174/0'
# Catch-up: 15/174 -> 16/174 -> 16/175 x3 idle samples -> PASS at sample 5.
run_sync_loop_case failover 30 'session sync node0->node1 baseline: source sent=15, target received=174, pending=0
session sync node0->node1 not idle: source sent=16 (baseline 15), target received=174 (baseline 174), pending=0
PASS-MARK loop: session sync idle (node0->node1, 3 consecutive samples)
LOOPRC=0
VERDICTS PASS=1 FAIL=0 VOID=0 CALLS=5' 'failover loop: received catch-up idles' '15/174/0' '16/174/0' '16/175/0'
run_sync_loop_case userspace 30 'PASS-MARK loop: session sync idle (source_sent=16 target_recv=175 target_delta_pending=0 target_delta_drained=0)
LOOPRC=0
VERDICTS PASS=1 FAIL=0 VOID=0 CALLS=5' 'userspace loop: received catch-up idles' '15/174/0' '16/174/0' '16/175/0'
# Rewind-only re-baseline: 15/174 -> restart 2/3 -> 2/3 x3 -> PASS sample 5.
run_sync_loop_case failover 30 'session sync node0->node1 baseline: source sent=15, target received=174, pending=0
session sync node0->node1 not idle: counters rewound since baseline (source sent=2 baseline=15, target received=3 baseline=174, pending=0); re-baseline required
PASS-MARK loop: session sync idle (node0->node1, 3 consecutive samples)
LOOPRC=0
VERDICTS PASS=1 FAIL=0 VOID=0 CALLS=5' 'failover loop: rewind re-baselines then idles' '15/174/0' '2/3/0'
run_sync_loop_case userspace 30 'PASS-MARK loop: session sync idle (source_sent=2 target_recv=3 target_delta_pending=0 target_delta_drained=0)
LOOPRC=0
VERDICTS PASS=1 FAIL=0 VOID=0 CALLS=5' 'userspace loop: rewind re-baselines then idles' '15/174/0' '2/3/0'
# First sample establishes the baseline (minimum 4 samples to PASS).
run_sync_loop_case failover 30 'session sync node0->node1 baseline: source sent=15, target received=174, pending=0
PASS-MARK loop: session sync idle (node0->node1, 3 consecutive samples)
LOOPRC=0
VERDICTS PASS=1 FAIL=0 VOID=0 CALLS=4' 'failover loop: first sample is never idle alone' '15/174/0'
run_sync_loop_case userspace 30 'PASS-MARK loop: session sync idle (source_sent=15 target_recv=174 target_delta_pending=0 target_delta_drained=0)
LOOPRC=0
VERDICTS PASS=1 FAIL=0 VOID=0 CALLS=4' 'userspace loop: first sample is never idle alone' '15/174/0'
# #16500 shrinking gap: baseline 20/17 with 3 in flight, delivered to
# 20/20 (repeated) -> 3 idle samples -> PASS at sample 4 (baseline + 3).
run_sync_loop_case failover 30 'session sync node0->node1 baseline: source sent=20, target received=17, pending=0
PASS-MARK loop: session sync idle (node0->node1, 3 consecutive samples)
LOOPRC=0
VERDICTS PASS=1 FAIL=0 VOID=0 CALLS=4' 'failover loop: shrinking in-flight gap idles' '20/17/0' '20/20/0'
run_sync_loop_case userspace 30 'PASS-MARK loop: session sync idle (source_sent=20 target_recv=20 target_delta_pending=0 target_delta_drained=0)
LOOPRC=0
VERDICTS PASS=1 FAIL=0 VOID=0 CALLS=4' 'userspace loop: shrinking in-flight gap idles' '20/17/0' '20/20/0'
# #16500 received-ahead baseline: 20/22 -> 22/22 (repeated) -> PASS.
run_sync_loop_case failover 30 'session sync node0->node1 baseline: source sent=20, target received=22, pending=0
PASS-MARK loop: session sync idle (node0->node1, 3 consecutive samples)
LOOPRC=0
VERDICTS PASS=1 FAIL=0 VOID=0 CALLS=4' 'failover loop: received-ahead baseline idles' '20/22/0' '22/22/0'
run_sync_loop_case userspace 30 'PASS-MARK loop: session sync idle (source_sent=22 target_recv=22 target_delta_pending=0 target_delta_drained=0)
LOOPRC=0
VERDICTS PASS=1 FAIL=0 VOID=0 CALLS=4' 'userspace loop: received-ahead baseline idles' '20/22/0' '22/22/0'
# #16500 growing gap never idles: 20/20 -> 25/20 repeated -> timeout.
run_sync_loop_case failover 8 'session sync node0->node1 baseline: source sent=20, target received=20, pending=0
session sync node0->node1 not idle: source sent=25 (baseline 20), target received=20 (baseline 20), pending=0
session sync node0->node1 not idle: source sent=25 (baseline 20), target received=20 (baseline 20), pending=0
session sync node0->node1 not idle: source sent=25 (baseline 20), target received=20 (baseline 20), pending=0
session sync node0->node1 not idle: source sent=25 (baseline 20), target received=20 (baseline 20), pending=0
session sync node0->node1 not idle: source sent=25 (baseline 20), target received=20 (baseline 20), pending=0
session sync node0->node1 not idle: source sent=25 (baseline 20), target received=20 (baseline 20), pending=0
session sync node0->node1 not idle: source sent=25 (baseline 20), target received=20 (baseline 20), pending=0
FAIL-MARK loop: session sync did not become idle within 8s (node0->node1)
LOOPRC=1
VERDICTS PASS=0 FAIL=1 VOID=0 CALLS=8' 'failover loop: growing gap never idles' '20/20/0' '25/20/0'
run_sync_loop_case userspace 8 'FAIL-MARK loop: session sync did not become idle before timeout (source_sent=25 target_recv=20 target_delta_pending=0 target_delta_drained=0)
LOOPRC=1
VERDICTS PASS=0 FAIL=1 VOID=0 CALLS=8' 'userspace loop: growing gap never idles' '20/20/0' '25/20/0'
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
calls = sum(1 for line in match.group(0).splitlines() if line.split("#", 1)[0].strip() == "wan_claim_cell")
blocks.append(f"WAN_CLAIM_CELL_CALLS={calls}\n")
pathlib.Path(sys.argv[3]).write_text("".join(blocks), encoding="utf-8")
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
assert_eq "$(bash -c "source '$CLAIM_WIRING'; echo \$WAN_CLAIM_CELL_CALLS")" 1 \
	'test-connectivity test_cluster calls wan_claim_cell exactly once (code, not a comment)'
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
