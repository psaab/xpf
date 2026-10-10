#!/usr/bin/env bash
# Shared JSON-stream client verdicts for multi-transition HA smoke tests.

HA_SMOKE_IPERF_LIB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=test/incus/failover-client-lib.sh
source "${HA_SMOKE_IPERF_LIB_DIR}/failover-client-lib.sh"
# shellcheck source=test/incus/ha-assurance-lib.sh
source "${HA_SMOKE_IPERF_LIB_DIR}/ha-assurance-lib.sh"
# shellcheck source=test/incus/iperf-throughput-lib.sh
source "${HA_SMOKE_IPERF_LIB_DIR}/iperf-throughput-lib.sh"

# ha_smoke_iperf_verdicts <remote-log> <duration> <streams> <min-gbps> <event-1-sec> <event-2-sec>
# Capture the tracked client's JSON stream once, then emit one anchored
# throughput cell, one whole-run interval verdict, and one stream verdict per
# recorded transition. Each output line starts with PASS or FAIL for the
# caller's existing result-cell adapter.
# shellcheck disable=SC2154 # ha_metrics_gate assignments are materialized by eval below.
ha_smoke_iperf_verdicts() {
	if [[ $# -ne 6 ]]; then
		printf 'FAIL iperf3 oracle: expected a log, duration, stream count, floor, and exactly two transition times\n'
		return 0
	fi

	local remote_log="$1" duration="$2" streams="$3" min_gbps="$4"
	local work_dir local_log metrics_file producer gate_output gate_error
	local capture_error metrics_error verdict reason event_number
	local oracle_output oracle_error line status message
	local -a oracle_lines=()
	local -a events=("$5" "$6")

	work_dir=$(mktemp -d "${TMPDIR:-/tmp}/ha-smoke-iperf.XXXXXX") || {
		printf 'FAIL iperf3 throughput: cannot create temporary metrics directory\n'
		printf 'FAIL iperf3 completion: cannot create temporary metrics directory\n'
		printf 'FAIL iperf3 intervals: cannot create temporary metrics directory\n'
		printf 'FAIL iperf3 transition 1 streams: cannot create temporary metrics directory\n'
		printf 'FAIL iperf3 transition 2 streams: cannot create temporary metrics directory\n'
		return 0
	}
	local_log="${work_dir}/iperf.jsonl"
	metrics_file="${work_dir}/metrics.json"
	gate_error="${work_dir}/gate.err"
	oracle_error="${work_dir}/oracle.err"
	producer="${HA_SMOKE_IPERF_LIB_DIR}/../../scripts/iperf-json-metrics.py"

	if ! failover_wait_main_iperf_result "$remote_log" "$duration"; then
		:
	fi

	capture_error=""
	if ! incus exec "$CLUSTER_LAN_HOST" -- cat "$remote_log" >"$local_log" 2>"${work_dir}/capture.err"; then
		capture_error=$(<"${work_dir}/capture.err")
		[[ -n "$capture_error" ]] || capture_error="remote iperf3 log capture failed"
		: >"$local_log"
	fi

	metrics_error=""
	if ! python3 "$producer" "$local_log" >"$metrics_file" 2>"${work_dir}/producer.err"; then
		metrics_error=$(<"${work_dir}/producer.err")
		[[ -n "$metrics_error" ]] || metrics_error="JSON metrics producer failed"
	fi

	if [[ -z "$capture_error" && -z "$metrics_error" ]] \
		&& gate_output=$(ha_metrics_gate "$metrics_file" 2>"$gate_error"); then
		eval "$gate_output"
		verdict=$(iperf_throughput_json_verdict "$min_gbps" "$avg_gbps" \
			"json-stream avg_gbps from iperf3 metrics; ${full_interval_count} full intervals")
		printf '%s\n' "$verdict"
		if [[ "$completed" == true ]]; then
			printf 'PASS iperf3 completed successfully\n'
		elif awk -v observed="$observed_end_sec" -v duration="$duration" -v avg="$avg_gbps" -v min="$min_gbps" \
			'BEGIN { exit !(observed >= duration - 2 && avg >= min) }'; then
			printf 'PASS iperf3 data transfer completed (%.3f Gbps) — JSON duration reached\n' "$avg_gbps"
		else
			printf 'FAIL iperf3 completion: JSON stream ended at %.3fs of %ss without a valid end event\n' \
				"$observed_end_sec" "$duration"
		fi
	else
		reason="$capture_error"
		if [[ -z "$reason" ]]; then
			reason="$metrics_error"
		fi
		if [[ -z "$reason" ]]; then
			reason=$(<"$gate_error")
		fi
		[[ -n "$reason" ]] || reason="JSON-stream metrics were unavailable or invalid"
		printf 'FAIL iperf3 throughput: JSON metrics unavailable: %s\n' "$reason"
		printf 'FAIL iperf3 completion: JSON metrics unavailable: %s\n' "$reason"
	fi

	for event_number in 1 2; do
		: >"$oracle_error"
		if oracle_output=$(python3 "${HA_SMOKE_IPERF_LIB_DIR}/iperf3_sum_parse.py" \
			--failover-check --json-stream --streams "$streams" \
			--min-throughput-gbps "$min_gbps" --crash-at "${events[$((event_number - 1))]}" \
			<"$local_log" 2>"$oracle_error"); then
			mapfile -t oracle_lines <<<"$oracle_output"
		else
			oracle_lines=()
		fi

		if (( ${#oracle_lines[@]} != 2 )); then
			message=$(<"$oracle_error")
			[[ -n "$message" ]] || message="failover oracle did not return both verdicts"
			if (( event_number == 1 )); then
				printf 'FAIL iperf3 intervals: %s\n' "$message"
			fi
			printf 'FAIL iperf3 transition %s streams: %s\n' "$event_number" "$message"
			continue
		fi

		if (( event_number == 1 )); then
			line="${oracle_lines[0]}"
			status="${line%% *}"
			message="${line#* }"
			if [[ "$status" != PASS && "$status" != FAIL ]]; then
				status=FAIL
				message="unrecognized failover interval verdict: $line"
			fi
			printf '%s iperf3 intervals: %s\n' "$status" "$message"
		fi
		line="${oracle_lines[1]}"
		status="${line%% *}"
		message="${line#* }"
		if [[ "$status" != PASS && "$status" != FAIL ]]; then
			status=FAIL
			message="unrecognized transition stream verdict: $line"
		fi
		printf '%s iperf3 transition %s streams: %s\n' "$status" "$event_number" "$message"
	done

	rm -rf "$work_dir"
}
