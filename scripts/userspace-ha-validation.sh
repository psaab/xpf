#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
source "${PROJECT_ROOT}/test/incus/ha-assurance-lib.sh"
ENV_FILE="${BPFRX_CLUSTER_ENV:-${PROJECT_ROOT}/test/incus/loss-userspace-cluster.env}"
RUNS="${RUNS-3}"
DURATION="${DURATION-5}"
PARALLEL="${PARALLEL-6}"
MIN_GBPS_V4="${MIN_GBPS_V4:-18.0}"
MIN_GBPS_V6="${MIN_GBPS_V6:-18.0}"
MARGINAL_GBPS_EPSILON="${MARGINAL_GBPS_EPSILON:-0.25}"
IPERF_MIN_PEAK_GBPS="${IPERF_MIN_PEAK_GBPS:-2.0}"
IPERF_MIN_TAIL_RATIO="${IPERF_MIN_TAIL_RATIO:-0.35}"
IPERF_ZERO_GBPS="${IPERF_ZERO_GBPS:-0.05}"
IPERF_STALL_GBPS="${IPERF_STALL_GBPS:-0.25}"
IPERF_TAIL_WINDOW="${IPERF_TAIL_WINDOW:-2}"
PREFERRED_ACTIVE_NODE="${PREFERRED_ACTIVE_NODE:-0}"
PREFERRED_ACTIVE_RGS="${PREFERRED_ACTIVE_RGS:-1 2}"
V4_TEST_TARGET="${V4_TEST_TARGET:-172.16.80.200}"
V6_TEST_TARGET="${V6_TEST_TARGET:-2001:559:8585:80::200}"
# Iperf port selection for the smoke harness:
# - FAST_IPERF_PORT: current-CoS fast/readiness cells, default 5201.
# - MATRIX_COS_OFF_IPERF_PORT: full-matrix CoS-off cells, default 5201.
# - MATRIX_COS_ON_IPERF_PORT: full-matrix CoS-on cells; default 5211
#   matches the uncapped class in test/incus/cos-iperf-symmetric.set.
# - PERF_IPERF_PORT: perf profiling traffic; captured pre-matrix in matrix
#   mode, default 5201.
# Keep these defaults in sync with docs/pr/1373-retire-ebpf-dataplane/smoke-gates.md.
# All four values are validated as TCP ports before any remote iperf command runs.
FAST_IPERF_PORT="${FAST_IPERF_PORT-5201}"
MATRIX_COS_OFF_IPERF_PORT="${MATRIX_COS_OFF_IPERF_PORT-5201}"
MATRIX_COS_ON_IPERF_PORT="${MATRIX_COS_ON_IPERF_PORT-5211}"
PERF_IPERF_PORT="${PERF_IPERF_PORT-5201}"
MTR_V4_TARGET="${MTR_V4_TARGET:-1.1.1.1}"
MTR_V6_TARGET="${MTR_V6_TARGET:-2607:f8b0:4005:814::200e}"
MTR_REPORT_CYCLES="${MTR_REPORT_CYCLES:-1}"
WAN_TEST_IFACE="${WAN_TEST_IFACE:-}"
IPERF_METRICS="${PROJECT_ROOT}/scripts/iperf-json-metrics.py"
ALLOW_LEGACY_EBPF_HA_VALIDATION="${ALLOW_LEGACY_EBPF_HA_VALIDATION:-0}"
SMOKE_MODE="${SMOKE_MODE:-fast}"
WITH_PERF=0
DEPLOY=0
DRY_RUN_MATRIX=0
DRY_RUN_FAIL_CELL="${DRY_RUN_FAIL_CELL:-}"

while [[ $# -gt 0 ]]; do
	case "$1" in
	--perf) WITH_PERF=1 ;;
	--deploy) DEPLOY=1 ;;
	--smoke-matrix | --full-matrix) SMOKE_MODE="matrix" ;;
	--fast) SMOKE_MODE="fast" ;;
	--dry-run-matrix) DRY_RUN_MATRIX=1 ;;
	--dry-run-fail-cell) DRY_RUN_FAIL_CELL="$2"; shift ;;
	--env) ENV_FILE="$2"; shift ;;
	--runs) RUNS="$2"; shift ;;
	--duration) DURATION="$2"; shift ;;
	--parallel) PARALLEL="$2"; shift ;;
	*)
		echo "unknown arg: $1" >&2
		exit 2
		;;
	esac
	shift
done

# shellcheck disable=SC1090
source "$ENV_FILE"

REMOTE_PREFIX="${INCUS_REMOTE:+${INCUS_REMOTE}:}"
FW0="${REMOTE_PREFIX}${VM0}"
FW1="${REMOTE_PREFIX}${VM1}"
HOST="${REMOTE_PREFIX}${LAN_HOST}"
ACTIVE_FW="${FW0}"

info() { printf '==> %s\n' "$*"; }
die() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }
void() { printf 'VOID: %s\n' "$*" >&2; exit 77; }

validate_port() {
	local name="$1" value="$2"
	if ! [[ "$value" =~ ^[0-9]+$ ]] ||
		((${#value} > 5)) ||
		((10#$value < 1 || 10#$value > 65535)); then
		die "${name} must be a numeric port (1-65535), got: ${value}"
	fi
}

validate_positive_int() {
	local name="$1" value="$2"
	if ! [[ "$value" =~ ^[0-9]+$ ]] ||
		((${#value} > 9)) ||
		((10#$value < 1)); then
		die "${name} must be a positive integer, got: ${value}"
	fi
}

validate_iperf_ports() {
	validate_port FAST_IPERF_PORT "$FAST_IPERF_PORT"
	validate_port MATRIX_COS_OFF_IPERF_PORT "$MATRIX_COS_OFF_IPERF_PORT"
	validate_port MATRIX_COS_ON_IPERF_PORT "$MATRIX_COS_ON_IPERF_PORT"
	validate_port PERF_IPERF_PORT "$PERF_IPERF_PORT"
}

validate_iperf_runtime_knobs() {
	validate_positive_int RUNS "$RUNS"
	validate_positive_int DURATION "$DURATION"
	validate_positive_int PARALLEL "$PARALLEL"
	validate_positive_int IPERF_TIMEOUT "$IPERF_TIMEOUT"
}

default_iperf_timeout() {
	validate_positive_int DURATION "$DURATION"
	IPERF_TIMEOUT="${IPERF_TIMEOUT-$((10#$DURATION + 15))}"
}

normalize_smoke_mode() {
	case "$SMOKE_MODE" in
	matrix | full | full-matrix | smoke-matrix) SMOKE_MODE="matrix" ;;
	fast | legacy) SMOKE_MODE="fast" ;;
	*) die "unknown SMOKE_MODE: ${SMOKE_MODE}" ;;
	esac
}

run_host() {
	sg incus-admin -c "incus exec ${HOST} -- bash -lc $(printf %q "$1")"
}

run_vm() {
	local vm="$1"
	shift
	sg incus-admin -c "incus exec ${vm} -- bash -lc $(printf %q "$1")"
}

run_fw0() {
	run_vm "${FW0}" "$1"
}

run_fw1() {
	run_vm "${FW1}" "$1"
}

run_active_fw() {
	run_vm "${ACTIVE_FW}" "$1"
}

wait_for_vm_cli() {
	local vm="$1"
	local tries=30
	while (( tries > 0 )); do
		if run_vm "$vm" 'cli -c "show chassis cluster data-plane statistics" >/tmp/userspace-cli-ready.out 2>/dev/null'; then
			return 0
		fi
		sleep 1
		tries=$((tries - 1))
	done
	return 1
}

runtime_mode() {
	local tries=20
	local prog_check helper_stats
	while (( tries > 0 )); do
		prog_check="$(run_fw0 'ip -details link show dev ge-0-0-1; echo ---; ip -details link show dev ge-0-0-2')"
		helper_stats="$(run_fw0 'cli -c "show chassis cluster data-plane statistics"')"
		if grep -Eq 'Forwarding supported:[[:space:]]+true' <<<"$helper_stats" &&
			[[ "$prog_check" == *"name xdp_userspace_p"* ]]; then
			printf 'supported\n'
			return 0
		fi
		if [[ "$prog_check" == *"name xdp_main_p"* ]] &&
			grep -Eq 'Forwarding supported:[[:space:]]+false' <<<"$helper_stats" &&
			grep -Eq 'Enabled:[[:space:]]+false' <<<"$helper_stats" &&
			grep -Eq 'Bound bindings:[[:space:]]+0/[0-9]+' <<<"$helper_stats"; then
			printf 'legacy\n'
			return 0
		fi
		sleep 1
		tries=$((tries - 1))
	done
	printf '%s\n---\n%s\n' "$prog_check" "$helper_stats" >&2
	return 1
}

enabled_userspace_vm() {
	local vm="$1"
	local stats
	stats="$(run_vm "$vm" 'cli -c "show chassis cluster data-plane statistics"')"
	grep -Eq 'Enabled:[[:space:]]+true' <<<"$stats" &&
		grep -Eq 'Forwarding supported:[[:space:]]+true' <<<"$stats" &&
		grep -Eq 'Ready bindings:[[:space:]]+[1-9][0-9]*/[0-9]+' <<<"$stats"
}

active_owner_vm() {
	local active=()
	local vm stats query_failed=0
	for vm in "$FW0" "$FW1"; do
		if ! stats="$(run_vm "$vm" 'cli -c "show chassis cluster data-plane statistics"' 2>/dev/null)"; then
			printf 'failed to query data-plane statistics from %s\n' "$vm" >&2
			query_failed=1
			continue
		fi
		if grep -Eq 'HA groups:[[:space:]].*rg[1-9][0-9]* active=true' <<<"$stats"; then
			active+=("$vm")
		fi
	done
	if (( query_failed != 0 )); then
		return 2
	fi
	if (( ${#active[@]} == 1 )); then
		printf '%s\n' "${active[0]}"
		return 0
	fi
	if (( ${#active[@]} > 1 )); then
		printf 'split-brain active owners: %s\n' "${active[*]}" >&2
		return 2
	fi
	return 1
}

rg_primary_node() {
	local vm="$1"
	local rg="$2"
	local status
	status="$(run_vm "$vm" 'cli -c "show chassis cluster status"' 2>/dev/null || true)"
	if grep -Eq "Redundancy group: ${rg} " <<<"$status"; then
		if awk -v rg="$rg" '
			$0 ~ ("Redundancy group: " rg " ") { in_rg=1; next }
			in_rg && /^Redundancy group:/ { in_rg=0 }
			in_rg && /primary/ { print $1; exit }
		' <<<"$status"; then
			return 0
		fi
	fi
	return 1
}

ensure_preferred_active_node() {
	local preferred_name="node0"
	if [[ "$PREFERRED_ACTIVE_NODE" == "1" ]]; then
		preferred_name="node1"
	fi
	info "pinning userspace validation to ${preferred_name} for RGs:${PREFERRED_ACTIVE_RGS}"
	run_host 'sysctl -qw net.ipv6.conf.eth0.accept_ra=2 || true'
	local tries=45
	while (( tries > 0 )); do
		local all_good=1
		for rg in $PREFERRED_ACTIVE_RGS; do
			local current=""
			current="$(rg_primary_node "$FW0" "$rg" || true)"
			if [[ "$current" != "$preferred_name" ]]; then
				local failover_cmd
				all_good=0
				failover_cmd="cli -c \"request chassis cluster failover redundancy-group ${rg} node ${PREFERRED_ACTIVE_NODE}\""
				failover_cmd+=" >/tmp/userspace-failover-rg${rg}.out 2>&1 || true"
				run_vm "$FW0" "$failover_cmd"
			fi
		done
		if (( all_good == 1 )); then
			return 0
		fi
		sleep 1
		tries=$((tries - 1))
	done
	die "preferred validation owner ${preferred_name} did not take over RGs:${PREFERRED_ACTIVE_RGS}"
}

wait_for_active_supported_runtime() {
	local tries=30
	while (( tries > 0 )); do
		local owner owner_status
		if owner="$(active_owner_vm)"; then
			if enabled_userspace_vm "$owner" >/dev/null 2>&1; then
				printf '%s\n' "$owner"
				return 0
			fi
		else
			owner_status=$?
			if (( owner_status == 2 )); then
				return 2
			fi
		fi
		sleep 1
		tries=$((tries - 1))
	done
	return 1
}

arm_supported_runtime() {
	local owner owner_status runtime_status
	info "waiting for userspace forwarding to auto-arm on the active node"
	if ACTIVE_FW="$(wait_for_active_supported_runtime)"; then
		info "active userspace firewall: ${ACTIVE_FW}"
		return 0
	else
		runtime_status=$?
		if (( runtime_status == 2 )); then
			die "supported userspace runtime requires an unambiguous active firewall owner"
		fi
	fi
	if ! owner="$(active_owner_vm)"; then
		owner_status=$?
		if (( owner_status == 2 )); then
			die "cannot force userspace arm with an ambiguous active firewall owner"
		fi
		die "cannot force userspace arm before an active firewall owner is reported"
	fi
	info "auto-arm did not settle, forcing forwarding arm on ${owner}"
	run_vm "$owner" 'cli -c "request chassis cluster data-plane userspace forwarding arm" >/tmp/userspace-arm.out'
	if ACTIVE_FW="$(wait_for_active_supported_runtime)"; then
		info "active userspace firewall: ${ACTIVE_FW}"
		return 0
	else
		runtime_status=$?
		if (( runtime_status == 2 )); then
			die "supported userspace runtime became ambiguous after forced arm"
		fi
	fi
	run_vm "$owner" 'cli -c "show chassis cluster data-plane statistics" >&2 || true'
	die "userspace forwarding did not become enabled on the active node"
}

wait_for_ipv6_default_route() {
	local tries=20
	while (( tries > 0 )); do
		local route
		route="$(run_host 'ip -6 route show default || true')"
		if [[ -n "$route" ]]; then
			return 0
		fi
		run_host 'timeout 8 rdisc6 -1 eth0 >/tmp/userspace-rdisc6.out 2>/dev/null || true'
		sleep 1
		tries=$((tries - 1))
	done
	return 1
}

ensure_dualstack_wan_neighbors() {
	local vm="$1"
	local mac=""
	local wan_iface=""
	if [[ -n "${WAN_TEST_IFACE}" ]]; then
		wan_iface="${WAN_TEST_IFACE}"
	else
		wan_iface="$(run_vm "$vm" "ip -6 route get ${V6_TEST_TARGET} 2>/dev/null | sed -n 's/.* dev \\([^ ]*\\) .*/\\1/p' | head -n 1")"
		if [[ -z "${wan_iface}" ]]; then
			wan_iface="$(run_vm "$vm" "ip route get ${V4_TEST_TARGET} 2>/dev/null | sed -n 's/.* dev \\([^ ]*\\) .*/\\1/p' | head -n 1")"
		fi
	fi
	if [[ -z "${wan_iface}" ]]; then
		die "unable to detect WAN test interface for ${vm}"
	fi
	info "ensuring IPv4/IPv6 WAN neighbor state on ${vm}"
	run_vm "$vm" "ping -6 -c 1 -W 1 ${V6_TEST_TARGET} >/dev/null 2>&1 || true"
	mac="$(run_vm "$vm" "ip -6 neigh show dev ${wan_iface} ${V6_TEST_TARGET} 2>/dev/null | sed -n 's/.* lladdr \\([^ ]*\\) .*/\\1/p' | head -n 1")"
	if [[ -z "${mac}" ]]; then
		die "unable to learn IPv6 neighbor MAC for ${V6_TEST_TARGET} on ${vm}:${wan_iface}"
	fi
	run_vm "$vm" "ip neigh replace ${V4_TEST_TARGET} lladdr ${mac} nud permanent dev ${wan_iface}"
}

run_ttl_probe() {
	local family="$1" target="$2" outfile="$3"
	local cmd
	if [[ "$family" == "6" ]]; then
		cmd="rm -f ${outfile}; if ping -6 -c 1 -W 2 -t 1 ${target} > ${outfile} 2>&1; then :; else rc=\$?; if [[ \$rc -gt 1 ]]; then echo \"ping exited with status \$rc\" >> ${outfile}; exit \$rc; fi; fi"
	else
		cmd="rm -f ${outfile}; if ping -c 1 -W 2 -t 1 ${target} > ${outfile} 2>&1; then :; else rc=\$?; if [[ \$rc -gt 1 ]]; then echo \"ping exited with status \$rc\" >> ${outfile}; exit \$rc; fi; fi"
	fi
	if run_host "$cmd"; then
		TTL_PROBE_COMMAND_STATUS=0
	else
		# The remote wrapper normalizes an expected ping rc=1 to zero, so
		# any command failure here means the captured ping evidence is blind.
		TTL_PROBE_COMMAND_STATUS=2
	fi
}

validate_ttl_probe() {
	local label="$1" path="$2"
	local output capture_status=0 command_status verdict_status verdict_output
	if output="$(run_host "cat ${path}")"; then
		:
	else
		capture_status=2
	fi
	command_status="${TTL_PROBE_COMMAND_STATUS:-2}"
	if (( capture_status != 0 )); then
		command_status=2
	fi
	if verdict_output="$(ha_ttl_output_verdict "$command_status" "$output" 2>&1)"; then
		printf '%s ttl probe: ok\n' "$label" | tee -a "$summary_file"
		return 0
	else
		verdict_status=$?
	fi
	if (( verdict_status == 2 )); then
		void "${label} TTL=1 probe evidence unavailable: ${verdict_output}"
	fi
	die "${label} TTL=1 probe did not return time-exceeded: ${output}"
}

run_mtr_report() {
	local family="$1" target="$2" outfile="$3"
	local cmd
	# Capture mtr output and swallow its exit code: a non-zero mtr exit
	# (e.g. partial/unanswered public trace) must not crash the validator
	# under `set -e` before validate_mtr_report can classify the report
	# and decide whether the result is fatal or observability-only.
	# LC_ALL=C pins the report wording (`(waiting for reply)`) and the
	# dot-decimal loss column the classifier parses, so the verdict is
	# locale-independent.
	if [[ "$family" == "6" ]]; then
		cmd="LC_ALL=C mtr -6 ${target} --report --report-cycles=${MTR_REPORT_CYCLES} > ${outfile} 2>&1 || true"
	else
		cmd="LC_ALL=C mtr ${target} --report --report-cycles=${MTR_REPORT_CYCLES} > ${outfile} 2>&1 || true"
	fi
	run_host "$cmd"
}

validate_mtr_report() {
	local label="$1" path="$2" allow_unresolved_destination="${3:-0}"
	local report result
	report="$(run_host "cat ${path}")"
	if ! result="$(python3 "${SCRIPT_DIR}/mtr_report_check.py" \
		"$label" "$report" "$allow_unresolved_destination" 2>&1)"; then
		die "$result"
	fi
	printf '%s\n' "$result" | tee -a "$summary_file"
}

# Assert the LAN host actually received ICMP echo replies from the target.
# Preserve ping's exit status so a valid zero-reply result remains a measured
# failure while an unavailable/malformed capture is VOID.
# This is the controlled forwarding-correctness gate: the LAN host reaches
# the WAN-side target only by transiting the userspace dataplane.
run_controlled_ping() {
	local family="$1" target="$2" path="$3" cmd
	if ! run_host "rm -f ${path}"; then
		CONTROLLED_PING_STATUS=2
		return 0
	fi
	if [[ "$family" == "6" ]]; then
		cmd="LC_ALL=C ping -6 -c 2 -W 1 ${target} > ${path} 2>&1"
	else
		cmd="LC_ALL=C ping -c 2 -W 1 ${target} > ${path} 2>&1"
	fi
	if run_host "$cmd"; then
		CONTROLLED_PING_STATUS=0
	else
		CONTROLLED_PING_STATUS=$?
	fi
}

validate_reachability() {
	local label="$1" path="$2" command_status="$3"
	local out capture_status=0 verdict_status verdict_output
	if out="$(run_host "cat ${path}")"; then
		:
	else
		capture_status=2
	fi
	if (( capture_status != 0 )); then
		command_status=2
	fi
	if verdict_output="$(ha_ping_reply_verdict "$command_status" "$out" 2>&1)"; then
		printf '%s reachability: ok\n' "$label" | tee -a "$summary_file"
		return 0
	else
		verdict_status=$?
	fi
	if (( verdict_status == 2 )); then
		void "${label} reachability evidence unavailable: ${verdict_output}"
	fi
	die "${label} reachability: target not reached (no replies): ${out}"
}

# Guard against topology drift: the controlled reachability ping only
# proves forwarding if the target is reached THROUGH the firewall. If the
# LAN host has the target assigned locally or routed via loopback, the
# ping never transits the dataplane and the gate would be meaningless.
assert_forwarding_route() {
	local family="$1" label="$2" target="$3"
	local route route_status=0 verdict_status verdict_output
	if [[ "$family" == "6" ]]; then
		if route="$(run_host "ip -6 route get ${target} 2>&1")"; then
			route_status=0
		else
			route_status=$?
		fi
	else
		if route="$(run_host "ip route get ${target} 2>&1")"; then
			route_status=0
		else
			route_status=$?
		fi
	fi
	if verdict_output="$(ha_route_lookup_verdict "$route_status" "$route" 2>&1)"; then
		printf '%s forwarding-route: %s\n' "$label" "$route" | tee -a "$summary_file"
		return 0
	else
		verdict_status=$?
	fi
	if (( verdict_status == 2 )); then
		void "${label} forwarding-route evidence unavailable for ${target}: ${verdict_output}"
	fi
	die "${label} forwarding-route: ${target} resolves on-box (no transit): ${route}"
}

validate_traceroute_visibility() {
	local ttl_v4="/tmp/userspace-ttl-v4.txt"
	local ttl_v6="/tmp/userspace-ttl-v6.txt"
	local mtr_v4="/tmp/userspace-mtr-v4.txt"
	local mtr_v6="/tmp/userspace-mtr-v6.txt"

	info "validating IPv4 traceroute visibility via ${MTR_V4_TARGET}"
	run_ttl_probe 4 "${MTR_V4_TARGET}" "${ttl_v4}"
	validate_ttl_probe "ipv4" "${ttl_v4}"
	run_mtr_report 4 "${MTR_V4_TARGET}" "${mtr_v4}"
	validate_mtr_report "ipv4" "${mtr_v4}"

	info "validating IPv6 traceroute visibility via ${MTR_V6_TARGET}"
	run_ttl_probe 6 "${MTR_V6_TARGET}" "${ttl_v6}"
	validate_ttl_probe "ipv6" "${ttl_v6}"
	run_mtr_report 6 "${MTR_V6_TARGET}" "${mtr_v6}"
	validate_mtr_report "ipv6" "${mtr_v6}" 1
}

run_iperf_json() {
	if (( $# < 5 )); then
		die "run_iperf_json requires an explicit iperf port"
	fi
	local family="$1" target="$2" outfile="$3" direction="${4:-push}" port="$5"
	local cmd tmpfile timeout_sec reverse_arg=""
	local port_arg target_arg outfile_arg outfile_err_arg tmpfile_arg
	local timeout_sec_arg parallel_arg duration_arg
	tmpfile="${outfile}.tmp"
	timeout_sec="${IPERF_TIMEOUT}s"
	validate_iperf_runtime_knobs
	validate_port run_iperf_json_port "$port"
	printf -v port_arg '%q' "$port"
	printf -v target_arg '%q' "$target"
	printf -v outfile_arg '%q' "$outfile"
	printf -v outfile_err_arg '%q' "${outfile}.err"
	printf -v tmpfile_arg '%q' "$tmpfile"
	printf -v timeout_sec_arg '%q' "$timeout_sec"
	printf -v parallel_arg '%q' "$PARALLEL"
	printf -v duration_arg '%q' "$DURATION"
	case "$direction" in
	push) reverse_arg="" ;;
	reverse) reverse_arg=" -R" ;;
	*) die "unknown iperf direction: ${direction}" ;;
	esac
	if [[ "$family" == "6" ]]; then
		cmd="rm -f ${outfile_arg} ${outfile_err_arg} ${tmpfile_arg}; if timeout -k 2 ${timeout_sec_arg} iperf3 -6 -J -c ${target_arg} -p ${port_arg} -P ${parallel_arg} -t ${duration_arg}${reverse_arg} > ${tmpfile_arg} 2>${outfile_err_arg}; then mv ${tmpfile_arg} ${outfile_arg}; else rc=\$?; rm -f ${tmpfile_arg} ${outfile_arg}; if [[ \$rc -eq 124 || \$rc -eq 137 ]]; then echo \"iperf3 timed out after ${timeout_sec}\" >> ${outfile_err_arg}; else echo \"iperf3 exited with status \$rc\" >> ${outfile_err_arg}; fi; fi"
	else
		cmd="rm -f ${outfile_arg} ${outfile_err_arg} ${tmpfile_arg}; if timeout -k 2 ${timeout_sec_arg} iperf3 -J -c ${target_arg} -p ${port_arg} -P ${parallel_arg} -t ${duration_arg}${reverse_arg} > ${tmpfile_arg} 2>${outfile_err_arg}; then mv ${tmpfile_arg} ${outfile_arg}; else rc=\$?; rm -f ${tmpfile_arg} ${outfile_arg}; if [[ \$rc -eq 124 || \$rc -eq 137 ]]; then echo \"iperf3 timed out after ${timeout_sec}\" >> ${outfile_err_arg}; else echo \"iperf3 exited with status \$rc\" >> ${outfile_err_arg}; fi; fi"
	fi
	run_host "$cmd"
}

parse_gbps() {
	local metrics="$1"
	if [[ "$metrics" == ERROR:* ]]; then
		printf '%s\n' "$metrics"
		return 0
	fi
	python3 -c 'import json,sys; print("{:.3f}".format(json.load(sys.stdin)["avg_gbps"]))' <<<"$metrics"
}

iperf_metrics() {
	local path="$1"
	local local_json
	local metrics
	if ! run_host "[ -s ${path} ]" >/dev/null 2>&1; then
		local err
		err="$(run_host "cat ${path}.err 2>/dev/null || true")"
		if [[ -z "$err" ]]; then
			err="iperf3 produced no JSON output"
		fi
		printf 'ERROR:%s\n' "$err"
		return 0
	fi
	local_json="$(mktemp)"
	if ! run_host "cat ${path}" >"${local_json}"; then
		rm -f "${local_json}"
		printf 'ERROR:failed to fetch iperf3 JSON output from cluster host\n'
		return 0
	fi
	if ! metrics="$(python3 "${IPERF_METRICS}" "${local_json}" \
		--tail-window "${IPERF_TAIL_WINDOW}" \
		--min-peak-gbps "${IPERF_MIN_PEAK_GBPS}" \
		--min-tail-ratio "${IPERF_MIN_TAIL_RATIO}" \
		--zero-gbps "${IPERF_ZERO_GBPS}" \
		--stall-gbps "${IPERF_STALL_GBPS}")"; then
		rm -f "${local_json}"
		printf 'ERROR:failed to summarize iperf3 JSON output\n'
		return 0
	fi
	rm -f "${local_json}"
	printf '%s\n' "${metrics}"
}

validate_sustained_iperf() {
	local label="$1" run="$2" metrics="$3"
	python3 - <<'PY' "$label" "$run" "$metrics"
import json
import sys

label = sys.argv[1]
run = sys.argv[2]
metrics = json.loads(sys.argv[3])

if metrics.get("error"):
    raise SystemExit(f"{label} run {run} iperf error: {metrics['error']}")

if metrics.get("collapse_detected"):
    intervals = ", ".join(f"{v:.3f}" for v in metrics.get("interval_gbps", []))
    raise SystemExit(
        f"{label} run {run} sustained throughput collapse: {metrics['collapse_reason']} "
        f"(peak={metrics['peak_gbps']:.3f} Gbps tail={metrics['tail_median_gbps']:.3f} Gbps "
        f"intervals=[{intervals}])"
    )
PY
}

format_metrics_line() {
	local metrics="$1"
	python3 - <<'PY' "$metrics"
import json
import sys
metrics = json.loads(sys.argv[1])
intervals = ",".join(f"{value:.2f}" for value in metrics.get("interval_gbps", []))
print(
    f"avg={metrics['avg_gbps']:.3f} peak={metrics['peak_gbps']:.3f} "
    f"tail={metrics['tail_median_gbps']:.3f} ratio={metrics['tail_peak_ratio']:.3f} "
    f"retr={metrics['retransmits']} intervals=[{intervals}]"
)
PY
}

validate_threshold() {
	python3 - <<'PY' "$1" "$2" "$3" "$4"
import sys
actual = float(sys.argv[1])
minimum = float(sys.argv[2])
label = sys.argv[3]
run = sys.argv[4]
if actual < minimum:
    raise SystemExit(f"{label} run {run} below threshold: {actual:.3f} < {minimum:.3f} Gbps")
PY
}

matrix_cell_specs() {
	local mode="$1"
	local cos_state family direction target min_gbps family_arg port
	case "$mode" in
	matrix)
		for cos_state in cos-off cos-on; do
			for family in ipv4 ipv6; do
				for direction in push reverse; do
					if [[ "$cos_state" == "cos-on" ]]; then
						port="$MATRIX_COS_ON_IPERF_PORT"
					else
						port="$MATRIX_COS_OFF_IPERF_PORT"
					fi
					if [[ "$family" == "ipv4" ]]; then
						target="$V4_TEST_TARGET"
						min_gbps="$MIN_GBPS_V4"
						family_arg="4"
					else
						target="$V6_TEST_TARGET"
						min_gbps="$MIN_GBPS_V6"
						family_arg="6"
					fi
					printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
						"$cos_state" "$family" "$direction" "$family_arg" "$target" "$min_gbps" "$port"
				done
			done
		done
		;;
	fast)
		for family in ipv4 ipv6; do
			if [[ "$family" == "ipv4" ]]; then
				target="$V4_TEST_TARGET"
				min_gbps="$MIN_GBPS_V4"
				family_arg="4"
			else
				target="$V6_TEST_TARGET"
				min_gbps="$MIN_GBPS_V6"
				family_arg="6"
			fi
			printf 'current-cos\t%s\tpush\t%s\t%s\t%s\t%s\n' \
				"$family" "$family_arg" "$target" "$min_gbps" "$FAST_IPERF_PORT"
		done
		;;
	*) die "unknown smoke mode: ${mode}" ;;
	esac
}

cell_label() {
	local cos_state="$1" family="$2" direction="$3"
	if [[ "$cos_state" == "current-cos" ]]; then
		printf 'fast-current-cos-%s-%s\n' "$family" "$direction"
	else
		printf '%s-%s-%s\n' "$cos_state" "$family" "$direction"
	fi
}

cos_config_active() {
	local output
	if ! output="$(run_fw0 'cli -c "show class-of-service interface"')"; then
		die "failed to query class-of-service interface state before smoke matrix"
	fi
	grep -iqE 'shaper|scheduler|traffic-control-profile|output.*traffic' <<<"$output"
}

ensure_cos_off_for_matrix() {
	if (( COS_OFF_MATRIX_PRECHECKED == 1 )); then
		return 0
	fi
	if (( DRY_RUN_MATRIX == 1 )); then
		printf 'cos-off precheck: dry-run\n' | tee -a "$summary_file"
		COS_OFF_MATRIX_PRECHECKED=1
		return 0
	fi
	info "verifying CoS-off baseline before smoke matrix"
	if cos_config_active; then
		die "smoke matrix CoS-off cells require no active CoS fixture; redeploy" \
			"the userspace cluster or pass --deploy before collecting matrix evidence"
	fi
	printf 'cos-off precheck: ok\n' | tee -a "$summary_file"
	COS_OFF_MATRIX_PRECHECKED=1
}

apply_symmetric_cos_config() {
	local cmd
	if (( DRY_RUN_MATRIX == 1 )); then
		printf 'cos-on apply: dry-run symmetric fixture on %s\n' "$FW0" | tee -a "$summary_file"
		return 0
	fi
	info "applying symmetric CoS fixture before CoS-on smoke cells"
	printf -v cmd '%q ' "${PROJECT_ROOT}/test/incus/apply-cos-config.sh" --symmetric "$FW0"
	sg incus-admin -c "$cmd"
	printf 'cos-on apply: symmetric fixture on %s\n' "$FW0" | tee -a "$summary_file"
}

print_smoke_matrix_plan() {
	local cos_state family direction family_arg target min_gbps port label cos_label
	while IFS=$'\t' read -r cos_state family direction family_arg target min_gbps port; do
		label="$(cell_label "$cos_state" "$family" "$direction")"
		cos_label="${cos_state#cos-}"
		printf 'matrix plan: %s cos=%s family=%s direction=%s target=%s port=%s min_gbps=%s\n' \
			"$label" "$cos_label" "$family" "$direction" "$target" "$port" "$min_gbps"
	done < <(matrix_cell_specs "$SMOKE_MODE")
}

warm_up_cell() {
	local label="$1" target="$2" family="$3" direction="$4" port="$5"
	local json="/tmp/${label}-warmup.json"
	local metrics
	if (( DRY_RUN_MATRIX == 1 )); then
		printf '%s warmup: dry-run direction=%s port=%s\n' "$label" "$direction" "$port" |
			tee -a "$summary_file"
		return 0
	fi
	info "warming up ${label} ${direction} path on iperf port ${port}"
	run_iperf_json "$family" "$target" "$json" "$direction" "$port"
	metrics="$(iperf_metrics "$json")"
	if [[ "$metrics" == ERROR:* ]]; then
		die "${label} warm-up iperf failed: ${metrics#ERROR:}"
	fi
}

validate_cell() {
	local label="$1" target="$2" family="$3" direction="$4" min_gbps="$5" port="$6"
	local i json gbps metrics metrics_line
	for i in $(seq 1 "$RUNS"); do
		if (( DRY_RUN_MATRIX == 1 )); then
			if [[ "$DRY_RUN_FAIL_CELL" == "$label" ]]; then
				die "dry-run injected failure for ${label}"
			fi
			printf '%s run %s: dry-run direction=%s port=%s min=%s Gbps\n' \
				"$label" "$i" "$direction" "$port" "$min_gbps" | tee -a "$summary_file"
			continue
		fi
		local attempt=1
		while true; do
			json="/tmp/${label}-${i}.json"
			info "running ${label} ${direction} iperf port ${port} iteration ${i}/${RUNS}"
			run_iperf_json "$family" "$target" "$json" "$direction" "$port"
			metrics="$(iperf_metrics "$json")"
			if [[ "$metrics" == ERROR:* ]]; then
				die "${label} iperf failed: ${metrics#ERROR:}"
			fi
			gbps="$(parse_gbps "$metrics")"
			metrics_line="$(format_metrics_line "$metrics")"
			validate_sustained_iperf "$label" "$i" "$metrics"
			if python3 - <<'PY' "$gbps" "$min_gbps" "$MARGINAL_GBPS_EPSILON"
import sys
actual = float(sys.argv[1])
minimum = float(sys.argv[2])
epsilon = float(sys.argv[3])
sys.exit(0 if actual + epsilon >= minimum else 1)
PY
			then
				printf '%s run %s: %s Gbps %s\n' "$label" "$i" "$gbps" "$metrics_line" | tee -a "$summary_file"
				if python3 - <<'PY' "$gbps" "$min_gbps"
import sys
actual = float(sys.argv[1])
minimum = float(sys.argv[2])
sys.exit(0 if actual >= minimum else 1)
PY
				then
					break
				fi
				if (( attempt == 1 )); then
					info "${label} iteration ${i} was marginal (${gbps} Gbps); rerunning once"
					attempt=2
					continue
				fi
				break
			fi
			printf '%s run %s: %s Gbps %s\n' "$label" "$i" "$gbps" "$metrics_line" | tee -a "$summary_file"
			validate_threshold "$gbps" "$min_gbps" "$label" "$i"
		done
	done
}

run_performance_profile() {
	local mode="$1"
	local cos_state family direction family_arg target min_gbps port label current_cos_state=""
	local expected=0 completed=0
	local complete_label="smoke matrix complete"

	printf 'smoke mode: %s\n' "$mode" | tee -a "$summary_file"
	if [[ "$mode" == "fast" ]]; then
		printf 'smoke matrix: fast mode runs current-CoS IPv4/IPv6 push only\n' |
			tee -a "$summary_file"
		complete_label="smoke fast complete"
	else
		ensure_cos_off_for_matrix
	fi

	while IFS=$'\t' read -r cos_state family direction family_arg target min_gbps port; do
		if [[ "$cos_state" == "cos-on" && "$current_cos_state" != "cos-on" ]]; then
			apply_symmetric_cos_config
			current_cos_state="cos-on"
		elif [[ "$cos_state" == "cos-off" && "$current_cos_state" != "cos-off" ]]; then
			current_cos_state="cos-off"
		fi
		label="$(cell_label "$cos_state" "$family" "$direction")"
		expected=$((expected + 1))
		printf 'smoke cell start: %s\n' "$label" | tee -a "$summary_file"
		warm_up_cell "$label" "$target" "$family_arg" "$direction" "$port"
		validate_cell "$label" "$target" "$family_arg" "$direction" "$min_gbps" "$port"
		completed=$((completed + 1))
		printf 'smoke cell pass: %s\n' "$label" | tee -a "$summary_file"
	done < <(matrix_cell_specs "$mode")

	printf '%s: %s/%s cells passed\n' "$complete_label" "$completed" "$expected" |
		tee -a "$summary_file"
}

run_perf_pair() {
	local label="$1" target="$2" family="$3" direction="${4:-push}"
	local perf_data="/tmp/${label}.data"
	local perf_report="/tmp/${label}.report"
	local iperf_json="/tmp/${label}.json"
	local perf_pid perf_status=0

	info "profiling ${label}"
	sg incus-admin -c "incus exec ${ACTIVE_FW} -- bash -lc $(printf %q "rm -f ${perf_data} ${perf_report}; perf record -a -g -F 997 -o ${perf_data} -- sleep $((DURATION + 2))")" &
	perf_pid=$!
	sleep 1
	run_iperf_json "$family" "$target" "$iperf_json" "$direction" "$PERF_IPERF_PORT"
	wait "$perf_pid" || perf_status=$?
	if (( perf_status != 0 )); then
		die "perf record for ${label} exited with status ${perf_status}"
	fi
	run_active_fw "perf report --stdio -i ${perf_data} --sort symbol | sed -n '1,80p' > ${perf_report}"
}

normalize_smoke_mode
validate_iperf_ports
default_iperf_timeout
validate_iperf_runtime_knobs

summary_file="$(mktemp)"
COS_OFF_MATRIX_PRECHECKED=0
cleanup() { rm -f "$summary_file"; }
trap cleanup EXIT

if (( DRY_RUN_MATRIX == 1 )); then
	info "dry-running userspace HA validation smoke matrix"
	print_smoke_matrix_plan
	printf 'iperf runtime: runs=%s duration=%s parallel=%s timeout=%s\n' \
		"$RUNS" "$DURATION" "$PARALLEL" "$IPERF_TIMEOUT" |
		tee -a "$summary_file"
	if (( WITH_PERF == 1 )) && [[ "$SMOKE_MODE" == "matrix" ]]; then
		ensure_cos_off_for_matrix
		printf 'perf order: before smoke matrix to keep CoS-off baseline clean\n' |
			tee -a "$summary_file"
	fi
	run_performance_profile "$SMOKE_MODE"
	info "dry-run validation summary"
	cat "$summary_file"
	exit 0
fi

if [[ $DEPLOY -eq 1 ]]; then
	info "deploying isolated userspace cluster from ${ENV_FILE}"
	BPFRX_CLUSTER_ENV="$ENV_FILE" "${PROJECT_ROOT}/test/incus/cluster-setup.sh" deploy all
fi

info "waiting for xpfd gRPC/CLI readiness"
wait_for_vm_cli "$FW0" || die "fw0 xpfd did not become reachable in time"
wait_for_vm_cli "$FW1" || die "fw1 xpfd did not become reachable in time"

info "detecting userspace runtime mode"
MODE="$(runtime_mode)" || die "userspace runtime mode did not settle in time"
info "runtime mode: ${MODE}"
if [[ "${MODE}" == "legacy" ]]; then
	if [[ "${ALLOW_LEGACY_EBPF_HA_VALIDATION}" == "1" ]]; then
		info "legacy eBPF fallback accepted by ALLOW_LEGACY_EBPF_HA_VALIDATION=1"
		ACTIVE_FW="$(active_owner_vm)" ||
			die "legacy fallback override requires an unambiguous active firewall owner"
		info "active legacy fallback firewall: ${ACTIVE_FW}"
	else
		die "legacy eBPF fallback detected; userspace HA validation requires" \
			"xdp_userspace_prog; set ALLOW_LEGACY_EBPF_HA_VALIDATION=1" \
			"only for legacy regression runs"
	fi
else
	info "supported userspace runtime detected"
	ensure_preferred_active_node
	arm_supported_runtime
fi

info "ensuring IPv6 default route via router advertisement"
wait_for_ipv6_default_route || die "cluster userspace host still has no IPv6 default route after repeated RA solicitation"

ensure_dualstack_wan_neighbors "$ACTIVE_FW"

info "basic reachability checks"
# LC_ALL=C pins ping's summary wording so the shared reply-count predicate
# is locale-independent; command status and output are both preserved for
# the evidence-aware PASS/FAIL/VOID decision.
assert_forwarding_route 4 "ipv4 forwarding" "${V4_TEST_TARGET}"
assert_forwarding_route 6 "ipv6 forwarding" "${V6_TEST_TARGET}"
run_controlled_ping 4 "${V4_TEST_TARGET}" "/tmp/userspace-ping-v4.out"
PING_V4_STATUS="$CONTROLLED_PING_STATUS"
run_controlled_ping 6 "${V6_TEST_TARGET}" "/tmp/userspace-ping-v6.out"
PING_V6_STATUS="$CONTROLLED_PING_STATUS"
validate_reachability "ipv4 forwarding" "/tmp/userspace-ping-v4.out" "$PING_V4_STATUS"
validate_reachability "ipv6 forwarding" "/tmp/userspace-ping-v6.out" "$PING_V6_STATUS"

validate_traceroute_visibility

if [[ $WITH_PERF -eq 1 && "$SMOKE_MODE" == "matrix" ]]; then
	ensure_cos_off_for_matrix
	info "capturing perf baseline before smoke matrix applies CoS"
	run_perf_pair perf-userspace-ipv4 "${V4_TEST_TARGET}" 4
	run_perf_pair perf-userspace-ipv6 "${V6_TEST_TARGET}" 6
fi

run_performance_profile "$SMOKE_MODE"

if [[ $WITH_PERF -eq 1 && "$SMOKE_MODE" != "matrix" ]]; then
	run_perf_pair perf-userspace-ipv4 "${V4_TEST_TARGET}" 4
	run_perf_pair perf-userspace-ipv6 "${V6_TEST_TARGET}" 6
fi

info "validation summary"
printf 'active fw: %s\n' "${ACTIVE_FW}" | tee -a "$summary_file"
cat "$summary_file"
if [[ $WITH_PERF -eq 1 ]]; then
	info "perf artifacts on ${ACTIVE_FW}: /tmp/perf-userspace-ipv4.{data,report} /tmp/perf-userspace-ipv6.{data,report}"
fi
