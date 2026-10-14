#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
ENV_FILE="${BPFRX_CLUSTER_ENV:-${PROJECT_ROOT}/test/incus/loss-userspace-cluster.env}"

IPERF_DURATION=8
IPERF_PARALLEL=4
PERF_SECONDS=$((IPERF_DURATION + 4))
OUTPUT_DIR="/tmp/userspace-perf-compare"
IPERF_METRICS="${PROJECT_ROOT}/scripts/iperf-json-metrics.py"

while [[ $# -gt 0 ]]; do
	case "$1" in
	--env)
		ENV_FILE="$2"
		shift
		;;
	--duration)
		IPERF_DURATION="$2"
		PERF_SECONDS=$((IPERF_DURATION + 4))
		shift
		;;
	--parallel)
		IPERF_PARALLEL="$2"
		shift
		;;
	*)
		echo "unknown arg: $1" >&2
		exit 2
		;;
	esac
	shift
done

if [[ ! -f "${ENV_FILE}" ]]; then
	echo "missing env file: ${ENV_FILE}" >&2
	exit 1
fi

# shellcheck disable=SC1090
source "${ENV_FILE}"
# #13070 (D10-15): the incus CLI wrapper comes from the shared CoS
# schedule + wrapper library (test/incus/cos-apply-lib.sh) instead of a
# script-local copy.
# shellcheck source=test/incus/cos-apply-lib.sh
source "${PROJECT_ROOT}/test/incus/cos-apply-lib.sh"

FW0="${INCUS_REMOTE}:${VM0}"
FW1="${INCUS_REMOTE}:${VM1}"
HOST="${INCUS_REMOTE}:${LAN_HOST}"
V4_TARGET="172.16.80.200"
V6_TARGET="2001:559:8585:80::200"

mkdir -p "${OUTPUT_DIR}"

# #13070 (D10-15): delegates to the shared wrapper; INCUS_FORCE_SG keeps
# this script's always-through-sg operator contract exactly as before.
run_incus() {
	local vm="$1"
	local cmd="$2"
	INCUS_FORCE_SG=1 incus_exec_shell "$vm" "$cmd"
}

wait_cli() {
	local vm="$1"
	for _ in $(seq 1 60); do
		if run_incus "${vm}" "cli -c 'show chassis cluster data-plane statistics' >/dev/null 2>&1"; then
			return 0
		fi
		sleep 1
	done
	echo "cli not ready on ${vm}" >&2
	return 1
}

stats_file() {
	local vm="$1"
	local out="$2"
	run_incus "${vm}" "cli -c 'show chassis cluster data-plane statistics'" >"${out}"
}

# Deliberately NOT the lib's detect_active_primary (#13070 / D10-15): that
# one answers "who holds RG0" with a tolerant fallback. THIS detector
# answers "whose data plane is forwarding" and always picks a node (fw1 as
# the last resort) so the comparison always runs — a hard fail here would
# abort a diagnostic, not gate a qualification.
detect_active_fw() {
	local fw0_stats fw1_stats
	fw0_stats="${OUTPUT_DIR}/fw0.stats.txt"
	fw1_stats="${OUTPUT_DIR}/fw1.stats.txt"
	stats_file "${FW0}" "${fw0_stats}"
	stats_file "${FW1}" "${fw1_stats}"

	if grep -q 'Forwarding armed:[[:space:]]*true' "${fw0_stats}" && grep -Eq 'rg(1|2) active=true' "${fw0_stats}"; then
		echo "${FW0}"
	elif grep -q 'Forwarding armed:[[:space:]]*true' "${fw1_stats}" && grep -Eq 'rg(1|2) active=true' "${fw1_stats}"; then
		echo "${FW1}"
	elif grep -Eq 'rg(1|2) active=true' "${fw0_stats}"; then
		echo "${FW0}"
	else
		echo "${FW1}"
	fi

}

ensure_ipv6_route() {
	run_incus "${HOST}" "sysctl -q net.ipv6.conf.eth0.accept_ra=2; ip -6 route | grep -q '^default ' || (command -v rdisc6 >/dev/null 2>&1 && rdisc6 -1 eth0 >/dev/null 2>&1 || true)"
}

reachability_check() {
	local family="$1"
	local target="$2"
	local out="${OUTPUT_DIR}/${family}-reachability.txt"
	if [[ "${family}" == "ipv4" ]]; then
		run_incus "${HOST}" "ping -c 2 -W 1 ${target}" >"${out}" 2>&1 || true
	else
		run_incus "${HOST}" "ping -6 -c 2 -W 1 ${target}" >"${out}" 2>&1 || true
	fi
}

run_case() {
	local family="$1"
	local target="$2"
	local fw="$3"
	local iperf_json="${OUTPUT_DIR}/${family}.json"
	local iperf_err="${OUTPUT_DIR}/${family}.err"
	local perf_data="/tmp/${family}-userspace-perf.data"
	local perf_report="${OUTPUT_DIR}/${family}.perf.txt"
	local perf_log="${OUTPUT_DIR}/${family}.perf.log"

	run_incus "${fw}" "rm -f ${perf_data}"
	INCUS_FORCE_SG=1 incus_exec "${fw}" sh -lc "timeout ${PERF_SECONDS} perf record -F 997 -a -g -o ${perf_data} -- sleep ${PERF_SECONDS}" \
		>"${perf_log}" 2>&1 &
	local perf_pid=$!
	sleep 1

	if [[ "${family}" == "ipv4" ]]; then
		run_incus "${HOST}" "timeout $((IPERF_DURATION + 8)) iperf3 -J -c ${target} -P ${IPERF_PARALLEL} -t ${IPERF_DURATION}" >"${iperf_json}" 2>"${iperf_err}" || true
	else
		run_incus "${HOST}" "timeout $((IPERF_DURATION + 8)) iperf3 -J -6 -c ${target} -P ${IPERF_PARALLEL} -t ${IPERF_DURATION}" >"${iperf_json}" 2>"${iperf_err}" || true
	fi

	wait "${perf_pid}" || true
	run_incus "${fw}" "perf report --stdio --no-children -i ${perf_data} --sort dso,symbol | sed -n '1,160p'" >"${perf_report}" 2>>"${perf_log}" || true
}

json_field() {
	local file="$1"
	local expr="$2"
	python3 - "$file" "$expr" <<'PY'
import json
import sys
path, expr = sys.argv[1], sys.argv[2]
try:
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
except Exception:
    print("")
    raise SystemExit(0)
cur = data
for part in expr.split("."):
    if not part:
        continue
    if isinstance(cur, dict):
        cur = cur.get(part)
    else:
        cur = None
        break
if cur is None:
    print("")
elif isinstance(cur, (int, float, str)):
    print(cur)
else:
    print(json.dumps(cur))
PY
}

iperf_metrics() {
	local path="$1"
	if [[ ! -s "${path}" ]]; then
		echo ""
		return 0
	fi
	python3 "${IPERF_METRICS}" "${path}" 2>/dev/null || true
}

top_symbols() {
	local report="$1"
	grep -E 'xpf-userspace-dp|mlx5e_xsk|bpf_prog_|xsk_|htab_map_hash|lookup_nulls_elem_raw' "${report}" | head -n 12 || true
}

write_summary() {
	local fw="$1"
	local out="${OUTPUT_DIR}/summary.md"
	local v4_bps v6_bps v4_err v6_err v4_metrics v6_metrics
	v4_bps="$(json_field "${OUTPUT_DIR}/ipv4.json" "end.sum_sent.bits_per_second")"
	v6_bps="$(json_field "${OUTPUT_DIR}/ipv6.json" "end.sum_sent.bits_per_second")"
	v4_err="$(json_field "${OUTPUT_DIR}/ipv4.json" "error")"
	v6_err="$(json_field "${OUTPUT_DIR}/ipv6.json" "error")"
	v4_metrics="$(iperf_metrics "${OUTPUT_DIR}/ipv4.json")"
	v6_metrics="$(iperf_metrics "${OUTPUT_DIR}/ipv6.json")"

	{
		echo "# Userspace Perf Compare"
		echo
		echo "- Active firewall: \`${fw}\`"
		echo "- Host: \`${HOST}\`"
		echo "- IPv4 target: \`${V4_TARGET}\`"
		echo "- IPv6 target: \`${V6_TARGET}\`"
		echo "- Duration: \`${IPERF_DURATION}s\`"
		echo "- Parallel streams: \`${IPERF_PARALLEL}\`"
		echo
		echo "## Reachability"
		echo
		echo "### IPv4"
		echo '```text'
		sed -n '1,80p' "${OUTPUT_DIR}/ipv4-reachability.txt"
		echo '```'
		echo
		echo "### IPv6"
		echo '```text'
		sed -n '1,80p' "${OUTPUT_DIR}/ipv6-reachability.txt"
		echo '```'
		echo
		echo "## iperf3"
		echo
		echo "- IPv4 bps: \`${v4_bps:-0}\`"
		if [[ -n "${v4_err}" ]]; then
			echo "- IPv4 error: \`${v4_err}\`"
		fi
		if [[ -n "${v4_metrics}" ]]; then
			echo "- IPv4 sustain: \`$(python3 - <<'PY' "$v4_metrics"
import json, sys
m = json.loads(sys.argv[1])
status = "collapse" if m.get("collapse_detected") else "steady"
print(f"{status}; peak={m['peak_gbps']:.3f} tail={m['tail_median_gbps']:.3f} ratio={m['tail_peak_ratio']:.3f}")
PY
)\`"
			echo "- IPv4 intervals: \`$(python3 - <<'PY' "$v4_metrics"
import json, sys
m = json.loads(sys.argv[1])
print(",".join(f"{v:.2f}" for v in m.get("interval_gbps", [])))
PY
)\`"
		fi
		echo "- IPv6 bps: \`${v6_bps:-0}\`"
		if [[ -n "${v6_err}" ]]; then
			echo "- IPv6 error: \`${v6_err}\`"
		fi
		if [[ -n "${v6_metrics}" ]]; then
			echo "- IPv6 sustain: \`$(python3 - <<'PY' "$v6_metrics"
import json, sys
m = json.loads(sys.argv[1])
status = "collapse" if m.get("collapse_detected") else "steady"
print(f"{status}; peak={m['peak_gbps']:.3f} tail={m['tail_median_gbps']:.3f} ratio={m['tail_peak_ratio']:.3f}")
PY
)\`"
			echo "- IPv6 intervals: \`$(python3 - <<'PY' "$v6_metrics"
import json, sys
m = json.loads(sys.argv[1])
print(",".join(f"{v:.2f}" for v in m.get("interval_gbps", [])))
PY
)\`"
		fi
		echo
		echo "## Perf Hot Symbols"
		echo
		echo "### IPv4"
		echo '```text'
		top_symbols "${OUTPUT_DIR}/ipv4.perf.txt"
		echo '```'
		echo
		echo "### IPv6"
		echo '```text'
		top_symbols "${OUTPUT_DIR}/ipv6.perf.txt"
		echo '```'
		echo
		echo "## Helper State At Capture"
		echo
		echo "### fw0"
		echo '```text'
		sed -n '1,120p' "${OUTPUT_DIR}/fw0.stats.txt"
		echo '```'
		echo
		echo "### fw1"
		echo '```text'
		sed -n '1,120p' "${OUTPUT_DIR}/fw1.stats.txt"
		echo '```'
		echo
		echo "## Raw Artifacts"
		echo
		echo "- ${OUTPUT_DIR}/ipv4.json"
		echo "- ${OUTPUT_DIR}/ipv4.err"
		echo "- ${OUTPUT_DIR}/ipv4.perf.txt"
		echo "- ${OUTPUT_DIR}/ipv6.json"
		echo "- ${OUTPUT_DIR}/ipv6.err"
		echo "- ${OUTPUT_DIR}/ipv6.perf.txt"
	} >"${out}"
}

wait_cli "${FW0}"
wait_cli "${FW1}"
ensure_ipv6_route
ACTIVE_FW="$(detect_active_fw)"

reachability_check ipv4 "${V4_TARGET}"
reachability_check ipv6 "${V6_TARGET}"
run_case ipv4 "${V4_TARGET}" "${ACTIVE_FW}"
run_case ipv6 "${V6_TARGET}" "${ACTIVE_FW}"
write_summary "${ACTIVE_FW}"

echo "summary: ${OUTPUT_DIR}/summary.md"
sed -n '1,220p' "${OUTPUT_DIR}/summary.md"
