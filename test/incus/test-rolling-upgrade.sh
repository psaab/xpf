#!/usr/bin/env bash
# Traffic-carrying, version-asserting two-cut upgrade gate (#12200).
set -euo pipefail

_CELL_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=cluster-cell.sh
source "${_CELL_DIR}/cluster-cell.sh"
xpf_enter_destructive_cluster_cell "test-rolling-upgrade $*" "$0" "$@"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
# shellcheck source=test/incus/cluster-env.sh
source "${SCRIPT_DIR}/cluster-env.sh"
# shellcheck source=test/incus/failover-client-lib.sh
source "${SCRIPT_DIR}/failover-client-lib.sh"
# shellcheck source=test/incus/iperf-throughput-lib.sh
source "${SCRIPT_DIR}/iperf-throughput-lib.sh"
# shellcheck source=test/incus/deploy-lib.sh
source "${SCRIPT_DIR}/deploy-lib.sh"

IPERF_TARGET="${IPERF_TARGET:-$IPERF_TARGET4}"
IPERF_PORT="${IPERF_PORT:-5211}"
IPERF_STREAMS="${IPERF_STREAMS:-8}"
ROLLING_IPERF_DURATION="${ROLLING_IPERF_DURATION:-180}"
ROLLING_IPERF_INTERVAL="0.1"
MIN_THROUGHPUT_GBPS="0.001"

PASS=0
FAIL=0
VOID=0
ERRORS=()
TMP_BASE="${TMPDIR:-/tmp}/xpf-rolling-upgrade-12200.$$"
REMOTE_DIR="/tmp/xpf-rolling-upgrade-12200-$$"
REMOTE_LOG="${REMOTE_DIR}/iperf.jsonl"
REMOTE_PID="${REMOTE_DIR}/iperf.pid"
LOCAL_LOG="${TMP_BASE}.iperf.jsonl"
CUT_TRACE="${TMP_BASE}.cuts.log"
VERSION_SAMPLES="${TMP_BASE}.versions.log"
DEPLOY_LOG="${TMP_BASE}.deploy.log"
SAMPLER_STOP="${TMP_BASE}.sampler.stop"
SAMPLER_PID=""
CLIENT_STARTED=false
REMOTE_DIR_CREATED=false

info()  { printf '==> %s\n' "$*"; }
pass()  { printf '  PASS  %s\n' "$*"; PASS=$((PASS + 1)); }
fail()  { printf '  FAIL  %s\n' "$*"; FAIL=$((FAIL + 1)); ERRORS+=("$*"); }
void()  { printf '  VOID  %s\n' "$*"; VOID=$((VOID + 1)); }
die()   { printf 'FATAL: %s\n' "$*" >&2; exit 2; }

stop_sampler() {
	if [[ -n "$SAMPLER_PID" ]]; then
		touch "$SAMPLER_STOP" 2>/dev/null || true
		wait "$SAMPLER_PID" 2>/dev/null || true
		SAMPLER_PID=""
	fi
}
cleanup() {
	stop_sampler
	if [[ "$CLIENT_STARTED" == true ]]; then
		failover_stop_main_iperf "$REMOTE_PID" "$IPERF_TARGET" "$IPERF_PORT" "$IPERF_STREAMS" || true
	fi
	if [[ "$REMOTE_DIR_CREATED" == true ]]; then
		incus exec "$CLUSTER_LAN_HOST" -- rm -rf "$REMOTE_DIR" &>/dev/null || true
	fi
	rm -f "${TMP_BASE}".* "$SAMPLER_STOP"
}
trap cleanup EXIT

finish() {
	echo "Rolling upgrade: $PASS passed, $FAIL failed"
	if (( FAIL > 0 )); then
		printf 'Failures:\n'
		printf '  - %s\n' "${ERRORS[@]}"
		exit 1
	fi
	if (( VOID > 0 )); then
		exit 77
	fi
	exit 0
}

throughput_verdict() {
	local avg_gbps="$1" note="$2" line
	line=$(iperf_throughput_json_verdict "$MIN_THROUGHPUT_GBPS" "$avg_gbps" "$note")
	case "$line" in
		PASS\ *) pass "${line#PASS }" ;;
		FAIL\ *) fail "${line#FAIL }" ;;
		*) fail "iperf3 throughput oracle returned an unrecognised verdict: $line" ;;
	esac
}

if [[ $# -ne 0 ]]; then
	die "test-rolling-upgrade.sh accepts no arguments"
fi
if [[ ! "$ROLLING_IPERF_DURATION" =~ ^[0-9]+$ ]] || (( ROLLING_IPERF_DURATION < 60 || ROLLING_IPERF_DURATION > 600 )); then
	die "ROLLING_IPERF_DURATION must be an integer from 60 through 600 seconds"
fi

for instance in "$FW0" "$FW1" "$CLUSTER_LAN_HOST"; do
	incus info "$instance" &>/dev/null 2>&1 || { void "$instance is unavailable"; finish; }
done

# The Makefile's `deb` prerequisite builds before this script acquires the
# cluster lock. Attest the package contents directly; never substitute a
# source-tree hash or an installed-path hash for the candidate process image.
deb=$(ls -t "$PROJECT_ROOT"/dist-deb/xpf_*.deb 2>/dev/null | head -1 || true)
[[ -n "$deb" ]] || { void "no runtime .deb in dist-deb; make deb must complete first"; finish; }
candidate_sha=$(deploy_manifest_sha_from_deb "$deb" xpfd || true)
[[ -n "$candidate_sha" ]] || { void "cannot read xpfd from candidate .deb: $deb"; finish; }
old0=$(deploy_running_xpfd_sha256 "$FW0" 1 || true)
old1=$(deploy_running_xpfd_sha256 "$FW1" 1 || true)
[[ "$old0" =~ ^[0-9a-f]{64}$ && "$old1" =~ ^[0-9a-f]{64}$ ]] || {
	void "cannot read both pre-cut running xpfd process identities"
	finish
}

# A candidate whose running-exe SHA is already present is an effective no-op
# for version assertion. Refuse before mutating the shared cluster.
if [[ "$old0" == "$candidate_sha" || "$old1" == "$candidate_sha" ]]; then
	fail "no-op drain: candidate .deb xpfd SHA already runs on node(s) whose version did not change"
	fail "CUT 1 not run: candidate build is not a version step"
	fail "CUT 2 not run: candidate build is not a version step"
	finish
fi

case "$IPERF_STREAMS" in ''|*[!0-9]*) die "IPERF_STREAMS must be a positive integer" ;; esac
(( IPERF_STREAMS > 1 )) || die "rolling-upgrade client must use multiple streams"

info "Starting tracked iperf3 client: -P${IPERF_STREAMS} -i${ROLLING_IPERF_INTERVAL} -t${ROLLING_IPERF_DURATION} → ${IPERF_TARGET}:${IPERF_PORT}"
incus exec "$CLUSTER_LAN_HOST" -- mkdir -m 700 -p "$REMOTE_DIR" || { void "cannot prepare client evidence directory"; finish; }
REMOTE_DIR_CREATED=true
client_started_at=$(date +%s.%N)
if ! failover_start_main_iperf "$ROLLING_IPERF_DURATION" "$IPERF_TARGET" "$IPERF_PORT" \
	"$IPERF_STREAMS" "$REMOTE_LOG" "$REMOTE_PID" "$ROLLING_IPERF_INTERVAL"; then
	void "cannot start tracked iperf3 client"
	finish
fi
CLIENT_STARTED=true
client_running=false
for _ in {1..30}; do
	if failover_main_iperf_running "$REMOTE_PID" "$IPERF_TARGET" "$IPERF_PORT" "$IPERF_STREAMS"; then
		client_running=true
		break
	fi
	sleep 0.1
done
[[ "$client_running" == true ]] || { void "tracked iperf3 client did not become live"; finish; }

# Seed the sample stream with the exact pre-cut running images; subsequent
# samples use the same authoritative /proc/<MainPID>/exe readback helper.
printf '%s %s %s\n' "$(date +%s.%N)" "$old0" "$old1" >"$VERSION_SAMPLES"
sample_versions() {
	local now sha0 sha1
	while [[ ! -e "$SAMPLER_STOP" ]]; do
		now=$(date +%s.%N)
		sha0=$(deploy_running_xpfd_sha256 "$FW0" 1 || printf '-')
		sha1=$(deploy_running_xpfd_sha256 "$FW1" 1 || printf '-')
		printf '%s %s %s\n' "$now" "$sha0" "$sha1" >>"$VERSION_SAMPLES"
		sleep 0.1
	done
}
sample_versions &
SAMPLER_PID=$!

info "Deploying the candidate .deb through the real secondary-first rolling path"
deploy_rc=0
env -u XPF_DEPLOY_FAST XPF_CLUSTER_SKIP_BUILD=1 XPF_ROLLING_UPGRADE_TRACE="$CUT_TRACE" \
	"${SCRIPT_DIR}/cluster-setup.sh" deploy all >"$DEPLOY_LOG" 2>&1 || deploy_rc=$?
stop_sampler
# Record an authoritative final sample after both deploy cuts have returned.
new0=$(deploy_running_xpfd_sha256 "$FW0" 1 || printf '-')
new1=$(deploy_running_xpfd_sha256 "$FW1" 1 || printf '-')
printf '%s %s %s\n' "$(date +%s.%N)" "$new0" "$new1" >>"$VERSION_SAMPLES"
if (( deploy_rc != 0 )); then
	fail "cluster-setup deploy all exited $deploy_rc"
	while IFS= read -r line; do printf '  %s\n' "$line"; done <"$DEPLOY_LOG"
	finish
fi

if ! failover_wait_main_iperf_result "$REMOTE_LOG" "$ROLLING_IPERF_DURATION"; then
	info "iperf3 did not emit a normal completion event; analyzing all captured cut evidence fail-closed"
fi
if ! incus exec "$CLUSTER_LAN_HOST" -- cat "$REMOTE_LOG" >"$LOCAL_LOG" 2>/dev/null; then
	void "cannot collect tracked iperf3 JSON-stream evidence"
	finish
fi

oracle_rc=0
oracle_output=$(python3 "${PROJECT_ROOT}/scripts/rolling_upgrade_oracle.py" \
	--evidence "$LOCAL_LOG" --cuts "$CUT_TRACE" --samples "$VERSION_SAMPLES" \
	--started-at "$client_started_at" --expected-version "$candidate_sha" \
	--streams "$IPERF_STREAMS" --max-interval-sec 0.25 2>&1) || oracle_rc=$?
if (( oracle_rc == 2 )); then
	void "rolling-upgrade evidence unusable: ${oracle_output//$'\n'/; }"
elif (( oracle_rc == 1 )); then
	while IFS= read -r line; do
		case "$line" in
			*" PASS "*) pass "${line#* PASS }" ;;
			*" FAIL "*) fail "${line#* FAIL }" ;;
			*) fail "rolling-upgrade oracle emitted an invalid verdict: $line" ;;
		esac
	done <<<"$oracle_output"
elif (( oracle_rc == 0 )); then
	while IFS= read -r line; do
		case "$line" in
			*" PASS "*) pass "${line#* PASS }" ;;
			*) fail "rolling-upgrade oracle emitted an invalid verdict: $line" ;;
		esac
	done <<<"$oracle_output"
else
	void "rolling-upgrade oracle exited $oracle_rc: ${oracle_output//$'\n'/; }"
fi

metrics_file="${TMP_BASE}.metrics.json"
metrics_error="${TMP_BASE}.metrics.err"
if python3 "${PROJECT_ROOT}/scripts/iperf-json-metrics.py" "$LOCAL_LOG" >"$metrics_file" 2>"$metrics_error"; then
	avg_gbps=$(python3 - "$metrics_file" <<'PY'
import json, math, sys
try:
    data = json.load(open(sys.argv[1], encoding="utf-8"))
    value = data.get("avg_gbps")
    if data.get("completed") is True and isinstance(value, (int, float)) and math.isfinite(value):
        print(value)
    else:
        raise ValueError("incomplete or missing aggregate throughput")
except (OSError, ValueError, TypeError, json.JSONDecodeError) as exc:
    print(f"invalid:{exc}")
PY
)
	if [[ "$avg_gbps" =~ ^[0-9]+([.][0-9]+)?$ ]]; then
		throughput_verdict "$avg_gbps" "completed tracked multi-stream run"
	else
		void "iperf3 aggregate throughput is unavailable: ${avg_gbps#invalid:}"
	fi
else
	void "iperf3 metrics could not be parsed: ${metrics_error:-no diagnostic}"
fi

finish
