#!/usr/bin/env bash
#
# #6897 — self-test for test/incus/iperf-throughput-lib.sh.
#
# The defect this guards is a MISSING CELL, not a wrong number, so the
# load-bearing assertion is TOTALITY: every input class must yield exactly
# one verdict. A test that only checked the arithmetic would have passed
# against the buggy version, because the buggy version's arithmetic was fine
# for the one unit it recognised.
#
# Hermetic — sources the lib and feeds it literal [SUM] lines. No incus,
# cluster, network, or iperf3.
#
# Usage: ./test/incus/iperf-throughput-selftest.sh   (rc 0 = all pass)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB="${SCRIPT_DIR}/iperf-throughput-lib.sh"
[[ -f "$LIB" ]] || { echo "FAIL: lib not found at $LIB" >&2; exit 1; }
# shellcheck source=/dev/null
source "$LIB"

PASS=0
ok()   { PASS=$((PASS + 1)); echo "PASS ($PASS): $*"; }
bad()  { echo "FAIL: $*" >&2; exit 1; }

SELFTEST_HARNESS="${1:-}"
if [[ $# -gt 1 ]]; then bad "usage: $0 [test-double-failover.sh|test-chained-crash.sh|test-active-active.sh]"; fi
case "$SELFTEST_HARNESS" in
	""|test-double-failover.sh|test-chained-crash.sh|test-active-active.sh) ;;
	*) bad "unknown harness self-test target: $SELFTEST_HARNESS" ;;
esac

# --- unit normalisation -------------------------------------------------
# Real [SUM] sender lines. The Mbits row is the #6897 case: the old parser
# matched only "Gbits" and silently produced no cell for it.
check_rate() { # <desc> <expected> <line>
	local got; got="$(iperf_sum_rate_gbps "$3")"
	[[ "$got" == "$2" ]] || bad "$1: want $2 Gbps, got '${got:-<empty>}' from: $3"
	ok "$1 -> $got Gbps"
}
check_rate "Gbits normalises"  "22.9000"  '[SUM]   0.00-120.00  sec   320 GBytes  22.9 Gbits/sec   12  sender'
check_rate "Mbits normalises"  "0.0860"   '[SUM]   0.00-120.00  sec  1.20 GBytes   86.0 Mbits/sec   0   sender'
check_rate "Kbits normalises"  "0.000500" '[SUM]   0.00-10.00   sec  0.00 GBytes  500 Kbits/sec    0   sender'
check_rate "integer rate"      "10.0000"  '[SUM]   0.00-10.00   sec   12 GBytes    10 Gbits/sec    0   sender'

got="$(iperf_sum_rate_gbps '[SUM]   0.00-120.00  sec  no rate here  sender')"
[[ -z "$got" ]] || bad "a line with no rate/unit pair must yield nothing, got '$got'"
ok "unrecognised line yields no rate"

got="$(iperf_sum_rate_gbps '')"
[[ -z "$got" ]] || bad "an empty line must yield nothing, got '$got'"
ok "empty line yields no rate"

# --- TOTALITY: every input class emits exactly one verdict ---------------
# This is the #6897 regression guard. Under the pre-fix logic the Mbits row
# and the unparseable row emitted NOTHING.
check_verdict() { # <desc> <want-status> <min> <line>
	local out status n
	out="$(iperf_throughput_verdict "$3" "$4")"
	n="$(printf '%s\n' "$out" | grep -c .)"
	[[ "$n" == "1" ]] || bad "$1: want exactly ONE verdict line, got $n:
$out"
	status="${out%% *}"
	[[ "$status" == "$2" ]] || bad "$1: want $2, got $status ($out)"
	ok "$1 -> $status"
}
check_verdict "healthy Gbits run passes"      PASS 5 '[SUM] 0.00-120.00 sec 320 GBytes 22.9 Gbits/sec 12 sender'
check_verdict "sub-Gbit run FAILS not silent" FAIL 5 '[SUM] 0.00-120.00 sec 1.20 GBytes 86.0 Mbits/sec 0 sender'
check_verdict "Gbits below the floor fails"   FAIL 5 '[SUM] 0.00-120.00 sec 40 GBytes 2.5 Gbits/sec 0 sender'
check_verdict "exactly at the floor passes"   PASS 5 '[SUM] 0.00-120.00 sec 70 GBytes 5.0 Gbits/sec 0 sender'
check_verdict "unparseable line FAILS"        FAIL 5 '[SUM] 0.00-120.00 sec garbage sender'
check_verdict "absent [SUM] line FAILS"       FAIL 5 ''

# A sub-Gbit result must be reported with its REAL value, not as "0" and not
# as an absence — the number is what tells an operator how far it fell.
out="$(iperf_throughput_verdict 5 '[SUM] 0.00-120.00 sec 1.20 GBytes 86.0 Mbits/sec 0 sender')"
[[ "$out" == *"0.0860 Gbps"* ]] || bad "a sub-Gbit verdict must carry the normalised value, got: $out"
ok "sub-Gbit verdict carries its measured value"

# The absent-line and unparseable verdicts must be DISTINGUISHABLE, so a
# reader can tell "iperf3 produced nothing" from "iperf3 produced something
# this parser did not understand" — different causes, different next step.
a="$(iperf_throughput_verdict 5 '')"
b="$(iperf_throughput_verdict 5 '[SUM] garbage')"
[[ "$a" != "$b" ]] || bad "absent and unparseable must not render identically"
[[ "$a" == *"no measurement at all"* ]] || bad "absent verdict must say so, got: $a"
[[ "$b" == *"unparseable"* ]] || bad "unparseable verdict must say so, got: $b"
ok "absent and unparseable verdicts are distinguishable"

# --- JSON-stream verdict API --------------------------------------------
check_json_verdict() { # <desc> <want-status> <min> <avg> <note>
	local out n status
	out="$(iperf_throughput_json_verdict "$3" "$4" "$5")"
	n="$(printf '%s\n' "$out" | grep -c .)"
	[[ "$n" == "1" ]] || bad "$1: want exactly ONE JSON verdict line, got $n:
$out"
	status="${out%% *}"
	[[ "$status" == "$2" ]] || bad "$1: want $2, got $status ($out)"
	ok "$1 -> $status"
}

check_json_verdict "JSON verdict passes at the 1.0 Gbps floor" PASS 1.0 1.0 "json-stream avg_gbps from metrics.json; 8 full intervals"
check_json_verdict "raw value below 1.0 fails even when display rounds to 1.000" FAIL 1.0 0.9999 "json-stream avg_gbps from metrics.json; 8 full intervals"
check_json_verdict "sub-Gbit JSON verdict is displayed as a decimal value" FAIL 1.0 0.0864 "json-stream avg_gbps from metrics.json; 8 full intervals"

out="$(iperf_throughput_json_verdict 1.0 0.0864 'json-stream avg_gbps from /tmp/metrics.json; 8 full intervals')"
[[ "$out" == *"0.086 Gbps"* ]] || bad "sub-Gbit JSON display must retain its measured decimal value, got: $out"
[[ "$out" == *"json-stream avg_gbps from /tmp/metrics.json; 8 full intervals"* ]] \
	|| bad "JSON verdict must retain its metrics provenance and interval count, got: $out"
ok "JSON verdict includes the provenance note and full-interval count"

adapter_extract_gbps() {
	local cell
	cell="$(grep -E '^[[:space:]]*(PASS|FAIL)[[:space:]]+iperf3 throughput' <<<"$1" || true)"
	[[ -n "$cell" ]] || return 1
	grep -oE '([0-9]+\.[0-9]+|[0-9]+) Gbps' <<<"$cell" | head -1 | sed 's/ Gbps//'
}
out="$(iperf_throughput_json_verdict 1.0 0.0864 'json-stream avg_gbps from metrics.json; 8 full intervals')"
measured="$(adapter_extract_gbps "$out")"
[[ "$measured" == "0.086" ]] || bad "adapter regex/first-figure extraction should see measured 0.086 Gbps, got '$measured'"
if adapter_extract_gbps 'PASS iperf3 data transfer completed (9.000 Gbps)'; then
	bad "adapter must not extract a throughput headline without the anchored verdict phrase"
fi
ok "adapter anchor and first-Gbps extraction use the measured JSON figure"

FAILOVER="${SCRIPT_DIR}/test-failover.sh"
grep -q 'iperf_throughput_json_verdict "\$MIN_THROUGHPUT" "\$avg_gbps"' "$FAILOVER" \
	|| bad "test-failover.sh does not call the JSON verdict with the validated avg_gbps"
gate_line="$(grep -n 'gate_output=$(ha_metrics_gate "\$LOCAL_IPERF_METRICS"' "$FAILOVER" | cut -d: -f1)"
verdict_line="$(grep -n 'iperf_throughput_json_verdict "\$MIN_THROUGHPUT" "\$avg_gbps"' "$FAILOVER" | cut -d: -f1)"
(( gate_line < verdict_line )) || bad "test-failover.sh must gate metrics before calling the JSON verdict"
ok "test-failover call shape gates before the JSON verdict"
grep -q -- '--crash-at "$failover_at_seconds"' "$FAILOVER" \
	|| bad "test-failover.sh does not pass the measured crash instant to the stream oracle"
grep -q -- '--failback-at "$failback_at_seconds"' "$FAILOVER" \
	|| bad "test-failover.sh does not pass the measured last-RG-moved instant to the second stream oracle"
grep -q 'failback_at_seconds=$((SECONDS - iperf_start_seconds))' "$FAILOVER" \
	|| bad "test-failover.sh does not record failback against the iperf start clock"
(( $(grep -c 'void "iperf3 completed before manual failback' "$FAILOVER") == 2 )) \
	|| bad "test-failover.sh must void early client completion in both the rejoin (:1611) and failback (:1688) cells"
! grep -q 'pass "iperf3 completed successfully (finished before' "$FAILOVER" \
	|| bad "test-failover.sh accepts an iperf client that ended before failback"
ok "test-failover wires crash and last-RG-moved timestamps and rejects early client completion"
# #12618: test-failover applies the same [T, T+3] outside-window budget.
grep -q -- '--event-sec "$failover_at_seconds"' "$FAILOVER" \
	|| bad "test-failover.sh does not pass its crash instant to the window-excluded producer"
grep -q -- '--event-sec "$failback_at_seconds"' "$FAILOVER" \
	|| bad "test-failover.sh does not pass its failback instant to the window-excluded producer"
grep -q -- '--event-window-sec 3' "$FAILOVER" \
	|| bad "test-failover.sh does not pin the [T, T+3] window width"
grep -q 'stream_zero_intervals_outside_events_total' "$FAILOVER" \
	|| bad "test-failover.sh does not gate on the outside-window counter"
grep -q 'MAX_STREAM_ZERO_INTERVALS:-0' "$FAILOVER" \
	|| bad "test-failover.sh does not pin MAX_STREAM_ZERO_INTERVALS default 0 (#12618)"
grep -q 'HA_SMOKE_MAX_STREAM_ZERO_INTERVALS:-0' "${SCRIPT_DIR}/ha-smoke-iperf-lib.sh" \
	|| bad "ha-smoke lib does not pin HA_SMOKE_MAX_STREAM_ZERO_INTERVALS default 0 (#12618)"
ok "test-failover and ha-smoke pin budget-0 outside [T, T+3] (full intervals only)"

# Execute the production capture/gate/verdict blocks with an absent remote
# artifact and the REAL metrics gate. The verdict symbol is observed only as a
# forbidden-call marker; it is never fed invalid metrics.
ASSURANCE_LIB="${SCRIPT_DIR}/ha-assurance-lib.sh"
[[ -f "$ASSURANCE_LIB" ]] || bad "assurance lib not found at $ASSURANCE_LIB"
gate_fixture="$(sed -n '/^# M1 JSON capture\/gate fixture begin$/,/^# M1 JSON capture\/gate fixture end$/p' "$FAILOVER" | sed '1d;$d')"
verdict_fixture="$(sed -n '/^# M1 JSON verdict fixture begin$/,/^# M1 JSON verdict fixture end$/p' "$FAILOVER" | sed '1d;$d')"
[[ -n "$gate_fixture" && -n "$verdict_fixture" ]] || bad "could not extract the production JSON gate fixture"
fixture_dir="$(mktemp -d)"
trap 'rm -rf "$fixture_dir"' EXIT
for fixture_mode in absent malformed valid; do
	mkdir "${fixture_dir}/${fixture_mode}"
	CALL_MARKER="${fixture_dir}/${fixture_mode}/verdict-called"
	(
		# shellcheck source=test/incus/ha-assurance-lib.sh
		source "${SCRIPT_DIR}/ha-assurance-lib.sh"
		SCRIPT_DIR="$SCRIPT_DIR"
		CLUSTER_LAN_HOST=fixture
		# shellcheck disable=SC2034 # Used by the extracted production fixture.
		MIN_THROUGHPUT=1.0
		VOID=0
		# shellcheck disable=SC2034 # Used by the extracted gate fixture producer call.
		failover_at_seconds=0
		# shellcheck disable=SC2034 # Used by the extracted gate fixture producer call.
		failback_at_seconds=0
		FIXTURE_MODE="$fixture_mode"
		incus() {
			case "$FIXTURE_MODE" in
			absent) return 1 ;;
			malformed)
				printf '{"event":\n'
				;;
			valid)
				printf '%s\n' \
					'{"event":"interval","data":{"sum":{"start":0,"end":1,"bits_per_second":1200000000},"streams":[{"socket":1,"start":0,"end":1,"bits_per_second":1200000000}]}}' \
					'{"event":"interval","data":{"sum":{"start":1,"end":2,"bits_per_second":1200000000},"streams":[{"socket":1,"start":1,"end":2,"bits_per_second":1200000000}]}}' \
					'{"event":"end","data":{"sum_sent":{"bits_per_second":1200000000,"retransmits":0},"sum_received":{"bits_per_second":1200000000}}}'
				;;
			esac
		}
		pass() { printf 'PASS %s\n' "$*"; }
		fail() { printf 'FAIL %s\n' "$*"; }
		if [[ "$FIXTURE_MODE" != valid ]]; then
			iperf_throughput_json_verdict() {
				: >"$CALL_MARKER"
				printf 'PASS iperf3 throughput: 0.000 Gbps (>= 1.0 Gbps) — invalid fixture\n'
			}
		fi
		eval "$gate_fixture"
		eval "$verdict_fixture"
		if [[ "$FIXTURE_MODE" == valid ]]; then
			fixture_interval_count="$(python3 - "$LOCAL_IPERF_METRICS" <<'PY'
import json
import pathlib
import sys

metrics = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
print(len(metrics["interval_gbps"]))
PY
)"
			printf 'FIXTURE_INTERVAL_COUNT=%s\n' "$fixture_interval_count"
			# shellcheck disable=SC2154 # ha_metrics_gate assignments are in eval output.
			printf 'GATE_COUNT=%s\n' "$full_interval_count"
		else
			printf 'VOID_COUNT=%s\n' "$VOID"
		fi
	) >"${fixture_dir}/${fixture_mode}/call-site.out"
	[[ ! -e "$CALL_MARKER" ]] || bad "$fixture_mode remote metrics invoked the verdict after gate rejection"
	if [[ "$fixture_mode" == valid ]]; then
		out="${fixture_dir}/${fixture_mode}/call-site.out"
		grep -qE '^[[:space:]]*PASS[[:space:]]+iperf3 throughput' "$out" \
			|| bad "valid metrics must produce an anchored throughput PASS cell"
		grep -qE 'json-stream avg_gbps from .*; 2 full intervals' "$out" \
			|| bad "the evidence note must carry the fixture's two full intervals"
		grep -q '^FIXTURE_INTERVAL_COUNT=2$' "$out" \
			|| bad "producer fixture must contain exactly two full intervals"
		grep -q '^GATE_COUNT=2$' "$out" \
			|| bad "gate stdout must hand the exact full-interval count to the caller"
		ok "valid call-site fixture carries len(interval_gbps) into the evidence note"
	else
		out="${fixture_dir}/${fixture_mode}/call-site.out"
		grep -q 'VOID iperf3 throughput:' "$out" \
			|| bad "$fixture_mode remote metrics must emit an explicit throughput VOID reason"
		grep -q '^VOID_COUNT=1$' "$out" \
			|| bad "$fixture_mode remote metrics must increment the VOID counter"
		if grep -qE '^[[:space:]]*(PASS|FAIL)[[:space:]]+iperf3 throughput' "$out"; then
			bad "$fixture_mode remote metrics must emit no anchored throughput cell"
		fi
	fi
done
ok "absent and malformed remote metrics are rejected by the real gate before the verdict call"

# Exercise the production summary decision: ordinary VOID preserves measured
# FAIL, while a VOID-only run suppresses the clean summary and exits 77.
summary_fixture="$(sed -n '/^# M1 JSON summary precedence fixture begin$/,/^# M1 JSON summary precedence fixture end$/p' "$FAILOVER" | sed '1d;$d')"
[[ -n "$summary_fixture" ]] || bad "could not extract the production summary precedence fixture"
summary_out="${fixture_dir}/summary-fail-then-void.out"
summary_rc=0
(
	PASS=4
	FAIL=1
	VOID=1
	ERRORS=("measured regression")
	eval "$summary_fixture"
) >"$summary_out" || summary_rc=$?
[[ "$summary_rc" == "1" ]] || bad "FAIL-then-VOID must keep exit 1, got rc=$summary_rc"
grep -q '^  Failover test: 4 passed, 1 failed$' "$summary_out" \
	|| bad "FAIL-then-VOID must retain the existing summary grammar"

summary_out="${fixture_dir}/summary-void-only.out"
summary_rc=0
(
	PASS=4
	FAIL=0
	VOID=1
	ERRORS=()
	eval "$summary_fixture"
) >"$summary_out" || summary_rc=$?
[[ "$summary_rc" == "77" ]] || bad "VOID-only must take exit 77, got rc=$summary_rc"
if grep -q '^  Failover test:' "$summary_out"; then
	bad "VOID-only run must suppress the clean summary"
fi

summary_out="${fixture_dir}/summary-clean.out"
(
	PASS=4
	# shellcheck disable=SC2034 # Read by the extracted summary fixture.
	FAIL=0
	VOID=0
	# shellcheck disable=SC2034 # Read by the extracted summary fixture.
	ERRORS=()
	eval "$summary_fixture"
) >"$summary_out"
grep -q '^  Failover test: 4 passed, 0 failed$' "$summary_out" \
	|| bad "clean run must retain the existing summary grammar"
ok "FAIL outranks ordinary VOID; VOID-only suppresses summary and exits 77"

# --- Two-transition JSON-stream regression fixture ---------------------
# Both event checks must catch their own lost-stream recovery window while the
# aggregate remains far above the throughput floor. Each event is tested
# against the same stream with all expected IDs present before that transition.
dual_transition_fixture="${fixture_dir}/dual-transition.jsonl"
python3 - "$dual_transition_fixture" <<'PY'
import json
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
events = []
for second in range(33):
    streams = []
    total_bps = 0
    for stream_id in range(1, 5):
        stalled = (stream_id == 4 and 11 <= second <= 13) or (
            stream_id == 3 and 21 <= second <= 23
        )
        bps = 0 if stalled else 6_000_000_000
        total_bps += bps
        streams.append({
            "socket": stream_id,
            "start": second,
            "end": second + 1,
            "bits_per_second": bps,
        })
    events.append({
        "event": "interval",
        "data": {
            "sum": {
                "start": second,
                "end": second + 1,
                "bits_per_second": total_bps,
            },
            "streams": streams,
        },
    })
events.append({
    "event": "end",
    "data": {
        "sum_sent": {"bits_per_second": 18_000_000_000, "retransmits": 0},
        "sum_received": {"bits_per_second": 18_000_000_000},
    },
})
path.write_text(
    "\n".join(json.dumps(event, separators=(",", ":")) for event in events) + "\n",
    encoding="utf-8",
)
PY
for transition in 10 20; do
	oracle_output=$(python3 "${SCRIPT_DIR}/iperf3_sum_parse.py" \
		--failover-check --json-stream --streams 4 --min-throughput-gbps 1 \
		--crash-at "$transition" <"$dual_transition_fixture")
	grep -q '^PASS ' <<<"$(sed -n '1p' <<<"$oracle_output")" \
		|| bad "transition $transition: healthy aggregate interval verdict must pass"
	case "$transition" in
	10) expected_lost_stream=4 ;;
	20) expected_lost_stream=3 ;;
	esac
	grep -q "^FAIL streams ${expected_lost_stream} " <<<"$(sed -n '2p' <<<"$oracle_output")" \
		|| bad "transition $transition: stream $expected_lost_stream loss must fail its own recovery check"
done
ok "two transition events reject subset stream stalls despite a healthy aggregate"
# Exercise the production capture/metrics/oracle validator against the same
# fixture; only the remote log read and completion wait are locally stubbed.
# All JSON parsing, metrics gating, and per-transition verdicts are real.
# shellcheck source=test/incus/ha-smoke-iperf-lib.sh
source "${SCRIPT_DIR}/ha-smoke-iperf-lib.sh"
CLUSTER_LAN_HOST=fixture-lan
incus() {
	[[ "$1" == exec && "$2" == "$CLUSTER_LAN_HOST" && "$3" == -- ]] || return 90
	if [[ "$4" == bash && "$5" == -c ]]; then
		return 0
	fi
	if [[ "$4" == cat && "$5" == /fixture/* ]]; then
		if [[ "${MOCK_CAPTURE_MODE:-ok}" == fail ]]; then
			echo "fixture capture denied" >&2
			return 1
		fi
		cat "${MOCK_CAPTURE_FILE:-$dual_transition_fixture}"
		return
	fi
	return 91
}
smoke_verdicts=$(ha_smoke_iperf_verdicts /fixture/iperf.jsonl 33 4 1 10 20)
grep -q '^PASS iperf3 throughput:' <<<"$smoke_verdicts" \
	|| bad "shared validator must keep a passing whole-run throughput cell"
grep -q '^PASS iperf3 intervals:' <<<"$smoke_verdicts" \
	|| bad "shared validator must pass the healthy aggregate intervals"
grep -q '^FAIL iperf3 transition 1 streams: streams 4 ' <<<"$smoke_verdicts" \
	|| bad "shared validator must fail the stream lost at transition 1"
grep -q '^FAIL iperf3 transition 2 streams: streams 3 ' <<<"$smoke_verdicts" \
	|| bad "shared validator must fail the stream lost at transition 2"
ok "shared smoke validator emits anchored throughput and both transition-specific failures"
missing_smoke_verdicts=$(MOCK_CAPTURE_MODE=fail \
	ha_smoke_iperf_verdicts /fixture/missing.jsonl 33 4 1 10 20)
grep -q '^FAIL iperf3 throughput: JSON metrics unavailable: fixture capture denied$' \
	<<<"$missing_smoke_verdicts" \
	|| bad "shared validator must fail when remote JSON log capture fails"
! grep -q '^PASS ' <<<"$missing_smoke_verdicts" \
	|| bad "failed remote capture must never produce a pass cell"
[[ $(grep -c '^FAIL iperf3 transition' <<<"$missing_smoke_verdicts") -eq 2 ]] \
	|| bad "failed remote capture must fail both transition stream checks"
ok "shared smoke validator fails closed when log capture fails"

# A late stream stall is outside both transition recovery windows but must
# still fail the whole-run per-stream budget.
late_stall_fixture="${fixture_dir}/late-stall.jsonl"
python3 - "$late_stall_fixture" <<'PY'
import json
import pathlib
import sys

events = []
for second in range(45):
    streams = []
    total_bps = 0
    for stream_id in range(1, 9):
        bps = 0 if stream_id == 5 and second >= 24 else 6_000_000_000
        total_bps += bps
        streams.append({
            "socket": stream_id,
            "start": second,
            "end": second + 1,
            "bits_per_second": bps,
        })
    events.append({
        "event": "interval",
        "data": {
            "sum": {
                "start": second,
                "end": second + 1,
                "bits_per_second": total_bps,
            },
            "streams": streams,
        },
    })
events.append({
    "event": "end",
    "data": {
        "sum_sent": {"bits_per_second": 42_000_000_000, "retransmits": 0},
        "sum_received": {"bits_per_second": 42_000_000_000},
    },
})
pathlib.Path(sys.argv[1]).write_text(
    "\n".join(json.dumps(event, separators=(",", ":")) for event in events) + "\n",
    encoding="utf-8",
)
PY
late_stall_verdicts=$(HA_SMOKE_MAX_STREAM_ZERO_INTERVALS=0 \
	MOCK_CAPTURE_FILE="$late_stall_fixture" \
	ha_smoke_iperf_verdicts /fixture/late.jsonl 45 8 1 10 20)
grep -q '^FAIL iperf3 whole-run per-stream zero intervals (21, limit 0 via HA_SMOKE_MAX_STREAM_ZERO_INTERVALS; 1 affected stream(s); 21 total):' \
	<<<"$late_stall_verdicts" \
	|| bad "late stream stall must fail the whole-run per-stream zero budget (HA_SMOKE_MAX_STREAM_ZERO_INTERVALS)"
grep -q '^PASS iperf3 transition 1 streams:' <<<"$late_stall_verdicts" \
	|| bad "late stream stall must not be attributed to transition 1"
grep -q '^PASS iperf3 transition 2 streams:' <<<"$late_stall_verdicts" \
	|| bad "late stream stall must not be attributed to transition 2"
ok "whole-run per-stream zero budget (HA_SMOKE_MAX_STREAM_ZERO_INTERVALS=0) fails a late stall outside both [T, T+3] windows"

# #12618: a healthy crash signature -- zeros only as full intervals wholly
# inside [T, T+3] for each transition -- must PASS at budget 0, while a
# straddling interval and a partial interval inside the window must count.
window_fixture="${fixture_dir}/window.jsonl"
python3 - "$window_fixture" <<'PY'
import json
import pathlib
import sys

events = []
for second in range(33):
    streams = []
    total_bps = 0
    for stream_id in range(1, 5):
        # Stream 4: zero at 10,11,12 (full, wholly inside [10,13]) -> excluded.
        # Stream 3: zero at 9 (straddles [10,13] start) -> counted.
        # Stream 3: zero at 20,21,22 (inside [20,23]) -> excluded.
        stalled = (stream_id == 4 and 10 <= second <= 12) or (
            stream_id == 3 and (second == 9 or 20 <= second <= 22)
        )
        bps = 0 if stalled else 6_000_000_000
        total_bps += bps
        streams.append({"socket": stream_id, "start": second, "end": second + 1, "bits_per_second": bps})
    events.append({"event": "interval", "data": {"sum": {"start": second, "end": second + 1, "bits_per_second": total_bps}, "streams": streams}})
events.append({"event": "end", "data": {"sum_sent": {"bits_per_second": 18_000_000_000, "retransmits": 0}, "sum_received": {"bits_per_second": 18_000_000_000}}})
pathlib.Path(sys.argv[1]).write_text("\n".join(json.dumps(e) for e in events) + "\n", encoding="utf-8")
PY
window_verdicts=$(HA_SMOKE_MAX_STREAM_ZERO_INTERVALS=0 \
	MOCK_CAPTURE_FILE="$window_fixture" \
	ha_smoke_iperf_verdicts /fixture/window.jsonl 33 4 1 10 20)
grep -q '^FAIL iperf3 whole-run per-stream zero intervals (1, limit 0 via HA_SMOKE_MAX_STREAM_ZERO_INTERVALS; 1 affected stream(s); 7 total):' \
	<<<"$window_verdicts" \
	|| bad "only the straddling pre-window zero must count outside [T, T+3] (got: $window_verdicts)"
window_pass_verdicts=$(HA_SMOKE_MAX_STREAM_ZERO_INTERVALS=1 \
	MOCK_CAPTURE_FILE="$window_fixture" \
	ha_smoke_iperf_verdicts /fixture/window.jsonl 33 4 1 10 20)
grep -q '^PASS iperf3 whole-run per-stream zero intervals outside transition windows (1, limit 1 via HA_SMOKE_MAX_STREAM_ZERO_INTERVALS; 1 affected stream(s); 7 total)' \
	<<<"$window_pass_verdicts" \
	|| bad "outside-window count of 1 must pass at HA_SMOKE_MAX_STREAM_ZERO_INTERVALS=1"
# In-window-only zeros pass at the pinned default budget 0.
inwindow_fixture="${fixture_dir}/inwindow.jsonl"
python3 - "$window_fixture" "$inwindow_fixture" <<'PY'
import json
import pathlib
import sys

events = []
for line in pathlib.Path(sys.argv[1]).read_text().splitlines():
    event = json.loads(line)
    if event.get("event") == "interval":
        second = event["data"]["sum"]["start"]
        for stream in event["data"]["streams"]:
            if stream["socket"] == 3 and second == 9:
                stream["bits_per_second"] = 6_000_000_000
        event["data"]["sum"]["bits_per_second"] = sum(s["bits_per_second"] for s in event["data"]["streams"])
    events.append(event)
pathlib.Path(sys.argv[2]).write_text("\n".join(json.dumps(e) for e in events) + "\n", encoding="utf-8")
PY
inwindow_verdicts=$(HA_SMOKE_MAX_STREAM_ZERO_INTERVALS=0 \
	MOCK_CAPTURE_FILE="$inwindow_fixture" \
	ha_smoke_iperf_verdicts /fixture/inwindow.jsonl 33 4 1 10 20)
grep -q '^PASS iperf3 whole-run per-stream zero intervals outside transition windows (0, limit 0 via HA_SMOKE_MAX_STREAM_ZERO_INTERVALS; 0 affected stream(s); 6 total)' \
	<<<"$inwindow_verdicts" \
	|| bad "zeros wholly inside [T, T+3] must pass at the pinned default HA_SMOKE_MAX_STREAM_ZERO_INTERVALS=0"
ok "window-excluded counting: in-window full intervals excluded, straddling counted, default pinned at 0"
# A shortened stream row inside an otherwise full-length interval keeps
# interval-level exclusion (the strict oracle bounds intervals to 0.5-1.5s).
python3 - "$window_fixture" <<'PY'
import json
import pathlib
import subprocess
import sys

path = pathlib.Path(sys.argv[1])
events = []
for second in range(33):
    streams = []
    total = 0
    for sid in range(1, 5):
        bps = 0 if (sid == 4 and second == 11) else 6_000_000_000
        total += bps
        # Shorten only the zero interval to 0.5s (partial).
        end = second + (0.5 if (sid == 4 and second == 11) else 1)
        streams.append({"socket": sid, "start": second, "end": end, "bits_per_second": bps})
    events.append({"event": "interval", "data": {"sum": {"start": second, "end": second + 1, "bits_per_second": total}, "streams": streams}})
events.append({"event": "end", "data": {"sum_sent": {"bits_per_second": 18_000_000_000, "retransmits": 0}, "sum_received": {"bits_per_second": 18_000_000_000}}})
path.write_text("\n".join(json.dumps(e) for e in events) + "\n", encoding="utf-8")
PY
producer_out=$(python3 "${SCRIPT_DIR}/../../scripts/iperf-json-metrics.py" "$window_fixture" --event-sec 10 --event-sec 20)
python3 - "$producer_out" <<'PY' || bad "zero in a full-length interval wholly inside a window must be excluded even if its stream row is shortened"
import json, sys
m = json.loads(sys.argv[1])
assert m["stream_zero_intervals_total"] == 1, m
assert m["stream_zero_intervals_outside_events_total"] == 0, m
PY
ok "producer exclusion is decided by the full-length interval bounds, not a shortened stream row"

# Completion requires an end event or evidence that the expected duration ran.
incomplete_fixture="${fixture_dir}/incomplete.jsonl"
python3 - "$dual_transition_fixture" "$incomplete_fixture" <<'PY'
import json
import pathlib
import sys

events = [
    event
    for event in (json.loads(line) for line in pathlib.Path(sys.argv[1]).read_text().splitlines())
    if event.get("event") != "end"
]
pathlib.Path(sys.argv[2]).write_text(
    "\n".join(json.dumps(event, separators=(",", ":")) for event in events) + "\n",
    encoding="utf-8",
)
PY
completion_python_dir="${fixture_dir}/completion-python"
mkdir -p "$completion_python_dir"
REAL_PYTHON="$(command -v python3)"
cat >"$completion_python_dir/python3" <<'SH'
#!/usr/bin/env bash
if [[ "${1:-}" == */iperf-json-metrics.py ]]; then
	"$REAL_PYTHON" "$@" |
		"$REAL_PYTHON" -c 'import json, sys; metrics = json.load(sys.stdin); metrics["avg_gbps"] = 1.0; print(json.dumps(metrics))'
	exit $?
fi
exec "$REAL_PYTHON" "$@"
SH
chmod +x "$completion_python_dir/python3"
#
# Keep a healthy measured rate while the fixture has no end event, so the
# duration threshold—not the throughput floor—determines completion.
incomplete_verdicts=$(REAL_PYTHON="$REAL_PYTHON" \
	PATH="$completion_python_dir:$PATH" MOCK_CAPTURE_FILE="$incomplete_fixture" \
	ha_smoke_iperf_verdicts /fixture/incomplete.jsonl 45 4 1 10 20)
grep -q '^FAIL iperf3 completion: JSON stream ended at 33.000s of 45s without a valid end event$' \
	<<<"$incomplete_verdicts" \
	|| bad "truncated JSON stream must fail completion below duration-2"
ok "truncated stream below the duration threshold fails completion"

# Invalid UTF-8 must fail closed with one-line oracle diagnostics.
invalid_utf8_fixture="${fixture_dir}/invalid-utf8.jsonl"
printf '\377\n' >"$invalid_utf8_fixture"
invalid_utf8_verdicts=$(MOCK_CAPTURE_FILE="$invalid_utf8_fixture" \
	ha_smoke_iperf_verdicts /fixture/invalid-utf8.jsonl 45 4 1 10 20)
grep -q '^FAIL iperf3 intervals: UnicodeDecodeError:' <<<"$invalid_utf8_verdicts" \
	|| bad "invalid UTF-8 must fail interval validation with the final oracle error line"
[[ $(grep -c '^FAIL iperf3 transition' <<<"$invalid_utf8_verdicts") -eq 2 ]] \
	|| bad "invalid UTF-8 must fail both transition checks"
[[ $(grep -c '^FAIL iperf3 intervals:' <<<"$invalid_utf8_verdicts") -eq 1 ]] \
	|| bad "invalid UTF-8 diagnostics must remain a single interval cell"
ok "invalid UTF-8 fails intervals and both transitions with single-line errors"

# The shared oracle must convert any status other than PASS/FAIL to FAIL.
unknown_python_dir="${fixture_dir}/unknown-python"
mkdir -p "$unknown_python_dir"

cat >"$unknown_python_dir/python3" <<'SH'
#!/usr/bin/env bash
if [[ "${1:-}" == */iperf3_sum_parse.py ]]; then
	printf 'MAYBE intervals\nMAYBE streams\n'
	exit 0
fi
exec "$REAL_PYTHON" "$@"
SH
chmod +x "$unknown_python_dir/python3"
unknown_verdicts=$(REAL_PYTHON="$REAL_PYTHON" PATH="$unknown_python_dir:$PATH" \
	ha_smoke_iperf_verdicts /fixture/iperf.jsonl 33 4 1 10 20)
grep -q '^FAIL iperf3 intervals: unrecognized failover interval verdict: MAYBE intervals$' \
	<<<"$unknown_verdicts" \
	|| bad "unknown interval oracle status must be converted to FAIL"
[[ $(grep -c '^FAIL iperf3 transition .*: unrecognized transition stream verdict: MAYBE streams$' \
	<<<"$unknown_verdicts") -eq 2 ]] \
	|| bad "unknown transition oracle statuses must be converted to FAIL"
ok "unknown oracle statuses fail closed for intervals and both transitions"



# --- WIRING + the #7673 PORT AGREEMENT, for EVERY HA smoke with a throughput cell ---
# Binding the lib alone would leave a green if someone deleted the CALL from a
# production path -- the shape that has repeatedly produced false confidence. A
# behavioural probe of these harnesses needs a cluster, so these are structural
# guards on each caller: the wiring exists, not that the surrounding logic is
# correct.
#
# #9690/#9691: these cells used to read test-failover.sh ONLY, and its four
# siblings kept both defects it had fixed: a Gbits-only parse with no else
# (#6897), and the 5201 default port that cos-iperf-config.set shapes to 100m.
# This legacy source-shape guard covers four sibling harnesses. test-failover
# is covered behaviorally by its interval/stream oracle tests instead.
#
# The port cells assert the AGREEMENT between each harness and the CoS set rather
# than pinning either to a literal. Pinning the port alone would encode which
# side is trusted, and the side that was wrong in #7673 is the one nobody
# suspected. Port to class is read in two steps (port to term, term to class)
# rather than assuming term 11.
#
# The current JSON smokes route the port through failover_start_main_iperf;
# stress-failover retains its text-client command. The per-sibling branch below
# checks each wiring shape without weakening the common port/class agreement.
COS_SET="$(dirname "$0")/cos-iperf-config.set"
ORACLE_LIB="${SCRIPT_DIR}/ha-smoke-iperf-lib.sh"
grep -q -- '--failover-check --json-stream --streams "$streams"' "$ORACLE_LIB" \
	|| bad "shared smoke oracle does not route JSON interval telemetry to --failover-check"
grep -Fq -- '--crash-at "${events[$((event_number - 1))]}"' "$ORACLE_LIB" \
	|| bad "shared smoke oracle does not evaluate every supplied transition timestamp"

SMOKES=(test-double-failover.sh test-chained-crash.sh test-active-active.sh test-stress-failover.sh test-rolling-upgrade.sh)
for smoke in "${SMOKES[@]}"; do
	[[ -z "$SELFTEST_HARNESS" || "$smoke" == "$SELFTEST_HARNESS" ]] || continue
	f="${SCRIPT_DIR}/${smoke}"
	[[ -f "$f" ]] || bad "$smoke not found at $f"

	grep -q 'source "${SCRIPT_DIR}/iperf-throughput-lib.sh"' "$f" \
		|| bad "$smoke does not source iperf-throughput-lib.sh"
	if [[ "$smoke" == "test-stress-failover.sh" ]]; then
		grep -q 'iperf_throughput_verdict "$MIN_THROUGHPUT" "$sum_line"' "$f" \
			|| bad "$smoke does not call iperf_throughput_verdict"
		awk '/^throughput_verdict=/,/^esac$/' "$f" | grep -qE '^\*\)[[:space:]]+fail ' \
			|| bad "$smoke: the text throughput verdict has no catch-all '*) fail'"
	elif [[ "$smoke" == "test-rolling-upgrade.sh" ]]; then
		grep -q 'source "${SCRIPT_DIR}/failover-client-lib.sh"' "$f" \
			&& grep -Fq 'failover_start_main_iperf "$ROLLING_IPERF_DURATION"' "$f" \
			&& grep -Fq '"$IPERF_STREAMS" "$REMOTE_LOG" "$REMOTE_PID" "$ROLLING_IPERF_INTERVAL"' "$f" \
			|| bad "$smoke does not use the tracked 100-ms client helper"
		grep -q 'failover_main_iperf_running "$REMOTE_PID" "$IPERF_TARGET" "$IPERF_PORT" "$IPERF_STREAMS"' "$f" \
			|| bad "$smoke does not scope client liveness to its pidfile and tuple"
		grep -q 'rolling_upgrade_oracle.py' "$f" \
			|| bad "$smoke does not run the per-stream rolling-upgrade oracle"
		grep -Fq -- '--max-interval-sec 0.25' "$f" \
			|| bad "$smoke does not pin the oracle's 250-ms interval-width limit"
		grep -Fq 'ROLLING_IPERF_INTERVAL="0.1"' "$f" \
			|| bad "$smoke does not pin the 100-ms iperf3 sampling interval"
		if grep -vE '^[[:space:]]*#' "$f" | grep -qE 'pgrep.*iperf3|pkill.*iperf3'; then
			bad "$smoke retains unscoped iperf3 process matching or termination"
		fi
	else
		grep -q 'source "${SCRIPT_DIR}/ha-smoke-iperf-lib.sh"' "$f" \
			|| bad "$smoke does not source the tracked JSON smoke client/oracle"
		grep -q 'failover_start_main_iperf "$IPERF_DURATION" "$IPERF_TARGET" "$IPERF_PORT" "$IPERF_STREAMS"' "$f" \
			|| bad "$smoke does not start its main client through failover_start_main_iperf"
		grep -q '"$LOG" "$PIDFILE" 1' "$f" \
			|| bad "$smoke does not provide its log, pidfile, and one-second interval"
		grep -q 'failover_main_iperf_running "$PIDFILE" "$IPERF_TARGET" "$IPERF_PORT" "$IPERF_STREAMS"' "$f" \
			|| bad "$smoke does not scope client liveness to its pidfile and command tuple"
		grep -q 'ha_smoke_iperf_verdicts "$LOG" "$IPERF_DURATION" "$IPERF_STREAMS"' "$f" \
			|| bad "$smoke does not run per-transition stream and interval verdicts"
		[[ "$(grep -c 'FAILOVER_EVENTS+=' "$f")" == 2 ]] \
			|| bad "$smoke does not record exactly one timestamp per transition"
		grep -q 'source "${SCRIPT_DIR}/deploy-lib.sh"' "$f" &&
			grep -q 'deploy_node_role_every_rg_ok' "$f" \
			|| bad "$smoke does not assert roles with deploy_node_role_every_rg_ok"
		role_gate_count=$(grep -c 'deploy_node_role_every_rg_ok' "$f")
		case "$smoke" in
		test-double-failover.sh)
			[[ "$role_gate_count" -eq 5 ]] &&
				grep -qF 'deploy_node_role_every_rg_ok node1 primary' "$f" &&
				grep -qF 'deploy_node_role_every_rg_ok node0 secondary' "$f" \
				|| bad "$smoke does not check every whole-cluster role cell"
			;;
		test-chained-crash.sh)
			[[ "$role_gate_count" -eq 5 ]] &&
				grep -qF 'deploy_node_role_every_rg_ok "$node" primary' "$f" &&
				grep -qF 'deploy_node_role_every_rg_ok node0 secondary' "$f" &&
				grep -qF 'deploy_node_role_every_rg_ok node1 secondary' "$f" \
				|| bad "$smoke does not check every whole-cluster role cell"
			grep -Fq 'restart_time=$(wait_for_xpfd "$FW0" "$VM_RESTART_WAIT" || true)' "$f" &&
				grep -Fq 'restart_time=$(wait_for_xpfd "$FW1" "$VM_RESTART_WAIT" || true)' "$f" \
				|| bad "$smoke must keep bounded xpfd restart waits for both phases"

			;;
		test-active-active.sh)
			[[ "$role_gate_count" -eq 2 ]] \
				|| bad "$smoke must gate preflight and reunification across all RGs"
			preflight_status_reads=$(sed -n '/^# Ensure all RGs are on fw0/,/^if printf/p' "$f" \
				| grep -c 'fw0_status=$(incus exec')
			[[ "$preflight_status_reads" -eq 2 ]] \
				|| bad "$smoke must refresh fw0_status after its preflight correction"

			;;
		esac
		if grep -vE '^[[:space:]]*#' "$f" | grep -qE 'pgrep.*iperf3|pkill.*iperf3'; then
			bad "$smoke retains unscoped iperf3 process matching or termination"
		fi
	fi
	if [[ "$smoke" == "test-stress-failover.sh" ]]; then
		grep -q -- '-p ${IPERF_PORT}' "$f" \
			|| bad "$smoke does not pass -p \${IPERF_PORT} to iperf3"
	elif [[ "$smoke" == "test-rolling-upgrade.sh" ]]; then
		grep -Fq 'IPERF_PORT="${IPERF_PORT:-5211}"' "$f" \
			|| bad "$smoke does not retain the dedicated port 5211"
	else
		grep -q 'failover_start_main_iperf "$IPERF_DURATION" "$IPERF_TARGET" "$IPERF_PORT" "$IPERF_STREAMS"' "$f" \
			&& grep -q ' -p "$3" ' "${SCRIPT_DIR}/failover-client-lib.sh" \
			|| bad "$smoke does not pass its configured port through the tracked client helper"
	fi
	if grep -vE '^[[:space:]]*#' "$f" | grep -qE "grep -o[a-zA-Z]* ['\"][^'\"]*Gbits"; then
		bad "$smoke: an inline Gbits-only throughput parse is back"
	fi
	ok "$smoke: client/verdict wiring is scoped and total"

	port=$(sed -n 's/^IPERF_PORT="\${IPERF_PORT:-\([0-9]*\)}"/\1/p' "$f")
	[ -n "$port" ] || bad "could not read the IPERF_PORT default out of $smoke -- this cell would otherwise pass having checked nothing"
	term=$(sed -n "s/^set firewall family inet filter bandwidth-output term \([0-9]*\) from destination-port ${port}$/\1/p" "$COS_SET" | head -1)
	[ -n "$term" ] || bad "$smoke: port $port matches no 'from destination-port' term in cos-iperf-config.set -- the smoke would be measuring an unclassified path"
	fc=$(sed -n "s/^set firewall family inet filter bandwidth-output term ${term} then forwarding-class \(.*\)$/\1/p" "$COS_SET" | head -1)
	[ -n "$fc" ] || bad "$smoke: filter term $term has no 'then forwarding-class' line -- cannot tell which class port $port lands in"
	sched=$(sed -n "s/^set class-of-service scheduler-maps [^ ]* forwarding-class $fc scheduler \(.*\)$/\1/p" "$COS_SET" | head -1)
	[ -n "$sched" ] || bad "$smoke: forwarding-class $fc has no scheduler in the scheduler-map -- cannot tell whether it is shaped"
	if grep -q "^set class-of-service schedulers $sched transmit-rate" "$COS_SET"; then
		bad "$smoke: iperf port $port lands in $fc/$sched, which HAS a transmit-rate -- the throughput gate is measuring a deliberately shaped class (#7673/#9691)"
	fi
	ok "$smoke: -p \${IPERF_PORT} default $port -> term $term -> $fc/$sched, unshaped"

done


echo
echo "iperf-throughput-lib self-test: $PASS passed"
