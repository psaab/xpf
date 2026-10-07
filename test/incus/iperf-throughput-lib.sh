#!/usr/bin/env bash
#
# #6897 — parsing and verdict for the iperf3 [SUM] sender throughput cell.
#
# Extracted from test-failover.sh so the decision is HERMETICALLY TESTABLE.
# The bug this exists to prevent was not a wrong number, it was NO CELL AT
# ALL: the old inline block matched only "Gbits", so a sub-Gbit run set the
# throughput to the literal "0" and then matched neither the pass branch nor
# the fail branch. There was no else. The run emitted nothing for that gate
# and still summarised as "0 failed".
#
# That is the failure mode the harness exists to catch, wearing the harness's
# own clothes: iperf3 reports Mbits/sec precisely when throughput has
# collapsed — a real regression, or a CoS-shaped class. Measured: one local
# run summarised "13 passed, 0 failed" where every sibling run reported 14
# cells, with the throughput cell absent rather than failed.
#
# Two rules follow, and both are asserted by iperf-throughput-selftest.sh:
#   1. normalise the UNIT, so a sub-Gbit result is a measurement rather than
#      a hole;
#   2. the verdict is TOTAL — every input class yields exactly one cell,
#      including "no [SUM] line" and "unparseable".

# iperf_sum_rate_gbps <sum_line>
#   Print the [SUM] sender rate in Gbits/sec, or nothing if the line carries
#   no recognisable "<number> <K|M|G>bits/sec" pair.
#
#   iperf3 chooses the unit by magnitude, so all three must be accepted. The
#   rate and its unit are ADJACENT fields, which is what makes this parseable
#   without depending on column positions that differ between iperf3 versions
#   and between the interval and summary lines.
iperf_sum_rate_gbps() {
	local line="$1"
	[[ -n "$line" ]] || return 0
	awk '{
		for (i = 2; i <= NF; i++) {
			if ($i ~ /^[KMG]bits\/sec$/ && $(i-1) ~ /^[0-9]+(\.[0-9]+)?$/) {
				unit = substr($i, 1, 1)
				val = $(i-1) + 0
				if (unit == "G") { printf "%.4f", val }
				else if (unit == "M") { printf "%.4f", val / 1000 }
				else { printf "%.6f", val / 1000000 }
				exit
			}
		}
	}' <<<"$line"
}

# iperf_throughput_verdict <min_gbps> <sum_line>
#   Print exactly one verdict line: "PASS <message>" or "FAIL <message>".
#
#   TOTAL BY CONSTRUCTION — every path prints. That totality is the fix; the
#   normalisation above only decides which branch is taken. A caller must map
#   the verdict onto its own pass/fail counters with a catch-all default, so a
#   future unhandled status still emits a cell.
iperf_throughput_verdict() {
	local min="$1" line="$2" gbps
	if [[ -z "$line" ]]; then
		printf 'FAIL %s\n' "iperf3 throughput: no [SUM] sender line in the iperf3 log — the run produced no measurement at all"
		return 0
	fi
	gbps="$(iperf_sum_rate_gbps "$line")"
	if [[ -z "$gbps" ]]; then
		printf 'FAIL %s\n' "iperf3 throughput unparseable — no '<rate> <K|M|G>bits/sec' pair in the [SUM] sender line: ${line}"
		return 0
	fi
	if awk "BEGIN{exit !($gbps >= $min)}"; then
		printf 'PASS %s\n' "iperf3 throughput: ${gbps} Gbps (>= ${min} Gbps)"
	else
		printf 'FAIL %s\n' "iperf3 throughput too low: ${gbps} Gbps (expected >= ${min} Gbps) — [SUM] line: ${line}"
	fi
}
# iperf_throughput_json_verdict <min_gbps> <avg_gbps> <evidence_note>
#   Verdict a validated JSON-stream average without parsing the source file.
#   Compare the raw scalar against the existing floor; round only its display.
iperf_throughput_json_verdict() {
	local min="$1" avg="$2" note="$3" display
	printf -v display '%.3f' "$avg"
	if awk "BEGIN{exit !($avg >= $min)}"; then
		printf 'PASS iperf3 throughput: %s Gbps (>= %s Gbps) — %s\n' "$display" "$min" "$note"
	else
		printf 'FAIL iperf3 throughput too low: %s Gbps (expected >= %s Gbps) — %s\n' "$display" "$min" "$note"
	fi
}
