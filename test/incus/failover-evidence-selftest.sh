#!/usr/bin/env bash
# test/incus/failover-evidence-selftest.sh -- #19168: test-failover.sh keeps
# the evidence of a per-stream zero-interval verdict. Hermetic: a fixture
# json-stream log (2 streams, 7 one-second intervals, a crash event at 1 s
# with a 3 s window) goes through the real producer
# (scripts/iperf-json-metrics.py) and the real archive and naming functions,
# extracted from test-failover.sh. Cells:
#   - the producer lists the one outside-window zero interval (stream 7,
#     5-6 s, wall clock = the client's start stamp + 5 s) and not the zero
#     inside the crash window (stream 5, 1-2 s);
#   - the archive holds the json-stream log, the metrics and
#     outside-zero-intervals.tsv with that row;
#   - the verdict detail names stream 7 and its wall-clock time;
#   - test-failover.sh archives right after the capture/gate block (PASS or
#     FAIL, before any verdict) and appends the detail to the verdict line.
# Mutations: the producer not listing the interval, the archive skipping the
# log, the archive call removed from the run.
set -uo pipefail
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)
producer="$root/scripts/iperf-json-metrics.py"
failover="$here/test-failover.sh"
tmp=$(mktemp -d "${TMPDIR:-/tmp}/failover-evidence-selftest.XXXXXX")
trap 'rm -rf "$tmp"' EXIT
pass=0
fail=0
ok() { pass=$((pass + 1)); echo "PASS: $*"; }
bad() { fail=$((fail + 1)); echo "FAIL: $*"; }

# The fixture: start stamp 2026-11-01T13:33:55.762Z; stream 5 is zero in
# [1,2] (inside the crash window [1,4]); stream 7 is zero in [5,6] (outside).
python3 - "$tmp/run.json-stream.log" <<'PY'
import json, sys
GBIT = 1e9
lines = [{"event": "start", "data": {
    "connected": [{"socket": 5}, {"socket": 7}],
    "timestamp": {"time": "Sun, 01 Nov 2026 13:33:55 GMT", "timesecs": 1793540035, "timemillisecs": 1793540035762},
    "test_start": {"protocol": "TCP", "num_streams": 2, "duration": 7}}}]
for i in range(7):
    rates = {5: 0.0 if i == 1 else 5 * GBIT, 7: 0.0 if i == 5 else 5 * GBIT}
    streams = [{"socket": s, "start": float(i), "end": float(i + 1), "seconds": 1.0,
                "bytes": int(r / 8), "bits_per_second": r, "retransmits": 0} for s, r in rates.items()]
    total = sum(rates.values())
    lines.append({"event": "interval", "data": {"streams": streams, "sum": {
        "start": float(i), "end": float(i + 1), "seconds": 1.0, "bytes": int(total / 8),
        "bits_per_second": total, "retransmits": 0}}})
summ = {"start": 0.0, "end": 7.0, "seconds": 7.0, "bytes": 1, "bits_per_second": 8 * GBIT, "retransmits": 0}
lines.append({"event": "end", "data": {"sum_sent": summ, "sum_received": summ, "streams": []}})
open(sys.argv[1], "w").write("".join(json.dumps(l) + "\n" for l in lines))
PY

# extract <script> <out>: the two #19168 functions from test-failover.sh.
extract() {
	python3 - "$1" "$2" <<'PY'
import re, sys
text = open(sys.argv[1]).read()
out = []
for name in ("failover_archive_evidence", "failover_outside_zero_detail"):
    m = re.search(rf"^{name}\(\) \{{\n.*?^\}}\n", text, re.M | re.S)
    if not m:
        raise SystemExit(f"cannot extract {name}")
    out.append(m.group(0))
open(sys.argv[2], "w").write("".join(out))
PY
}

# cells <producer> <test-failover.sh>: one line per cell, "<name> <result>".
cells() {
	local p=$1 f=$2 d="$tmp/cell.$RANDOM"
	mkdir -p "$d"
	python3 "$p" "$tmp/run.json-stream.log" --event-sec 1 --event-window-sec 3 >"$d/metrics.json" 2>"$d/producer.err"
	echo "producer $(python3 -c '
import json, sys
m = json.load(open(sys.argv[1]))
rows = m.get("stream_zero_intervals_outside_events") or []
print(m.get("stream_zero_intervals_outside_events_total"), " ".join("%s:%s-%s@%s" % (r["stream"], r["start"], r["end"], r["wall_start_utc"]) for r in rows))
' "$d/metrics.json" 2>&1)"
	if ! extract "$f" "$d/fns.sh" 2>"$d/extract.err"; then
		echo "archive extract-failed"
		echo "detail extract-failed"
	else
		(
			# shellcheck source=/dev/null
			source "$d/fns.sh"
			# shellcheck disable=SC2034 # read by the sourced functions
			LOCAL_IPERF_LOG="$tmp/run.json-stream.log" LOCAL_IPERF_METRICS="$d/metrics.json"
			# shellcheck disable=SC2034
			LOCAL_IPERF_PRODUCER_ERR="$d/producer.err" LOCAL_IPERF_GATE_ERR="$d/gate.err"
			failover_archive_evidence "$d/evidence" >/dev/null
			echo "archive $(cd "$d/evidence" 2>/dev/null && ls | sort | tr '\n' ' ')| $(sed -n 2p "$d/evidence/outside-zero-intervals.tsv" 2>/dev/null | tr '\t' ' ')"
			echo "detail $(failover_outside_zero_detail "$d/metrics.json")"
		)
	fi
	# Wiring: the archive runs right after the capture/gate block, before the
	# gate-success guard (so PASS or FAIL), and the verdict line carries the
	# detail.
	echo "wiring $(python3 - "$f" <<'PY'
import sys
t = open(sys.argv[1]).read()
end = t.find("# M1 JSON capture/gate fixture end")
guard = t.find('if [[ "$iperf_gate_ok" == true ]]; then', end)
call = t.find('failover_archive_evidence "$FAILOVER_ARTIFACT_DIR"', end)
verdict = t.find('limit ${MAX_STREAM_ZERO_INTERVALS} via MAX_STREAM_ZERO_INTERVALS; ${zero_streams_outside_events_total} affected stream(s); ${stream_zero_intervals_total} total)${outside_zero_detail}"')
print("ok" if end >= 0 and 0 <= call < guard and verdict > guard else f"end={end} call={call} guard={guard} verdict={verdict}")
PY
)"
}
result() { sed -n "s/^$1 //p" "$2"; }

want_producer='1 7:5.0-6.0@2026-11-01T13:34:00.762Z'
cells "$producer" "$failover" >"$tmp/real.txt"
[[ "$(result producer "$tmp/real.txt")" == "$want_producer" ]] &&
	ok "the producer lists the outside zero interval (stream 7, 5-6 s, its wall clock) and not the one inside the crash window" ||
	bad "producer: $(result producer "$tmp/real.txt"), want $want_producer"
arch=$(result archive "$tmp/real.txt")
if [[ "$arch" == *"run.json-stream.log"* && "$arch" == *"metrics.json"* && "$arch" == *"outside-zero-intervals.tsv"* && "$arch" == *"| 7 5.0 6.0 2026-11-01T13:34:00.762Z" ]]; then
	ok "the archive holds the json-stream log, the metrics and the interval row"
else
	bad "archive: $arch"
fi
[[ "$(result detail "$tmp/real.txt")" == "stream 7 at 2026-11-01T13:34:00.762Z (+5.0-6.0 s)" ]] &&
	ok "the verdict detail names stream 7 and its wall-clock time" ||
	bad "detail: $(result detail "$tmp/real.txt")"
[[ "$(result wiring "$tmp/real.txt")" == ok ]] &&
	ok "test-failover.sh archives after the capture/gate block, before the verdicts, and the verdict line carries the detail" ||
	bad "wiring: $(result wiring "$tmp/real.txt")"

# Mutations.
# shellcheck disable=SC2016 # sed programs: the $ is literal
sed 's/^                    outside_zero.append(.*$/                    pass/' "$producer" >"$tmp/m1.py"
if cmp -s "$producer" "$tmp/m1.py"; then
	bad "mutation no-list: anchor not found"
else
	cells "$tmp/m1.py" "$failover" >"$tmp/m1.txt"
	[[ "$(result producer "$tmp/m1.txt")" != "$want_producer" && "$(result detail "$tmp/m1.txt")" != *"stream 7"* ]] &&
		ok "mutation no-list: the producer and detail cells fail" || bad "mutation no-list: the cells still pass"
fi
# shellcheck disable=SC2016
sed 's/^\tfor f in "$LOCAL_IPERF_LOG" /\tfor f in /' "$failover" >"$tmp/m2.sh"
if cmp -s "$failover" "$tmp/m2.sh"; then
	bad "mutation archive-skips-log: anchor not found"
else
	cells "$producer" "$tmp/m2.sh" >"$tmp/m2.txt"
	[[ "$(result archive "$tmp/m2.txt")" != *"run.json-stream.log"* ]] &&
		ok "mutation archive-skips-log: the archive cell fails" || bad "mutation archive-skips-log: the archive cell still passes"
fi
# shellcheck disable=SC2016
sed '/^failover_archive_evidence "\$FAILOVER_ARTIFACT_DIR"$/d' "$failover" >"$tmp/m3.sh"
if cmp -s "$failover" "$tmp/m3.sh"; then
	bad "mutation archive-not-called: anchor not found"
else
	cells "$producer" "$tmp/m3.sh" >"$tmp/m3.txt"
	[[ "$(result wiring "$tmp/m3.txt")" != ok ]] &&
		ok "mutation archive-not-called: the wiring cell fails" || bad "mutation archive-not-called: the wiring cell still passes"
fi

echo "failover-evidence selftest: ${pass} passed, ${fail} failed"
[[ "$fail" -eq 0 ]]
