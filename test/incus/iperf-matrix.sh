#!/bin/bash
# Throughput and stall matrix (docs/regression-test-matrix.md rows F2/F6).
#
# Usage: iperf-matrix.sh <outdir> [duration-s] [reps]
#        iperf-matrix.sh --selftest
#
# Runs iperf3 -J from the cluster LAN host for v4/v6 x push/reverse x
# -P1/-P8/-P12 against the env's IPERF_TARGET4/6 on IPERF_PORT (default 5211,
# the unshaped class; 5201 is the lab CoS config's 100 Mbit/s exact class,
# #9691) and records one summary line
# per run. Throughput numbers are recorded, not judged: each cluster has its
# own band, and a band compared without loadavg is not a measurement. What the
# matrix DOES judge is the user-visible failure "the iperf stops":
#   - a run that errors or fails to connect;
#   - any 1 s interval whose aggregate is under 25% of the run's peak
#     (healthy runs on loss and tcp never dip below 74% of their peak; a
#     median-relative test misses a stall that covers most of the run);
#   - any 1 s interval in which a single stream moves under 1 Mbit/s.
# Any of these FAILs the matrix (exit 1). A run whose JSON cannot be parsed,
# or that recorded no intervals, is a FAIL too: an empty measurement must
# never read as a clean one.
#
# The caller holds the cluster lock (`make perf-matrix` wraps this in
# with-cluster.sh). BPFRX_CLUSTER_ENV selects the cluster. Each run writes a
# fresh <outdir>/<UTC timestamp>-<pid>/ directory and prints its path.
set -u

verdict() { # <json-file>: prints the summary line; exit 0 clean, 1 stalled/failed
	python3 -I - "$1" <<'PY'
import json, statistics, sys

path = sys.argv[1]
try:
    with open(path) as f:
        d = json.load(f)
except Exception as e:  # noqa: BLE001 - any unreadable result is a FAIL
    print(f"FAIL parse-error={type(e).__name__}")
    sys.exit(1)
if "error" in d:
    connected = len(d.get("start", {}).get("connected", []))
    print(f"FAIL iperf-error={d['error'][:120]!r} streams_connected={connected}")
    sys.exit(1)
intervals = d.get("intervals", [])
agg = [i["sum"]["bits_per_second"] / 1e9 for i in intervals]
if not agg:
    print("FAIL no-intervals")
    sys.exit(1)
end = d.get("end", {})
sent = end.get("sum_sent", {})
recv = end.get("sum_received", {})
med = statistics.median(agg)
peak = max(agg)
low = [n for n, x in enumerate(agg) if x < 0.25 * peak]
stream_stalls = sum(
    1 for i in intervals for s in i.get("streams", []) if s["bits_per_second"] < 1e6
)
bad = bool(low) or stream_stalls > 0 or peak <= 0
print(
    f"{'FAIL' if bad else 'ok'} sent={sent.get('bits_per_second', 0) / 1e9:.2f} "
    f"recv={recv.get('bits_per_second', 0) / 1e9:.2f} retr={sent.get('retransmits', '-')} "
    f"med_iv={med:.2f} peak_iv={peak:.2f} min_iv={min(agg):.2f} low_iv={low} stream_stall_iv={stream_stalls} "
    f"n_iv={len(agg)}"
)
sys.exit(1 if bad else 0)
PY
}

selftest() {
	local dir rc fails=0
	dir=$(mktemp -d "${TMPDIR:-/var/tmp}/iperf-matrix-selftest.XXXXXX") || return 1
	# shellcheck disable=SC2064
	trap "rm -rf '$dir'" RETURN
	python3 -I - "$dir" <<'PY'
import json, sys

out = sys.argv[1]

def run(aggs, streams=None):
    ivs = []
    for n, a in enumerate(aggs):
        per = streams[n] if streams else [a * 1e9 / 2] * 2
        ivs.append({"sum": {"bits_per_second": a * 1e9},
                    "streams": [{"bits_per_second": b} for b in per]})
    return {"intervals": ivs, "end": {"sum_sent": {"bits_per_second": 1e10, "retransmits": 0},
                                      "sum_received": {"bits_per_second": 1e10}}}

cases = {
    "healthy": run([10.0] * 10),
    # A stall covering most of the run: its median is the stalled rate, so a
    # median-relative test reads it clean.
    "long-stall": run([20.0] * 9 + [0.002] * 11,
                      [[1e10, 1e10]] * 9 + [[1e6 + 1, 1e6 + 1]] * 11),
    # The aggregate collapses to 5% of the median for two seconds while every
    # stream still moves more than 1 Mbit/s: only the aggregate term sees it.
    "aggregate-stall": run([10.0] * 5 + [0.5, 0.5] + [10.0] * 3,
                           [[5e9, 5e9]] * 5 + [[2.5e8, 2.5e8]] * 2 + [[5e9, 5e9]] * 3),
    # The "iperf stops" shape: everything falls to zero for two seconds.
    "total-stall": run([10.0] * 5 + [0.0, 0.0] + [10.0] * 3),
    # One stream dies while the others take its share: the aggregate looks fine.
    "one-stream-stall": run([10.0] * 4, [[5e9, 5e9]] * 3 + [[1e10, 0.0]]),
    "iperf-error": {"error": "unable to connect to server", "start": {"connected": []}},
    "no-intervals": {"intervals": [], "end": {}},
}
for name, body in cases.items():
    with open(f"{out}/{name}.json", "w") as f:
        json.dump(body, f)
with open(f"{out}/unparseable.json", "w") as f:
    f.write("{truncated")
PY
	# name:expected-rc. Only "healthy" may pass; every other row is a shape
	# that once read as clean somewhere in this tree.
	for cell in healthy:0 long-stall:1 aggregate-stall:1 total-stall:1 one-stream-stall:1 iperf-error:1 no-intervals:1 unparseable:1; do
		verdict "$dir/${cell%%:*}.json" >/dev/null
		rc=$?
		if [ "$rc" = "${cell##*:}" ]; then
			echo "  PASS  ${cell%%:*} -> rc=$rc"
		else
			echo "  FAIL  ${cell%%:*} -> rc=$rc, want ${cell##*:}"
			fails=$((fails + 1))
		fi
	done
	[ "$fails" = 0 ] && echo "iperf-matrix selftest: PASS" || echo "iperf-matrix selftest: $fails FAILED"
	[ "$fails" = 0 ]
}

case "${1:-}" in
--selftest)
	selftest
	exit $?
	;;
esac

BASE=${1:?usage: iperf-matrix.sh <outdir> [duration-s] [reps] | --selftest}
DUR=${2:-20}
PORT=${IPERF_PORT:-5211}
REPS=${3:-1}
cd "$(dirname "$0")/../.." || exit 1
# shellcheck source=/dev/null
source test/incus/cluster-env.sh
case "$IPERF_TARGET4" in
172.16.100.*)
	echo "iperf-matrix: refusing IPERF_TARGET4=$IPERF_TARGET4: 172.16.100.x is the capped uplink, not the cluster's data path (see CLAUDE.md)" >&2
	exit 2
	;;
esac
# Every run gets its own directory, so a rerun or another cluster's run can
# never leave an older PASS or JSON file where this run's verdict is read.
OUT="$BASE/$(date -u +%Y%m%dT%H%M%SZ)-$$"
mkdir -p "$OUT" || exit 1
echo "iperf-matrix: writing $OUT"
# The orchestrator is not where the VMs run, so record the guests' load too.
loadavgs() {
	local n
	echo "orchestrator $(cat /proc/loadavg)"
	for n in "$FW0" "$FW1" "$CLUSTER_LAN_HOST"; do
		echo "$n $(incus exec "$n" -- cat /proc/loadavg 2>/dev/null || echo unavailable)"
	done
}
loadavgs >"$OUT/loadavg.before"
fails=0
for rep in $(seq 1 "$REPS"); do
	for fam in 4 6; do
		target=$IPERF_TARGET4
		[ "$fam" = 6 ] && target=$IPERF_TARGET6
		for dir in push reverse; do
			rev=()
			[ "$dir" = reverse ] && rev=(-R)
			for p in 1 8 12; do
				tag="v${fam}-${dir}-P${p}-r${rep}"
				timeout $((DUR + 40)) incus exec "$CLUSTER_LAN_HOST" -- \
					iperf3 -c "$target" -p "$PORT" -P "$p" -t "$DUR" "${rev[@]}" -J --connect-timeout 5000 \
					>"$OUT/$tag.json" 2>"$OUT/$tag.err"
				rc=$?
				line=$(verdict "$OUT/$tag.json")
				vrc=$?
				# A killed or failed client is a FAIL even if it left valid JSON.
				if [ "$vrc" != 0 ] || [ "$rc" != 0 ]; then
					fails=$((fails + 1))
				fi
				echo "$tag rc=$rc $line" | tee -a "$OUT/summary.txt"
				sleep 2
			done
		done
	done
done
loadavgs >"$OUT/loadavg.after"
{
	echo "loadavg before:"
	sed 's/^/  /' "$OUT/loadavg.before"
	echo "loadavg after:"
	sed 's/^/  /' "$OUT/loadavg.after"
} | tee -a "$OUT/summary.txt"
if [ "$fails" = 0 ]; then
	echo "RESULT: PASS (no stalls, no errors)" | tee -a "$OUT/summary.txt"
	exit 0
fi
echo "RESULT: FAIL ($fails runs stalled or errored)" | tee -a "$OUT/summary.txt"
exit 1
