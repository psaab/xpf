#!/usr/bin/env bash
#
# step1-classify.sh — Phase B Step 1 classifier (plan §4).
#
# Reads each cell directory under
#   docs/pr/line-rate-investigation/step1-evidence/<cos>/p<port>-<dir>/
# and computes X (flow-count spread per worker), Y (max/min rate ratio),
# Z (park-rate), then emits verdict.txt per cell per plan §4.3.
#
# Called after all step1-capture.sh cells have completed.
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
EVIDENCE="$REPO_ROOT/docs/pr/line-rate-investigation/step1-evidence"
# #13070 (D10-15): Verdict D's per-port shaper cap comes from the shared
# CoS schedule library (pinned to cos-iperf-config.set) instead of a
# classify-local table.
# shellcheck source=cos-apply-lib.sh
source "${SCRIPT_DIR}/cos-apply-lib.sh"

# Z thresholds per plan §4.2.
Z_NOCOS=10
Z_COS=500
# X threshold per plan §4.2: fire A iff max(n_w) >= 9 OR min(n_w) <= 0
# Y threshold per plan §4.2: 2.72
# C threshold per plan §4.2: ring_w/60 >= 50 events/s AND cpu_w < 85%.
RING_THR=50
CPU_HEADROOM=85

classify_cell() {
	local dir="$1"
	local cos="$2"
	local port="$3"
	local cdir="$4"  # fwd|rev

	local iperf="$dir/iperf3.json"
	local cold="$dir/flow_steer_cold.json"
	local post="$dir/flow_steer_post.json"
	local samples="$dir/flow_steer_samples.jsonl"
	local mpstat="$dir/mpstat.txt"
	local ping_s="$dir/ping-small.txt"
	local ping_l="$dir/ping-large.txt"

	if [[ ! -f "$iperf" ]]; then
		echo "p${port}-${cdir}-${cos}: SKIP no-data" > "$dir/verdict.txt"
		return
	fi

	# SUM + retr.
	local sum_gbps retr
	sum_gbps=$(jq -r '(.end.sum_received.bits_per_second // .end.sum_sent.bits_per_second // 0) / 1e9' "$iperf")
	retr=$(jq -r '.end.sum_sent.retransmits // 0' "$iperf")

	# --- Per-worker flow counts (n_w) ---
	# Proxy: per-binding (worker_id) tx_packets delta between cold and post.
	# A flow count is then estimated from total flows (16) × share.
	# Since iperf3 sends 16 flows and fabric has 4 workers, we compute the
	# share per worker and round to integer n_w summing to 16.
	# Per plan §4.1, per-worker load share uses rx_packets delta on the
	# RX-facing binding. For fwd cells, that's ge-0-0-1 (LAN ingress).
	# For rev cells, RX is on ge-0-0-2.80 (WAN ingress). Rather than
	# branch, aggregate rx_packets across ALL bindings per worker —
	# this captures total per-worker work regardless of direction.
	local tx_cold tx_post
	tx_cold=$(jq '[(.status.bindings // []) | group_by(.worker_id) | map({wid: .[0].worker_id, tx: (map(.rx_packets // 0) | add)}) | .[]]' "$cold")
	tx_post=$(jq '[(.status.bindings // []) | group_by(.worker_id) | map({wid: .[0].worker_id, tx: (map(.rx_packets // 0) | add)}) | .[]]' "$post")
	local worker_shares
	worker_shares=$(jq -n --argjson c "$tx_cold" --argjson p "$tx_post" '
	  ($p | map(.wid)) as $wids |
	  $wids | map(. as $w |
	    {wid: $w,
	     delta: ((($p | map(select(.wid == $w)))[0].tx // 0)
	           - (($c | map(select(.wid == $w)))[0].tx // 0))})
	')
	local total_delta
	total_delta=$(echo "$worker_shares" | jq '[.[].delta] | add // 0')
	if [[ "$total_delta" == "0" ]]; then
		total_delta=1  # avoid divide-by-zero
	fi
	# Round per-worker flow count to nearest integer. Use `round`
	# (floor(x+0.5)) so totals stay close to 16 without inflating max.
	local n_arr
	n_arr=$(echo "$worker_shares" | jq -c --argjson td "$total_delta" \
	  '[.[] | (.delta * 16 / $td + 0.5) | floor]')
	local n_max n_min
	n_max=$(echo "$n_arr" | jq 'max')
	n_min=$(echo "$n_arr" | jq 'min')

	# --- Per-flow rate spread (Y) ---
	# read each stream's sender.bits_per_second, trim <0.5*median, compute max/min.
	local y_ratio
	y_ratio=$(jq -r '
	  [.end.streams[].sender.bits_per_second // 0] | sort |
	  (length) as $n |
	  (.[$n/2 | floor]) as $med |
	  map(select(. >= 0.5 * $med)) |
	  (if length > 1 then (max / (min | if . == 0 then 1 else . end)) else 1 end)
	' "$iperf")

	# --- Park rate (B-direct) ---
	# Sum queue_token_starvation_parks delta across cos_interfaces.queues on this cell's port's
	# bandwidth-output term queue. Conservative: sum ALL queues, divide by 60s.
	local park_rate
	local cold_parks post_parks
	cold_parks=$(jq '[(.status.cos_interfaces // [])[] | (.queues // [])[] | (.queue_token_starvation_parks // 0)] | add // 0' "$cold")
	post_parks=$(jq '[(.status.cos_interfaces // [])[] | (.queues // [])[] | (.queue_token_starvation_parks // 0)] | add // 0' "$post")
	park_rate=$(echo "scale=3; ($post_parks - $cold_parks) / 60" | bc)

	# --- Ring pressure (C) ---
	local ring_w_max
	local ring_cold ring_post
	ring_cold=$(jq '[(.status.bindings // []) | group_by(.worker_id) | map({wid: .[0].worker_id, ring: (map((.dbg_tx_ring_full // 0) + (.pending_tx_local_overflow_drops // 0) + (.tx_submit_error_drops // 0) + (.dbg_sendto_enobufs // 0)) | add)}) | .[]]' "$cold")
	ring_post=$(jq '[(.status.bindings // []) | group_by(.worker_id) | map({wid: .[0].worker_id, ring: (map((.dbg_tx_ring_full // 0) + (.pending_tx_local_overflow_drops // 0) + (.tx_submit_error_drops // 0) + (.dbg_sendto_enobufs // 0)) | add)}) | .[]]' "$post")
	ring_w_max=$(jq -n --argjson c "$ring_cold" --argjson p "$ring_post" '
	  ($p | map(.wid)) as $wids |
	  [$wids[] | . as $w |
	    ((($p | map(select(.wid == $w)))[0].ring // 0)
	   - (($c | map(select(.wid == $w)))[0].ring // 0))] |
	  max // 0
	')

	# --- Per-CPU %usage (max) ---
	# mpstat format: "Average:     CPU     %usr ...", we pick the per-CPU avg rows.
	# If mpstat is not installed (firewall image is minimal), fall back
	# to 50 — safely below the 85 % C-verdict gate.
	local cpu_max
	cpu_max=$(awk '/^Average:/ && $2 ~ /^[0-9]+$/ {
		idle=$NF; usage=100-idle; if (usage>max) max=usage
	} END {if (max=="") print "50"; else printf "%.0f", max}' "$mpstat" 2>/dev/null || echo 50)
	if [[ -z "$cpu_max" || "$cpu_max" == "0" ]]; then cpu_max=50; fi

	# --- ping percentiles (p99 proxy) ---
	# The capture uses `ping -q` (quiet) which only emits summary stats,
	# not per-packet timestamps. Extract `rtt min/avg/max/mdev = a/b/c/d`
	# and use `max` as a conservative p99 proxy. (p99 <= max by definition.)
	local small_p99 large_p99
	small_p99=$(grep -oE 'rtt min/avg/max/mdev = [0-9.]+/[0-9.]+/[0-9.]+/[0-9.]+' "$ping_s" 2>/dev/null \
		| awk -F'/' '{print $5}')
	large_p99=$(grep -oE 'rtt min/avg/max/mdev = [0-9.]+/[0-9.]+/[0-9.]+/[0-9.]+' "$ping_l" 2>/dev/null \
		| awk -F'/' '{print $5}')
	[[ -z "$small_p99" ]] && small_p99=0
	[[ -z "$large_p99" ]] && large_p99=0

	# --- Verdict logic ---
	local z_thr
	if [[ "$cos" == "no-cos" ]]; then
		z_thr="$Z_NOCOS"
	else
		z_thr="$Z_COS"
	fi

	local ring_per_s
	ring_per_s=$(echo "scale=2; $ring_w_max / 60" | bc)

	# Shaper max for verdict D (per plan §4.2):
	#   no-cos: 25 Gbps cap
	#   with-cos forward: the port's canonical class cap, from the shared
	#     schedule (cos_port_to_rate_bps / 1e9 — 0.1/1/3/6 Gbps for ports
	#     5201..5204 under cos-iperf-config.set). This table used to
	#     restate a RETIRED 4-port fixture's 1/10/25/0.1 values (D10-08),
	#     miscalculating Verdict D's cap by up to 60x; it now cannot drift
	#     from the fixture the cluster actually runs (#13070 / D10-15).
	#   with-cos reverse: ~20 Gbps (unshaped egress ge-0-0-1, hits 25G)
	local shaper_max
	if [[ "$cos" == "no-cos" ]]; then
		shaper_max=25
	elif [[ "$cdir" == "rev" ]]; then
		shaper_max=20
	else
		if ! shaper_max=$(cos_port_to_rate_bps "$port" | awk '{printf "%.3g", $1 / 1e9}'); then
			echo "step1-classify: no canonical shaper cap for port $port; refusing to guess" >&2
			exit 2
		fi
	fi

	local verdict=""
	local a_fires=0 b_fires=0 c_fires=0
	# A: max(n_w) >= 9 OR min(n_w) <= 0
	if (( n_max >= 9 )) || (( n_min <= 0 )); then a_fires=1; fi
	# C: ring_per_s >= 50 AND cpu_max < 85
	if (( $(echo "$ring_per_s >= $RING_THR" | bc -l) )) && (( cpu_max < CPU_HEADROOM )); then
		c_fires=1
	fi
	# B: park_rate >= z_thr AND y_ratio >= 2.72 AND (NOT A) AND (NOT C)
	if (( $(echo "$park_rate >= $z_thr" | bc -l) )) && \
	   (( $(echo "$y_ratio >= 2.72" | bc -l) )) && \
	   (( a_fires == 0 )) && (( c_fires == 0 )); then
		b_fires=1
	fi

	# Tie-breaks per §4.2:
	# A beats C, A beats B; C beats B.
	if [[ "$a_fires" == "1" ]]; then
		verdict="A"
	elif [[ "$c_fires" == "1" ]]; then
		verdict="C"
	elif [[ "$b_fires" == "1" ]]; then
		verdict="B"
	else
		# D: within 2 Gbps of shaper max?
		local gap
		gap=$(echo "scale=3; $shaper_max - $sum_gbps" | bc)
		local gap_gt_2
		gap_gt_2=$(echo "$gap > 2" | bc -l)
		if [[ "$gap_gt_2" == "1" ]]; then
			verdict="D-escalate"
		else
			verdict="D"
		fi
	fi

	printf "p%s-%s-%s: %s n_max=%d n_min=%d park_rate=%.2f/s rate_spread=%.3f worst_ring_w=%d@%d%% small_p99=%s large_p99=%s sum=%.3f retr=%d\n" \
		"$port" "$cdir" "$cos" "$verdict" \
		"$n_max" "$n_min" "$park_rate" "$y_ratio" "$ring_w_max" "$cpu_max" \
		"$small_p99" "$large_p99" "$sum_gbps" "$retr" \
		> "$dir/verdict.txt"
}

# --- main ---
for cos in with-cos no-cos; do
	for celldir in "$EVIDENCE/$cos"/p*; do
		[[ -d "$celldir" ]] || continue
		local_name=$(basename "$celldir")
		# p5201-fwd etc.
		port=$(echo "$local_name" | sed 's/^p\([0-9]*\)-.*/\1/')
		cdir=$(echo "$local_name" | sed 's/^p[0-9]*-//')
		classify_cell "$celldir" "$cos" "$port" "$cdir"
	done
done

echo "=== verdict summary ==="
for vf in $(find "$EVIDENCE" -name verdict.txt | sort); do
	cat "$vf"
done
