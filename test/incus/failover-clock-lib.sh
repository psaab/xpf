#!/usr/bin/env bash
#
# Clock resync for the crash-failover smokes (#11872).
#
# The loss lab has no NTP anywhere, and a crash reboot comes back with the
# guest clock behind (measured 2m18s on fw0): the skew breaks fabric-auth
# windows and heartbeat freshness, stretches the rejoin bulk past the failback
# budget, and gets every manual failback refused at the peer barrier — while a
# manual resync unblocked all three transfers immediately. The smokes therefore
# resync both nodes from the host clock after the crash-reboot wait, before
# any failback/takeover phase.

# failover_resync_node_clocks <node>...
#   Set every named node's wall clock from a SINGLE host reading, so the nodes
#   agree with each other: inter-node skew is what breaks the fabric-auth
#   windows, and one reading keeps them identical by construction rather than
#   by two readings that happen to fall in the same second.
#   Prints one line per node ("set ..." / "FAILED ..."); returns 0 only if
#   every node was set. Every node is ATTEMPTED even when an earlier one
#   failed, so one down node does not hide the other's outcome.
#   FAILOVER_CLOCK_NOW overrides the host reading (hermetic self-test seam).
failover_resync_node_clocks() {
	if (($# == 0)); then
		echo "failover_resync_node_clocks: no nodes given" >&2
		return 1
	fi
	local now="${FAILOVER_CLOCK_NOW:-$(date -u '+%Y-%m-%d %H:%M:%S')}"
	local node rc=0
	for node in "$@"; do
		if incus exec "$node" -- date -u -s "$now" >/dev/null 2>&1; then
			echo "clock resync: $node set to ${now} UTC"
		else
			echo "clock resync: FAILED to set $node to ${now} UTC" >&2
			rc=1
		fi
	done
	return "$rc"
}
