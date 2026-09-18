package api

import "github.com/prometheus/client_golang/prometheus"

func (c *xpfCollector) initBindingDescriptors() {
	c.bindingActiveFlowCount = prometheus.NewDesc(
		"xpf_userspace_binding_active_flow_count",
		"Distinct active flows observed in this binding's flow_cache "+
			"in the last ~650ms (10 epoch ticks × ~65ms debug-state tick; "+
			"snapshot refreshed on each tick). Read by the fairness harness to "+
			"compute the structural CoV ceiling per docs/fairness-regimes.md (#1219).",
		[]string{"binding_slot", "queue_id", "worker_id", "iface"}, nil,
	)
	c.bindingFlowCacheCapacity = prometheus.NewDesc(
		"xpf_userspace_binding_flow_cache_capacity",
		"Flow-cache capacity published by the userspace helper for this binding.",
		[]string{"binding_slot", "queue_id", "worker_id", "iface"}, nil,
	)
	c.bindingTXCompletions = prometheus.NewDesc(
		"xpf_userspace_binding_tx_completions_total",
		"Cumulative AF_XDP TX completions reaped by this binding's owner worker (#1241).",
		[]string{"binding_slot", "queue_id", "worker_id", "iface"}, nil,
	)
	c.bindingTXCompletionRingAvailable = prometheus.NewDesc(
		"xpf_userspace_binding_tx_completion_ring_available",
		"Last sampled AF_XDP TX completion-ring descriptors available before the owner worker drained completions (#1241).",
		[]string{"binding_slot", "queue_id", "worker_id", "iface"}, nil,
	)
	c.bindingTXCompletionRingAvailableMax = prometheus.NewDesc(
		"xpf_userspace_binding_tx_completion_ring_available_max",
		"Maximum sampled AF_XDP TX completion-ring descriptors available in the last debug window (#1241).",
		[]string{"binding_slot", "queue_id", "worker_id", "iface"}, nil,
	)
	// #1831 (follow-up to #1766): per-binding V_min fairness-throttle
	// counters (#941 work item D / #943), already carried in
	// BindingStatus on the wire but previously unexported.
	c.bindingVMinThrottles = prometheus.NewDesc(
		"xpf_userspace_binding_v_min_throttles_total",
		"V_min fairness-brake throttle decisions on this binding's "+
			"shared-exact CoS queues: a drain batch early-broke because the "+
			"queue's virtual time ran more than LAG_THRESHOLD ahead of the "+
			"slowest participating peer worker's V_min (#917/#943). Non-zero "+
			"under load confirms the cross-worker brake is engaged; the "+
			"hard-cap-overrides / throttles ratio is the diagnostic for "+
			"LAG_THRESHOLD tuned too tight.",
		[]string{"binding_slot", "queue_id", "worker_id", "iface"}, nil,
	)
	c.bindingVMinThrottleHardCapOverrides = prometheus.NewDesc(
		"xpf_userspace_binding_v_min_throttle_hard_cap_overrides_total",
		"V_MIN_CONSECUTIVE_SKIP_HARD_CAP escape-hatch activations on this "+
			"binding: after that many back-to-back V_min throttle decisions "+
			"the drain force-continues and arms suspension — 'brake too "+
			"tight, escape hatch rescued throughput' (#941 work item D). "+
			"Counted distinctly from (not a subset of) "+
			"xpf_userspace_binding_v_min_throttles_total.",
		[]string{"binding_slot", "queue_id", "worker_id", "iface"}, nil,
	)
	// #10131: per-binding fragment-overlap attribution, split by the
	// reason that caused the drop. Emit zeros too, so a binding's absence of
	// overlap is distinguishable from an unavailable status snapshot.
	c.bindingFragOverlapDropped = prometheus.NewDesc(
		"xpf_userspace_binding_frag_overlap_drops_total",
		"Fragment-overlap drops observed by this userspace binding (#10131).",
		[]string{"binding_slot", "queue_id", "worker_id", "iface"}, nil,
	)
	c.bindingFragOverlapOverflowDropped = prometheus.NewDesc(
		"xpf_userspace_binding_frag_overlap_overflow_drops_total",
		"Fragment-overlap drops caused by fragment-range overflow on this binding (#10131).",
		[]string{"binding_slot", "queue_id", "worker_id", "iface"}, nil,
	)
	c.bindingFragOverlapShardFullDropped = prometheus.NewDesc(
		"xpf_userspace_binding_frag_overlap_shard_full_drops_total",
		"Fragment-overlap drops caused by a full overlap shard on this binding (#10131).",
		[]string{"binding_slot", "queue_id", "worker_id", "iface"}, nil,
	)
	c.bindingFragOverlapPostNATDropped = prometheus.NewDesc(
		"xpf_userspace_binding_frag_overlap_post_nat_drops_total",
		"Post-NAT fragment-overlap drops observed by this userspace binding (#10131).",
		[]string{"binding_slot", "queue_id", "worker_id", "iface"}, nil,
	)
	c.bindingFragOverlapMaxLifetimeEvictions = prometheus.NewDesc(
		"xpf_userspace_binding_frag_overlap_max_lifetime_evictions_total",
		"Fragment-overlap entries evicted at maximum lifetime on this binding (#10131).",
		[]string{"binding_slot", "queue_id", "worker_id", "iface"}, nil,
	)
	// #7409: per-binding slow-path reinject counters, split by disposition.
	// The frames counted here left the userspace dataplane WITHOUT being
	// adjudicated and were forwarded by the kernel FIB — there is no
	// nftables `hook forward` chain behind them, so no zone policy, session,
	// NAT or screen applied. Emitted UNCONDITIONALLY per binding so a 0 is a
	// real "nothing was reinjected" signal rather than an absent series;
	// alerting on the absence of a series is what let this stay invisible.
	c.bindingSlowPathNoRoutePackets = prometheus.NewDesc(
		"xpf_userspace_binding_slow_path_no_route_packets_total",
		"Transit frames reinjected to the kernel because the userspace FIB "+
			"had no route for the destination (#7409). Each one was forwarded "+
			"by the kernel with NO zone policy, session, NAT or screen. A "+
			"sustained non-zero rate means the helper FIB disagrees with the "+
			"kernel FIB — the usual cause is a learned (BGP/OSPF/IS-IS/RIP or "+
			"DHCP) route that has not yet been imported into a snapshot, since "+
			"the FIB refreshes only on commit and ip-monitoring actuation.",
		[]string{"binding_slot", "queue_id", "worker_id", "iface"}, nil,
	)
	c.bindingSlowPathNextTablePackets = prometheus.NewDesc(
		"xpf_userspace_binding_slow_path_next_table_packets_total",
		"RETIRED by #6664 and frozen at its last value: NextTableUnsupported "+
			"is no longer reinjected to the kernel, so this counter no longer "+
			"advances. It is still exported so an existing dashboard or alert "+
			"does not break on a missing series. Use "+
			"xpf_userspace_binding_next_table_unsupported_drops_total instead — "+
			"the same packets, now counted where they are dropped.",
		[]string{"binding_slot", "queue_id", "worker_id", "iface"}, nil,
	)
	c.bindingNextTableUnsupportedDrops = prometheus.NewDesc(
		"xpf_userspace_binding_next_table_unsupported_drops_total",
		"Transit frames DROPPED fail-closed because they hit an inter-VRF "+
			"next-table chain the helper cannot resolve — deeper than the "+
			"eight-table limit, or a cycle (#6664). Before #6664 these were "+
			"reinjected to the kernel, which forwarded them with no zone "+
			"policy, session, NAT or screen. Unlike no_route the condition is "+
			"not transient — no FIB refresh resolves it — so delegating was a "+
			"standing policy bypass rather than a window. A non-zero value "+
			"means an operator config defect: an over-deep or cyclic "+
			"next-table chain. An attacker cannot create this condition.",
		[]string{"binding_slot", "queue_id", "worker_id", "iface"}, nil,
	)
	c.bindingTableUnavailableDrops = prometheus.NewDesc(
		"xpf_userspace_binding_table_unavailable_drops_total",
		"Transit frames DROPPED fail-closed because the session's installing "+
			"table is not resolvable in the current config — retired/unknown "+
			"routing instance, or an owner change (#9752). Unlike no_route "+
			"there is nothing to delegate: no table the kernel FIB could "+
			"correctly forward. A non-zero value during steady config means "+
			"HA/config skew worth investigating.",
		[]string{"binding_slot", "queue_id", "worker_id", "iface"}, nil,
	)
	c.bindingTableUnavailablePackets = prometheus.NewDesc(
		"xpf_userspace_binding_table_unavailable_packets_total",
		"Frames observed with a TableUnavailable disposition on the fast path "+
			"(#9752 round 5): every frame whose session resolved terminal. A "+
			"superset of table_unavailable_drops (which counts only slow-path "+
			"allow-list refusals); packets that resolve terminal but never "+
			"reach the slow path appear here only.",
		[]string{"binding_slot", "queue_id", "worker_id", "iface"}, nil,
	)
	c.bindingSlowPathLocalDeliveryPackets = prometheus.NewDesc(
		"xpf_userspace_binding_slow_path_local_delivery_packets_total",
		"Frames delivered to the local host stack via the slow path (#7409). "+
			"NOT a bypass: host-inbound admission is gated on all three "+
			"delivery paths by host_inbound_gated_lo0_action plus the kernel "+
			"nft xpf_hostinbound `hook input` chain, so transit forward policy "+
			"is deliberately not the authority here. Exported for volume "+
			"context alongside the other reinject reasons.",
		[]string{"binding_slot", "queue_id", "worker_id", "iface"}, nil,
	)
	c.bindingSlowPathMissingNeighborPackets = prometheus.NewDesc(
		"xpf_userspace_binding_slow_path_missing_neighbor_packets_total",
		"Transit frames reinjected because the next-hop's ARP/NDP entry was "+
			"unresolved while the userspace prober ran (#7409). Zone policy IS "+
			"enforced on the flowless branch of this arm (#4024). Expect a "+
			"transient burst on a cold neighbour table; a sustained rate means "+
			"neighbour resolution is failing for a live next-hop.",
		[]string{"binding_slot", "queue_id", "worker_id", "iface"}, nil,
	)
}
