package api

import "github.com/prometheus/client_golang/prometheus"

func (c *xpfCollector) initNeighborDescriptors() {
	// #1636 option C: proactive-neighbor-warm telemetry.
	c.neighborWarmDropsTotal = prometheus.NewDesc(
		"xpf_userspace_neighbor_warm_drops_total",
		"Proactive neighbor-warm requests dropped because the bounded warmer queue was full (transient saturation under route churn) (#1636).",
		nil, nil,
	)
	c.neighborWarmDisconnectedTotal = prometheus.NewDesc(
		"xpf_userspace_neighbor_warm_disconnected_total",
		"Proactive neighbor-warm requests dropped because the warmer worker thread died; warming is disabled until daemon restart (#1636).",
		nil, nil,
	)
	// #1782 cold-start capture instrumentation.
	c.negNeighFastFailTotal = prometheus.NewDesc(
		"xpf_userspace_neg_neigh_fast_fail_total",
		"Packets fast-failed by the per-worker neighbor negative cache after a pending_neigh timeout armed the 3s lockout (cold-start H1 amplifier signal) (#1782).",
		nil, nil,
	)
	c.pendingNeighDuplicateDropsTotal = prometheus.NewDesc(
		"xpf_userspace_pending_neigh_duplicate_drops_total",
		"MissingNeighbor sibling packets recycled because the (egress_ifindex, next_hop) key was already pending in pending_neigh (cold-start H5 sibling-drop signal; excludes the MAX_PENDING_NEIGH capacity-drop case) (#1782).",
		nil, nil,
	)
	c.pendingNeighDecapDropsTotal = prometheus.NewDesc(
		"xpf_userspace_pending_neigh_decap_drops_total",
		"GRE-decapped MissingNeighbor packets refused pending_neigh admission: the buffered descriptor would pair the un-decapped OUTER UMEM frame with the post-decap INNER meta, and the neighbor-resolution retry would TX a mis-rewritten outer packet (#1902).",
		nil, nil,
	)
	c.pendingNeighCapacityDropsTotal = prometheus.NewDesc(
		"xpf_userspace_pending_neigh_capacity_drops_total",
		"MissingNeighbor packets for a NEW distinct (egress_ifindex, next_hop) dropped because the per-binding pending_neigh map is at MAX_PENDING_NEIGH distinct unresolved hops — distinct-hop neighbor exhaustion (a scan or upstream outage hitting many cold next hops). Counted separately from xpf_userspace_pending_neigh_duplicate_drops_total, which is normal cold-start coalescing of siblings for an already-pending hop (#2375).",
		nil, nil,
	)
	c.dynamicNeighborLearnCapDropsTotal = prometheus.NewDesc(
		"xpf_userspace_dynamic_neighbor_learn_cap_drops_total",
		"Data-path neighbor learns refused because the shared dynamic_neighbors map's target shard was at MAX_DYNAMIC_NEIGHBORS_PER_SHARD. Source-address learning runs on RX BEFORE screen/policy admission, so this is the always-on signal that the aggregate neighbor-map cap is bounding a spoofed-source pre-policy flood (a CPU/memory DoS an attacker on an untrusted segment could otherwise drive). A rising value means over-cap new learns are being refused; already-learned neighbors and their MAC failovers are unaffected (#5673).",
		nil, nil,
	)
	c.dynamicNeighborPresent = prometheus.NewDesc(
		"xpf_userspace_dynamic_neighbor_present",
		"Per-key presence gauge (always 1) dumped from the helper userspace dynamic_neighbors mirror so the cold-start capture harness can grep the pre-connect t0' next-hop membership (the H2 absence fingerprint) (#1782). DEBUG-ONLY: gated behind the helper's XPF_DEBUG_NEIGHBOR_KEYS env var and absent by default — an absent metric family means the dump is disabled, NOT that dynamic_neighbors is empty.",
		[]string{"ifindex", "ip"}, nil,
	)
	c.ndpNaFragRefusedTotal = prometheus.NewDesc(
		"xpf_userspace_ndp_na_frag_refused_total",
		"NDP Neighbor Advertisement learns refused because the IPv6 chain carried a Fragment header; this is the RFC 6980 learn-refusal counter (#10097).",
		nil, nil,
	)
	c.ndpNaBadSourceRefusedTotal = prometheus.NewDesc(
		"xpf_userspace_ndp_na_bad_source_refused_total",
		"NDP Neighbor Advertisement learns refused because the IPv6 source was not valid on-link unicast (#10097).",
		nil, nil,
	)
	// #1769: on-demand neighbor-resolver telemetry — operator-visible
	// signal for the MissingNeighbor negative-cache stuck-state.
	c.neighborResolverQueueDepth = prometheus.NewDesc(
		"xpf_userspace_neighbor_resolver_queue_depth",
		"On-demand neighbor-resolver queue depth: dsts queued for a single-key RTM_GETNEIGH after a MissingNeighbor negative-cache fast-fail but not yet processed (gauge) (#1769).",
		nil, nil,
	)
	c.neighborResolverEnqueueDropsTotal = prometheus.NewDesc(
		"xpf_userspace_neighbor_resolver_enqueue_drops_total",
		"On-demand neighbor-resolver enqueue attempts dropped because the bounded queue was full (transient; the dst still fast-fails this round) (#1769).",
		nil, nil,
	)
	c.neighborResolverDisconnectedTotal = prometheus.NewDesc(
		"xpf_userspace_neighbor_resolver_disconnected_total",
		"On-demand neighbor-resolver enqueue attempts dropped because the resolver worker thread died; on-demand resolution is disabled until daemon restart (#1769).",
		nil, nil,
	)
	c.neighborResolverGetAttemptsTotal = prometheus.NewDesc(
		"xpf_userspace_neighbor_resolver_get_attempts_total",
		"Single-key RTM_GETNEIGH requests issued by the on-demand resolver (after the per-key rate-limit coalesces a SYN storm) (#1769).",
		nil, nil,
	)
	c.neighborResolverGetResolvedTotal = prometheus.NewDesc(
		"xpf_userspace_neighbor_resolver_get_resolved_total",
		"On-demand RTM_GETNEIGH replies confirmed REACHABLE/PERMANENT and cached into the dynamic neighbor map (epoch guard passed) (#1769).",
		nil, nil,
	)
	c.neighborResolverProbeOnStaleTotal = prometheus.NewDesc(
		"xpf_userspace_neighbor_resolver_probe_on_stale_total",
		"On-demand RTM_GETNEIGH replies in STALE/DELAY/PROBE that triggered a revalidation probe instead of caching the unconfirmed MAC (the live #1769 wedge state) (#1769).",
		nil, nil,
	)
	c.neighborResolverGetFailuresTotal = prometheus.NewDesc(
		"xpf_userspace_neighbor_resolver_get_failures_total",
		"On-demand RTM_GETNEIGH attempts with no usable reply (timeout, FAILED, INCOMPLETE, no entry, or recv/parse error) (#1769).",
		nil, nil,
	)
	c.neighborResolverEpochRejectsTotal = prometheus.NewDesc(
		"xpf_userspace_neighbor_resolver_epoch_rejects_total",
		"Confirmed on-demand inserts skipped because the global neighbor epoch advanced between enqueue and the GET reply (epoch guard rejected a potentially-raced stale insert) (#1769).",
		nil, nil,
	)
	// #1772: neighbor/ARP resolution LATENCY metrics. The two
	// histograms localize where an intermittent slow new connection
	// spends its time: pending-buffer dwell vs resolver GETNEIGH RTT.
	c.neighborPendingDwellSeconds = prometheus.NewDesc(
		"xpf_userspace_neighbor_pending_dwell_seconds",
		"Histogram of how long a packet sat in the pending-neighbor buffer before its neighbor resolved and it was dispatched (now-queued at the retry-sweep success path). The 3 s blackout class from #1769 lands in the +Inf tail (#1772).",
		nil, nil,
	)
	c.neighborResolverGetRttSeconds = prometheus.NewDesc(
		"xpf_userspace_neighbor_resolver_get_rtt_seconds",
		"Histogram of the on-demand resolver single-key RTM_GETNEIGH round-trip time (request sent to reply read) on the resolver thread (#1772).",
		nil, nil,
	)
	c.neighborPendingTimeoutDropsTotal = prometheus.NewDesc(
		"xpf_userspace_neighbor_pending_timeout_drops_total",
		"Pending-neighbor packets dropped after exceeding PENDING_NEIGH_TIMEOUT without resolving (never reached a usable neighbor within the window) (#1772).",
		nil, nil,
	)
	c.neighborPendingMaxDepth = prometheus.NewDesc(
		"xpf_userspace_neighbor_pending_max_depth",
		"High-water mark of the per-binding pending-neighbor queue depth observed at any retry-sweep entry (gauge) (#1772).",
		nil, nil,
	)
	// #1771 §2.6: resolver backoff + §2.5 ENOBUFS/re-dump telemetry.
	c.neighborResolverGetBackoffAttemptsTotal = prometheus.NewDesc(
		"xpf_userspace_neighbor_resolver_get_backoff_attempts_total",
		"On-demand resolver GET attempts that were backoff RETRIES: the key had already been attempted within the resolver's per-key memory and was re-admitted after the per-key rate-limit window. Subset of get_attempts; a rising rate means the same next-hops keep failing to resolve. Per invariant N1 (#1771 §2.4) these retries keep firing even while the key is negatively cached.",
		nil, nil,
	)
	c.neighborNetlinkEnobufsTotal = prometheus.NewDesc(
		"xpf_userspace_neighbor_netlink_enobufs_total",
		"ENOBUFS receives on the neighbor-monitor netlink socket: the kernel dropped RTM_NEWNEIGH/DELNEIGH multicast notifications on rcvbuf overflow (the lost-notification desync class the throttled upsert-only re-dump self-heals) (#1771 §2.5).",
		nil, nil,
	)
	c.neighborNetlinkRedumpsTotal = prometheus.NewDesc(
		"xpf_userspace_neighbor_netlink_redumps_total",
		"Throttled (5s) upsert-only neighbor-table re-dumps issued after an ENOBUFS (at least one of the v4/v6 dump requests was sent) (#1771 §2.5).",
		nil, nil,
	)
	c.neighborNetlinkRedumpUpsertsTotal = prometheus.NewDesc(
		"xpf_userspace_neighbor_netlink_redump_upserts_total",
		"Dynamic-neighbor entries (re)added by an upsert-only re-dump reply — RTM_NEWNEIGH dump replies whose insert changed the map. Nonzero proves a re-dump repopulated keys that lost multicast events had desynced (#1771 §2.5).",
		nil, nil,
	)
	c.neighborPendingKeys = prometheus.NewDesc(
		"xpf_userspace_neighbor_pending_keys",
		"Distinct unresolved (egress_ifindex, next_hop) keys currently holding a buffered packet in the per-binding pending_neigh maps, summed across bindings (gauge; refreshed at the ~65ms per-binding debug tick) (#1771 §2.6).",
		nil, nil,
	)
	c.negNeighKeys = prometheus.NewDesc(
		"xpf_userspace_neg_neigh_keys",
		"Keys currently held in the per-binding negative neighbor caches, summed across bindings (gauge; lazy-TTL upper bound — an expired entry stays counted until its next access) (#1771 §2.6).",
		nil, nil,
	)
	// #3773 (M13): fabric-link skip diagnostics.
	c.fabricLinkSkippedMalformedTotal = prometheus.NewDesc(
		"xpf_userspace_fabric_link_skipped_malformed_total",
		"HA cross-chassis fabric links skipped during a forwarding build/refresh because a value was MALFORMED: an invalid parent ifindex, an unparseable peer address, or a non-empty local/peer MAC string that failed to parse. Non-zero (especially climbing) is a fabric config/environment fault an operator must fix; the helper journal names which fabric and why. Before #3773 these were silent (no counter, log, or status) (#3773 M13).",
		nil, nil,
	)
	c.fabricLinkUnresolvedPeerTotal = prometheus.NewDesc(
		"xpf_userspace_fabric_link_unresolved_peer_total",
		"HA cross-chassis fabric links skipped during a forwarding build/refresh because a peer or local MAC was UNRESOLVED: an EMPTY MAC field still awaiting neighbor/interface resolution (the expected late-resolution SyncFabricState transient). Briefly non-zero at startup is normal; a persistently climbing value means a fabric peer is not resolving. A distinct, non-malformed state vs xpf_userspace_fabric_link_skipped_malformed_total (#3773 M13).",
		nil, nil,
	)
}
