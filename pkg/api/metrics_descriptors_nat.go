package api

import "github.com/prometheus/client_golang/prometheus"

func (c *xpfCollector) initNATDescriptors() {
	c.natPoolUsedPorts = prometheus.NewDesc(
		"xpf_nat_pool_used_ports",
		"Number of used ports in a NAT pool.",
		[]string{"pool"}, nil,
	)
	c.natPoolTotalPorts = prometheus.NewDesc(
		"xpf_nat_pool_total_ports",
		"Total available ports in a NAT pool.",
		[]string{"pool"}, nil,
	)
	c.natPoolDeterministicInfo = prometheus.NewDesc(
		"xpf_nat_pool_deterministic_info",
		"Deterministic NAT pool configuration (1 = enabled).",
		[]string{"pool", "block_size", "host_count"}, nil,
	)
	c.natPoolDetBlocksTotal = prometheus.NewDesc(
		"xpf_nat_deterministic_pool_blocks_total",
		"Total per-subscriber port-block capacity of a deterministic NAT "+
			"pool (pool addresses x floor(port-range / block-size)). The "+
			"denominator for deterministic-pool block utilization; the "+
			"pool-wide xpf_nat_pool_used_ports metric is meaningless for a "+
			"deterministic pool (#4752).",
		[]string{"pool"}, nil,
	)
	c.natPoolDetBlocksAllocated = prometheus.NewDesc(
		"xpf_nat_deterministic_pool_blocks_allocated",
		"Port blocks statically allocated to the provisioned subscriber "+
			"range of a deterministic NAT pool (one block per subscriber). "+
			"The numerator for block utilization: divide by "+
			"xpf_nat_deterministic_pool_blocks_total and alarm as it "+
			"approaches 1.0 (#4752).",
		[]string{"pool"}, nil,
	)
	c.userspaceSNATPoolLiveFlows = prometheus.NewDesc(
		"xpf_userspace_source_nat_pool_live_flows",
		"Live source NAT pool flow allocations tracked by the userspace dataplane.",
		[]string{"pool", "rule"}, nil,
	)
	// #9896 fold 2: the DENOMINATOR for the live gauge above. A live count
	// without its cap cannot tell "pool nearly refusing" from "pool idle",
	// and the pair is what the pool-utilization alarm's tracked-flow leg
	// evaluates — export it so PromQL can alarm identically.
	c.userspaceSNATPoolMaxTrackedFlows = prometheus.NewDesc(
		"xpf_userspace_source_nat_pool_max_tracked_flows",
		"Source NAT pool tracked-flow cap enforced by the userspace dataplane allocator.",
		[]string{"pool", "rule"}, nil,
	)
	c.userspaceSNATPoolUsedPorts = prometheus.NewDesc(
		"xpf_userspace_source_nat_pool_used_ports",
		"Source NAT pool translated ports currently owned by the userspace dataplane allocator.",
		[]string{"pool", "rule"}, nil,
	)
	c.userspaceSNATPoolPersistentLeases = prometheus.NewDesc(
		"xpf_userspace_source_nat_pool_persistent_leases",
		"Persistent source NAT leases retained by the userspace dataplane allocator.",
		[]string{"pool", "rule"}, nil,
	)
	c.userspaceSNATPoolAllocationsTotal = prometheus.NewDesc(
		"xpf_userspace_source_nat_pool_allocations_total",
		"Total new source NAT pool translated tuple allocations by the userspace dataplane.",
		[]string{"pool", "rule"}, nil,
	)
	c.userspaceSNATPoolReusesTotal = prometheus.NewDesc(
		"xpf_userspace_source_nat_pool_reuses_total",
		"Total source NAT pool live or persistent lease reuses by the userspace dataplane.",
		[]string{"pool", "rule"}, nil,
	)
	// #8447: the persistent-NAT admission PAIR. Exported together because a
	// decline count of zero cannot be told from "this path never ran" on its
	// own, and separating those is the entire question the counters answer.
	c.userspaceSNATPoolPersistentAdmittedTotal = prometheus.NewDesc(
		"xpf_userspace_source_nat_pool_persistent_admitted_total",
		"Total persistent-NAT admissions that produced a translation in the userspace dataplane.",
		[]string{"pool", "rule"}, nil,
	)
	c.userspaceSNATPoolPersistentDeclinedTotal = prometheus.NewDesc(
		"xpf_userspace_source_nat_pool_persistent_declined_total",
		"Total persistent-NAT admissions that returned a failure in the userspace dataplane.",
		[]string{"pool", "rule"}, nil,
	)
	c.userspaceSNATPoolExhaustionsTotal = prometheus.NewDesc(
		"xpf_userspace_source_nat_pool_exhaustions_total",
		"Total source NAT pool allocator exhaustion events in the userspace dataplane.",
		[]string{"pool", "rule"}, nil,
	)
	c.userspaceSNATPoolIdleLeaseImportCapacityTotal = prometheus.NewDesc(
		"xpf_userspace_source_nat_pool_idle_lease_import_capacity_total",
		"Total HA idle-lease imports refused because the bounded persistent-lease table remained full after pressure GC.",
		[]string{"pool", "rule"}, nil,
	)
	c.userspaceSNATPoolFlowShardLockAcquisitionsTotal = prometheus.NewDesc(
		"xpf_userspace_source_nat_pool_flow_shard_lock_acquisitions_total",
		"Counted acquisitions of this source NAT pool's flow-shard mutexes "+
			"(one of 16 shards, #15956) on the counted production paths. The "+
			"DENOMINATOR for the flow-shard contended counter below: a "+
			"contention rate is only interpretable against the acquisition "+
			"rate that produced it. Excludes uncounted shard sites and the "+
			"status-poll snapshot (#4800/#17036).",
		[]string{"pool", "rule"}, nil,
	)
	c.userspaceSNATPoolFlowShardLockContendedTotal = prometheus.NewDesc(
		"xpf_userspace_source_nat_pool_flow_shard_lock_contended_total",
		"Subset of counted flow-shard mutex acquisitions that found the "+
			"shard already held and had to block. Divided by "+
			"..._flow_shard_lock_acquisitions_total this is the sharded "+
			"flow-map share of new-flow-install serialization (#4800/#17036).",
		[]string{"pool", "rule"}, nil,
	)
	c.userspaceSNATPoolLiveWriteLockAcquisitionsTotal = prometheus.NewDesc(
		"xpf_userspace_source_nat_pool_live_write_lock_acquisitions_total",
		"Counted write acquisitions of this source NAT pool's live-state "+
			"RwLock (persistent-lease/ownership/GC state, #15956) on the "+
			"counted production paths, including the non-persistent fast "+
			"path's counted try_write. The DENOMINATOR for the live-write "+
			"contended counter below. Excludes read guards and the "+
			"status-poll snapshot (#4800/#17036).",
		[]string{"pool", "rule"}, nil,
	)
	c.userspaceSNATPoolLiveWriteLockContendedTotal = prometheus.NewDesc(
		"xpf_userspace_source_nat_pool_live_write_lock_contended_total",
		"Subset of counted live-state RwLock write acquisitions that found "+
			"the write guard unavailable and had to block (or, on the fast "+
			"path try_write, contended and fell back). Divided by "+
			"..._live_write_lock_acquisitions_total this is the live-write "+
			"share of new-flow-install serialization (#4800/#17036).",
		[]string{"pool", "rule"}, nil,
	)
	c.userspaceSNATPoolLiveLockAcquisitionsTotal = prometheus.NewDesc(
		"xpf_userspace_source_nat_pool_live_lock_acquisitions_total",
		"Legacy summed counted lock acquisitions for this source NAT pool: "+
			"flow-shard plus live-write acquisitions (#17036). Kept for one "+
			"release for dashboard continuity. Do NOT use its ratio for the "+
			"#15956 perf gate — since #15956 it mixes two lock domains; use "+
			"the flow_shard_lock and live_write_lock pairs instead.",
		[]string{"pool", "rule"}, nil,
	)
	c.userspaceSNATPoolLiveLockContendedTotal = prometheus.NewDesc(
		"xpf_userspace_source_nat_pool_live_lock_contended_total",
		"Legacy summed counted lock contended acquisitions for this source "+
			"NAT pool: flow-shard plus live-write contended acquisitions "+
			"(#17036). Kept for one release. Do NOT divide by "+
			"..._live_lock_acquisitions_total for the #15956 perf gate — "+
			"the population mixes two lock domains; use the split pairs.",
		[]string{"pool", "rule"}, nil,
	)
	c.userspaceSNATPoolRecycleScanPopsTotal = prometheus.NewDesc(
		"xpf_userspace_source_nat_pool_recycle_scan_pops_total",
		"Total recycled-phase port-allocation tokens popped across pool addresses.",
		[]string{"pool", "rule"}, nil,
	)
	c.userspaceSNATPoolRecycleScanWalksTotal = prometheus.NewDesc(
		"xpf_userspace_source_nat_pool_recycle_scan_walks_total",
		"Total recycled-phase port-allocation walks across pool addresses.",
		[]string{"pool", "rule"}, nil,
	)
	// #16547: export InterfaceSNATPoolOverlapStats as the scans/addresses
	// pair its contract requires (scans==0 = detector never ran = unknown,
	// not healthy), plus a per-pool quarantined gauge fed from the applied
	// snapshot verdicts.
	c.ifaceSNATOverlapScansTotal = prometheus.NewDesc(
		"xpf_iface_snat_overlap_scans_total",
		"Total interface source-NAT pool overlap detector scans (#7717). Zero means the detector has never run (unknown, not healthy).",
		nil, nil,
	)
	c.ifaceSNATOverlapAddresses = prometheus.NewDesc(
		"xpf_iface_snat_overlap_addresses",
		"Overlapping (pool, interface-SNAT egress) addresses found at the most recent overlap scan (#7717). Meaningful only when xpf_iface_snat_overlap_scans_total > 0.",
		nil, nil,
	)
	c.ifaceSNATOverlapQuarantined = prometheus.NewDesc(
		"xpf_iface_snat_overlap_quarantined",
		"1 while this source-NAT pool is quarantined by the runtime interface-SNAT egress overlap (#7717/#16547), 0 otherwise.",
		[]string{"pool"}, nil,
	)
}
