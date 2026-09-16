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
	c.userspaceSNATPoolLiveLockAcquisitionsTotal = prometheus.NewDesc(
		"xpf_userspace_source_nat_pool_live_lock_acquisitions_total",
		"Acquisitions of this source NAT pool's residual live-state mutex "+
			"on the helper's production allocate/reserve/release/rollback/GC "+
			"paths. The DENOMINATOR for the contended counter below: a "+
			"contention rate is only interpretable against the acquisition "+
			"rate that produced it. Excludes the status-poll snapshot, which "+
			"reads these very counters (#4800).",
		[]string{"pool", "rule"}, nil,
	)
	c.userspaceSNATPoolLiveLockContendedTotal = prometheus.NewDesc(
		"xpf_userspace_source_nat_pool_live_lock_contended_total",
		"Subset of source NAT pool live-state mutex acquisitions that found "+
			"the mutex already held and had to block. Divided by "+
			"..._live_lock_acquisitions_total this is the NAT allocator's "+
			"share of new-flow-install serialization — the measurement the "+
			"#2852 Phase-2 sharding decision is gated on (#4800).",
		[]string{"pool", "rule"}, nil,
	)
}
