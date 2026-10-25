package api

import (
	"net"
	"strconv"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
	"github.com/psaab/xpf/pkg/dataplane/mgmtview"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)

func (c *xpfCollector) collectNATPoolMetrics(ch chan<- prometheus.Metric, dp apiRuntimeDataPlane, userspaceStatus *dpuserspace.ProcessStatus) {
	cfg := c.deps.activeConfig()
	if cfg == nil {
		return
	}
	cr := dataplane.LastApplyResultOf(dp)
	if cr == nil {
		return
	}

	// #7000: this gauge is the DENOMINATOR of pool-utilisation alerts, so
	// reporting a figure for a pool the dataplane refused is a monitoring-visible
	// contract break — the alert reads capacity for something that can allocate
	// nothing. Capacity now comes from the compiler's verdict.
	overBudget := config.SourceNATAggregateOverBudgetPools(cfg)
	// #5317: the helper status is fetched ONCE per scrape and shared. Calling
	// runtimeSourceNATPools() here would issue a SECOND control-socket round
	// trip -- which is exactly what #5317 removed, and what
	// TestMetricsCollectFetchesUserspaceStatusOncePerScrape caught when an
	// earlier revision of this change did it.
	//
	// #5046 contract, preserved: a nil status is a failed or absent round trip,
	// not idle usage. Bump the shared scrape-error counter and emit no
	// used-ports sample, rather than degrading every pool to a healthy-looking
	// zero.
	var poolOccupancy map[string]dpuserspace.SourceNATPoolStatus
	if userspaceStatus == nil {
		c.counterReadErrors.Add(1)
	} else {
		poolOccupancy = dpuserspace.SourceNATPoolOccupancy(*userspaceStatus)
	}
	// #16547: the overlap detector's scans/addresses pair. Emitted on
	// every scrape (even with no pools) so scans==0 reads as "never ran".
	if c.ifaceSNATOverlapScansTotal != nil && c.ifaceSNATOverlapAddresses != nil {
		scans, addrs := dpuserspace.InterfaceSNATPoolOverlapStats()
		c.emitConstMetric(ch, c.ifaceSNATOverlapScansTotal, prometheus.CounterValue, float64(scans))
		c.emitConstMetric(ch, c.ifaceSNATOverlapAddresses, prometheus.GaugeValue, float64(addrs))
	}
	// Runtime quarantine verdicts from the applied snapshot (#16547):
	// a quarantined pool installs nothing, so its capacity/usage samples
	// are omitted exactly like a config-refused pool's.
	var runtimePools map[string]string
	if provider, ok := mgmtview.Probe(dp).(interface {
		AppliedNATSnapshotVerdicts() dpuserspace.AppliedNATSnapshotVerdicts
	}); ok {
		if v := provider.AppliedNATSnapshotVerdicts(); v.Available {
			runtimePools = v.SourceNATPools
		}
	}
	for name, pool := range cfg.Security.NAT.SourcePools {
		if pool == nil {
			// Tolerant restore and HA peer-sync may preserve nil map values.
			// A missing pool has no capacity or usage metrics to report.
			continue
		}
		portLow, portHigh := pool.PortLow, pool.PortHigh
		if portLow == 0 {
			portLow = 1024
		}
		if portHigh == 0 {
			portHigh = 65535
		}
		ports, cfgUnusable := config.SourceNATPoolReportablePorts(pool, name, portLow, portHigh, overBudget)
		unusable := cfgUnusable
		if unusable == "" {
			unusable = runtimePools[name]
		}
		// #16547: per-pool quarantine gauge (1 = quarantined). Emitted for
		// every configured pool so a cleared quarantine reads 0, not absent.
		if c.ifaceSNATOverlapQuarantined != nil {
			q := 0.0
			if runtimePools[name] == "iface_snat_egress_overlap" {
				q = 1.0
			}
			c.emitConstMetric(ch, c.ifaceSNATOverlapQuarantined, prometheus.GaugeValue, q, name)
		}
		totalPorts := int(ports)
		if cfgUnusable == "" && unusable != "" {
			totalPorts = 0
		}
		if !pool.PortNoTranslation || unusable != "" {
			c.emitConstMetric(ch, c.natPoolTotalPorts, prometheus.GaugeValue,
				float64(totalPorts), name)
		}

		// #7473: a disarmed pool still HAS a PoolID — `compiler_nat.go` assigns
		// them without consulting any disarm predicate — so this lookup
		// succeeds and the counter reads 0. Publishing that as
		// `xpf_nat_pool_used_ports` is the same fake zero the #5046 comment
		// below refuses for a read failure, reached a different way: a missing
		// series says "not installed", a 0 says "measured, and nothing is
		// used", and monitoring cannot tell the second from health. Unlike the
		// two CLI twins of this bug there is no adjacent annotation here — the
		// sample is all a scrape sees — so omission is the only honest form.
		//
		// The reason was already computed for the capacity gauge above and
		// DISCARDED into `_`. Binding it is the whole fix: one verdict, both
		// samples, no second call that could disagree with the first.
		// #8606: the sample comes from the helper's live occupancy, not from
		// the legacy `nat_port_counters` map -- which is seeded with
		// `rand.Uint64()` and has had no writer since #1476 deleted the eBPF
		// pipeline, so this gauge was publishing a random number as used
		// ports. As the numerator of every pool-utilisation alert, that is the
		// worst place in the product for a fabricated figure.
		//
		// With no helper entry the sample is OMITTED, which is the same
		// judgement the paragraph above reaches for a disarmed pool: a missing
		// series says "not installed", a 0 says "measured, and nothing is
		// used", and monitoring cannot tell the second from health.
		if !pool.PortNoTranslation {
			if rp, ok := poolOccupancy[name]; ok && unusable == "" {
				c.emitConstMetric(ch, c.natPoolUsedPorts, prometheus.GaugeValue,
					float64(rp.UsedPorts), name)
			}
		}
		if pool.Deterministic != nil {
			c.emitConstMetric(ch, c.natPoolDeterministicInfo, prometheus.GaugeValue,
				1.0, name,
				strconv.Itoa(pool.Deterministic.BlockSize),
				strconv.Itoa(deterministicSubscriberCapacity(pool, name, overBudget)))

			// #4752: deterministic-pool block utilization. The pool-wide
			// used-ports counter is meaningless for a deterministic pool
			// (ports are pre-partitioned into fixed per-subscriber blocks),
			// so expose the block-occupancy numerator/denominator instead:
			//   total     = pool block capacity (numAddrs * blocksPerIP)
			//   allocated = provisioned subscriber blocks (one per subscriber)
			// An operator divides allocated/total for utilization and alarms
			// as it approaches 1.0. allocated is clamped to total so the ratio
			// never exceeds 1.0 (the compiler already rejects an over-provisioned
			// IPv4 pool; the clamp is defensive and also covers the IPv6 case
			// where every block is provisioned).
			totalBlocks := deterministicPoolBlockCapacity(pool, name, overBudget)
			if totalBlocks > 0 {
				allocated := deterministicSubscriberCapacity(pool, name, overBudget)
				if allocated > totalBlocks {
					allocated = totalBlocks
				}
				c.emitConstMetric(ch, c.natPoolDetBlocksTotal, prometheus.GaugeValue,
					float64(totalBlocks), name)
				c.emitConstMetric(ch, c.natPoolDetBlocksAllocated, prometheus.GaugeValue,
					float64(allocated), name)
			}
		}
	}
}

// deterministicPoolBlockCapacity returns the total per-subscriber port-block
// capacity of a deterministic CGNAT pool: deterministic-v4 addresses *
// blocksPerIP, where blocksPerIP = portRange / block-size. This mirrors the
// totalBlocks value the compiler validates (#15177: only the addresses Rust
// places in the deterministic IPv4 vector count — mode 1 unique-expanded v4,
// mode 2 bare//32 v4 hosts). Returns 0 when the pool is not a valid
// deterministic pool (nil, non-positive block size, or block size larger
// than the port range).
func deterministicPoolBlockCapacity(pool *config.NATPool, poolName string, overBudget map[string]bool) int {
	if pool == nil || pool.Deterministic == nil {
		return 0
	}
	// #7000: a refused pool installs no allocator, so it has no blocks.
	if _, unusable := config.SourceNATPoolReportableAddresses(pool, poolName, overBudget); unusable != "" {
		return 0
	}
	bs := pool.Deterministic.BlockSize
	if bs <= 0 {
		return 0
	}
	// #16822: use the pool's own port range for BOTH modes. #15283 made
	// mode 2 (IPv6 subscriber / NAT64) honour `port range` (default
	// 1024-65535) in pkg/nat, the wire builder, and the Rust allocator;
	// this gauge previously overrode it with the fixed 1024-65535
	// window, overstating a range-limited pool by the range ratio.
	// SourceNATPoolPortRange is the SSOT (default 1024-65535, invalid
	// spec fails closed); SourceNATPoolReportableAddresses above has
	// already returned 0 for an unusable pool, so !ok here is only a
	// defensive guard.
	portLow, portHigh, ok := config.SourceNATPoolPortRange(pool)
	if !ok {
		return 0
	}
	portRange := int(portHigh) - int(portLow) + 1
	if portRange <= 0 || bs > portRange {
		return 0
	}
	ipv6Subscriber := false
	if _, n, err := net.ParseCIDR(pool.Deterministic.HostAddress); err == nil {
		_, bits := n.Mask.Size()
		ipv6Subscriber = bits == 128
	}
	addrs := config.SourceNATPoolDeterministicV4AddressCount(pool, ipv6Subscriber)
	maxInt := uint64(^uint(0) >> 1)
	total := addrs * uint64(portRange/bs)
	if addrs != 0 && total/addrs != uint64(portRange/bs) {
		return int(maxInt)
	}
	if total > maxInt {
		return int(maxInt)
	}
	return int(total)
}

// deterministicSubscriberCapacity returns the value reported in the
// natPoolDeterministicInfo `host_count` label for a deterministic CGNAT pool.
//
// For an IPv4 subscriber CIDR the capacity is the number of host addresses,
// 1<<(32-ones). For IPv6 (bits==128) that shift is >=64, which is 0 in Go
// (#4692) — so, mirroring the compiler_nat.go deterministic-capacity gate
// (which caps the IPv6 subscriber count by pool capacity rather than by the
// host CIDR), report the pool's block/subscriber capacity: blocksPerIP =
// portRange/blockSize, totalBlocks = len(addresses)*blocksPerIP. Returns 0
// when the host CIDR is unparseable or the block size is non-positive.
func deterministicSubscriberCapacity(pool *config.NATPool, poolName string, overBudget map[string]bool) int {
	if pool == nil || pool.Deterministic == nil {
		return 0
	}
	_, n, err := net.ParseCIDR(pool.Deterministic.HostAddress)
	if err != nil {
		return 0
	}
	ones, bits := n.Mask.Size()
	if bits != 128 {
		// IPv4 subscriber CIDR — host-address count.
		return 1 << uint(bits-ones)
	}
	// IPv6 — 1<<(128-ones) overflows Go's shift width. Mirror the compiler,
	// which caps the IPv6 subscriber count by pool block capacity.
	return deterministicPoolBlockCapacity(pool, poolName, overBudget)
}
