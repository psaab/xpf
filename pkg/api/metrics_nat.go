package api

import (
	"net"
	"strconv"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)

func (c *xpfCollector) collectNATPoolMetrics(ch chan<- prometheus.Metric, dp apiRuntimeDataPlane, userspaceStatus *dpuserspace.ProcessStatus) {
	cfg := c.srv.store.ActiveConfig()
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
	for name, pool := range cfg.Security.NAT.SourcePools {
		portLow, portHigh := pool.PortLow, pool.PortHigh
		if portLow == 0 {
			portLow = 1024
		}
		if portHigh == 0 {
			portHigh = 65535
		}
		ports, unusable := config.SourceNATPoolReportablePorts(pool, name, portLow, portHigh, overBudget)
		totalPorts := int(ports)
		if !pool.PortNoTranslation || unusable != "" {
			ch <- prometheus.MustNewConstMetric(c.natPoolTotalPorts, prometheus.GaugeValue,
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
				ch <- prometheus.MustNewConstMetric(c.natPoolUsedPorts, prometheus.GaugeValue,
					float64(rp.UsedPorts), name)
			}
		}
		if pool.Deterministic != nil {
			ch <- prometheus.MustNewConstMetric(c.natPoolDeterministicInfo, prometheus.GaugeValue,
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
				ch <- prometheus.MustNewConstMetric(c.natPoolDetBlocksTotal, prometheus.GaugeValue,
					float64(totalBlocks), name)
				ch <- prometheus.MustNewConstMetric(c.natPoolDetBlocksAllocated, prometheus.GaugeValue,
					float64(allocated), name)
			}
		}
	}
}

// deterministicPoolBlockCapacity returns the total per-subscriber port-block
// capacity of a deterministic CGNAT pool: len(addresses) * blocksPerIP, where
// blocksPerIP = portRange / block-size. This mirrors the totalBlocks value the
// compiler validates against the provisioned subscriber count
// (compiler_nat.go) and the dataplane NATPoolConfig.BlocksPerIP field. Returns
// 0 when the pool is not a valid deterministic pool (nil, non-positive block
// size, or block size larger than the port range).
func deterministicPoolBlockCapacity(pool *config.NATPool, poolName string, overBudget map[string]bool) int {
	if pool == nil || pool.Deterministic == nil {
		return 0
	}
	// #7000: a refused pool installs no allocator, so it has no blocks — and a
	// prefix member expands, so the address count is not `len(pool.Addresses)`.
	addrs, unusable := config.SourceNATPoolReportableAddresses(pool, poolName, overBudget)
	if unusable != "" {
		return 0
	}
	bs := pool.Deterministic.BlockSize
	if bs <= 0 {
		return 0
	}
	portLow := pool.PortLow
	if portLow == 0 {
		portLow = 1024
	}
	portHigh := pool.PortHigh
	if portHigh == 0 {
		portHigh = 65535
	}
	portRange := portHigh - portLow + 1
	if portRange <= 0 || bs > portRange {
		return 0
	}
	return addrs * (portRange / bs)
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
