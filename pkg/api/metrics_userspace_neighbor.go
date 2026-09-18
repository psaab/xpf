package api

import (
	"strings"

	"github.com/prometheus/client_golang/prometheus"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)

// Prometheus emitters for the userspace dataplane's NEIGHBOR telemetry — cold
// start capture, warm counters, and the resolution-latency histograms.
// Split out of metrics_userspace.go for the #7700 modularity floor; this is a
// move, not a behaviour change.

// neighLatencyBucketCount mirrors the Rust NEIGH_LATENCY_BUCKETS (16):
// 15 finite pow2-ns buckets + 1 +Inf saturate.
const neighLatencyBucketCount = 16

// emitNeighborColdStartCapture exposes the #1782 cold-start capture
// instrumentation: the per-worker-summed neg-neigh fast-fail counter
// (H1 amplifier), the pending_neigh key-already-pending duplicate-drop
// counter (H5 sibling drop), and a per-key presence gauge dumped from
// the helper's dynamic_neighbors mirror so the capture harness can grep
// the pre-connect t0' next-hop membership (the H2 absence fingerprint).
// All three are read straight off the single per-scrape ProcessStatus;
// no extra control-socket round trip.
func (c *xpfCollector) emitNeighborColdStartCapture(ch chan<- prometheus.Metric, status dpuserspace.ProcessStatus) {
	ch <- prometheus.MustNewConstMetric(
		c.negNeighFastFailTotal,
		prometheus.CounterValue,
		float64(status.NegNeighFastFailTotal),
	)
	ch <- prometheus.MustNewConstMetric(
		c.pendingNeighDuplicateDropsTotal,
		prometheus.CounterValue,
		float64(status.PendingNeighDuplicateDropsTotal),
	)
	ch <- prometheus.MustNewConstMetric(
		c.pendingNeighDecapDropsTotal,
		prometheus.CounterValue,
		float64(status.PendingNeighDecapDropsTotal),
	)
	ch <- prometheus.MustNewConstMetric(
		c.pendingNeighCapacityDropsTotal,
		prometheus.CounterValue,
		float64(status.PendingNeighCapacityDropsTotal),
	)
	// #5673: data-path neighbor learns refused by the aggregate
	// dynamic-neighbor map cap (spoofed-source pre-policy flood bound).
	ch <- prometheus.MustNewConstMetric(
		c.dynamicNeighborLearnCapDropsTotal,
		prometheus.CounterValue,
		float64(status.DynamicNeighborLearnCapDropsTotal),
	)
	// #10097: NDP Neighbor Advertisement learn-refusal counters.
	ch <- prometheus.MustNewConstMetric(
		c.ndpNaFragRefusedTotal,
		prometheus.CounterValue,
		float64(status.NDPNAFragRefusedTotal),
	)
	ch <- prometheus.MustNewConstMetric(
		c.ndpNaBadSourceRefusedTotal,
		prometheus.CounterValue,
		float64(status.NDPNABadSourceRefusedTotal),
	)
	for _, key := range status.DynamicNeighborKeys {
		// Each key is rendered "ifindex ip" by the helper. Split on the
		// single space into the two gauge labels; skip a malformed entry
		// rather than emit a partial-label series.
		ifindex, ip, ok := strings.Cut(key, " ")
		if !ok || ifindex == "" || ip == "" {
			continue
		}
		ch <- prometheus.MustNewConstMetric(
			c.dynamicNeighborPresent,
			prometheus.GaugeValue,
			1,
			ifindex,
			ip,
		)
	}
}

// emitNeighborWarmCounters exposes the #1636 proactive-neighbor-warm
// telemetry. These are the only operator-visible signal for the warmer
// in production builds (the per-key debug eprintln is gated on the
// debug-log feature). A non-zero `disconnected` series means the warmer
// worker died and proactive warming is off until daemon restart.
func (c *xpfCollector) emitNeighborWarmCounters(ch chan<- prometheus.Metric, status dpuserspace.ProcessStatus) {
	ch <- prometheus.MustNewConstMetric(
		c.neighborWarmDropsTotal,
		prometheus.CounterValue,
		float64(status.NeighborWarmDropsTotal),
	)
	ch <- prometheus.MustNewConstMetric(
		c.neighborWarmDisconnectedTotal,
		prometheus.CounterValue,
		float64(status.NeighborWarmDisconnectedTotal),
	)
	// #1769: on-demand neighbor-resolver telemetry.
	ch <- prometheus.MustNewConstMetric(
		c.neighborResolverQueueDepth,
		prometheus.GaugeValue,
		float64(status.NeighborResolverQueueDepth),
	)
	ch <- prometheus.MustNewConstMetric(
		c.neighborResolverEnqueueDropsTotal,
		prometheus.CounterValue,
		float64(status.NeighborResolverEnqueueDropsTotal),
	)
	ch <- prometheus.MustNewConstMetric(
		c.neighborResolverDisconnectedTotal,
		prometheus.CounterValue,
		float64(status.NeighborResolverDisconnectedTotal),
	)
	ch <- prometheus.MustNewConstMetric(
		c.neighborResolverGetAttemptsTotal,
		prometheus.CounterValue,
		float64(status.NeighborResolverGetAttemptsTotal),
	)
	ch <- prometheus.MustNewConstMetric(
		c.neighborResolverGetResolvedTotal,
		prometheus.CounterValue,
		float64(status.NeighborResolverGetResolvedTotal),
	)
	ch <- prometheus.MustNewConstMetric(
		c.neighborResolverProbeOnStaleTotal,
		prometheus.CounterValue,
		float64(status.NeighborResolverProbeOnStaleTotal),
	)
	ch <- prometheus.MustNewConstMetric(
		c.neighborResolverGetFailuresTotal,
		prometheus.CounterValue,
		float64(status.NeighborResolverGetFailuresTotal),
	)
	ch <- prometheus.MustNewConstMetric(
		c.neighborResolverEpochRejectsTotal,
		prometheus.CounterValue,
		float64(status.NeighborResolverEpochRejectsTotal),
	)
	// #1771 §2.6: backoff-retry GETs, the §2.5 ENOBUFS/re-dump
	// self-heal counters, and the pending/negative key gauges. All
	// emitted unconditionally so a 0 is a real signal (no ENOBUFS, no
	// parked packets) rather than an absent series.
	ch <- prometheus.MustNewConstMetric(
		c.neighborResolverGetBackoffAttemptsTotal,
		prometheus.CounterValue,
		float64(status.NeighborResolverGetBackoffAttemptsTotal),
	)
	ch <- prometheus.MustNewConstMetric(
		c.neighborNetlinkEnobufsTotal,
		prometheus.CounterValue,
		float64(status.NeighborNetlinkEnobufsTotal),
	)
	ch <- prometheus.MustNewConstMetric(
		c.neighborNetlinkRedumpsTotal,
		prometheus.CounterValue,
		float64(status.NeighborNetlinkRedumpsTotal),
	)
	ch <- prometheus.MustNewConstMetric(
		c.neighborNetlinkRedumpUpsertsTotal,
		prometheus.CounterValue,
		float64(status.NeighborNetlinkRedumpUpsertsTotal),
	)
	ch <- prometheus.MustNewConstMetric(
		c.neighborPendingKeys,
		prometheus.GaugeValue,
		float64(status.NeighborPendingKeys),
	)
	ch <- prometheus.MustNewConstMetric(
		c.negNeighKeys,
		prometheus.GaugeValue,
		float64(status.NegNeighKeys),
	)
	// #1772: neighbor/ARP resolution LATENCY telemetry.
	c.emitNeighborLatencyHistograms(ch, status)
}

// neighLatencyBucketUpperSeconds returns the inclusive upper bound (in
// SECONDS, for the Prometheus `le` label) of finite bucket i, mirroring
// the Rust `neigh_latency_bucket_upper_ns`: bucket i upper bound is
// 2^(16+i) ns. The final bucket (15) is +Inf and is NOT emitted as an
// explicit `le` boundary — prometheus.MustNewConstHistogram appends the
// implicit +Inf bucket from the total count.
func neighLatencyBucketUpperSeconds(i int) float64 {
	return float64(uint64(1)<<(16+uint(i))) / 1e9
}

// neighLatencyCumulativeBuckets converts the dataplane's NON-cumulative
// per-bucket sample counts into the cumulative `le`→count map Prometheus
// histograms require. Defensive against a short/absent slice (a peer on
// an older protocol that does not send the buckets yields an empty map +
// the count/sum we do have).
func neighLatencyCumulativeBuckets(buckets []uint64) map[float64]uint64 {
	out := make(map[float64]uint64, neighLatencyBucketCount-1)
	var cum uint64
	// Only the 15 finite buckets get an explicit `le`; the 16th (+Inf)
	// is implicit in the histogram's total count.
	for i := 0; i < neighLatencyBucketCount-1; i++ {
		if i < len(buckets) {
			cum += buckets[i]
		}
		out[neighLatencyBucketUpperSeconds(i)] = cum
	}
	return out
}

// emitNeighborLatencyHistograms exposes the #1772 neighbor/ARP
// resolution LATENCY metrics: the pending-buffer dwell and resolver
// GETNEIGH RTT histograms, plus the pending timeout-drop counter and the
// pending queue-depth high-water gauge. The histograms localize where an
// intermittent slow new connection spends its time (pending dwell vs
// kernel GETNEIGH RTT).
func (c *xpfCollector) emitNeighborLatencyHistograms(ch chan<- prometheus.Metric, status dpuserspace.ProcessStatus) {
	ch <- prometheus.MustNewConstHistogram(
		c.neighborPendingDwellSeconds,
		status.NeighborPendingDwellCount,
		float64(status.NeighborPendingDwellSumNs)/1e9,
		neighLatencyCumulativeBuckets(status.NeighborPendingDwellBuckets),
	)
	ch <- prometheus.MustNewConstHistogram(
		c.neighborResolverGetRttSeconds,
		status.NeighborResolverGetRttCount,
		float64(status.NeighborResolverGetRttSumNs)/1e9,
		neighLatencyCumulativeBuckets(status.NeighborResolverGetRttBuckets),
	)
	ch <- prometheus.MustNewConstMetric(
		c.neighborPendingTimeoutDropsTotal,
		prometheus.CounterValue,
		float64(status.NeighborPendingTimeoutDropsTotal),
	)
	ch <- prometheus.MustNewConstMetric(
		c.neighborPendingMaxDepth,
		prometheus.GaugeValue,
		float64(status.NeighborPendingMaxDepth),
	)
}
