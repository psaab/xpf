package api

import (
	"math"
	"testing"

	"github.com/prometheus/client_golang/prometheus"

	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)

// #1772: pin the Go-side bucket conversion that turns the dataplane's
// NON-cumulative pow2-ns sample counts into the cumulative seconds-`le`
// map a Prometheus histogram requires. The boundaries MUST mirror the
// Rust `neigh_latency_bucket_upper_ns` (bucket i upper bound 2^(16+i) ns)
// exactly, or the histogram `le` labels drift from where samples landed.

func TestNeighLatencyBucketUpperSecondsMirrorsRust(t *testing.T) {
	// Bucket i (0..=14) upper bound is 2^(16+i) ns, expressed in seconds.
	cases := []struct {
		idx    int
		wantNs uint64
	}{
		{0, 1 << 16},  // 65536 ns
		{7, 1 << 23},  // 8.4 ms
		{13, 1 << 29}, // 537 ms
		{14, 1 << 30}, // 1.07 s — last finite bucket
	}
	for _, c := range cases {
		got := neighLatencyBucketUpperSeconds(c.idx)
		want := float64(c.wantNs) / 1e9
		if math.Abs(got-want) > 1e-12 {
			t.Errorf("bucket %d: got %g s, want %g s", c.idx, got, want)
		}
	}
}

func TestNeighLatencyCumulativeBucketsAccumulates(t *testing.T) {
	// Non-cumulative per-bucket counts: 3 in bucket 0, 2 in bucket 1,
	// 5 in bucket 14 (last finite). The 16th (+Inf) bucket is implicit.
	raw := make([]uint64, neighLatencyBucketCount)
	raw[0] = 3
	raw[1] = 2
	raw[14] = 5

	got := neighLatencyCumulativeBuckets(raw)

	// Only the 15 finite buckets get an explicit `le`.
	if len(got) != neighLatencyBucketCount-1 {
		t.Fatalf("expected %d finite le-buckets, got %d", neighLatencyBucketCount-1, len(got))
	}
	// Cumulative: le(2^16)=3, le(2^17)=5, ... le(2^30)=10.
	mustBucket := func(idx int, want uint64) {
		le := neighLatencyBucketUpperSeconds(idx)
		if got[le] != want {
			t.Errorf("cumulative le=%g (bucket %d): got %d, want %d", le, idx, got[le], want)
		}
	}
	mustBucket(0, 3)
	mustBucket(1, 5)
	mustBucket(13, 5)  // nothing added between bucket 1 and 13
	mustBucket(14, 10) // + the 5 in bucket 14
}

// A 3 s dwell lands in the +Inf saturate bucket on the Rust side (index
// 15), which is NOT an explicit `le` boundary — so a sample there must
// NOT inflate any finite `le` bucket; it shows up only via the histogram
// total count. Model that here: a saturate-tail sample (slot 15) leaves
// every finite cumulative bucket at its pre-tail value.
func TestNeighLatencyCumulativeBucketsExcludesSaturateTail(t *testing.T) {
	raw := make([]uint64, neighLatencyBucketCount)
	raw[15] = 7 // 7 multi-second (>=1.07 s) samples — the 3 s blackout class

	got := neighLatencyCumulativeBuckets(raw)
	for idx := 0; idx < neighLatencyBucketCount-1; idx++ {
		le := neighLatencyBucketUpperSeconds(idx)
		if got[le] != 0 {
			t.Errorf("saturate-tail samples must not enter finite le=%g: got %d", le, got[le])
		}
	}
}

// Defensive: a short/empty slice from an older peer (no buckets sent)
// must yield all-zero finite buckets, never panic or index out of range.
func TestNeighLatencyCumulativeBucketsShortSlice(t *testing.T) {
	for _, raw := range [][]uint64{nil, {}, {1, 2}} {
		got := neighLatencyCumulativeBuckets(raw)
		if len(got) != neighLatencyBucketCount-1 {
			t.Fatalf("short slice %v: expected %d le-buckets, got %d", raw, neighLatencyBucketCount-1, len(got))
		}
		// Cumulative counts never exceed what the (short) slice carried.
		var total uint64
		for _, v := range raw {
			total += v
		}
		top := got[neighLatencyBucketUpperSeconds(neighLatencyBucketCount-2)]
		if top != total {
			t.Errorf("short slice %v: top cumulative %d, want %d", raw, top, total)
		}
	}
}

// #1771 §2.6: value + type pin for the Phase-3 neighbor metrics emitted
// by emitNeighborWarmCounters — the backoff-retry counter, the §2.5
// ENOBUFS/re-dump counters (CounterValue), and the pending/negative key
// gauges (GaugeValue). assertCounterClose/assertGaugeClose check the
// concrete dto type, so a Counter↔Gauge mixup here fails the test.
func TestEmitNeighborPhase3CountersAndGauges(t *testing.T) {
	newDesc := func(name string) *prometheus.Desc {
		return prometheus.NewDesc(name, name, nil, nil)
	}
	c := &xpfCollector{
		neighborWarmDropsTotal:        newDesc("xpf_userspace_neighbor_warm_drops_total"),
		neighborWarmDisconnectedTotal: newDesc("xpf_userspace_neighbor_warm_disconnected_total"),
		neighborResolverQueueDepth:    newDesc("xpf_userspace_neighbor_resolver_queue_depth"),
		neighborResolverEnqueueDropsTotal: newDesc(
			"xpf_userspace_neighbor_resolver_enqueue_drops_total"),
		neighborResolverDisconnectedTotal: newDesc(
			"xpf_userspace_neighbor_resolver_disconnected_total"),
		neighborResolverGetAttemptsTotal: newDesc(
			"xpf_userspace_neighbor_resolver_get_attempts_total"),
		neighborResolverGetResolvedTotal: newDesc(
			"xpf_userspace_neighbor_resolver_get_resolved_total"),
		neighborResolverProbeOnStaleTotal: newDesc(
			"xpf_userspace_neighbor_resolver_probe_on_stale_total"),
		neighborResolverGetFailuresTotal: newDesc(
			"xpf_userspace_neighbor_resolver_get_failures_total"),
		neighborResolverEpochRejectsTotal: newDesc(
			"xpf_userspace_neighbor_resolver_epoch_rejects_total"),
		neighborResolverGetBackoffAttemptsTotal: newDesc(
			"xpf_userspace_neighbor_resolver_get_backoff_attempts_total"),
		neighborNetlinkEnobufsTotal: newDesc(
			"xpf_userspace_neighbor_netlink_enobufs_total"),
		neighborNetlinkRedumpsTotal: newDesc(
			"xpf_userspace_neighbor_netlink_redumps_total"),
		neighborNetlinkRedumpUpsertsTotal: newDesc(
			"xpf_userspace_neighbor_netlink_redump_upserts_total"),
		neighborPendingKeys: newDesc("xpf_userspace_neighbor_pending_keys"),
		negNeighKeys:        newDesc("xpf_userspace_neg_neigh_keys"),
		neighborPendingDwellSeconds: newDesc(
			"xpf_userspace_neighbor_pending_dwell_seconds"),
		neighborResolverGetRttSeconds: newDesc(
			"xpf_userspace_neighbor_resolver_get_rtt_seconds"),
		neighborPendingTimeoutDropsTotal: newDesc(
			"xpf_userspace_neighbor_pending_timeout_drops_total"),
		neighborPendingMaxDepth: newDesc("xpf_userspace_neighbor_pending_max_depth"),
	}
	status := dpuserspace.ProcessStatus{
		NeighborResolverGetBackoffAttemptsTotal: 9,
		NeighborNetlinkEnobufsTotal:             4,
		NeighborNetlinkRedumpsTotal:             2,
		NeighborNetlinkRedumpUpsertsTotal:       13,
		NeighborPendingKeys:                     3,
		NegNeighKeys:                            1,
	}

	ch := make(chan prometheus.Metric, 64)
	c.emitNeighborWarmCounters(ch, status)
	close(ch)
	var got []prometheus.Metric
	for m := range ch {
		got = append(got, m)
	}

	assertCounterClose(t, got, c.neighborResolverGetBackoffAttemptsTotal, nil, 9)
	assertCounterClose(t, got, c.neighborNetlinkEnobufsTotal, nil, 4)
	assertCounterClose(t, got, c.neighborNetlinkRedumpsTotal, nil, 2)
	assertCounterClose(t, got, c.neighborNetlinkRedumpUpsertsTotal, nil, 13)
	assertGaugeClose(t, got, c.neighborPendingKeys, nil, 3)
	assertGaugeClose(t, got, c.negNeighKeys, nil, 1)
}

// #3773 (M13): value + type pin for the fabric-link skip counters emitted by
// emitFabricSkipCounters. Both are CounterValue; a mixup or a dropped emit
// fails this test. fail-on-revert: removing the emit leaves `got` without the
// series and assertCounterClose fails.
func TestEmitFabricSkipCounters(t *testing.T) {
	newDesc := func(name string) *prometheus.Desc {
		return prometheus.NewDesc(name, name, nil, nil)
	}
	c := &xpfCollector{
		fabricLinkSkippedMalformedTotal: newDesc(
			"xpf_userspace_fabric_link_skipped_malformed_total"),
		fabricLinkUnresolvedPeerTotal: newDesc(
			"xpf_userspace_fabric_link_unresolved_peer_total"),
	}
	status := dpuserspace.ProcessStatus{
		FabricLinkSkippedMalformedTotal: 6,
		FabricLinkUnresolvedPeerTotal:   2,
	}
	ch := make(chan prometheus.Metric, 8)
	c.emitFabricSkipCounters(ch, status)
	close(ch)
	var got []prometheus.Metric
	for m := range ch {
		got = append(got, m)
	}
	assertCounterClose(t, got, c.fabricLinkSkippedMalformedTotal, nil, 6)
	assertCounterClose(t, got, c.fabricLinkUnresolvedPeerTotal, nil, 2)
}

func TestEmitFabricTrustBoundaryCounters(t *testing.T) {
	desc := func(name string) *prometheus.Desc {
		return prometheus.NewDesc(name, name, nil, nil)
	}
	c := &xpfCollector{
		userspaceFabricInvalidStampDrops: desc("xpf_userspace_fabric_invalid_stamp_drops_total"),
		userspaceFabricUnstampedIngressDrops: desc(
			"xpf_userspace_fabric_unstamped_ingress_drops_total",
		),
		userspaceFabricAmbiguousZoneDrops: desc(
			"xpf_userspace_fabric_ambiguous_zone_drops_total",
		),
		userspaceFabricAmbiguousZoneCount: desc(
			"xpf_userspace_fabric_ambiguous_zone_count",
		),
	}
	status := dpuserspace.ProcessStatus{
		AmbiguousFabricZoneCount: 2,
		Bindings: []dpuserspace.BindingStatus{
			{
				InvalidFabricStampDrops: 3, UnstampedFabricIngressDrops: 5,
				AmbiguousFabricZoneDrops: 7,
			},
			{
				InvalidFabricStampDrops: 11, UnstampedFabricIngressDrops: 13,
				AmbiguousFabricZoneDrops: 17,
			},
		},
	}
	ch := make(chan prometheus.Metric, 4)
	c.emitFabricTrustBoundaryCounters(ch, status)
	close(ch)
	got := make([]prometheus.Metric, 0, 4)
	for metric := range ch {
		got = append(got, metric)
	}
	assertCounterClose(t, got, c.userspaceFabricInvalidStampDrops, nil, 14)
	assertCounterClose(t, got, c.userspaceFabricUnstampedIngressDrops, nil, 18)
	assertCounterClose(t, got, c.userspaceFabricAmbiguousZoneDrops, nil, 24)
	assertGaugeClose(t, got, c.userspaceFabricAmbiguousZoneCount, nil, 2)
}
