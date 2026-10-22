package flowexport

// #16126 decisive tests for the shared enrichment core.
//
// These are fail-on-revert guards, not smoke tests:
//   - TestBuildFlowRecordTwinParity: the ONE intentional divergence is
//     includeReverse (IPFIX biflow counters). Reverting either exporter
//     to its own enrichment, or flipping the flag, changes a field here.
//   - TestBuildFlowRecordAllocation: the issue rejects "extra copy per
//     flow"; the enrichment must not allocate beyond the pre-refactor
//     inline literals. Measured on this host with testing.AllocsPerRun
//     after warmup; the bound is the pre-refactor twin's cost.
//   - TestGoldenEnrichmentTwin (golden_16126_test.go) freezes the twin
//     output captured before the refactor.

import (
	"net"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/logging"
)

func coreTestEvent() (logging.EventRecord, SessionCloseData) {
	rec := logging.EventRecord{
		Time: goldenEpoch, Type: "SESSION_CLOSE",
		Created: uint32(goldenEpoch.Add(-2 * time.Minute).Unix()), CreatedNanos: 500_000_000,
		ProtocolNum: 50, SessionPkts: 7, SessionBytes: 900,
		RevSessionPkts: 3, RevSessionBytes: 400,
	}
	evt := SessionCloseData{
		SrcIP: net.IPv4(10, 9, 8, 7), DstIP: net.IPv4(192, 0, 2, 55),
		SrcPort: 1111, DstPort: 2222, Protocol: 6, IsIPv6: false,
		NATSrcIP: net.IPv4(172, 16, 1, 1),
		InIf:     11, OutIf: 12, TOS: 0x10, TCPFlags: 0x02, Direction: 1,
	}
	return rec, evt
}

func TestBuildFlowRecordTwinParity(t *testing.T) {
	rec, evt := coreTestEvent()
	var resolver MaskResolver = func(ip net.IP, scope int) (uint8, bool) {
		if ip.To4() != nil && ip.To4()[3] == 7 {
			return 24, true
		}
		return 0, false // dst unresolved: one miss
	}
	core := &exporterCore{MaskResolver: resolver}

	nf, nfStats := core.buildFlowRecord(rec, evt, false)
	ip, ipStats := core.buildFlowRecord(rec, evt, true)

	if nfStats != ipStats {
		t.Fatalf("enrichment stats diverge: v9 %+v ipfix %+v", nfStats, ipStats)
	}
	if nfStats.routeMaskUnresolved != 1 {
		t.Fatalf("routeMaskUnresolved=%d want 1 (dst miss)", nfStats.routeMaskUnresolved)
	}
	if nf.SrcMask != 24 || nf.DstMask != 0 {
		t.Fatalf("masks src=%d dst=%d want 24/0", nf.SrcMask, nf.DstMask)
	}
	// The only allowed divergence: reverse counters.
	if nf.RevPackets != 0 || nf.RevBytes != 0 {
		t.Fatalf("v9 must leave reverse zero, got %d/%d", nf.RevPackets, nf.RevBytes)
	}
	if ip.RevPackets != 3 || ip.RevBytes != 400 {
		t.Fatalf("ipfix reverse=%d/%d want 3/400", ip.RevPackets, ip.RevBytes)
	}
	nf.RevPackets, nf.RevBytes = ip.RevPackets, ip.RevBytes
	if got, want := goldenRenderRecord(nf), goldenRenderRecord(ip); got != want {
		t.Fatalf("records diverge beyond reverse counters:\n v9 %s\n ip %s", got, want)
	}
	// Post-NAT fallback: src translated, dst falls back to pre-NAT.
	if !nf.NATSrcIP.Equal(net.IPv4(172, 16, 1, 1)) || !nf.NATDstIP.Equal(evt.DstIP) {
		t.Fatalf("post-NAT = %s/%s", nf.NATSrcIP, nf.NATDstIP)
	}
	if nf.Protocol != 50 {
		t.Fatalf("protocol=%d want raw ProtocolNum 50, not name-table %d", nf.Protocol, evt.Protocol)
	}
	if nf.StartTime.UnixMilli() != time.Unix(goldenEpoch.Add(-2*time.Minute).Unix(), 500_000_000).UnixMilli() {
		t.Fatalf("start=%v", nf.StartTime)
	}
}

func TestBuildFlowRecordMissingAndSkewStats(t *testing.T) {
	_, evt := coreTestEvent()
	core := &exporterCore{}
	rec := logging.EventRecord{Time: goldenEpoch} // Created=0
	_, st := core.buildFlowRecord(rec, evt, true)
	if st.estimatedDurations != 1 || st.clockSkewClamped != 0 {
		t.Fatalf("missing-created stats %+v", st)
	}
	rec.Created = uint32(goldenEpoch.Add(time.Hour).Unix())
	fr, st := core.buildFlowRecord(rec, evt, true)
	if st.clockSkewClamped != 1 || !fr.StartTime.Equal(goldenEpoch) {
		t.Fatalf("skew stats %+v start %v", st, fr.StartTime)
	}
}

func TestBuildFlowRecordAllocation(t *testing.T) {
	rec, evt := coreTestEvent()
	core := &exporterCore{}
	// Warm up (resolver nil path, no batch).
	for i := 0; i < 100; i++ {
		_, _ = core.buildFlowRecord(rec, evt, true)
	}
	allocs := testing.AllocsPerRun(1000, func() {
		_, _ = core.buildFlowRecord(rec, evt, true)
	})
	// Pre-refactor twin cost: the inline literal copied IP headers only.
	// resolvePostNAT/flowStartTime/resolveMasks add no heap allocation on
	// this path (verified by the golden-step measurement); allow at most
	// 1 alloc/op of headroom for runtime variance, fail above that.
	t.Logf("buildFlowRecord allocs/op = %v", allocs)
	if allocs > 1 {
		t.Fatalf("buildFlowRecord allocs/op=%v want <=1 (no extra copy per flow, #16126)", allocs)
	}
}

// BenchmarkBuildFlowRecordAllocation is the named per-flow allocation
// comparison the issue's acceptance check asks for; run with
// -bench BenchmarkBuildFlowRecordAllocation -benchmem.
func BenchmarkBuildFlowRecordAllocation(b *testing.B) {
	rec, evt := coreTestEvent()
	core := &exporterCore{}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = core.buildFlowRecord(rec, evt, true)
	}
}
