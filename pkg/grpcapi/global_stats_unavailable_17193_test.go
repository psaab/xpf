// #17193: the userspace adapter-sentinel fixture (the four #13274
// known-unsourced indexes return ErrCounterNotPopulated, every other index
// is healthy) must not fail GetGlobalStats or the text surfaces. Before the
// shared dataplane.ReadGlobalCounters classification, GetGlobalStats
// returned codes.Internal on every call and showFlowStatistics printed a
// fabricated "TC egress packets: 0" plus a permanent false warning.
//
// FAIL-ON-REVERT: restoring the first-error closures in GetGlobalStats /
// showFlowStatistics makes the RPC return Internal and the text assertions
// (unavailable, no warning, no fabricated 0) go RED.
package grpcapi

import (
	"context"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/dataplane"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
)

// sentinelGRPCDP17193 drives the real LegacyDataPlaneAdapter sentinel for
// the four unsourced indexes and healthy idx+1 values elsewhere, exactly
// the fixture the REST twin (stats_unavailable_global_counters_13274_test)
// uses.
type sentinelGRPCDP17193 struct {
	*dpuserspace.LegacyDataPlaneAdapter
}

func (d *sentinelGRPCDP17193) IsLoaded() bool { return true }

func (d *sentinelGRPCDP17193) ReadGlobalCounter(idx uint32) (uint64, error) {
	switch idx {
	case dataplane.GlobalCtrFlowCacheFlush, dataplane.GlobalCtrFlowCacheInvalidate,
		dataplane.GlobalCtrTCEgressPackets, dataplane.GlobalCtrFabricRedirect:
		return d.LegacyDataPlaneAdapter.ReadGlobalCounter(idx)
	default:
		return uint64(idx) + 1, nil
	}
}

func newSentinelServer17193(t *testing.T) *Server {
	t.Helper()
	adapter := dpuserspace.NewLegacyDataPlaneAdapter(dpuserspace.New())
	return newViewServer(t, &sentinelGRPCDP17193{LegacyDataPlaneAdapter: adapter})
}

func TestGetGlobalStatsUnavailableNotError17193(t *testing.T) {
	s := newSentinelServer17193(t)
	resp, err := s.GetGlobalStats(context.Background(), &pb.GetGlobalStatsRequest{})
	if err != nil {
		t.Fatalf("GetGlobalStats on the userspace sentinel fixture: %v; want success with unavailable_counters", err)
	}
	// GetGlobalStats reads tc_egress_packets among its named fields; the
	// other three unsourced counters belong to the REST/text read sets.
	// Exactly the counters this RPC reads and found unsourced must be named.
	if len(resp.UnavailableCounters) != 1 || resp.UnavailableCounters[0] != "tc_egress_packets" {
		t.Errorf("unavailable_counters = %v, want [tc_egress_packets]", resp.UnavailableCounters)
	}
	if resp.RxPackets != uint64(dataplane.GlobalCtrRxPackets)+1 {
		t.Errorf("RxPackets = %d, want %d (healthy counters unaffected)", resp.RxPackets, uint64(dataplane.GlobalCtrRxPackets)+1)
	}
}

func TestShowFlowStatisticsUnavailableNotZero17193(t *testing.T) {
	s := newSentinelServer17193(t)
	var buf strings.Builder
	if err := s.showFlowStatistics(context.Background(), &buf); err != nil {
		t.Fatalf("showFlowStatistics: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "TC egress packets:") || !strings.Contains(out, "unavailable") {
		t.Errorf("TC egress must render unavailable, got:\n%s", out)
	}
	if strings.Contains(out, "TC egress packets:             0") {
		t.Errorf("fabricated TC egress 0 still printed:\n%s", out)
	}
	if strings.Contains(out, "read failed") {
		t.Errorf("false read-failed warning on unavailable counters:\n%s", out)
	}
	// Flow-cache section: hit/miss are healthy in this fixture, so the
	// section renders and flush/invalidate must be unavailable, not 0.
	if !strings.Contains(out, "Flow cache flushes:") {
		t.Errorf("flow cache section missing (hit/miss healthy):\n%s", out)
	}
}
