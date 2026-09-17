package grpcapi

import (
	"context"
	"testing"

	"github.com/psaab/xpf/pkg/dataplane"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
)

type natAddressOnlyGRPCDP9995 struct {
	*dataplane.Manager
	status dpuserspace.ProcessStatus
	result *dataplane.ApplyResult
}

func (d *natAddressOnlyGRPCDP9995) IsLoaded() bool { return true }
func (d *natAddressOnlyGRPCDP9995) Status() (dpuserspace.ProcessStatus, error) {
	return d.status, nil
}
func (d *natAddressOnlyGRPCDP9995) LastApplyResult() *dataplane.ApplyResult {
	return d.result.Clone()
}

// TestGetNATPoolStatsAddressOnlyIsNotApplicable9995 is a FAIL-ON-REVERT guard
// for the gRPC structured surface. Port no-translation preserves the source
// port, so UsedPorts=0 must not become full availability and 0.0% utilization.
func TestGetNATPoolStatsAddressOnlyIsNotApplicable9995(t *testing.T) {
	store := newNATPoolStatsGRPCStore(t)
	cfg := store.ActiveConfig()
	pool := cfg.Security.NAT.SourcePools["p1"]
	if pool == nil {
		t.Fatal("fixture: source pool p1 missing")
	}
	pool.PortNoTranslation = true

	dp := &natAddressOnlyGRPCDP9995{
		Manager: dataplane.New(),
		status: dpuserspace.ProcessStatus{SourceNATPools: []dpuserspace.SourceNATPoolStatus{
			{PoolName: "p1", AddressCount: 1, PortLow: 1024, PortHigh: 2023, UsedPorts: 0},
		}},
		result: &dataplane.ApplyResult{},
	}
	s := &Server{store: store, dp: dp}
	resp, err := s.GetNATPoolStats(context.Background(), &pb.GetNATPoolStatsRequest{})
	if err != nil {
		t.Fatalf("GetNATPoolStats: %v", err)
	}
	if len(resp.GetPools()) != 1 {
		t.Fatalf("fixture: want one pool, got %d", len(resp.GetPools()))
	}
	got := resp.GetPools()[0]
	if got.GetUtilization() != "NOT APPLICABLE" {
		t.Fatalf("address-only gRPC utilization = %q, want NOT APPLICABLE", got.GetUtilization())
	}
	if got.GetTotalPorts() != 0 || got.GetUsedPorts() != 0 || got.GetAvailablePorts() != 0 {
		t.Fatalf("address-only gRPC port figures = total %d used %d available %d, want all zero/N/A",
			got.GetTotalPorts(), got.GetUsedPorts(), got.GetAvailablePorts())
	}

	// Control: the same live status remains measurable for a normal PAT pool.
	pool.PortNoTranslation = false
	dp.status.SourceNATPools[0].UsedPorts = 100
	resp, err = s.GetNATPoolStats(context.Background(), &pb.GetNATPoolStatsRequest{})
	if err != nil {
		t.Fatalf("GetNATPoolStats control: %v", err)
	}
	if len(resp.GetPools()) != 1 || resp.GetPools()[0].GetUtilization() == "NOT APPLICABLE" {
		t.Fatalf("normal PAT control lost numeric utilization: %+v", resp.GetPools())
	}
}
