package grpcapi

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/psaab/xpf/pkg/configstore"
	"github.com/psaab/xpf/pkg/dataplane"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
)

type natApplyResultGRPCDP struct {
	*dataplane.Manager
	result *dataplane.ApplyResult
	calls  int
}

func (d *natApplyResultGRPCDP) IsLoaded() bool {
	return true
}

func (d *natApplyResultGRPCDP) LastApplyResult() *dataplane.ApplyResult {
	d.calls++
	return d.result.Clone()
}

func (d *natApplyResultGRPCDP) ReadNATRuleCounter(counterID uint32) (dataplane.CounterValue, error) {
	return dataplane.CounterValue{Packets: uint64(counterID), Bytes: uint64(counterID) * 100}, nil
}

func newNATStatsGRPCStore(t *testing.T) *configstore.Store {
	t.Helper()

	store := configstore.New(filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure() error = %v", err)
	}
	if _, err := store.LoadSet(`set security nat source rule-set trust-to-untrust from zone trust
set security nat source rule-set trust-to-untrust to zone untrust
set security nat source rule-set trust-to-untrust rule r1 match source-address 10.0.0.0/8
set security nat source rule-set trust-to-untrust rule r1 then source-nat interface
set security nat source rule-set trust-to-untrust rule r2 match source-address 172.16.0.0/12
set security nat source rule-set trust-to-untrust rule r2 then source-nat interface`); err != nil {
		t.Fatalf("LoadSet() error = %v", err)
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit() error = %v", err)
	}
	return store
}

func TestGetNATRuleStatsReadsApplyResultOnce(t *testing.T) {
	dp := &natApplyResultGRPCDP{
		Manager: dataplane.New(),
		result: &dataplane.ApplyResult{
			NATCounterIDs: map[string]uint32{
				"trust-to-untrust/r1": 21,
				"trust-to-untrust/r2": 22,
			},
		},
	}
	s := &Server{store: newNATStatsGRPCStore(t), dp: dp}

	resp, err := s.GetNATRuleStats(context.Background(), &pb.GetNATRuleStatsRequest{})
	if err != nil {
		t.Fatalf("GetNATRuleStats() error = %v", err)
	}
	if dp.calls != 1 {
		t.Fatalf("LastApplyResult() calls = %d, want 1", dp.calls)
	}
	if len(resp.Rules) != 2 {
		t.Fatalf("len(resp.Rules) = %d, want 2", len(resp.Rules))
	}
	hits := make(map[string]uint64, len(resp.Rules))
	for _, rule := range resp.Rules {
		hits[rule.RuleName] = rule.HitPackets
	}
	if hits["r1"] != 21 || hits["r2"] != 22 {
		t.Fatalf("hit packets = %+v, want r1=21 r2=22", hits)
	}
}
