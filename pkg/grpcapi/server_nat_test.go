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

func (d *natApplyResultGRPCDP) Telemetry() dataplane.Telemetry {
	return dataplane.NewDataPlaneTelemetry(d)
}

func (d *natApplyResultGRPCDP) ReadNATRuleCounter(counterID uint32) (dataplane.CounterValue, error) {
	return dataplane.CounterValue{Packets: uint64(counterID), Bytes: uint64(counterID) * 100}, nil
}

type natSessionProviderGRPCDP struct {
	*dataplane.Manager
	result *dataplane.ApplyResult
	store  dataplane.SessionStore
}

func (d *natSessionProviderGRPCDP) IsLoaded() bool {
	return true
}

func (d *natSessionProviderGRPCDP) LastApplyResult() *dataplane.ApplyResult {
	return d.result.Clone()
}

func (d *natSessionProviderGRPCDP) Sessions() dataplane.SessionStore {
	return d.store
}

type natSessionGRPCStore struct {
	dataplane.SessionStore
	v4 []dataplane.SessionValue
	v6 []dataplane.SessionValueV6
}

func (s *natSessionGRPCStore) ForEachV4(fn func(dataplane.SessionKey, dataplane.SessionValue) bool) error {
	for _, val := range s.v4 {
		if !fn(dataplane.SessionKey{}, val) {
			return nil
		}
	}
	return nil
}

func (s *natSessionGRPCStore) ForEachV6(fn func(dataplane.SessionKeyV6, dataplane.SessionValueV6) bool) error {
	for _, val := range s.v6 {
		if !fn(dataplane.SessionKeyV6{}, val) {
			return nil
		}
	}
	return nil
}

func newNATStatsGRPCStore(t *testing.T) *configstore.Store {
	t.Helper()

	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
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

func newIfaceNATStatsGRPCStore(t *testing.T) *configstore.Store {
	t.Helper()
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure() error = %v", err)
	}
	if _, err := store.LoadSet(`set security nat source rule-set trust-to-wan from zone trust
set security nat source rule-set trust-to-wan to zone wan
set security nat source rule-set trust-to-wan rule r1 match source-address 0.0.0.0/0
set security nat source rule-set trust-to-wan rule r1 then source-nat interface
set security nat source rule-set guest-to-wan from zone guest
set security nat source rule-set guest-to-wan to zone wan
set security nat source rule-set guest-to-wan rule r1 match source-address 0.0.0.0/0
set security nat source rule-set guest-to-wan rule r1 then source-nat interface`); err != nil {
		t.Fatalf("LoadSet() error = %v", err)
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit() error = %v", err)
	}
	return store
}

// TestGetNATPoolStatsInterfaceModePerRuleSet is a FAIL-ON-REVERT guard for
// #3417: each interface-mode pool row must report only the SNAT sessions that
// traversed its own from/to zone pair, NOT the firewall-wide SNAT total.
//
// Two distinct interface-mode rule sets: trust->wan (3 SNAT sessions) and
// guest->wan (1 SNAT session). The global SNAT total is 4. If the row UsedPorts
// is reverted to counts.total, BOTH rows report 4 and the assertions fail.
func TestGetNATPoolStatsInterfaceModePerRuleSet(t *testing.T) {
	dp := &natSessionProviderGRPCDP{
		Manager: dataplane.New(),
		result: &dataplane.ApplyResult{
			ZoneIDs: map[string]uint16{"trust": 2, "guest": 4, "wan": 5},
		},
		store: &natSessionGRPCStore{
			v4: []dataplane.SessionValue{
				{Flags: dataplane.SessFlagSNAT, IngressZone: 2, EgressZone: 5},
				{Flags: dataplane.SessFlagSNAT, IngressZone: 2, EgressZone: 5},
				{Flags: dataplane.SessFlagSNAT, IngressZone: 2, EgressZone: 5},
				{Flags: dataplane.SessFlagSNAT, IngressZone: 4, EgressZone: 5},
				// reverse + non-SNAT noise that must not count.
				{Flags: dataplane.SessFlagSNAT, IsReverse: 1, IngressZone: 5, EgressZone: 2},
				{Flags: dataplane.SessFlagDNAT, IngressZone: 2, EgressZone: 5},
			},
		},
	}
	s := &Server{store: newIfaceNATStatsGRPCStore(t), dp: dp}

	resp, err := s.GetNATPoolStats(context.Background(), &pb.GetNATPoolStatsRequest{})
	if err != nil {
		t.Fatalf("GetNATPoolStats() error = %v", err)
	}
	if resp.TotalActiveTranslations != 4 {
		t.Fatalf("TotalActiveTranslations = %d, want 4", resp.TotalActiveTranslations)
	}
	got := map[string]int32{}
	for _, pool := range resp.Pools {
		if !pool.IsInterface {
			t.Errorf("unexpected non-interface pool %q", pool.Name)
			continue
		}
		got[pool.Name] = pool.UsedPorts
	}
	if got["trust->wan"] != 3 {
		t.Errorf("trust->wan UsedPorts = %d, want 3 (per-rule-set, NOT global total 4)", got["trust->wan"])
	}
	if got["guest->wan"] != 1 {
		t.Errorf("guest->wan UsedPorts = %d, want 1 (per-rule-set, NOT global total 4)", got["guest->wan"])
	}
}

func TestGetNATRuleStatsReadsApplyResultOnce(t *testing.T) {
	dp := &natApplyResultGRPCDP{
		Manager: dataplane.New(),
		result: &dataplane.ApplyResult{
			NATCounterIDs: map[string]uint32{
				dataplane.NATCounterKey(dataplane.NATCounterTypeSource, "trust-to-untrust", "r1"): 21,
				dataplane.NATCounterKey(dataplane.NATCounterTypeSource, "trust-to-untrust", "r2"): 22,
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

func TestGetNATPoolStatsUsesSessionStoreProvider(t *testing.T) {
	dp := &natSessionProviderGRPCDP{
		Manager: dataplane.New(),
		result: &dataplane.ApplyResult{
			ZoneIDs: map[string]uint16{
				"trust":   1,
				"untrust": 2,
			},
		},
		store: &natSessionGRPCStore{
			v4: []dataplane.SessionValue{
				{Flags: dataplane.SessFlagSNAT, IngressZone: 1, EgressZone: 2},
				{Flags: dataplane.SessFlagSNAT, IsReverse: 1, IngressZone: 1, EgressZone: 2},
				{Flags: dataplane.SessFlagDNAT, IngressZone: 1, EgressZone: 2},
			},
			v6: []dataplane.SessionValueV6{
				{Flags: dataplane.SessFlagSNAT, IngressZone: 1, EgressZone: 2},
			},
		},
	}
	s := &Server{store: newNATStatsGRPCStore(t), dp: dp}

	resp, err := s.GetNATPoolStats(context.Background(), &pb.GetNATPoolStatsRequest{})
	if err != nil {
		t.Fatalf("GetNATPoolStats() error = %v", err)
	}
	if resp.TotalActiveTranslations != 2 {
		t.Fatalf("TotalActiveTranslations = %d, want 2", resp.TotalActiveTranslations)
	}
	if len(resp.RuleSetSessions) != 1 {
		t.Fatalf("len(RuleSetSessions) = %d, want 1", len(resp.RuleSetSessions))
	}
	got := resp.RuleSetSessions[0]
	if got.FromZone != "trust" || got.ToZone != "untrust" || got.Sessions != 2 {
		t.Fatalf("RuleSetSessions[0] = %+v, want trust->untrust sessions=2", got)
	}
	interfacePools := 0
	for _, pool := range resp.Pools {
		if pool.IsInterface && pool.UsedPorts != 2 {
			t.Fatalf("interface pool %q UsedPorts = %d, want 2", pool.Name, pool.UsedPorts)
		}
		if pool.IsInterface {
			interfacePools++
		}
	}
	if interfacePools != 1 {
		t.Fatalf("interface pool count = %d, want 1 (one row per from/to zone pair)", interfacePools)
	}
}
