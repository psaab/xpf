package grpcapi

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/psaab/xpf/pkg/configstore"
	"github.com/psaab/xpf/pkg/dataplane"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
)

type schedulerCounterGRPCDP struct {
	*dataplane.Manager
	counters map[uint32]dataplane.CounterValue
}

func (d *schedulerCounterGRPCDP) IsLoaded() bool {
	return true
}

func (d *schedulerCounterGRPCDP) ReadPolicyCounters(policyID uint32) (dataplane.CounterValue, error) {
	return d.counters[policyID], nil
}

func newSchedulerCounterGRPCStore(t *testing.T) *configstore.Store {
	t.Helper()

	store := configstore.New(filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure() error = %v", err)
	}
	if err := store.LoadOverride(`
schedulers {
    scheduler workhours {
        daily;
    }
}
security {
    zones {
        security-zone dmz;
        security-zone trust;
        security-zone untrust;
    }
    policies {
        from-zone trust to-zone dmz {
            policy plain-allow {
                match { source-address any; destination-address any; application any; }
                then { permit; }
            }
        }
        from-zone trust to-zone untrust {
            policy scheduled-allow {
                match { source-address any; destination-address any; application any; }
                then { permit; count; }
                scheduler-name workhours;
            }
        }
        global {
            policy global-scheduled {
                match { source-address any; destination-address any; application any; }
                then { permit; count; }
                scheduler-name workhours;
            }
        }
    }
}
`); err != nil {
		t.Fatalf("LoadOverride() error = %v", err)
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit() error = %v", err)
	}
	return store
}

func scheduledCounterGRPCPolicyID(t *testing.T, store *configstore.Store) uint32 {
	t.Helper()

	cfg := store.ActiveConfig()
	if cfg == nil {
		t.Fatal("ActiveConfig() = nil")
	}
	for setID, zpp := range cfg.Security.Policies {
		for ruleIndex, pol := range zpp.Policies {
			if zpp.FromZone == "trust" && zpp.ToZone == "untrust" && pol.Name == "scheduled-allow" {
				if setID == 0 {
					t.Fatalf("scheduled policy compiled in policy set 0; test needs a nonzero policy set")
				}
				return uint32(setID)*dataplane.MaxRulesPerPolicy + uint32(ruleIndex)
			}
		}
	}
	t.Fatal("scheduled policy not found")
	return 0
}

func TestGetPoliciesExposesScheduledRuleCounters(t *testing.T) {
	store := newSchedulerCounterGRPCStore(t)
	policyID := scheduledCounterGRPCPolicyID(t, store)
	s := &Server{
		store: store,
		dp: &schedulerCounterGRPCDP{
			Manager: dataplane.New(),
			counters: map[uint32]dataplane.CounterValue{
				1:                               {Packets: 99, Bytes: 9900},
				policyID:                        {Packets: 23, Bytes: 2300},
				dataplane.MaxRulesPerPolicy * 2: {Packets: 31, Bytes: 3100},
			},
		},
	}

	resp, err := s.GetPolicies(context.Background(), &pb.GetPoliciesRequest{})
	if err != nil {
		t.Fatalf("GetPolicies() error = %v", err)
	}
	for _, policy := range resp.GetPolicies() {
		if policy.GetFromZone() != "trust" || policy.GetToZone() != "untrust" {
			continue
		}
		for _, rule := range policy.GetRules() {
			if rule.GetName() != "scheduled-allow" {
				continue
			}
			if !rule.GetCount() {
				t.Fatal("scheduled-allow Count = false, want true")
			}
			if rule.GetHitPackets() != 23 || rule.GetHitBytes() != 2300 {
				t.Fatalf("scheduled-allow counters = %d packets/%d bytes, want 23/2300",
					rule.GetHitPackets(), rule.GetHitBytes())
			}
			return
		}
	}
	t.Fatal("scheduled-allow rule not found in gRPC response")
}

func TestGetPoliciesExposesGlobalScheduledRuleCounters(t *testing.T) {
	store := newSchedulerCounterGRPCStore(t)
	s := &Server{
		store: store,
		dp: &schedulerCounterGRPCDP{
			Manager: dataplane.New(),
			counters: map[uint32]dataplane.CounterValue{
				dataplane.MaxRulesPerPolicy * 2: {Packets: 31, Bytes: 3100},
			},
		},
	}

	resp, err := s.GetPolicies(context.Background(), &pb.GetPoliciesRequest{})
	if err != nil {
		t.Fatalf("GetPolicies() error = %v", err)
	}
	for _, policy := range resp.GetPolicies() {
		if policy.GetFromZone() != "*" || policy.GetToZone() != "*" {
			continue
		}
		for _, rule := range policy.GetRules() {
			if rule.GetName() != "global-scheduled" {
				continue
			}
			if !rule.GetCount() {
				t.Fatal("global-scheduled Count = false, want true")
			}
			if rule.GetHitPackets() != 31 || rule.GetHitBytes() != 3100 {
				t.Fatalf("global-scheduled counters = %d packets/%d bytes, want 31/3100",
					rule.GetHitPackets(), rule.GetHitBytes())
			}
			return
		}
	}
	t.Fatal("global-scheduled rule not found in gRPC response")
}
