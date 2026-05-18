package api

import (
	"encoding/json"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/psaab/xpf/pkg/configstore"
	"github.com/psaab/xpf/pkg/dataplane"
)

type schedulerCounterAPIDP struct {
	*dataplane.Manager
	counters map[uint32]dataplane.CounterValue
}

func (d *schedulerCounterAPIDP) IsLoaded() bool {
	return true
}

func (d *schedulerCounterAPIDP) ReadPolicyCounters(policyID uint32) (dataplane.CounterValue, error) {
	return d.counters[policyID], nil
}

func newSchedulerCounterAPIStore(t *testing.T) *configstore.Store {
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

func scheduledCounterPolicyID(t *testing.T, store *configstore.Store) uint32 {
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

func TestPoliciesHandlerExposesScheduledRuleCounters(t *testing.T) {
	store := newSchedulerCounterAPIStore(t)
	policyID := scheduledCounterPolicyID(t, store)
	s := &Server{
		store: store,
		dp: &schedulerCounterAPIDP{
			Manager: dataplane.New(),
			counters: map[uint32]dataplane.CounterValue{
				1:        {Packets: 99, Bytes: 9900},
				policyID: {Packets: 17, Bytes: 1700},
			},
		},
	}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/v1/security/policies", nil)
	s.policiesHandler(rr, req)

	if rr.Code != 200 {
		t.Fatalf("status = %d, want 200; body: %s", rr.Code, rr.Body.String())
	}
	var resp struct {
		Success bool         `json:"success"`
		Data    []PolicyInfo `json:"data"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	if !resp.Success {
		t.Fatalf("success = false; body: %s", rr.Body.String())
	}

	for _, policy := range resp.Data {
		if policy.FromZone != "trust" || policy.ToZone != "untrust" {
			continue
		}
		for _, rule := range policy.Rules {
			if rule.Name != "scheduled-allow" {
				continue
			}
			if !rule.Count {
				t.Fatal("scheduled-allow Count = false, want true")
			}
			if rule.HitPackets != 17 || rule.HitBytes != 1700 {
				t.Fatalf("scheduled-allow counters = %d packets/%d bytes, want 17/1700",
					rule.HitPackets, rule.HitBytes)
			}
			return
		}
	}
	t.Fatal("scheduled-allow rule not found in API response")
}
