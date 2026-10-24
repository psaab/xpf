package api

import (
	"encoding/json"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/psaab/xpf/pkg/configstore"
	"github.com/psaab/xpf/pkg/dataplane"
)

// #3476: the policy/screen inventory display surfaces dereference nil
// zone-pair sets, nil rules, nil global rules, and nil screen-profile map
// values that the tolerant / HA-sync config path (#3474) can produce and the
// runtime walker (pkg/dataplane/userspace/{policies,screens}.go) tolerates.
// These tests inject those nil slots into the live ActiveConfig and drive each
// REST/Prometheus surface; reverting any of the security.go / metrics_counters.go
// nil guards makes the corresponding subtest panic (RED on revert).

// nilSlotStore builds a committed config with one zone-pair policy set, one
// global policy, and one screen profile, then injects a nil zone-pair set, a
// nil rule, a nil global rule, and a nil screen-profile value into the live
// ActiveConfig (the strict compiler never emits these; the tolerant path can).
func nilSlotStore(t *testing.T) *configstore.Store {
	t.Helper()
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure() error = %v", err)
	}
	if err := store.LoadOverride(`
security {
    policy-stats {
        system-wide enable;
    }
    zones {
        security-zone trust;
        security-zone untrust;
    }
    policies {
        from-zone trust to-zone untrust {
            policy p1 {
                match { source-address any; destination-address any; application any; }
                then { permit; count; }
            }
        }
        global {
            policy g1 {
                match { source-address any; destination-address any; application any; }
                then { deny; count; }
            }
        }
    }
    screen {
        ids-option sp {
            tcp { land; syn-flood; }
            icmp { ping-death; }
        }
    }
}
`); err != nil {
		t.Fatalf("LoadOverride() error = %v", err)
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit() error = %v", err)
	}
	injectNilSlots(t, store)
	return store
}

// injectNilSlots mutates the live compiled config to add the nil slots a
// tolerant/HA-sync config path can leave behind. Must run AFTER the final
// Commit (which recompiles and would normalize the nils away).
func injectNilSlots(t *testing.T, store *configstore.Store) {
	t.Helper()
	cfg := store.ActiveConfig()
	if cfg == nil {
		t.Fatal("ActiveConfig() = nil")
	}
	if len(cfg.Security.Policies) == 0 || len(cfg.Security.GlobalPolicies) == 0 {
		t.Fatalf("fixture missing policies: %d zone-pair sets, %d globals",
			len(cfg.Security.Policies), len(cfg.Security.GlobalPolicies))
	}
	// nil rule inside the real zone-pair set
	cfg.Security.Policies[0].Policies = append(cfg.Security.Policies[0].Policies, nil)
	// nil zone-pair set
	cfg.Security.Policies = append(cfg.Security.Policies, nil)
	// nil global rule
	cfg.Security.GlobalPolicies = append(cfg.Security.GlobalPolicies, nil)
	// nil screen-profile map value (the fixture always commits one profile, so
	// the map is non-nil here)
	cfg.Security.Screen["zz-nil-profile"] = nil
}

func TestPoliciesHandlerNilSlotsNoPanic(t *testing.T) {
	s := &Server{
		store: nilSlotStore(t),
		dp: &schedulerCounterAPIDP{
			Manager:  dataplane.New(),
			counters: map[uint32]dataplane.CounterValue{},
		},
	}
	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/v1/security/policies", nil)
	s.policiesHandler(rr, req) // panics on revert of the zpp/rule guards
	if rr.Code != 200 {
		t.Fatalf("status = %d, want 200; body: %s", rr.Code, rr.Body.String())
	}
	var resp struct {
		Success bool         `json:"success"`
		Data    []PolicyInfo `json:"data"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v; body: %s", err, rr.Body.String())
	}
	if !resp.Success {
		t.Fatalf("success=false; body: %s", rr.Body.String())
	}
}

func TestScreenHandlerNilProfileNoPanic(t *testing.T) {
	s := &Server{store: nilSlotStore(t)}
	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/v1/security/screen", nil)
	s.screenHandler(rr, req) // panics on revert of the screenChecks(nil) guard
	if rr.Code != 200 {
		t.Fatalf("status = %d, want 200; body: %s", rr.Code, rr.Body.String())
	}
}

func TestScreenChecksNilReturnsNil(t *testing.T) {
	if got := screenChecks(nil); got != nil {
		t.Fatalf("screenChecks(nil) = %v, want nil", got)
	}
}

func TestCollectPolicyCountersNilSlotsNoPanic(t *testing.T) {
	store := nilSlotStore(t)
	// #7016: initialize the real policy descriptor set so every desc
	// collectPolicyCounters emits UNCONDITIONALLY (the
	// xpf_policy_counters_unpublished_rules gauge) is present, then override
	// the one desc this test asserts custom labels on. A bare literal listing
	// only policyHitsTotal nil-panics the moment the collector gains another
	// always-emitted family.
	c := &xpfCollector{deps: collectorDeps{store: store}}
	c.initPolicyDescriptors()
	c.policyHitsTotal = prometheus.NewDesc(
		"xpf_policy_hits_total", "policy hits",
		[]string{"from_zone", "to_zone", "policy_name"}, nil,
	)
	dp := &schedulerCounterAPIDP{
		Manager:  dataplane.New(),
		counters: map[uint32]dataplane.CounterValue{},
	}
	ch := make(chan prometheus.Metric)
	go func() {
		// panics on revert of the zpp/rule guards in collectPolicyCounters
		c.collectPolicyCounters(ch, dp)
		close(ch)
	}()
	for range ch {
	}
}
