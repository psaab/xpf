package api

import (
	"path/filepath"
	"testing"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/psaab/xpf/pkg/configstore"
	"github.com/psaab/xpf/pkg/dataplane"
)

// #3286: the Prometheus `xpf_policy_hits_total` collector emitted
// from_zone="*"/to_zone="*" for ALL global policies, scoped included.
// Prometheus is the canonical counter-validation surface, so a scoped
// global (#3148 `match from-zone`/`to-zone`) showing all-zones labels is the
// exact ambiguity the issue calls out. The collector now uses the policy's
// Match.FromZone/ToZone for the labels when set. This test is the
// fail-on-revert guard: revert the label fix to "*"/"*" → the scoped
// assertion goes RED.

func scopedGlobalMetricsStore(t *testing.T) *configstore.Store {
	t.Helper()
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure() error = %v", err)
	}
	// policy-stats enabled so both globals emit a per-policy counter.
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
        global {
            policy scoped-global {
                match {
                    from-zone trust;
                    to-zone untrust;
                    source-address any;
                    destination-address any;
                    application any;
                }
                then { deny; }
            }
            policy open-global {
                match { source-address any; destination-address any; application any; }
                then { permit; }
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
	cfg := store.ActiveConfig()
	if cfg == nil || len(cfg.Security.GlobalPolicies) != 2 {
		t.Fatalf("want 2 global policies, got %v", cfg)
	}
	if !cfg.Security.PolicyStatsEnabled {
		t.Fatal("policy-stats precondition not met")
	}
	return store
}

func TestCollectPolicyCountersScopedGlobalLabels(t *testing.T) {
	store := scopedGlobalMetricsStore(t)
	scopedID := globalCounterPolicyID(t, store, "scoped-global")
	openID := globalCounterPolicyID(t, store, "open-global")
	// #7016: see TestCollectPolicyCountersNilSlotsNoPanic -- initialize the
	// real descriptor set, then override the asserted one.
	c := &xpfCollector{deps: collectorDeps{store: store}}
	c.initPolicyDescriptors()
	c.policyHitsTotal = prometheus.NewDesc(
		"xpf_policy_hits_total",
		"policy hits",
		[]string{"from_zone", "to_zone", "policy_name"},
		nil,
	)
	dp := &schedulerCounterAPIDP{
		Manager: dataplane.New(),
		counters: map[uint32]dataplane.CounterValue{
			scopedID: {Packets: 41, Bytes: 4100},
			openID:   {Packets: 52, Bytes: 5200},
		},
	}

	ch := make(chan prometheus.Metric)
	go func() {
		c.collectPolicyCounters(ch, dp)
		close(ch)
	}()
	var got []prometheus.Metric
	for m := range ch {
		got = append(got, m)
	}

	// Scoped global must carry its real zone pair on the labels — NOT */*.
	assertCounterClose(t, got, c.policyHitsTotal, map[string]string{
		"from_zone":   "trust",
		"to_zone":     "untrust",
		"policy_name": "scoped-global",
	}, 41)
	// Unscoped global keeps the all-zones labels (no regression).
	assertCounterClose(t, got, c.policyHitsTotal, map[string]string{
		"from_zone":   "*",
		"to_zone":     "*",
		"policy_name": "open-global",
	}, 52)
}
