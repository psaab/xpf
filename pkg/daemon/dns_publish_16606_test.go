package daemon

import (
	"reflect"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #16606: the dns-name refresher applied a private clone the store never
// published. Scheduler / route-overlay republishes read
// store.ActiveConfig() (stale answers) and rebuilt address-book rows
// with the old answer, while the baseline already recorded the new one
// so no tick repaired it.
//
// FAIL-ON-REVERT: removing the Store.PublishRefreshedDNS swap from
// applyDNSRefreshedConfig leaves ActiveConfig() at the old answer and
// the baseline keyed to the unpublished base — both asserts RED.

func TestDNSRefreshPublishesStoreGeneration16606(t *testing.T) {
	set := stubDNS15933(t, map[string][]string{
		"global.example.com": {"10.0.0.1"},
		"local.example.com":  {"10.0.0.2"},
	})
	d, s := dnsDaemon15933(t)
	base := s.ActiveConfig()
	baseGen, _ := s.ActiveSnapshot()

	var applied []*config.Config
	d.applyBodyForTest = func(cfg *config.Config) { applied = append(applied, cfg) }

	set(map[string][]string{
		"global.example.com": {"10.9.9.9"},
		"local.example.com":  {"10.0.0.2"},
	})
	d.refreshDNSOnce()

	if len(applied) != 1 {
		t.Fatalf("refresh applies = %d, want 1", len(applied))
	}
	// The store now publishes the refreshed generation.
	active := s.ActiveConfig()
	if active == base {
		t.Fatal("store still publishes the stale generation after DNS refresh (#16606)")
	}
	if active != applied[0] {
		t.Fatal("store active is not the applied refreshed clone")
	}
	if got := globalSvc15933(t, active); !reflect.DeepEqual(got, []string{"10.9.9.9/32"}) {
		t.Fatalf("store active global svc = %v, want refreshed answer 10.9.9.9/32", got)
	}
	// The original generation object was never mutated (C5 preserved).
	if got := globalSvc15933(t, base); !reflect.DeepEqual(got, []string{"10.0.0.1/32"}) {
		t.Fatalf("original generation mutated: %v", got)
	}
	// A new store generation was published.
	gen, snapCfg := s.ActiveSnapshot()
	if gen <= baseGen || snapCfg != active {
		t.Fatalf("ActiveSnapshot = (%d, %p), want advanced gen with refreshed cfg", gen, snapCfg)
	}
	// Baseline is keyed to the published generation.
	if got := d.dnsBaselineFor(active); got == nil {
		t.Fatal("baseline not keyed to published refreshed generation")
	}
	// Operator tree / persisted identity is untouched: DNS answers are
	// runtime state, so the active tree hash must be unchanged.
	if got := s.ActiveConfigGeneration(); got == "" {
		t.Fatal("ActiveConfigGeneration empty after publish")
	}

	// Next tick with unchanged answers: no republish, no store churn.
	d.refreshDNSOnce()
	if len(applied) != 1 {
		t.Fatalf("unchanged tick republished: applies=%d", len(applied))
	}
	if s.ActiveConfig() != active {
		t.Fatal("unchanged tick churned the published generation")
	}
}
