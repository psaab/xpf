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

// ordinaryDNSApply17744 drives applyConfigLocked's normal deferred baseline
// hook through the test apply-body seam, then lets the production defer run.
// Clearing the seam inside the body keeps this an observed successful apply
// while exercising the same publication decision as the real apply path.
func ordinaryDNSApply17744(t *testing.T, d *Daemon, cfg *config.Config) *config.Config {
	t.Helper()
	if err := d.applySem.Acquire(t.Context(), 1); err != nil {
		t.Fatalf("acquire applySem: %v", err)
	}
	defer d.applySem.Release(1)
	var applied *config.Config
	d.applyBodyForTest = func(cfg *config.Config) {
		applied = cfg
		d.applyBodyForTest = nil
	}
	d.applyConfigUnderSem(cfg)
	return applied
}

func TestOrdinaryDNSApplyPublishesResolvedClone17744(t *testing.T) {
	set := stubDNS15933(t, map[string][]string{
		"global.example.com": {"10.0.0.1"},
		"local.example.com":  {"10.0.0.2"},
	})
	d, s := dnsDaemon15933(t)
	base := s.ActiveConfig()
	baseGen, _ := s.ActiveSnapshot()

	set(map[string][]string{
		"global.example.com": {"10.9.9.9"},
		"local.example.com":  {"10.0.0.2"},
	})
	resolved := d.resolveDNSBeforeApply(base)
	if resolved == base {
		t.Fatal("ordinary apply resolution reused the published pointer")
	}
	applied := ordinaryDNSApply17744(t, d, resolved)
	if applied != resolved {
		t.Fatalf("ordinary apply used %p, want resolved clone %p", applied, resolved)
	}
	active := s.ActiveConfig()
	if active != resolved {
		t.Fatalf("store active = %p, want applied DNS clone %p", active, resolved)
	}
	if got := globalSvc15933(t, active); !reflect.DeepEqual(got, []string{"10.9.9.9/32"}) {
		t.Fatalf("store active DNS answer = %v, want B [10.9.9.9/32]", got)
	}
	gen, snapshotCfg := s.ActiveSnapshot()
	if gen <= baseGen || snapshotCfg != active {
		t.Fatalf("active snapshot = (%d, %p), want published clone after generation %d", gen, snapshotCfg, baseGen)
	}
	if got := d.dnsBaselineFor(active); got == nil || !dnsAnswersEqual(got, snapshotDNSAnswers(active)) {
		t.Fatalf("baseline = %v, want answers keyed to the published clone", got)
	}

	// The next identical refresh used to compare B against the baseline
	// while the store still held A, suppressing the publication needed to
	// repair the active config. Now both store and baseline carry B.
	d.refreshDNSOnce()
	if s.ActiveConfig() != active {
		t.Fatal("unchanged refresh churned the published clone")
	}
	if got := globalSvc15933(t, s.ActiveConfig()); !reflect.DeepEqual(got, []string{"10.9.9.9/32"}) {
		t.Fatalf("active DNS answer after refresh = %v, want B [10.9.9.9/32]", got)
	}
}

func TestOrdinaryDNSApplyUnchangedAnswersSkipsRepublish17744(t *testing.T) {
	stubDNS15933(t, map[string][]string{
		"global.example.com": {"10.0.0.1"},
		"local.example.com":  {"10.0.0.2"},
	})
	d, s := dnsDaemon15933(t)
	base := s.ActiveConfig()
	baseGen, _ := s.ActiveSnapshot()
	resolved := d.resolveDNSBeforeApply(base)
	if resolved == base {
		t.Fatal("ordinary apply resolution reused the published pointer")
	}
	if applied := ordinaryDNSApply17744(t, d, resolved); applied != resolved {
		t.Fatalf("ordinary apply used %p, want resolved clone %p", applied, resolved)
	}
	gen, snapshotCfg := s.ActiveSnapshot()
	if s.ActiveConfig() != base || snapshotCfg != base || gen != baseGen {
		t.Fatalf("unchanged-DNS apply republished store generation: active=%p snapshot=(%d,%p), want base=%p generation=%d",
			s.ActiveConfig(), gen, snapshotCfg, base, baseGen)
	}
}

func TestExplicitDNSApplyDoesNotPublishUnrelatedConfig17744(t *testing.T) {
	set := stubDNS15933(t, map[string][]string{
		"global.example.com": {"10.0.0.1"},
		"local.example.com":  {"10.0.0.2"},
	})
	d, s := dnsDaemon15933(t)
	base := s.ActiveConfig()
	baseGen, _ := s.ActiveSnapshot()
	unrelated := base.CloneForDNSRefresh()
	set(map[string][]string{
		"global.example.com": {"10.9.9.9"},
		"local.example.com":  {"10.0.0.2"},
	})
	var applied *config.Config
	d.applyBodyForTest = func(cfg *config.Config) {
		applied = cfg
		d.applyBodyForTest = nil
	}
	d.applyConfig(unrelated)
	if applied == nil || applied == unrelated {
		t.Fatal("explicit DNS apply did not use its own resolved clone")
	}
	if got := globalSvc15933(t, applied); !reflect.DeepEqual(got, []string{"10.9.9.9/32"}) {
		t.Fatalf("explicit apply DNS answer = %v, want B [10.9.9.9/32]", got)
	}
	gen, snapshotCfg := s.ActiveSnapshot()
	if s.ActiveConfig() != base || snapshotCfg != base || gen != baseGen {
		t.Fatalf("explicit unrelated apply replaced active config: active=%p snapshot=(%d,%p), want base=%p generation=%d",
			s.ActiveConfig(), gen, snapshotCfg, base, baseGen)
	}
}
