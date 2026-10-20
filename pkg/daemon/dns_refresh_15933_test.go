package daemon

import (
	"context"
	"path/filepath"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sync/semaphore"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/configstore"
	"github.com/psaab/xpf/pkg/vrrp"
)

// #15933 — periodic dns-name refresh defects (retro C4/C5):
//
//   C4: snapshotDNSAnswers keyed by bare authored name, so a stable
//   same-named zone-local entry overwrote a changed global entry and the
//   global change was never republished.
//   C5: the refresher mutated the published active config (resolver writes
//   into store.ActiveConfig()'s *Config) before/outside the apply lock,
//   racing concurrent applies and readers of the same generation.
//
// FAIL-ON-REVERT: restoring bare-name keys makes the C4 test report no
// change; restoring in-place refresh of the active config makes the C5
// tests mutate the published generation (and trips -race against the
// concurrent reader below).

const dnsCfg15933 = `
security {
    zones {
        security-zone trust;
        security-zone untrust;
    }
    address-book {
        global {
            address svc { dns-name global.example.com; }
        }
    }
    zones {
        security-zone trust {
            address-book {
                address svc { dns-name local.example.com; }
            }
        }
    }
}
`

// stubDNS15933 installs a mutable, concurrency-safe resolver. Answers are
// swapped between phases of a test via set().
func stubDNS15933(t *testing.T, initial map[string][]string) (set func(map[string][]string)) {
	t.Helper()
	var mu sync.RWMutex
	answers := initial
	set = func(m map[string][]string) {
		mu.Lock()
		answers = m
		mu.Unlock()
	}
	restore := config.SetLookupAddressDNSNameForTest(func(fqdn string) ([]string, error) {
		mu.RLock()
		defer mu.RUnlock()
		return append([]string(nil), answers[fqdn]...), nil
	})
	t.Cleanup(restore)
	return set
}

func dnsDaemon15933(t *testing.T) (*Daemon, *configstore.Store) {
	t.Helper()
	s := newConfigStore(t, filepath.Join(t.TempDir(), "config.db"))
	if _, err := s.SyncApply(dnsCfg15933, nil); err != nil {
		t.Fatalf("SyncApply premise config: %v", err)
	}
	d := &Daemon{
		applySem: semaphore.NewWeighted(1),
		store:    s,
		opts:     Options{NoDataplane: true},
	}
	return d, s
}

func globalSvc15933(t *testing.T, cfg *config.Config) []string {
	t.Helper()
	a := cfg.Security.AddressBook.Addresses["svc"]
	if a == nil {
		t.Fatalf("global svc missing: %v", cfg.Security.AddressBook.Addresses)
	}
	return a.UsableValues()
}

// C4: a global dns answer change must be detected and republished even when
// a same-named zone-local entry is unchanged.
func TestDNSRefreshDetectsGlobalChangeShadowedByZoneLocal15933(t *testing.T) {
	set := stubDNS15933(t, map[string][]string{
		"global.example.com": {"10.0.0.1"},
		"local.example.com":  {"10.0.0.2"},
	})
	d, s := dnsDaemon15933(t)

	active := s.ActiveConfig()
	if got := globalSvc15933(t, active); !reflect.DeepEqual(got, []string{"10.0.0.1/32"}) {
		t.Fatalf("premise global svc = %v", got)
	}
	folded := config.ZoneLocalQualify("trust", "svc")
	if got := active.Security.AddressBook.Addresses[folded].UsableValues(); !reflect.DeepEqual(got, []string{"10.0.0.2/32"}) {
		t.Fatalf("premise folded svc = %v", got)
	}

	var applied []*config.Config
	d.applyBodyForTest = func(cfg *config.Config) { applied = append(applied, cfg) }

	// Only the GLOBAL answer changes; the zone-local answer is stable.
	set(map[string][]string{
		"global.example.com": {"10.9.9.9"},
		"local.example.com":  {"10.0.0.2"},
	})
	d.refreshDNSOnce()

	if len(applied) != 1 {
		t.Fatalf("refresh published %d applies, want 1 (global change shadowed by same-named zone-local entry?)", len(applied))
	}
	if got := globalSvc15933(t, applied[0]); !reflect.DeepEqual(got, []string{"10.9.9.9/32"}) {
		t.Fatalf("published global svc = %v, want new global answer", got)
	}
	if got := applied[0].Security.AddressBook.Addresses[folded].UsableValues(); !reflect.DeepEqual(got, []string{"10.0.0.2/32"}) {
		t.Fatalf("published folded svc = %v, want unchanged local answer", got)
	}
	// C5 half of this cell: the published generation was never mutated.
	if got := globalSvc15933(t, active); !reflect.DeepEqual(got, []string{"10.0.0.1/32"}) {
		t.Fatalf("published active config mutated by refresh: global svc = %v", got)
	}

	// Unchanged control: a tick with no answer change must not republish.
	d.refreshDNSOnce()
	if len(applied) != 1 {
		t.Fatalf("unchanged tick republished: applies = %d, want 1", len(applied))
	}
}

// C5 (concurrent-apply regression, required by #15933): while a refresh
// tick is resolving DNS, a concurrent apply of the SAME active generation
// runs under applySem. The resolver must never write into that published
// generation; the refresh may only publish its private copy, and only
// while its base generation is still active. Run with -race: on the old
// in-place shape the resolver writes race the concurrent reader here.
func TestDNSRefreshConcurrentApplyNeverMutatesPublished15933(t *testing.T) {
	entered := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	var barrier atomic.Bool
	restore := config.SetLookupAddressDNSNameForTest(func(fqdn string) ([]string, error) {
		if fqdn == "global.example.com" {
			if barrier.Load() {
				once.Do(func() { close(entered) })
				<-release
				return []string{"10.9.9.9"}, nil
			}
			return []string{"10.0.0.1"}, nil
		}
		return []string{"10.0.0.2"}, nil
	})
	t.Cleanup(restore)

	d, s := dnsDaemon15933(t)
	published := s.ActiveConfig()
	if got := globalSvc15933(t, published); !reflect.DeepEqual(got, []string{"10.0.0.1/32"}) {
		t.Fatalf("premise global svc = %v, want compile-time answer", got)
	}
	barrier.Store(true)

	var tickApplied atomic.Int32
	d.applyBodyForTest = func(cfg *config.Config) { tickApplied.Add(1) }

	tickDone := make(chan struct{})
	go func() {
		defer close(tickDone)
		d.refreshDNSOnce()
	}()

	select {
	case <-entered:
	case <-time.After(10 * time.Second):
		t.Fatal("refresh tick never entered the resolver")
	}

	// Concurrent apply of the same published generation under applySem,
	// reading the DNS state throughout (the racing reader on old code).
	applyDone := make(chan struct{})
	go func() {
		defer close(applyDone)
		if err := d.applySem.Acquire(context.Background(), 1); err != nil {
			return
		}
		defer d.applySem.Release(1)
		deadline := time.Now().Add(2 * time.Second)
		for time.Now().Before(deadline) {
			_ = published.Security.AddressBook.Addresses["svc"].UsableValues()
			_ = snapshotDNSAnswers(published)
		}
	}()

	// Let the resolver finish while the concurrent apply is reading, then
	// let both complete (apply releases the sem; tick publishes after).
	close(release)
	<-applyDone
	select {
	case <-tickDone:
	case <-time.After(10 * time.Second):
		t.Fatal("refresh tick did not finish")
	}

	// The published generation still carries its original answers: the
	// resolver wrote only into the tick's private copy.
	if got := globalSvc15933(t, published); reflect.DeepEqual(got, []string{"10.9.9.9/32"}) {
		t.Fatalf("published config mutated by concurrent refresh: global svc = %v", got)
	}
	for _, v := range published.Security.AddressBook.Addresses["svc"].DNSAddresses {
		if v == "10.9.9.9/32" {
			t.Fatalf("published DNSAddresses contains refreshed answer: %v", published.Security.AddressBook.Addresses["svc"].DNSAddresses)
		}
	}
}

// C5 generation guard: if a newer config is promoted while a tick is
// resolving, the tick must not publish its stale copy over the new
// generation (the new generation's own apply re-resolves DNS).
func TestDNSRefreshStaleGenerationNotPublished15933(t *testing.T) {
	set := stubDNS15933(t, map[string][]string{
		"global.example.com": {"10.0.0.1"},
		"local.example.com":  {"10.0.0.2"},
	})
	d, s := dnsDaemon15933(t)
	base := s.ActiveConfig()

	var applied []*config.Config
	d.applyBodyForTest = func(cfg *config.Config) { applied = append(applied, cfg) }

	set(map[string][]string{
		"global.example.com": {"10.9.9.9"},
		"local.example.com":  {"10.0.0.2"},
	})
	refreshed := base.CloneForDNSRefresh()
	config.RefreshDNSAddressBooks(refreshed)

	// A commit lands a newer generation before the tick publishes.
	if _, err := s.SyncApply(dnsCfg15933+"\nsystem { host-name newer; }\n", nil); err != nil {
		t.Fatalf("SyncApply newer generation: %v", err)
	}
	if s.ActiveConfig() == base {
		t.Fatal("premise: active generation did not move")
	}
	if _, err := d.applyDNSRefreshedConfig(base, refreshed); err != nil {
		t.Fatalf("stale publish returned error: %v", err)
	}
	if len(applied) != 0 {
		t.Fatalf("stale DNS refresh published over newer generation: %d applies", len(applied))
	}
}

// --- #15962 fold regressions ---------------------------------------------

// dnsRealDaemon15962 builds a daemon that drives the REAL
// applyConfigLocked (fake dataplane counter, no applyBodyForTest seam).
func dnsRealDaemon15962(t *testing.T) (*Daemon, *runtimeOnlyApplyTestDP, *configstore.Store) {
	t.Helper()
	installFakeNetworkctl(t)
	installSSHDSeam(t, &sshdSeamRecorder{})
	s := newConfigStore(t, filepath.Join(t.TempDir(), "config.db"))
	if _, err := s.SyncApply(dnsCfg15933, nil); err != nil {
		t.Fatalf("SyncApply premise config: %v", err)
	}
	dp := &runtimeOnlyApplyTestDP{}
	d := &Daemon{
		applySem: semaphore.NewWeighted(1),
		store:    s,
		vrrpMgr:  vrrp.NewManager(),
		opts:     Options{NoDataplane: true},
	}
	d.setDataplane(dp)
	return d, dp, s
}

// B1 (#15962, simplified round-2): ticks take snapshot+clone under
// applySem while the production apply writer runs concurrently. Writer
// progress is bounded and asserted: the writer MUST land its applies
// while ticks run (no lease starvation by construction). Run with
// -race. FAIL-ON-REVERT: moving the tick snapshot/clone outside
// applySem makes the writer's in-place RefreshDNSAddressBooks race the
// tick reads (DATA RACE) and turns this RED.
func TestDNSRefreshTickSnapshotRacesRealApplyWriter15962(t *testing.T) {
	stubDNS15933(t, map[string][]string{
		"global.example.com": {"10.0.0.1"},
		"local.example.com":  {"10.0.0.2"},
	})
	d, dp, _ := dnsRealDaemon15962(t)
	writerDone := make(chan struct{})
	go func() {
		defer close(writerDone)
		// Production writer shape: full ActiveConfig applies (the C5
		// production collision), not a test-only reader.
		for range 3 {
			if err := d.applyActiveConfigResult(); err != nil {
				t.Errorf("writer apply: %v", err)
				return
			}
		}
	}()
	deadline := time.Now().Add(60 * time.Second)
	for {
		select {
		case <-writerDone:
			goto writerLanded
		default:
		}
		if time.Now().After(deadline) {
			t.Fatal("writer starved: no apply landed while ticks ran")
		}
		d.refreshDNSOnce()
	}
writerLanded:
	if dp.applyCalls < 3 {
		t.Fatalf("writer landed %d applies, want >=3 (bounded writer progress)", dp.applyCalls)
	}
	for range 10 {
		d.refreshDNSOnce()
	}
}

// B2 (#15962, simplified round-2): a non-refresh re-apply of the same
// generation via the REAL applyConfigLocked exit must reconcile the
// refresher baseline, so a DNS flap-back is detected again. Driven
// through production applyActiveConfigResult — not hand-called helpers
// (round-2 F3: hand-calling recordAppliedDNSBaseline was test-only-green
// for the apply-exit wiring). FAIL-ON-REVERT: removing the
// applyConfigLocked-exit reconcile makes this cell go RED.
func TestDNSRefreshBaselineReconciledAfterBackgroundReapply15962(t *testing.T) {
	set := stubDNS15933(t, map[string][]string{
		"global.example.com": {"10.0.0.1"},
		"local.example.com":  {"10.0.0.2"},
	})
	d, dp, _ := dnsRealDaemon15962(t)

	// DNS moves to B; a real background apply lands B and (via the
	// apply-exit reconcile) becomes the baseline.
	set(map[string][]string{"global.example.com": {"10.9.9.9"}, "local.example.com": {"10.0.0.2"}})
	if err := d.applyActiveConfigResult(); err != nil {
		t.Fatalf("background apply B: %v", err)
	}
	if dp.applyCalls != 1 {
		t.Fatalf("background apply calls = %d, want 1", dp.applyCalls)
	}
	// Tick with DNS still at B: no republish owed.
	d.refreshDNSOnce()
	if dp.applyCalls != 1 {
		t.Fatalf("tick at applied B republished: calls = %d", dp.applyCalls)
	}
	// DNS flaps to C: tick must detect against the actually-applied B
	// baseline and republish.
	set(map[string][]string{"global.example.com": {"10.5.5.5"}, "local.example.com": {"10.0.0.2"}})
	d.refreshDNSOnce()
	if dp.applyCalls != 2 {
		t.Fatalf("flap tick applied %d total, want 2 (baseline desync after background re-apply)", dp.applyCalls)
	}
	// Steady state.
	d.refreshDNSOnce()
	if dp.applyCalls != 2 {
		t.Fatalf("steady-state tick republished: calls = %d", dp.applyCalls)
	}
}

// M1 (#15962): a refused publish (fenced daemon) must not be recorded as
// the applied baseline; after un-fencing the same change republishes.
func TestDNSRefreshRefusedPublishNotRecorded15962(t *testing.T) {
	set := stubDNS15933(t, map[string][]string{
		"global.example.com": {"10.0.0.1"},
		"local.example.com":  {"10.0.0.2"},
	})
	d, _ := dnsDaemon15933(t)
	var applied []*config.Config
	d.applyBodyForTest = func(cfg *config.Config) { applied = append(applied, cfg) }

	set(map[string][]string{"global.example.com": {"10.9.9.9"}, "local.example.com": {"10.0.0.2"}})
	d.fenceBackgroundApplies()
	d.refreshDNSOnce()
	if len(applied) != 0 {
		t.Fatalf("fenced tick applied %d, want 0", len(applied))
	}
	d.applyFenced.Store(false)
	d.refreshDNSOnce()
	if len(applied) != 1 {
		t.Fatalf("after un-fence, tick applied %d, want 1 (refused publish was recorded as applied)", len(applied))
	}
}

// M2/codex-1 (#15962): a global dns entry whose authored name collides
// textually with the named-book identity prefix must not shadow (or be
// shadowed by) the named book's entry in change detection.
func TestDNSRefreshNamedBookIdentityCollision15962(t *testing.T) {
	set := stubDNS15933(t, map[string][]string{
		"global.example.com": {"10.0.0.1"},
		"book.example.com":   {"10.0.0.3"},
	})
	s := newConfigStore(t, filepath.Join(t.TempDir(), "config.db"))
	cfgText := `
security {
    zones { security-zone trust; }
    address-book {
        global {
            address address-book/eng-book/svc { dns-name global.example.com; }
        }
        eng-book {
            address svc { dns-name book.example.com; }
        }
    }
}
`
	if _, err := s.SyncApply(cfgText, nil); err != nil {
		t.Fatalf("SyncApply premise: %v", err)
	}
	d := &Daemon{applySem: semaphore.NewWeighted(1), store: s, opts: Options{NoDataplane: true}}
	var applied []*config.Config
	d.applyBodyForTest = func(cfg *config.Config) { applied = append(applied, cfg) }

	// Change ONLY the global (collision-named) answer; named book stable.
	set(map[string][]string{"global.example.com": {"10.9.9.9"}, "book.example.com": {"10.0.0.3"}})
	d.refreshDNSOnce()
	if len(applied) != 1 {
		t.Fatalf("collision-named global change published %d, want 1 (identity collision shadows global entry)", len(applied))
	}
	// Unchanged control.
	d.refreshDNSOnce()
	if len(applied) != 1 {
		t.Fatalf("unchanged tick republished: %d", len(applied))
	}
}

// Codex gate 3 (#15962, round-2 F4): the baseline records what the real
// apply actually resolved, not the tick's pre-apply proposal. The
// resolver therefore succeeds on the TICK's lookup and fails on the
// APPLY's re-lookup (call-indexed), so the applied state is fail-closed
// empty while the proposal was B; the next healthy tick must recover B.
// FAIL-ON-REVERT: caching the proposal makes recovery compare equal and
// this cell goes RED.
func TestDNSRefreshBaselineRecordsActuallyApplied15962(t *testing.T) {
	var callIdx atomic.Int64
	restore := config.SetLookupAddressDNSNameForTest(func(fqdn string) ([]string, error) {
		if fqdn != "global.example.com" {
			return []string{"10.0.0.2"}, nil
		}
		n := callIdx.Add(1)
		// Call 1: compile-time (inside dnsRealDaemon15962) — answer A.
		// Call 2: tick lookup — answer B (success).
		// Call 3: apply-time re-lookup — fail (fail-closed empty applied).
		// Later: healthy B.
		switch n {
		case 1:
			return []string{"10.0.0.1"}, nil
		case 3:
			return nil, context.DeadlineExceeded
		default:
			return []string{"10.9.9.9"}, nil
		}
	})
	t.Cleanup(restore)

	d, dp, _ := dnsRealDaemon15962(t)
	// First tick: proposal B, apply-time lookup fails, empty applied.
	d.refreshDNSOnce()
	if dp.applyCalls != 1 {
		t.Fatalf("first tick applies = %d, want 1 (real apply)", dp.applyCalls)
	}
	// Healthy DNS: the same B must now be published (recovery) — only
	// possible if the baseline stayed at the actually-applied empty/A
	// state instead of the unapplied proposal B.
	d.refreshDNSOnce()
	if dp.applyCalls != 2 {
		t.Fatalf("recovery tick applies = %d, want 2 (baseline suppressed recovery — proposal was cached)", dp.applyCalls)
	}
	// Steady state: no further republish.
	d.refreshDNSOnce()
	if dp.applyCalls != 2 {
		t.Fatalf("steady-state tick republished: applies = %d", dp.applyCalls)
	}
}
