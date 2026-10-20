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
	if err := d.applyDNSRefreshedConfig(base, refreshed); err != nil {
		t.Fatalf("stale publish returned error: %v", err)
	}
	if len(applied) != 0 {
		t.Fatalf("stale DNS refresh published over newer generation: %d applies", len(applied))
	}
}
