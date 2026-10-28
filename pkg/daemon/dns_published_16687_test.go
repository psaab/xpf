package daemon

import (
	"net"
	"path/filepath"
	"reflect"
	"sync"
	"testing"

	"golang.org/x/sync/semaphore"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/policymatch"
)

// #16687: residual of #15933 C5. The apply path still wrote dns-name
// answers in place into the published active config (the owned-config
// arm of resolveDNSBeforeApply called PopulateDNSFromCache on the
// caller's pointer, and commit/sync/rollback callers hand it the
// store's ActiveConfig() / frozen confirmPrevCfg). That raced
// `show security match-policies` readers outside applySem and left the
// pointer-keyed policymatch cache stale.
//
// FAIL-ON-REVERT: restoring the PopulateDNSFromCache(cfg) arm makes
// TestResolveDNSBeforeApplyNeverMutatesPublished16687 mutate the
// published generation (answers move under the reader) and makes the
// race test below report DATA RACE under -race.

const dnsCfg16687 = `
security {
    zones {
        security-zone trust;
        security-zone untrust;
    }
    address-book {
        global {
            address svc { dns-name svc.example.com; }
        }
    }
    policies {
        from-zone trust to-zone untrust {
            policy allow-svc {
                match { source-address any; destination-address svc; application any; }
                then { permit; }
            }
        }
    }
}
`

func dnsDaemon16687(t *testing.T) (*Daemon, *config.Config) {
	t.Helper()
	stubDNS15933(t, map[string][]string{
		"svc.example.com": {"10.0.0.1"},
	})
	s := newConfigStore(t, filepath.Join(t.TempDir(), "config.db"))
	if _, err := s.SyncApply(dnsCfg16687, nil); err != nil {
		t.Fatalf("SyncApply premise: %v", err)
	}
	d := &Daemon{
		applySem: semaphore.NewWeighted(1),
		store:    s,
		opts:     Options{NoDataplane: true},
	}
	published := s.ActiveConfig()
	if published == nil {
		t.Fatal("no active config after SyncApply")
	}
	// Publish the first resolved generation exactly as #16606 does:
	// resolve into a private clone, then swap the store pointer.
	clone := d.resolveDNSBeforeApply(published)
	if clone == published {
		t.Fatal("premise: resolve returned the published pointer (#16687)")
	}
	// The real refresher consumes the resolved marker before its apply
	// (applyDNSRefreshedConfig); mirror that so the published clone is
	// unmarked, exactly as after a production publish.
	d.consumeDNSResolved(clone)
	if !s.PublishRefreshedDNS(published, clone) {
		t.Fatal("premise: PublishRefreshedDNS failed")
	}
	return d, s.ActiveConfig()
}

// TestResolveDNSBeforeApplyNeverMutatesPublished16687: resolving the
// published active config returns a private clone carrying the fresh
// answer; the published generation's answers do not move.
func TestResolveDNSBeforeApplyNeverMutatesPublished16687(t *testing.T) {
	d, published := dnsDaemon16687(t)
	if got := published.Security.AddressBook.Addresses["svc"].UsableValues(); !reflect.DeepEqual(got, []string{"10.0.0.1/32"}) {
		t.Fatalf("premise published svc = %v, want [10.0.0.1/32]", got)
	}

	stubDNS15933(t, map[string][]string{"svc.example.com": {"10.9.9.9"}})
	out := d.resolveDNSBeforeApply(published)
	if out == published {
		t.Fatal("resolve returned the published pointer; want a private clone (#16687)")
	}
	if got := published.Security.AddressBook.Addresses["svc"].UsableValues(); !reflect.DeepEqual(got, []string{"10.0.0.1/32"}) {
		t.Fatalf("published generation mutated by resolve: %v (#16687)", got)
	}
	if got := out.Security.AddressBook.Addresses["svc"].UsableValues(); !reflect.DeepEqual(got, []string{"10.9.9.9/32"}) {
		t.Fatalf("resolved clone svc = %v, want [10.9.9.9/32]", got)
	}
}

// TestDNSApplyResolveRacesMatchPoliciesReader16687 is the race probe
// from the issue, driven through the production arms: the writer
// repeatedly resolves the published config (the background apply path)
// while a reader goroutine runs the MatchPolicies evaluation
// (policymatch.Match -> UsableValues) on the published pointer, with
// no applySem on the reader side. Under -race this reports DATA RACE
// on the pre-fix PopulateDNSFromCache arm; with the clone-only resolve
// the published object is never written and the run is clean. The
// reader-only control arm proves the reader alone is race-free.
func TestDNSApplyResolveRacesMatchPoliciesReader16687(t *testing.T) {
	t.Run("control-reader-only", func(t *testing.T) {
		_, published := dnsDaemon16687(t)
		q := policymatch.Query{
			FromZone: "trust", ToZone: "untrust", Protocol: "tcp",
			SrcIP: net.ParseIP("10.0.1.5"), DstIP: net.ParseIP("10.0.0.1"), DstPort: policymatch.PortPtr(443),
		}
		for range 300 {
			_ = policymatch.Match(published, q)
			_ = published.Security.AddressBook.Addresses["svc"].UsableValues()
		}
	})

	t.Run("writer-and-reader", func(t *testing.T) {
		d, published := dnsDaemon16687(t)
		q := policymatch.Query{
			FromZone: "trust", ToZone: "untrust", Protocol: "tcp",
			SrcIP: net.ParseIP("10.0.1.5"), DstIP: net.ParseIP("10.0.0.1"), DstPort: policymatch.PortPtr(443),
		}
		stop := make(chan struct{})
		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				_ = policymatch.Match(published, q)
				_ = published.Security.AddressBook.Addresses["svc"].UsableValues()
			}
		}()
		for range 300 {
			out := d.resolveDNSBeforeApply(published)
			if out == published {
				t.Fatal("resolve returned the published pointer (#16687)")
			}
			clone := published.CloneForDNSRefresh()
			config.RefreshDNSAddressBooks(clone)
		}
		close(stop)
		wg.Wait()
		if got := published.Security.AddressBook.Addresses["svc"].UsableValues(); !reflect.DeepEqual(got, []string{"10.0.0.1/32"}) {
			t.Fatalf("published generation mutated during concurrent resolve: %v (#16687)", got)
		}
	})
}

// TestConfigApplyReassertResolvesClone16687: the #9811 debt retry
// previously called applyConfigLocked directly on ActiveConfig()
// with no DNS resolve at all. It must now resolve into a clone first
// (never the published pointer).
func TestConfigApplyReassertResolvesClone16687(t *testing.T) {
	d, published := dnsDaemon16687(t)
	var applied *config.Config
	d.applyBodyForTest = func(cfg *config.Config) { applied = cfg }
	if err := configApplyReassertFn(d); err != nil {
		t.Fatalf("configApplyReassertFn: %v", err)
	}
	if applied == nil {
		t.Fatal("reassert applied nothing")
	}
	if applied == published {
		t.Fatal("reassert applied the published pointer directly; want the resolved clone (#16687)")
	}
	if got := applied.Security.AddressBook.Addresses["svc"].UsableValues(); len(got) == 0 {
		t.Fatalf("reassert applied an unresolved clone: %v", got)
	}
	if got := published.Security.AddressBook.Addresses["svc"].UsableValues(); !reflect.DeepEqual(got, []string{"10.0.0.1/32"}) {
		t.Fatalf("published generation mutated by reassert: %v (#16687)", got)
	}
}
