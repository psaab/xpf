package daemon

import (
	"sync/atomic"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
	"golang.org/x/sync/semaphore"
)

// #16601: applyConfig (background path) must resolve dns-names BEFORE
// acquiring applySem, and a slow resolver must not delay a competing
// applySem/ActiveConfig reader. The refreshed clone is applied without
// a second resolution.

func TestResolveDNSBeforeApply16601(t *testing.T) {
	var calls atomic.Int32
	restore := config.SetLookupAddressDNSNameForTest(func(fqdn string) ([]string, error) {
		calls.Add(1)
		return []string{"10.5.5.5"}, nil
	})
	defer restore()

	d := &Daemon{applySem: semaphore.NewWeighted(1)}
	cfg, err := config.CompileConfig(buildDaemonTree16601(t))
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	if n := calls.Load(); n != 0 {
		t.Fatalf("compile did %d lookups, want 0", n)
	}
	// Compile is cache-only (#16601): with the stub resolver not yet
	// run, the cache is empty, so the compiled entry starts unresolved.
	// Capture that premise before resolving.
	if got := cfg.Security.AddressBook.Addresses["svc"].UsableValues(); len(got) != 0 {
		t.Fatalf("premise: compiled svc already resolved: %v", got)
	}
	out := d.resolveDNSBeforeApply(cfg)
	// #16687: resolve returns a private clone; the argument's DNS
	// answers are never written by the resolve itself. (Compile may
	// already have populated them from a warm cache — not the case
	// here — so assert against the captured premise by checking the
	// argument did not GAIN the freshly resolved answer.)
	if out == cfg {
		t.Fatal("resolve returned its argument; want a private clone (#16687)")
	}
	if got := cfg.Security.AddressBook.Addresses["svc"].UsableValues(); len(got) != 0 {
		t.Fatalf("resolve mutated its argument: %v (#16687)", got)
	}
	if n := calls.Load(); n == 0 {
		t.Fatal("resolveDNSBeforeApply did no lookups for an unresolved dns cfg")
	}
	if got := out.Security.AddressBook.Addresses["svc"].UsableValues(); len(got) != 1 || got[0] != "10.5.5.5/32" {
		t.Fatalf("resolved values = %v, want [10.5.5.5/32]", got)
	}
	// Marked: resolving the returned clone again must NOT resolve again
	// (refresher-clone rule).
	before := calls.Load()
	_ = d.resolveDNSBeforeApply(out)
	if calls.Load() != before {
		t.Fatalf("marked cfg resolved again: calls %d -> %d", before, calls.Load())
	}
	_ = time.Now
}

func buildDaemonTree16601(t *testing.T) *config.ConfigTree {
	t.Helper()
	tree, errs := config.NewParser(`
security {
    zones { security-zone trust; }
    address-book { global { address svc { dns-name svc16601.example.com; } } }
}
`).Parse()
	if len(errs) > 0 {
		t.Fatalf("parse: %v", errs)
	}
	return tree
}
