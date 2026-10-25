package configstore

import (
	"fmt"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
)

// #16601: commit / SyncApply compile under s.mu (write lock) must do
// ZERO DNS lookups, so a slow resolver cannot stall ActiveConfig()
// readers (HA readiness). The stub resolver sleeps 40ms per lookup;
// with 5 dns-names a serial in-lock resolve would hold the lock for
// >=200ms (x3 compiles on cluster). Here lookups must be 0 and the
// ActiveConfig wait prompt. FAIL-ON-REVERT: restoring compile-time
// lookup makes lookups>0 and the wait jump.

func dnsStoreCfg16601(n int) string {
	var b strings.Builder
	b.WriteString("security {\n zones { security-zone trust; security-zone untrust; }\n address-book { global {\n")
	for i := range n {
		fmt.Fprintf(&b, "address svc%d dns-name svc%d.example.com;\n", i, i)
	}
	b.WriteString("} }\n}\n")
	return b.String()
}

func TestDNSCommitDoesNotResolveUnderLock16601(t *testing.T) {
	var calls atomic.Int32
	restore := config.SetLookupAddressDNSNameForTest(func(fqdn string) ([]string, error) {
		calls.Add(1)
		time.Sleep(40 * time.Millisecond)
		return []string{"10.0.0.1"}, nil
	})
	defer restore()

	s := newTestStore(t)
	if err := s.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	// Stage 5 dns-name entries via LoadSet-style candidate edits is
	// awkward hierarchically; use SyncApply to install then re-commit
	// the same tree through the candidate path if available. The core
	// assertion uses SyncApply (compileTreeLenient under s.mu.Lock).
	text := dnsStoreCfg16601(5)

	// Time ActiveConfig() wait while SyncApply compiles under the lock.
	done := make(chan struct{})
	var maxWait atomic.Int64
	go func() {
		defer close(done)
		deadline := time.Now().Add(3 * time.Second)
		for time.Now().Before(deadline) {
			start := time.Now()
			_ = s.ActiveConfig()
			if w := time.Since(start).Milliseconds(); w > maxWait.Load() {
				maxWait.Store(w)
			}
		}
	}()
	start := time.Now()
	if _, err := s.SyncApply(text, nil); err != nil {
		t.Fatalf("SyncApply: %v", err)
	}
	elapsed := time.Since(start)
	// Give the reader goroutine a moment, then stop by waiting for its deadline is
	// too slow; instead just read current max (goroutine exits on its own deadline
	// but we don't block on it beyond a short grace).
	select {
	case <-done:
	case <-time.After(100 * time.Millisecond):
	}
	if n := calls.Load(); n != 0 {
		t.Fatalf("SyncApply compile performed %d DNS lookups under s.mu, want 0 (#16601)", n)
	}
	if elapsed > 500*time.Millisecond {
		t.Fatalf("SyncApply took %v with 5x40ms resolver; in-lock serial resolve would be >=200ms+", elapsed)
	}
	if w := maxWait.Load(); w > 200 {
		t.Fatalf("max ActiveConfig() wait = %dms during SyncApply; readers stalled behind DNS under lock", w)
	}
	// Entries are fail-closed until the daemon resolves off-lock.
	cfg := s.ActiveConfig()
	if cfg == nil {
		t.Fatal("ActiveConfig nil after SyncApply")
	}
	a := cfg.Security.AddressBook.Addresses["svc0"]
	if a == nil || a.DNSName != "svc0.example.com" {
		t.Fatalf("svc0 not modelled: %+v", a)
	}
	if got := a.UsableValues(); len(got) != 0 {
		t.Fatalf("unresolved-at-compile entry must be fail-closed, got %v", got)
	}
}
