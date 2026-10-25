package config

import (
	"fmt"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// #16601: compile performs NO network I/O. A slow resolver installed via
// the lookup seam must never be called by CompileConfig; entries compile
// fail-closed empty on a cache miss and pick up cached answers with no
// lookup at all. FAIL-ON-REVERT: restoring applyDNSName->lookup makes
// the lookup counter non-zero and this test red.

func TestCompileNeverResolvesDNS16601(t *testing.T) {
	var calls atomic.Int32
	orig := lookupAddressDNSName
	defer func() { lookupAddressDNSName = orig }()
	lookupAddressDNSName = func(fqdn string) ([]string, error) {
		calls.Add(1)
		time.Sleep(50 * time.Millisecond)
		return []string{"10.0.0.1"}, nil
	}
	start := time.Now()
	cfg, err := CompileConfig(soleFormTree(t, `address svc { dns-name slow.example.com; }`))
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	if n := calls.Load(); n != 0 {
		t.Fatalf("compile performed %d DNS lookups, want 0 (#16601)", n)
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("compile took %v with a slow resolver; lookup latency leaked into compile", elapsed)
	}
	a := cfg.Security.AddressBook.Addresses["svc"]
	if a == nil || a.DNSName != "slow.example.com" {
		t.Fatalf("dns-name not modelled: %+v", a)
	}
	if got := a.UsableValues(); len(got) != 0 {
		t.Fatalf("cache-miss compile must be fail-closed empty, got %v", got)
	}

	// Cache hit: compile reads the daemon-owned cache, still 0 lookups.
	restore := SeedDNSAnswerCacheForTest("slow.example.com", "", []string{"10.7.7.7/32"})
	defer restore()
	cfg2, err := CompileConfig(soleFormTree(t, `address svc { dns-name slow.example.com; }`))
	if err != nil {
		t.Fatalf("CompileConfig (cached): %v", err)
	}
	if n := calls.Load(); n != 0 {
		t.Fatalf("cached compile performed %d lookups, want 0", n)
	}
	if got := cfg2.Security.AddressBook.Addresses["svc"].UsableValues(); !reflect.DeepEqual(got, []string{"10.7.7.7/32"}) {
		t.Fatalf("cached compile values = %v, want [10.7.7.7/32]", got)
	}
}

// #16601: RefreshDNSAddressBooks resolves many names concurrently with
// a bounded pool. 20 names x 50ms serially would take >=1s; parallel
// (8 workers) finishes well under that, each exactly once.
func TestRefreshDNSParallelBounded16601(t *testing.T) {
	var calls atomic.Int32
	var mu sync.Mutex
	seen := map[string]int{}
	orig := lookupAddressDNSName
	defer func() { lookupAddressDNSName = orig }()
	lookupAddressDNSName = func(fqdn string) ([]string, error) {
		calls.Add(1)
		mu.Lock()
		seen[fqdn]++
		mu.Unlock()
		time.Sleep(50 * time.Millisecond)
		// Distinct IP per name: last octet from name index.
		var idx int
		fmt.Sscanf(fqdn, "h%d.example.com", &idx)
		return []string{fmt.Sprintf("10.0.0.%d", idx+1)}, nil
	}
	var lines []string
	lines = append(lines, "set security zones security-zone trust")
	for i := range 20 {
		lines = append(lines, fmt.Sprintf("set security address-book global address h%d dns-name h%d.example.com", i, i))
	}
	cfg, err := CompileConfig(buildTree(t, lines))
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	if n := calls.Load(); n != 0 {
		t.Fatalf("compile did %d lookups, want 0", n)
	}
	start := time.Now()
	RefreshDNSAddressBooks(cfg)
	elapsed := time.Since(start)
	if n := calls.Load(); n != 20 {
		t.Fatalf("refresh did %d lookups, want 20 (one per distinct name)", n)
	}
	if elapsed >= 900*time.Millisecond {
		t.Fatalf("refresh of 20x50ms names took %v; serial or unbounded-slow (want parallel, <<900ms)", elapsed)
	}
	for i := range 20 {
		name := fmt.Sprintf("h%d", i)
		want := []string{fmt.Sprintf("10.0.0.%d/32", i+1)}
		if got := cfg.Security.AddressBook.Addresses[name].UsableValues(); !reflect.DeepEqual(got, want) {
			t.Errorf("%s = %v, want %v", name, got, want)
		}
		if seen[fmt.Sprintf("h%d.example.com", i)] != 1 {
			t.Errorf("h%d.example.com resolved %d times, want 1", i, seen[fmt.Sprintf("h%d.example.com", i)])
		}
	}
	// Duplicate entries sharing one name resolve once.
	if !strings.Contains(fmt.Sprint(seen), "h0.example.com") {
		t.Fatal("premise: seen map empty")
	}
}

// #16601: a failed lookup is fail-closed and PeekDNSNames reports the
// name unresolved (daemon retries); a successful empty answer is NOT
// re-reported.
func TestPeekDNSNames16601(t *testing.T) {
	orig := lookupAddressDNSName
	defer func() { lookupAddressDNSName = orig }()
	lookupAddressDNSName = func(fqdn string) ([]string, error) {
		if fqdn == "bad.example.com" {
			return nil, fmt.Errorf("boom")
		}
		return nil, nil // successful, no records
	}
	cfg, err := CompileConfig(buildTree(t, []string{
		"set security zones security-zone trust",
		"set security address-book global address good dns-name good.example.com",
		"set security address-book global address bad dns-name bad.example.com",
	}))
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	pairs := PeekDNSNames(cfg)
	if len(pairs) != 2 {
		t.Fatalf("Peek before resolve = %v, want 2 pairs", pairs)
	}
	RefreshDNSAddressBooks(cfg)
	pairs = PeekDNSNames(cfg)
	if len(pairs) != 1 || pairs[0][0] != "bad.example.com" {
		t.Fatalf("Peek after resolve = %v, want only bad.example.com (failed lookups retry, successful-empty does not)", pairs)
	}
	if got := cfg.Security.AddressBook.Addresses["bad"].UsableValues(); len(got) != 0 {
		t.Fatalf("failed lookup must be fail-closed, got %v", got)
	}
}
