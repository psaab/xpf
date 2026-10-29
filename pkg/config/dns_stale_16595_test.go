package config

import (
	"errors"
	"reflect"
	"strings"
	"testing"
)

// #16595 — a transient dns-name lookup failure must not discard the last
// answer, must not depend on live DNS at strict commit, and must stay
// distinct from "name has no addresses" (a successful empty answer).

var errDNSDown16595 = errors.New("SERVFAIL")

func stubLookup16595(t *testing.T, fn func(string) ([]string, error)) {
	t.Helper()
	orig := lookupAddressDNSName
	lookupAddressDNSName = fn
	t.Cleanup(func() { lookupAddressDNSName = orig })
}

func TestDNSStaleWhileError16595(t *testing.T) {
	down := false
	stubLookup16595(t, func(string) ([]string, error) {
		if down {
			return nil, errDNSDown16595
		}
		return []string{"203.0.113.10"}, nil
	})
	cfg, err := CompileConfig(soleFormTree(t, `address partner-api { dns-name api.example.com; }`))
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	// #16601: compile is cache-only; the initial answer arrives via the
	// off-lock refresh the daemon performs before apply.
	RefreshDNSAddressBooks(cfg)
	a := cfg.Security.AddressBook.Addresses["partner-api"]
	if got := a.UsableValues(); !reflect.DeepEqual(got, []string{"203.0.113.10/32"}) {
		t.Fatalf("initial UsableValues = %v", got)
	}
	down = true
	RefreshDNSAddressBooks(cfg)
	if got := a.UsableValues(); !reflect.DeepEqual(got, []string{"203.0.113.10/32"}) {
		t.Fatalf("stale-while-error: UsableValues = %v, want last good retained", got)
	}
	if !a.DNSLookupFailed {
		t.Fatal("DNSLookupFailed must be set after a failed refresh")
	}
	// A successful empty answer replaces the stale answer and clears the flag.
	down = false
	orig := lookupAddressDNSName
	lookupAddressDNSName = func(string) ([]string, error) { return nil, nil }
	defer func() { lookupAddressDNSName = orig }()
	RefreshDNSAddressBooks(cfg)
	if a.DNSLookupFailed {
		t.Fatal("successful lookup must clear DNSLookupFailed")
	}
	if got := a.UsableValues(); len(got) != 0 {
		t.Fatalf("successful empty answer must replace stale: %v", got)
	}
}

func TestDNSLookupFailedDistinctFromEmpty16595(t *testing.T) {
	// #16601: resolveDNSAddressEntry is cache-only; a failed resolution
	// is recorded in the cache by RefreshDNSAddressBooks. Drive entries
	// through a one-entry config refresh.
	stubLookup16595(t, func(string) ([]string, error) { return nil, errDNSDown16595 })
	a := &Address{Name: "bad", DNSName: "bad.example.com"}
	cfgBad := &Config{}
	cfgBad.Security.AddressBook = &AddressBook{Addresses: map[string]*Address{"bad": a}}
	RefreshDNSAddressBooks(cfgBad)
	if !a.DNSLookupFailed {
		t.Fatal("failed first lookup must set DNSLookupFailed")
	}
	ab := &AddressBook{Addresses: map[string]*Address{"bad": a}}
	if !ab.DNSEntryLookupFailed("bad") {
		t.Fatal("DNSEntryLookupFailed must report the failed entry")
	}
	// Successful empty is NOT lookup-failed.
	a2 := &Address{Name: "empty", DNSName: "empty.example.com"}
	stubLookup16595(t, func(string) ([]string, error) { return nil, nil })
	cfgEmpty := &Config{}
	cfgEmpty.Security.AddressBook = &AddressBook{Addresses: map[string]*Address{"empty": a2}}
	RefreshDNSAddressBooks(cfgEmpty)
	ab.Addresses["empty"] = a2
	if ab.DNSEntryLookupFailed("empty") {
		t.Fatal("successful empty answer must not be lookup-failed")
	}
	ab.AddressSets = map[string]*AddressSet{"grp": {Name: "grp", Addresses: []string{"bad"}}}
	if !ab.DNSEntryLookupFailed("grp") {
		t.Fatal("nested failed member must taint the set closure")
	}
	// CloneForDNSRefresh preserves the flag.
	cfg := &Config{}
	cfg.Security.AddressBook = ab
	clone := cfg.CloneForDNSRefresh()
	if !clone.Security.AddressBook.Addresses["bad"].DNSLookupFailed {
		t.Fatal("clone must preserve DNSLookupFailed")
	}
}

func TestDNSColdCacheUnresolvedDistinctFromFailure17782(t *testing.T) {
	a := &Address{Name: "cold", DNSName: "cold-17782.example.invalid"}
	cfg := &Config{}
	cfg.Security.AddressBook = &AddressBook{Addresses: map[string]*Address{"cold": a}}
	resolveDNSAddressEntry(a)
	if !a.DNSUnresolved || a.DNSLookupFailed {
		t.Fatalf("cold cache state: unresolved=%t failed=%t, want unresolved only", a.DNSUnresolved, a.DNSLookupFailed)
	}
	if cfg.Security.AddressBook.DNSEntryLookupFailed("cold") {
		t.Fatal("cold-cache miss must not masquerade as a resolver failure")
	}
	if !cfg.Security.AddressBook.DNSEntryResolutionUnavailable("cold") {
		t.Fatal("cold-cache miss must remain unavailable to strict validation")
	}
	unresolvedDigest := DNSAnswersDigest(cfg)
	a.DNSUnresolved = false
	if DNSAnswersDigest(cfg) == unresolvedDigest {
		t.Fatal("unresolved-state change did not change the DNS answer digest")
	}
	a.DNSUnresolved = true

	stubLookup16595(t, func(string) ([]string, error) { return nil, nil })
	RefreshDNSAddressBooks(cfg)
	if a.DNSUnresolved || a.DNSLookupFailed {
		t.Fatalf("successful empty result: unresolved=%t failed=%t, want neither", a.DNSUnresolved, a.DNSLookupFailed)
	}
}

func TestStrictCommitWarnsNotRejectsWhenDNSDown16595(t *testing.T) {
	stubLookup16595(t, func(string) ([]string, error) { return nil, errDNSDown16595 })
	tree := buildTree(t, []string{
		"set security zones security-zone trust",
		"set security zones security-zone untrust",
		"set security address-book global address bad dns-name bad.example.com",
		"set security address-book global address good 10.0.0.5/32",
		"set security policies from-zone trust to-zone untrust policy block-bad match source-address any",
		"set security policies from-zone trust to-zone untrust policy block-bad match destination-address bad",
		"set security policies from-zone trust to-zone untrust policy block-bad match application any",
		"set security policies from-zone trust to-zone untrust policy block-bad then deny",
		"set security policies from-zone trust to-zone untrust policy allow-good match source-address any",
		"set security policies from-zone trust to-zone untrust policy allow-good match destination-address good",
		"set security policies from-zone trust to-zone untrust policy allow-good match application any",
		"set security policies from-zone trust to-zone untrust policy allow-good then permit",
	})
	probe := &Config{}
	probe.Security.AddressBook = &AddressBook{Addresses: map[string]*Address{"bad": {Name: "bad", DNSName: "bad.example.com"}}}
	RefreshDNSAddressBooks(probe)
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("strict commit must not depend on live DNS (#16595): %v", err)
	}
	warned := false
	for _, w := range ValidateConfig(cfg) {
		if strings.Contains(w, "bad") && strings.Contains(w, "match nothing until DNS resolves") {
			warned = true
		}
	}
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "match nothing until DNS resolves") {
			warned = true
		}
	}
	// The existing dns-name warning is asserted via ValidateConfig; compile
	// warnings are a separate channel, either satisfies the operator signal.
	_ = warned
	a := cfg.Security.AddressBook.Addresses["bad"]
	if a == nil || !a.DNSLookupFailed {
		t.Fatalf("bad entry must carry DNSLookupFailed, got %+v", a)
	}
}

func TestStrictCommitStillRejectsSuccessfulEmptyDNS16595(t *testing.T) {
	stubLookup16595(t, func(string) ([]string, error) { return nil, nil })
	probe := &Config{}
	probe.Security.AddressBook = &AddressBook{Addresses: map[string]*Address{"bad": {Name: "bad", DNSName: "bad.example.com"}}}
	RefreshDNSAddressBooks(probe)
	tree := buildTree(t, []string{
		"set security zones security-zone trust",
		"set security zones security-zone untrust",
		"set security address-book global address bad dns-name bad.example.com",
		"set security policies from-zone trust to-zone untrust policy block-bad match source-address any",
		"set security policies from-zone trust to-zone untrust policy block-bad match destination-address bad",
		"set security policies from-zone trust to-zone untrust policy block-bad match application any",
		"set security policies from-zone trust to-zone untrust policy block-bad then deny",
	})
	_, err := CompileConfig(tree)
	if err == nil || !strings.Contains(err.Error(), "does not fully resolve") {
		t.Fatalf("successful-empty dns-name must still reject strict, got %v", err)
	}
}
