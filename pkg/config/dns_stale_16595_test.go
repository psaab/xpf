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

func TestZoneLocalFoldPreservesDNSUnresolved17782(t *testing.T) {
	tree := buildTree(t, []string{
		"set security zones security-zone trust",
		"set security zones security-zone untrust",
		"set security zones security-zone trust address-book address api dns-name cold-fold-17782.example.invalid",
	})
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("cold zone-local compile: %v", err)
	}
	folded := cfg.Security.AddressBook.Addresses["zone-local/trust/api"]
	if folded == nil || !folded.DNSUnresolved || folded.DNSLookupFailed {
		t.Fatalf("folded cold entry state = %+v, want unresolved without resolver-failed", folded)
	}
	if !cfg.Security.AddressBook.DNSEntryResolutionUnavailable("zone-local/trust/api") {
		t.Fatal("folded cold entry must remain unavailable to strict validation")
	}
	if cfg.Security.AddressBook.DNSEntryLookupFailed("zone-local/trust/api") {
		t.Fatal("folded cold entry must not be reported as a resolver failure")
	}
}

func TestZoneLocalFoldPreservesDNSLookupFailed17782(t *testing.T) {
	fqdn := "failed-fold-17782.example.invalid"
	seeded := &Address{Name: "failed", DNSName: fqdn}
	seedCfg := &Config{}
	seedCfg.Security.AddressBook = &AddressBook{Addresses: map[string]*Address{"failed": seeded}}
	stubLookup16595(t, func(string) ([]string, error) { return nil, errDNSDown16595 })
	RefreshDNSAddressBooks(seedCfg)
	if !seeded.DNSLookupFailed {
		t.Fatalf("seed failed lookup state = %+v, want lookup failed", seeded)
	}
	tree := buildTree(t, []string{
		"set security zones security-zone trust",
		"set security zones security-zone untrust",
		"set security zones security-zone trust address-book address api dns-name " + fqdn,
	})
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("failed zone-local compile: %v", err)
	}
	folded := cfg.Security.AddressBook.Addresses["zone-local/trust/api"]
	if folded == nil || !folded.DNSLookupFailed || folded.DNSUnresolved {
		t.Fatalf("folded failed entry state = %+v, want lookup failed without unresolved", folded)
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
	if !warned {
		t.Fatalf("failed DNS lookup must keep the match-nothing warning; warnings=%v compile=%v", ValidateConfig(cfg), cfg.Warnings)
	}
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

// #17721: a successful lookup that returns only addresses outside the
// entry's family (AAAA-only for an ipv4-only entry) is a runtime-empty
// success, distinct from a resolver failure. It contributes no prefixes
// and must not withdraw sibling static junos-host denies.
func TestJunosHostSiblingStaticSurvivesRuntimeEmptyDNS17721(t *testing.T) {
	stubLookup16595(t, func(string) ([]string, error) { return []string{"2001:db8::10"}, nil })
	cfg := jhTestConfig()
	cfg.Security.AddressBook.Addresses["dns-v4"] = &Address{Name: "dns-v4", DNSName: "v6only.example.com", DNSFamily: "ipv4-only"}
	refresh := &Config{}
	refresh.Security.AddressBook = cfg.Security.AddressBook
	RefreshDNSAddressBooks(refresh)
	a := cfg.Security.AddressBook.Addresses["dns-v4"]
	if a.DNSLookupFailed || a.DNSUnresolved || len(a.DNSAddresses) != 0 {
		t.Fatalf("runtime-empty success state = %+v, want no failed/unresolved flags and no prefixes", a)
	}
	var runtimeEmptyWarning bool
	for _, warning := range ValidateConfig(cfg) {
		if strings.Contains(warning, `"dns-v4"`) &&
			strings.Contains(warning, "currently resolves to no addresses") {
			runtimeEmptyWarning = true
		}
	}
	if !runtimeEmptyWarning {
		t.Fatalf("runtime-empty success diagnostic missing; warnings=%v", ValidateConfig(cfg))
	}
	cfg.Security.Policies = []*ZonePairPolicies{
		{FromZone: "untrust", ToZone: "junos-host", Policies: []*Policy{
			jhDeny("block-dns", []string{"dns-v4"}, []string{"any"}),
			jhDeny("block-static", []string{"bad-net"}, []string{"any"}),
		}},
	}
	// Successful empty answers without a family filter retain the existing
	// fail-closed whole-program representability gate.
	a.DNSFamily = ""
	unfiltered := BuildJunosHostDenyProjection(cfg)
	if len(unfiltered.Programs) != 1 || unfiltered.Programs[0].Representable {
		t.Fatalf("unfiltered successful-empty DNS must remain unrepresentable: %+v", unfiltered.Programs)
	}
	a.DNSFamily = "ipv4-only"
	proj := BuildJunosHostDenyProjection(cfg)
	if len(proj.Programs) != 1 || !proj.Programs[0].Representable {
		t.Fatalf("runtime-empty DNS must not withdraw the zone program: %+v", proj.Programs)
	}
	prog := proj.Programs[0]
	foundStatic := false
	for _, rules := range [][]JunosHostDenyRule{prog.RulesV4, prog.RulesV6} {
		for _, r := range rules {
			for _, s := range r.Src {
				if s == "10.0.0.0/8" {
					foundStatic = true
				}
				if strings.Contains(s, "2001:db8") {
					t.Fatalf("family-empty DNS answer leaked into family rules: %+v", prog)
				}
			}
		}
	}
	if !foundStatic {
		t.Fatalf("sibling static deny missing after runtime-empty DNS: %+v", prog.RulesV4)
	}
	if proj.RenderedPolicyKeys[JunosHostZonePairPolicyKey("untrust", "block-dns")] {
		t.Fatal("runtime-empty DNS deny emitted no rule and must retain its warning (not rendered)")
	}
	if !proj.RenderedPolicyKeys[JunosHostZonePairPolicyKey("untrust", "block-static")] {
		t.Fatal("sibling static deny must be rendered")
	}
	// Failed-lookup control: unchanged.
	a.DNSLookupFailed = true
	proj = BuildJunosHostDenyProjection(cfg)
	if len(proj.Programs) != 1 || !proj.Programs[0].Representable {
		t.Fatalf("failed-lookup control changed: %+v", proj.Programs)
	}
	foundStatic = false
	for _, r := range proj.Programs[0].RulesV4 {
		for _, s := range r.Src {
			if s == "10.0.0.0/8" {
				foundStatic = true
			}
		}
	}
	if !foundStatic {
		t.Fatalf("failed-lookup control lost sibling static deny: %+v", proj.Programs[0].RulesV4)
	}
}
