package config

import (
	"strings"
	"testing"
)

// #16837: `then static-nat prefix-name` must resolve only when the named
// object denotes exactly one static prefix. resolveStaticNATThenPrefixName
// previously used singular UsableValue(), which returns ExpandedPrefixes[0] /
// DNSAddresses[0], so a multi-host range-address committed as 1:1 NAT to its
// first host, a 1-member set wrapping such an entry did the same, and a
// dns-name target was frozen at its compile-time answer. Fix: require
// len(UsableValues())==1 and DNSName=="" (a dynamic object is not a static
// 1:1 target), otherwise ok=false → strict reject / lenient warn (#4290).
// FAIL-ON-REVERT: restoring UsableValue() makes the range / set / dns cases
// resolve to 10.0.0.5/32 again.

func staticNATPrefixName16837Cmds(entryLines []string, ref string) []string {
	cmds := append([]string{}, entryLines...)
	cmds = append(cmds,
		"set security nat static rule-set S rule R1 match destination-address 203.0.113.5/32",
		"set security nat static rule-set S rule R1 then static-nat prefix-name "+ref)
	return cmds
}

// Unit level: the resolver itself refuses multi-value and dns entries while
// still accepting a single static prefix (incl. single-value expansions).
func TestStaticNATPrefixNameMultiValueUnit16837(t *testing.T) {
	rangeAddr := &Address{Name: "rng", ExpandedPrefixes: []string{"10.0.0.5/32", "10.0.0.6/32", "10.0.0.7/32", "10.0.0.8/32"}}
	singleRange := &Address{Name: "one", ExpandedPrefixes: []string{"10.0.0.5/32"}}
	wildcard := &Address{Name: "wc", ExpandedPrefixes: []string{"10.1.2.0/24"}, WildcardSpec: "10.1.2.3/255.255.255.0"}
	dnsMulti := &Address{Name: "svc", DNSName: "svc.example", DNSAddresses: []string{"10.0.0.5/32", "10.0.0.9/32"}}
	dnsSingle := &Address{Name: "svc1", DNSName: "svc1.example", DNSAddresses: []string{"10.0.0.5/32"}}
	plain := &Address{Name: "srv", Value: "10.0.0.5/32"}

	for _, tc := range []struct {
		name string
		ab   *AddressBook
		ref  string
		want string
	}{
		{"direct range multi-host", &AddressBook{Addresses: map[string]*Address{"rng": rangeAddr}}, "rng", ""},
		{"1-member set wrapping range", &AddressBook{
			Addresses:   map[string]*Address{"rng": rangeAddr},
			AddressSets: map[string]*AddressSet{"GRP": {Name: "GRP", Addresses: []string{"rng"}}},
		}, "GRP", ""},
		{"direct dns multi-answer", &AddressBook{Addresses: map[string]*Address{"svc": dnsMulti}}, "svc", ""},
		{"direct dns single-answer still dynamic", &AddressBook{Addresses: map[string]*Address{"svc1": dnsSingle}}, "svc1", ""},
		{"1-member set wrapping dns", &AddressBook{
			Addresses:   map[string]*Address{"svc1": dnsSingle},
			AddressSets: map[string]*AddressSet{"GRP": {Name: "GRP", Addresses: []string{"svc1"}}},
		}, "GRP", ""},
		{"control single prefix", &AddressBook{Addresses: map[string]*Address{"srv": plain}}, "srv", "10.0.0.5/32"},
		{"control single-host range", &AddressBook{Addresses: map[string]*Address{"one": singleRange}}, "one", "10.0.0.5/32"},
		{"control wildcard single prefix", &AddressBook{Addresses: map[string]*Address{"wc": wildcard}}, "wc", "10.1.2.0/24"},
		{"control 1-member set single prefix", &AddressBook{
			Addresses:   map[string]*Address{"srv": plain},
			AddressSets: map[string]*AddressSet{"GRP": {Name: "GRP", Addresses: []string{"srv"}}},
		}, "GRP", "10.0.0.5/32"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := resolveStaticNATThenPrefixName(tc.ab, tc.ref)
			if tc.want == "" {
				if ok || got != "" {
					t.Fatalf("resolveStaticNATThenPrefixName(%q) = %q, %v; want \"\", false (multi-value/dynamic must fail closed)", tc.ref, got, ok)
				}
				return
			}
			if !ok || got != tc.want {
				t.Fatalf("resolveStaticNATThenPrefixName(%q) = %q, %v; want %q, true", tc.ref, got, ok, tc.want)
			}
		})
	}
}

// End-to-end: range, 1-member-set-of-range and dns-name rows are rejected
// strict and warned (Then=="") lenient; the single-prefix control resolves.
func TestStaticNATPrefixNameMultiValueCompile16837(t *testing.T) {
	rangeEntry := []string{"set security address-book global address rng range-address 10.0.0.5 to 10.0.0.8"}
	dnsEntry := []string{"set security address-book global address svc dns-name svc.example"}

	for _, tc := range []struct {
		name    string
		entries []string
		ref     string
	}{
		{"range-address 4 hosts", rangeEntry, "rng"},
		{"range-address in 1-member set", append(append([]string{}, rangeEntry...),
			"set security address-book global address-set GRP address rng"), "GRP"},
		{"dns-name", dnsEntry, "svc"},
		{"dns-name in 1-member set", append(append([]string{}, dnsEntry...),
			"set security address-book global address-set GRP address svc"), "GRP"},
	} {
		t.Run(tc.name+"/strict-rejected", func(t *testing.T) {
			_, err := CompileConfig(buildTree(t, staticNATPrefixName16837Cmds(tc.entries, tc.ref)))
			if err == nil {
				t.Fatalf("strict commit must reject multi-value/dynamic prefix-name %q (was silently 1:1 to first host)", tc.ref)
			}
			if !strings.Contains(err.Error(), "prefix-name") {
				t.Fatalf("error must reference prefix-name, got: %v", err)
			}
		})
		t.Run(tc.name+"/lenient-warns-empty", func(t *testing.T) {
			cfg, err := CompileConfigLenient(buildTree(t, staticNATPrefixName16837Cmds(tc.entries, tc.ref)))
			if err != nil {
				t.Fatalf("lenient compile must not brick: %v", err)
			}
			rule := cfg.Security.NAT.Static[0].Rules[0]
			if rule.Then != "" {
				t.Fatalf("lenient prefix-name %q resolved Then=%q, want \"\" (must not install first host)", tc.ref, rule.Then)
			}
			if !natWarnContains(cfg, "static NAT translation target") {
				t.Fatalf("lenient compile must emit the #4290 empty-target warning; warnings=%v", cfg.Warnings)
			}
		})
	}

	// Control: single prefix still resolves on both paths.
	control := []string{"set security address-book global address srv 10.0.0.5/32"}
	for _, compile := range []struct {
		name string
		fn   func(*ConfigTree) (*Config, error)
	}{{"strict", CompileConfig}, {"lenient", CompileConfigLenient}} {
		t.Run("single-prefix control/"+compile.name, func(t *testing.T) {
			cfg, err := compile.fn(buildTree(t, staticNATPrefixName16837Cmds(control, "srv")))
			if err != nil {
				t.Fatalf("single-prefix control must compile: %v", err)
			}
			if got := cfg.Security.NAT.Static[0].Rules[0].Then; got != "10.0.0.5/32" {
				t.Fatalf("Then = %q, want 10.0.0.5/32", got)
			}
		})
	}

	// Control: single-host range (one usable prefix) still resolves — the
	// fix keys on multiplicity, not on the range-address form itself.
	oneHost := []string{"set security address-book global address one range-address 10.0.0.5 to 10.0.0.5"}
	cfg, err := CompileConfig(buildTree(t, staticNATPrefixName16837Cmds(oneHost, "one")))
	if err != nil {
		t.Fatalf("single-host range must compile: %v", err)
	}
	if got := cfg.Security.NAT.Static[0].Rules[0].Then; got != "10.0.0.5/32" {
		t.Fatalf("single-host range Then = %q, want 10.0.0.5/32", got)
	}
}
