package config

import (
	"reflect"
	"testing"
)

// TestCrossKindAddressSetResolution12502 pins the leaf contract of the
// literal-prefix consumers (junos-host deny and static-NAT prefix-name):
// `address B` may name an address-set, just as `address-set B` does, while
// ExpandAddressSet keeps that member as a set-ID graph reference for the
// dataplane compiler. The referencing set sorts before (A) and after (Z) the
// referenced set B, so a resolver that depends on name order cannot pass both.
func TestCrossKindAddressSetResolution12502(t *testing.T) {
	for _, tc := range []struct {
		name       string
		outer      string
		memberKind string
	}{
		{name: "address-member-referrer-sorts-before", outer: "A", memberKind: "address"},
		{name: "address-member-referrer-sorts-after", outer: "Z", memberKind: "address"},
		{name: "address-set-member", outer: "A", memberKind: "address-set"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			outer := &AddressSet{Name: tc.outer}
			wantGraph := []string{"h1"}
			if tc.memberKind == "address" {
				outer.Addresses = []string{"B"}
				wantGraph = []string{"B"}
			} else {
				outer.AddressSets = []string{"B"}
			}
			ab := &AddressBook{
				Addresses: map[string]*Address{"h1": {Name: "h1", Value: "10.9.0.1/32"}},
				AddressSets: map[string]*AddressSet{
					tc.outer: outer,
					"B":      {Name: "B", Addresses: []string{"h1"}},
				},
			}
			graph, err := ExpandAddressSet(tc.outer, ab)
			if err != nil || !reflect.DeepEqual(graph, wantGraph) {
				t.Fatalf("ExpandAddressSet(%q) = %v, %v; want %v", tc.outer, graph, err, wantGraph)
			}
			got, err := expandAddressSetLeaves(tc.outer, ab)
			if err != nil || !reflect.DeepEqual(got, []string{"h1"}) {
				t.Fatalf("expandAddressSetLeaves(%q) = %v, %v; want [h1]", tc.outer, got, err)
			}
			cfg := &Config{}
			cfg.Security.AddressBook = ab
			v4, v6, _, _, ok := junosHostResolveAddrSet(cfg, []string{tc.outer}, nil)
			if !ok || !reflect.DeepEqual(v4, []string{"10.9.0.1/32"}) || len(v6) != 0 {
				t.Fatalf("junosHostResolveAddrSet = v4 %v v6 %v ok %v", v4, v6, ok)
			}
			prefix, ok := resolveStaticNATThenPrefixName(ab, tc.outer)
			if !ok || prefix != "10.9.0.1/32" {
				t.Fatalf("resolveStaticNATThenPrefixName = %q, %v", prefix, ok)
			}
		})
	}
}

func TestCrossKindAddressSetUnknownMemberStillFails12502(t *testing.T) {
	ab := &AddressBook{
		Addresses: map[string]*Address{},
		AddressSets: map[string]*AddressSet{
			"A": {Name: "A", Addresses: []string{"missing"}},
		},
	}
	if got, ok := resolveStaticNATThenPrefixName(ab, "A"); ok || got != "" {
		t.Fatalf("unknown static-NAT prefix-name resolved to %q", got)
	}
	cfg := &Config{}
	cfg.Security.AddressBook = ab
	if _, _, _, _, ok := junosHostResolveAddrSet(cfg, []string{"A"}, nil); ok {
		t.Fatal("junos-host resolver accepted unknown member")
	}
}

func TestCrossKindJunosHostDenyRenders12502(t *testing.T) {
	proj := jh4146DstProjection(t,
		"set security address-book global address-set A address B",
		"set security address-book global address-set B address bad-host",
		"set security policies from-zone untrust to-zone junos-host policy blk match source-address A",
		"set security policies from-zone untrust to-zone junos-host policy blk match destination-address any",
		"set security policies from-zone untrust to-zone junos-host policy blk match application any",
		"set security policies from-zone untrust to-zone junos-host policy blk then deny",
	)
	p := jh4146OneProgram(t, proj)
	if !p.Representable || len(p.RulesV4) != 1 || p.RulesV4[0].SrcAny ||
		!reflect.DeepEqual(p.RulesV4[0].Src, []string{"10.0.0.5/32"}) {
		t.Fatalf("cross-kind deny was not emitted as the expected host drop: %+v", p)
	}
	if !proj.RenderedPolicyKeys[JunosHostZonePairPolicyKey("untrust", "blk")] {
		t.Fatalf("cross-kind deny was not recorded as rendered: %+v", proj.RenderedPolicyKeys)
	}
}

func TestCrossKindStaticNATPrefixNameCompiles12502(t *testing.T) {
	lines := []string{
		"set security address-book global address INSIDEHOST 10.0.0.5/32",
		"set security address-book global address-set POOL address INSIDEHOST",
		"set security address-book global address-set ALIAS address POOL",
		"set security nat static rule-set S rule R1 match destination-address 203.0.113.5/32",
		"set security nat static rule-set S rule R1 then static-nat prefix-name ALIAS",
	}
	for _, compile := range []struct {
		name string
		fn   func(*ConfigTree) (*Config, error)
	}{
		{"strict", CompileConfig},
		{"lenient", CompileConfigLenient},
	} {
		t.Run(compile.name, func(t *testing.T) {
			cfg, err := compile.fn(buildTree(t, lines))
			if err != nil {
				t.Fatalf("cross-kind prefix-name should compile: %v", err)
			}
			rule := cfg.Security.NAT.Static[0].Rules[0]
			if rule.ThenPrefixName != "ALIAS" || rule.Then != "10.0.0.5/32" {
				t.Fatalf("static-NAT target = name %q, prefix %q; want ALIAS / 10.0.0.5/32",
					rule.ThenPrefixName, rule.Then)
			}
		})
	}
}
