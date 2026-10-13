package config

import (
	"fmt"
	"reflect"
	"strings"
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

// crossKindChain12502 builds s0 -> s1 -> ... -> s<edges> -> a0, where every
// set reaches the next one through a cross-kind `address` member.
func crossKindChain12502(edges int) *AddressBook {
	ab := &AddressBook{
		Addresses:   map[string]*Address{"a0": {Name: "a0", Value: "10.9.0.1/32"}},
		AddressSets: make(map[string]*AddressSet, edges+1),
	}
	for i := 0; i <= edges; i++ {
		name, member := fmt.Sprintf("s%d", i), fmt.Sprintf("s%d", i+1)
		if i == edges {
			member = "a0"
		}
		ab.AddressSets[name] = &AddressSet{Name: name, Addresses: []string{member}}
	}
	return ab
}

// TestCrossKindAddressSetBounds12502 pins that a cross-kind `address` edge is
// bounded like a nested `address-set` edge: it counts toward the five-edge
// depth limit and shares the path-local cycle set, so a cycle is reported as
// a cycle rather than as a depth overrun. Both literal-prefix consumers fail
// closed on either error.
func TestCrossKindAddressSetBounds12502(t *testing.T) {
	cycle := &AddressBook{
		Addresses: map[string]*Address{},
		AddressSets: map[string]*AddressSet{
			"A": {Name: "A", Addresses: []string{"B"}},
			"B": {Name: "B", Addresses: []string{"A"}},
		},
	}
	for _, tc := range []struct {
		name    string
		ab      *AddressBook
		root    string
		wantErr string
	}{
		{name: "five-edge-chain-resolves", ab: crossKindChain12502(5), root: "s0"},
		{name: "nine-edge-chain-too-deep", ab: crossKindChain12502(9), root: "s0",
			wantErr: "address-set nesting too deep (max 5): s6"},
		{name: "mutual-cycle", ab: cycle, root: "A",
			wantErr: `cycle detected in address-set "A"`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := expandAddressSetLeaves(tc.root, tc.ab)
			cfg := &Config{}
			cfg.Security.AddressBook = tc.ab
			v4, _, _, _, hostOK := junosHostResolveAddrSet(cfg, []string{tc.root}, nil)
			prefix, natOK := resolveStaticNATThenPrefixName(tc.ab, tc.root)
			if tc.wantErr == "" {
				if err != nil || !reflect.DeepEqual(got, []string{"a0"}) {
					t.Fatalf("expandAddressSetLeaves(%q) = %v, %v; want [a0]", tc.root, got, err)
				}
				if !hostOK || !reflect.DeepEqual(v4, []string{"10.9.0.1/32"}) ||
					!natOK || prefix != "10.9.0.1/32" {
					t.Fatalf("junos-host = %v, %v; static-NAT = %q, %v; want 10.9.0.1/32",
						v4, hostOK, prefix, natOK)
				}
				return
			}
			if err == nil || err.Error() != tc.wantErr {
				t.Fatalf("expandAddressSetLeaves(%q) = %v, %v; want error %q",
					tc.root, got, err, tc.wantErr)
			}
			if hostOK || natOK {
				t.Fatalf("consumer resolved past the error: junos-host = %v, %v; static-NAT = %q, %v",
					v4, hostOK, prefix, natOK)
			}
		})
	}
}

// TestCrossKindAddressFirstOnNameCollision12502 pins that a cross-kind member
// collision is refused during static-NAT prefix-name resolution. Strict
// commit rejects the collision; tolerant compilation records it and leaves the
// NAT target empty so the #4290 warning fires rather than selecting either
// definition.
func TestCrossKindAddressFirstOnNameCollision12502(t *testing.T) {
	lines := []string{
		"set security address-book global address X 10.1.1.1/32",
		"set security address-book global address xm 10.9.0.1/32",
		"set security address-book global address-set X address xm",
		"set security address-book global address-set A address X",
		"set security nat static rule-set S rule R1 match destination-address 203.0.113.5/32",
		"set security nat static rule-set S rule R1 then static-nat prefix-name A",
	}
	if _, err := CompileConfig(buildTree(t, lines)); err == nil ||
		!strings.Contains(err.Error(), `defines "X" as BOTH`) {
		t.Fatalf("strict commit error = %v; want the X address/address-set collision", err)
	}
	cfg, err := CompileConfigLenient(buildTree(t, lines))
	if err != nil {
		t.Fatalf("lenient compile: %v", err)
	}
	rule := cfg.Security.NAT.Static[0].Rules[0]
	if rule.Then != "" {
		t.Fatalf("lenient static-NAT target = %q; want empty so the collision is not selected", rule.Then)
	}
	if !natWarnContains(cfg, "static NAT translation target") {
		t.Fatalf("lenient static-NAT collision must warn via the empty-target gate; warnings=%v", cfg.Warnings)
	}
}
