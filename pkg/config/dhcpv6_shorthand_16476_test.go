package config

import (
	"strings"
	"testing"
)

// #16476: `family inet6 { dhcpv6; }` is a consumed Junos shorthand
// (compiler sets unit.DHCPv6; daemon starts an AFInet6 client), but the
// schema declared only `dhcpv6-client`, so the #10707/#15199 open-world
// walker falsely advised that `dhcpv6` "may be silently ignored" on both
// strict and tolerant paths, and `set ... family inet6 dhcpv6` had no
// completion. Declaring the bare leaf fixes all three. The three arms
// pin: shorthand silent + consumed, long form silent + consumed, and
// the near-typo `dhcpv6x` still advised + not consumed.

func dhcpv6Unit16476(t *testing.T, cfg *Config) *InterfaceUnit {
	t.Helper()
	ifc := cfg.Interfaces.Interfaces["ge-0/0/0"]
	if ifc == nil {
		t.Fatalf("interface ge-0/0/0 missing; interfaces=%v", cfg.Interfaces.Interfaces)
	}
	unit := ifc.Units[0]
	if unit == nil {
		t.Fatalf("unit 0 missing; units=%v", ifc.Units)
	}
	return unit
}

func has10707For16476(warnings []string, keyword string) bool {
	for _, w := range warnings {
		if strings.Contains(w, "#10707") && strings.Contains(w, `"`+keyword+`"`) {
			return true
		}
	}
	return false
}

func TestDHCPv6ShorthandNotAdvised16476(t *testing.T) {
	cases := []struct {
		name        string
		lines       []string
		hier        string
		wantDHCPv6  bool
		wantAdvised bool
	}{
		{
			name:       "shorthand",
			lines:      []string{"set interfaces ge-0/0/0 unit 0 family inet6 dhcpv6"},
			hier:       "interfaces { ge-0/0/0 { unit 0 { family inet6 { dhcpv6; } } } }",
			wantDHCPv6: true,
		},
		{
			name:       "dhcpv6-client control",
			lines:      []string{"set interfaces ge-0/0/0 unit 0 family inet6 dhcpv6-client"},
			hier:       "interfaces { ge-0/0/0 { unit 0 { family inet6 { dhcpv6-client; } } } }",
			wantDHCPv6: true,
		},
		{
			name:        "dhcpv6x typo still advised",
			lines:       []string{"set interfaces ge-0/0/0 unit 0 family inet6 dhcpv6x"},
			hier:        "interfaces { ge-0/0/0 { unit 0 { family inet6 { dhcpv6x; } } } }",
			wantDHCPv6:  false,
			wantAdvised: true,
		},
	}
	for _, tc := range cases {
		for _, form := range []struct {
			name string
			tree func() *ConfigTree
		}{
			{"flat-set", func() *ConfigTree { return buildTree(t, tc.lines) }},
			{"hierarchical", func() *ConfigTree { return parseHierText(t, tc.hier) }},
		} {
			t.Run(tc.name+"/"+form.name+"/strict", func(t *testing.T) {
				cfg, err := CompileConfig(form.tree())
				if err != nil {
					t.Fatalf("CompileConfig: %v", err)
				}
				if got := dhcpv6Unit16476(t, cfg).DHCPv6; got != tc.wantDHCPv6 {
					t.Fatalf("DHCPv6 = %v, want %v", got, tc.wantDHCPv6)
				}
				keyword := "dhcpv6"
				if tc.wantAdvised {
					keyword = "dhcpv6x"
				}
				if advised := has10707For16476(cfg.Warnings, keyword); advised != tc.wantAdvised {
					t.Fatalf("#10707 advisory for %q = %v, want %v; warnings=%v", keyword, advised, tc.wantAdvised, cfg.Warnings)
				}
			})
			t.Run(tc.name+"/"+form.name+"/lenient", func(t *testing.T) {
				cfg, err := CompileConfigLenient(form.tree())
				if err != nil {
					t.Fatalf("CompileConfigLenient: %v", err)
				}
				if got := dhcpv6Unit16476(t, cfg).DHCPv6; got != tc.wantDHCPv6 {
					t.Fatalf("lenient DHCPv6 = %v, want %v", got, tc.wantDHCPv6)
				}
				keyword := "dhcpv6"
				if tc.wantAdvised {
					keyword = "dhcpv6x"
				}
				if advised := has10707For16476(cfg.Warnings, keyword); advised != tc.wantAdvised {
					t.Fatalf("lenient #10707 advisory for %q = %v, want %v; warnings=%v", keyword, advised, tc.wantAdvised, cfg.Warnings)
				}
			})
		}
	}
}

// The schema declaration must also surface in completion / `?` help:
// `dhcpv6` is offered beside `dhcpv6-client` under family inet6.
func TestDHCPv6ShorthandCompletion16476(t *testing.T) {
	got := CompleteSetPath([]string{"interfaces", "ge-0/0/0", "unit", "0", "family", "inet6", "dh"})
	found := map[string]bool{}
	for _, name := range got {
		found[name] = true
	}
	if !found["dhcpv6"] {
		t.Fatalf("completion for `... family inet6 dh` = %v, want dhcpv6 offered", got)
	}
	if !found["dhcpv6-client"] {
		t.Fatalf("completion for `... family inet6 dh` = %v, want dhcpv6-client still offered", got)
	}
	// Exact leaf: no further children beyond the Enter hint.
	leaf := CompleteSetPath([]string{"interfaces", "ge-0/0/0", "unit", "0", "family", "inet6", "dhcpv6", ""})
	for _, name := range leaf {
		if name == "dhcpv6-client" || name == "client-type" {
			t.Fatalf("dhcpv6 leaf completion = %v, must not offer dhcpv6-client options", leaf)
		}
	}
}
