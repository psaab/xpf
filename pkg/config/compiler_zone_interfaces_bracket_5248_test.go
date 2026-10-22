package config

import (
	"reflect"
	"strings"
	"testing"
)

// Tests for #5248: a security-zone `interfaces` bracketed / load-override
// membership list `interfaces [ a b c ]` dropped every member but the first.
// The #2419 dual-AST SSOT (firewallMatchValues) converts multi:true value
// leaves, but the zone interface name is a WILDCARD container, so the bracket
// tail does NOT collapse onto one leaf's Keys — SetPath nests each surplus
// token under the first member (`interfaces -> a(container) -> leaf [b c]`).
// compileZones read only iface.Name() and silently dropped the nested members,
// a zone-membership (security boundary) loss: the dropped interfaces are left
// unmanaged / brought DOWN or evaluated against the wrong zone, and their
// absence hid them from the strict zone-interface-defined gate. The fix flattens
// the nested chain via zoneInterfaceMembers so every AST shape yields all
// members.
//
// Every RED-on-revert case below fails (only the first member present, or an
// undefined member no longer rejected) if the zoneInterfaceMembers flatten is
// reverted to iface.Name()-only.
//
// IMPORTANT (per CLAUDE.md): flat-set syntax is built with ParseSetCommand +
// tree.SetPath, never NewParser; the hierarchical shape uses parseHierText (#16139 kit).

// compileZonesFromSet5248 builds a tree from flat-set commands and compiles just
// the zones subtree, returning the zone membership by name. It targets
// compileZones directly (per the #5248 repro guidance) so the assertion is on
// the compiled zone.Interfaces slice, independent of the full-pipeline strict
// gates.
func compileZonesFromSet5248(t *testing.T, cmds ...string) map[string][]string {
	t.Helper()
	tree := &ConfigTree{}
	for _, cmd := range cmds {
		path, err := ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", cmd, err)
		}
	}
	return compileZonesMembership5248(t, tree)
}

func compileZonesMembership5248(t *testing.T, tree *ConfigTree) map[string][]string {
	t.Helper()
	sec := tree.FindChild("security")
	if sec == nil {
		t.Fatalf("no security node in tree")
	}
	zonesNode := sec.FindChild("zones")
	if zonesNode == nil {
		t.Fatalf("no security zones node in tree")
	}
	secCfg := &SecurityConfig{Zones: map[string]*ZoneConfig{}}
	if err := compileZones(zonesNode, secCfg); err != nil {
		t.Fatalf("compileZones: %v", err)
	}
	out := make(map[string][]string, len(secCfg.Zones))
	for name, z := range secCfg.Zones {
		out[name] = z.Interfaces
	}
	return out
}

// TestZoneInterfacesBracket5248FlatSetKeepsAllMembers is the primary
// RED-on-revert guard: a two- and a three-member bracketed flat-set list must
// land EVERY member. Reverting zoneInterfaceMembers to iface.Name()-only drops
// everything after the first and this goes RED.
func TestZoneInterfacesBracket5248FlatSetKeepsAllMembers(t *testing.T) {
	cases := []struct {
		name string
		cmd  string
		want []string
	}{
		{
			name: "two-member bracket",
			cmd:  "set security zones security-zone Z interfaces [ ge-0/0/0 ge-0/0/1 ]",
			want: []string{"ge-0/0/0", "ge-0/0/1"},
		},
		{
			name: "three-member bracket",
			cmd:  "set security zones security-zone Z interfaces [ ge-0/0/0 ge-0/0/1 ge-0/0/2 ]",
			want: []string{"ge-0/0/0", "ge-0/0/1", "ge-0/0/2"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := compileZonesFromSet5248(t, tc.cmd)["Z"]
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("zone Z interfaces = %v, want %v (bracket tail dropped — #5248)", got, tc.want)
			}
		})
	}
}

// TestZoneInterfacesBracket5248DualASTParity pins the documented dual-AST
// contract: the hierarchical block and the bracketed flat-set list must compile
// to the SAME zone membership. Before the fix the flat-set list yielded only the
// first member while the hierarchical block yielded both — a parity break.
func TestZoneInterfacesBracket5248DualASTParity(t *testing.T) {
	flat := compileZonesFromSet5248(t,
		"set security zones security-zone Z interfaces [ ge-0/0/0 ge-0/0/1 ]",
	)["Z"]

	hierTree := parseHierText(t, `
security {
    zones {
        security-zone Z {
            interfaces {
                ge-0/0/0;
                ge-0/0/1;
            }
        }
    }
}`)
	hier := compileZonesMembership5248(t, hierTree)["Z"]

	want := []string{"ge-0/0/0", "ge-0/0/1"}
	if !reflect.DeepEqual(hier, want) {
		t.Fatalf("hierarchical zone interfaces = %v, want %v", hier, want)
	}
	if !reflect.DeepEqual(flat, hier) {
		t.Fatalf("dual-AST parity broken: flat-set %v != hierarchical %v (#5248)", flat, hier)
	}
}

// TestZoneInterfaces5248SingleMembershipNotOverCollapsed is the negative
// control: a single membership must yield EXACTLY one member (the flatten must
// not invent phantom members from an empty tail).
func TestZoneInterfaces5248SingleMembershipNotOverCollapsed(t *testing.T) {
	got := compileZonesFromSet5248(t,
		"set security zones security-zone Z interfaces ge-0/0/0",
	)["Z"]
	want := []string{"ge-0/0/0"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("single membership zone interfaces = %v, want %v (over-collapse)", got, want)
	}
}

// TestZoneInterfaces5248PerInterfaceHostInboundPreserved confirms the flatten
// does NOT regress the #3362 per-interface host-inbound-traffic override: the
// interface still appears as a member AND its host-inbound stanza still keys on
// the interface name (the flatten skips the host-inbound-traffic body, so it is
// not mistaken for a member).
func TestZoneInterfaces5248PerInterfaceHostInboundPreserved(t *testing.T) {
	tree := &ConfigTree{}
	for _, cmd := range []string{
		"set security zones security-zone Z interfaces ge-0/0/0 host-inbound-traffic system-services [ ssh ping ]",
		"set security zones security-zone Z interfaces ge-0/0/1",
	} {
		path, err := ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", cmd, err)
		}
	}
	sec := tree.FindChild("security")
	secCfg := &SecurityConfig{Zones: map[string]*ZoneConfig{}}
	if err := compileZones(sec.FindChild("zones"), secCfg); err != nil {
		t.Fatalf("compileZones: %v", err)
	}
	z := secCfg.Zones["Z"]
	if !reflect.DeepEqual(z.Interfaces, []string{"ge-0/0/0", "ge-0/0/1"}) {
		t.Fatalf("zone interfaces = %v, want [ge-0/0/0 ge-0/0/1]", z.Interfaces)
	}
	hib := z.InterfaceHostInbound["ge-0/0/0"]
	if hib == nil {
		t.Fatalf("per-interface host-inbound for ge-0/0/0 missing (flatten swallowed the body?)")
	}
	if !reflect.DeepEqual(hib.SystemServices, []string{"ssh", "ping"}) {
		t.Fatalf("per-interface system-services = %v, want [ssh ping]", hib.SystemServices)
	}
	// The host-inbound-traffic body must NOT leak into the membership list.
	for _, m := range z.Interfaces {
		if m == "host-inbound-traffic" {
			t.Fatalf("host-inbound-traffic leaked into zone membership: %v", z.Interfaces)
		}
	}
}

// TestZoneInterfacesBracket5248EndToEndCompile drives the FULL CompileConfig
// pipeline: both bracketed members are defined under `interfaces`, so both must
// survive into zone membership and pass the strict zone-interface-defined gate.
func TestZoneInterfacesBracket5248EndToEndCompile(t *testing.T) {
	tree := &ConfigTree{}
	for _, cmd := range []string{
		"set interfaces ge-0/0/0 unit 0 family inet address 10.0.0.1/24",
		"set interfaces ge-0/0/1 unit 0 family inet address 10.0.1.1/24",
		"set security zones security-zone trust interfaces [ ge-0/0/0 ge-0/0/1 ]",
	} {
		path, err := ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", cmd, err)
		}
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	got := cfg.Security.Zones["trust"].Interfaces
	if !reflect.DeepEqual(got, []string{"ge-0/0/0", "ge-0/0/1"}) {
		t.Fatalf("trust zone interfaces = %v, want [ge-0/0/0 ge-0/0/1] (#5248)", got)
	}
}

// TestZoneInterfacesBracket5248UndefinedMemberRejected is the fail-fast
// RED-on-revert guard mirroring #3703's unknown-token gate: a bracketed member
// that names an UNDEFINED interface must reach the strict zone-interface-defined
// gate and be REJECTED at commit. Before the fix the second member was dropped
// before validation, so the config committed with the undefined interface
// silently absent — reverting the flatten makes this compile clean and the test
// goes RED.
func TestZoneInterfacesBracket5248UndefinedMemberRejected(t *testing.T) {
	tree := &ConfigTree{}
	for _, cmd := range []string{
		"set interfaces ge-0/0/0 unit 0 family inet address 10.0.0.1/24",
		"set security zones security-zone trust interfaces [ ge-0/0/0 ge-0/0/9 ]",
	} {
		path, err := ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", cmd, err)
		}
	}
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatalf("CompileConfig accepted a bracketed zone member naming an undefined interface; want a strict reject (#5248)")
	}
	if !strings.Contains(err.Error(), "ge-0/0/9") {
		t.Fatalf("reject error %q does not name the undefined member ge-0/0/9", err.Error())
	}
}
