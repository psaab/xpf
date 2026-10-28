package config

import (
	"strings"
	"testing"
)

// #17205: the DHCPv6 relay commit gate (validateDHCPRelayDHCPv6AST) re-walked
// the tree by hand instead of using the compilers' shape readers, so it
// rejected configuration both compilers read correctly:
//
//   - the canonical Junos `server-group { SG6 { addr; } }` block (the gate
//     reported the first server ADDRESS as an unsupported keyword);
//   - a flat-set or display-set `interface a b` list (the gate told a list
//     from a scalar-plus-option by KeyBracketed provenance, which FormatSet
//     does not carry — so xpf's own `show configuration | display set`
//     output could not be reloaded).
//
// The gate now iterates namedInstances exactly like both compilers and
// judges the members of the shared dhcpRelayGroupInterfaces reader. This
// table pins {v4, v6} x {canonical server-group block, compact, flat-set
// repeated, flat-set bracket, hierarchical bracket, display-set replay} to
// identical strict verdicts with unchanged compiled values, so the gate and
// the compilers cannot diverge again without a cell going red.

type relayShapeCase17205 struct {
	name string
	make func(t *testing.T) *ConfigTree
}

func relayShapeCases17205(v6 bool) []relayShapeCase17205 {
	sg, grp, asg := "SG", "G", "SG"
	addr, addr2 := "10.9.9.9", "10.9.9.10"
	if v6 {
		sg, grp, asg = "SG6", "G6", "SG6"
		addr, addr2 = "2001:db8:9::9", "2001:db8:9::10"
	}
	fam := "dhcp-relay"
	hierPfx := "forwarding-options { dhcp-relay { "
	hierSfx := " } }"
	if v6 {
		fam = "dhcp-relay dhcpv6"
		hierPfx = "forwarding-options { dhcp-relay { dhcpv6 { "
		hierSfx = " } } }"
	}
	flat := func(lines ...string) func(*testing.T) *ConfigTree {
		return func(t *testing.T) *ConfigTree { return flatTree9411(t, lines...) }
	}
	hier := func(body string) func(*testing.T) *ConfigTree {
		return func(t *testing.T) *ConfigTree { return parseHierText(t, hierPfx+body+hierSfx) }
	}
	return []relayShapeCase17205{
		{"canonical server-group block", hier(
			"server-group { " + sg + " { " + addr + "; } } " +
				"group " + grp + " { active-server-group " + asg + "; interface ge-0/0/1.0; }")},
		{"compact", hier(
			"server-group " + sg + " { " + addr + "; " + addr2 + "; } " +
				"group " + grp + " { active-server-group " + asg + "; interface ge-0/0/1.0; }")},
		{"flat-set repeated", flat(
			"set forwarding-options "+fam+" server-group "+sg+" "+addr,
			"set forwarding-options "+fam+" server-group "+sg+" "+addr2,
			"set forwarding-options "+fam+" group "+grp+" active-server-group "+asg,
			"set forwarding-options "+fam+" group "+grp+" interface ge-0/0/1.0",
			"set forwarding-options "+fam+" group "+grp+" interface ge-0/0/2.0")},
		{"flat-set bracket", flat(
			"set forwarding-options "+fam+" server-group "+sg+" "+addr,
			"set forwarding-options "+fam+" group "+grp+" active-server-group "+asg,
			"set forwarding-options "+fam+" group "+grp+" interface ge-0/0/1.0 ge-0/0/2.0")},
		{"hierarchical bracket", hier(
			"server-group " + sg + " { " + addr + "; } " +
				"group " + grp + " { active-server-group " + asg + "; interface [ ge-0/0/1.0 ge-0/0/2.0 ]; }")},
	}
}

// replayDisplaySet17205 renders tree via FormatSet (xpf's display-set output)
// and reloads it through ParseSetCommand+SetPath, the production load-set
// channel. It returns the reloaded tree.
func replayDisplaySet17205(t *testing.T, tree *ConfigTree) *ConfigTree {
	t.Helper()
	setText := tree.FormatSet()
	out := &ConfigTree{}
	for _, line := range strings.Split(strings.TrimSpace(setText), "\n") {
		if line == "" {
			continue
		}
		p, err := ParseSetCommand(line)
		if err != nil {
			t.Fatalf("display-set line %q did not parse: %v", line, err)
		}
		if err := out.SetPath(p); err != nil {
			t.Fatalf("display-set line %q did not reload: %v", line, err)
		}
	}
	return out
}

func TestDHCPRelayShapeParity17205(t *testing.T) {
	for _, v6 := range []bool{false, true} {
		family := "v4"
		if v6 {
			family = "v6"
		}
		for _, tc := range relayShapeCases17205(v6) {
			t.Run(family+"/"+tc.name, func(t *testing.T) {
				for _, channel := range []string{"direct", "display-set replay"} {
					tree := tc.make(t)
					if channel == "display-set replay" {
						tree = replayDisplaySet17205(t, tree)
					}
					cfg, err := CompileConfig(tree)
					if err != nil {
						t.Fatalf("#17205: %s %s (%s) strict-compiled with error: %v", family, tc.name, channel, err)
					}
					relay := cfg.ForwardingOptions.DHCPRelay
					if relay == nil {
						t.Fatalf("#17205: %s %s (%s) compiled no relay", family, tc.name, channel)
					}
					if v6 {
						if relay.V6 == nil {
							t.Fatalf("#17205: v6 %s (%s) compiled no v6 relay", tc.name, channel)
						}
						sg := relay.V6.ServerGroups["SG6"]
						if sg == nil || len(sg.Servers) == 0 || sg.Servers[0] != "2001:db8:9::9" {
							t.Fatalf("#17205: v6 %s (%s) server-group = %+v, want first server 2001:db8:9::9", tc.name, channel, sg)
						}
						g := relay.V6.Groups["G6"]
						if g == nil || g.ActiveServerGroup != "SG6" || len(g.Interfaces) == 0 || g.Interfaces[0] != "ge-0/0/1.0" {
							t.Fatalf("#17205: v6 %s (%s) group = %+v, want active SG6 and first interface ge-0/0/1.0", tc.name, channel, g)
						}
					} else {
						sg := relay.ServerGroups["SG"]
						if sg == nil || len(sg.Servers) == 0 || sg.Servers[0] != "10.9.9.9" {
							t.Fatalf("#17205: v4 %s (%s) server-group = %+v, want first server 10.9.9.9", tc.name, channel, sg)
						}
						g := relay.Groups["G"]
						if g == nil || g.ActiveServerGroup != "SG" || len(g.Interfaces) == 0 || g.Interfaces[0] != "ge-0/0/1.0" {
							t.Fatalf("#17205: v4 %s (%s) group = %+v, want active SG and first interface ge-0/0/1.0", tc.name, channel, g)
						}
					}
				}
			})
		}
	}
}

// TestDHCPRelayV6GateNoKeyBracketed17205 pins the acceptance census: the v6
// gate must not consult bracket provenance at all. A display-set replay
// carries none, so any KeyBracketed use in the gate file can reintroduce
// the provenance-dependent verdict. (Kept as a behavioural companion: the
// parity table above fails if provenance creeps back in; this documents
// why.)
func TestDHCPRelayV6GateNoKeyBracketed17205(t *testing.T) {
	tree := parseHierText(t, "forwarding-options { dhcp-relay { dhcpv6 { "+
		"server-group { SG6 { 2001:db8:9::9; } } "+
		"group G6 { active-server-group SG6; interface [ ge-0/0/1.0 ge-0/0/2.0 ]; } } } }")
	if _, err := validateDHCPRelayDHCPv6AST(tree.Children, false); err != nil {
		t.Fatalf("#17205: canonical block + bracket list refused by gate: %v", err)
	}
	replayed := replayDisplaySet17205(t, tree)
	if _, err := validateDHCPRelayDHCPv6AST(replayed.Children, false); err != nil {
		t.Fatalf("#17205: display-set replay of the same config refused by gate: %v", err)
	}
}
