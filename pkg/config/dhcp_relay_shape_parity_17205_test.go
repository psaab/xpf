package config

import (
	"slices"
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
			"set forwarding-options "+fam+" server-group "+sg+" "+addr2,
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

// relayShapeWantServers17205 is the FULL server list a parity row must
// compile (fold B3: comparing only element [0] let a dropped or doubled
// tail pass green). Canonical-block and hierarchical-bracket rows carry
// one server; the other rows carry both.
func relayShapeWantServers17205(name string, v6 bool) []string {
	addr, addr2 := "10.9.9.9", "10.9.9.10"
	if v6 {
		addr, addr2 = "2001:db8:9::9", "2001:db8:9::10"
	}
	switch name {
	case "canonical server-group block", "hierarchical bracket":
		return []string{addr}
	default:
		return []string{addr, addr2}
	}
}

// relayShapeWantInterfaces17205 is the FULL interface list a parity row
// must compile.
func relayShapeWantInterfaces17205(name string) []string {
	switch name {
	case "canonical server-group block", "compact":
		return []string{"ge-0/0/1.0"}
	default:
		return []string{"ge-0/0/1.0", "ge-0/0/2.0"}
	}
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
						if sg == nil || !slices.Equal(sg.Servers, relayShapeWantServers17205(tc.name, true)) {
							t.Fatalf("#17205: v6 %s (%s) servers = %+v, want %v", tc.name, channel, sg, relayShapeWantServers17205(tc.name, true))
						}
						g := relay.V6.Groups["G6"]
						if g == nil || g.ActiveServerGroup != "SG6" || !slices.Equal(g.Interfaces, relayShapeWantInterfaces17205(tc.name)) {
							t.Fatalf("#17205: v6 %s (%s) group = %+v, want active SG6 interfaces %v", tc.name, channel, g, relayShapeWantInterfaces17205(tc.name))
						}
					} else {
						sg := relay.ServerGroups["SG"]
						if sg == nil || !slices.Equal(sg.Servers, relayShapeWantServers17205(tc.name, false)) {
							t.Fatalf("#17205: v4 %s (%s) servers = %+v, want %v", tc.name, channel, sg, relayShapeWantServers17205(tc.name, false))
						}
						g := relay.Groups["G"]
						if g == nil || g.ActiveServerGroup != "SG" || !slices.Equal(g.Interfaces, relayShapeWantInterfaces17205(tc.name)) {
							t.Fatalf("#17205: v4 %s (%s) group = %+v, want active SG interfaces %v", tc.name, channel, g, relayShapeWantInterfaces17205(tc.name))
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

// TestDHCPRelayDigitLessMember17205 pins fold B1: digit-less bare
// interface names are legal members. `uplink` and `vrf-mgmt` pass
// ValidateInterfaceName (validate_interface_name_6834_test.go census)
// and the pre-#17205 gate accepted any single bare member; the digit
// requirement added by the first #17205 head refused them, breaking
// strict configs on upgrade. Each name must strict-compile and
// install as the group's sole interface.
func TestDHCPRelayDigitLessMember17205(t *testing.T) {
	for _, member := range []string{"uplink", "vrf-mgmt"} {
		t.Run(member, func(t *testing.T) {
			tree := parseHierText(t, "forwarding-options { dhcp-relay { dhcpv6 { "+
				"server-group { SG6 { 2001:db8:9::9; } } "+
				"group G6 { active-server-group SG6; interface "+member+"; } } } }")
			cfg, err := CompileConfig(tree)
			if err != nil {
				t.Fatalf("#17205 B1: digit-less member %q strict-refused: %v", member, err)
			}
			g := cfg.ForwardingOptions.DHCPRelay.V6.Groups["G6"]
			if g == nil || !slices.Equal(g.Interfaces, []string{member}) {
				t.Fatalf("#17205 B1: digit-less member %q group = %+v, want interfaces [%s]", member, g, member)
			}
		})
	}
}

// TestDHCPRelayPackedVersusList17205 pins the three verdicts of fold
// B1's packed-remainder mechanism on the same member vocabulary:
// (a) a single bare any-name member ACCEPTS, (b) a multi-token packed
// remainder behind a first value REFUSES naming the remainder token
// even though that token is a legal bare name on its own, and (c) a
// braced child behind a scalar or a braced member REFUSES naming the
// child. (b) is refused by position (unbracketed Keys[2:]), not by
// name-shape: `disable` would pass member validity alone.
func TestDHCPRelayPackedVersusList17205(t *testing.T) {
	sg := "server-group { SG6 { 2001:db8:9::9; } } "
	hier := func(body string) *ConfigTree {
		return parseHierText(t, "forwarding-options { dhcp-relay { dhcpv6 { "+sg+body+" } } }")
	}
	t.Run("single bare any-name accepts", func(t *testing.T) {
		cfg, err := CompileConfig(hier("group G6 { active-server-group SG6; interface disable; }"))
		if err != nil {
			t.Fatalf("#17205 B1: single bare member strict-refused: %v", err)
		}
		g := cfg.ForwardingOptions.DHCPRelay.V6.Groups["G6"]
		if g == nil || !slices.Equal(g.Interfaces, []string{"disable"}) {
			t.Fatalf("#17205 B1: single bare member group = %+v, want [disable]", g)
		}
	})
	for _, tc := range []struct {
		name string
		tree *ConfigTree
		want string
	}{
		{"hier packed remainder", hier("group G6 { active-server-group SG6; interface ge-0/0/0.0 disable; }"), "disable"},
		{"flat packed remainder", flatTree9411(t,
			"set forwarding-options dhcp-relay dhcpv6 server-group SG6 2001:db8:9::9",
			"set forwarding-options dhcp-relay dhcpv6 group G6 active-server-group SG6",
			"set forwarding-options dhcp-relay dhcpv6 group G6 interface ge-0/0/0.0 disable"), "disable"},
		{"hier scalar braced child", hier("group G6 { active-server-group SG6; interface ge-0/0/0.0 { disable; } }"), "disable"},
		{"hier braced-member child", hier("group G6 { active-server-group SG6; interface { ge-0/0/0.0 { disable; } } }"), "disable"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := CompileConfig(tc.tree)
			if err == nil || !strings.Contains(err.Error(), "#9553") || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("#17205 B1: %s must refuse naming %q with #9553, got %v", tc.name, tc.want, err)
			}
		})
	}
}

// TestDHCPRelayContainerPackedGroup17205 pins fold B2 (fail-open):
// the container spelling `group { G6 unsupported-knob interface
// badname; }` rides the whole group body on the instance node's
// packed run. The compiler consumes that run and installed
// Interfaces=[badname]; the gate iterated only Children and let it
// strict-compile clean. With a family active-server-group fallback
// the config is otherwise valid, so the ONLY refusal must name the
// packed unsupported knob. A packed bad member alone must likewise
// refuse naming the member.
func TestDHCPRelayContainerPackedGroup17205(t *testing.T) {
	for _, tc := range []struct{ name, body, want string }{
		{"packed unsupported knob", "group { G6 unsupported-knob interface badname; }", "unsupported-knob"},
		{"packed second remainder", "group { G6 interface ge-0/0/0.0 badname; }", "badname"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tree := parseHierText(t, "forwarding-options { dhcp-relay { dhcpv6 { "+
				"active-server-group SG6; server-group SG6 { 2001:db8:9::9; } "+tc.body+" } } }")
			_, err := CompileConfig(tree)
			if err == nil || !strings.Contains(err.Error(), "#9553") || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("#17205 B2: %s must strict-refuse naming %q with #9553, got %v", tc.name, tc.want, err)
			}
			lenient, lerr := CompileConfigLenient(tree)
			if lerr != nil {
				t.Fatalf("#17205 B2 no-brick: tolerant %s rejected: %v", tc.name, lerr)
			}
			if !mentions9553(lenient.Warnings) {
				t.Fatalf("#17205 B2 no-brick: tolerant %s emitted no #9553 warning: %v", tc.name, lenient.Warnings)
			}
		})
	}
}

// TestDHCPRelayPackedMetaGroup17205 pins fold F1: meta statements
// (apply-groups / apply-groups-except / apply-macro) packed onto a
// relay group's tail are legal at any hierarchy point (#7029), so
// the braced spellings the children loops exempt must also be
// exempt in the packed spelling checkGroupPacked judges. The
// compiler ignores those tokens on the same run, so strict must
// accept them and install only the real members.
func TestDHCPRelayPackedMetaGroup17205(t *testing.T) {
	for _, tc := range []struct{ name, body string }{
		{"packed apply-groups", "group { G6 apply-groups foo interface ge-0/0/0.0; }"},
		{"packed apply-groups-except", "group { G6 apply-groups-except foo interface ge-0/0/0.0; }"},
		{"packed apply-macro bare", "group { G6 apply-macro M foo interface ge-0/0/0.0; }"},
		{"packed apply-macro body tokens", "group { G6 apply-macro M interface ge-0/0/0.0; }"},
		{"packed apply-macro after scalar", "group { G6 active-server-group SG6 apply-macro M k v interface ge-0/0/0.0; }"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tree := parseHierText(t, "forwarding-options { dhcp-relay { dhcpv6 { "+
				"active-server-group SG6; server-group SG6 { 2001:db8:9::9; } "+tc.body+" } } }")
			cfg, err := CompileConfig(tree)
			if err != nil {
				t.Fatalf("#17205 F1: %s strict-refused: %v", tc.name, err)
			}
			g := cfg.ForwardingOptions.DHCPRelay.V6.Groups["G6"]
			if g == nil || !slices.Equal(g.Interfaces, []string{"ge-0/0/0.0"}) {
				t.Fatalf("#17205 F1: %s group = %+v, want interfaces [ge-0/0/0.0]", tc.name, g)
			}
		})
	}
}
