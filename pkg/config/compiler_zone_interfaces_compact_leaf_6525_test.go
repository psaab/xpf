package config

import (
	"reflect"
	"sort"
	"strings"
	"testing"
)

// Tests for #6525: the hierarchical COMPACT-LEAF spelling of a security-zone
// membership list —
//
//	security { zones { security-zone untrust { interfaces ge-0/0/1.0; } } }
//
// — put the member name on the `interfaces` STANZA's own Keys tail with nil
// Children, and compileZones iterated prop.Children, so the loop body ran ZERO
// times and the zone compiled with NO interfaces at all. Cleanly: no error, no
// warning. Both strict zone-membership gates then passed VACUOUSLY over the
// empty slice (they iterate zone.Interfaces), so the gates that exist
// specifically to protect zone membership were inert. Downstream
// dataplane/userspace.UserspaceBoundLinuxInterfaces skips any interface with
// Zone == "", so the interface was never AF_XDP-bound and every policy naming
// that zone never applied to its traffic.
//
// The with-body variant was worse than a drop: prop.Children held the member's
// BODY, so the loop ran once with the `host-inbound-traffic` node mistaken for a
// member — the member name was dropped AND its body keywords were compiled as
// phantom interface names.
//
// REACHABILITY (honest bound) — of THIS shape, the compact leaf: hierarchical
// text ingest only, i.e. `load override` / `load merge` / the persisted config
// file / HA SyncApply. NOT reachable from the `set` CLI — SetPath always leaves
// the STANZA node at Keys=["interfaces"] and puts the members underneath, which
// is the whole load-bearing claim (pinned by
// TestZoneInterfaces6525FlatSetNeverReachesCompactLeaf). Note "underneath" is
// NOT "one child per member": a flat bracket list NESTS
// (`interfaces -> a -> leaf Keys=["b","c"]`, pinned by
// TestZoneInterfaces6735FlatSetBracketNestsRatherThanFanning). Only the stanza's
// own Keys tail distinguishes COMPACT from `set`. `show configuration | display
// set` round-trips safely. Those are still the boot path and the
// peer-sync path.
//
// Do NOT generalize that bound to the whole defect class. The sibling #6735
// shape — a body keyword with tokens AFTER it — IS reachable from the ordinary
// `set` CLI, because SetPath collapses a bracket tail onto one NESTED leaf,
// keyword included, and the truncator then runs on that nested member. See
// TestZoneInterfaces6735FlatSetReachesThePackedTail, which pins the shape and
// the dropped member.
//
// IMPORTANT (per CLAUDE.md): flat-set syntax is built with ParseSetCommand +
// tree.SetPath in a loop, never NewParser; the hierarchical shape uses
// parseHierText (#16139 kit).

// zoneMembership6525 compiles just the zones subtree of a hierarchical config
// and returns the compiled membership for zone Z, plus the per-interface
// host-inbound override map. It targets compileZones directly so the assertion
// is on the compiled zone.Interfaces slice, independent of the full-pipeline
// strict gates.
func zoneMembership6525(t *testing.T, cfgText string) ([]string, map[string]*HostInboundTraffic) {
	t.Helper()
	tree := parseHierText(t, cfgText)
	sec := tree.FindChild("security")
	if sec == nil {
		t.Fatalf("no security node in tree for:\n%s", cfgText)
	}
	zonesNode := sec.FindChild("zones")
	if zonesNode == nil {
		t.Fatalf("no security zones node in tree for:\n%s", cfgText)
	}
	secCfg := &SecurityConfig{Zones: map[string]*ZoneConfig{}}
	if err := compileZones(zonesNode, secCfg); err != nil {
		t.Fatalf("compileZones: %v", err)
	}
	z := secCfg.Zones["Z"]
	if z == nil {
		t.Fatalf("zone Z missing after compile of:\n%s", cfgText)
	}
	return z.Interfaces, z.InterfaceHostInbound
}

// TestZoneInterfaces6525CompactLeafMatchesBlock is the primary differential and
// the primary RED-on-revert guard. For each variant the SAME membership is
// authored twice — once in the block spelling, once in the compact-leaf
// spelling — and the two compiled member sets must be equal. The expectation is
// DERIVED from the block spelling, never hardcoded, so the test cannot go
// vacuous by agreeing with a wrong constant; a `want` floor is asserted
// separately so the pair cannot both collapse to empty and still pass.
func TestZoneInterfaces6525CompactLeafMatchesBlock(t *testing.T) {
	cases := []struct {
		name  string
		block string
		leaf  string
		// wantLen is the number of members the authored config names. It
		// exists only to stop a both-empty (or both-truncated) pair from
		// passing the equality assertion vacuously — the VALUES themselves
		// come from the block spelling.
		wantLen int
	}{
		{
			name:    "single",
			block:   `interfaces { ge-0/0/1.0; }`,
			leaf:    `interfaces ge-0/0/1.0;`,
			wantLen: 1,
		},
		{
			name:    "multi",
			block:   `interfaces { ge-0/0/0.0; ge-0/0/1.0; }`,
			leaf:    `interfaces [ ge-0/0/0.0 ge-0/0/1.0 ];`,
			wantLen: 2,
		},
		{
			name:    "with-body",
			block:   `interfaces { ge-0/0/0.0 { host-inbound-traffic { system-services ssh; } } }`,
			leaf:    `interfaces ge-0/0/0.0 { host-inbound-traffic { system-services ssh; } }`,
			wantLen: 1,
		},
	}
	wrap := func(stanza string) string {
		return "security {\n    zones {\n        security-zone Z {\n            " + stanza + "\n        }\n    }\n}"
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			blockIfaces, blockHIB := zoneMembership6525(t, wrap(tc.block))
			leafIfaces, leafHIB := zoneMembership6525(t, wrap(tc.leaf))

			if len(blockIfaces) != tc.wantLen {
				t.Fatalf("block spelling %q compiled %d members %v, want %d — the differential's reference side is itself broken",
					tc.block, len(blockIfaces), blockIfaces, tc.wantLen)
			}
			if !reflect.DeepEqual(leafIfaces, blockIfaces) {
				t.Fatalf("compact-leaf %q compiled zone membership %v, but the block spelling %q compiled %v — the compact leaf must yield the SAME members (#6525)",
					tc.leaf, leafIfaces, tc.block, blockIfaces)
			}
			if !reflect.DeepEqual(hibKeys6525(leafHIB), hibKeys6525(blockHIB)) {
				t.Fatalf("compact-leaf %q scoped per-interface host-inbound to %v, but the block spelling %q scoped it to %v (#6525)",
					tc.leaf, hibKeys6525(leafHIB), tc.block, hibKeys6525(blockHIB))
			}
		})
	}
}

// TestZoneInterfaces6525CompactLeafNeverInventsMembers is the OTHER direction of
// the same defect: a fix that reads prop.Keys[1:] (or iterates prop.Children)
// without excluding the member's BODY trades a silent DROP for a silent
// INVENTION — body keywords promoted to interface names. That invention is what
// the issue measured on master for the with-body variant
// (ifaces=[host-inbound-traffic system-services ssh]).
//
// Every member of a zone must look like an interface reference; a body keyword
// must never appear. This covers both the compact-leaf body-as-CHILD shape and
// the hierarchical PACKED shape that puts the body on the member's own Keys.
func TestZoneInterfaces6525CompactLeafNeverInventsMembers(t *testing.T) {
	bodyTokens := []string{"host-inbound-traffic", "system-services", "protocols", "ssh", "ping", "ospf"}
	cases := []struct {
		name    string
		stanza  string
		want    []string
		wantHIB []string
	}{
		{
			name:    "compact-leaf body as child",
			stanza:  `interfaces ge-0/0/0.0 { host-inbound-traffic { system-services ssh; } }`,
			want:    []string{"ge-0/0/0.0"},
			wantHIB: []string{"ge-0/0/0.0"},
		},
		{
			name:    "compact-leaf bracket members with a shared body",
			stanza:  `interfaces [ ge-0/0/0.0 ge-0/0/1.0 ] { host-inbound-traffic { system-services ssh; } }`,
			want:    []string{"ge-0/0/0.0", "ge-0/0/1.0"},
			wantHIB: []string{"ge-0/0/0.0", "ge-0/0/1.0"},
		},
		{
			name:   "compact-leaf packed body on Keys",
			stanza: `interfaces ge-0/0/0.0 host-inbound-traffic system-services ssh;`,
			want:   []string{"ge-0/0/0.0"},
			// The packed body is not parsed into an override — fail-CLOSED
			// (the interface admits only what the zone level admits), the
			// residual tracked separately from #6525.
			wantHIB: nil,
		},
		{
			name:    "block packed body on the member's Keys",
			stanza:  `interfaces { ge-0/0/0.0 host-inbound-traffic system-services ssh; }`,
			want:    []string{"ge-0/0/0.0"},
			wantHIB: nil,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, hib := zoneMembership6525(t,
				"security {\n    zones {\n        security-zone Z {\n            "+tc.stanza+"\n        }\n    }\n}")
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("stanza %q compiled zone membership %v, want %v (#6525)", tc.stanza, got, tc.want)
			}
			for _, m := range got {
				for _, bad := range bodyTokens {
					if m == bad {
						t.Fatalf("stanza %q promoted body keyword %q to a zone MEMBER: %v — a silent invention (#6525)",
							tc.stanza, bad, got)
					}
				}
			}
			if !reflect.DeepEqual(hibKeys6525(hib), tc.wantHIB) {
				t.Fatalf("stanza %q scoped per-interface host-inbound to %v, want %v (#6525)",
					tc.stanza, hibKeys6525(hib), tc.wantHIB)
			}
			for _, k := range hibKeys6525(hib) {
				for _, bad := range bodyTokens {
					if k == bad {
						t.Fatalf("stanza %q keyed a per-interface host-inbound override on body keyword %q (#6525)", tc.stanza, bad)
					}
				}
			}
		})
	}
}

// TestZoneInterfaces6525OverrideStaysScopedToItsOwnMember is the #6391
// non-regression proof: a per-interface host-inbound override authored for `a`
// must NOT reach a sibling member `b`. compileZones scopes the override on the
// member node's own KEYS and never on its CHILDREN, precisely because a nested
// membership statement is not a bracket sibling of the node the body was
// authored on. The #6525 compact-leaf normalization must not collapse that
// distinction — the synthesized member node keys the override the same way.
//
// Both spellings of the ambiguous shape are checked: the hierarchical form and
// the flat-set form (`set ... interfaces [ a b ]` then
// `set ... interfaces a host-inbound-traffic ... ssh`), which is the exact
// #6389 regression config — SetPath nests `b` UNDER `a` and the second `set`
// reuses that same `a` container, so a children-inclusive fan would open ssh on
// `b`, which the operator never configured.
func TestZoneInterfaces6525OverrideStaysScopedToItsOwnMember(t *testing.T) {
	t.Run("hierarchical nested member under a body", func(t *testing.T) {
		ifaces, hib := zoneMembership6525(t, `
security {
    zones {
        security-zone Z {
            interfaces ge-0/0/0.0 {
                host-inbound-traffic {
                    system-services ssh;
                }
                ge-0/0/1.0;
            }
        }
    }
}`)
		if want := []string{"ge-0/0/0.0", "ge-0/0/1.0"}; !reflect.DeepEqual(ifaces, want) {
			t.Fatalf("zone membership = %v, want %v (both members must survive)", ifaces, want)
		}
		if got := hibKeys6525(hib); !reflect.DeepEqual(got, []string{"ge-0/0/0.0"}) {
			t.Fatalf("host-inbound override scoped to %v, want [ge-0/0/0.0] only — fanning onto the nested member ge-0/0/1.0 opens ssh the operator never configured (#6391/#6389)", got)
		}
	})

	t.Run("flat-set bracket then single-scoped override", func(t *testing.T) {
		tree := &ConfigTree{}
		for _, cmd := range []string{
			"set security zones security-zone Z interfaces [ ge-0/0/0 ge-0/0/1 ]",
			"set security zones security-zone Z interfaces ge-0/0/0 host-inbound-traffic system-services ssh",
		} {
			path, err := ParseSetCommand(cmd)
			if err != nil {
				t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
			}
			if err := tree.SetPath(path); err != nil {
				t.Fatalf("SetPath(%q): %v", cmd, err)
			}
		}
		secCfg := &SecurityConfig{Zones: map[string]*ZoneConfig{}}
		if err := compileZones(tree.FindChild("security").FindChild("zones"), secCfg); err != nil {
			t.Fatalf("compileZones: %v", err)
		}
		z := secCfg.Zones["Z"]
		if want := []string{"ge-0/0/0", "ge-0/0/1"}; !reflect.DeepEqual(z.Interfaces, want) {
			t.Fatalf("zone membership = %v, want %v (#5248)", z.Interfaces, want)
		}
		if got := hibKeys6525(z.InterfaceHostInbound); !reflect.DeepEqual(got, []string{"ge-0/0/0"}) {
			t.Fatalf("host-inbound override scoped to %v, want [ge-0/0/0] only — this is the #6389 regression config; fanning it onto ge-0/0/1 opens ssh there (admission is additive)", got)
		}
	})
}

// TestZoneInterfaces6525FlatSetNeverReachesCompactLeaf pins the reachability
// bound this fix is documented under: no `set`-authored config can produce the
// compact-leaf shape. SetPath descends the `interfaces` wildcard and puts the
// members BELOW it, so the stanza node's Keys are always exactly ["interfaces"]
// — which is the only property this test asserts, and the only one the
// normalization depends on. It deliberately says nothing about how the members
// are ARRANGED below the stanza: a flat bracket list nests them into a chain
// rather than fanning them out one per child
// (TestZoneInterfaces6735FlatSetBracketNestsRatherThanFanning). If the stanza
// Keys assumption ever changes, the normalization's premise (a Keys tail means
// the compact-leaf hierarchical shape) needs re-checking.
func TestZoneInterfaces6525FlatSetNeverReachesCompactLeaf(t *testing.T) {
	for _, cmd := range []string{
		"set security zones security-zone Z interfaces ge-0/0/0",
		"set security zones security-zone Z interfaces [ ge-0/0/0 ge-0/0/1 ]",
		"set security zones security-zone Z interfaces ge-0/0/0 host-inbound-traffic system-services ssh",
	} {
		t.Run(cmd, func(t *testing.T) {
			tree := &ConfigTree{}
			path, err := ParseSetCommand(cmd)
			if err != nil {
				t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
			}
			if err := tree.SetPath(path); err != nil {
				t.Fatalf("SetPath(%q): %v", cmd, err)
			}
			zonesNode := tree.FindChild("security").FindChild("zones")
			// The Keys assertion below lives inside two filtered loops, so if
			// SetPath ever stops emitting an `interfaces` property the loop body
			// never runs and this test passes having asserted NOTHING. Count the
			// stanzas actually examined and require at least one.
			examined := 0
			for _, inst := range namedInstances(zonesNode.FindChildren("security-zone")) {
				for _, prop := range inst.node.Children {
					if prop.Name() != "interfaces" {
						continue
					}
					examined++
					if len(prop.Keys) != 1 {
						t.Fatalf("flat-set %q produced an `interfaces` stanza with Keys=%v; the compact-leaf shape was believed unreachable from `set`", cmd, prop.Keys)
					}
				}
			}
			if examined == 0 {
				t.Fatalf("flat-set %q produced NO `interfaces` stanza to examine; this test asserted nothing — either SetPath changed shape or the config path is wrong", cmd)
			}
		})
	}
}

// TestZoneInterfaces6525EmptyStanzaRejected is the fail-closed belt
// (validateZoneInterfacesNonEmptyStrict): an `interfaces` stanza that CARRIES
// CONTENT but names no interface must be REJECTED at commit rather than
// compiling a zone with an empty member set that both zone gates then walk
// vacuously.
func TestZoneInterfaces6525EmptyStanzaRejected(t *testing.T) {
	cases := []struct {
		name   string
		stanza string
	}{
		{
			name:   "member spelled as the body keyword",
			stanza: `interfaces host-inbound-traffic;`,
		},
		{
			name:   "stanza holding only a body block",
			stanza: `interfaces { host-inbound-traffic { system-services ssh; } }`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tree := parseHierText(t, `
interfaces {
    ge-0/0/0 {
        unit 0 {
            family inet {
                address 10.0.0.1/24;
            }
        }
    }
}
security {
    zones {
        security-zone Z {
            `+tc.stanza+`
        }
    }
}`)
			_, err := CompileConfig(tree)
			if err == nil {
				t.Fatalf("CompileConfig accepted a zone whose `interfaces` stanza (%s) names no interface; want a strict reject so the empty member set cannot ship silently (#6525)", tc.stanza)
			}
			if !strings.Contains(err.Error(), "names no interface") {
				t.Fatalf("reject error %q is not the #6525 non-empty gate", err.Error())
			}
			if !strings.Contains(err.Error(), `"Z"`) {
				t.Fatalf("reject error %q does not name the offending zone Z", err.Error())
			}
		})
	}

	// POSITIVE CONTROL. Without it this test cannot distinguish "rejects a
	// stanza that names no interface" from "rejects every stanza": a
	// zoneInterfaceStanzaMembers that always returned nil would make EVERY
	// stanza look empty and the reject table above would still pass, green and
	// meaningless. Measured — that mutation builds clean, vets clean, and this
	// test passed under it before this subtest existed.
	t.Run("positive control: a stanza that names an interface still compiles", func(t *testing.T) {
		for _, stanza := range []string{
			`interfaces ge-0/0/0.0;`,
			`interfaces { ge-0/0/0.0; }`,
			`interfaces [ ge-0/0/0.0 ge-0/0/1.0 ];`,
		} {
			t.Run(stanza, func(t *testing.T) {
				tree := parseHierText(t, `
interfaces {
    ge-0/0/0 {
        unit 0 {
            family inet {
                address 10.0.0.1/24;
            }
        }
    }
    ge-0/0/1 {
        unit 0 {
            family inet {
                address 10.0.1.1/24;
            }
        }
    }
}
security {
    zones {
        security-zone Z {
            `+stanza+`
        }
    }
}`)
				cfg, err := CompileConfig(tree)
				if err != nil {
					t.Fatalf("CompileConfig rejected %q, which names a defined interface: %v — the non-empty gate must fire only on a stanza that contributes NO members (#6525/#4191)", stanza, err)
				}
				if got := cfg.Security.Zones["Z"].Interfaces; len(got) == 0 {
					t.Fatalf("stanza %q compiled to an EMPTY member set without erroring — the gate is reading a different member set than the compiler", stanza)
				}
			})
		}
	})
}

// TestZoneInterfaces6525VacuousStanzaAccepted is the over-rejection control for
// the gate above, and the reason it is content-sensitive rather than a blanket
// "declared but empty" check. `delete security zones security-zone <z>
// interfaces <if>` of the LAST member leaves the now-empty `interfaces`
// container behind (deletePath removes the member node but does not prune the
// container), and a bare hand-authored `interfaces;` parses to the same shape.
// Neither declares a member, so neither can lose one — rejecting them would make
// an ordinary "remove the last interface from this zone" edit uncommittable
// against a stanza that renders invisibly (the #4191 over-rejection class).
func TestZoneInterfaces6525VacuousStanzaAccepted(t *testing.T) {
	t.Run("delete of the last member", func(t *testing.T) {
		tree := &ConfigTree{}
		for _, cmd := range []string{
			"set interfaces ge-0/0/0 unit 0 family inet address 10.0.0.1/24",
			"set security zones security-zone Z interfaces ge-0/0/0",
		} {
			path, err := ParseSetCommand(cmd)
			if err != nil {
				t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
			}
			if err := tree.SetPath(path); err != nil {
				t.Fatalf("SetPath(%q): %v", cmd, err)
			}
		}
		del, err := ParseSetCommand("set security zones security-zone Z interfaces ge-0/0/0")
		if err != nil {
			t.Fatalf("ParseSetCommand(delete): %v", err)
		}
		if err := tree.DeletePath(del); err != nil {
			t.Fatalf("DeletePath: %v", err)
		}
		// Guard the premise: the empty container really is left behind. If
		// delete ever starts pruning it, this control is testing nothing.
		zonesNode := tree.FindChild("security").FindChild("zones")
		found := false
		for _, inst := range namedInstances(zonesNode.FindChildren("security-zone")) {
			for _, prop := range inst.node.Children {
				if prop.Name() == "interfaces" {
					found = true
					if len(prop.Keys) != 1 || len(prop.Children) != 0 {
						t.Fatalf("premise broken: post-delete `interfaces` stanza is Keys=%v children=%d, expected a bare empty container", prop.Keys, len(prop.Children))
					}
				}
			}
		}
		if !found {
			t.Skip("delete now prunes the empty `interfaces` container; the over-rejection control is moot")
		}
		if _, err := CompileConfig(tree); err != nil {
			t.Fatalf("CompileConfig rejected a config whose zone lost its last interface via `delete`: %v — the non-empty gate must not fire on a stanza that declares nothing (#4191 over-rejection class)", err)
		}
	})

	t.Run("bare hierarchical interfaces stanza", func(t *testing.T) {
		tree := parseHierText(t, `
interfaces {
    ge-0/0/0 {
        unit 0 {
            family inet {
                address 10.0.0.1/24;
            }
        }
    }
}
security {
    zones {
        security-zone Z {
            interfaces;
        }
    }
}`)
		if _, err := CompileConfig(tree); err != nil {
			t.Fatalf("CompileConfig rejected a bare `interfaces;` stanza: %v — it declares no member, so it cannot have lost one (#6525)", err)
		}
	})
}

// TestZoneInterfaces6525StrictGatesNoLongerVacuous drives the FULL CompileConfig
// pipeline and proves the two strict zone gates actually SEE a compact-leaf
// membership now. Before the fix each of these compiled clean because the member
// never reached zone.Interfaces at all.
func TestZoneInterfaces6525StrictGatesNoLongerVacuous(t *testing.T) {
	t.Run("undefined member reaches the defined gate", func(t *testing.T) {
		tree := parseHierText(t, `
interfaces {
    ge-0/0/0 {
        unit 0 {
            family inet {
                address 10.0.0.1/24;
            }
        }
    }
}
security {
    zones {
        security-zone Z {
            interfaces ge-0/0/9.0;
        }
    }
}`)
		_, err := CompileConfig(tree)
		if err == nil {
			t.Fatalf("CompileConfig accepted a compact-leaf zone member naming an UNDEFINED interface; the strict zone-interface-defined gate passed vacuously over an empty member set (#6525)")
		}
		if !strings.Contains(err.Error(), "ge-0/0/9.0") {
			t.Fatalf("reject error %q does not name the undefined member ge-0/0/9.0", err.Error())
		}
	})

	t.Run("duplicate assignment reaches the membership gate", func(t *testing.T) {
		tree := parseHierText(t, `
interfaces {
    ge-0/0/0 {
        unit 0 {
            family inet {
                address 10.0.0.1/24;
            }
        }
    }
}
security {
    zones {
        security-zone A {
            interfaces ge-0/0/0.0;
        }
        security-zone B {
            interfaces ge-0/0/0.0;
        }
    }
}`)
		_, err := CompileConfig(tree)
		if err == nil {
			t.Fatalf("CompileConfig accepted the same interface in TWO zones via the compact-leaf spelling; the strict zone-interface-membership gate passed vacuously over an empty member set (#6525)")
		}
		if !strings.Contains(err.Error(), "exactly one security zone") {
			t.Fatalf("reject error %q is not the zone-interface-membership gate", err.Error())
		}
	})

	t.Run("member survives end to end", func(t *testing.T) {
		tree := parseHierText(t, `
interfaces {
    ge-0/0/0 {
        unit 0 {
            family inet {
                address 10.0.0.1/24;
            }
        }
    }
    ge-0/0/1 {
        unit 0 {
            family inet {
                address 10.0.1.1/24;
            }
        }
    }
}
security {
    zones {
        security-zone Z {
            interfaces [ ge-0/0/0.0 ge-0/0/1.0 ];
        }
    }
}`)
		cfg, err := CompileConfig(tree)
		if err != nil {
			t.Fatalf("CompileConfig: %v", err)
		}
		want := []string{"ge-0/0/0.0", "ge-0/0/1.0"}
		if got := cfg.Security.Zones["Z"].Interfaces; !reflect.DeepEqual(got, want) {
			t.Fatalf("zone Z interfaces = %v, want %v (#6525)", got, want)
		}
	})
}

// TestZoneInterfaces6525LenientPathWarnsInsteadOfRejecting pins the #1960
// no-brick side of the strict/lenient split: on the tolerant load / peer-sync
// path the non-empty gate must DOWNGRADE to a cfg.Warnings entry so an
// already-persisted or peer-synced config an older binary accepted still BOOTS.
func TestZoneInterfaces6525LenientPathWarnsInsteadOfRejecting(t *testing.T) {
	tree := parseHierText(t, `
interfaces {
    ge-0/0/0 {
        unit 0 {
            family inet {
                address 10.0.0.1/24;
            }
        }
    }
}
security {
    zones {
        security-zone Z {
            interfaces host-inbound-traffic;
        }
    }
}`)
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("CompileConfigLenient rejected a config the tolerant path must still BOOT (#1960): %v", err)
	}
	var found bool
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "zone interfaces non-empty") {
			found = true
		}
	}
	if !found {
		t.Fatalf("tolerant path produced no `zone interfaces non-empty` warning; warnings = %v", cfg.Warnings)
	}
}

// hibKeys6525 returns the sorted interface refs a per-interface host-inbound
// map is keyed on, so a scope assertion reads as a set comparison.
func hibKeys6525(m map[string]*HostInboundTraffic) []string {
	if len(m) == 0 {
		return nil
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
