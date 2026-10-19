package config

import (
	"sort"
	"testing"
)

// #14444 (DR18-H9): mergeNodes container branch ignored groupReplace/range
// on block/block pairs. A single-key group block whose schema leaf is
// groupReplace (firewall ports, NAT match ports, NAT pool address,
// community, as-path-prepend) fell through to the generic container
// child-merge, which adopted group members beside inline members —
// a UNION even for ranges. The leaf path for the same statement drops
// the group value (inline wins). The container branch must take the
// same decision, refined per DR16-H1 for ports: union iff neither side
// carries a range (hyphen "1000-2000" or "to" separator), override
// otherwise; non-port groupReplace leaves override unconditionally.
//
// Fixtures use hierarchical text (NewParser) so both sides are authored
// in BLOCK shape: destination-port { ...; }.

// blockFilterTree14444Family builds the #14444 fixture under an explicit
// firewall family spelling. blockFilterTree14444 is the inet instance.
func blockFilterTree14444Family(t *testing.T, family, groupBody, inlineBody string) *ConfigTree {
	t.Helper()
	text := `
groups {
    G {
        firewall {
            family ` + family + ` {
                filter F {
                    term T1 {
                        from {
                            ` + groupBody + `
                        }
                        then accept;
                    }
                }
            }
        }
    }
}
firewall {
    family ` + family + ` {
        filter F {
            term T1 {
                apply-groups G;
                from {
                    ` + inlineBody + `
                }
                then accept;
            }
            term T2 {
                from {
                    destination-port { 1000-2000; }
                }
                then discard;
            }
        }
    }
}
`
	tree := parseHierarchical(t, text)
	if err := tree.ExpandGroups(); err != nil {
		t.Fatalf("ExpandGroups: %v", err)
	}
	return tree
}

func blockFilterTree14444(t *testing.T, groupBody, inlineBody string) *ConfigTree {
	t.Helper()
	return blockFilterTree14444Family(t, "inet", groupBody, inlineBody)
}

// compiledTerm14444Family returns term name from the compiled pool for
// family: inet/implicit read FiltersInet, inet6 reads FiltersInet6, and
// any reads FiltersInet (its IPv6 arm is checked separately where needed).
func compiledTerm14444Family(t *testing.T, tree *ConfigTree, family, name string) *FirewallFilterTerm {
	t.Helper()
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	var filters map[string]*FirewallFilter
	switch family {
	case "inet6":
		filters = cfg.Firewall.FiltersInet6
	default:
		filters = cfg.Firewall.FiltersInet
	}
	f := filters["F"]
	if f == nil {
		t.Fatalf("filter F not compiled for family %s", family)
	}
	for _, term := range f.Terms {
		if term.Name == name {
			return term
		}
	}
	t.Fatalf("term %s not found in %v", name, f.Terms)
	return nil
}

func compiledTerm14444(t *testing.T, tree *ConfigTree, name string) *FirewallFilterTerm {
	t.Helper()
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	f := cfg.Firewall.FiltersInet["F"]
	if f == nil {
		t.Fatalf("filter F not compiled")
	}
	for _, term := range f.Terms {
		if term.Name == name {
			return term
		}
	}
	t.Fatalf("term %s not found in %v", name, f.Terms)
	return nil
}

func sortedCopy14444(in []string) []string {
	out := append([]string(nil), in...)
	sort.Strings(out)
	return out
}

func assertPorts14444(t *testing.T, what string, got, want []string) {
	t.Helper()
	g, w := sortedCopy14444(got), sortedCopy14444(want)
	if len(g) != len(w) {
		t.Fatalf("%s: got %v, want %v", what, got, want)
	}
	for i := range w {
		if g[i] != w[i] {
			t.Fatalf("%s: got %v, want %v", what, got, want)
		}
	}
}

// Headline: block/block hyphen-range pair must compile to OVERRIDE.
func TestGroupReplaceBlockHyphenRangeOverrides14444(t *testing.T) {
	tree := blockFilterTree14444(t,
		"destination-port { 1000-2000; }",
		"destination-port { 3000-4000; }")
	term := compiledTerm14444(t, tree, "T1")
	assertPorts14444(t, "block/block hyphen range override", term.DestinationPorts, []string{"3000-4000"})
}

// Range on inline side only also overrides.
func TestGroupReplaceBlockInlineRangeOverrides14444(t *testing.T) {
	tree := blockFilterTree14444(t,
		"destination-port { 443; }",
		"destination-port { 3000-4000; }")
	term := compiledTerm14444(t, tree, "T1")
	assertPorts14444(t, "inline range overrides group member", term.DestinationPorts, []string{"3000-4000"})
}

// Range on group side only also overrides.
func TestGroupReplaceBlockGroupRangeOverrides14444(t *testing.T) {
	tree := blockFilterTree14444(t,
		"destination-port { 1000-2000; }",
		"destination-port { 80; }")
	term := compiledTerm14444(t, tree, "T1")
	assertPorts14444(t, "group range overridden by inline member", term.DestinationPorts, []string{"80"})
}

// "to" separator range in block shape also overrides. Asserted at merge
// level: strict compile rejects a bare "to" token as an unknown port
// regardless of the merge, so the compiled-port assertion cannot run.
func TestGroupReplaceBlockToRangeOverrides14444(t *testing.T) {
	tree := blockFilterTree14444(t,
		"destination-port { 1000 to 2000; }",
		"destination-port { 3000 to 4000; }")
	nodes := findNodesByKey(tree.Children, "destination-port")
	// T1 merged node + T2 node = 2; T1 must carry only the inline range.
	found := false
	for _, n := range nodes {
		vals := firewallMatchValues(n)
		for _, v := range vals {
			if v == "3000" {
				found = true
				assertMembers(t, "to-range block override", vals, []string{"3000", "to", "4000"})
			}
		}
	}
	if !found {
		t.Fatalf("inline to-range node not found in %s", describeNodes(nodes))
	}
}
func TestGroupReplaceBlockRangeFreeUnions14444(t *testing.T) {
	tree := blockFilterTree14444(t,
		"destination-port { 443; }",
		"destination-port { 80; }")
	term := compiledTerm14444(t, tree, "T1")
	assertPorts14444(t, "block/block range-free union", term.DestinationPorts, []string{"80", "443"})
}

// Source-NAT match destination-port block/block: hyphen range overrides,
// range-free unions (same port-leaf decision at the NAT match path).
// Asserted at merge level on the single destination-port node.
func TestGroupReplaceBlockNATMatchPort14444(t *testing.T) {
	build := func(groupPort, inlinePort string) []string {
		text := `
groups {
    G {
        security {
            nat {
                source {
                    rule-set RS {
                        rule R {
                            match {
                                destination-port { ` + groupPort + `; }
                            }
                        }
                    }
                }
            }
        }
    }
}
security {
    nat {
        source {
            rule-set RS {
                rule R {
                    apply-groups G;
                    match {
                        destination-port { ` + inlinePort + `; }
                    }
                }
            }
        }
    }
}
`
		tree := parseHierarchical(t, text)
		if err := tree.ExpandGroups(); err != nil {
			t.Fatalf("ExpandGroups: %v", err)
		}
		nodes := findNodesByKey(tree.Children, "destination-port")
		if len(nodes) != 1 {
			t.Fatalf("NAT destination-port must be ONE node, got %d: %s", len(nodes), describeNodes(nodes))
		}
		return firewallMatchValues(nodes[0])
	}
	assertMembers(t, "NAT match hyphen range override", build("1000-2000", "3000-4000"), []string{"3000-4000"})
	assertMembers(t, "NAT match range-free union", build("443", "80"), []string{"80", "443"})
}

// NAT source pool address block/block overrides unconditionally
// (non-port groupReplace; range token "to" packed as members).
func TestGroupReplaceBlockNATPoolAddress14444(t *testing.T) {
	text := `
groups {
    G {
        security {
            nat {
                source {
                    pool P {
                        address { 10.0.0.9/32; }
                    }
                }
            }
        }
    }
}
security {
    nat {
        source {
            pool P {
                apply-groups G;
                address { 10.0.0.1/32; }
            }
        }
    }
}
`
	tree := parseHierarchical(t, text)
	if err := tree.ExpandGroups(); err != nil {
		t.Fatalf("ExpandGroups: %v", err)
	}
	nodes := findNodesByKey(tree.Children, "address")
	if len(nodes) != 1 {
		t.Fatalf("pool address must be ONE node, got %d: %s", len(nodes), describeNodes(nodes))
	}
	assertMembers(t, "pool address block override", firewallMatchValues(nodes[0]), []string{"10.0.0.1/32"})
}

// Community range-free block/block still overrides (non-port
// groupReplace is unconditional — no range-free union exception).
func TestGroupReplaceBlockCommunityRangeFreeOverrides14444(t *testing.T) {
	// Covered by TestGroupReplaceBlockCommunityOverrides14444 (add values
	// are range-free); this cell pins a bare-value pair.
	text := `
groups {
    G {
        policy-options {
            policy-statement P {
                term t1 {
                    then {
                        community { 65000:100; }
                    }
                }
            }
        }
    }
}
policy-options {
    policy-statement P {
        term t1 {
            apply-groups G;
            then {
                community { 65000:200; }
            }
        }
        term t2 {
            then accept;
        }
    }
}
`
	tree := parseHierarchical(t, text)
	if err := tree.ExpandGroups(); err != nil {
		t.Fatalf("ExpandGroups: %v", err)
	}
	comms := findNodesByKey(tree.Children, "community")
	if len(comms) != 1 {
		t.Fatalf("community override must yield ONE node, got %d: %s", len(comms), describeNodes(comms))
	}
	assertMembers(t, "community bare block override", firewallMatchValues(comms[0]), []string{"65000:200"})
}

// Except hyphen-range: override, not union.
func TestGroupReplaceBlockExceptRangeOverrides14444(t *testing.T) {
	text := `
groups {
    G {
        firewall {
            family inet {
                filter F {
                    term T1 {
                        from {
                            destination-port-except { 1000-2000; }
                        }
                        then discard;
                    }
                }
            }
        }
    }
}
firewall {
    family inet {
        filter F {
            term T1 {
                apply-groups G;
                from {
                    destination-port-except { 80; }
                }
                then discard;
            }
        }
    }
}
`
	tree := parseHierarchical(t, text)
	if err := tree.ExpandGroups(); err != nil {
		t.Fatalf("ExpandGroups: %v", err)
	}
	term := compiledTerm14444(t, tree, "T1")
	assertPorts14444(t, "except hyphen range override", term.DestPortsExcept, []string{"80"})
}

// Except range-free union control.
func TestGroupReplaceBlockExceptRangeFreeUnions14444(t *testing.T) {
	text := `
groups {
    G {
        firewall {
            family inet {
                filter F {
                    term T1 {
                        from {
                            destination-port-except { 443; }
                        }
                        then discard;
                    }
                }
            }
        }
    }
}
firewall {
    family inet {
        filter F {
            term T1 {
                apply-groups G;
                from {
                    destination-port-except { 80; }
                }
                then discard;
            }
        }
    }
}
`
	tree := parseHierarchical(t, text)
	if err := tree.ExpandGroups(); err != nil {
		t.Fatalf("ExpandGroups: %v", err)
	}
	term := compiledTerm14444(t, tree, "T1")
	assertPorts14444(t, "except range-free union", term.DestPortsExcept, []string{"80", "443"})
}

// Empty inline block wins: group block dropped, not adopted beside.
// Asserted at merge level (strict compile rejects an empty port leaf
// as match-any regardless of the merge).
func TestGroupReplaceBlockEmptyInlineOverrides14444(t *testing.T) {
	tree := blockFilterTree14444(t,
		"destination-port { 1000-2000; }",
		"destination-port { }")
	// Walk to T1 and inspect its destination-port node.
	var t1Ports []string
	var walk func(nodes []*Node, inT1 bool)
	walk = func(nodes []*Node, inT1 bool) {
		for _, n := range nodes {
			here := inT1 || (len(n.Keys) >= 2 && n.Keys[0] == "term" && n.Keys[1] == "T1")
			if here && len(n.Keys) > 0 && n.Keys[0] == "destination-port" {
				t1Ports = firewallMatchValues(n)
			}
			walk(n.Children, here)
		}
	}
	walk(tree.Children, false)
	if len(t1Ports) != 0 {
		t.Fatalf("empty inline block override: group range leaked into T1, got %v", t1Ports)
	}
}

// No inline peer: group block adopted wholesale (inheritance unchanged).
func TestGroupReplaceBlockNoPeerAdopts14444(t *testing.T) {
	text := `
groups {
    G {
        firewall {
            family inet {
                filter F {
                    term T1 {
                        from {
                            destination-port { 1000-2000; }
                        }
                        then accept;
                    }
                }
            }
        }
    }
}
firewall {
    family inet {
        filter F {
            term T1 {
                apply-groups G;
                then accept;
            }
        }
    }
}
`
	tree := parseHierarchical(t, text)
	if err := tree.ExpandGroups(); err != nil {
		t.Fatalf("ExpandGroups: %v", err)
	}
	term := compiledTerm14444(t, tree, "T1")
	assertPorts14444(t, "no-peer adoption", term.DestinationPorts, []string{"1000-2000"})
}

// Non-port groupReplace (community) block/block overrides unconditionally,
// even range-free.
func TestGroupReplaceBlockCommunityOverrides14444(t *testing.T) {
	text := `
groups {
    G {
        policy-options {
            policy-statement P {
                term t1 {
                    then {
                        community { add 65000:100; }
                    }
                }
            }
        }
    }
}
policy-options {
    policy-statement P {
        term t1 {
            apply-groups G;
            then {
                community { add 65000:200; }
            }
        }
        term t2 {
            then accept;
        }
    }
}
`
	tree := parseHierarchical(t, text)
	if err := tree.ExpandGroups(); err != nil {
		t.Fatalf("ExpandGroups: %v", err)
	}
	comms := findNodesByKey(tree.Children, "community")
	if len(comms) != 1 {
		t.Fatalf("community override must yield ONE node, got %d: %s", len(comms), describeNodes(comms))
	}
	assertMembers(t, "community block override", firewallMatchValues(comms[0]), []string{"add", "65000:200"})
}

// Two-group fan-in: G1 adopted, G2 ranged block merges against G1 as peer.
func TestGroupReplaceBlockTwoGroupRangeOverrides14444(t *testing.T) {
	text := `
groups {
    G1 {
        firewall {
            family inet {
                filter F {
                    term T1 {
                        from {
                            destination-port { 3000-4000; }
                        }
                        then accept;
                    }
                }
            }
        }
    }
    G2 {
        firewall {
            family inet {
                filter F {
                    term T1 {
                        from {
                            destination-port { 1000-2000; }
                        }
                        then accept;
                    }
                }
            }
        }
    }
}
firewall {
    family inet {
        filter F {
            term T1 {
                apply-groups [ G1 G2 ];
                then accept;
            }
        }
    }
}
`
	tree := parseHierarchical(t, text)
	if err := tree.ExpandGroups(); err != nil {
		t.Fatalf("ExpandGroups: %v", err)
	}
	term := compiledTerm14444(t, tree, "T1")
	// First adopted group (G1) stands as peer; G2 range must not union.
	assertPorts14444(t, "two-group range override", term.DestinationPorts, []string{"3000-4000"})
}

// #15030 (A02-02): the #14444 pointer registry must cover `family any`.
// The any tree is a #9017 deep copy with distinct schema pointers, so a
// block-shaped apply-groups port member beside an inline block must union
// range-free ([80 443] on both compiled arms) instead of taking OVERRIDE
// and dropping the inherited port from the discard-adjacent term. These
// cells live in this file per the #15030 fix direction; the #14966 file
// covers the same mechanism with its own fixture.
func TestGroupReplaceBlockAnyFamilyRangeFreeUnions15030(t *testing.T) {
	for _, kw := range []string{"destination-port", "source-port", "destination-port-except", "source-port-except"} {
		tree := blockFilterTree14444Family(t, "any", kw+" { 443; }", kw+" { 80; }")
		for _, fam := range []string{"inet", "inet6"} {
			term := compiledTerm14444Family(t, tree, fam, "T1")
			var got []string
			switch kw {
			case "destination-port":
				got = term.DestinationPorts
			case "source-port":
				got = term.SourcePorts
			case "destination-port-except":
				got = term.DestPortsExcept
			case "source-port-except":
				got = term.SourcePortsExcept
			}
			assertPorts14444(t, "family any/"+fam+" "+kw+" range-free union", got, []string{"80", "443"})
		}
	}
}

// Control: a range on either side under `family any` still overrides.
func TestGroupReplaceBlockAnyFamilyRangeOverrides15030(t *testing.T) {
	tree := blockFilterTree14444Family(t, "any",
		"destination-port { 1000-2000; }", "destination-port { 80; }")
	assertPorts14444(t, "family any group range override (inet arm)",
		compiledTerm14444Family(t, tree, "inet", "T1").DestinationPorts, []string{"80"})
	assertPorts14444(t, "family any group range override (inet6 arm)",
		compiledTerm14444Family(t, tree, "inet6", "T1").DestinationPorts, []string{"80"})
	tree2 := blockFilterTree14444Family(t, "any",
		"destination-port { 443; }", "destination-port { 3000-4000; }")
	assertPorts14444(t, "family any inline range override (inet arm)",
		compiledTerm14444Family(t, tree2, "inet", "T1").DestinationPorts, []string{"3000-4000"})
}
