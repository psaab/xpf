package config

import (
	"sort"
	"testing"
)

// #14966 (D29-01): two defects in the #14444 groupReplace port-leaf
// handling silently dropped group-inherited ports:
//
//  1. groupReplacePortLeaves14444 enumerated only family inet/inet6.
//     The `family any` tree (#9017) is a deep copy with distinct
//     schema pointers, and the implicit `firewall filter` tree
//     (#9899) is another copy, so isGroupReplacePortLeaf14444 was
//     false there and a range-free group block beside an inline block
//     took OVERRIDE instead of UNION.
//
//  2. groupReplaceBlockCarriesRange14444 treated ANY child with
//     len(Keys)>1 as a range. A discrete multi-token child
//     (`destination-port { 80 443; }`) packs two plain members into
//     one child leaf, so it was misclassified as a range and the
//     group members were dropped. A `to` range also packs into one
//     child (`{ 1000 to 2000; }`) and must still count as a range.

func hier14966(t *testing.T, famPrefix, groupBody, inlineBody, kw string) *ConfigTree {
	t.Helper()
	famOpen, famClose := "", ""
	if famPrefix != "" {
		famOpen = "family " + famPrefix + " {"
		famClose = "}"
	}
	text := `
groups {
    G {
        firewall {
            ` + famOpen + `
                filter F {
                    term T1 {
                        from {
                            ` + groupBody + `
                        }
                        then accept;
                    }
                }
            ` + famClose + `
        }
    }
}
firewall {
    ` + famOpen + `
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
    ` + famClose + `
}
`
	_ = kw
	tree := parseHierarchical(t, text)
	if err := tree.ExpandGroups(); err != nil {
		t.Fatalf("ExpandGroups: %v", err)
	}
	return tree
}

func compiledPorts14966(t *testing.T, tree *ConfigTree, fam, kw string) []string {
	t.Helper()
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	var filters map[string]*FirewallFilter
	switch fam {
	case "inet", "implicit":
		filters = cfg.Firewall.FiltersInet
	case "inet6":
		filters = cfg.Firewall.FiltersInet6
	case "any-inet":
		// caller checks both maps separately; not used here
		t.Fatalf("use both-family helper")
	}
	f := filters["F"]
	if f == nil {
		t.Fatalf("filter F not compiled for %s (filters=%v)", fam, filters)
	}
	for _, term := range f.Terms {
		if term.Name == "T1" {
			switch kw {
			case "destination-port":
				return append([]string(nil), term.DestinationPorts...)
			case "source-port":
				return append([]string(nil), term.SourcePorts...)
			case "destination-port-except":
				return append([]string(nil), term.DestPortsExcept...)
			case "source-port-except":
				return append([]string(nil), term.SourcePortsExcept...)
			}
		}
	}
	t.Fatalf("term T1 not found")
	return nil
}

func assertSet14966(t *testing.T, what string, got, want []string) {
	t.Helper()
	g := append([]string(nil), got...)
	w := append([]string(nil), want...)
	sort.Strings(g)
	sort.Strings(w)
	if len(g) != len(w) {
		t.Fatalf("%s: got %v, want %v", what, got, want)
	}
	for i := range w {
		if g[i] != w[i] {
			t.Fatalf("%s: got %v, want %v", what, got, want)
		}
	}
}

// Family `any` (and the implicit filter tree) must union a range-free
// group block beside an inline block, exactly like inet/inet6.
func TestGroupReplaceAnyAndImplicitRangeFreeUnion14966(t *testing.T) {
	for _, fam := range []string{"any", ""} {
		label := fam
		if label == "" {
			label = "implicit"
		}
		tree := hier14966(t, fam, "destination-port { 443; }", "destination-port { 80; }", "destination-port")
		if fam == "any" {
			// `any` compiles to both families; check both.
			for _, m := range []string{"inet", "inet6"} {
				assertSet14966(t, label+"/"+m+" range-free union", compiledPorts14966(t, tree, m, "destination-port"), []string{"80", "443"})
			}
		} else {
			assertSet14966(t, label+" range-free union", compiledPorts14966(t, tree, "implicit", "destination-port"), []string{"80", "443"})
		}
		// Control: a range on the group side still overrides under `any`/implicit.
		treeRange := hier14966(t, fam, "destination-port { 1000-2000; }", "destination-port { 80; }", "destination-port")
		checkFam := fam
		if checkFam == "" {
			checkFam = "implicit"
		}
		if fam == "any" {
			assertSet14966(t, "any/inet range override", compiledPorts14966(t, treeRange, "inet", "destination-port"), []string{"80"})
		} else {
			assertSet14966(t, label+" range override", compiledPorts14966(t, treeRange, checkFam, "destination-port"), []string{"80"})
		}
	}
	// Controls: inet/inet6 range-free union stays green.
	for _, fam := range []string{"inet", "inet6"} {
		tree := hier14966(t, fam, "destination-port { 443; }", "destination-port { 80; }", "destination-port")
		assertSet14966(t, fam+" control union", compiledPorts14966(t, tree, fam, "destination-port"), []string{"80", "443"})
	}
}

// Except leaves under `any` carry the fail-open risk (a lost exclusion
// lets discard-scoped traffic escape), so pin them too.
func TestGroupReplaceAnyExceptRangeFreeUnion14966(t *testing.T) {
	tree := hier14966(t, "any", "destination-port-except { 443; }", "destination-port-except { 80; }", "destination-port-except")
	assertSet14966(t, "any except union inet", compiledPorts14966(t, tree, "inet", "destination-port-except"), []string{"80", "443"})
	assertSet14966(t, "any except union inet6", compiledPorts14966(t, tree, "inet6", "destination-port-except"), []string{"80", "443"})
}

// A discrete multi-token child (`{ 80 443; }`) is two plain members,
// not a range: it must union on either side, in every family spelling.
func TestGroupReplaceDiscreteMultiTokenUnion14966(t *testing.T) {
	for _, fam := range []string{"inet", "any", ""} {
		label := fam
		if label == "" {
			label = "implicit"
		}
		checkFam := fam
		if checkFam == "" {
			checkFam = "implicit"
		}
		if fam == "any" {
			checkFam = "inet"
		}
		// Group side discrete multi-token.
		tree := hier14966(t, fam, "destination-port { 80 443; }", "destination-port { 8443; }", "destination-port")
		assertSet14966(t, label+" group discrete multi-token union", compiledPorts14966(t, tree, checkFam, "destination-port"), []string{"80", "443", "8443"})
		// Inline side discrete multi-token.
		tree2 := hier14966(t, fam, "destination-port { 8443; }", "destination-port { 80 443; }", "destination-port")
		assertSet14966(t, label+" inline discrete multi-token union", compiledPorts14966(t, tree2, checkFam, "destination-port"), []string{"80", "443", "8443"})
		// Control: a genuine `to` range packed into one child still overrides.
		tree3 := hier14966(t, fam, "destination-port { 1000 to 2000; }", "destination-port { 80; }", "destination-port")
		// Assert at merge level: strict compile rejects a bare `to` token
		// as an unknown port regardless of the merge (see #14444 test).
		nodes := findNodesByKey(tree3.Children, "destination-port")
		found := false
		for _, n := range nodes {
			vals := firewallMatchValues(n)
			for _, v := range vals {
				if v == "80" {
					found = true
					assertSet14966(t, label+" to-range override (merge level)", vals, []string{"80"})
				}
			}
		}
		if !found {
			t.Fatalf("%s: inline 80 node not found in %v", label, nodes)
		}
	}
}
