package config

import (
	"sort"
	"strings"
	"testing"
)

// #14423 (DR16-H1): the firewall-filter and NAT `match` port leaves
// (destination-port, source-port, destination-port-except,
// source-port-except) are schema `args:1, multi:true, groupReplace:true`.
// The groupReplace flag exists to keep a RANGE (`1000 to 2000`) or an
// operation keyword from being token-merged, but isLeafListSchema's
// `!groupReplace` gate made leafListUnionEligible unreachable for these
// leaves, so a range-free group member beside an inline peer was dropped
// by the `continue` in mergeNodes instead of being unioned:
//
//	inline destination-port 80 + group destination-port 443
//	  compiled to match {80} only — port 443 fell through a `then discard`
//	  term (fail-open), and for `*-except` the group exclusion was lost.
//
// The fix unions ONLY when neither side carries a range/operation token
// (the repo already owns that discriminator, leafListCarriesRange);
// range-bearing values and the other groupReplace leaves
// (`then community`, `then as-path-prepend`) keep inline-wins override.
//
// RED on base: every range-free cell below yields only the inline member.

func expandHier14423(t *testing.T, src string) *ConfigTree {
	t.Helper()
	tree, errs := NewParser(src).Parse()
	if len(errs) > 0 {
		t.Fatalf("parse: %v", errs)
	}
	if err := tree.ExpandGroups(); err != nil {
		t.Fatalf("ExpandGroups: %v", err)
	}
	return tree
}

func portNodes14423(tree *ConfigTree, key string) []*Node {
	return findNodesByKey(tree.Children, key)
}

func assertPortUnion14423(t *testing.T, what string, nodes []*Node, want []string) {
	t.Helper()
	if len(nodes) != 1 {
		t.Fatalf("%s: must yield exactly ONE port node, got %d: %s",
			what, len(nodes), describeNodes(nodes))
	}
	assertMembers(t, what, firewallMatchValues(nodes[0]), want)
}

// Leaf x leaf (collapsed both sides, flat-set spelling) for every port
// keyword in both families, in both authorship orders.
func TestApplyGroupsPortRangeFreeUnionLeafLeaf14423(t *testing.T) {
	keywords := []string{
		"destination-port", "source-port",
		"destination-port-except", "source-port-except",
	}
	for _, family := range []string{"inet", "inet6"} {
		for _, kw := range keywords {
			for _, groupFirst := range []bool{true, false} {
				name := family + "/" + kw
				if groupFirst {
					name += "/group-first"
				} else {
					name += "/inline-first"
				}
				t.Run(name, func(t *testing.T) {
					group := "set groups g firewall family " + family +
						" filter F term T from " + kw + " 443"
					inline := "set firewall family " + family +
						" filter F term T from " + kw + " 80"
					cmds := []string{group, inline}
					if !groupFirst {
						cmds = []string{inline, group}
					}
					cmds = append(cmds,
						"set firewall family "+family+" filter F term T then discard",
						"set apply-groups g")
					tree := setTreeFromCommands(t, cmds)
					assertPortUnion14423(t, "range-free "+kw+" leaf/leaf union",
						portNodes14423(tree, kw), []string{"80", "443"})
				})
			}
		}
	}
}

// All shape pairs. Block spellings need hierarchical syntax; the flat-set
// leaf spelling is exercised above and as the leaf half of the mixed pairs.
func TestApplyGroupsPortRangeFreeUnionShapes14423(t *testing.T) {
	const groupBlock = `
groups {
    g {
        firewall {
            family inet {
                filter F {
                    term T {
                        from {
                            destination-port {
                                443;
                                8443;
                            }
                        }
                    }
                }
            }
        }
    }
}
apply-groups g;
`
	const inlineBlockTail = `
firewall {
    family inet {
        filter F {
            term T {
                from {
                    destination-port {
                        80;
                    }
                }
                then discard;
            }
        }
    }
}
`

	t.Run("group-block/inline-leaf", func(t *testing.T) {
		tree := expandHier14423(t, groupBlock+`
firewall {
    family inet {
        filter F {
            term T {
                from {
                    destination-port 80;
                }
                then discard;
            }
        }
    }
}
`)
		assertPortUnion14423(t, "group-block/inline-leaf union",
			portNodes14423(tree, "destination-port"),
			[]string{"80", "443", "8443"})
	})

	t.Run("group-leaf/inline-block", func(t *testing.T) {
		tree := expandHier14423(t, `
groups {
    g {
        firewall {
            family inet {
                filter F {
                    term T {
                        from {
                            destination-port 443;
                        }
                    }
                }
            }
        }
    }
}
apply-groups g;
`+inlineBlockTail)
		assertPortUnion14423(t, "group-leaf/inline-block union",
			portNodes14423(tree, "destination-port"),
			[]string{"80", "443"})
	})

	// Block x block already survived on base (children merge one level
	// down); pin it so the fix does not regress the surviving pair.
	t.Run("group-block/inline-block", func(t *testing.T) {
		tree := expandHier14423(t, groupBlock+inlineBlockTail)
		assertPortUnion14423(t, "group-block/inline-block union",
			portNodes14423(tree, "destination-port"),
			[]string{"80", "443", "8443"})
	})
}

// Bracketed members are plain values too: `[ 443 8443 ]` beside inline
// 80 unions; a bracketed RANGE spelling is not valid Junos for ports, so
// only the plain form is pinned here.
func TestApplyGroupsPortRangeFreeUnionBracket14423(t *testing.T) {
	tree := setTreeFromCommands(t, []string{
		"set groups g firewall family inet filter F term T from destination-port [ 443 8443 ]",
		"set firewall family inet filter F term T from destination-port 80",
		"set firewall family inet filter F term T then discard",
		"set apply-groups g",
	})
	assertPortUnion14423(t, "bracketed group members union",
		portNodes14423(tree, "destination-port"), []string{"80", "443", "8443"})
}

// A member present on both sides is kept once.
func TestApplyGroupsPortRangeFreeUnionDedup14423(t *testing.T) {
	tree := setTreeFromCommands(t, []string{
		"set groups g firewall family inet filter F term T from destination-port [ 80 443 ]",
		"set firewall family inet filter F term T from destination-port 80",
		"set firewall family inet filter F term T then discard",
		"set apply-groups g",
	})
	assertPortUnion14423(t, "shared member deduplicated",
		portNodes14423(tree, "destination-port"), []string{"80", "443"})
}

// Range guards: when EITHER side carries a `to` range, the group value
// keeps the pinned inline-wins override — the union must not token-merge
// a range into a member set. (Range-vs-range is pinned by
// TestApplyGroupsLeafListPortRangeOverrides and must stay green.)
func TestApplyGroupsPortRangeStillOverrides14423(t *testing.T) {
	t.Run("group-range/inline-plain", func(t *testing.T) {
		tree := setTreeFromCommands(t, []string{
			"set groups g firewall family inet filter F term T from destination-port 1000 to 2000",
			"set firewall family inet filter F term T from destination-port 80",
			"set firewall family inet filter F term T then accept",
			"set apply-groups g",
		})
		assertPortUnion14423(t, "group range beside inline plain overrides",
			portNodes14423(tree, "destination-port"), []string{"80"})
	})
	t.Run("group-plain/inline-range", func(t *testing.T) {
		tree := setTreeFromCommands(t, []string{
			"set groups g firewall family inet filter F term T from destination-port 443",
			"set firewall family inet filter F term T from destination-port 3000 to 4000",
			"set firewall family inet filter F term T then accept",
			"set apply-groups g",
		})
		nodes := portNodes14423(tree, "destination-port")
		if len(nodes) != 1 {
			t.Fatalf("inline range must yield ONE node, got %d: %s",
				len(nodes), describeNodes(nodes))
		}
		assertMembers(t, "inline range beside group plain overrides",
			firewallMatchValues(nodes[0]), []string{"3000", "to", "4000"})
	})
	t.Run("group-block-range/inline-leaf", func(t *testing.T) {
		tree := expandHier14423(t, `
groups {
    g {
        firewall {
            family inet {
                filter F {
                    term T {
                        from {
                            destination-port {
                                1000 to 2000;
                            }
                        }
                    }
                }
            }
        }
    }
}
apply-groups g;
firewall {
    family inet {
        filter F {
            term T {
                from {
                    destination-port 80;
                }
                then accept;
            }
        }
    }
}
`)
		assertPortUnion14423(t, "group block range overrides",
			portNodes14423(tree, "destination-port"), []string{"80"})
	})
}

// Hyphen ranges (`1000-2000`, the other Junos range spelling that
// resolveFilterPort expands) are ranges too: on either side they keep
// the inline-wins override, exactly like a `to` range. #14444's block
// predicate covers this for blocks; the leaf path must agree, or a
// hyphen group member unions into a range the operator never wrote
// beside the inline peer.
func TestApplyGroupsPortHyphenRangeStillOverrides14423(t *testing.T) {
	t.Run("leaf/group-hyphen/inline-plain", func(t *testing.T) {
		tree := setTreeFromCommands(t, []string{
			"set groups g firewall family inet filter F term T from destination-port 1000-2000",
			"set firewall family inet filter F term T from destination-port 80",
			"set firewall family inet filter F term T then accept",
			"set apply-groups g",
		})
		assertPortUnion14423(t, "group hyphen range overrides",
			portNodes14423(tree, "destination-port"), []string{"80"})
	})
	t.Run("leaf/group-plain/inline-hyphen", func(t *testing.T) {
		tree := setTreeFromCommands(t, []string{
			"set groups g firewall family inet filter F term T from destination-port 443",
			"set firewall family inet filter F term T from destination-port 1000-2000",
			"set firewall family inet filter F term T then accept",
			"set apply-groups g",
		})
		assertPortUnion14423(t, "inline hyphen range overrides",
			portNodes14423(tree, "destination-port"), []string{"1000-2000"})
	})
	t.Run("block/group-hyphen/inline-leaf", func(t *testing.T) {
		tree := expandHier14423(t, `
groups {
    g {
        firewall {
            family inet {
                filter F {
                    term T {
                        from {
                            destination-port {
                                1000-2000;
                            }
                        }
                    }
                }
            }
        }
    }
}
apply-groups g;
firewall {
    family inet {
        filter F {
            term T {
                from {
                    destination-port 80;
                }
                then accept;
            }
        }
    }
}
`)
		assertPortUnion14423(t, "group block hyphen range overrides",
			portNodes14423(tree, "destination-port"), []string{"80"})
	})
}

// The other groupReplace leaves must NOT be swept into the union:
// `then community add ...` packs an operation keyword, so inline still
// wins outright. (Also pinned by
// TestApplyGroupsLeafListThenCommunityOverrides /
// TestApplyGroupsLeafListThenAsPathPrependOverrides.)
func TestApplyGroupsPortUnionLeavesCommunityOverride14423(t *testing.T) {
	tree := setTreeFromCommands(t, []string{
		"set groups g policy-options policy-statement P term t1 then community add 65000:100",
		"set policy-options policy-statement P term t1 then community add 65000:200",
		"set policy-options policy-statement P term t1 then accept",
		"set apply-groups g",
	})
	comm := findNodesByKey(tree.Children, "community")
	if len(comm) != 1 {
		t.Fatalf("community override must yield ONE node, got %d: %s",
			len(comm), describeNodes(comm))
	}
	assertMembers(t, "then community still overrides",
		firewallMatchValues(comm[0]), []string{"add", "65000:200"})
}

// Compiled end state: the unioned term matches BOTH ports, and an
// except-term excludes BOTH ports.
func TestApplyGroupsPortUnionCompiledFilter14423(t *testing.T) {
	compile := func(t *testing.T, cmds []string) *FirewallFilterTerm {
		t.Helper()
		cfg, err := CompileConfig(buildTree(t, cmds))
		if err != nil {
			t.Fatalf("CompileConfig: %v", err)
		}
		f := cfg.Firewall.FiltersInet["F"]
		if f == nil || len(f.Terms) != 1 {
			t.Fatalf("expected filter F with 1 term, got %#v", f)
		}
		return f.Terms[0]
	}
	sorted := func(in []string) []string {
		out := append([]string(nil), in...)
		sort.Strings(out)
		return out
	}

	t.Run("discard-term-matches-both", func(t *testing.T) {
		term := compile(t, []string{
			"set groups g firewall family inet filter F term T from destination-port 443",
			"set firewall family inet filter F term T from destination-port 80",
			"set firewall family inet filter F term T then discard",
			"set apply-groups g",
		})
		if got := strings.Join(sorted(term.DestinationPorts), ","); got != "443,80" {
			t.Fatalf("compiled term must match {80,443}, got DestinationPorts %v", term.DestinationPorts)
		}
		if len(term.UnknownPorts) != 0 {
			t.Fatalf("no unknown ports expected, got %v", term.UnknownPorts)
		}
	})

	t.Run("except-term-excludes-both", func(t *testing.T) {
		term := compile(t, []string{
			"set groups g firewall family inet filter F term T from destination-port-except 443",
			"set firewall family inet filter F term T from destination-port-except 80",
			"set firewall family inet filter F term T then accept",
			"set apply-groups g",
		})
		if got := strings.Join(sorted(term.DestPortsExcept), ","); got != "443,80" {
			t.Fatalf("compiled term must exclude {80,443}, got DestPortsExcept %v", term.DestPortsExcept)
		}
	})

	// NAT subcase (same root cause, MEDIUM alone): source and destination
	// NAT rule `match destination-port` route through parseDNATPortList,
	// which appends across nodes — a range-free union parses identically.
	t.Run("nat-match-matches-both", func(t *testing.T) {
		cfg, err := CompileConfig(buildTree(t, []string{
			"set groups g security nat destination rule-set RS rule R1 match destination-port 443",
			"set security nat destination rule-set RS rule R1 match destination-port 80",
			"set security nat destination rule-set RS rule R1 then destination-nat pool P",
			"set security nat destination pool P address 10.0.0.1/32",
			"set apply-groups g",
		}))
		if err != nil {
			t.Fatalf("CompileConfig: %v", err)
		}
		if cfg.Security.NAT.Destination == nil ||
			len(cfg.Security.NAT.Destination.RuleSets) == 0 ||
			len(cfg.Security.NAT.Destination.RuleSets[0].Rules) == 0 {
			t.Fatalf("expected one DNAT rule, got %#v", cfg.Security)
		}
		ports := cfg.Security.NAT.Destination.RuleSets[0].Rules[0].Match.DestinationPorts
		got := map[int]bool{}
		for _, p := range ports {
			got[p] = true
		}
		if len(ports) != 2 || !got[80] || !got[443] {
			t.Fatalf("DNAT rule must match {80,443}, got %v", ports)
		}
	})
}
