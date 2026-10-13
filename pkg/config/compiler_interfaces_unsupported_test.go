package config

import (
	"strings"
	"testing"
)

// flatTreeFromSets builds a candidate ConfigTree from flat `set` commands
// using ParseSetCommand + SetPath — the ONLY correct way to exercise the
// flat-set AST shape (NewParser merges newline-separated set lines).
func flatTreeFromSets(t *testing.T, sets ...string) *ConfigTree {
	t.Helper()
	tree := &ConfigTree{}
	for _, s := range sets {
		path, err := ParseSetCommand(s)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", s, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", s, err)
		}
	}
	return tree
}

// hierTree parses a hierarchical config block via NewParser.
func hierTree(t *testing.T, src string) *ConfigTree {
	t.Helper()
	tree, err := NewParser(src).Parse()
	if err != nil {
		t.Fatalf("parse hierarchical config: %v", err)
	}
	return tree
}

// assertCommitRejects asserts the strict commit path (CompileConfig)
// fails with an error mentioning want.
func assertCommitRejects(t *testing.T, tree *ConfigTree, want string) {
	t.Helper()
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatalf("expected strict compile to reject, got nil error")
	}
	if !strings.Contains(err.Error(), want) {
		t.Fatalf("error %q does not mention %q", err.Error(), want)
	}
}

// assertCommitAccepts asserts the strict commit path compiles cleanly,
// with no H9/H10 warning. This is the non-tautological companion: the
// SAME structure minus the offending stanza must compile, proving the
// reject is caused by the stanza under test and not an unrelated error.
func assertCommitAccepts(t *testing.T, tree *ConfigTree) *Config {
	t.Helper()
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("expected strict compile to accept, got %v", err)
	}
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "#2008 H9") || strings.Contains(w, "#2008 H10") {
			t.Fatalf("unexpected H9/H10 warning on a clean config: %q", w)
		}
	}
	return cfg
}

// assertLenientWarns asserts the tolerant path (CompileConfigLenient)
// compiles WITHOUT error but records an H9/H10 warning.
func assertLenientWarns(t *testing.T, tree *ConfigTree, wantTag string) {
	t.Helper()
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("expected lenient compile to accept, got %v", err)
	}
	found := false
	for _, w := range cfg.Warnings {
		if strings.Contains(w, wantTag) {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected a %q warning on the lenient path, warnings=%v", wantTag, cfg.Warnings)
	}
}

// --- H9: per-unit ARP policer ---

func TestH9ARPPolicerFlatInetRejected(t *testing.T) {
	// Non-tautological baseline: same interface minus the policer compiles.
	assertCommitAccepts(t, flatTreeFromSets(t,
		"set interfaces ge-0/0/0 unit 0 family inet address 10.0.1.1/24",
	))
	assertCommitRejects(t, flatTreeFromSets(t,
		"set interfaces ge-0/0/0 unit 0 family inet address 10.0.1.1/24",
		"set interfaces ge-0/0/0 unit 0 family inet policer arp myarp",
	), "#2008 H9")
}

func TestH9ARPPolicerFlatInet6Rejected(t *testing.T) {
	assertCommitAccepts(t, flatTreeFromSets(t,
		"set interfaces ge-0/0/0 unit 0 family inet6 address 2001:db8::1/64",
	))
	assertCommitRejects(t, flatTreeFromSets(t,
		"set interfaces ge-0/0/0 unit 0 family inet6 address 2001:db8::1/64",
		"set interfaces ge-0/0/0 unit 0 family inet6 policer arp myarp",
	), "#2008 H9")
}

func TestH9ARPPolicerHierarchicalRejected(t *testing.T) {
	assertCommitRejects(t, hierTree(t, `interfaces {
    ge-0/0/0 {
        unit 0 {
            family inet {
                policer {
                    arp myarp;
                }
                address 10.0.1.1/24;
            }
        }
    }
}`), "#2008 H9")
}

func TestH9ARPPolicerLenientWarns(t *testing.T) {
	assertLenientWarns(t, flatTreeFromSets(t,
		"set interfaces ge-0/0/0 unit 0 family inet policer arp myarp",
	), "#2008 H9")
}

// --- H10: static MAC override ---

func TestH10InterfaceMACRejected(t *testing.T) {
	// Non-tautological baseline: same interface minus the mac compiles.
	assertCommitAccepts(t, flatTreeFromSets(t,
		"set interfaces ge-0/0/0 unit 0 family inet address 10.0.1.1/24",
	))
	assertCommitRejects(t, flatTreeFromSets(t,
		"set interfaces ge-0/0/0 mac 00:11:22:33:44:55",
		"set interfaces ge-0/0/0 unit 0 family inet address 10.0.1.1/24",
	), "#2008 H10")
}

func TestH10InterfaceMACHierarchicalRejected(t *testing.T) {
	assertCommitRejects(t, hierTree(t, `interfaces {
    ge-0/0/0 {
        mac 00:11:22:33:44:55;
        unit 0 {
            family inet {
                address 10.0.1.1/24;
            }
        }
    }
}`), "#2008 H10")
}

func TestH10UnitMACRejected(t *testing.T) {
	assertCommitRejects(t, flatTreeFromSets(t,
		"set interfaces ge-0/0/0 unit 0 mac 00:11:22:33:44:66",
		"set interfaces ge-0/0/0 unit 0 family inet address 10.0.1.1/24",
	), "#2008 H10")
}

func TestH10MACLenientWarns(t *testing.T) {
	assertLenientWarns(t, flatTreeFromSets(t,
		"set interfaces ge-0/0/0 mac 00:11:22:33:44:55",
	), "#2008 H10")
}

func TestH10PackedUnitMACWithoutInlinePeerRejected(t *testing.T) {
	// The packed leaf is the unit node itself, rather than a mac child of an
	// inline unit container. This is the group-expanded shape when no peer
	// unit exists to receive the packed tail.
	assertCommitAccepts(t, hierTree(t, `interfaces {
    ge-0/0/0 {
        unit 0 {
            family inet {
                address 10.0.1.1/24;
            }
        }
    }
}`))
	packed := func() *ConfigTree {
		return hierTree(t, `interfaces {
    ge-0/0/0 {
        unit 0 mac 00:11:22:33:44:66;
    }
}`)
	}
	assertCommitRejects(t, packed(), "#2008 H10")
	assertLenientWarns(t, packed(), "#2008 H10")
}

// --- #2354: QinQ / stacked-VLAN inner tag (inner-vlan-id) ---

func TestQinQInnerVlanIDFlatRejected(t *testing.T) {
	// Non-tautological baseline: the SAME unit with single-tag
	// flexible-vlan-tagging + vlan-id (no inner tag) compiles clean.
	assertCommitAccepts(t, flatTreeFromSets(t,
		"set interfaces ge-0/0/0 flexible-vlan-tagging",
		"set interfaces ge-0/0/0 unit 0 vlan-id 100",
		"set interfaces ge-0/0/0 unit 0 family inet address 10.0.1.1/24",
	))
	// Adding inner-vlan-id (QinQ) hard-rejects at commit.
	assertCommitRejects(t, flatTreeFromSets(t,
		"set interfaces ge-0/0/0 flexible-vlan-tagging",
		"set interfaces ge-0/0/0 unit 0 vlan-id 100",
		"set interfaces ge-0/0/0 unit 0 inner-vlan-id 200",
		"set interfaces ge-0/0/0 unit 0 family inet address 10.0.1.1/24",
	), "#2354")
}

func TestQinQInnerVlanIDHierarchicalRejected(t *testing.T) {
	assertCommitRejects(t, hierTree(t, `interfaces {
    ge-0/0/0 {
        flexible-vlan-tagging;
        unit 0 {
            vlan-id 100;
            inner-vlan-id 200;
            family inet {
                address 10.0.1.1/24;
            }
        }
    }
}`), "#2354")
}

func TestQinQInnerVlanIDLenientWarns(t *testing.T) {
	assertLenientWarns(t, flatTreeFromSets(t,
		"set interfaces ge-0/0/0 unit 0 inner-vlan-id 200",
	), "#2354")
}

// TestQinQGateDoesNotMatchSingleTag is the load-bearing negative: a
// single 802.1Q unit — flexible-vlan-tagging + vlan-id but NO
// inner-vlan-id — is CORRECT (#2346) and must stay accepted with no
// #2354 warning. The gate keys on inner-vlan-id, not flexible-vlan-
// tagging, so single-tag transit is never falsely rejected.
func TestQinQGateDoesNotMatchSingleTag(t *testing.T) {
	cfg := assertCommitAccepts(t, flatTreeFromSets(t,
		"set interfaces ge-0/0/0 flexible-vlan-tagging",
		"set interfaces ge-0/0/0 unit 0 vlan-id 100",
		"set interfaces ge-0/0/0 unit 0 family inet address 10.0.1.1/24",
	))
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "#2354") {
			t.Fatalf("single-tag flexible-vlan-tagging must not trip #2354, got %q", w)
		}
	}
	// Also assert the lenient path stays quiet for single-tag config.
	lenient, err := CompileConfigLenient(flatTreeFromSets(t,
		"set interfaces ge-0/0/0 flexible-vlan-tagging",
		"set interfaces ge-0/0/0 unit 0 vlan-id 100",
		"set interfaces ge-0/0/0 unit 0 family inet address 10.0.1.1/24",
	))
	if err != nil {
		t.Fatalf("lenient single-tag compile failed: %v", err)
	}
	for _, w := range lenient.Warnings {
		if strings.Contains(w, "#2354") {
			t.Fatalf("single-tag flexible-vlan-tagging must not warn #2354 on lenient path, got %q", w)
		}
	}
}

// --- #2008 H1 inactive: deactivated stanza must NOT be rejected ---

func TestH9H10InactiveStanzaCompilesClean(t *testing.T) {
	cfg, err := CompileConfig(hierTree(t, `interfaces {
    ge-0/0/0 {
        inactive: mac 00:11:22:33:44:55;
        unit 0 {
            family inet {
                inactive: policer {
                    arp myarp;
                }
                address 10.0.1.1/24;
            }
        }
    }
}`))
	if err != nil {
		t.Fatalf("inactive H9/H10 stanzas must compile clean, got %v", err)
	}
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "#2008 H9") || strings.Contains(w, "#2008 H10") {
			t.Fatalf("inactive stanza must not warn, got %q", w)
		}
	}
}

// --- apply-groups inheritance: an inherited offending stanza is caught ---

func TestH9H10ViaApplyGroupsRejected(t *testing.T) {
	assertCommitRejects(t, hierTree(t, `groups {
    badmac {
        interfaces {
            ge-0/0/0 {
                mac 00:11:22:33:44:55;
            }
        }
    }
}
apply-groups badmac;
interfaces {
    ge-0/0/0 {
        unit 0 {
            family inet {
                address 10.0.1.1/24;
            }
        }
    }
}`), "#2008 H10")
}

// --- Non-regression: legitimate mac / policer keywords elsewhere ---

func TestUnsupportedGateDoesNotMatchFirewallPolicer(t *testing.T) {
	// `firewall policer <name>` is a legitimate, compiled definition. It
	// must not be mistaken for an interface ARP policer.
	assertCommitAccepts(t, flatTreeFromSets(t,
		"set firewall policer p1 if-exceeding bandwidth-limit 1m",
		"set firewall policer p1 if-exceeding burst-size-limit 15k",
		"set firewall policer p1 then discard",
		"set interfaces ge-0/0/0 unit 0 family inet address 10.0.1.1/24",
	))
}

func TestUnsupportedGateDoesNotMatchDeviceMapMAC(t *testing.T) {
	// chassis device-map interface ... mac is an identity KEY, not an
	// interface static-MAC override. It must not be rejected.
	assertCommitAccepts(t, flatTreeFromSets(t,
		"set chassis device-map interface ge-0/0/0 mac 00:11:22:33:44:55",
		"set interfaces ge-0/0/0 unit 0 family inet address 10.0.1.1/24",
	))
}

func TestUnsupportedGateDoesNotMatchInterfaceFilter(t *testing.T) {
	// A unit-level firewall filter binding is supported and must compile
	// (the referenced filter is defined; #3296 only rejects DANGLING refs).
	assertCommitAccepts(t, flatTreeFromSets(t,
		"set firewall family inet filter myfilter term t1 then accept",
		"set interfaces ge-0/0/0 unit 0 family inet filter input myfilter",
		"set interfaces ge-0/0/0 unit 0 family inet address 10.0.1.1/24",
	))
}

func TestH9GateDoesNotMatchNonARPPolicer(t *testing.T) {
	// H9 is precisely `policer arp`. A `policer input`/`policer output`
	// reference is a DIFFERENT stanza (not in scope for this gate) and must
	// NOT trip the H9 reject — its disposition is independent. Verify both
	// AST shapes are left alone by the ARP-specific matcher.
	if hasARPPolicer(famNode(t, flatTreeFromSets(t,
		"set interfaces ge-0/0/0 unit 0 family inet policer input p1",
	))) {
		t.Fatal("flat `policer input` must not match hasARPPolicer")
	}
	if hasARPPolicer(famNode(t, hierTree(t, `interfaces {
    ge-0/0/0 {
        unit 0 {
            family inet {
                policer {
                    input p1;
                }
            }
        }
    }
}`))) {
		t.Fatal("hierarchical `policer { input ...; }` must not match hasARPPolicer")
	}
}

// famNode digs out the `family inet` node from a one-interface tree for
// the white-box hasARPPolicer assertion.
func famNode(t *testing.T, tree *ConfigTree) *Node {
	t.Helper()
	ifaces := tree.FindChild("interfaces")
	if ifaces == nil || len(ifaces.Children) == 0 {
		t.Fatal("no interfaces node")
	}
	for _, unit := range ifaces.Children[0].Children {
		if unit.Name() != "unit" {
			continue
		}
		for _, fam := range unit.Children {
			if fam.Name() == "family" {
				return fam
			}
		}
	}
	t.Fatal("no family node")
	return nil
}

func TestH10PackedUnitMACMidTailRejected(t *testing.T) {
	// `mac` after another packed stanza is the same H10 violation as
	// first-position mac; the tail walk is schema-guided so a value
	// spelling "mac" (description) is not a hit.
	assertCommitRejects(t, flatTreeFromSets(t,
		"set interfaces ge-0/0/0 unit 0 vlan-id 5 mac 00:11:22:33:44:66",
	), "#2008 H10")
	assertCommitAccepts(t, flatTreeFromSets(t,
		"set interfaces ge-0/0/0 unit 0 description mac",
		"set interfaces ge-0/0/0 unit 0 family inet address 10.0.1.1/24",
	))
}
