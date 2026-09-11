package config

import (
	"fmt"
	"testing"
)

// A split config with TWO top-level roots of the same stanza is a
// hierarchical-only shape: the flat-set path (ParseSetCommand + tree.SetPath)
// always MERGES `set interfaces …` onto ONE `interfaces` root, so it can never
// produce sibling roots. compileSections, by contrast, dispatches EVERY
// matching root. These tests pin the AST pre-passes to that reality — they must
// union across all matching roots, not just the first FindChild hit. They are
// authored through NewParser (the only shape that can express split roots) and
// each asserts the two-root precondition before exercising the fix, so a future
// parser change that starts merging duplicate roots surfaces as a loud
// precondition failure rather than a silently-passing test.

// TestInterfaceRangeSecondRootExpands_5675 is the #5675 (codex-182 M09)
// RED-on-revert guard. An `interfaces interface-range` stanza living in a
// SECOND top-level `interfaces { }` root must still expand into its member
// interfaces. Before the fix expandInterfaceRanges broke on the first
// `interfaces` root, so a range in a later root was never expanded: the range
// name was compiled as a phantom interface (the #4027 regression) and its
// members plus shared config were dropped. This test goes RED on that behavior.
func TestInterfaceRangeSecondRootExpands_5675(t *testing.T) {
	input := `
interfaces {
    ge-0/0/0 {
        mtu 1500;
    }
}
interfaces {
    interface-range R {
        member ge-0/0/1;
        member ge-0/0/2;
        mtu 9000;
    }
}
`
	tree, errs := NewParser(input).Parse()
	if len(errs) > 0 {
		t.Fatalf("parse: %v", errs)
	}
	// Precondition: the split-root shape this guards actually exists.
	if got := len(tree.FindChildren("interfaces")); got != 2 {
		t.Fatalf("expected 2 top-level interfaces roots, got %d", got)
	}

	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	ifaces := cfg.Interfaces.Interfaces

	// No phantom interface minted from the second root's range name.
	if _, ok := ifaces["interface-range"]; ok {
		t.Errorf("phantom interface %q minted from the second interfaces root (#5675)", "interface-range")
	}
	if _, ok := ifaces["R"]; ok {
		t.Errorf("phantom interface %q minted from the second interfaces root (#5675)", "R")
	}

	// Both members from the second-root range exist and carry its shared MTU.
	for _, m := range []string{"ge-0/0/1", "ge-0/0/2"} {
		ifc, ok := ifaces[m]
		if !ok {
			t.Errorf("member %s from the second-root interface-range not compiled (#5675)", m)
			continue
		}
		if ifc.Disable {
			t.Errorf("member %s must not be admin-down", m)
		}
		if ifc.MTU != 9000 {
			t.Errorf("member %s MTU = %d, want 9000 (second-root range shared config)", m, ifc.MTU)
		}
	}

	// The first root's normal interface is untouched.
	if ge0 := ifaces["ge-0/0/0"]; ge0 == nil || ge0.MTU != 1500 {
		t.Errorf("first-root ge-0/0/0 disturbed: %+v", ge0)
	}
}

// TestZoneIDCollisionAcrossSplitSecurityRoots_5691 is one arm of the #5691
// (codex-182 M08) RED-on-revert guard. Two security zones whose names fold to
// the same StableZoneID, split across two top-level `security { }` roots, must
// be rejected by the collision gate. Before the fix validateZoneIDCollisionAST
// read only the first `security` root (tree.FindChild), so a collision spanning
// the roots was invisible and admitted — while compileSections compiled BOTH
// zones with the same numeric id (a silent zone merge). This test goes RED
// (err == nil) on that behavior.
func TestZoneIDCollisionAcrossSplitSecurityRoots_5691(t *testing.T) {
	a, b := findZoneCollisionPair(t)
	input := fmt.Sprintf(`
security {
    zones {
        security-zone %s {
            host-inbound-traffic {
                system-services {
                    ping;
                }
            }
        }
    }
}
security {
    zones {
        security-zone %s {
            host-inbound-traffic {
                system-services {
                    ping;
                }
            }
        }
    }
}
`, a, b)
	tree, errs := NewParser(input).Parse()
	if len(errs) > 0 {
		t.Fatalf("parse: %v", errs)
	}
	if got := len(tree.FindChildren("security")); got != 2 {
		t.Fatalf("expected 2 top-level security roots, got %d", got)
	}

	if _, err := validateZoneIDCollisionAST(tree, false); err == nil {
		t.Fatalf("expected a zone-id collision error across split security roots "+
			"(zones %q/%q both fold to %d), got nil (#5691)", a, b, StableZoneID(a))
	}
}

// TestRoutingInstanceTableIDCollisionAcrossSplitRoots_5691 is the routing-
// instance (VRF) arm of the #5691 guard. Two instances whose names fold to the
// same kernel table id, split across two `routing-instances { }` roots, must be
// rejected. Before the fix the gate read only the first root, so two VRFs could
// silently share one kernel table (a cross-VRF route leak). RED on revert.
func TestRoutingInstanceTableIDCollisionAcrossSplitRoots_5691(t *testing.T) {
	a, b := findRoutingInstanceCollisionPair(t)
	input := fmt.Sprintf(`
routing-instances {
    %s {
        instance-type virtual-router;
    }
}
routing-instances {
    %s {
        instance-type virtual-router;
    }
}
`, a, b)
	tree, errs := NewParser(input).Parse()
	if len(errs) > 0 {
		t.Fatalf("parse: %v", errs)
	}
	if got := len(tree.FindChildren("routing-instances")); got != 2 {
		t.Fatalf("expected 2 top-level routing-instances roots, got %d", got)
	}

	if _, err := validateRoutingInstanceTableIDCollisionAST(tree, -1, false); err == nil {
		t.Fatalf("expected a routing-instance table-id collision error across split roots "+
			"(instances %q/%q both fold to table %d), got nil (#5691)",
			a, b, StableRoutingInstanceTableID(a))
	}
}

// TestTunnelEndpointIDCollisionAcrossSplitInterfaceRoots_5691 is the tunnel arm
// of the #5691 guard. Two tunnel interfaces whose unit-qualified endpoint names
// fold to the same StableTunnelEndpointID, split across two `interfaces { }`
// roots, must be rejected. Before the fix View 1 (and Views 2/3) read only the
// first `interfaces` root, so a cross-root tunnel id collision was admitted
// while the snapshot builder would drop one endpoint at runtime. RED on revert.
func TestTunnelEndpointIDCollisionAcrossSplitInterfaceRoots_5691(t *testing.T) {
	ifA, ifB := findTunnelCollisionPair(t)
	input := fmt.Sprintf(`
interfaces {
    %s {
        unit 0 {
            tunnel {
                source 10.0.0.1;
                destination 10.0.0.2;
            }
        }
    }
}
interfaces {
    %s {
        unit 0 {
            tunnel {
                source 10.0.1.1;
                destination 10.0.1.2;
            }
        }
    }
}
`, ifA, ifB)
	tree, errs := NewParser(input).Parse()
	if len(errs) > 0 {
		t.Fatalf("parse: %v", errs)
	}
	if got := len(tree.FindChildren("interfaces")); got != 2 {
		t.Fatalf("expected 2 top-level interfaces roots, got %d", got)
	}

	if _, err := validateTunnelEndpointIDCollisionAST(tree, false); err == nil {
		t.Fatalf("expected a tunnel-endpoint id collision error across split interfaces roots "+
			"(%s.0 / %s.0 both fold to %d), got nil (#5691)",
			ifA, ifB, StableTunnelEndpointID(ifA+".0"))
	}
}

// findZoneCollisionPair returns two distinct zone names that fold to the same
// StableZoneID. The zone id space has ~65533 buckets, so a collision is found
// within a few hundred candidates by the birthday bound (pigeonhole guarantees
// one well before the cap).
func findZoneCollisionPair(t *testing.T) (string, string) {
	t.Helper()
	seen := map[uint16]string{}
	for i := 0; i < 300000; i++ {
		name := fmt.Sprintf("zone%d", i)
		id := StableZoneID(name)
		if other, ok := seen[id]; ok {
			return other, name
		}
		seen[id] = name
	}
	t.Fatal("no StableZoneID collision found within 300000 candidates")
	return "", ""
}

// findRoutingInstanceCollisionPair returns two distinct instance names that
// fold to the same StableRoutingInstanceTableID. The band has 900000 buckets;
// the birthday bound finds a collision within a couple thousand candidates.
func findRoutingInstanceCollisionPair(t *testing.T) (string, string) {
	t.Helper()
	seen := map[int]string{}
	for i := 0; i < 300000; i++ {
		name := fmt.Sprintf("vrf%d", i)
		id := StableRoutingInstanceTableID(name)
		if other, ok := seen[id]; ok {
			return other, name
		}
		seen[id] = name
	}
	t.Fatal("no StableRoutingInstanceTableID collision found within 300000 candidates")
	return "", ""
}

// findTunnelCollisionPair returns two distinct tunnel interface base names
// whose unit-0 endpoint names ("<base>.0") fold to the same
// StableTunnelEndpointID. ~65535 buckets, so a collision is found within a few
// hundred candidates.
func findTunnelCollisionPair(t *testing.T) (string, string) {
	t.Helper()
	seen := map[uint16]string{}
	for i := 0; i < 300000; i++ {
		base := fmt.Sprintf("gr-0/0/%d", i)
		id := StableTunnelEndpointID(base + ".0")
		if other, ok := seen[id]; ok {
			return other, base
		}
		seen[id] = base
	}
	t.Fatal("no StableTunnelEndpointID collision found within 300000 candidates")
	return "", ""
}
