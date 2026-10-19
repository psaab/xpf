package config

import (
	"reflect"
	"strings"
	"testing"
)

// Regression tests for #15713 — inline `inactive:` governing a braced
// sub-block whose keys follow the marker.
//
// RED: pre-fix parseStatement truncated keys to keys[:i] and set
// Inactive=true on the outer node when LBrace followed, so
// `ge-0/0/0.0 inactive: host-inbound-traffic { ... }` became an inactive
// `ge-0/0/0.0` with host-inbound-traffic's children re-parented directly.
// GREEN: outer stays active, inner sub-block is its sole inactive child.

func TestInlineInactiveGovernedBlock15713(t *testing.T) {
	tree := mustParse(t, `security {
    zones {
        security-zone trust {
            interfaces {
                ge-0/0/0.0 inactive: host-inbound-traffic {
                    system-services {
                        ping;
                    }
                }
            }
        }
    }
}`)
	iface := tree.FindChild("security").FindChild("zones").FindChild("security-zone").FindChild("interfaces").FindChild("ge-0/0/0.0")
	if iface == nil {
		t.Fatalf("ge-0/0/0.0 interface node not found; tree:\n%s", tree.Format())
	}
	if iface.Inactive {
		t.Fatal("outer ge-0/0/0.0 hoisted Inactive=true; want active")
	}
	if iface.IsLeaf {
		t.Fatal("outer ge-0/0/0.0 is leaf; want container")
	}
	if len(iface.Children) != 1 {
		t.Fatalf("outer children = %d, want 1 (host-inbound-traffic); tree:\n%s", len(iface.Children), tree.Format())
	}
	inner := iface.Children[0]
	if !reflect.DeepEqual(inner.Keys, []string{"host-inbound-traffic"}) {
		t.Fatalf("inner keys = %v, want [host-inbound-traffic]", inner.Keys)
	}
	if !inner.Inactive {
		t.Fatal("inner host-inbound-traffic not Inactive")
	}
	if inner.IsLeaf {
		t.Fatal("inner host-inbound-traffic is leaf; want container")
	}
	if inner.FindChild("system-services") == nil || inner.FindChild("system-services").FindChild("ping") == nil {
		t.Fatalf("inner children lost; inner:\n%v", inner)
	}

	// WithoutInactive: outer survives, inactive sub-block pruned.
	stripped := tree.WithoutInactive()
	sIface := stripped.FindChild("security").FindChild("zones").FindChild("security-zone").FindChild("interfaces").FindChild("ge-0/0/0.0")
	if sIface == nil {
		t.Fatal("WithoutInactive stripped active outer ge-0/0/0.0")
	}
	if sIface.FindChild("host-inbound-traffic") != nil {
		t.Fatal("WithoutInactive retained inactive host-inbound-traffic")
	}

	// FormatSet: must emit set for governed leaf and deactivate only the
	// sub-block path, never deactivate the outer interface.
	setOut := tree.FormatSet()
	if !strings.Contains(setOut, "set security zones security-zone trust interfaces ge-0/0/0.0 host-inbound-traffic system-services ping") {
		t.Fatalf("FormatSet missing governed set line:\n%s", setOut)
	}
	if !strings.Contains(setOut, "deactivate security zones security-zone trust interfaces ge-0/0/0.0 host-inbound-traffic") {
		t.Fatalf("FormatSet missing deactivate for sub-block:\n%s", setOut)
	}
	if strings.Contains(setOut, "deactivate security zones security-zone trust interfaces ge-0/0/0.0\n") {
		t.Fatalf("FormatSet deactivated outer interface:\n%s", setOut)
	}

	// Format (hierarchical) round-trip.
	hier := tree.Format()
	reparsed := mustParse(t, hier)
	rIface := reparsed.FindChild("security").FindChild("zones").FindChild("security-zone").FindChild("interfaces").FindChild("ge-0/0/0.0")
	if rIface == nil || rIface.Inactive {
		t.Fatalf("round-trip outer = %+v, want active ge-0/0/0.0; hier:\n%s", rIface, hier)
	}
	if len(rIface.Children) != 1 || !rIface.Children[0].Inactive || rIface.Children[0].KeyPath() != "host-inbound-traffic" {
		t.Fatalf("round-trip inner mismatch: %+v; hier:\n%s", rIface.Children, hier)
	}
}

func TestInlineInactiveGovernedMultiKeyBlock15713(t *testing.T) {
	tree := mustParse(t, `interfaces {
    ge-0/0/0 {
        unit 0 inactive: family inet6 {
            address 2001:db8::1/64;
        }
    }
}`)
	unit := tree.FindChild("interfaces").FindChild("ge-0/0/0").FindChild("unit")
	if unit == nil {
		t.Fatalf("unit node not found:\n%s", tree.Format())
	}
	// unit keys are [unit 0]
	if unit.Inactive {
		t.Fatal("outer unit 0 hoisted Inactive")
	}
	if len(unit.Children) != 1 {
		t.Fatalf("unit children = %d want 1:\n%s", len(unit.Children), tree.Format())
	}
	inner := unit.Children[0]
	if !reflect.DeepEqual(inner.Keys, []string{"family", "inet6"}) {
		t.Fatalf("inner keys = %v want [family inet6]", inner.Keys)
	}
	if !inner.Inactive {
		t.Fatal("inner family inet6 not inactive")
	}
	if inner.FindChild("address") == nil {
		t.Fatal("inner lost address child")
	}
	stripped := tree.WithoutInactive()
	sUnit := stripped.FindChild("interfaces").FindChild("ge-0/0/0").FindChild("unit")
	if sUnit == nil {
		t.Fatal("WithoutInactive stripped active unit")
	}
	if sUnit.FindChild("family") != nil {
		t.Fatal("WithoutInactive retained inactive family")
	}
	setOut := tree.FormatSet()
	if strings.Contains(setOut, "deactivate interfaces ge-0/0/0 unit 0\n") {
		t.Fatalf("FormatSet deactivated outer unit:\n%s", setOut)
	}
	if !strings.Contains(setOut, "deactivate interfaces ge-0/0/0 unit 0 family inet6") {
		t.Fatalf("FormatSet missing deactivate family inet6:\n%s", setOut)
	}
}

// Neighbour guards: existing behaviours must not regress.

func TestInlineInactiveMarkerAtEndBeforeBlock15713(t *testing.T) {
	// i == len(keys)-1: whole outer block deactivated (existing test shape).
	tree := mustParse(t, "parent {\n child name inactive: {\n hidden value;\n }\n}")
	parent := tree.FindChild("parent")
	var n *Node
	for _, c := range parent.Children {
		if c.KeyPath() == "child name" {
			n = c
		}
	}
	if n == nil || !n.Inactive {
		t.Fatalf("marker-at-end block not inactive: %+v", parent.Children)
	}
	if len(n.Children) == 0 || n.FindChild("hidden") == nil {
		t.Fatal("marker-at-end block lost children")
	}
}

func TestInlineInactiveLeafTailStillDropped15713(t *testing.T) {
	tree := mustParse(t, "system {\n host-name keep inactive: extra token;\n}")
	hn := tree.FindChild("system").FindChild("host-name")
	if hn == nil || hn.Inactive || !reflect.DeepEqual(hn.Keys, []string{"host-name", "keep"}) {
		t.Fatalf("leaf inline inactive changed: %+v", hn)
	}
}
