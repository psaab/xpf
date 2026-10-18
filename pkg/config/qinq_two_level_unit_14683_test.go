package config

import (
	"strings"
	"testing"
)

// Tests for #14683 (D9-03): the #5879 QinQ gate missed the two-level
// hierarchical unit form `unit { 0 { vlan-id; inner-vlan-id; } }` and the
// flat `unit 0 point-to-point inner-vlan-id ...` form, while the compiler
// compiled both tags (two-level: VlanID/InnerVlanID via namedInstances
// descending into `0`; flat-nested: the inner leaf nested under the
// point-to-point child). Both forms therefore committed unsupported QinQ
// (or, for the flat form, proved the compiler reads a nested spelling the
// gate never saw) while the single-level control was correctly rejected.
//
// FAIL-ON-REVERT: reverting the namedInstances enumeration in
// collectQinQFromInterfacesNode (back to direct `unit` children) makes the
// two-level cells accept; reverting the recursive leaf scan in
// unitVLANStack makes the flat-nested cell accept.

// TestQinQTwoLevelUnitAndNestedFlatRunRejected is the decisive regression
// named in #14683: the two-level form must strict-error, and the flat
// nested form must strict-error (not silently compile).
func TestQinQTwoLevelUnitAndNestedFlatRunRejected(t *testing.T) {
	// Two-level hierarchical: unit { 0 { ... } }.
	mustReject5879(t, hierTree(t, `interfaces {
    ge-0/0/0 {
        vlan-tagging;
        unit {
            0 {
                vlan-id 100;
                inner-vlan-id 200;
                family inet { address 10.0.1.1/24; }
            }
        }
    }
}`))

	// Two-level with vlan-tags spelling.
	mustReject5879(t, hierTree(t, `interfaces {
    ge-0/0/0 {
        vlan-tagging;
        unit {
            0 {
                vlan-tags outer 100 inner 200;
                family inet { address 10.0.1.1/24; }
            }
        }
    }
}`))

	// Flat nested: `unit 0 point-to-point inner-vlan-id 200` packs the
	// inner leaf under the point-to-point child; the compiler compiles it
	// (probe: lenient VlanID/InnerVlanID), so the gate must see it too.
	mustReject5879(t, flatTreeFromSets(t,
		"set interfaces ge-0/0/0 unit 0 point-to-point inner-vlan-id 200",
		"set interfaces ge-0/0/0 unit 0 family inet address 10.0.1.1/24",
	))
}

// TestQinQTwoLevelApplyGroupsRejected14683 covers the apply-groups variant:
// the same two-level unit contributed via a group must be caught after
// per-node expansion (collectQinQFindingsForNode shares the collector).
func TestQinQTwoLevelApplyGroupsRejected14683(t *testing.T) {
	mustReject5879(t, hierTree(t, `groups {
    g1 {
        interfaces {
            ge-0/0/0 {
                vlan-tagging;
                unit {
                    0 {
                        vlan-id 100;
                        inner-vlan-id 200;
                        family inet { address 10.0.1.1/24; }
                    }
                }
            }
        }
    }
}
apply-groups g1;
`))
}

// TestQinQTwoLevelLenientWarns14683 pins the #1960 no-brick contract for
// the new shapes: lenient compile warns (naming the QinQ gate) and still
// compiles with both tags, instead of hard-erroring.
func TestQinQTwoLevelLenientWarns14683(t *testing.T) {
	cfg, err := CompileConfigLenient(hierTree(t, `interfaces {
    ge-0/0/0 {
        vlan-tagging;
        unit {
            0 {
                vlan-id 100;
                inner-vlan-id 200;
                family inet { address 10.0.1.1/24; }
            }
        }
    }
}`))
	if err != nil {
		t.Fatalf("lenient compile must not brick on two-level QinQ: %v", err)
	}
	found := false
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "#5879") && strings.Contains(w, "ge-0/0/0") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("lenient compile must warn about two-level QinQ; warnings = %v", cfg.Warnings)
	}
	if ifc := cfg.Interfaces.Interfaces["ge-0/0/0"]; ifc == nil || ifc.Units[0] == nil ||
		ifc.Units[0].VlanID != 100 || ifc.Units[0].InnerVlanID != 200 {
		t.Fatalf("lenient compile must still compile both tags: %+v", cfg.Interfaces.Interfaces["ge-0/0/0"])
	}
}

// TestQinQTwoLevelSingleTagAccepted14683 is the narrowness control: a
// two-level unit with only a single (outer) tag is supported and must
// stay accepted with its value, proving the fix keys on the inner tag
// rather than the two-level shape itself.
func TestQinQTwoLevelSingleTagAccepted14683(t *testing.T) {
	cfg := mustAcceptNoQinQ(t, hierTree(t, `interfaces {
    ge-0/0/0 {
        vlan-tagging;
        unit {
            0 {
                vlan-id 100;
                family inet { address 10.0.1.1/24; }
            }
        }
    }
}`))
	if ifc := cfg.Interfaces.Interfaces["ge-0/0/0"]; ifc == nil || ifc.Units[0] == nil ||
		ifc.Units[0].VlanID != 100 || ifc.Units[0].InnerVlanID != 0 {
		t.Fatalf("single-tag two-level unit must compile with VlanID=100 Inner=0: %+v", cfg.Interfaces.Interfaces["ge-0/0/0"])
	}
}
