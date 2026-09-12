package config

import (
	"strings"
	"testing"
)

// #9656 M26 + M6. Two members of muse-spark-review-008's remainder, both of the
// same family: a value the operator wrote, dropped on a green commit because
// nothing unpacked the statement's packed tail.
//
// They are in one file because they share a PREMISE, not a mechanism: for each,
// the braced spelling is the control, and the elided spelling must reach the
// same verdict as its control — which for M26 is a compiled value and for M6 is
// a REFUSAL. A cell that only checked "the elided form no longer drops the
// value" would be satisfied by either outcome, so each row names which.

func compile9656(t *testing.T, text string) (*Config, error) {
	t.Helper()
	tree, errs := NewParser(text).Parse()
	if len(errs) > 0 {
		t.Fatalf("fixture does not parse, so this cell is vacuous: %v", errs)
	}
	return CompileConfig(tree)
}

func ospfArea9656(t *testing.T, body string) *OSPFArea {
	t.Helper()
	cfg, err := compile9656(t, "protocols {\n    ospf {\n"+body+"\n    }\n}")
	if err != nil {
		t.Fatalf("strict commit refused a supported OSPF area: %v", err)
	}
	if cfg.Protocols.OSPF == nil {
		t.Fatal("fixture produced no OSPF config, so this cell is vacuous")
	}
	if len(cfg.Protocols.OSPF.Areas) != 1 {
		t.Fatalf("want exactly 1 area, got %d", len(cfg.Protocols.OSPF.Areas))
	}
	return cfg.Protocols.OSPF.Areas[0]
}

// TestAreaTypeIsReadFromEverySpelling9656 pins M26.
//
// Measured at 766da5332 BEFORE the fix: the elided and the braced-LEAF
// spellings both committed clean with AreaType="" — a stub or NSSA area
// rendered as a normal area, which floods exactly the Type-5/7 LSAs the
// operator configured it to keep out. Only the braced-CONTAINER spelling
// worked, and it is the one `show configuration` renders, so a save-and-reload
// hid the defect from anyone who looked for it that way.
func TestAreaTypeIsReadFromEverySpelling9656(t *testing.T) {
	for name, tc := range map[string]struct {
		body       string
		wantType   string
		wantNoSumm bool
	}{
		// The spelling the operator types on one line.
		"elided stub":         {"        area 0.0.0.1 area-type stub;", "stub", false},
		"elided nssa":         {"        area 0.0.0.1 area-type nssa;", "nssa", false},
		"elided no-summaries": {"        area 0.0.0.1 area-type stub no-summaries;", "stub", true},
		// A packed tail one level DOWN: the area is braced, the area-type is a
		// leaf. This is the row the pre-#9656 reader could not see either,
		// because it iterated the area-type node's Children and there were none.
		"braced leaf stub":         {"        area 0.0.0.1 {\n            area-type stub;\n        }", "stub", false},
		"braced leaf no-summaries": {"        area 0.0.0.1 {\n            area-type stub no-summaries;\n        }", "stub", true},
		// CONTROL: the spelling that already worked. It must keep working —
		// this is what stops the fix from being a rewrite that trades one
		// readable spelling for another.
		"braced container stub": {"        area 0.0.0.1 {\n            area-type {\n                stub;\n            }\n        }", "stub", false},
		"braced container nssa with no-summaries": {"        area 0.0.0.1 {\n            area-type {\n                nssa {\n                    no-summaries;\n                }\n            }\n        }", "nssa", true},
	} {
		t.Run(name, func(t *testing.T) {
			area := ospfArea9656(t, tc.body)
			if area.AreaType != tc.wantType {
				t.Errorf("AreaType = %q, want %q — a %s area rendered as a NORMAL area floods the LSAs it exists to suppress (#9656 M26)",
					area.AreaType, tc.wantType, tc.wantType)
			}
			if area.NoSummary != tc.wantNoSumm {
				t.Errorf("NoSummary = %v, want %v", area.NoSummary, tc.wantNoSumm)
			}
		})
	}
}

// TestAreaWithNoAreaTypeStaysNormal9656 is the NEGATIVE control for the cell
// above, and it is not optional: every row there asserts a NON-empty AreaType,
// so a fix that unconditionally assigned "stub" would pass all of them. This is
// the only row that fails on that mutant.
func TestAreaWithNoAreaTypeStaysNormal9656(t *testing.T) {
	area := ospfArea9656(t, "        area 0.0.0.1 {\n            interface ge-0/0/0.0;\n        }")
	if area.AreaType != "" {
		t.Errorf("AreaType = %q for an area that declares none; a normal area must stay normal", area.AreaType)
	}
	if area.NoSummary {
		t.Error("NoSummary set on an area that declares no area-type")
	}
}

// TestElidedInnerVlanIsRefusedLikeItsBracedTwin9656 pins M6.
//
// This one INVERTS the family: the elided spelling must be REFUSED, not
// compiled, because its braced twin is refused. Measured at 766da5332 before
// the fix:
//
//	unit 0 { vlan-id 10; inner-vlan-id 20; }   REJECTS (#2354 text)
//	unit 0 { inner-vlan-id 20; }               REJECTS (#2354 text)
//	unit 0 inner-vlan-id 20;                   ACCEPTS, InnerVlanID=0
//
// The green commit was the defect: the appliance cannot enforce a double tag,
// so the frame falls to the kernel forwarding path and is never firewalled,
// and the operator was told nothing.
func TestElidedInnerVlanIsRefusedLikeItsBracedTwin9656(t *testing.T) {
	for name, body := range map[string]string{
		"elided inner only":       "        unit 0 inner-vlan-id 20;",
		"elided inner after vlan": "        unit 0 vlan-id 10 inner-vlan-id 20;",
		"braced twin (control)":   "        unit 0 {\n            inner-vlan-id 20;\n        }",
	} {
		t.Run(name, func(t *testing.T) {
			_, err := compile9656(t, "interfaces {\n    ge-0/0/0 {\n        vlan-tagging;\n"+body+"\n    }\n}")
			if err == nil {
				t.Fatal("strict commit ACCEPTED an unsupported QinQ inner tag; the tag is dropped and a double-tagged frame is never firewalled (#9656 M6)")
			}
			// The message must NAME the spelling, per this issue's acceptance —
			// a bare "invalid configuration" would satisfy the refusal above
			// and leave the operator with no way to act on it.
			if !strings.Contains(err.Error(), "inner-vlan-id 20") {
				t.Errorf("refusal does not name the inner tag the operator wrote: %v", err)
			}
			if !strings.Contains(err.Error(), "#2354") {
				t.Errorf("refusal does not cite the gate that owns this decision: %v", err)
			}
		})
	}
}

// TestSupportedSingleTagStillCommits9656 is the NARROWNESS control for the cell
// above. Admitting `unit <n> inner-vlan-id` to the compact-statement fold scope
// is a change to that scope, and the cheapest way to make the refusal cell green
// would be to refuse more than the inner tag. Single 802.1Q tagging is the
// supported case and must still compile — with its VALUE, which also proves the
// sibling `unit vlan-id` fold did not regress.
func TestSupportedSingleTagStillCommits9656(t *testing.T) {
	for name, tc := range map[string]struct {
		body string
		want int
	}{
		"elided vlan-id": {"        unit 0 vlan-id 10;", 10},
		"braced vlan-id": {"        unit 0 {\n            vlan-id 10;\n        }", 10},
	} {
		t.Run(name, func(t *testing.T) {
			cfg, err := compile9656(t, "interfaces {\n    ge-0/0/0 {\n        vlan-tagging;\n"+tc.body+"\n    }\n}")
			if err != nil {
				t.Fatalf("strict commit refused SUPPORTED single 802.1Q tagging: %v", err)
			}
			ifc := cfg.Interfaces.Interfaces["ge-0/0/0"]
			if ifc == nil {
				t.Fatal("fixture produced no ge-0/0/0, so this cell is vacuous")
			}
			u := ifc.Units[0]
			if u == nil {
				t.Fatal("fixture produced no unit 0, so this cell is vacuous")
			}
			if u.VlanID != tc.want {
				t.Errorf("VlanID = %d, want %d", u.VlanID, tc.want)
			}
			if u.InnerVlanID != 0 {
				t.Errorf("InnerVlanID = %d on a single-tagged unit, want 0", u.InnerVlanID)
			}
		})
	}
}
