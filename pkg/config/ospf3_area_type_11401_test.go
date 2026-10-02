package config

import (
	"testing"
)

// #11401: `protocols ospf3 area <id> area-type { stub | nssa }` was silently
// dropped — OSPFv3Area carried no AreaType/NoSummary, the ospf3 area schema
// declared no area-type child, the compiler loop read only
// interface/router-id/export, and the renderer emitted no `area` line under
// `router ospf6`. The stub area flooded as a normal area.
//
// These cells mirror TestAreaTypeIsReadFromEverySpelling9656 (the OSPFv2 M26
// family): every spelling an operator can write must reach the compiled area,
// and an area that declares no type must stay normal.
func TestOSPFv3AreaTypeIsReadFromEverySpelling11401(t *testing.T) {
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
		// leaf.
		"braced leaf stub":         {"        area 0.0.0.1 {\n            area-type stub;\n        }", "stub", false},
		"braced leaf no-summaries": {"        area 0.0.0.1 {\n            area-type stub no-summaries;\n        }", "stub", true},
		// The `show configuration` spelling: braced container.
		"braced container stub": {"        area 0.0.0.1 {\n            area-type {\n                stub;\n            }\n        }", "stub", false},
		// `stub no-summaries;` inside the container arrives as one node with
		// Keys=["stub","no-summaries"] and no children; FindChild alone
		// cannot see it (the #9656 packed branch).
		"braced container with packed leaf": {"        area 0.0.0.1 {\n            area-type {\n                stub no-summaries;\n            }\n        }", "stub", true},
		"braced container nssa with no-summaries": {"        area 0.0.0.1 {\n            area-type {\n                nssa {\n                    no-summaries;\n                }\n            }\n        }", "nssa", true},
	} {
		t.Run(name, func(t *testing.T) {
			area := ospf3Area11401(t, tc.body)
			if area.AreaType != tc.wantType {
				t.Errorf("AreaType = %q, want %q — a %s area rendered as a NORMAL area floods the LSAs it exists to suppress (#11401)",
					area.AreaType, tc.wantType, tc.wantType)
			}
			if area.NoSummary != tc.wantNoSumm {
				t.Errorf("NoSummary = %v, want %v", area.NoSummary, tc.wantNoSumm)
			}
		})
	}
}

// TestOSPFv3AreaWithNoAreaTypeStaysNormal11401 is the NEGATIVE control: every
// row above asserts a NON-empty AreaType, so a fix that unconditionally
// assigned "stub" would pass all of them. This is the only row that fails on
// that mutant.
func TestOSPFv3AreaWithNoAreaTypeStaysNormal11401(t *testing.T) {
	area := ospf3Area11401(t, "        area 0.0.0.1 {\n            interface ge-0/0/0.0;\n        }")
	if area.AreaType != "" {
		t.Errorf("AreaType = %q for an area that declares none; a normal area must stay normal", area.AreaType)
	}
	if area.NoSummary {
		t.Error("NoSummary set on an area that declares no area-type")
	}
}

// TestOSPFv3AreaTypeSetSyntax11401 pins the set-channel spelling: each area
// keeps its own type and the no-summaries flag rides the same line.
func TestOSPFv3AreaTypeSetSyntax11401(t *testing.T) {
	cmds := []string{
		"set protocols ospf3 area 0.0.0.0 interface trust0",
		"set protocols ospf3 area 0.0.0.1 interface dmz0",
		"set protocols ospf3 area 0.0.0.1 area-type stub",
		"set protocols ospf3 area 0.0.0.2 interface untrust0",
		"set protocols ospf3 area 0.0.0.2 area-type nssa",
		"set protocols ospf3 area 0.0.0.3 interface tunnel0",
		"set protocols ospf3 area 0.0.0.3 area-type stub no-summaries",
	}
	tree := &ConfigTree{}
	for _, cmd := range cmds {
		path, err := ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		tree.SetPath(path)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	ospf3 := cfg.Protocols.OSPFv3
	if ospf3 == nil {
		t.Fatal("expected OSPFv3 config, got nil")
	}
	if len(ospf3.Areas) != 4 {
		t.Fatalf("expected 4 areas, got %d", len(ospf3.Areas))
	}
	if ospf3.Areas[0].AreaType != "" {
		t.Errorf("area 0 should have no type, got %q", ospf3.Areas[0].AreaType)
	}
	if ospf3.Areas[1].AreaType != "stub" {
		t.Errorf("area 1 AreaType: got %q, want stub", ospf3.Areas[1].AreaType)
	}
	if ospf3.Areas[1].NoSummary {
		t.Error("area 1 should not have NoSummary")
	}
	if ospf3.Areas[2].AreaType != "nssa" {
		t.Errorf("area 2 AreaType: got %q, want nssa", ospf3.Areas[2].AreaType)
	}
	if ospf3.Areas[3].AreaType != "stub" {
		t.Errorf("area 3 AreaType: got %q, want stub", ospf3.Areas[3].AreaType)
	}
	if !ospf3.Areas[3].NoSummary {
		t.Error("area 3 should have NoSummary")
	}
}

// TestOSPFv3AreaTypeInRoutingInstance11401 pins the shared protocols schema
// and compiler path used beneath routing-instances as well as at top level.
func TestOSPFv3AreaTypeInRoutingInstance11401(t *testing.T) {
	tree, errs := NewParser(`routing-instances {
    RI {
        instance-type virtual-router;
        protocols {
            ospf3 {
                area 0.0.0.8 area-type nssa no-summaries;
            }
        }
    }
}`).Parse()
	if len(errs) > 0 {
		t.Fatalf("fixture must parse: %v", errs[0])
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	if len(cfg.RoutingInstances) != 1 || cfg.RoutingInstances[0].OSPFv3 == nil ||
		len(cfg.RoutingInstances[0].OSPFv3.Areas) != 1 {
		t.Fatalf("fixture produced no routing-instance OSPFv3 area: %+v", cfg.RoutingInstances)
	}
	area := cfg.RoutingInstances[0].OSPFv3.Areas[0]
	if area.ID != "0.0.0.8" || area.AreaType != "nssa" || !area.NoSummary {
		t.Fatalf("routing-instance OSPFv3 area = %+v, want nssa no-summary", area)
	}
}

func ospf3Area11401(t *testing.T, body string) *OSPFv3Area {
	t.Helper()
	tree, errs := NewParser("protocols {\n    ospf3 {\n" + body + "\n    }\n}").Parse()
	if len(errs) > 0 {
		t.Fatalf("fixture must parse: %v", errs[0])
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	if cfg.Protocols.OSPFv3 == nil || len(cfg.Protocols.OSPFv3.Areas) != 1 {
		t.Fatalf("fixture produced %+v, so this cell is vacuous", cfg.Protocols.OSPFv3)
	}
	return cfg.Protocols.OSPFv3.Areas[0]
}
