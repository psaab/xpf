package config

import (
	"reflect"
	"testing"
)

// #14427 (DR16-H6): OSPF top level, `passive` first on the ospf line.
//
//	packed: ospf passive router-id 1.1.1.1 { area ... }
//	mixed (spec text): ospf { passive router-id 1.1.1.1; area ... }
//	braced: ospf { passive; router-id 1.1.1.1; area ... }
//
// The ospf-line form packs the whole body onto ospfNode.Keys, so the
// Children-only reader at the OSPF top loop saw no children: PassiveDefault
// stayed false and RouterID empty while the braced area child survived,
// so ospfd formed adjacencies on interfaces the operator made passive.
// The nested packed statement inside a braced ospf block is already read
// (expandFlatRun splits its Keys); it is a control here, not the defect.

func compileOSPFPacked14427(t *testing.T, src string) *Config {
	t.Helper()
	cfg, err := CompileConfig(hierTree(t, src))
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	if cfg == nil || cfg.Protocols.OSPF == nil {
		t.Fatalf("OSPF not compiled from %q", src)
	}
	return cfg
}

func TestOSPFPackedTopPassiveFirst14427(t *testing.T) {
	braced := compileOSPFPacked14427(t, "protocols {\n ospf {\n  passive;\n  router-id 1.1.1.1;\n  area 0.0.0.0 {\n   interface ge-0/0/0.0;\n  }\n }\n}\n")
	if !braced.Protocols.OSPF.PassiveDefault || braced.Protocols.OSPF.RouterID != "1.1.1.1" {
		t.Fatalf("braced control broken: %+v", braced.Protocols.OSPF)
	}
	if len(braced.Protocols.OSPF.Areas) != 1 || len(braced.Protocols.OSPF.Areas[0].Interfaces) != 1 {
		t.Fatalf("braced control area broken: %+v", braced.Protocols.OSPF.Areas)
	}

	cases := map[string]string{
		// The defect: packed tail on the ospf node itself, braced area body.
		"passive_first_on_ospf_line": "protocols {\n ospf passive router-id 1.1.1.1 {\n  area 0.0.0.0 {\n   interface ge-0/0/0.0;\n  }\n }\n}\n",
		// Same packed tail with no braced body at all.
		"passive_first_ospf_line_only": "protocols {\n ospf passive router-id 1.1.1.1;\n}\n",
		// Control: packed statement inside a braced ospf block (already worked).
		"mixed_inside_braced_ospf": "protocols {\n ospf {\n  passive router-id 1.1.1.1;\n  area 0.0.0.0 {\n   interface ge-0/0/0.0;\n  }\n }\n}\n",
		// Control: single-leaf packed tail on ospf line (census row).
		"passive_only_on_ospf_line": "protocols {\n ospf passive;\n}\n",
	}
	for name, src := range cases {
		t.Run(name, func(t *testing.T) {
			got := compileOSPFPacked14427(t, src)
			if !got.Protocols.OSPF.PassiveDefault {
				t.Errorf("PassiveDefault dropped: got %+v, want passive default (braced twin)", got.Protocols.OSPF)
			}
			if name != "passive_only_on_ospf_line" && got.Protocols.OSPF.RouterID != "1.1.1.1" {
				t.Errorf("RouterID dropped: got %q, want 1.1.1.1", got.Protocols.OSPF.RouterID)
			}
		})
	}

	// Packed-on-ospf-line must equal the braced twin exactly, area included.
	packed := compileOSPFPacked14427(t, cases["passive_first_on_ospf_line"])
	if !reflect.DeepEqual(packed.Protocols.OSPF, braced.Protocols.OSPF) {
		t.Errorf("packed != braced:\n packed=%+v areas=%+v\n braced=%+v areas=%+v",
			packed.Protocols.OSPF, packed.Protocols.OSPF.Areas,
			braced.Protocols.OSPF, braced.Protocols.OSPF.Areas)
	}
}

func TestOSPFPackedTopAreaOnlyStaysFailClosed14427(t *testing.T) {
	// Area-only packed line: after the fix the area is unpacked, so the
	// negative control is NOT that the area drops — it is that no
	// PassiveDefault is invented and no adjacency-relevant default appears.
	// A passive flag must never be synthesized for a line that lacks it.
	got := compileOSPFPacked14427(t, "protocols {\n ospf area 0.0.0.0 interface ge-0/0/0.0;\n}\n")
	if got.Protocols.OSPF.PassiveDefault {
		t.Errorf("area-only packed line invented PassiveDefault: %+v", got.Protocols.OSPF)
	}
	if got.Protocols.OSPF.RouterID != "" {
		t.Errorf("area-only packed line invented RouterID: %q", got.Protocols.OSPF.RouterID)
	}
	if len(got.Protocols.OSPF.Areas) != 1 || len(got.Protocols.OSPF.Areas[0].Interfaces) != 1 ||
		got.Protocols.OSPF.Areas[0].Interfaces[0].Name != "ge-0/0/0.0" {
		t.Errorf("area-only packed line area/interface wrong: %+v", got.Protocols.OSPF.Areas)
	}
}

func TestOSPFPackedTopRoutingInstanceMirror14427(t *testing.T) {
	// compileProtocols is shared by routing-instances; the same packed
	// ospf line under an instance must compile identically.
	src := "routing-instances {\n ri1 {\n  protocols {\n   ospf passive router-id 2.2.2.2 {\n    area 0.0.0.0 {\n     interface ge-0/0/1.0;\n    }\n   }\n  }\n }\n}\n"
	cfg, err := CompileConfig(hierTree(t, src))
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	if len(cfg.RoutingInstances) != 1 || cfg.RoutingInstances[0].OSPF == nil {
		t.Fatalf("routing-instance OSPF not compiled: %+v", cfg.RoutingInstances)
	}
	ospf := cfg.RoutingInstances[0].OSPF
	if !ospf.PassiveDefault || ospf.RouterID != "2.2.2.2" {
		t.Errorf("routing-instance packed ospf dropped: %+v", ospf)
	}
	if len(ospf.Areas) != 1 || len(ospf.Areas[0].Interfaces) != 1 {
		t.Errorf("routing-instance packed ospf area wrong: %+v", ospf.Areas)
	}
}
