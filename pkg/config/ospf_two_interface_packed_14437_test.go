package config

import "testing"

// ospf_two_interface_packed_14437_test.go — #14437 (DR18-H1).
//
// A packed run carrying TWO OSPF `interface` heads in one statement inside
// a braced area:
//
//	area 0.0.0.0 {
//	    interface ge-0/0/0.0 authentication simple-password "SECRET"
//	        interface ge-0/0/1.0 cost 10;
//	}
//
// arrives as one childless node whose Keys carry the whole run.
// packedBodyChildren bails out whole at the second `interface` token (it is
// declared at no open level of the per-interface call), so the first
// interface compiled with NO properties — AuthType/AuthKey empty, and
// pkg/frr activates every configured interface unconditionally while
// authentication is conditional on AuthType, so the adjacency formed
// UNAUTHENTICATED — and the second interface never existed. The fix splits
// the run at each subsequent unquoted `interface` head
// (splitPackedSiblingInterfaceNodes14437) before the existing
// packedBodyChildren + find-or-create path.
//
// Every cell asserts ABSOLUTE compiled values, not only packed==braced:
// two spellings that both drop the credential would also "agree". The
// braced twin and the single-interface packed control (#7653) pin that the
// split did not change spellings that already worked.
//
// FAIL-ON-REVERT: drop the splitPackedSiblingInterfaceNodes14437 wrap at
// either loop and the corresponding two-interface cells RED (one interface,
// empty auth/cost).

func compile14437(t *testing.T, src string) *Config {
	t.Helper()
	p := NewParser(src)
	tree, errs := p.Parse()
	if len(errs) > 0 {
		t.Fatalf("parse: %v\n%s", errs, src)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v\n%s", err, src)
	}
	return cfg
}

func ospfArea14437(t *testing.T, cfg *Config) *OSPFArea {
	t.Helper()
	if cfg.Protocols.OSPF == nil || len(cfg.Protocols.OSPF.Areas) != 1 {
		t.Fatalf("OSPF areas = %+v, want exactly one", cfg.Protocols.OSPF)
	}
	return cfg.Protocols.OSPF.Areas[0]
}

func TestOSPFv2TwoInterfacesOnePackedRun14437(t *testing.T) {
	packed := compile14437(t, `protocols { ospf { area 0.0.0.0 { interface ge-0/0/0.0 authentication simple-password "SECRET" interface ge-0/0/1.0 cost 10; } } }`)
	area := ospfArea14437(t, packed)
	if len(area.Interfaces) != 2 {
		t.Fatalf("packed two-interface run compiled %d interfaces, want 2: %+v", len(area.Interfaces), area.Interfaces)
	}
	if0, if1 := area.Interfaces[0], area.Interfaces[1]
	if if0.Name != "ge-0/0/0.0" || if0.AuthType != "simple" || string(if0.AuthKey) != "SECRET" {
		t.Errorf("IF1 = {%q auth=%q key=%q}, want {ge-0/0/0.0 simple SECRET} — empty auth activates the adjacency unauthenticated", if0.Name, if0.AuthType, string(if0.AuthKey))
	}
	if if1.Name != "ge-0/0/1.0" || if1.Cost != 10 {
		t.Errorf("IF2 = {%q cost=%d}, want {ge-0/0/1.0 cost 10} — second interface lost", if1.Name, if1.Cost)
	}

	// Braced twin must compile identically.
	braced := compile14437(t, `protocols { ospf { area 0.0.0.0 { interface ge-0/0/0.0 { authentication { simple-password "SECRET"; } } interface ge-0/0/1.0 { cost 10; } } } }`)
	b := ospfArea14437(t, braced)
	if len(b.Interfaces) != 2 {
		t.Fatalf("braced twin compiled %d interfaces, want 2", len(b.Interfaces))
	}
	for i := range area.Interfaces {
		got, want := area.Interfaces[i], b.Interfaces[i]
		if got.Name != want.Name || got.AuthType != want.AuthType || string(got.AuthKey) != string(want.AuthKey) || got.Cost != want.Cost {
			t.Errorf("interface %d packed %+v != braced %+v", i, got, want)
		}
	}
}

func TestOSPFv2TwoInterfacesPackedMD5AndThreeHeads14437(t *testing.T) {
	cfg := compile14437(t, `protocols { ospf { area 0.0.0.0 { interface ge-0/0/0.0 authentication md5 7 key "SECRET" interface ge-0/0/1.0 cost 10 interface ge-0/0/2.0 cost 15; } } }`)
	area := ospfArea14437(t, cfg)
	if len(area.Interfaces) != 3 {
		t.Fatalf("packed three-interface run compiled %d interfaces, want 3", len(area.Interfaces))
	}
	if0 := area.Interfaces[0]
	if if0.Name != "ge-0/0/0.0" || if0.AuthType != "md5" || if0.AuthKeyID != 7 || string(if0.AuthKey) != "SECRET" {
		t.Errorf("IF1 = {%q auth=%q keyID=%d key=%q}, want {ge-0/0/0.0 md5 7 SECRET}", if0.Name, if0.AuthType, if0.AuthKeyID, string(if0.AuthKey))
	}
	if area.Interfaces[1].Name != "ge-0/0/1.0" || area.Interfaces[1].Cost != 10 {
		t.Errorf("IF2 = %+v, want ge-0/0/1.0 cost 10", area.Interfaces[1])
	}
	if area.Interfaces[2].Name != "ge-0/0/2.0" || area.Interfaces[2].Cost != 15 {
		t.Errorf("IF3 = %+v, want ge-0/0/2.0 cost 15", area.Interfaces[2])
	}
}

func TestOSPFv2TwoInterfacesFullyElided14437(t *testing.T) {
	cfg := compile14437(t, `protocols ospf area 0.0.0.0 interface ge-0/0/0.0 authentication simple-password "SECRET" interface ge-0/0/1.0 cost 10;`)
	area := ospfArea14437(t, cfg)
	if len(area.Interfaces) != 2 {
		t.Fatalf("fully-elided run compiled %d interfaces, want 2", len(area.Interfaces))
	}
	if area.Interfaces[0].AuthType != "simple" || string(area.Interfaces[0].AuthKey) != "SECRET" {
		t.Errorf("IF1 auth = %q/%q, want simple/SECRET", area.Interfaces[0].AuthType, string(area.Interfaces[0].AuthKey))
	}
	if area.Interfaces[1].Name != "ge-0/0/1.0" || area.Interfaces[1].Cost != 10 {
		t.Errorf("IF2 = %+v, want ge-0/0/1.0 cost 10", area.Interfaces[1])
	}
}

func TestOSPFv2TwoInterfacesPackedRunFromGroup14437(t *testing.T) {
	// Group-authored spelling: expansion runs before compilation, so the
	// split must fire on the expanded tree exactly as on an inline run.
	cfg := compile14437(t, `
groups { G1 { protocols { ospf { area 0.0.0.0 { interface ge-0/0/0.0 authentication simple-password "SECRET" interface ge-0/0/1.0 cost 10; } } } } }
protocols { ospf { apply-groups G1; } }`)
	area := ospfArea14437(t, cfg)
	if len(area.Interfaces) != 2 {
		t.Fatalf("group packed run compiled %d interfaces, want 2: %+v", len(area.Interfaces), area.Interfaces)
	}
	if area.Interfaces[0].AuthType != "simple" || string(area.Interfaces[0].AuthKey) != "SECRET" {
		t.Errorf("group IF1 auth = %q/%q, want simple/SECRET", area.Interfaces[0].AuthType, string(area.Interfaces[0].AuthKey))
	}
	if area.Interfaces[1].Name != "ge-0/0/1.0" || area.Interfaces[1].Cost != 10 {
		t.Errorf("group IF2 = %+v, want ge-0/0/1.0 cost 10", area.Interfaces[1])
	}
}

func TestOSPFv3TwoInterfacesOnePackedRun14437(t *testing.T) {
	// v3 has no auth leaf; the loss there is the second interface and the
	// first interface's body (availability). Same split, same bailout.
	cfg := compile14437(t, `protocols { ospf3 { area 0.0.0.0 { interface ge-0/0/0.0 cost 5 interface ge-0/0/1.0 cost 10; } } }`)
	if cfg.Protocols.OSPFv3 == nil || len(cfg.Protocols.OSPFv3.Areas) != 1 {
		t.Fatalf("OSPFv3 areas = %+v, want exactly one", cfg.Protocols.OSPFv3)
	}
	ifs := cfg.Protocols.OSPFv3.Areas[0].Interfaces
	if len(ifs) != 2 {
		t.Fatalf("packed v3 two-interface run compiled %d interfaces, want 2: %+v", len(ifs), ifs)
	}
	if ifs[0].Name != "ge-0/0/0.0" || ifs[0].Cost != 5 {
		t.Errorf("v3 IF1 = %+v, want ge-0/0/0.0 cost 5", ifs[0])
	}
	if ifs[1].Name != "ge-0/0/1.0" || ifs[1].Cost != 10 {
		t.Errorf("v3 IF2 = %+v, want ge-0/0/1.0 cost 10", ifs[1])
	}
}

func TestOSPFPackedControlsUnchanged14437(t *testing.T) {
	// Single-interface packed auth (#7653) must be unchanged by the split.
	single := compile14437(t, `protocols { ospf { area 0.0.0.0 { interface ge-0/0/0.0 authentication simple-password "SECRET"; } } }`)
	area := ospfArea14437(t, single)
	if len(area.Interfaces) != 1 || area.Interfaces[0].AuthType != "simple" || string(area.Interfaces[0].AuthKey) != "SECRET" {
		t.Errorf("single packed = %+v, want one interface simple/SECRET (#7653)", area.Interfaces)
	}

	// Same-name find-or-create (#8436): two braced blocks naming the SAME
	// interface still merge into one entry.
	dup := compile14437(t, `protocols { ospf { area 0.0.0.0 { interface ge-0/0/0.0 { cost 5; } interface ge-0/0/0.0 { hello-interval 3; } } } }`)
	darea := ospfArea14437(t, dup)
	if len(darea.Interfaces) != 1 || darea.Interfaces[0].Cost != 5 || darea.Interfaces[0].HelloInterval != 3 {
		t.Errorf("same-name braced merge = %+v, want one interface cost 5 hello 3 (#8436)", darea.Interfaces)
	}

	// A quoted instance name spelled "interface" is a name, not a head:
	// splitting there would invent a nameless interface and lose the body.
	quoted := compile14437(t, `protocols { ospf { area 0.0.0.0 { interface "interface" authentication simple-password "SECRET" interface ge-0/0/1.0 cost 10; } } }`)
	qarea := ospfArea14437(t, quoted)
	if len(qarea.Interfaces) != 2 {
		t.Fatalf("quoted-name run compiled %d interfaces, want 2: %+v", len(qarea.Interfaces), qarea.Interfaces)
	}
	if qarea.Interfaces[0].Name != "interface" || qarea.Interfaces[0].AuthType != "simple" || string(qarea.Interfaces[0].AuthKey) != "SECRET" {
		t.Errorf("quoted-name IF1 = %+v, want name \"interface\" simple/SECRET", qarea.Interfaces[0])
	}
	if qarea.Interfaces[1].Name != "ge-0/0/1.0" || qarea.Interfaces[1].Cost != 10 {
		t.Errorf("quoted-name IF2 = %+v, want ge-0/0/1.0 cost 10", qarea.Interfaces[1])
	}
}

func TestSplitPackedSiblingInterfaceNodesUnit14437(t *testing.T) {
	// No split: single head and braced (Children-carrying) nodes pass
	// through as the identical slice/pointer.
	single := &Node{Keys: []string{"interface", "ge-0/0/0.0", "cost", "5"}, IsLeaf: true}
	if got := splitPackedSiblingInterfaceNodes14437([]*Node{single}); len(got) != 1 || got[0] != single {
		t.Errorf("single-head run was split: %v", got)
	}
	braced := &Node{Keys: []string{"interface", "ge-0/0/0.0"}, Children: []*Node{{Keys: []string{"cost", "5"}}}}
	if got := splitPackedSiblingInterfaceNodes14437([]*Node{braced}); len(got) != 1 || got[0] != braced {
		t.Errorf("braced node was split: %v", got)
	}
	// Split preserves order, keys, and quote provenance per fragment, and
	// never mutates the input.
	run := &Node{Keys: []string{"interface", "ge-0/0/0.0", "authentication", "simple-password", "SECRET", "interface", "ge-0/0/1.0", "cost", "10"}, IsLeaf: true}
	run.setKeysQuoted([]bool{false, false, false, false, true, false, false, false, false})
	frags := splitPackedSiblingInterfaceNodes14437([]*Node{run})
	if len(frags) != 2 {
		t.Fatalf("fragments = %d, want 2", len(frags))
	}
	if len(run.Keys) != 9 {
		t.Errorf("input mutated: Keys=%q", run.Keys)
	}
	want0 := []string{"interface", "ge-0/0/0.0", "authentication", "simple-password", "SECRET"}
	if len(frags[0].Keys) != len(want0) {
		t.Fatalf("frag0 Keys=%q", frags[0].Keys)
	}
	for i, w := range want0 {
		if frags[0].Keys[i] != w {
			t.Errorf("frag0 Keys[%d]=%q want %q", i, frags[0].Keys[i], w)
		}
	}
	if !frags[0].KeyQuoted(4) {
		t.Errorf("frag0 lost quote provenance for SECRET")
	}
	if frags[1].Keys[1] != "ge-0/0/1.0" || frags[1].KeyQuoted(0) {
		t.Errorf("frag1 = %q quoted0=%v", frags[1].Keys, frags[1].KeyQuoted(0))
	}
}
