package config

import (
	"strings"
	"testing"
)

// Tests for #16433: `vlan-tags outer N <anything>` committed as a plain
// single-tag VlanID=N. The Junos inner spellings `inner-list`,
// `inner-range` and `inner-vlan-id-range` carry no exact `inner` token,
// so the #5879 QinQ gate counted the statement as an outer single tag,
// and the #15035 reader took `vals[0]` after `outer` and ignored every
// trailing token — `outer 100 bogus 7` committed too.
//
// Fix: the `vlan-tags` world is closed. vlanTagsIsInner matches `inner`
// and any `inner-*` token (existing QinQ reject text); vlanTagsIsOuterOnly
// admits exactly `outer <one value>` in every AST shape; any other
// `vlan-tags` node is an invalid finding rejected by the QinQ gate, and
// the #15035 reader skips every non-outer-only node. RED on pre-fix:
// every reject row below compiled with VlanID=100.

var vlanTagsForms16433 = []struct {
	name  string
	flat  string
	hier  string
	inner bool
}{
	{"inner-range", "vlan-tags outer 100 inner-range 1-200", "vlan-tags outer 100 inner-range 1-200;", true},
	{"inner-list-bracket", "vlan-tags outer 100 inner-list [ 10 20 ]", "vlan-tags outer 100 inner-list [ 10 20 ];", true},
	{"inner-list-values", "vlan-tags outer 100 inner-list 10 20", "vlan-tags outer 100 inner-list 10 20;", true},
	{"inner-vlan-id-range", "vlan-tags outer 100 inner-vlan-id-range 1-200", "vlan-tags outer 100 inner-vlan-id-range 1-200;", true},
	{"inner-bogus-prefix", "vlan-tags outer 100 inner-bogus 7", "vlan-tags outer 100 inner-bogus 7;", true},
	{"bogus-tail", "vlan-tags outer 100 bogus 7", "vlan-tags outer 100 bogus 7;", false},
	{"extra-value", "vlan-tags outer 100 200", "vlan-tags outer 100 200;", false},
	{"inner-keyword", "vlan-tags outer 100 inner 200", "vlan-tags outer 100 inner 200;", true},
}

func flatVlanTagsTree16433(t *testing.T, tail string) *ConfigTree {
	t.Helper()
	return flatTreeFromSets(t,
		"set interfaces ge-0/0/0 flexible-vlan-tagging",
		"set interfaces ge-0/0/0 unit 0 "+tail,
		"set interfaces ge-0/0/0 unit 0 family inet address 10.0.1.1/24",
	)
}

func hierVlanTagsTree16433(t *testing.T, stmt string) *ConfigTree {
	t.Helper()
	return hierTree(t, `interfaces {
    ge-0/0/0 {
        flexible-vlan-tagging;
        unit 0 {
            `+stmt+`
            family inet { address 10.0.1.1/24; }
        }
    }
}`)
}

func hierBlockVlanTagsTree16433(t *testing.T, block string) *ConfigTree {
	t.Helper()
	return hierTree(t, `interfaces {
    ge-0/0/0 {
        flexible-vlan-tagging;
        unit 0 {
            vlan-tags { `+block+` }
            family inet { address 10.0.1.1/24; }
        }
    }
}`)
}

func assertReject16433(t *testing.T, tree *ConfigTree, inner bool) {
	t.Helper()
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatalf("expected strict compile to reject, got nil error")
	}
	if inner {
		if !strings.Contains(err.Error(), "#5879") || !strings.Contains(err.Error(), "QinQ") {
			t.Fatalf("inner spelling: error %q does not name the #5879 QinQ gate", err.Error())
		}
		if !strings.Contains(err.Error(), "vlan-tags") {
			t.Fatalf("inner spelling: error %q does not name vlan-tags", err.Error())
		}
		return
	}
	if !strings.Contains(err.Error(), "#16433") || !strings.Contains(err.Error(), "vlan-tags") {
		t.Fatalf("malformed spelling: error %q does not name vlan-tags / #16433", err.Error())
	}
	if strings.Contains(err.Error(), "QinQ") {
		t.Fatalf("malformed spelling must not use the QinQ text, got %q", err.Error())
	}
}

func TestVlanTagsInnerSpellingsRejected16433(t *testing.T) {
	for _, tc := range vlanTagsForms16433 {
		t.Run("flat/"+tc.name, func(t *testing.T) {
			assertReject16433(t, flatVlanTagsTree16433(t, tc.flat), tc.inner)
		})
		t.Run("hier/"+tc.name, func(t *testing.T) {
			assertReject16433(t, hierVlanTagsTree16433(t, tc.hier), tc.inner)
		})
	}
	assertReject16433(t, hierBlockVlanTagsTree16433(t, "outer 100; inner-range 1-200;"), true)
	assertReject16433(t, hierBlockVlanTagsTree16433(t, "outer 100; inner-list 10 20;"), true)
	assertReject16433(t, hierBlockVlanTagsTree16433(t, "outer 100; bogus 7;"), false)
	assertReject16433(t, hierBlockVlanTagsTree16433(t, "outer { 100; } bogus;"), false)
	assertReject16433(t, flatTreeFromSets(t,
		"set interfaces ge-0/0/0 flexible-vlan-tagging",
		"set interfaces ge-0/0/0 unit 0 vlan-tags outer 100",
		"set interfaces ge-0/0/0 unit 0 vlan-tags inner-range 1-200",
		"set interfaces ge-0/0/0 unit 0 family inet address 10.0.1.1/24",
	), true)
	assertReject16433(t, hierVlanTagsTree16433(t, "vlan-tags bogus;"), false)
	assertReject16433(t, flatVlanTagsTree16433(t, "vlan-tags outer 0 bogus"), false)
}

func TestVlanTagsOuterOnlyStillCompiles16433(t *testing.T) {
	if u := compileVlanUnit15035(t, flatVlanTagsTree16433(t, "vlan-tags outer 100"), "ge-0/0/0", 0); u.VlanID != 100 || u.InnerVlanID != 0 {
		t.Fatalf("flat outer-only: VlanID=%d Inner=%d, want 100/0", u.VlanID, u.InnerVlanID)
	}
	if u := compileVlanUnit15035(t, hierVlanTagsTree16433(t, "vlan-tags outer 100;"), "ge-0/0/0", 0); u.VlanID != 100 {
		t.Fatalf("hier outer-only: VlanID=%d, want 100", u.VlanID)
	}
	if u := compileVlanUnit15035(t, hierBlockVlanTagsTree16433(t, "outer 100;"), "ge-0/0/0", 0); u.VlanID != 100 {
		t.Fatalf("block outer-only: VlanID=%d, want 100", u.VlanID)
	}
	if u := compileVlanUnit15035(t, hierBlockVlanTagsTree16433(t, "outer { 100; }"), "ge-0/0/0", 0); u.VlanID != 100 {
		t.Fatalf("one-deeper outer-only: VlanID=%d, want 100", u.VlanID)
	}
	if u := compileVlanUnit15035(t, flatVlanTagsTree16433(t, "vlan-tags outer 0"), "ge-0/0/0", 0); u.VlanID != 0 {
		t.Fatalf("outer 0: VlanID=%d, want 0", u.VlanID)
	}
	_, err := CompileConfig(flatVlanTagsTree16433(t, "vlan-tags outer 0x88a8.100"))
	if err == nil || !strings.Contains(err.Error(), "#15035") {
		t.Fatalf("TPID outer: expected #15035 reject, got %v", err)
	}
}

func TestVlanTagsClosedWorldLenient16433(t *testing.T) {
	cfg, err := CompileConfigLenient(flatVlanTagsTree16433(t, "vlan-tags outer 100 inner-range 1-200"))
	if err != nil {
		t.Fatalf("lenient inner-range must not brick: %v", err)
	}
	found := false
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "#5879") {
			found = true
		}
	}
	if !found {
		t.Fatalf("lenient inner-range: expected #5879 warning, warnings=%v", cfg.Warnings)
	}
	if u := cfg.Interfaces.Interfaces["ge-0/0/0"].Units[0]; u == nil || u.VlanID != 0 {
		t.Fatalf("lenient inner-range: unit must survive untagged, got %+v", u)
	}
	cfg, err = CompileConfigLenient(flatVlanTagsTree16433(t, "vlan-tags outer 100 bogus 7"))
	if err != nil {
		t.Fatalf("lenient bogus tail must not brick: %v", err)
	}
	found = false
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "#16433") {
			found = true
		}
	}
	if !found {
		t.Fatalf("lenient bogus tail: expected #16433 warning, warnings=%v", cfg.Warnings)
	}
	if u := cfg.Interfaces.Interfaces["ge-0/0/0"].Units[0]; u == nil || u.VlanID != 0 {
		t.Fatalf("lenient bogus tail: unit must survive untagged, got %+v", u)
	}
	cfg, err = CompileConfigLenient(flatTreeFromSets(t,
		"set interfaces ge-0/0/0 flexible-vlan-tagging",
		"set interfaces ge-0/0/0 unit 0 vlan-tags outer 100 bogus 7",
		"set interfaces ge-0/0/0 unit 0 vlan-tags outer 100",
		"set interfaces ge-0/0/0 unit 0 family inet address 10.0.1.1/24",
	))
	if err != nil {
		t.Fatalf("lenient mixed statements must not brick: %v", err)
	}
	if u := cfg.Interfaces.Interfaces["ge-0/0/0"].Units[0]; u == nil || u.VlanID != 100 {
		t.Fatalf("lenient mixed: valid sibling must apply VlanID=100, got %+v", u)
	}
}

func TestVlanTagsOuterOnlyPredicate16433(t *testing.T) {
	cases := []struct {
		node *Node
		want bool
	}{
		{&Node{Keys: []string{"vlan-tags", "outer", "100"}}, true},
		{&Node{Keys: []string{"vlan-tags", "outer"}}, false},
		{&Node{Keys: []string{"vlan-tags", "outer", "100", "bogus"}}, false},
		{&Node{Keys: []string{"vlan-tags"}}, false},
		{&Node{Keys: []string{"vlan-tags"}, Children: []*Node{{Keys: []string{"outer", "100"}}}}, true},
		{&Node{Keys: []string{"vlan-tags"}, Children: []*Node{{Keys: []string{"outer"}}}}, false},
		{&Node{Keys: []string{"vlan-tags"}, Children: []*Node{{Keys: []string{"outer"}, Children: []*Node{{Keys: []string{"100"}}}}}}, true},
		{&Node{Keys: []string{"vlan-tags"}, Children: []*Node{{Keys: []string{"outer"}, Children: []*Node{{Keys: []string{"100"}}, {Keys: []string{"200"}}}}}}, false},
		{&Node{Keys: []string{"vlan-tags"}, Children: []*Node{{Keys: []string{"outer", "100"}}, {Keys: []string{"bogus"}}}}, false},
	}
	for i, tc := range cases {
		if got := vlanTagsIsOuterOnly(tc.node); got != tc.want {
			t.Errorf("case %d: vlanTagsIsOuterOnly = %v, want %v", i, got, tc.want)
		}
	}
}
