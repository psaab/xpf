package config

import (
	"reflect"
	"testing"
)

// #14442 (DR18-H6): interface-level leaf-run tail — `disable` as a
// non-first leaf is dropped.
//
//	interfaces { ge-0/0/0 description "uplink" disable; }   packed, disable non-first
//	interfaces { ge-0/0/0 { description "uplink"; disable; } }  braced twin
//
// Before the fix compileInterfaces read interface-level leaves off the
// raw child (FindChild over Children). A packed tail lives on the
// interface node's own Keys with no Children, so only a leaf exposed
// by the #9792 nested-run expansion (description) was seen: `disable`
// after it vanished, and a packed interface with no bandwidth was
// skipped entirely (`if child.IsLeaf && bandwidthNode == nil`). The
// flat-set spelling `set interfaces ge-0/0/0 description uplink
// disable` nests disable under description, where
// packedOrNestedLeafRun9792 refuses to expand (description is scalar,
// so strict rejects the trailing token, but CompileConfig /
// CompileConfigLenient directly — the tolerant load / HA-sync path —
// dropped it). An operator's admin-down therefore compiled to an
// enabled interface.
func TestInterfaceDisableNonFirstPacked14442(t *testing.T) {
	compileBrace := func(t *testing.T, body string) *InterfaceConfig {
		t.Helper()
		tree, errs := NewParser(body).Parse()
		if len(errs) > 0 {
			t.Fatalf("parse %q: %v", body, errs)
		}
		cfg, err := CompileConfig(tree)
		if err != nil {
			t.Fatalf("CompileConfig(%q): %v", body, err)
		}
		return cfg.Interfaces.Interfaces["ge-0/0/0"]
	}
	compileBraceLenient := func(t *testing.T, body string) *InterfaceConfig {
		t.Helper()
		tree, errs := NewParser(body).Parse()
		if len(errs) > 0 {
			t.Fatalf("parse %q: %v", body, errs)
		}
		cfg, err := CompileConfigLenient(tree)
		if err != nil {
			t.Fatalf("CompileConfigLenient(%q): %v", body, err)
		}
		return cfg.Interfaces.Interfaces["ge-0/0/0"]
	}

	// Braced reference arm: always worked.
	ref := compileBrace(t, `interfaces { ge-0/0/0 { description "uplink"; disable; } }`)
	if ref == nil || !ref.Disable || ref.Description != "uplink" {
		t.Fatalf("braced reference arm broken (%+v); comparison meaningless (#14442)", ref)
	}
	// disable-first braced control: unchanged.
	first := compileBrace(t, `interfaces { ge-0/0/0 { disable; description "uplink"; } }`)
	if first == nil || !first.Disable || first.Description != "uplink" {
		t.Fatalf("disable-first braced control broken (%+v) (#14442)", first)
	}

	packed := []string{
		`interfaces { ge-0/0/0 description "uplink" disable; }`,
		`interfaces { ge-0/0/0 disable description "uplink"; }`,
		`interfaces { ge-0/0/0 { description "uplink" disable; } }`,
		`interfaces { ge-0/0/0 mtu 9000 disable; }`,
		`interfaces { ge-0/0/0 disable mtu 9000; }`,
		`interfaces { ge-0/0/0 description "uplink" disable unit 0 family inet address 10.0.0.1/24; }`,
	}
	for _, body := range packed {
		ifc := compileBrace(t, body)
		if ifc == nil {
			t.Errorf("%q: interface dropped entirely, want present with Disable=true (#14442)", body)
			continue
		}
		if !ifc.Disable {
			t.Errorf("%q: Disable=false, want true (non-first disable dropped) (#14442)", body)
		}
	}
	// Packed forms must compile identically to the braced twin.
	for _, body := range []string{
		`interfaces { ge-0/0/0 description "uplink" disable; }`,
		`interfaces { ge-0/0/0 disable description "uplink"; }`,
		`interfaces { ge-0/0/0 { description "uplink" disable; } }`,
	} {
		ifc := compileBrace(t, body)
		if !reflect.DeepEqual(ifc, ref) {
			t.Errorf("%q: compiled %+v, want identical to braced twin %+v (#14442)", body, ifc, ref)
		}
		lenient := compileBraceLenient(t, body)
		if !reflect.DeepEqual(lenient, ref) {
			t.Errorf("lenient %q: compiled %+v, want identical to braced twin %+v (#14442)", body, lenient, ref)
		}
	}
	// Non-first leaf beyond disable: mtu after/before disable.
	if ifc := compileBrace(t, `interfaces { ge-0/0/0 mtu 9000 disable; }`); ifc == nil || ifc.MTU != 9000 || !ifc.Disable {
		t.Errorf("mtu-then-disable packed: got %+v, want MTU=9000 Disable=true (#14442)", ifc)
	}
	if ifc := compileBrace(t, `interfaces { ge-0/0/0 disable mtu 9000; }`); ifc == nil || ifc.MTU != 9000 || !ifc.Disable {
		t.Errorf("disable-then-mtu packed: got %+v, want MTU=9000 Disable=true (#14442)", ifc)
	}
	// Packed tail carrying a unit: unit + address survive beside disable.
	if ifc := compileBrace(t, `interfaces { ge-0/0/0 description "uplink" disable unit 0 family inet address 10.0.0.1/24; }`); ifc == nil || !ifc.Disable || len(ifc.Units) != 1 {
		t.Errorf("packed with unit: got %+v, want Disable=true with 1 unit (#14442)", ifc)
	} else if u := ifc.Units[0]; u == nil || len(u.Addresses) == 0 {
		t.Errorf("packed with unit: unit 0 = %+v, want address 10.0.0.1/24 (#14442)", u)
	}

	// Flat-set axis: one `set` line nests disable under description.
	for _, cmds := range [][]string{
		{"set interfaces ge-0/0/0 description uplink disable"},
		{"set interfaces ge-0/0/0 disable description uplink"},
	} {
		for _, lenient := range []bool{false, true} {
			tree := setTree(t, cmds...)
			var cfg *Config
			var err error
			if lenient {
				cfg, err = CompileConfigLenient(tree)
			} else {
				cfg, err = CompileConfig(tree)
			}
			if err != nil {
				t.Fatalf("set %v lenient=%v: %v", cmds, lenient, err)
			}
			ifc := cfg.Interfaces.Interfaces["ge-0/0/0"]
			if ifc == nil || !ifc.Disable || ifc.Description != "uplink" {
				t.Errorf("set %v lenient=%v: got %+v, want Disable=true Description=uplink (#14442)", cmds, lenient, ifc)
			}
		}
	}
	// Flat-set oracle (separate lines) control: unchanged.
	tree := setTree(t, "set interfaces ge-0/0/0 description uplink", "set interfaces ge-0/0/0 disable")
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("flat oracle: %v", err)
	}
	if ifc := cfg.Interfaces.Interfaces["ge-0/0/0"]; ifc == nil || !ifc.Disable || ifc.Description != "uplink" {
		t.Errorf("flat oracle control broken: %+v (#14442)", ifc)
	}
	// No-disable control: packed without disable stays enabled.
	if ifc := compileBrace(t, `interfaces { ge-0/0/0 description "uplink"; }`); ifc == nil || ifc.Disable {
		t.Errorf("no-disable braced control: got %+v, want present Disable=false (#14442)", ifc)
	}
	if ifc := compileBrace(t, `interfaces { ge-0/0/0 description "uplink" mtu 9000; }`); ifc == nil || ifc.Disable || ifc.MTU != 9000 {
		t.Errorf("no-disable packed control: got %+v, want present Disable=false MTU=9000 (#14442)", ifc)
	}
}
