package config

import (
	"testing"
)

// #14575 (Y02-03): logical-unit `disable` commits clean and is silently
// discarded. `InterfaceUnit` carried no Disable field, the unit schema had
// no `disable` leaf, and compileInterfaces never read one — so
// `unit 0 disable` in both flat and hierarchical spellings left the unit
// addressed/zoned/forwarding while the commit reported success.
//
// RED on master: Unit.Disable does not exist (compile fails / field false),
// unit 0 keeps 10.0.1.1/24. GREEN after fix: every spelling sets
// Unit.Disable, the interface-level control is unchanged, and a sibling
// enabled unit is untouched.
func TestUnitDisable14575(t *testing.T) {
	hier := func(t *testing.T, body string) *Config {
		t.Helper()
		tree, errs := NewParser(body).Parse()
		if len(errs) > 0 {
			t.Fatalf("parse %q: %v", body, errs)
		}
		if err := SchemaValidate(tree, nil); err != nil {
			t.Fatalf("SchemaValidate(%q): %v", body, err)
		}
		cfg, err := CompileConfig(tree)
		if err != nil {
			t.Fatalf("CompileConfig(%q): %v", body, err)
		}
		return cfg
	}

	cfg := hier(t, `interfaces { ge-0/0/1 { unit 0 { disable; family inet { address 10.0.1.1/24; } } unit 1 { family inet { address 10.0.2.1/24; } } } }`)
	ifc := cfg.Interfaces.Interfaces["ge-0/0/1"]
	if ifc == nil {
		t.Fatal("hier: ge-0/0/1 missing")
	}
	if ifc.Disable {
		t.Error("hier: interface-level Disable=true, want false (only unit 0 disabled)")
	}
	u0, u1 := ifc.Units[0], ifc.Units[1]
	if u0 == nil || !u0.Disable {
		t.Fatalf("hier: unit 0 = %+v, want Disable=true", u0)
	}
	if len(u0.Addresses) != 1 || u0.Addresses[0] != "10.0.1.1/24" {
		t.Errorf("hier: unit 0 addresses = %v, want [10.0.1.1/24] retained in typed config (suppression is at snapshot/apply)", u0.Addresses)
	}
	if u1 == nil || u1.Disable {
		t.Fatalf("hier: sibling unit 1 = %+v, want Disable=false", u1)
	}

	// Flat-set spelling.
	flat := setTree(t,
		"set interfaces ge-0/0/1 unit 0 disable",
		"set interfaces ge-0/0/1 unit 0 family inet address 10.0.1.1/24",
		"set interfaces ge-0/0/1 unit 1 family inet address 10.0.2.1/24",
	)
	if err := SchemaValidate(flat, nil); err != nil {
		t.Fatalf("SchemaValidate flat: %v", err)
	}
	fcfg, err := CompileConfig(flat)
	if err != nil {
		t.Fatalf("CompileConfig flat: %v", err)
	}
	fifc := fcfg.Interfaces.Interfaces["ge-0/0/1"]
	if fifc == nil || fifc.Units[0] == nil || !fifc.Units[0].Disable {
		t.Fatalf("flat: unit 0 = %+v, want Disable=true", fifc)
	}
	if fifc.Units[1] == nil || fifc.Units[1].Disable {
		t.Fatalf("flat: sibling unit 1 must stay enabled: %+v", fifc)
	}

	// Packed tail: `unit 0 disable family inet address ...`.
	pcfg := hier(t, `interfaces { ge-0/0/1 { unit 0 disable family inet address 10.0.1.1/24; } }`)
	if pu := pcfg.Interfaces.Interfaces["ge-0/0/1"].Units[0]; pu == nil || !pu.Disable || len(pu.Addresses) != 1 {
		t.Fatalf("packed: unit 0 = %+v, want Disable=true with address retained", pu)
	}
	// Packed non-first: description before disable.
	pcfg2 := hier(t, `interfaces { ge-0/0/1 { unit 0 { description "x"; disable; family inet { address 10.0.1.1/24; } } } }`)
	if pu := pcfg2.Interfaces.Interfaces["ge-0/0/1"].Units[0]; pu == nil || !pu.Disable {
		t.Fatalf("braced non-first: unit 0 = %+v, want Disable=true", pu)
	}

	// Lenient compile also honours it (tolerant load / peer-sync).
	ltree, errs := NewParser(`interfaces { ge-0/0/1 { unit 0 { disable; family inet { address 10.0.1.1/24; } } } }`).Parse()
	if len(errs) > 0 {
		t.Fatalf("parse lenient: %v", errs)
	}
	lcfg, err := CompileConfigLenient(ltree)
	if err != nil {
		t.Fatalf("CompileConfigLenient: %v", err)
	}
	if lu := lcfg.Interfaces.Interfaces["ge-0/0/1"].Units[0]; lu == nil || !lu.Disable {
		t.Fatalf("lenient: unit 0 = %+v, want Disable=true", lu)
	}

	// Interface-level disable control: unchanged.
	ccfg := hier(t, `interfaces { ge-0/0/1 { disable; unit 0 { family inet { address 10.0.1.1/24; } } } }`)
	cifc := ccfg.Interfaces.Interfaces["ge-0/0/1"]
	if cifc == nil || !cifc.Disable {
		t.Fatalf("control: interface Disable must stay true: %+v", cifc)
	}
	if cifc.Units[0] == nil || cifc.Units[0].Disable {
		t.Fatalf("control: unit 0 must not inherit interface Disable as its own field: %+v", cifc.Units[0])
	}

	// No-disable control.
	ncfg := hier(t, `interfaces { ge-0/0/1 { unit 0 { family inet { address 10.0.1.1/24; } } } }`)
	if nu := ncfg.Interfaces.Interfaces["ge-0/0/1"].Units[0]; nu == nil || nu.Disable {
		t.Fatalf("no-disable control: unit 0 = %+v, want Disable=false", nu)
	}
}
