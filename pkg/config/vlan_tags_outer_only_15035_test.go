package config

import (
	"strings"
	"testing"
)

// Tests for #15035 (A06-02): `vlan-tags outer N` without an inner tag was
// counted as a positive tag by the gates (#5879 treats it as a single
// S-tag, #14574 requires tagging for it) but compileInterfaces only read
// `vlan-id`, so the outer value was silently dropped and the unit compiled
// untagged (VlanID=0). Tagged traffic for the unit is lost after a green
// commit, and on unit 0 untagged frames gain the unit's zone.
//
// Fix: compile the outer value into VlanID (rejecting TPID-prefixed
// values such as `0x88a8.100`, which the single-tag dataplane cannot
// represent), across every AST shape. RED on pre-fix: outer-only cases
// compile with VlanID=0 instead of 100, and the TPID-prefixed case
// compiles clean instead of rejecting.

func compileVlanUnit15035(t *testing.T, tree *ConfigTree, ifName string, unitNum int) *InterfaceUnit {
	t.Helper()
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("expected strict compile to accept, got %v", err)
	}
	ifc := cfg.Interfaces.Interfaces[ifName]
	if ifc == nil {
		t.Fatalf("interface %s not compiled", ifName)
	}
	u := ifc.Units[unitNum]
	if u == nil {
		t.Fatalf("unit %d not compiled on %s (units=%v)", unitNum, ifName, ifc.Units)
	}
	return u
}

func TestVlanTagsOuterOnlyCompilesToVlanID15035(t *testing.T) {
	// Flat-set spelling.
	u := compileVlanUnit15035(t, flatTreeFromSets(t,
		"set interfaces ge-0/0/0 flexible-vlan-tagging",
		"set interfaces ge-0/0/0 unit 0 vlan-tags outer 100",
		"set interfaces ge-0/0/0 unit 0 family inet address 10.0.1.1/24",
	), "ge-0/0/0", 0)
	if u.VlanID != 100 {
		t.Fatalf("flat vlan-tags outer 100: VlanID=%d, want 100", u.VlanID)
	}
	if u.InnerVlanID != 0 {
		t.Fatalf("flat vlan-tags outer 100: InnerVlanID=%d, want 0", u.InnerVlanID)
	}

	// Hierarchical packed spelling: `vlan-tags outer 100;`
	u = compileVlanUnit15035(t, hierTree(t, `interfaces {
    ge-0/0/0 {
        flexible-vlan-tagging;
        unit 0 {
            vlan-tags outer 100;
            family inet { address 10.0.1.1/24; }
        }
    }
}`), "ge-0/0/0", 0)
	if u.VlanID != 100 {
		t.Fatalf("hier vlan-tags outer 100: VlanID=%d, want 100", u.VlanID)
	}

	// Hierarchical block spelling: `vlan-tags { outer 100; }`
	u = compileVlanUnit15035(t, hierTree(t, `interfaces {
    ge-0/0/0 {
        flexible-vlan-tagging;
        unit 0 {
            vlan-tags { outer 100; }
            family inet { address 10.0.1.1/24; }
        }
    }
}`), "ge-0/0/0", 0)
	if u.VlanID != 100 {
		t.Fatalf("hier vlan-tags { outer 100; }: VlanID=%d, want 100", u.VlanID)
	}

	// vlan-tagging (non-flexible) parent, non-zero unit.
	u = compileVlanUnit15035(t, flatTreeFromSets(t,
		"set interfaces ge-0/0/1 vlan-tagging",
		"set interfaces ge-0/0/1 unit 100 vlan-tags outer 100",
		"set interfaces ge-0/0/1 unit 100 family inet address 10.0.1.1/24",
	), "ge-0/0/1", 100)
	if u.VlanID != 100 {
		t.Fatalf("unit 100 vlan-tags outer 100: VlanID=%d, want 100", u.VlanID)
	}
}

func TestVlanTagsOuterZeroStaysUntagged15035(t *testing.T) {
	u := compileVlanUnit15035(t, flatTreeFromSets(t,
		"set interfaces ge-0/0/0 unit 0 vlan-tags outer 0",
		"set interfaces ge-0/0/0 unit 0 family inet address 10.0.1.1/24",
	), "ge-0/0/0", 0)
	if u.VlanID != 0 {
		t.Fatalf("vlan-tags outer 0: VlanID=%d, want 0 (untagged sentinel)", u.VlanID)
	}
}

func TestVlanTagsOuterTPIDPrefixedRejected15035(t *testing.T) {
	for name, tree := range map[string]*ConfigTree{
		"flat 0x88a8.100": flatTreeFromSets(t,
			"set interfaces ge-0/0/0 flexible-vlan-tagging",
			"set interfaces ge-0/0/0 unit 0 vlan-tags outer 0x88a8.100",
			"set interfaces ge-0/0/0 unit 0 family inet address 10.0.1.1/24",
		),
		"hier 0x8100.100": hierTree(t, `interfaces {
    ge-0/0/0 {
        flexible-vlan-tagging;
        unit 0 {
            vlan-tags outer 0x8100.100;
            family inet { address 10.0.1.1/24; }
        }
    }
}`),
		"hier block 0x88a8.100": hierTree(t, `interfaces {
    ge-0/0/0 {
        flexible-vlan-tagging;
        unit 0 {
            vlan-tags { outer 0x88a8.100; }
            family inet { address 10.0.1.1/24; }
        }
    }
}`),
	} {
		t.Run(name, func(t *testing.T) {
			_, err := CompileConfig(tree)
			if err == nil {
				t.Fatalf("expected strict compile to reject TPID-prefixed outer tag, got nil")
			}
			if !strings.Contains(err.Error(), "vlan-tags") || !strings.Contains(err.Error(), "#15035") {
				t.Fatalf("reject error %q does not name vlan-tags / #15035", err.Error())
			}
		})
	}
}

func TestVlanTagsOuterMalformedRejected15035(t *testing.T) {
	// Out-of-range and non-canonical outer values must fail closed with
	// the same bounds contract as vlan-id, not silently compile untagged.
	for _, raw := range []string{"4095", "abc", "100x"} {
		_, err := CompileConfig(flatTreeFromSets(t,
			"set interfaces ge-0/0/0 flexible-vlan-tagging",
			"set interfaces ge-0/0/0 unit 0 vlan-tags outer "+raw,
			"set interfaces ge-0/0/0 unit 0 family inet address 10.0.1.1/24",
		))
		if err == nil {
			t.Fatalf("vlan-tags outer %s: expected strict reject, got nil", raw)
		}
		if !strings.Contains(err.Error(), "vlan-tags outer") {
			t.Fatalf("vlan-tags outer %s: error %q does not name the statement", raw, err.Error())
		}
	}
	// Missing value.
	_, err := CompileConfig(hierTree(t, `interfaces {
    ge-0/0/0 {
        flexible-vlan-tagging;
        unit 0 {
            vlan-tags outer;
            family inet { address 10.0.1.1/24; }
        }
    }
}`))
	if err == nil || !strings.Contains(err.Error(), "vlan-tags outer") {
		t.Fatalf("vlan-tags outer (missing value): expected reject naming the statement, got %v", err)
	}
}

func TestVlanTagsOuterControlsUnchanged15035(t *testing.T) {
	// vlan-id control still compiles to its value.
	u := compileVlanUnit15035(t, flatTreeFromSets(t,
		"set interfaces ge-0/0/0 vlan-tagging",
		"set interfaces ge-0/0/0 unit 0 vlan-id 100",
		"set interfaces ge-0/0/0 unit 0 family inet address 10.0.1.1/24",
	), "ge-0/0/0", 0)
	if u.VlanID != 100 {
		t.Fatalf("vlan-id 100 control: VlanID=%d, want 100", u.VlanID)
	}
	// Untagged unit stays untagged.
	u = compileVlanUnit15035(t, flatTreeFromSets(t,
		"set interfaces ge-0/0/0 unit 0 family inet address 10.0.1.1/24",
	), "ge-0/0/0", 0)
	if u.VlanID != 0 {
		t.Fatalf("untagged control: VlanID=%d, want 0", u.VlanID)
	}
	// Combined outer+inner still rejected as QinQ.
	_, err := CompileConfig(flatTreeFromSets(t,
		"set interfaces ge-0/0/0 flexible-vlan-tagging",
		"set interfaces ge-0/0/0 unit 0 vlan-tags outer 100 inner 200",
		"set interfaces ge-0/0/0 unit 0 family inet address 10.0.1.1/24",
	))
	if err == nil || !strings.Contains(err.Error(), "#5879") {
		t.Fatalf("combined outer+inner: expected #5879 QinQ reject, got %v", err)
	}
}

func TestVlanTagsOuterLenientCompilesValue15035(t *testing.T) {
	cfg, err := CompileConfigLenient(flatTreeFromSets(t,
		"set interfaces ge-0/0/0 flexible-vlan-tagging",
		"set interfaces ge-0/0/0 unit 0 vlan-tags outer 100",
		"set interfaces ge-0/0/0 unit 0 family inet address 10.0.1.1/24",
	))
	if err != nil {
		t.Fatalf("lenient compile: %v", err)
	}
	u := cfg.Interfaces.Interfaces["ge-0/0/0"].Units[0]
	if u == nil || u.VlanID != 100 {
		t.Fatalf("lenient vlan-tags outer 100: %+v, want VlanID=100", u)
	}
	// Lenient TPID-prefixed: warns (naming #15035) and quarantines the
	// unit — the sibling `vlan-id` lenient contract for a malformed
	// value ("skipping unit %d") — so an already-persisted config still
	// boots (#1960) without the unit silently going untagged.
	cfg, err = CompileConfigLenient(flatTreeFromSets(t,
		"set interfaces ge-0/0/0 flexible-vlan-tagging",
		"set interfaces ge-0/0/0 unit 0 vlan-tags outer 0x88a8.100",
		"set interfaces ge-0/0/0 unit 0 family inet address 10.0.1.1/24",
		"set interfaces ge-0/0/0 unit 1 vlan-tags outer 100",
		"set interfaces ge-0/0/0 unit 1 family inet address 10.0.2.1/24",
	))
	if err != nil {
		t.Fatalf("lenient TPID compile must not brick: %v", err)
	}
	found := false
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "#15035") {
			found = true
		}
	}
	if !found {
		t.Fatalf("lenient TPID: expected #15035 warning, warnings=%v", cfg.Warnings)
	}
	if u := cfg.Interfaces.Interfaces["ge-0/0/0"].Units[0]; u != nil {
		t.Fatalf("lenient TPID: unit 0 must be quarantined (skipped), got %+v", u)
	}
	if u := cfg.Interfaces.Interfaces["ge-0/0/0"].Units[1]; u == nil || u.VlanID != 100 {
		t.Fatalf("lenient TPID: sibling unit 1 must survive with VlanID=100, got %+v", u)
	}
}
