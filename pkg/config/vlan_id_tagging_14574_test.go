package config

import (
	"strings"
	"testing"
)

// Tests for #14574: `vlan-id N` (N > 0) without `vlan-tagging` /
// `flexible-vlan-tagging` committed clean, and the two writers disagreed:
// buildInterfaceNetworkdModels put the unit's addresses on the untagged
// parent while resolveInterfaceRef/ensureVLANSubInterface created the
// tagged sub-interface. The gate (validateVlanIDTaggingAST) mirrors
// #5879/#6178: strict rejects naming interface+unit, lenient warns.
//
// FAIL-ON-REVERT: removing the validateVlanIDTaggingAST call sites makes
// the strict rejects below compile clean (RED) and drops the lenient
// warning. The tagged, flexible, vlan-id 0, and no-vlan-id controls stay
// green either way — they prove the gate keys on positive-tag-without-
// tagging, not on any unit/vlan presence.

func mustReject14574(t *testing.T, tree *ConfigTree) {
	t.Helper()
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatalf("expected strict compile to reject vlan-id without tagging, got nil error")
	}
	if !strings.Contains(err.Error(), "#14574") || !strings.Contains(err.Error(), "ge-0/0/1") || !strings.Contains(err.Error(), "unit 100") {
		t.Fatalf("reject error %q does not name #14574 / interface / unit", err.Error())
	}
}

func mustAccept14574(t *testing.T, tree *ConfigTree) *Config {
	t.Helper()
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("expected strict compile to accept, got %v", err)
	}
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "#14574") {
			t.Fatalf("accepted config must not warn #14574, got %q", w)
		}
	}
	return cfg
}

func TestVlanIDWithoutTaggingRejected14574(t *testing.T) {
	// Issue's exact acceptance shape (flat-set).
	mustReject14574(t, flatTreeFromSets(t,
		"set interfaces ge-0/0/1 unit 100 vlan-id 100",
		"set interfaces ge-0/0/1 unit 100 family inet address 10.0.1.1/24",
	))
	// Hierarchical shape.
	mustReject14574(t, hierTree(t, `interfaces {
    ge-0/0/1 {
        unit 100 {
            vlan-id 100;
            family inet { address 10.0.1.1/24; }
        }
    }
}`))
	// vlan-tags outer spelling (no tagging flag either).
	mustReject14574(t, flatTreeFromSets(t,
		"set interfaces ge-0/0/1 unit 100 vlan-tags outer 100",
		"set interfaces ge-0/0/1 unit 100 family inet address 10.0.1.1/24",
	))
	mustReject14574(t, hierTree(t, `interfaces {
    ge-0/0/1 {
        unit 100 {
            vlan-tags outer 100;
            family inet { address 10.0.1.1/24; }
        }
    }
}`))
}

func TestVlanIDTaggingControlsAccepted14574(t *testing.T) {
	// vlan-tagging control (issue's control): compiles, tagged.
	cfg := mustAccept14574(t, flatTreeFromSets(t,
		"set interfaces ge-0/0/1 vlan-tagging",
		"set interfaces ge-0/0/1 unit 100 vlan-id 100",
		"set interfaces ge-0/0/1 unit 100 family inet address 10.0.1.1/24",
	))
	if ifc := cfg.Interfaces.Interfaces["ge-0/0/1"]; ifc == nil || !ifc.VlanTagging || ifc.Units[100] == nil || ifc.Units[100].VlanID != 100 {
		t.Fatalf("tagged control compiled wrong: %+v", cfg.Interfaces.Interfaces["ge-0/0/1"])
	}
	// flexible-vlan-tagging control.
	mustAccept14574(t, flatTreeFromSets(t,
		"set interfaces ge-0/0/1 flexible-vlan-tagging",
		"set interfaces ge-0/0/1 unit 100 vlan-id 100",
		"set interfaces ge-0/0/1 unit 100 family inet address 10.0.1.1/24",
	))
	// vlan-tags outer under flexible tagging.
	mustAccept14574(t, flatTreeFromSets(t,
		"set interfaces ge-0/0/1 flexible-vlan-tagging",
		"set interfaces ge-0/0/1 unit 100 vlan-tags outer 100",
		"set interfaces ge-0/0/1 unit 100 family inet address 10.0.1.1/24",
	))
	// vlan-id 0 is the untagged sentinel — legal without tagging.
	mustAccept14574(t, flatTreeFromSets(t,
		"set interfaces ge-0/0/1 unit 0 vlan-id 0",
		"set interfaces ge-0/0/1 unit 0 family inet address 10.0.1.1/24",
	))
	// No vlan-id at all.
	mustAccept14574(t, flatTreeFromSets(t,
		"set interfaces ge-0/0/1 unit 0 family inet address 10.0.1.1/24",
	))
	// vlan-tags outer 0 — untagged.
	mustAccept14574(t, flatTreeFromSets(t,
		"set interfaces ge-0/0/1 unit 0 vlan-tags outer 0",
		"set interfaces ge-0/0/1 unit 0 family inet address 10.0.1.1/24",
	))
}

func TestVlanIDTaggingPeerOnlyGroup14574(t *testing.T) {
	src := `groups {
    node0 {
        interfaces {
            ge-0/0/1 { unit 100 { vlan-id 100; family inet { address 10.0.1.1/24; } } }
        }
    }
    node1 {
        interfaces {
            ge-0/0/1 { vlan-tagging; unit 100 { vlan-id 100; family inet { address 10.0.1.1/24; } } }
        }
    }
}
apply-groups "${node}";
chassis { cluster { node 0; authentication-key test-cluster-psk-6611; } }`
	tree := hierTree(t, src)
	if _, err := CompileConfigForNode(tree, 0); err == nil {
		t.Fatalf("commit as node0 must reject: node0 view lacks tagging (node1 tagging must not excuse it)")
	} else if !strings.Contains(err.Error(), "#14574") {
		t.Fatalf("node0 reject %q not #14574", err.Error())
	}
	if _, err := CompileConfigForNode(tree, 1); err == nil {
		t.Fatalf("commit as node1 must reject: both-node union includes node0's untagged view")
	}
}

func TestVlanIDTaggingLenientWarns14574(t *testing.T) {
	cfg, err := CompileConfigLenient(flatTreeFromSets(t,
		"set interfaces ge-0/0/1 unit 100 vlan-id 100",
		"set interfaces ge-0/0/1 unit 100 family inet address 10.0.1.1/24",
	))
	if err != nil {
		t.Fatalf("lenient must not brick: %v", err)
	}
	found := false
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "#14574") && strings.Contains(w, "ge-0/0/1") && strings.Contains(w, "unit 100") {
			found = true
		}
	}
	if !found {
		t.Fatalf("lenient must warn #14574; warnings=%v", cfg.Warnings)
	}
	// Lenient keeps historical compiled shape.
	if ifc := cfg.Interfaces.Interfaces["ge-0/0/1"]; ifc == nil || ifc.Units[100] == nil || ifc.Units[100].VlanID != 100 {
		t.Fatalf("lenient compiled shape changed: %+v", cfg.Interfaces.Interfaces["ge-0/0/1"])
	}
}
