package config

import (
	"strings"
	"testing"
)

// Tests for #6178: input-vlan-map / output-vlan-map (per-unit VLAN
// push/pop/swap rewrite) is not in the unit setSchema and has no compiler
// consumer, so it parse-accepts and is silently DROPPED — the AF_XDP
// dataplane performs no rewrite. This is NOT a firewall bypass (a
// single-tagged frame still arrives single-tagged and IS firewalled, unlike
// the #5879 receive-side QinQ case), but a strict commit ACCEPTS a rewrite
// the dataplane cannot perform, so the operator believes tags are pushed /
// swapped when they are not. The #6178 honesty gate (validateVLANMapAST)
// mirrors the #5879 validateQinQVLANStackAST doctrine exactly: strict
// (commit / commit-check) rejects; lenient (tolerant load / peer-sync) warns
// (#1960 no-brick).
//
// FAIL-ON-REVERT: reverting the gate (removing the validateVLANMapAST call
// sites, or the input-vlan-map/output-vlan-map arms of unitVLANMapStmts)
// makes the strict compile ACCEPT the vlan-map — turning the reject
// assertions below RED — and drops the lenient warning.

// mustRejectVLANMap6178 asserts the strict generic compile (CompileConfig)
// rejects the tree with a #6178 vlan-map error naming the interface.
func mustRejectVLANMap6178(t *testing.T, tree *ConfigTree) {
	t.Helper()
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatalf("expected strict compile to reject unsupported vlan-map, got nil error")
	}
	if !strings.Contains(err.Error(), "#6178") || !strings.Contains(err.Error(), "ge-0/0/0") {
		t.Fatalf("reject error %q does not name the #6178 vlan-map gate / interface", err.Error())
	}
}

// mustAcceptNoVLANMap asserts the strict generic compile accepts the tree
// and records no #6178 warning — the scoped-gate control proving a
// legitimate single-tag / no-vlan-map config is not caught.
func mustAcceptNoVLANMap(t *testing.T, tree *ConfigTree) {
	t.Helper()
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("expected strict compile to accept config without vlan-map, got %v", err)
	}
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "#6178") {
			t.Fatalf("config without vlan-map must not warn #6178, got %q", w)
		}
	}
}

// TestVLANMapHonestyGate6178 is the primary fail-on-revert: a unit carrying
// an input-vlan-map / output-vlan-map rewrite is rejected at strict commit,
// in both flat-set and hierarchical AST shapes, while an otherwise-identical
// unit with no vlan-map compiles clean.
func TestVLANMapHonestyGate6178(t *testing.T) {
	// Non-tautological baseline: the same interface + a plain single 802.1Q
	// vlan-id (fully supported) must compile clean — the gate keys on the
	// vlan-map, not on the presence of a VLAN tag or a logical unit.
	mustAcceptNoVLANMap(t, flatTreeFromSets(t,
		"set interfaces ge-0/0/0 vlan-tagging",
		"set interfaces ge-0/0/0 unit 0 vlan-id 100",
		"set interfaces ge-0/0/0 unit 0 family inet address 10.0.1.1/24",
	))

	// input-vlan-map push (flat-set) — an ingress tag push the dataplane
	// cannot perform — hard-rejects.
	mustRejectVLANMap6178(t, flatTreeFromSets(t,
		"set interfaces ge-0/0/0 unit 0 vlan-id 100",
		"set interfaces ge-0/0/0 unit 0 input-vlan-map push",
		"set interfaces ge-0/0/0 unit 0 family inet address 10.0.1.1/24",
	))

	// output-vlan-map swap (flat-set) — an egress tag swap — also rejects.
	mustRejectVLANMap6178(t, flatTreeFromSets(t,
		"set interfaces ge-0/0/0 unit 0 vlan-id 100",
		"set interfaces ge-0/0/0 unit 0 output-vlan-map swap",
		"set interfaces ge-0/0/0 unit 0 family inet address 10.0.1.1/24",
	))

	// Hierarchical shape (input-vlan-map with nested action + tag args) is
	// detected the same way — the gate folds the nested children onto one
	// line for the message.
	mustRejectVLANMap6178(t, hierTree(t, `interfaces {
    ge-0/0/0 {
        unit 0 {
            input-vlan-map { swap; vlan-id 200; }
            family inet { address 10.0.1.1/24; }
        }
    }
}`))
}

// TestVLANMapPeerOnlyGroupRejectedOnCommittingNode6178 mirrors the #5879
// peer-only-group case: a vlan-map that only materializes in the node1
// (standby) effective view — it lives under `groups node1` applied through
// `apply-groups "${node}"` — is rejected when the config is compiled FOR
// NODE 0 (the primary's commit), because validateVLANMapAST evaluates both
// per-node effective views. Proves the verdict is HA-symmetric.
func TestVLANMapPeerOnlyGroupRejectedOnCommittingNode6178(t *testing.T) {
	src := `groups {
    node0 {
        interfaces {
            ge-0/0/0 { unit 0 { vlan-id 100; family inet { address 10.0.1.1/24; } } }
        }
    }
    node1 {
        interfaces {
            ge-0/0/0 { unit 0 { vlan-id 100; input-vlan-map push; family inet { address 10.0.1.1/24; } } }
        }
    }
}
apply-groups "${node}";
chassis { cluster { node 0; } }`
	tree := hierTree(t, src)

	// Committing AS NODE 0: node0's own view has no vlan-map (clean), but the
	// node1 effective view carries an unsupported input-vlan-map — the
	// both-node union rejects.
	if _, err := CompileConfigForNode(tree, 0); err == nil {
		t.Fatalf("commit as node0 must reject a vlan-map that renders only in the node1 view")
	} else if !strings.Contains(err.Error(), "#6178") || !strings.Contains(err.Error(), "ge-0/0/0") {
		t.Fatalf("node0-commit reject %q does not name the #6178 vlan-map gate / interface", err.Error())
	}
	// Committing AS NODE 1 also rejects (its own view has the vlan-map) —
	// proving the verdict is node-symmetric, not a node0-only artifact.
	if _, err := CompileConfigForNode(tree, 1); err == nil {
		t.Fatalf("commit as node1 must reject its own vlan-map view")
	}
}

// TestVLANMapGateLenientWarnsNoBrick6178 — the tolerant load / peer-sync
// path (#1960) downgrades an unsupported vlan-map to a warning and still
// compiles, so a config an older binary silently accepted never bricks an
// upgrading / receiving node.
func TestVLANMapGateLenientWarnsNoBrick6178(t *testing.T) {
	cfg, err := CompileConfigLenient(flatTreeFromSets(t,
		"set interfaces ge-0/0/0 unit 0 vlan-id 100",
		"set interfaces ge-0/0/0 unit 0 output-vlan-map swap",
		"set interfaces ge-0/0/0 unit 0 family inet address 10.0.1.1/24",
	))
	if err != nil {
		t.Fatalf("lenient compile must not brick on an unsupported vlan-map: %v", err)
	}
	found := false
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "#6178") && strings.Contains(w, "ge-0/0/0") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("lenient compile must warn about the unsupported vlan-map; warnings = %v", cfg.Warnings)
	}
}

// TestVLANMapPeeledUnitRejected13146 covers D2-15 subcase A: the peeled
// 3-level `unit { 0 { ... } }` spelling, which compileInterfaces compiles via
// namedInstances, must not bypass the #6178 gate (which previously only
// matched two-key `unit 0` nodes).
func TestVLANMapPeeledUnitRejected13146(t *testing.T) {
	tree := hierTree(t, `interfaces {
    ge-0/0/0 {
        vlan-tagging;
        unit {
            0 {
                vlan-id 100;
                input-vlan-map { push; }
                family inet { address 10.0.1.1/24; }
            }
        }
    }
}`)
	mustRejectVLANMap6178(t, tree)
}

// TestVLANMapDuplicateUnitStatementsRetained13146 covers D2-15 subcase B:
// multiple same-key unit findings must retain every unsupported statement.
// CompileConfig rejects duplicate unit blocks via its independent #8427 gate,
// so call the #6178 validator directly to isolate its union behavior.
func TestVLANMapDuplicateUnitStatementsRetained13146(t *testing.T) {
	first := hierTree(t, `interfaces {
    ge-0/0/0 {
        unit 0 { input-vlan-map { push; } }
    }
}`)
	second := hierTree(t, `interfaces {
    ge-0/0/0 {
        unit 0 { output-vlan-map { pop; } }
    }
}`)
	firstIface := first.FindChildren("interfaces")[0].FindChild("ge-0/0/0")
	secondIface := second.FindChildren("interfaces")[0].FindChild("ge-0/0/0")
	firstIface.Children = append(firstIface.Children, secondIface.FindChild("unit"))

	_, err := validateVLANMapAST(first, false)
	if err == nil {
		t.Fatal("expected #6178 validator to reject duplicate-unit vlan-map")
	}
	if !strings.Contains(err.Error(), "input-vlan-map") ||
		!strings.Contains(err.Error(), "output-vlan-map") {
		t.Fatalf("duplicate-unit finding lost a vlan-map statement: %v", err)
	}
}

// TestVLANMapLiteralNodeGroupRejected13146 covers D2-15 subcase C: a literal
// `groups "${node}"` + `apply-groups "${node}"` config defeats per-node
// group expansion, but the vlan-map sits in the top-level interfaces stanza
// the compiler still compiles, so the gate must reject it instead of
// silently returning no findings.
func TestVLANMapLiteralNodeGroupRejected13146(t *testing.T) {
	tree := hierTree(t, `groups {
    "${node}" {
        interfaces {
            ge-0/0/0 { vlan-tagging; }
        }
    }
}
apply-groups "${node}";
interfaces {
    ge-0/0/0 {
        unit 0 {
            vlan-id 100;
            input-vlan-map { push; }
            family inet { address 10.0.1.1/24; }
        }
    }
}`)
	mustRejectVLANMap6178(t, tree)
}
