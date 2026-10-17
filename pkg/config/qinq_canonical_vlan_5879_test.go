package config

import (
	"strings"
	"testing"
)

// Tests for #5879: the unsupported-QinQ honesty gate must validate the
// AGGREGATE canonical per-physical-interface VLAN stack — across every tag
// spelling, statements split across a unit, and BOTH cluster-node effective
// views — not just a single literal `inner-vlan-id` leaf on the committing
// node's own expansion (the #2354 gate's blind spot).
//
// Before #5879 two classes of unsupported stacked-VLAN bypassed commit:
//
//   1. `vlan-tags outer <x> inner <y>` (the modern Junos QinQ spelling) is
//      not in setSchema and has no compiler consumer, so it parse-accepted
//      and was silently DROPPED — the #2354 gate only looked at
//      `inner-vlan-id`. The inner half can even be split across two set
//      statements, so no single leaf is the recognizable `inner-vlan-id`.
//   2. An `inner-vlan-id` living under `groups node1` + `apply-groups
//      "${node}"` never materializes when the candidate is compiled for
//      node0, so a commit ON node0 accepted a stack that renders
//      unsupported QinQ on node1 (an active/standby posture split).
//
// FAIL-ON-REVERT: dropping the `vlan-tags` inner branch of unitVLANStack
// turns the split/combined vlan-tags rejects GREEN-accept (RED here);
// dropping the node1 view in validateQinQVLANStackAST turns the peer-only
// reject GREEN-accept (RED here).

// mustReject5879 asserts the strict generic compile (CompileConfig) rejects
// the tree with a #5879 QinQ error.
func mustReject5879(t *testing.T, tree *ConfigTree) {
	t.Helper()
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatalf("expected strict compile to reject unsupported QinQ, got nil error")
	}
	if !strings.Contains(err.Error(), "#5879") || !strings.Contains(err.Error(), "QinQ") {
		t.Fatalf("reject error %q does not name the #5879 QinQ gate", err.Error())
	}
}

// mustAcceptNoQinQ asserts the strict generic compile accepts the tree and
// records no #5879 QinQ warning — the scoped-gate control proving a
// legitimate single-tag config is not caught.
func mustAcceptNoQinQ(t *testing.T, tree *ConfigTree) *Config {
	t.Helper()
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("expected strict compile to accept supported VLAN config, got %v", err)
	}
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "#5879") {
			t.Fatalf("supported VLAN config must not warn #5879, got %q", w)
		}
	}
	return cfg
}

// TestQinQVlanTagsSplitAcrossStatementsRejected_5879 is the primary
// fail-on-revert: an inner tag spelled via `vlan-tags`, SPLIT across two set
// statements so neither statement alone is the `inner-vlan-id` the old gate
// keyed on, is rejected at commit. Control: the outer half alone (a single
// S-tag) still compiles.
func TestQinQVlanTagsSplitAcrossStatementsRejected_5879(t *testing.T) {
	// Non-tautological baseline: the outer `vlan-tags` statement ALONE is a
	// single tag and must compile clean (the gate keys on the INNER tag).
	mustAcceptNoQinQ(t, flatTreeFromSets(t,
		"set interfaces ge-0/0/0 flexible-vlan-tagging",
		"set interfaces ge-0/0/0 unit 0 vlan-tags outer 100",
		"set interfaces ge-0/0/0 unit 0 family inet address 10.0.1.1/24",
	))
	// Adding the inner half — a SEPARATE statement — makes the aggregate
	// stack unsupported QinQ and hard-rejects.
	mustReject5879(t, flatTreeFromSets(t,
		"set interfaces ge-0/0/0 flexible-vlan-tagging",
		"set interfaces ge-0/0/0 unit 0 vlan-tags outer 100",
		"set interfaces ge-0/0/0 unit 0 vlan-tags inner 200",
		"set interfaces ge-0/0/0 unit 0 family inet address 10.0.1.1/24",
	))
}

// TestQinQVlanTagsCombinedRejected_5879 — the inner tag spelled via the
// single-statement `vlan-tags outer X inner Y` form (which the #2354 gate
// never inspected) is rejected, in both flat-set and hierarchical shapes.
func TestQinQVlanTagsCombinedRejected_5879(t *testing.T) {
	mustReject5879(t, flatTreeFromSets(t,
		"set interfaces ge-0/0/0 flexible-vlan-tagging",
		"set interfaces ge-0/0/0 unit 0 vlan-tags outer 100 inner 200",
		"set interfaces ge-0/0/0 unit 0 family inet address 10.0.1.1/24",
	))
	mustReject5879(t, hierTree(t, `interfaces {
    ge-0/0/0 {
        flexible-vlan-tagging;
        unit 0 {
            vlan-tags outer 100 inner 200;
            family inet { address 10.0.1.1/24; }
        }
    }
}`))
}

// TestQinQVlanTagsOuterOnlyAccepted_5879 pins the scope: a single S-tag via
// `vlan-tags outer` (no inner) is NOT QinQ and must stay accepted — the gate
// keys on the inner (second) tag, not on the presence of `vlan-tags`.
func TestQinQVlanTagsOuterOnlyAccepted_5879(t *testing.T) {
	mustAcceptNoQinQ(t, flatTreeFromSets(t,
		"set interfaces ge-0/0/0 flexible-vlan-tagging",
		"set interfaces ge-0/0/0 unit 0 vlan-tags outer 100",
		"set interfaces ge-0/0/0 unit 0 family inet address 10.0.1.1/24",
	))
	// A plain single 802.1Q `vlan-id` (the fully-supported common case).
	// #14574: the parent carries vlan-tagging — without it this shape is
	// the vlan-id-without-tagging defect, not a QinQ control.
	mustAcceptNoQinQ(t, flatTreeFromSets(t,
		"set interfaces ge-0/0/0 vlan-tagging",
		"set interfaces ge-0/0/0 unit 0 vlan-id 100",
		"set interfaces ge-0/0/0 unit 0 family inet address 10.0.1.1/24",
	))
}

// TestQinQPeerOnlyGroupRejectedOnCommittingNode_5879 is the second
// fail-on-revert: an `inner-vlan-id` that only materializes in the node1
// (standby) effective view — it lives under `groups node1` applied through
// `apply-groups "${node}"` — is rejected when the config is compiled FOR
// NODE 0 (the primary's commit). The primary's own expansion has no inner
// tag, so only the both-node union catches it.
func TestQinQPeerOnlyGroupRejectedOnCommittingNode_5879(t *testing.T) {
	src := `groups {
    node0 {
        interfaces {
            ge-0/0/0 { vlan-tagging; unit 0 { vlan-id 100; family inet { address 10.0.1.1/24; } } }
        }
    }
    node1 {
        interfaces {
            ge-0/0/0 { vlan-tagging; unit 0 { vlan-id 100; inner-vlan-id 200; family inet { address 10.0.1.1/24; } } }
        }
    }
}
apply-groups "${node}";
chassis { cluster { node 0; authentication-key test-cluster-psk-6611; } }`
	tree := hierTree(t, src)

	// Committing AS NODE 0: node0's own view is single-tag (clean), but the
	// node1 effective view is unsupported QinQ — the both-node union rejects.
	if _, err := CompileConfigForNode(tree, 0); err == nil {
		t.Fatalf("commit as node0 must reject a QinQ that renders only in the node1 view")
	} else if !strings.Contains(err.Error(), "#5879") || !strings.Contains(err.Error(), "ge-0/0/0") {
		t.Fatalf("node0-commit reject %q does not name the #5879 QinQ gate / interface", err.Error())
	}
	// Committing AS NODE 1 also rejects (its own view is QinQ) — proving the
	// verdict is node-symmetric, not a node0-only artifact.
	if _, err := CompileConfigForNode(tree, 1); err == nil {
		t.Fatalf("commit as node1 must reject its own QinQ view")
	}

	// Control: the SAME structure with node1 also single-tag (no inner) must
	// compile clean for both nodes — proving the reject is the inner tag, not
	// the group scaffolding.
	clean := hierTree(t, `groups {
    node0 { interfaces { ge-0/0/0 { vlan-tagging; unit 0 { vlan-id 100; family inet { address 10.0.1.1/24; } } } } }
    node1 { interfaces { ge-0/0/0 { vlan-tagging; unit 0 { vlan-id 100; family inet { address 10.0.1.1/24; } } } } }
}
apply-groups "${node}";
chassis { cluster { node 0; authentication-key test-cluster-psk-6611; } }`)
	if _, err := CompileConfigForNode(clean, 0); err != nil {
		t.Fatalf("single-tag node-scoped config must compile for node0: %v", err)
	}
	if _, err := CompileConfigForNode(clean, 1); err != nil {
		t.Fatalf("single-tag node-scoped config must compile for node1: %v", err)
	}
}

// TestQinQGateLenientWarnsNoBrick_5879 — the tolerant load / peer-sync path
// (#1960) downgrades an unsupported QinQ stack (here the `vlan-tags` inner
// spelling) to a warning and still compiles, so a config an older binary
// silently accepted never bricks an upgrading / receiving node.
func TestQinQGateLenientWarnsNoBrick_5879(t *testing.T) {
	cfg, err := CompileConfigLenient(flatTreeFromSets(t,
		"set interfaces ge-0/0/0 flexible-vlan-tagging",
		"set interfaces ge-0/0/0 unit 0 vlan-tags outer 100 inner 200",
		"set interfaces ge-0/0/0 unit 0 family inet address 10.0.1.1/24",
	))
	if err != nil {
		t.Fatalf("lenient compile must not brick on an unsupported QinQ stack: %v", err)
	}
	found := false
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "#5879") && strings.Contains(w, "ge-0/0/0") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("lenient compile must warn about the unsupported QinQ stack; warnings = %v", cfg.Warnings)
	}
}
