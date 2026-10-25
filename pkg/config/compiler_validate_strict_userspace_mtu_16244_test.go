package config

import (
	"strings"
	"testing"
)

// #16244: MTU 9000 (authored media MTU; #16594 effective L3 8986 untagged) on a userspace-dataplane-bound interface must be
// refused at commit with a named refusal, not committed clean and then
// dropped at line rate. The netdev takes the MTU (planPhysDesired ->
// LinkSetMTU runs before the deferred XDP attach), but the AF_XDP
// helper binds without multi-buffer support into 4096-byte UMEM frames,
// so no frame above userspaceRxMTUBudget can reach a worker.
//
// FAIL-ON-REVERT: drop validateUserspaceRxMTUStrict (or its
// runUniformGatesInterfaceAddr call) and every reject case below
// compiles clean — the strict error disappears and only the #9727
// advisory warning remains.

func TestUserspaceMTU9000BoundRejected16244(t *testing.T) {
	_, err := CompileConfig(flatTreeFromSets(t,
		"set interfaces ge-0/0/1 mtu 9000",
		"set interfaces ge-0/0/1 unit 0 family inet address 10.0.1.1/24",
		"set security zones security-zone trust interfaces ge-0/0/1.0",
	))
	if err == nil {
		t.Fatal("strict commit ACCEPTED MTU 9000 on a dataplane-bound interface")
	}
	for _, want := range []string{"ge-0/0/1", "8986", "3566", "#16244"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("refusal %q does not name %q", err.Error(), want)
		}
	}
}

func TestUserspaceMTUBoundary16244(t *testing.T) {
	// Exactly the budget fits one UMEM frame: accepted.
	assertCommitAccepts(t, flatTreeFromSets(t,
		"set interfaces ge-0/0/1 mtu 3580",
		"set interfaces ge-0/0/1 unit 0 family inet address 10.0.1.1/24",
		"set security zones security-zone trust interfaces ge-0/0/1.0",
	))
	// One byte over: refused.
	assertCommitRejects(t, flatTreeFromSets(t,
		"set interfaces ge-0/0/1 mtu 3581",
		"set interfaces ge-0/0/1 unit 0 family inet address 10.0.1.1/24",
		"set security zones security-zone trust interfaces ge-0/0/1.0",
	), "#16244")
	// Ordinary MTU: accepted, no refusal.
	assertCommitAccepts(t, flatTreeFromSets(t,
		"set interfaces ge-0/0/1 mtu 1514",
		"set interfaces ge-0/0/1 unit 0 family inet address 10.0.1.1/24",
		"set security zones security-zone trust interfaces ge-0/0/1.0",
	))
}

func TestUserspaceMTUUnitOverride16244(t *testing.T) {
	// A referenced untagged unit MTU overrides the interface MTU:
	// jumbo unit under a small interface still refuses.
	assertCommitRejects(t, flatTreeFromSets(t,
		"set interfaces ge-0/0/1 mtu 1500",
		"set interfaces ge-0/0/1 unit 0 family inet address 10.0.1.1/24",
		"set interfaces ge-0/0/1 unit 0 family inet mtu 9000",
		"set security zones security-zone trust interfaces ge-0/0/1.0",
	), "#16244")
	// A small untagged unit under a jumbo interface is the effective
	// MTU: accepted.
	assertCommitAccepts(t, flatTreeFromSets(t,
		"set interfaces ge-0/0/1 mtu 9000",
		"set interfaces ge-0/0/1 unit 0 family inet address 10.0.1.1/24",
		"set interfaces ge-0/0/1 unit 0 family inet mtu 1500",
		"set security zones security-zone trust interfaces ge-0/0/1.0",
	))
}

func TestUserspaceMTUTaggedParentRejected16244(t *testing.T) {
	// Shape A from the fold review: only a tagged child is zoned and
	// carries 1500, but AF_XDP binds its parent. Tagged units do not
	// replace the parent, so interface MTU 9000 remains effective.
	_, err := CompileConfig(flatTreeFromSets(t,
		"set interfaces ge-0/0/1 vlan-tagging",
		"set interfaces ge-0/0/1 mtu 9000",
		"set interfaces ge-0/0/1 unit 50 vlan-id 50",
		"set interfaces ge-0/0/1 unit 50 family inet address 10.0.50.1/24",
		"set interfaces ge-0/0/1 unit 50 family inet mtu 1500",
		"set security zones security-zone trust interfaces ge-0/0/1.50",
	))
	if err == nil {
		t.Fatal("strict commit ACCEPTED an over-budget tagged parent")
	}
	for _, want := range []string{"ge-0/0/1", "8982", "3566", "#16244"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("tagged-parent refusal %q does not name %q", err.Error(), want)
		}
	}
}

func TestUserspaceMTUTaggedSiblingOverrideAccepted16244(t *testing.T) {
	// Shape B from the fold review: a referenced untagged sibling at
	// 1500 lowers the shared physical parent even though another
	// referenced unit is tagged. The tagged unit has no MTU statement
	// and inherits that effective 1500 parent.
	assertCommitAccepts(t, flatTreeFromSets(t,
		"set interfaces ge-0/0/1 vlan-tagging",
		"set interfaces ge-0/0/1 mtu 9000",
		"set interfaces ge-0/0/1 unit 0 family inet address 10.0.1.1/24",
		"set interfaces ge-0/0/1 unit 0 family inet mtu 1500",
		"set interfaces ge-0/0/1 unit 50 vlan-id 50",
		"set interfaces ge-0/0/1 unit 50 family inet address 10.0.50.1/24",
		"set security zones security-zone trust interfaces ge-0/0/1.0",
		"set security zones security-zone trust interfaces ge-0/0/1.50",
	))
}

func TestUserspaceMTUTaggedRETHParentRejected16244(t *testing.T) {
	tree := flatTreeFromSets(t,
		"set chassis cluster cluster-id 1",
		"set chassis cluster authentication-key aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		"set chassis cluster redundancy-group 1 node 0 priority 200",
		"set chassis cluster redundancy-group 1 node 1 priority 100",
		"set interfaces ge-0/0/2 gigether-options redundant-parent reth0",
		"set interfaces ge-7/0/2 gigether-options redundant-parent reth0",
		"set interfaces reth0 redundant-ether-options redundancy-group 1",
		"set interfaces reth0 vlan-tagging",
		"set interfaces reth0 mtu 9000",
		"set interfaces reth0 unit 50 vlan-id 50",
		"set interfaces reth0 unit 50 family inet address 172.16.50.8/24",
		"set interfaces reth0 unit 50 family inet mtu 1500",
		"set security zones security-zone trust interfaces reth0.50",
	)
	_, err := CompileConfigForNode(tree, 0)
	if err == nil {
		t.Fatal("strict node commit ACCEPTED an over-budget tagged RETH parent")
	}
	for _, want := range []string{"reth0", "ge-0-0-2", "9000", "#16244"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("tagged RETH refusal %q does not name %q", err.Error(), want)
		}
	}
}

func TestUserspaceMTUNotBoundAccepted16244(t *testing.T) {
	// Unzoned: the dataplane never binds it, jumbo stays legal for
	// kernel-forwarded traffic.
	assertCommitAccepts(t, flatTreeFromSets(t,
		"set interfaces ge-0/0/1 mtu 9000",
		"set interfaces ge-0/0/1 unit 0 family inet address 10.0.1.1/24",
	))
	// Management lifeline in a zone: not AF_XDP-bound.
	assertCommitAccepts(t, flatTreeFromSets(t,
		"set interfaces fxp0 mtu 9000",
		"set interfaces fxp0 unit 0 family inet address 10.0.1.1/24",
		"set security zones security-zone trust interfaces fxp0.0",
	))
}

func TestUserspaceMTULenientWarns16244(t *testing.T) {
	cfg, err := CompileConfigLenient(flatTreeFromSets(t,
		"set interfaces ge-0/0/1 mtu 9000",
		"set interfaces ge-0/0/1 unit 0 family inet address 10.0.1.1/24",
		"set security zones security-zone trust interfaces ge-0/0/1.0",
	))
	if err != nil {
		t.Fatalf("lenient compile must accept a persisted jumbo config (#1960), got %v", err)
	}
	joined := strings.Join(cfg.Warnings, "\n")
	for _, want := range []string{"ge-0/0/1", "8986", "#16244"} {
		if !strings.Contains(joined, want) {
			t.Errorf("lenient warnings %q do not name %q", joined, want)
		}
	}
}

func TestUserspaceMTUForNodeRejected16244(t *testing.T) {
	// The node-scoped strict path (CompileConfigForNode) shares
	// compileTree, so the refusal fires there too — a clustered commit
	// must not bypass it.
	_, err := CompileConfigForNode(flatTreeFromSets(t,
		"set interfaces ge-0/0/1 mtu 9000",
		"set interfaces ge-0/0/1 unit 0 family inet address 10.0.1.1/24",
		"set security zones security-zone trust interfaces ge-0/0/1.0",
	), 0)
	if err == nil || !strings.Contains(err.Error(), "#16244") {
		t.Fatalf("CompileConfigForNode accepted MTU 9000, err=%v", err)
	}
	cfg, err := CompileConfigForNodeLenient(flatTreeFromSets(t,
		"set interfaces ge-0/0/1 mtu 9000",
		"set interfaces ge-0/0/1 unit 0 family inet address 10.0.1.1/24",
		"set security zones security-zone trust interfaces ge-0/0/1.0",
	), 0)
	if err != nil {
		t.Fatalf("CompileConfigForNodeLenient must accept, got %v", err)
	}
	if !strings.Contains(strings.Join(cfg.Warnings, "\n"), "#16244") {
		t.Errorf("node lenient warnings missing #16244: %v", cfg.Warnings)
	}
}
