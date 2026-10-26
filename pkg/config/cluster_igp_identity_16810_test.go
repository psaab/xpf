package config

import (
	"strings"
	"testing"
)

// #16810: in an active/active RG split both nodes run OSPF under the
// same router-id (explicit or inherited), so the area keeps only one
// node's RETH prefixes. The gate rejects at strict commit (warns on
// tolerant load) a shared OSPF/OSPFv3 router-id or IS-IS NET whose
// interfaces span RETHs of more than one data RG, and excuses the
// Junos `${node}` groups idiom when each node view is distinct.
//
// FAIL-ON-REVERT: dropping validateClusterIGPIdentityStrict (or its
// call site) makes every reject case below compile clean; dropping
// the ${node} excuse makes TestClusterIGPNodeGroupsDistinct16810
// reject; making the tolerant flag strict makes the lenient cases
// fail to compile.

func clusterSplitLines16810(extra ...string) []string {
	lines := []string{
		"set chassis cluster no-private-rg-election",
		"set chassis cluster authentication-key test-cluster-psk-16810-long",
		"set chassis cluster node 0",
		"set chassis cluster reth-count 2",
		"set chassis cluster redundancy-group 0 node 0 priority 200",
		"set chassis cluster redundancy-group 0 node 1 priority 100",
		"set chassis cluster redundancy-group 1 node 0 priority 200",
		"set chassis cluster redundancy-group 1 node 1 priority 100",
		"set chassis cluster redundancy-group 2 node 0 priority 100",
		"set chassis cluster redundancy-group 2 node 1 priority 200",
		"set interfaces ge-0/0/1 gigether-options redundant-parent reth0",
		"set interfaces ge-7/0/1 gigether-options redundant-parent reth0",
		"set interfaces reth0 redundant-ether-options redundancy-group 1",
		"set interfaces reth0 unit 0 family inet address 198.51.100.1/24",
		"set interfaces ge-0/0/2 gigether-options redundant-parent reth1",
		"set interfaces ge-7/0/2 gigether-options redundant-parent reth1",
		"set interfaces reth1 redundant-ether-options redundancy-group 2",
		"set interfaces reth1 unit 0 family inet address 203.0.113.1/24",
	}
	return append(lines, extra...)
}

func TestClusterOSPFSharedRouterIDSplitRejected16810(t *testing.T) {
	tree := buildTree(t, clusterSplitLines16810(
		"set protocols ospf router-id 10.0.0.1",
		"set protocols ospf area 0.0.0.0 interface reth0.0",
		"set protocols ospf area 0.0.0.0 interface reth1.0",
	))
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("strict commit accepted a shared OSPF router-id spanning RG1+RG2 — both nodes originate LSAs under 10.0.0.1 in a split (#16810)")
	}
	for _, want := range []string{"10.0.0.1", "RG1", "RG2", "${node}"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("reject error %q missing %q", err.Error(), want)
		}
	}
}

func TestClusterOSPFInheritedRouterIDSplitRejected16810(t *testing.T) {
	tree := buildTree(t, clusterSplitLines16810(
		"set routing-options router-id 10.0.0.9",
		"set protocols ospf area 0.0.0.0 interface reth0.0",
		"set protocols ospf area 0.0.0.0 interface reth1.0",
	))
	if _, err := CompileConfig(tree); err == nil {
		t.Fatal("strict commit accepted an inherited routing-options router-id spanning RG1+RG2 (#16810)")
	}
}

func TestClusterOSPFv3SharedRouterIDSplitRejected16810(t *testing.T) {
	tree := buildTree(t, clusterSplitLines16810(
		"set protocols ospf3 router-id 10.0.0.3",
		"set protocols ospf3 area 0.0.0.0 interface reth0.0",
		"set protocols ospf3 area 0.0.0.0 interface reth1.0",
	))
	if _, err := CompileConfig(tree); err == nil {
		t.Fatal("strict commit accepted a shared OSPFv3 router-id spanning RG1+RG2 (#16810)")
	}
}

func TestClusterISISSharedNETSplitRejected16810(t *testing.T) {
	tree := buildTree(t, clusterSplitLines16810(
		"set protocols isis net 49.0001.0100.0000.0001.00",
		"set protocols isis interface reth0.0",
		"set protocols isis interface reth1.0",
	))
	if _, err := CompileConfig(tree); err == nil {
		t.Fatal("strict commit accepted a shared IS-IS NET spanning RG1+RG2 (#16810)")
	}
}

func TestClusterRoutingInstanceOSPFSharedRouterIDRejected16810(t *testing.T) {
	tree := buildTree(t, clusterSplitLines16810(
		"set routing-instances tenant instance-type virtual-router",
		"set routing-instances tenant interface reth0.0",
		"set routing-instances tenant interface reth1.0",
		"set routing-instances tenant protocols ospf router-id 10.0.0.5",
		"set routing-instances tenant protocols ospf area 0.0.0.0 interface reth0.0",
		"set routing-instances tenant protocols ospf area 0.0.0.0 interface reth1.0",
	))
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("strict commit accepted a routing-instance OSPF router-id spanning RG1+RG2 (#16810)")
	}
	if !strings.Contains(err.Error(), "tenant") {
		t.Errorf("reject error should name the instance: %v", err)
	}
}

// Controls: shapes that must still commit cleanly.

func TestClusterOSPFSharedRouterIDSingleRGAccepted16810(t *testing.T) {
	tree := buildTree(t, clusterSplitLines16810(
		"set protocols ospf router-id 10.0.0.1",
		"set protocols ospf area 0.0.0.0 interface reth0.0",
	))
	if _, err := CompileConfig(tree); err != nil {
		t.Fatalf("single-RG OSPF wrongly rejected: %v", err)
	}
}

func TestClusterOSPFNoRouterIDAccepted16810(t *testing.T) {
	tree := buildTree(t, clusterSplitLines16810(
		"set protocols ospf area 0.0.0.0 interface reth0.0",
		"set protocols ospf area 0.0.0.0 interface reth1.0",
	))
	if _, err := CompileConfig(tree); err != nil {
		t.Fatalf("unset router-id (FRR auto-derives per node) wrongly rejected: %v", err)
	}
}

func TestStandaloneOSPFSharedRouterIDAccepted16810(t *testing.T) {
	tree := buildTree(t, []string{
		"set interfaces reth0 unit 0 family inet address 198.51.100.1/24",
		"set protocols ospf router-id 10.0.0.1",
		"set protocols ospf area 0.0.0.0 interface reth0.0",
		"set protocols ospf area 0.0.0.0 interface reth1.0",
	})
	if _, err := CompileConfig(tree); err != nil {
		t.Fatalf("non-cluster OSPF wrongly rejected: %v", err)
	}
}

func TestClusterOSPFDisabledAccepted16810(t *testing.T) {
	tree := buildTree(t, clusterSplitLines16810(
		"set protocols ospf router-id 10.0.0.1",
		"set protocols ospf disable",
		"set protocols ospf area 0.0.0.0 interface reth0.0",
		"set protocols ospf area 0.0.0.0 interface reth1.0",
	))
	if _, err := CompileConfig(tree); err != nil {
		t.Fatalf("disabled OSPF wrongly rejected: %v", err)
	}
}

// The Junos remedy: distinct router-ids per node via groups.
// The generic compile sees only the node0 fallback; the excuse must
// recognise both node views as distinct, and each node-aware compile
// must independently be clean.
func TestClusterIGPNodeGroupsDistinct16810(t *testing.T) {
	src := `groups {
  node0 { protocols { ospf { router-id 10.0.0.1; } } }
  node1 { protocols { ospf { router-id 10.0.0.2; } } }
}
apply-groups "${node}";
	chassis { cluster { cluster-id 1; authentication-key test-cluster-psk-16810-long; node 0; reth-count 2; no-private-rg-election;
	  redundancy-group 0 { node 0 priority 200; node 1 priority 100; }
	  redundancy-group 1 { node 0 priority 200; node 1 priority 100; }
	  redundancy-group 2 { node 0 priority 100; node 1 priority 200; } } }
interfaces {
  ge-0/0/1 { gigether-options { redundant-parent reth0; } }
  ge-7/0/1 { gigether-options { redundant-parent reth0; } }
  reth0 { redundant-ether-options { redundancy-group 1; } unit 0 { family inet { address 198.51.100.1/24; } } }
  ge-0/0/2 { gigether-options { redundant-parent reth1; } }
  ge-7/0/2 { gigether-options { redundant-parent reth1; } }
  reth1 { redundant-ether-options { redundancy-group 2; } unit 0 { family inet { address 203.0.113.1/24; } } }
}
protocols { ospf { area 0.0.0.0 { interface reth0.0; interface reth1.0; } } }
`
	tree := parseHierText(t, src)
	if _, err := CompileConfig(tree); err != nil {
		t.Fatalf("generic strict compile rejected the ${node} distinct-router-id idiom: %v", err)
	}
	for node, want := range map[int]string{0: "10.0.0.1", 1: "10.0.0.2"} {
		cfg, err := CompileConfigForNode(tree, node)
		if err != nil {
			t.Fatalf("node%d strict compile rejected: %v", node, err)
		}
		if cfg.Protocols.OSPF == nil || cfg.Protocols.OSPF.RouterID != want {
			t.Fatalf("node%d OSPF router-id = %+v, want %s", node, cfg.Protocols.OSPF, want)
		}
	}
}

// Same idiom but both node groups carry the SAME router-id: the
// excuse must not fire.
func TestClusterIGPNodeGroupsSameRejected16810(t *testing.T) {
	src := `groups {
  node0 { protocols { ospf { router-id 10.0.0.1; } } }
  node1 { protocols { ospf { router-id 10.0.0.1; } } }
}
apply-groups "${node}";
	chassis { cluster { cluster-id 1; authentication-key test-cluster-psk-16810-long; node 0; reth-count 2; no-private-rg-election;
	  redundancy-group 0 { node 0 priority 200; node 1 priority 100; }
	  redundancy-group 1 { node 0 priority 200; node 1 priority 100; }
	  redundancy-group 2 { node 0 priority 100; node 1 priority 200; } } }
interfaces {
  ge-0/0/1 { gigether-options { redundant-parent reth0; } }
  ge-7/0/1 { gigether-options { redundant-parent reth0; } }
  reth0 { redundant-ether-options { redundancy-group 1; } unit 0 { family inet { address 198.51.100.1/24; } } }
  ge-0/0/2 { gigether-options { redundant-parent reth1; } }
  ge-7/0/2 { gigether-options { redundant-parent reth1; } }
  reth1 { redundant-ether-options { redundancy-group 2; } unit 0 { family inet { address 203.0.113.1/24; } } }
}
protocols { ospf { area 0.0.0.0 { interface reth0.0; interface reth1.0; } } }
`
	tree := parseHierText(t, src)
	if _, err := CompileConfig(tree); err == nil {
		t.Fatal("strict commit accepted identical node0/node1 router-ids spanning RG1+RG2 (#16810)")
	}
}

// Tolerant load: warns, still compiles (#1960).
func TestClusterOSPFSharedRouterIDLenientWarns16810(t *testing.T) {
	tree := buildTree(t, clusterSplitLines16810(
		"set protocols ospf router-id 10.0.0.1",
		"set protocols ospf area 0.0.0.0 interface reth0.0",
		"set protocols ospf area 0.0.0.0 interface reth1.0",
	))
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("tolerant load rejected a persisted shared router-id: %v", err)
	}
	found := false
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "cluster IGP identity") && strings.Contains(w, "10.0.0.1") {
			found = true
		}
	}
	if !found {
		t.Fatalf("tolerant load carried no #16810 warning: %v", cfg.Warnings)
	}
	if _, err := CompileConfigForNodeLenient(tree, 0); err != nil {
		t.Fatalf("tolerant node load rejected: %v", err)
	}
}
