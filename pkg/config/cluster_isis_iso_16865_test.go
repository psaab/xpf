package config

import (
	"strings"
	"testing"
)

// F3: distinct per-node ISO NETs earn the cluster exemption; identical
// per-node ISO NETs spanning two data RGs still reject.
func TestClusterISISISONodeGroupsDistinct16865(t *testing.T) {
	src := `groups {
  node0 { interfaces { lo0 { unit 0 { family iso { address 49.0001.0100.0000.0001.00; } } } } }
  node1 { interfaces { lo0 { unit 0 { family iso { address 49.0001.0100.0000.0002.00; } } } } }
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
protocols { isis { interface reth0.0; interface reth1.0; } }
`
	tree := parseHierText(t, src)
	if _, err := CompileConfig(tree); err != nil {
		t.Fatalf("generic strict compile rejected distinct per-node ISO NETs: %v", err)
	}
	for node, want := range map[int]string{0: "49.0001.0100.0000.0001.00", 1: "49.0001.0100.0000.0002.00"} {
		cfg, err := CompileConfigForNode(tree, node)
		if err != nil {
			t.Fatalf("node%d strict compile: %v", node, err)
		}
		if cfg.Protocols.ISIS == nil || cfg.Protocols.ISIS.NET != want {
			t.Fatalf("node%d ISIS NET = %+v, want %s", node, cfg.Protocols.ISIS, want)
		}
	}
	// Same NET on both nodes must still reject.
	same := strings.Replace(src, "49.0001.0100.0000.0002.00", "49.0001.0100.0000.0001.00", 1)
	if _, err := CompileConfig(parseHierText(t, same)); err == nil {
		t.Fatal("identical per-node ISO NETs spanning RG1+RG2 accepted (#16865 F3 control)")
	}
}
