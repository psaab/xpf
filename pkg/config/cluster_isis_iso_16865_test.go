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
	// R2: node1 carrying node0's NET bytes in a different grouping
	// (4900.0101.0000.0000.0100 == 49.0001.0100.0000.0001.00) must
	// still reject — canonical bytes are identical.
	sameBytes := strings.Replace(src,
		"node1 { interfaces { lo0 { unit 0 { family iso { address 49.0001.0100.0000.0002.00; } } } } }",
		"node1 { interfaces { lo0 { unit 0 { family iso { address 4900.0101.0000.0000.0100; } } } } }", 1)
	if sameBytes == src {
		t.Fatal("sameBytes fixture did not rewrite node1")
	}
	if _, err := CompileConfig(parseHierText(t, sameBytes)); err == nil {
		t.Fatal("grouping-equivalent per-node ISO NETs accepted as distinct (#16865 R2)")
	}
}

// B-NEW-1 (explicit source): per-node `protocols isis net` in case /
// grouping variants of one NET must still reject through the cluster
// gate (canonical comparison), not just the ISO source.
func TestClusterISISExplicitCanonicalSameRejected16865(t *testing.T) {
	base := `groups {
  node0 { protocols { isis { net NET0; } } }
  node1 { protocols { isis { net NET1; } } }
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
	for _, tc := range []struct {
		name, net0, net1 string
		wantErr          bool
	}{
		{"case variants same NET", "49.0001.ABCD.0000.0001.00", "49.0001.abcd.0000.0001.00", true},
		{"grouping variants same NET", "49.0001.0100.0000.0001.00", "4900.0101.0000.0000.0100", true},
		{"distinct NETs accepted", "49.0001.0100.0000.0001.00", "49.0001.0100.0000.0002.00", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			src := strings.NewReplacer("NET0", tc.net0, "NET1", tc.net1).Replace(base)
			_, err := CompileConfig(parseHierText(t, src))
			if tc.wantErr && err == nil {
				t.Fatalf("byte-identical NETs %q / %q accepted as distinct (#16865 B-NEW-1)", tc.net0, tc.net1)
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("distinct NETs rejected: %v", err)
			}
		})
	}
	// Case-variant ISO source, same bytes: reject (attack 3).
	isoSrc := `groups {
  node0 { interfaces { lo0 { unit 0 { family iso { address 49.0001.ABCD.0000.0001.00; } } } } }
  node1 { interfaces { lo0 { unit 0 { family iso { address 49.0001.abcd.0000.0001.00; } } } } }
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
	if _, err := CompileConfig(parseHierText(t, isoSrc)); err == nil {
		t.Fatal("case-variant ISO NETs accepted as distinct (#16865 B-NEW-1 ISO)")
	}
}
