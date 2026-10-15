package config

import "testing"

func TestBGPChainedGroupMatchesBlock13531(t *testing.T) {
	const block = `protocols { bgp { local-as 65001; group EXT { peer-as 65002; neighbor 10.0.0.1; } } }`
	cases := []struct {
		name string
		sets []string
	}{
		{
			name: "group chained after local-as",
			sets: []string{"set protocols bgp local-as 65001 group EXT peer-as 65002 neighbor 10.0.0.1"},
		},
		{
			name: "split flat statements",
			sets: []string{
				"set protocols bgp local-as 65001",
				"set protocols bgp group EXT peer-as 65002",
				"set protocols bgp group EXT neighbor 10.0.0.1",
			},
		},
	}
	want := compileProtocolTree13531(t, hierTree(t, block))
	if want.Protocols.BGP.LocalAS != 65001 || len(want.Protocols.BGP.Neighbors) != 1 ||
		want.Protocols.BGP.Neighbors[0].Address != "10.0.0.1" || want.Protocols.BGP.Neighbors[0].PeerAS != 65002 {
		t.Fatalf("block reference did not compile expected neighbor: %+v", want.Protocols.BGP)
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := compileProtocolTree13531(t, flatTreeFromSets(t, tc.sets...))
			if got.Protocols.BGP.LocalAS != want.Protocols.BGP.LocalAS || len(got.Protocols.BGP.Neighbors) != 1 {
				t.Fatalf("flat form differs from block: local-as=%d neighbors=%d", got.Protocols.BGP.LocalAS, len(got.Protocols.BGP.Neighbors))
			}
			n := got.Protocols.BGP.Neighbors[0]
			if n.Address != want.Protocols.BGP.Neighbors[0].Address || n.PeerAS != want.Protocols.BGP.Neighbors[0].PeerAS {
				t.Fatalf("flat neighbor=%+v, block neighbor=%+v", n, want.Protocols.BGP.Neighbors[0])
			}
		})
	}
	t.Run("mixed block and flat", func(t *testing.T) {
		tree := hierTree(t, "protocols { bgp { local-as 65001; } }")
		for _, set := range []string{
			"set protocols bgp group EXT peer-as 65002",
			"set protocols bgp group EXT neighbor 10.0.0.1",
		} {
			path, err := ParseSetCommand(set)
			if err != nil {
				t.Fatal(err)
			}
			if err := tree.SetPath(path); err != nil {
				t.Fatal(err)
			}
		}
		got := compileProtocolTree13531(t, tree)
		if got.Protocols.BGP.LocalAS != want.Protocols.BGP.LocalAS || len(got.Protocols.BGP.Neighbors) != 1 ||
			got.Protocols.BGP.Neighbors[0].Address != want.Protocols.BGP.Neighbors[0].Address ||
			got.Protocols.BGP.Neighbors[0].PeerAS != want.Protocols.BGP.Neighbors[0].PeerAS {
			t.Fatalf("mixed form differs from block: %+v", got.Protocols.BGP)
		}
	})
}

func TestOSPFv3ChainedAreaMatchesBlock13531(t *testing.T) {
	const block = `protocols { ospf3 { router-id 1.1.1.1; area 0.0.0.0 { interface ge-0/0/0.0; } } }`
	cases := []struct {
		name string
		sets []string
	}{
		{
			name: "area chained after router-id",
			sets: []string{"set protocols ospf3 router-id 1.1.1.1 area 0.0.0.0 interface ge-0/0/0.0"},
		},
		{
			name: "split flat statements",
			sets: []string{
				"set protocols ospf3 router-id 1.1.1.1",
				"set protocols ospf3 area 0.0.0.0 interface ge-0/0/0.0",
			},
		},
	}
	want := compileProtocolTree13531(t, hierTree(t, block))
	if want.Protocols.OSPFv3.RouterID != "1.1.1.1" || len(want.Protocols.OSPFv3.Areas) != 1 || want.Protocols.OSPFv3.Areas[0].ID != "0.0.0.0" {
		t.Fatalf("block reference did not compile expected area: %+v", want.Protocols.OSPFv3)
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := compileProtocolTree13531(t, flatTreeFromSets(t, tc.sets...))
			if got.Protocols.OSPFv3.RouterID != want.Protocols.OSPFv3.RouterID || len(got.Protocols.OSPFv3.Areas) != 1 || got.Protocols.OSPFv3.Areas[0].ID != want.Protocols.OSPFv3.Areas[0].ID {
				t.Fatalf("flat OSPFv3 differs from block: %+v", got.Protocols.OSPFv3)
			}
			if len(got.Protocols.OSPFv3.Areas[0].Interfaces) != 1 || got.Protocols.OSPFv3.Areas[0].Interfaces[0].Name != want.Protocols.OSPFv3.Areas[0].Interfaces[0].Name {
				t.Fatalf("flat interfaces=%+v, block interfaces=%+v", got.Protocols.OSPFv3.Areas[0].Interfaces, want.Protocols.OSPFv3.Areas[0].Interfaces)
			}
		})
	}
	t.Run("mixed block and flat", func(t *testing.T) {
		tree := hierTree(t, "protocols { ospf3 { router-id 1.1.1.1; } }")
		path, err := ParseSetCommand("set protocols ospf3 area 0.0.0.0 interface ge-0/0/0.0")
		if err != nil {
			t.Fatal(err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatal(err)
		}
		got := compileProtocolTree13531(t, tree)
		if got.Protocols.OSPFv3.RouterID != want.Protocols.OSPFv3.RouterID ||
			len(got.Protocols.OSPFv3.Areas) != 1 ||
			got.Protocols.OSPFv3.Areas[0].ID != want.Protocols.OSPFv3.Areas[0].ID ||
			len(got.Protocols.OSPFv3.Areas[0].Interfaces) != 1 ||
			got.Protocols.OSPFv3.Areas[0].Interfaces[0].Name != want.Protocols.OSPFv3.Areas[0].Interfaces[0].Name {
			t.Fatalf("mixed form differs from block: %+v", got.Protocols.OSPFv3)
		}
	})
}

func compileProtocolTree13531(t *testing.T, tree *ConfigTree) *Config {
	t.Helper()
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("compile configuration: %v", err)
	}
	return cfg
}
