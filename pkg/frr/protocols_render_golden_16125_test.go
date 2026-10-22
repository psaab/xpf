package frr

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #16125: byte-identical golden corpus for the verbatim per-protocol
// extraction out of generateProtocolsCluster15158. Every fixture is a
// complete buildManagedSection render (the production assembly path,
// including cluster-mode and QNH wiring), compared byte-for-byte
// against a checked-in golden captured from the pre-extraction
// renderer. Any reordering of the OSPF/OSPFv3/BGP-pre-pass/BGP/RIP/
// IS-IS/BFD-tail sequence, renaming of a generated stanza, or drift
// in a shared-BFD accumulation changes bytes and fails here — the
// strings.Contains corpus elsewhere cannot prove that.

type goldenFixture16125 struct {
	name   string
	config *FullConfig
	// keyword is the top-level routing keyword the real-FRR oracle
	// mutates for its invalid-keyword control (empty = not in oracle).
	keyword string
}

func goldenFixtures16125() []goldenFixture16125 {
	return []goldenFixture16125{
		{
			name: "ospf-full",
			config: &FullConfig{OSPF: &config.OSPFConfig{
				RouterID: "10.0.0.1", ReferenceBandwidthMbps: 1000,
				Areas: []*config.OSPFArea{
					{ID: "0.0.0.0", Interfaces: []*config.OSPFInterface{
						{Name: "ge-0-0-0", Cost: 10, HelloInterval: 5, DeadInterval: 20, BFD: true, BFDInterval: 300, BFDMultiplier: 3},
						{Name: "ge-0-0-1", Passive: true},
					}},
					{ID: "0.0.0.1", AreaType: "stub", NoSummary: true, Interfaces: []*config.OSPFInterface{
						{Name: "ge-0-0-2", AuthType: "md5", AuthKey: config.NewSecret("ospf-secret"), AuthKeyID: 1},
					}},
					{ID: "0.0.0.2", Interfaces: []*config.OSPFInterface{
						{Name: "ge-0-0-3"},
					}, VirtualLinks: []*config.OSPFVirtualLink{{NeighborID: "10.0.0.9", TransitArea: "0.0.0.2"}}},
				},
				Export: []string{"connected", "static"},
			}},
			keyword: "router ospf",
		},
		{
			name: "ospfv3-full",
			config: &FullConfig{OSPFv3: &config.OSPFv3Config{
				RouterID: "10.0.0.2",
				Areas: []*config.OSPFv3Area{
					{ID: "0.0.0.0", Interfaces: []*config.OSPFv3Interface{
						{Name: "ge-0-0-0", Cost: 5, BFD: true},
						{Name: "ge-0-0-1", Passive: true, HasPriority: true, Priority: 0},
					}},
					{ID: "0.0.0.2", AreaType: "nssa", Interfaces: []*config.OSPFv3Interface{{Name: "ge-0-0-3"}}},
				},
				Export: []string{"connected"},
			}},
			keyword: "router ospf6",
		},
		{
			name: "bgp-full",
			config: &FullConfig{BGP: &config.BGPConfig{
				LocalAS: 65000, RouterID: "10.0.0.3", ClusterID: "10.0.0.3",
				GracefulRestart: true, LogNeighborChanges: true,
				Neighbors: []*config.BGPNeighbor{
					{Address: "192.0.2.1", PeerAS: 65001, BFD: true, BFDInterval: 300, BFDMultiplier: 3, Description: "ebgp peer"},
					{Address: "2001:db8::1", PeerAS: 65002},
					{Address: "10.0.0.9", PeerAS: 65000, LocalAddress: "10.0.0.3", BFD: true},
				},
				Export: []string{"connected", "static"},
			}},
			keyword: "router bgp ",
		},
		{
			name: "bgp-denied-malformed-auth",
			config: &FullConfig{BGP: &config.BGPConfig{
				LocalAS: 65000,
				Neighbors: []*config.BGPNeighbor{
					{Address: "192.0.2.1", PeerAS: 65001},
					{Address: "192.0.2.2", PeerAS: 65002, AuthPassword: config.NewSecret("bad password with spaces")},
					{Address: "192.0.2.3", PeerAS: 0},
				},
			}},
			keyword: "router bgp ",
		},
		{
			name: "rip-md5",
			config: &FullConfig{RIP: &config.RIPConfig{
				Interfaces: []string{"ge-0-0-0", "ge-0-0-1"}, Passive: []string{"ge-0-0-1"},
				Redistribute: []string{"connected", "static"},
				AuthType:     "md5", AuthKey: config.NewSecret("rip-secret"),
			}},
			keyword: "router rip",
		},
		{
			name: "rip-denied-malformed-auth",
			config: &FullConfig{RIP: &config.RIPConfig{
				Interfaces: []string{"ge-0-0-0"},
				AuthType:   "md5-typo", AuthKey: config.NewSecret("rip-secret"),
			}},
		},
		{
			name: "isis-full",
			config: &FullConfig{ISIS: &config.ISISConfig{
				NET: "49.0001.0100.0000.0001.00", Level: "level-1-2",
				WideMetricsOnly: true,
				AuthType:        "md5", AuthKey: config.NewSecret("isis-secret"),
				Interfaces: []*config.ISISInterface{
					{Name: "ge-0-0-0", Metric: 10, BFD: true, BFDInterval: 300, BFDMultiplier: 3},
					{Name: "ge-0-0-1", Passive: true, Level: "level-2"},
				},
				Export: []string{"connected"},
			}},
			keyword: "router isis ",
		},
		{
			name: "isis-denied-malformed-auth",
			config: &FullConfig{ISIS: &config.ISISConfig{
				NET: "49.0001.0100.0000.0001.00", Level: "level-2",
				AuthType: "md5-typo", AuthKey: config.NewSecret("isis-secret"),
				Interfaces: []*config.ISISInterface{{Name: "ge-0-0-0"}},
			}},
		},
		{
			name: "all-protocols-shared-bfd",
			config: &FullConfig{
				OSPF:   &config.OSPFConfig{RouterID: "10.0.0.1", Areas: []*config.OSPFArea{{ID: "0.0.0.0", Interfaces: []*config.OSPFInterface{{Name: "ge-0-0-0", BFD: true, BFDInterval: 300, BFDMultiplier: 3}}}}},
				OSPFv3: &config.OSPFv3Config{RouterID: "10.0.0.4", Areas: []*config.OSPFv3Area{{ID: "0.0.0.0", Interfaces: []*config.OSPFv3Interface{{Name: "ge-0-0-4", BFD: true}}}}},
				BGP:    &config.BGPConfig{LocalAS: 65000, Neighbors: []*config.BGPNeighbor{{Address: "192.0.2.1", PeerAS: 65001, BFD: true}}},
				RIP:    &config.RIPConfig{Interfaces: []string{"ge-0-0-1"}},
				ISIS:   &config.ISISConfig{NET: "49.0001.0100.0000.0001.00", Interfaces: []*config.ISISInterface{{Name: "ge-0-0-2", BFD: true}}},
			},
			keyword: "router bgp ",
		},
		{
			name: "vrf-all-protocols",
			config: &FullConfig{Instances: []InstanceConfig{{
				Name: "BLUE", VRFName: "vrf-BLUE", TableID: 101,
				OSPF:   &config.OSPFConfig{RouterID: "10.1.0.1", Areas: []*config.OSPFArea{{ID: "0.0.0.0", Interfaces: []*config.OSPFInterface{{Name: "ge-0-0-0"}}}}},
				OSPFv3: &config.OSPFv3Config{RouterID: "10.1.0.2", Areas: []*config.OSPFv3Area{{ID: "0.0.0.0", Interfaces: []*config.OSPFv3Interface{{Name: "ge-0-0-5"}}}}},
				BGP:    &config.BGPConfig{LocalAS: 65010, Neighbors: []*config.BGPNeighbor{{Address: "192.0.2.5", PeerAS: 65011, BFD: true}}},
				RIP:    &config.RIPConfig{Interfaces: []string{"ge-0-0-1"}},
				ISIS:   &config.ISISConfig{NET: "49.0001.0100.0000.0002.00", Interfaces: []*config.ISISInterface{{Name: "ge-0-0-2"}}},
			}}},
			keyword: "router bgp ",
		},
		{
			name:   "cluster-mode",
			config: clusterGolden16125(),
		},
		{
			name:   "qnh-ospf-export",
			config: qnhGolden16125(),
		},
	}
}

func clusterGolden16125() *FullConfig {
	return &FullConfig{
		ClusterMode:  true,
		StaticRoutes: []*config.StaticRoute{{Destination: "0.0.0.0/0", NextHops: []config.NextHopEntry{{Address: "192.0.2.254"}}}},
		OSPF:         &config.OSPFConfig{RouterID: "10.0.0.1", Areas: []*config.OSPFArea{{ID: "0.0.0.0", Interfaces: []*config.OSPFInterface{{Name: "ge-0-0-0"}}}}, Export: []string{"static"}},
		BGP:          &config.BGPConfig{LocalAS: 65000, Neighbors: []*config.BGPNeighbor{{Address: "192.0.2.1", PeerAS: 65001}}, Export: []string{"static"}},
	}
}

func qnhGolden16125() *FullConfig {
	compiled := compileQNHGolden16125()
	return &FullConfig{
		OSPF:          compiled.Protocols.OSPF,
		StaticRoutes:  compiled.RoutingOptions.StaticRoutes,
		PolicyOptions: &compiled.PolicyOptions,
	}
}

func compileQNHGolden16125() *config.Config {
	tree := &config.ConfigTree{}
	for _, command := range []string{
		"set routing-options static route 203.0.113.0/24 qualified-next-hop 192.0.2.10 metric 10",
		"set protocols ospf export static",
		"set protocols ospf area 0.0.0.0 interface ge-0/0/0",
	} {
		path, err := config.ParseSetCommand(command)
		if err != nil {
			panic(err)
		}
		if err := tree.SetPath(path); err != nil {
			panic(err)
		}
	}
	compiled, err := config.CompileConfig(tree)
	if err != nil {
		panic(err)
	}
	return compiled
}

// TestProtocolsRenderGolden16125 is the decisive byte-identity gate
// for the #16125 extraction: it needs no vtysh and runs everywhere.
func TestProtocolsRenderGolden16125(t *testing.T) {
	for _, tc := range goldenFixtures16125() {
		t.Run(tc.name, func(t *testing.T) {
			got := New().buildManagedSection(tc.config)
			want, err := os.ReadFile(filepath.Join("testdata", "golden16125", tc.name+".golden"))
			if err != nil {
				t.Fatalf("read golden: %v", err)
			}
			if got != string(want) {
				gotLines := strings.Split(got, "\n")
				wantLines := strings.Split(string(want), "\n")
				for i := 0; i < len(gotLines) || i < len(wantLines); i++ {
					var g, w string
					if i < len(gotLines) {
						g = gotLines[i]
					}
					if i < len(wantLines) {
						w = wantLines[i]
					}
					if g != w {
						t.Fatalf("byte drift at line %d:\n got: %q\nwant: %q\n--- got ---\n%s\n--- want ---\n%s", i+1, g, w, got, want)
					}
				}
				t.Fatalf("byte drift (length got %d want %d)", len(got), len(want))
			}
		})
	}
}

// TestGenerateGolden16125 regenerates the corpus; only run with
// UPDATE_GOLDEN16125=1. Goldens were first captured from the
// pre-extraction renderer (origin/master) — regenerating after the
// extraction without reviewing the diff defeats the gate.
func TestGenerateGolden16125(t *testing.T) {
	if os.Getenv("UPDATE_GOLDEN16125") == "" {
		t.Skip("set UPDATE_GOLDEN16125=1 to regenerate goldens")
	}
	for _, tc := range goldenFixtures16125() {
		got := New().buildManagedSection(tc.config)
		if err := os.WriteFile(filepath.Join("testdata", "golden16125", tc.name+".golden"), []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}
