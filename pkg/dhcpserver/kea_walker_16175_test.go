package dhcpserver

import (
	"bytes"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #16175: generateKea4Config, generateKea6Config, and
// SubnetIDAssignments15694 now share walkKeaSubnets. These tests pin the
// golden-JSON output for BOTH families (byte-identical renders of a
// kitchen-sink fixture) and the acceptance cells the issue names:
// subnet-less pool skip, interface-less group skip, duplicate-prefix
// claim (#9785), hash-collision probe (#5203), and the v6
// multi-interface refusal asymmetry (generators refuse;
// SubnetIDAssignments15694 does not).
//
// FAIL-ON-REVERT: reverting any consumer to its own hand-copy of the
// walk, or dropping a skip from walkKeaSubnets, makes the assignment map
// diverge from the rendered conf (or the goldens move).

// collidingPair16175 are two distinct canonical CIDRs whose FNV-1a
// stableSubnetID collides (brute-forced over 10.a.b.{0,64,128,192}/26),
// so the #5203 collision probe is exercised end-to-end through the walker.
const collidingA16175 = "10.10.32.64/26"
const collidingB16175 = "10.99.33.0/26"

func keaWalkerV4Fixture16175() *config.DHCPServerConfig {
	cfg := &config.DHCPServerConfig{
		DHCPLocalServer: &config.DHCPLocalServerConfig{
			SocketType: "udp",
			Groups: map[string]*config.DHCPServerGroup{
				"beta": {Name: "beta", Interfaces: []string{"ge-0-0-1"}, Pools: []*config.DHCPPool{
					{Name: "collide-b", Subnet: collidingB16175, RangeLow: "10.99.33.10", RangeHigh: "10.99.33.20"},
					{Name: "collide-a", Subnet: collidingA16175, RangeLow: "10.10.32.70", RangeHigh: "10.10.32.80"},
					{Name: "dup-of-alpha", Subnet: "10.0.1.1/25", RangeLow: "10.0.1.10", RangeHigh: "10.0.1.20"},
					{Name: "nosubnet"},
				}},
				"alpha": {Name: "alpha", Interfaces: []string{"ge-0-0-0"}, Pools: []*config.DHCPPool{
					{Name: "a0", Subnet: "10.0.1.0/25", RangeLow: "10.0.1.10", RangeHigh: "10.0.1.20",
						Router: "10.0.1.1", DNSServers: []string{"10.0.1.2", "10.0.1.3"}, Domain: "example.com", LeaseTime: 3600,
						StaticBindings: []*config.DHCPStaticBinding{
							{MACAddress: "AA:BB:CC:DD:EE:FF", FixedAddress: "10.0.1.50", HostName: "host-a"},
							{MACAddress: "not-a-mac", FixedAddress: "10.0.1.51"},
							nil,
							{MACAddress: "", FixedAddress: "10.0.1.52"},
						}},
				}},
				"noiface": {Name: "noiface", Pools: []*config.DHCPPool{
					{Name: "orphan", Subnet: "10.98.0.0/24", RangeLow: "10.98.0.10", RangeHigh: "10.98.0.20"},
				}},
			},
		},
	}
	return cfg
}

func keaWalkerV6Fixture16175() *config.DHCPServerConfig {
	return &config.DHCPServerConfig{
		DHCPv6LocalServer: &config.DHCPLocalServerConfig{
			Groups: map[string]*config.DHCPServerGroup{
				"beta": {Name: "beta", Interfaces: []string{"ge-0-0-1"}, Pools: []*config.DHCPPool{
					{Name: "b0", Subnet: "2001:db8:2::/64", RangeLow: "2001:db8:2::10", RangeHigh: "2001:db8:2::20",
						DNSServers: []string{"2001:db8::1"}, Domain: "example.com", LeaseTime: 7200,
						StaticBindings: []*config.DHCPStaticBinding{
							{MACAddress: "aa:bb:cc:dd:ee:01", FixedAddress: "2001:db8:2::50", HostName: "host-b"},
						}},
					{Name: "dup-of-alpha6", Subnet: "2001:db8:1::1/64"},
					{Name: "nosubnet6"},
				}},
				"alpha": {Name: "alpha", Interfaces: []string{"ge-0-0-0"}, Pools: []*config.DHCPPool{
					{Name: "a0", Subnet: "2001:db8:1::/64", RangeLow: "2001:db8:1::10", RangeHigh: "2001:db8:1::20"},
				}},
				"noiface": {Name: "noiface", Pools: []*config.DHCPPool{
					{Name: "orphan6", Subnet: "2001:db8:98::/64"},
				}},
			},
		},
	}
}

// The collision fixture uses the two brute-forced CIDRs; verify the pair
// really collides so the golden below is known to exercise the probe.
// The walk visits collide-a before collide-b (stablePools sorts by
// subnet), so collide-a keeps the shared base id and collide-b is the
// probe loser.
func TestKeaWalkerCollisionFixtureCollides16175(t *testing.T) {
	if stableSubnetID(collidingA16175) != stableSubnetID(collidingB16175) {
		t.Fatalf("fixture pair no longer collides: %s=%d %s=%d",
			collidingA16175, stableSubnetID(collidingA16175),
			collidingB16175, stableSubnetID(collidingB16175))
	}
}

func renderAndRead16175(t *testing.T, family string, cfg *config.DHCPServerConfig) []byte {
	t.Helper()
	m, _ := testManager(t, map[string]bool{}, "")
	var path string
	if family == "4" {
		if err := m.generateKea4Config(cfg); err != nil {
			t.Fatalf("generateKea4Config: %v", err)
		}
		path = m.confPath4
	} else {
		if err := m.generateKea6Config(cfg); err != nil {
			t.Fatalf("generateKea6Config: %v", err)
		}
		path = m.confPath6
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestKeaWalkerGoldenV4_16175(t *testing.T) {
	cfg := keaWalkerV4Fixture16175()
	got := renderAndRead16175(t, "4", cfg)
	// Golden captured from the pre-refactor renderer at ba55ef7 with the
	// colliding subnets in place of the original beta pools; the only
	// intentional delta from that capture is the colliding pair itself.
	want, err := os.ReadFile("testdata/kea_walker_golden4_16175.json")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("v4 golden drift:\n got: %s\nwant: %s", got, want)
	}
	v4, _ := SubnetIDAssignments15694(cfg)
	m, _ := testManager(t, map[string]bool{}, "")
	if err := m.generateKea4Config(cfg); err != nil {
		t.Fatal(err)
	}
	if wantMap := subnetIDMap(t, m.confPath4, "4"); !reflect.DeepEqual(v4, wantMap) {
		t.Errorf("v4 assignments %v != rendered %v", v4, wantMap)
	}
	for _, skipped := range []string{"10.98.0.0/24", "10.0.1.1/25"} {
		if _, ok := v4[skipped]; ok {
			t.Errorf("skipped pool %s took an id: %v", skipped, v4)
		}
	}
	if _, ok := v4[""]; ok {
		t.Errorf("subnet-less pool took an id: %v", v4)
	}
	// Collision: the winner keeps the shared base id, the loser probes
	// to a distinct id (#5203).
	base := stableSubnetID(collidingA16175)
	if v4[collidingA16175] != base {
		t.Errorf("collision winner id = %d, want base %d", v4[collidingA16175], base)
	}
	if loser := v4[collidingB16175]; loser == 0 || loser == base {
		t.Errorf("collision loser id = %d, want a probed id != base %d", loser, base)
	}
}

func TestKeaWalkerGoldenV6_16175(t *testing.T) {
	cfg := keaWalkerV6Fixture16175()
	got := renderAndRead16175(t, "6", cfg)
	want, err := os.ReadFile("testdata/kea_walker_golden6_16175.json")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("v6 golden drift:\n got: %s\nwant: %s", got, want)
	}
	_, v6 := SubnetIDAssignments15694(cfg)
	m, _ := testManager(t, map[string]bool{}, "")
	if err := m.generateKea6Config(cfg); err != nil {
		t.Fatal(err)
	}
	if wantMap := subnetIDMap(t, m.confPath6, "6"); !reflect.DeepEqual(v6, wantMap) {
		t.Errorf("v6 assignments %v != rendered %v", v6, wantMap)
	}
	for _, skipped := range []string{"2001:db8:98::/64", "2001:db8:1::1/64"} {
		if _, ok := v6[skipped]; ok {
			t.Errorf("skipped pool %s took an id: %v", skipped, v6)
		}
	}
}

// The v6 refusal asymmetry: the generator refuses a multi-interface (and
// a narrowed) v6 group, while SubnetIDAssignments15694 deliberately does
// not reproduce the refusal and still returns ids for the pools.
func TestKeaWalkerV6RefusalAsymmetry16175(t *testing.T) {
	cfg := &config.DHCPServerConfig{
		DHCPv6LocalServer: &config.DHCPLocalServerConfig{
			Groups: map[string]*config.DHCPServerGroup{
				"multi": {Name: "multi", Interfaces: []string{"ge-0-0-0", "ge-0-0-1"}, Pools: []*config.DHCPPool{
					{Name: "m0", Subnet: "2001:db8:7::/64", RangeLow: "2001:db8:7::10", RangeHigh: "2001:db8:7::20"},
				}},
			},
		},
	}
	m, _ := testManager(t, map[string]bool{}, "")
	if err := m.generateKea6Config(cfg); err == nil || !strings.Contains(err.Error(), "single interface selector") {
		t.Fatalf("generator must refuse multi-interface v6 group, got %v", err)
	}
	if _, v6 := SubnetIDAssignments15694(cfg); v6["2001:db8:7::/64"] == 0 {
		t.Errorf("assignments must NOT reproduce the v6 refusal, got %v", v6)
	}

	filtered := filteredGroupV6Config(true)
	m2, _ := testManager(t, map[string]bool{}, "")
	if err := m2.generateKea6Config(filtered); err == nil || !strings.Contains(err.Error(), "narrowed") {
		t.Fatalf("generator must refuse narrowed v6 group, got %v", err)
	}
	_, v6f := SubnetIDAssignments15694(filtered)
	if len(v6f) == 0 {
		t.Errorf("assignments must NOT reproduce the narrowed-group refusal, got %v", v6f)
	}
}
