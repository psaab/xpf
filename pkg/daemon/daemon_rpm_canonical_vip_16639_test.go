package daemon

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// canonicalVIP16639Config builds a split-RG cluster shape for #16639:
// reth1 carries redundancy-group 2, RG1 is the lowest data RG (the
// fallback an unmatched ip-monitoring-referenced test gates by), and
// the WAN probe is ip-monitoring-referenced. mutate authors the
// interface side and the test's source-address in whatever spelling
// the row exercises.
func canonicalVIP16639Config(mutate func(cfg *config.Config)) *config.Config {
	cfg := &config.Config{}
	cfg.Services.RPM = &config.RPMConfig{Probes: map[string]*config.RPMProbe{
		"WAN": {Name: "WAN", Tests: map[string]*config.RPMTest{
			"v6-src": {Name: "v6-src", Target: "2001:db8:ffff::1"},
		}},
	}}
	cfg.Services.IPMonitoring = &config.IPMonitoringConfig{Policies: map[string]*config.IPMonitoringPolicy{
		"wan-failover": {Name: "wan-failover", MatchRPMProbe: "WAN"},
	}}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"reth0": {Name: "reth0", RedundancyGroup: 1, Units: map[int]*config.InterfaceUnit{
			0: {Number: 0, Addresses: []string{"2001:db8:1::1/64"}},
		}},
		"reth1": {Name: "reth1", RedundancyGroup: 2, Units: map[int]*config.InterfaceUnit{
			0: {Number: 0},
		}},
	}
	cfg.Chassis.Cluster = &config.ClusterConfig{
		ClusterID:        1,
		ControlInterface: "control0",
		RedundancyGroups: []*config.RedundancyGroup{{ID: 0}, {ID: 1}, {ID: 2}},
	}
	if mutate != nil {
		mutate(cfg)
	}
	return cfg
}

func setCanonicalUnit16639(cfg *config.Config, addrs ...string) {
	cfg.Interfaces.Interfaces["reth1"].Units[0].Addresses = addrs
}

func setCanonicalSource16639(cfg *config.Config, src string) {
	cfg.Services.RPM.Probes["WAN"].Tests["v6-src"].SourceAddress = src
}

// TestRPMProbeTestGatingCanonicalIPv6_16639 is the #16639 regression:
// the VIP->RG map and the source-address lookup were keyed by the
// authored strings, so a non-canonical IPv6 spelling (case, zero-run
// expansion, or a 4-in-6 form) on either side missed and the
// ip-monitoring-referenced test fell back to the lowest data RG (1)
// instead of the VIP owner's RG (2). Every non-canonical row below
// gates by RG1 pre-fix and RG2 post-fix; the exact-spelling and
// unrelated-source controls are unchanged in both.
func TestRPMProbeTestGatingCanonicalIPv6_16639(t *testing.T) {
	key := probeTestKey{"WAN", "v6-src"}
	cases := []struct {
		name   string
		mutate func(cfg *config.Config)
		want   int
	}{
		{
			name: "interface expanded uppercase, source compressed",
			mutate: func(cfg *config.Config) {
				setCanonicalUnit16639(cfg, "2001:0DB8:0000:0000:0000:0000:0000:0001/64")
				setCanonicalSource16639(cfg, "2001:db8::1")
			},
			want: 2,
		},
		{
			name: "interface compressed, source expanded uppercase",
			mutate: func(cfg *config.Config) {
				setCanonicalUnit16639(cfg, "2001:db8::1/64")
				setCanonicalSource16639(cfg, "2001:0DB8:0:0:0:0:0:1")
			},
			want: 2,
		},
		{
			name: "both sides non-canonical, different zero runs",
			mutate: func(cfg *config.Config) {
				setCanonicalUnit16639(cfg, "2001:0db8:0000:0000::0001/64")
				setCanonicalSource16639(cfg, "2001:DB8::1")
			},
			want: 2,
		},
		{
			name: "interface IPv4, source 4-in-6",
			mutate: func(cfg *config.Config) {
				setCanonicalUnit16639(cfg, "10.0.1.1/24")
				setCanonicalSource16639(cfg, "::ffff:10.0.1.1")
			},
			want: 2,
		},
		{
			name: "interface 4-in-6, source IPv4",
			mutate: func(cfg *config.Config) {
				setCanonicalUnit16639(cfg, "::ffff:10.0.1.1/120")
				setCanonicalSource16639(cfg, "10.0.1.1")
			},
			want: 2,
		},
		{
			name: "vrrp-group virtual-address non-canonical",
			mutate: func(cfg *config.Config) {
				setCanonicalUnit16639(cfg, "2001:db8::10/64")
				cfg.Interfaces.Interfaces["reth1"].Units[0].VRRPGroups = map[string]*config.VRRPGroup{
					"2001:db8::10/64_grp1": {ID: 1, VirtualAddresses: []string{"2001:0DB8:0000::1/64"}},
				}
				setCanonicalSource16639(cfg, "2001:db8::1")
			},
			want: 2,
		},
		{
			name: "control exact spelling",
			mutate: func(cfg *config.Config) {
				setCanonicalUnit16639(cfg, "2001:db8::1/64")
				setCanonicalSource16639(cfg, "2001:db8::1")
			},
			want: 2,
		},
		{
			name: "control IPv4 exact spelling",
			mutate: func(cfg *config.Config) {
				setCanonicalUnit16639(cfg, "10.0.2.1/24")
				setCanonicalSource16639(cfg, "10.0.2.1")
			},
			want: 2,
		},
		{
			name: "control unrelated source falls back to lowest data RG",
			mutate: func(cfg *config.Config) {
				setCanonicalUnit16639(cfg, "2001:db8::1/64")
				setCanonicalSource16639(cfg, "2001:db8::99")
			},
			want: 1,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := canonicalVIP16639Config(tc.mutate)
			got := rpmProbeTestGating(cfg)
			if got[key] != tc.want {
				t.Fatalf("gating[%v] = %d, want %d (full %v)", key, got[key], tc.want, got)
			}
		})
	}
}

// TestRPMProbeTestGatingCanonicalCompiled16639 drives the same shape
// through the production strict-compile path (configstore commit):
// both a unit-address-bound and a vrrp-group-virtual-address-bound
// IPv6 test whose spellings differ from the interface stanza must
// gate by RG2, and the RG2-primary node must run both.
func TestRPMProbeTestGatingCanonicalCompiled16639(t *testing.T) {
	store := testStoreWithSetConfig(t, []string{
		"set chassis cluster cluster-id 1",
		"set chassis cluster authentication-key test-cluster-psk-16639",
		"set chassis cluster redundancy-group 0 node 0 priority 200",
		"set chassis cluster redundancy-group 0 node 1 priority 100",
		"set chassis cluster redundancy-group 1 node 0 priority 200",
		"set chassis cluster redundancy-group 1 node 1 priority 100",
		"set chassis cluster redundancy-group 2 node 0 priority 100",
		"set chassis cluster redundancy-group 2 node 1 priority 200",
		"set interfaces ge-0/0/0 gigether-options redundant-parent reth0",
		"set interfaces ge-0/0/1 gigether-options redundant-parent reth1",
		"set interfaces reth0 redundant-ether-options redundancy-group 1",
		"set interfaces reth0 unit 0 family inet6 address 2001:db8:1::1/64",
		"set interfaces reth1 redundant-ether-options redundancy-group 2",
		"set interfaces reth1 unit 0 family inet6 address 2001:0DB8:0002:0000:0000:0000:0000:0010/64",
		"set interfaces reth1 unit 0 family inet6 address 2001:0DB8:0002:0000:0000:0000:0000:0010/64 vrrp-group 1 virtual-address 2001:0DB8:0002::1/64",
		"set services rpm probe WAN test via-unit probe-type icmp-ping",
		"set services rpm probe WAN test via-unit target address 2001:db8:ffff::1",
		"set services rpm probe WAN test via-unit source-address 2001:DB8:2::10",
		"set services rpm probe WAN test via-vrrp probe-type icmp-ping",
		"set services rpm probe WAN test via-vrrp target address 2001:db8:ffff::1",
		"set services rpm probe WAN test via-vrrp source-address 2001:db8:2::1",
		"set services ip-monitoring policy wan-failover match rpm-probe WAN",
		"set services ip-monitoring policy wan-failover then preferred-route route 0.0.0.0/0 next-hop 192.0.2.1",
	})
	cfg := store.ActiveConfig()
	if cfg == nil {
		t.Fatal("ActiveConfig is nil after commit")
	}
	got := rpmProbeTestGating(cfg)
	for _, test := range []string{"via-unit", "via-vrrp"} {
		if rg := got[probeTestKey{"WAN", test}]; rg != 2 {
			t.Fatalf("gating[WAN/%s] = %d, want 2 (full %v)", test, rg, got)
		}
	}

	// The RG2-primary node runs both tests; the RG1-primary node
	// (which does not hold the RG2 VIP) runs neither.
	rg2 := daemonPrimaryFor15074(t, map[int]bool{1: false, 2: true})
	names := probeTestNames(rg2.effectiveRPMConfig(cfg).Probes["WAN"])
	if !names["via-unit"] || !names["via-vrrp"] || len(names) != 2 {
		t.Fatalf("RG2-primary effective WAN tests = %v, want exactly {via-unit, via-vrrp}", names)
	}
	rg1 := daemonPrimaryFor15074(t, map[int]bool{1: true, 2: false})
	if _, ok := rg1.effectiveRPMConfig(cfg).Probes["WAN"]; ok {
		t.Fatalf("RG1-primary must drop WAN entirely, got %v",
			probeTestNames(rg1.effectiveRPMConfig(cfg).Probes["WAN"]))
	}
}
