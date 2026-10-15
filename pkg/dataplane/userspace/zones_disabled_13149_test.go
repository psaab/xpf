package userspace

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #13149 (D3-03): disabled interfaces must not latch addressless signals or
// contribute config-derived VRRP VIPs to zoned or unzoned host-inbound sets.
func TestDisabledInterfaceNoPendingOrVIPLeak13149(t *testing.T) {
	tree := &config.ConfigTree{}
	for _, cmd := range []string{
		"set interfaces ge-0/0/0 disable",
		"set interfaces ge-0/0/0 unit 0 family inet address 192.0.2.1/24",
		"set interfaces ge-0/0/1 disable",
		"set interfaces ge-0/0/1 unit 0 family inet dhcp",
		"set interfaces ge-0/0/2 disable",
		"set interfaces ge-0/0/2 unit 0 family inet address 198.51.100.1/24 vrrp-group 1 virtual-address 198.51.100.254",
		"set interfaces ge-0/0/3 unit 0 family inet dhcp",
		"set interfaces ge-0/0/5 disable",
		"set interfaces ge-0/0/5 unit 0 family inet address 203.0.113.1/24 vrrp-group 2 virtual-address 203.0.113.254",
		"set security zones security-zone trust interfaces ge-0/0/0.0",
		"set security zones security-zone trust host-inbound-traffic system-services ssh",
		"set security zones security-zone wan interfaces ge-0/0/1.0",
		"set security zones security-zone wan host-inbound-traffic system-services ssh",
		"set security zones security-zone dmz interfaces ge-0/0/2.0",
		"set security zones security-zone dmz host-inbound-traffic system-services ssh",
		"set security zones security-zone ctrl interfaces ge-0/0/3.0",
		"set security zones security-zone ctrl host-inbound-traffic system-services ssh",
	} {
		p, err := config.ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(p); err != nil {
			t.Fatalf("SetPath(%q): %v", cmd, err)
		}
	}
	cfg, err := config.CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	snaps := buildInterfaceSnapshots(cfg)
	if az := addresslessEnforcingZonesFromSnapshots(cfg, snaps); len(az) != 1 || az[0].Zone != "ctrl" {
		t.Fatalf("addressless zones = %+v, want only enabled DHCP zone ctrl", az)
	}
	ai := addresslessEnforcingInterfacesFromSnapshots(cfg, snaps)
	if len(ai) != 1 || ai[0].Zone != "ctrl" || ai[0].Interface != "ge-0/0/3.0" {
		t.Fatalf("addressless interfaces = %+v, want only enabled DHCP ctrl interface", ai)
	}
	if !HostInboundPendingIntentFromSnapshots(cfg, snaps) {
		t.Fatal("enabled DHCP zone should keep pending intent true")
	}
	views := BuildZoneHostInboundViewsFromSnapshots(cfg, snaps)
	for _, v := range views {
		for _, addr := range v.V4Addrs {
			if addr == "198.51.100.254" {
				t.Fatalf("disabled VRRP VIP leaked into zone %s: %v", v.Zone, v.V4Addrs)
			}
		}
	}
	v4, _ := BuildUnzonedHostInboundAddrsFromSnapshots(cfg, snaps)
	for _, addr := range v4 {
		if addr == "198.51.100.254" || addr == "203.0.113.254" {
			t.Fatalf("disabled VRRP VIP leaked into unzoned addresses: %v", v4)
		}
	}
}

func TestDisabledRethHasNoStableHostInboundLinkLocal13149(t *testing.T) {
	cfg := &config.Config{
		Chassis: config.ChassisConfig{Cluster: &config.ClusterConfig{ClusterID: 1}},
		Interfaces: config.InterfacesConfig{Interfaces: map[string]*config.InterfaceConfig{
			"reth0":    {Name: "reth0", Disable: true, RedundancyGroup: 1},
			"ge-0/0/0": {Name: "ge-0/0/0", RedundantParent: "reth0"},
		}},
	}
	if targets := stableRethLinkLocalTargets(cfg); len(targets) != 0 {
		t.Fatalf("disabled reth emitted stable link-local targets: %+v", targets)
	}
	cfg.Interfaces.Interfaces["reth0"].Disable = false
	if targets := stableRethLinkLocalTargets(cfg); len(targets) == 0 {
		t.Fatal("enabled reth should retain stable link-local targets")
	}
}
