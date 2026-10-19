package daemon

import (
	"testing"

	"github.com/psaab/xpf/pkg/cluster"
	"github.com/psaab/xpf/pkg/config"
)

// #15783: staticHopActive reused the protocol-oriented inactiveInterface,
// whose !matched fallthrough follows instance groups and then RG0
// (globalActive). With RG0 (or the VRF's RETH RG) secondary that demoted
// statics whose egress is node-local, and the address walk never scanned
// vrrp-group VirtualAddresses. Tests always had RG0 primary (#15734).
//
// Three narrowed shapes (acceptance):
//  1. non-RETH interface-qualified static (explicit + v6-inferred) with
//     RG0 secondary — must be RETAINED;
//  2. IPv6 address-only static in a non-RETH (xe-0/0/0) prefix with RG0
//     secondary — must be RETAINED;
//  3. IPv4 static in a RETH vrrp-group virtual-address subnet (RG1 reth0)
//     with RG1 secondary — must be DEMOTED (pre-fix kept: FAIL-ON-REVERT
//     for the VRRP arm), and restored on promotion.
//
// Genuinely RG-owned RETH hops (address + qualified) must stay demoted,
// and dynamic protocols must keep their RG0-follow behaviour (guarded
// by the #11415 suite, not re-asserted here beyond a control).
//
// FAIL-ON-REVERT: restoring inactiveInterface in staticHopActive (or
// dropping VirtualAddresses from unitAddressOrVRRPContains) reds cells
// 1-3 respectively.
func frrStaticHAConfig15783() *config.Config {
	cfg := frrRGShutdownConfig11415()
	// reth0 (RG1): WAN. Configured prefix 172.16.50.8/24; the VRRP
	// virtual-address carries the wider gateway subnet 192.0.2.0/24's
	// host .1 — no configured unit address covers 192.0.2.0/24.
	cfg.Interfaces.Interfaces["reth0"].Units = map[int]*config.InterfaceUnit{
		0: {
			Number:    0,
			Addresses: []string{"198.51.100.1/24", "172.16.50.8/24", "2001:db8:50::8/64"},
			VRRPGroups: map[string]*config.VRRPGroup{
				"192.0.2.1_grp1": {ID: 1, VirtualAddresses: []string{"192.0.2.1/24"}},
			},
		},
	}
	// xe-0/0/0 (base fixture) is the node-local non-RETH interface:
	// 203.0.113.1/24. Add an IPv6 non-RETH prefix on a second plain iface.
	cfg.Interfaces.Interfaces["xe-0/0/1"] = &config.InterfaceConfig{
		Name: "xe-0/0/1", Units: map[int]*config.InterfaceUnit{
			0: {Number: 0, Addresses: []string{"2001:db8:113::1/64"}},
		},
	}
	// VRF tenant owns reth0.0 (RG1) — its statics follow RG1, not RG0.
	cfg.RoutingInstances = []*config.RoutingInstanceConfig{{
		Name:       "tenant",
		Interfaces: []string{"reth0.0"},
		StaticRoutes: []*config.StaticRoute{
			// Node-local qualified hop inside the VRF whose RETH RG is secondary.
			{Destination: "10.83.0.0/24", NextHops: []config.NextHopEntry{{Address: "203.0.113.2", Interface: "xe-0/0/0.0"}}},
		},
	}}
	cfg.RoutingOptions.StaticRoutes = []*config.StaticRoute{
		// (1) non-RETH interface-qualified, v4.
		{Destination: "10.83.1.0/24", NextHops: []config.NextHopEntry{{Address: "203.0.113.2", Interface: "xe-0/0/0.0"}}},
		// (3) IPv4 in RETH vrrp-group virtual-address subnet only.
		{Destination: "10.83.2.0/24", NextHops: []config.NextHopEntry{{Address: "192.0.2.9"}}},
		// Control: genuinely RG1-owned (configured RETH prefix).
		{Destination: "10.83.3.0/24", NextHops: []config.NextHopEntry{{Address: "172.16.50.1"}}},
		// Control: RG1-qualified.
		{Destination: "10.83.4.0/24", NextHops: []config.NextHopEntry{{Address: "172.16.50.1", Interface: "reth0.0"}}},
	}
	cfg.RoutingOptions.Inet6StaticRoutes = []*config.StaticRoute{
		// (1b) non-RETH interface-qualified, v6 (explicit).
		{Destination: "2001:db8:830::/64", NextHops: []config.NextHopEntry{{Address: "2001:db8:113::2", Interface: "xe-0/0/1.0"}}},
		// (2) IPv6 address-only in non-RETH prefix (also v6-inferred).
		{Destination: "2001:db8:831::/64", NextHops: []config.NextHopEntry{{Address: "2001:db8:113::2"}}},
		// Control: RG1 v6 prefix.
		{Destination: "2001:db8:832::/64", NextHops: []config.NextHopEntry{{Address: "2001:db8:50::1"}}},
	}
	return cfg
}

func hasDest15783(routes []*config.StaticRoute, dest string) bool {
	for _, r := range routes {
		if r != nil && r.Destination == dest && len(r.NextHops) > 0 {
			return true
		}
	}
	return false
}

func TestFRRStaticsNonRETHAndVRRP15783(t *testing.T) {
	cfg := frrStaticHAConfig15783()
	cm := cluster.NewManager(0, 1)
	cm.UpdateConfig(cfg.Chassis.Cluster)
	d := &Daemon{cluster: cm}

	// RG0 AND RG1 secondary: the HEADLINE state every #15734 test missed.
	cm.SetGroupStateForTesting(0, cluster.StateSecondary)
	cm.SetGroupStateForTesting(1, cluster.StateSecondary)
	fc := d.assembleFRRConfig(cfg, nil)

	// (1)+(2) node-local statics retained despite RG0 secondary.
	if !hasDest15783(fc.StaticRoutes, "10.83.1.0/24") {
		t.Errorf("RG0-secondary dropped non-RETH interface-qualified v4 static: %v", fc.StaticRoutes)
	}
	if !hasDest15783(fc.Inet6StaticRoutes, "2001:db8:830::/64") {
		t.Errorf("RG0-secondary dropped non-RETH interface-qualified v6 static: %v", fc.Inet6StaticRoutes)
	}
	if !hasDest15783(fc.Inet6StaticRoutes, "2001:db8:831::/64") {
		t.Errorf("RG0-secondary dropped IPv6 address-only static in non-RETH prefix: %v", fc.Inet6StaticRoutes)
	}
	// VRF cell: instance's RETH RG (RG1) secondary must not drop node-local hop.
	if len(fc.Instances) != 1 || !hasDest15783(fc.Instances[0].StaticRoutes, "10.83.0.0/24") {
		t.Errorf("VRF (RG1 secondary) dropped non-RETH interface-qualified static: %+v", fc.Instances)
	}
	// (3) VRRP-virtual-subnet static demoted with RG1 secondary (pre-fix kept).
	if hasDest15783(fc.StaticRoutes, "10.83.2.0/24") {
		t.Errorf("RG1-secondary kept static in RETH vrrp-group virtual-address subnet: %v", fc.StaticRoutes)
	}
	// Controls: genuinely RG-owned hops still demoted.
	if hasDest15783(fc.StaticRoutes, "10.83.3.0/24") {
		t.Errorf("RG1-secondary kept RETH-prefix static: %v", fc.StaticRoutes)
	}
	if hasDest15783(fc.StaticRoutes, "10.83.4.0/24") {
		t.Errorf("RG1-secondary kept RETH-qualified static: %v", fc.StaticRoutes)
	}
	if hasDest15783(fc.Inet6StaticRoutes, "2001:db8:832::/64") {
		t.Errorf("RG1-secondary kept RETH v6 static: %v", fc.Inet6StaticRoutes)
	}

	// RG0 stays secondary, RG1 promoted: only the RG-owned statics return;
	// node-local ones were never dropped so they simply remain.
	cm.SetGroupStateForTesting(1, cluster.StatePrimary)
	fc = d.assembleFRRConfig(cfg, nil)
	for _, dest := range []string{"10.83.2.0/24", "10.83.3.0/24", "10.83.4.0/24"} {
		if !hasDest15783(fc.StaticRoutes, dest) {
			t.Errorf("RG1-promoted (RG0 still secondary) missing %s: %v", dest, fc.StaticRoutes)
		}
	}
	if !hasDest15783(fc.Inet6StaticRoutes, "2001:db8:832::/64") {
		t.Errorf("RG1-promoted missing RETH v6 static: %v", fc.Inet6StaticRoutes)
	}
	if !hasDest15783(fc.StaticRoutes, "10.83.1.0/24") || !hasDest15783(fc.Inet6StaticRoutes, "2001:db8:831::/64") {
		t.Errorf("promotion lost node-local statics: v4=%v v6=%v", fc.StaticRoutes, fc.Inet6StaticRoutes)
	}
	if len(fc.Instances) != 1 || !hasDest15783(fc.Instances[0].StaticRoutes, "10.83.0.0/24") {
		t.Errorf("RG1-promoted VRF lost node-local static: %+v", fc.Instances)
	}

	// Committed config untouched.
	if len(cfg.RoutingOptions.StaticRoutes) != 4 || len(cfg.RoutingOptions.Inet6StaticRoutes) != 3 {
		t.Fatal("HA static filtering mutated the committed config")
	}
}
