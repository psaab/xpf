package config

import (
	"slices"
	"testing"
)

// #12844 (D3-09): HostInboundVRFEnslavedNetdevs resolved only keys[0] of a
// routing-instance member, so a bare member naming a multi-unit trunk
// enslaved only the first key's netdev (usually the physical parent), tunnel
// devices claimed by an explicit tunnel routing-instance stanza were never
// marked enslaved, and management interfaces bound to vrf-mgmt were ignored.
// The unzoned ingress guard then classified omitted slaves as iifname
// instead of sdifname, fail-opening unzoned VRF admission.

func sortedKeys12844(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}

func requireEnslaved12844(t *testing.T, cfg *Config, want ...string) {
	t.Helper()
	got := sortedKeys12844(HostInboundVRFEnslavedNetdevs(cfg))
	slices.Sort(want)
	if !slices.Equal(got, want) {
		t.Fatalf("HostInboundVRFEnslavedNetdevs = %v, want %v", got, want)
	}
}

func multiUnitTrunkCfg12844(member string) *Config {
	cfg := &Config{}
	cfg.Interfaces.Interfaces = map[string]*InterfaceConfig{
		"ge-0/0/1": {Name: "ge-0/0/1", Units: map[int]*InterfaceUnit{
			50: {Number: 50, VlanID: 50, Addresses: []string{"172.16.50.8/24"}},
			80: {Number: 80, VlanID: 80, Addresses: []string{"172.16.80.8/24"}},
		}},
		"ge-0/0/9": {Name: "ge-0/0/9", Units: map[int]*InterfaceUnit{
			0: {Number: 0, Addresses: []string{"192.0.2.9/24"}},
		}},
	}
	cfg.RoutingInstances = []*RoutingInstanceConfig{
		{Name: "tenant", InstanceType: "virtual-router", Interfaces: []string{member}},
	}
	return cfg
}

func TestHostInboundVRFEnslavedBareMemberFansDownAllUnits12844(t *testing.T) {
	cfg := multiUnitTrunkCfg12844("ge-0/0/1")
	// Every unit the bare member fans down onto is enslaved; the unreferenced
	// sibling ge-0/0/9 is not. The bare key itself was already resolved
	// pre-fix, so its parent name stays in the set.
	requireEnslaved12844(t, cfg, "ge-0-0-1", "ge-0-0-1.50", "ge-0-0-1.80")
}

func TestHostInboundVRFEnslavedUnitMemberBindsOnlyThatUnit12844(t *testing.T) {
	cfg := multiUnitTrunkCfg12844("ge-0/0/1.80")
	// A unit member must not fan up to the parent or sideways to unit 50.
	requireEnslaved12844(t, cfg, "ge-0-0-1.80")
}

func TestHostInboundVRFEnslavedTunnelStanzaClaim12844(t *testing.T) {
	cfg := &Config{}
	cfg.Interfaces.Interfaces = map[string]*InterfaceConfig{
		"gr-0/0/0": {
			Name:   "gr-0/0/0",
			Tunnel: &TunnelConfig{Name: "gr-0-0-0", Mode: "gre", Source: "192.0.2.1", Destination: "192.0.2.2", RoutingInstance: "tenant"},
			Units:  map[int]*InterfaceUnit{0: {Number: 0, Addresses: []string{"10.10.10.1/30"}}},
		},
		"ge-0/0/9": {Name: "ge-0/0/9", Units: map[int]*InterfaceUnit{
			0: {Number: 0, Addresses: []string{"192.0.2.9/24"}},
		}},
	}
	cfg.RoutingInstances = []*RoutingInstanceConfig{
		{Name: "tenant", InstanceType: "virtual-router"},
	}
	requireEnslaved12844(t, cfg, "gr-0-0-0")
}

func TestHostInboundVRFEnslavedManagementVRF12844(t *testing.T) {
	cfg := &Config{}
	cfg.Interfaces.Interfaces = map[string]*InterfaceConfig{
		"fxp0":     {Name: "fxp0", Units: map[int]*InterfaceUnit{0: {Number: 0, Addresses: []string{"192.168.1.1/24"}}}},
		"ge-0/0/9": {Name: "ge-0/0/9", Units: map[int]*InterfaceUnit{0: {Number: 0, Addresses: []string{"192.0.2.9/24"}}}},
	}
	// vrf-mgmt exists independently of tenant routing-instances.
	requireEnslaved12844(t, cfg, "fxp0")
}

func TestHostInboundVRFEnslavedForwardingInstanceNotEnslaved12844(t *testing.T) {
	cfg := multiUnitTrunkCfg12844("ge-0/0/1")
	cfg.RoutingInstances[0].InstanceType = "forwarding"
	requireEnslaved12844(t, cfg)
}

func TestHostInboundVRFEnslavedConflictedMemberExcluded12844(t *testing.T) {
	cfg := multiUnitTrunkCfg12844("ge-0/0/1")
	cfg.RoutingInstances = append(cfg.RoutingInstances, &RoutingInstanceConfig{
		Name: "other", InstanceType: "virtual-router", Interfaces: []string{"ge-0/0/1.80"},
	})
	// The contested unit must not be guessed as enslaved by either owner.
	requireEnslaved12844(t, cfg, "ge-0-0-1", "ge-0-0-1.50")
}
