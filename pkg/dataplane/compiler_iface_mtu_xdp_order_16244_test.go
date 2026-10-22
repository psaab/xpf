package dataplane

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #16244 trace, daemon level: config mtu -> netdev propagation already
// happens in-order — planPhysDesired resolves one MTU per netdev and
// mapZoneInterface writes it (attemptPhysMTU9841) BEFORE LinkSetUp and
// before the deferred XDP attach (st.xdpIfindexes / pendingTC are only
// queued in the same call, actuated after all compile phases). So the
// MTU write survives XDP attach by construction; what cannot survive is
// the frame itself, because the AF_XDP helper binds without
// multi-buffer support into 4096-byte UMEM frames. The commit-time
// named refusal for that half lives in pkg/config
// (validateUserspaceRxMTUStrict, #16244); these cells pin the daemon
// half: the plan carries the configured MTU to the netdev, and a
// userspace-bound jumbo plan is exactly the shape the config gate
// refuses, so plan and gate cannot drift.

func TestPlanPhysDesiredCarriesJumboMTU16244(t *testing.T) {
	cfg := &config.Config{
		Security: config.SecurityConfig{Zones: map[string]*config.ZoneConfig{
			"trust": {Name: "trust", Interfaces: []string{"ge-0/0/1.0"}},
		}},
		Interfaces: config.InterfacesConfig{Interfaces: map[string]*config.InterfaceConfig{
			"ge-0/0/1": {
				Name: "ge-0/0/1", MTU: 9000,
				Units: map[int]*config.InterfaceUnit{
					0: {Number: 0, Addresses: []string{"10.0.1.1/24"}},
				},
			},
		}},
	}
	pd := planPhysDesired(cfg)["ge-0-0-1"]
	if pd == nil {
		t.Fatal("planPhysDesired produced no plan for ge-0-0-1")
	}
	if pd.mtu != 9000 || !pd.mtuExplicit {
		t.Fatalf("plan mtu = %d explicit=%v, want 9000 explicit — the configured MTU must reach the netdev plan that LinkSetMTU writes before XDP attach", pd.mtu, pd.mtuExplicit)
	}
}

func TestPlanPhysDesiredUnitOverrideJumbo16244(t *testing.T) {
	cfg := &config.Config{
		Security: config.SecurityConfig{Zones: map[string]*config.ZoneConfig{
			"trust": {Name: "trust", Interfaces: []string{"ge-0/0/1.0"}},
		}},
		Interfaces: config.InterfacesConfig{Interfaces: map[string]*config.InterfaceConfig{
			"ge-0/0/1": {
				Name: "ge-0/0/1", MTU: 1500,
				Units: map[int]*config.InterfaceUnit{
					0: {Number: 0, MTU: 9000, Addresses: []string{"10.0.1.1/24"}},
				},
			},
		}},
	}
	pd := planPhysDesired(cfg)["ge-0-0-1"]
	if pd == nil || pd.mtu != 9000 {
		t.Fatalf("plan mtu = %+v, want unit-override 9000 planned for the netdev", pd)
	}
}

func TestPlanPhysDesiredTaggedParentJumbo16244(t *testing.T) {
	cfg := &config.Config{
		Security: config.SecurityConfig{Zones: map[string]*config.ZoneConfig{
			"trust": {Name: "trust", Interfaces: []string{"ge-0/0/1.50"}},
		}},
		Interfaces: config.InterfacesConfig{Interfaces: map[string]*config.InterfaceConfig{
			"ge-0/0/1": {
				Name: "ge-0/0/1", VlanTagging: true, MTU: 9000,
				Units: map[int]*config.InterfaceUnit{
					50: {Number: 50, VlanID: 50, MTU: 1500, Addresses: []string{"10.0.50.1/24"}},
				},
			},
		}},
	}
	pd := planPhysDesired(cfg)["ge-0-0-1"]
	if pd == nil || pd.mtu != 9000 {
		t.Fatalf("tagged parent plan = %+v, want parent MTU 9000; the child's 1500 belongs to its VLAN device", pd)
	}
}

func TestPlanPhysDesiredTaggedSiblingOverride16244(t *testing.T) {
	cfg := &config.Config{
		Security: config.SecurityConfig{Zones: map[string]*config.ZoneConfig{
			"trust": {Name: "trust", Interfaces: []string{"ge-0/0/1.0", "ge-0/0/1.50"}},
		}},
		Interfaces: config.InterfacesConfig{Interfaces: map[string]*config.InterfaceConfig{
			"ge-0/0/1": {
				Name: "ge-0/0/1", VlanTagging: true, MTU: 9000,
				Units: map[int]*config.InterfaceUnit{
					0:  {Number: 0, MTU: 1500, Addresses: []string{"10.0.1.1/24"}},
					50: {Number: 50, VlanID: 50, Addresses: []string{"10.0.50.1/24"}},
				},
			},
		}},
	}
	pd := planPhysDesired(cfg)["ge-0-0-1"]
	if pd == nil || pd.mtu != 1500 {
		t.Fatalf("shared parent plan = %+v, want referenced untagged sibling MTU 1500", pd)
	}
}

func TestPlanPhysDesiredTaggedRETHParent16244(t *testing.T) {
	cfg := &config.Config{}
	cfg.Chassis.Cluster = &config.ClusterConfig{NodeID: 0}
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"trust": {Name: "trust", Interfaces: []string{"reth0.50"}},
	}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"reth0": {
			Name: "reth0", RedundancyGroup: 1, VlanTagging: true, MTU: 9000,
			Units: map[int]*config.InterfaceUnit{
				50: {Number: 50, VlanID: 50, MTU: 1500, Addresses: []string{"172.16.50.8/24"}},
			},
		},
		"ge-0/0/2": {Name: "ge-0/0/2", RedundantParent: "reth0"},
		"ge-7/0/2": {Name: "ge-7/0/2", RedundantParent: "reth0"},
	}
	plan := planPhysDesired(cfg)
	pd := plan["ge-0-0-2"]
	if pd == nil || pd.mtu != 9000 {
		t.Fatalf("tagged RETH parent plan[ge-0-0-2] = %+v, want local member MTU 9000", pd)
	}
	if len(plan) != 1 {
		t.Fatalf("tagged RETH plan has %d netdevs, want only local member ge-0-0-2: %v", len(plan), plan)
	}
}
