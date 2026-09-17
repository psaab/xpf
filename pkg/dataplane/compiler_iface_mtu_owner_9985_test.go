package dataplane

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// An interface-level tunnel owns one resolved Linux netdev even when its zone
// references mix tagged and untagged units. The ownership decision must be
// made once for that netdev, rather than in the two reference branches.
func TestMTUOwnershipIsPerResolvedNetdev_9985(t *testing.T) {
	for _, refs := range [][]string{
		{"gre0.0", "gre0.10"},
		{"gre0.10", "gre0.0"},
	} {
		cfg := &config.Config{
			Security: config.SecurityConfig{Zones: map[string]*config.ZoneConfig{
				"z": {Name: "z", Interfaces: refs},
			}},
			Interfaces: config.InterfacesConfig{Interfaces: map[string]*config.InterfaceConfig{
				"gre0": {
					Name: "gre0", MTU: 1400,
					Tunnel: &config.TunnelConfig{Name: "gre0", Mode: "gre", Source: "192.0.2.1", Destination: "192.0.2.2"},
					Units: map[int]*config.InterfaceUnit{
						0:  {Number: 0},
						10: {Number: 10, VlanID: 10},
					},
				},
			}},
		}
		phys, _, _, _ := resolveInterfaceRef("gre0.0", cfg)
		if phys != "gre0" {
			t.Fatalf("gre0.0 resolved to %q, want one gre0 netdev", phys)
		}
		plan := planPhysDesired(cfg)
		pd := plan[phys]
		if pd == nil {
			t.Fatalf("plan[%s] = nil, want the untagged reference's desired-state row", phys)
		}
		if pd.mtu != 0 {
			t.Fatalf("plan[%s].mtu = %d, want 0: the tunnel owner must reconcile the value", phys, pd.mtu)
		}
	}
}
// An unzoned tunnel still owns its configured Linux device. A separately
// authored ordinary alias that canonicalizes to the same netdev must yield to
// that owner; discovering ownership only from zone references misses this.
func TestUnzonedTunnelOwnerSuppressesAliasReference_9985(t *testing.T) {
	cfg := &config.Config{
		Security: config.SecurityConfig{Zones: map[string]*config.ZoneConfig{
			"trust": {Name: "trust", Interfaces: []string{"gre/0.0"}},
		}},
		Interfaces: config.InterfacesConfig{Interfaces: map[string]*config.InterfaceConfig{
			"gre-0": {
				Name: "gre-0",
				Tunnel: &config.TunnelConfig{Name: "gre-0", Mode: "gre", Source: "192.0.2.1", Destination: "192.0.2.2"},
			},
			"gre/0": {
				Name: "gre/0", MTU: 1400,
				Units: map[int]*config.InterfaceUnit{0: {Number: 0}},
			},
		}},
	}
	phys, _, _, _ := resolveInterfaceRef("gre/0.0", cfg)
	if phys != "gre-0" {
		t.Fatalf("alias reference resolved to %q, want tunnel device gre-0", phys)
	}
	pd := planPhysDesired(cfg)[phys]
	if pd == nil {
		t.Fatalf("plan[%s] = nil, want the alias reference's desired-state row", phys)
	}
	if pd.mtu != 0 {
		t.Fatalf("plan[%s].mtu = %d, want 0: unzoned tunnel owner must suppress alias MTU", phys, pd.mtu)
	}
}

// An interface-level tunnel must not claim a different per-unit tunnel device.
// The unit tunnel is unusable here, so neither owner creates the child and the
// planner retains its configured MTU rather than silently deferring it.
func TestInterfaceTunnelDoesNotClaimPerUnitDevice_9985(t *testing.T) {
	cfg := &config.Config{
		Security: config.SecurityConfig{Zones: map[string]*config.ZoneConfig{
			"trust": {Name: "trust", Interfaces: []string{"gr-0/0/5.1"}},
		}},
		Interfaces: config.InterfacesConfig{Interfaces: map[string]*config.InterfaceConfig{
			"gr-0/0/5": {
				Name: "gr-0/0/5", MTU: 1400,
				Tunnel: &config.TunnelConfig{Name: "gr-0-0-5", Mode: "gre", Source: "192.0.2.1", Destination: "192.0.2.2"},
				Units: map[int]*config.InterfaceUnit{
					1: {Number: 1, MTU: 1300, Tunnel: &config.TunnelConfig{Name: "gr-0-0-5u1", Mode: "gre", Source: "192.0.2.1"}},
				},
			},
		}},
	}
	phys, _, _, _ := resolveInterfaceRef("gr-0/0/5.1", cfg)
	if phys != "gr-0-0-5u1" {
		t.Fatalf("per-unit reference resolved to %q, want child tunnel gr-0-0-5u1", phys)
	}
	pd := planPhysDesired(cfg)[phys]
	if pd == nil {
		t.Fatalf("plan[%s] = nil, want planner ownership for the uncreated child", phys)
	}
	if pd.mtu != 1300 {
		t.Fatalf("plan[%s].mtu = %d, want the child unit MTU 1300", phys, pd.mtu)
	}
}

// A tunneled reth stanza must not own its physical member. The zone ref
// resolves to the member, but the routing owner writes only the reth0 TUN;
// the member-side MTU stays planner-owned. Keying ownership by the resolved
// ref owned the member and yielded to nothing, since reth apply is a no-op
// on the member, so this pins the exactly-one-writer member plan.
func TestTunneledRethPlansMemberMTU_9985(t *testing.T) {
	cfg := &config.Config{
		Security: config.SecurityConfig{Zones: map[string]*config.ZoneConfig{
			"trust": {Name: "trust", Interfaces: []string{"reth0.0"}},
		}},
		Interfaces: config.InterfacesConfig{Interfaces: map[string]*config.InterfaceConfig{
			"reth0": {
				Name: "reth0", MTU: 1400, RedundancyGroup: 1,
				Tunnel: &config.TunnelConfig{Name: "reth0", Mode: "gre", Source: "192.0.2.1", Destination: "192.0.2.2"},
				Units: map[int]*config.InterfaceUnit{0: {Number: 0}},
			},
			"ge-0/0/0": {
				Name: "ge-0/0/0", RedundantParent: "reth0",
			},
		}},
	}
	phys, cfgName, unitNum, vlanID := resolveInterfaceRef("reth0.0", cfg)
	if phys != "ge-0-0-0" || cfgName != "reth0" || unitNum != 0 || vlanID != 0 {
		t.Fatalf("reth0.0 resolved to (%q, %q, unit %d, vlan %d), want (ge-0-0-0, reth0, unit 0, vlan 0)", phys, cfgName, unitNum, vlanID)
	}
	pd := planPhysDesired(cfg)[phys]
	if pd == nil {
		t.Fatalf("plan[%s] = nil, want the member-side desired-state row", phys)
	}
	if pd.mtu != 1400 {
		t.Fatalf("plan[%s].mtu = %d, want member MTU 1400: the reth TUN owner must not own the member", phys, pd.mtu)
	}
}

// The older tagged-only exception covered only the tagged arm. An untagged
// unit-level tunnel reaches the same resolved tunnel netdev through the other
// arm and must yield there too.
func TestUntaggedTunnelReferenceDoesNotPlanMTU_9985(t *testing.T) {
	cfg := &config.Config{
		Security: config.SecurityConfig{Zones: map[string]*config.ZoneConfig{
			"tunnels": {Name: "tunnels", Interfaces: []string{"ge-0/0/3.0"}},
		}},
		Interfaces: config.InterfacesConfig{Interfaces: map[string]*config.InterfaceConfig{
			"ge-0/0/3": {
				Name: "ge-0/0/3", MTU: 1400,
				Units: map[int]*config.InterfaceUnit{
					0: {Number: 0, MTU: 1300, Tunnel: &config.TunnelConfig{Name: "gr-0-0-3", Mode: "gre", Source: "192.0.2.1", Destination: "192.0.2.2"}},
				},
			},
		}},
	}
	phys, _, unit, vlan := resolveInterfaceRef("ge-0/0/3.0", cfg)
	if phys != "gr-0-0-3" || unit != 0 || vlan != 0 {
		t.Fatalf("reference resolved to (%q, unit %d, vlan %d), want tunnel netdev gr-0-0-3 unit 0 vlan 0", phys, unit, vlan)
	}
	pd := planPhysDesired(cfg)[phys]
	if pd == nil {
		t.Fatalf("plan[%s] = nil, want the untagged tunnel's desired-state row", phys)
	}
	if pd.mtu != 0 {
		t.Fatalf("plan[%s].mtu = %d, want 0: the tunnel owner must reconcile the unit MTU", phys, pd.mtu)
	}
}

// An unusable tunnel is not an MTU owner: the daemon does not create it, so
// the planner must retain the configured physical target instead of silently
// deferring it.
func TestUnusableTunnelDoesNotOwnMTU_9985(t *testing.T) {
	cfg := &config.Config{
		Security: config.SecurityConfig{Zones: map[string]*config.ZoneConfig{
			"tunnels": {Name: "tunnels", Interfaces: []string{"ge-0/0/4.0"}},
		}},
		Interfaces: config.InterfacesConfig{Interfaces: map[string]*config.InterfaceConfig{
			"ge-0/0/4": {
				Name: "ge-0/0/4", MTU: 1400,
				Units: map[int]*config.InterfaceUnit{
					0: {Number: 0, MTU: 1300, Tunnel: &config.TunnelConfig{Name: "gr-0-0-4", Mode: "gre", Source: "192.0.2.1"}},
				},
			},
		}},
	}
	phys, _, _, _ := resolveInterfaceRef("ge-0/0/4.0", cfg)
	pd := planPhysDesired(cfg)[phys]
	if pd == nil {
		t.Fatalf("plan[%s] = nil, want planner ownership when tunnel endpoints are unusable", phys)
	}
	if pd.mtu != 1300 {
		t.Fatalf("plan[%s].mtu = %d, want the configured unit MTU 1300", phys, pd.mtu)
	}
}

// A deleted interface-level mtu must not become a planner no-op. The explicit
// Linux default gives the actuator a target that resets a stale live MTU.
func TestDeletedInterfaceMTUPlansExplicitLinuxDefault_9985(t *testing.T) {
	cfg := &config.Config{
		Security: config.SecurityConfig{Zones: map[string]*config.ZoneConfig{
			"trust": {Name: "trust", Interfaces: []string{"ge-0/0/1.0"}},
		}},
		Interfaces: config.InterfacesConfig{Interfaces: map[string]*config.InterfaceConfig{
			"ge-0/0/1": {
				Name: "ge-0/0/1",
				Units: map[int]*config.InterfaceUnit{0: {Number: 0}},
			},
		}},
	}
	phys, _, _, _ := resolveInterfaceRef("ge-0/0/1.0", cfg)
	pd := planPhysDesired(cfg)[phys]
	if pd == nil {
		t.Fatalf("plan[%s] = nil, want an explicit reset target", phys)
	}
	if pd.mtu != defaultPhysicalMTU9985 {
		t.Fatalf("plan[%s].mtu = %d, want explicit Linux default %d", phys, pd.mtu, defaultPhysicalMTU9985)
	}
}
