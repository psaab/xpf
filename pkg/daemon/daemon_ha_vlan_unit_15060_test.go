package daemon

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/cluster"
	"github.com/psaab/xpf/pkg/config"
)

// #15060 (A34-01): RG interface sets held only base RETH names, so a
// VLAN-tagged unit ref (reth0.80, resolving to ge-0-0-2.80) missed the set,
// followed RG0 in the #11415 FRR filter, and was invisible to the #11377
// readiness gate. Config mirrors the issue: reth0 in RG1 with members
// ge-0/0/2 (node 0) / ge-7/0/2 (node 1), unit 80 carrying vlan-id 80.

func vlanUnitConfig15060() *config.Config {
	return &config.Config{
		Chassis: config.ChassisConfig{Cluster: &config.ClusterConfig{
			NodeID: 0,
			RedundancyGroups: []*config.RedundancyGroup{
				{ID: 0, NodePriorities: map[int]int{0: 200, 1: 100}},
				{ID: 1, NodePriorities: map[int]int{0: 200, 1: 100}},
			},
		}},
		Interfaces: config.InterfacesConfig{Interfaces: map[string]*config.InterfaceConfig{
			"reth0": {Name: "reth0", VlanTagging: true, RedundancyGroup: 1, Units: map[int]*config.InterfaceUnit{
				0:  {Number: 0, Addresses: []string{"10.0.0.1/24"}},
				80: {Number: 80, VlanID: 80, Addresses: []string{"10.0.80.1/24"}},
			}},
			"ge-0/0/2": {Name: "ge-0/0/2", RedundantParent: "reth0"},
			"ge-7/0/2": {Name: "ge-7/0/2", RedundantParent: "reth0"},
			"lo0": {Name: "lo0", Units: map[int]*config.InterfaceUnit{
				0: {Number: 0, Addresses: []string{"192.0.2.1/32"}},
			}},
		}},
		Protocols: config.ProtocolsConfig{
			OSPF: &config.OSPFConfig{RouterID: "192.0.2.1", Areas: []*config.OSPFArea{{
				ID: "0.0.0.0", Interfaces: []*config.OSPFInterface{
					{Name: "reth0.0"},
					{Name: "reth0.80"},
				},
			}}},
			OSPFv3: &config.OSPFv3Config{Areas: []*config.OSPFv3Area{{
				ID: "0.0.0.0", Interfaces: []*config.OSPFv3Interface{
					{Name: "reth0.80"},
				},
			}}},
			RIP:  &config.RIPConfig{Interfaces: []string{"reth0.80"}},
			ISIS: &config.ISISConfig{Interfaces: []*config.ISISInterface{{Name: "reth0.80"}}},
		},
	}
}

func vlanUnitDaemon15060(t *testing.T) (*Daemon, *config.Config) {
	t.Helper()
	cfg := vlanUnitConfig15060()
	cm := cluster.NewManager(0, 1)
	cm.UpdateConfig(cfg.Chassis.Cluster)
	cm.SetGroupStateForTesting(0, cluster.StatePrimary)
	cm.SetGroupStateForTesting(1, cluster.StatePrimary)
	return &Daemon{cluster: cm}, cfg
}

func ospfNames15060(protocols config.ProtocolsConfig) []string {
	var names []string
	if protocols.OSPF != nil {
		for _, area := range protocols.OSPF.Areas {
			for _, iface := range area.Interfaces {
				names = append(names, iface.Name)
			}
		}
	}
	return names
}

func ospfv3Names15060(protocols config.ProtocolsConfig) []string {
	var names []string
	if protocols.OSPFv3 != nil {
		for _, area := range protocols.OSPFv3.Areas {
			for _, iface := range area.Interfaces {
				names = append(names, iface.Name)
			}
		}
	}
	return names
}

func isisNames15060(protocols config.ProtocolsConfig) []string {
	var names []string
	if protocols.ISIS != nil {
		for _, iface := range protocols.ISIS.Interfaces {
			names = append(names, iface.Name)
		}
	}
	return names
}

// FAIL-ON-REVERT: without unit expansion in the RG sets, reth0.80 misses the
// RG1 set and follows globalActive (RG0), so demoting RG1 alone keeps it.
func TestVLANUnitFollowsOwningRGNotRG015060(t *testing.T) {
	d, cfg := vlanUnitDaemon15060(t)

	// Both RGs primary: all protocol participation kept.
	state := newFRRHADemotionState(d, cfg)
	kept := state.filterProtocols(cfg, cfg.Protocols, nil)
	if got := ospfNames15060(kept); len(got) != 2 {
		t.Fatalf("both primary OSPF = %v, want reth0.0+reth0.80", got)
	}

	// Data RG1 demotes, RG0 stays local-primary: every reth0 unit must be
	// withdrawn — including the VLAN-tagged reth0.80 — while RG0 is active.
	d.cluster.SetGroupStateForTesting(1, cluster.StateSecondary)
	state = newFRRHADemotionState(d, cfg)
	filtered := state.filterProtocols(cfg, cfg.Protocols, nil)
	if got := ospfNames15060(filtered); len(got) != 0 {
		t.Errorf("RG1 secondary/RG0 primary OSPF = %v, want reth0.80 withdrawn with RG1", got)
	}
	if got := ospfv3Names15060(filtered); len(got) != 0 {
		t.Errorf("RG1 secondary/RG0 primary OSPFv3 = %v, want reth0.80 withdrawn", got)
	}
	if filtered.RIP != nil && len(filtered.RIP.Interfaces) != 0 {
		t.Errorf("RG1 secondary/RG0 primary RIP = %v, want reth0.80 withdrawn", filtered.RIP.Interfaces)
	}
	if got := isisNames15060(filtered); len(got) != 0 {
		t.Errorf("RG1 secondary/RG0 primary IS-IS = %v, want reth0.80 withdrawn", got)
	}
	// Direct probe: strict iff RG1 active, independent of RG0.
	if !state.inactiveInterface(cfg, "reth0.80", nil) {
		t.Error("inactiveInterface(reth0.80) = false with RG1 secondary, want true")
	}

	// Inverse: RG1 primary, RG0 secondary — reth0.80 must be KEPT even
	// though RG0 (the old fallback owner) is inactive.
	d.cluster.SetGroupStateForTesting(1, cluster.StatePrimary)
	d.cluster.SetGroupStateForTesting(0, cluster.StateSecondary)
	state = newFRRHADemotionState(d, cfg)
	if state.inactiveInterface(cfg, "reth0.80", nil) {
		t.Error("inactiveInterface(reth0.80) = true with RG1 primary/RG0 secondary, want false (kept iff RG1 active)")
	}
	kept = state.filterProtocols(cfg, cfg.Protocols, nil)
	if got := ospfNames15060(kept); len(got) != 2 {
		t.Errorf("RG1 primary/RG0 secondary OSPF = %v, want reth0.0+reth0.80 kept", got)
	}
}

// FAIL-ON-REVERT: without unit expansion, haRoutingRequirementsForRG(1)
// matches nothing for reth0.80 and the #11377 gate never gates on it.
func TestHARoutingRequirementsIncludeVLANUnit15060(t *testing.T) {
	cfg := vlanUnitConfig15060()

	reqs := haRoutingRequirementsForRG(cfg, 1)
	found := map[string]bool{}
	for _, req := range reqs {
		found[req.protocol] = true
		for _, iface := range req.interfaces {
			if iface == "ge-0-0-2.80" {
				found["netdev:"+req.protocol] = true
			}
		}
	}
	for _, proto := range []string{"ospf", "ospfv3", "rip", "isis"} {
		if !found[proto] {
			t.Errorf("RG1 requirements missing %s for reth0.80: %+v", proto, reqs)
		}
		if !found["netdev:"+proto] {
			t.Errorf("RG1 %s requirement lacks resolved netdev ge-0-0-2.80: %+v", proto, reqs)
		}
	}
	// RG with no interfaces: no requirements (unchanged).
	if got := haRoutingRequirementsForRG(cfg, 7); len(got) != 0 {
		t.Errorf("RG7 requirements = %+v, want none", got)
	}
	// Presence check via joined interfaces for diagnostics.
	var all []string
	for _, req := range reqs {
		all = append(all, req.interfaces...)
	}
	if !strings.Contains(strings.Join(all, ","), "ge-0-0-2.80") {
		t.Errorf("RG1 requirement interfaces = %v, want ge-0-0-2.80 present", all)
	}
}
