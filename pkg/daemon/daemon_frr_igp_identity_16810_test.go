package daemon

import (
	"testing"

	"github.com/psaab/xpf/pkg/cluster"
	"github.com/psaab/xpf/pkg/config"
)

// #16810 render belt: a leniently loaded cluster config with ONE
// shared OSPF router-id spanning RG1 (reth0) + RG2 (reth1) must not
// originate LSAs from both nodes in a split. The owner of the
// lowest spanning RG (RG1) keeps its per-RG-pruned OSPF; the other
// node withholds the whole protocol. Single-RG OSPF is untouched.
//
// FAIL-ON-REVERT: removing enforceSingleIGPParticipant16810 from
// filterProtocols makes the RG2-owner cell below keep reth1.0 under
// the shared 10.0.0.1 identity.

func igpSplitConfig16810() *config.Config {
	return &config.Config{
		Chassis: config.ChassisConfig{Cluster: &config.ClusterConfig{
			RedundancyGroups: []*config.RedundancyGroup{
				{ID: 0, NodePriorities: map[int]int{0: 200, 1: 100}},
				{ID: 1, NodePriorities: map[int]int{0: 200, 1: 100}},
				{ID: 2, NodePriorities: map[int]int{0: 100, 1: 200}},
			},
		}},
		Interfaces: config.InterfacesConfig{Interfaces: map[string]*config.InterfaceConfig{
			"reth0": {Name: "reth0", RedundancyGroup: 1, Units: map[int]*config.InterfaceUnit{
				0: {Number: 0, Addresses: []string{"198.51.100.1/24"}},
			}},
			"ge-0/0/1": {Name: "ge-0/0/1", RedundantParent: "reth0"},
			"ge-7/0/1": {Name: "ge-7/0/1", RedundantParent: "reth0"},
			"reth1": {Name: "reth1", RedundancyGroup: 2, Units: map[int]*config.InterfaceUnit{
				0: {Number: 0, Addresses: []string{"203.0.113.1/24"}},
			}},
			"ge-0/0/2": {Name: "ge-0/0/2", RedundantParent: "reth1"},
			"ge-7/0/2": {Name: "ge-7/0/2", RedundantParent: "reth1"},
		}},
		Protocols: config.ProtocolsConfig{
			OSPF: &config.OSPFConfig{RouterID: "10.0.0.1", Areas: []*config.OSPFArea{{
				ID: "0.0.0.0", Interfaces: []*config.OSPFInterface{
					{Name: "reth0.0"},
					{Name: "reth1.0"},
				},
			}}},
			ISIS: &config.ISISConfig{NET: "49.0001.0100.0000.0001.00", Interfaces: []*config.ISISInterface{
				{Name: "reth0.0"},
				{Name: "reth1.0"},
			}},
		},
	}
}

func igpDaemon16810(rg1, rg2 cluster.NodeState) *Daemon {
	cfg := igpSplitConfig16810()
	cm := cluster.NewManager(0, 1)
	cm.UpdateConfig(cfg.Chassis.Cluster)
	cm.SetGroupStateForTesting(0, cluster.StatePrimary)
	cm.SetGroupStateForTesting(1, rg1)
	cm.SetGroupStateForTesting(2, rg2)
	return &Daemon{cluster: cm}
}

func ospfIfaceNames16810(cfg *config.Config, d *Daemon) []string {
	fc := d.assembleFRRConfig(cfg, nil)
	if fc.OSPF == nil {
		return nil
	}
	var names []string
	for _, a := range fc.OSPF.Areas {
		for _, i := range a.Interfaces {
			names = append(names, i.Name)
		}
	}
	return names
}

func TestSplitSharedOSPFOnlyLowestRGParticipates16810(t *testing.T) {
	cfg := igpSplitConfig16810()

	// Split view from the RG1 owner (node0 also RG0 primary, RG2 secondary).
	d1 := igpDaemon16810(cluster.StatePrimary, cluster.StateSecondary)
	if got := ospfIfaceNames16810(cfg, d1); len(got) != 1 || got[0] != "reth0.0" {
		t.Errorf("RG1 owner OSPF interfaces = %v, want [reth0.0] participating", got)
	}
	fc1 := d1.assembleFRRConfig(cfg, nil)
	if fc1.ISIS == nil || len(fc1.ISIS.Interfaces) != 1 {
		t.Errorf("RG1 owner IS-IS interfaces = %+v, want 1 participating interface", fc1.ISIS)
	}

	// Split view from the RG2 owner: same shared identity, but this
	// node does not own the lowest spanning RG -> withhold entirely.
	d2 := igpDaemon16810(cluster.StateSecondary, cluster.StatePrimary)
	// d2's manager is node0-id but group states model the peer view:
	// RG1 secondary, RG2 primary is exactly node1's split state.
	if got := ospfIfaceNames16810(cfg, d2); len(got) != 0 {
		t.Errorf("RG2 owner OSPF interfaces = %v, want [] (withheld under shared identity #16810)", got)
	}
	fc2 := d2.assembleFRRConfig(cfg, nil)
	if fc2.ISIS != nil && len(fc2.ISIS.Interfaces) != 0 {
		t.Errorf("RG2 owner IS-IS interfaces = %+v, want withheld", fc2.ISIS)
	}
	// Source config must not be mutated by the belt.
	if len(cfg.Protocols.OSPF.Areas[0].Interfaces) != 2 || len(cfg.Protocols.ISIS.Interfaces) != 2 {
		t.Fatal("single-participant belt mutated the committed protocol config")
	}
}

func TestSingleRGSharedOSPFUnaffected16810(t *testing.T) {
	cfg := igpSplitConfig16810()
	cfg.Protocols.OSPF.Areas[0].Interfaces = []*config.OSPFInterface{{Name: "reth1.0"}}
	cfg.Protocols.ISIS.Interfaces = []*config.ISISInterface{{Name: "reth1.0"}}
	d := igpDaemon16810(cluster.StateSecondary, cluster.StatePrimary)
	if got := ospfIfaceNames16810(cfg, d); len(got) != 1 || got[0] != "reth1.0" {
		t.Errorf("single-RG OSPF interfaces = %v, want [reth1.0] on its owner", got)
	}
}
