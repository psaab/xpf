package daemon

import (
	"path/filepath"
	"testing"

	"github.com/psaab/xpf/pkg/cluster"
	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/configstore"
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

// TestSplitDistinctNodeIGPIdentitiesKeepBothRGOwners17874 proves the
// strict-commit remedy also survives the daemon belt: each peer's own
// distinct OSPF/OSPFv3/IS-IS identity keeps its owned RETH interface.
//
// FAIL-ON-REVERT: removing the peer-identity exemption makes node1
// withhold each multi-RG IGP despite strict per-node compilation passing.
func TestSplitDistinctNodeIGPIdentitiesKeepBothRGOwners17874(t *testing.T) {
	const source = `groups {
  node0 {
    chassis { cluster { node 0; } }
    protocols {
      ospf { router-id 10.0.0.1; }
      ospf3 { router-id 10.0.0.1; }
      isis { net 49.0001.0100.0000.0001.00; }
    }
  }
  node1 {
    chassis { cluster { node 1; } }
    protocols {
      ospf { router-id 10.0.0.2; }
      ospf3 { router-id 10.0.0.2; }
      isis { net 49.0001.0100.0000.0002.00; }
    }
  }
}

apply-groups "${node}";
chassis {
  cluster {
    cluster-id 1;
    authentication-key test-cluster-psk-17874-long;
    reth-count 2;
    no-private-rg-election;
    redundancy-group 0 { node 0 priority 200; node 1 priority 100; }
    redundancy-group 1 { node 0 priority 200; node 1 priority 100; }
    redundancy-group 2 { node 0 priority 100; node 1 priority 200; }
  }
}
interfaces {
  ge-0/0/1 { gigether-options { redundant-parent reth0; } }
  ge-7/0/1 { gigether-options { redundant-parent reth0; } }
  reth0 {
    redundant-ether-options { redundancy-group 1; }
    unit 0 { family inet { address 198.51.100.1/24; } }
  }
  ge-0/0/2 { gigether-options { redundant-parent reth1; } }
  ge-7/0/2 { gigether-options { redundant-parent reth1; } }
  reth1 {
    redundant-ether-options { redundancy-group 2; }
    unit 0 { family inet { address 203.0.113.1/24; } }
  }
}
protocols {
  ospf { area 0.0.0.0 { interface reth0.0; interface reth1.0; } }
  ospf3 { area 0.0.0.0 { interface reth0.0; interface reth1.0; } }
  isis { interface reth0.0; interface reth1.0; }
}
`
	stores := make([]*configstore.Store, 2)
	configs := make([]*config.Config, 2)
	for nodeID := range 2 {
		store, err := configstore.New(filepath.Join(t.TempDir(), "xpf.conf"))
		if err != nil {
			t.Fatalf("node%d configstore.New: %v", nodeID, err)
		}
		store.SetNodeID(nodeID)
		cfg, err := store.SyncApply(source, nil)
		if err != nil {
			t.Fatalf("node%d SyncApply: %v", nodeID, err)
		}
		if _, err := config.CompileConfigForNode(store.ActiveTree(), nodeID); err != nil {
			t.Fatalf("node%d strict compile rejected distinct identities: %v", nodeID, err)
		}
		stores[nodeID], configs[nodeID] = store, cfg
	}

	for nodeID, want := range map[int]string{0: "reth0.0", 1: "reth1.0"} {
		rg1, rg2 := cluster.StateSecondary, cluster.StatePrimary
		if nodeID == 0 {
			rg1, rg2 = cluster.StatePrimary, cluster.StateSecondary
		}
		manager := cluster.NewManager(nodeID, 1)
		manager.UpdateConfig(configs[nodeID].Chassis.Cluster)
		manager.SetGroupStateForTesting(0, cluster.StatePrimary)
		manager.SetGroupStateForTesting(1, rg1)
		manager.SetGroupStateForTesting(2, rg2)
		d := &Daemon{cluster: manager, store: stores[nodeID]}
		fc := d.assembleFRRConfig(configs[nodeID], nil)

		ospfNames := ospfIfaceNames17874(fc.OSPF)
		if len(ospfNames) != 1 || ospfNames[0] != want {
			t.Errorf("node%d OSPF interfaces = %v, want [%s]", nodeID, ospfNames, want)
		}
		ospf3Names := ospf3IfaceNames17874(fc.OSPFv3)
		if len(ospf3Names) != 1 || ospf3Names[0] != want {
			t.Errorf("node%d OSPFv3 interfaces = %v, want [%s]", nodeID, ospf3Names, want)
		}
		isisNames := isisIfaceNames17874(fc.ISIS)
		if len(isisNames) != 1 || isisNames[0] != want {
			t.Errorf("node%d IS-IS interfaces = %v, want [%s]", nodeID, isisNames, want)
		}
	}
}

func ospfIfaceNames17874(ospf *config.OSPFConfig) []string {
	if ospf == nil {
		return nil
	}
	var names []string
	for _, area := range ospf.Areas {
		if area == nil {
			continue
		}
		for _, iface := range area.Interfaces {
			if iface != nil {
				names = append(names, iface.Name)
			}
		}
	}
	return names
}

func ospf3IfaceNames17874(ospf *config.OSPFv3Config) []string {
	if ospf == nil {
		return nil
	}
	var names []string
	for _, area := range ospf.Areas {
		if area == nil {
			continue
		}
		for _, iface := range area.Interfaces {
			if iface != nil {
				names = append(names, iface.Name)
			}
		}
	}
	return names
}

func isisIfaceNames17874(isis *config.ISISConfig) []string {
	if isis == nil {
		return nil
	}
	var names []string
	for _, iface := range isis.Interfaces {
		if iface != nil {
			names = append(names, iface.Name)
		}
	}
	return names
}
