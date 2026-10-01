package daemon

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/cluster"
	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/frr"
	"golang.org/x/sync/semaphore"
)

func frrRGShutdownConfig11415() *config.Config {
	return &config.Config{
		Chassis: config.ChassisConfig{Cluster: &config.ClusterConfig{
			RedundancyGroups: []*config.RedundancyGroup{
				{ID: 0, NodePriorities: map[int]int{0: 200, 1: 100}},
				{ID: 1, NodePriorities: map[int]int{0: 200, 1: 100}},
			},
		}},
		Interfaces: config.InterfacesConfig{Interfaces: map[string]*config.InterfaceConfig{
			"reth0": {Name: "reth0", RedundancyGroup: 1, Units: map[int]*config.InterfaceUnit{
				0: {Number: 0, Addresses: []string{"198.51.100.1/24"}},
			}},
			"ge-0/0/1": {Name: "ge-0/0/1", RedundantParent: "reth0"},
			"ge-7/0/1": {Name: "ge-7/0/1", RedundantParent: "reth0"},
			"lo0": {Name: "lo0", Units: map[int]*config.InterfaceUnit{
				0: {Number: 0, Addresses: []string{"192.0.2.1/32"}},
			}},
			"xe-0/0/0": {Name: "xe-0/0/0", Units: map[int]*config.InterfaceUnit{
				0: {Number: 0, Addresses: []string{"203.0.113.1/24"}},
			}},
		}},
		Protocols: config.ProtocolsConfig{
			BGP: &config.BGPConfig{LocalAS: 65000, Neighbors: []*config.BGPNeighbor{
				{Address: "198.51.100.2", PeerAS: 65001, LocalAddress: "198.51.100.1"},
				{Address: "203.0.113.2", PeerAS: 65000, LocalAddress: "192.0.2.1"},
			}},
			OSPF: &config.OSPFConfig{RouterID: "192.0.2.1", Areas: []*config.OSPFArea{{
				ID: "0.0.0.0", Interfaces: []*config.OSPFInterface{
					{Name: "reth0.0"},
					{Name: "xe-0/0/0.0"},
				},
			}}},
		},
	}
}

func newFRRRGShutdownDaemon11415(t *testing.T) (*Daemon, *config.Config) {
	t.Helper()
	cfg := frrRGShutdownConfig11415()
	cm := cluster.NewManager(0, 1)
	cm.UpdateConfig(cfg.Chassis.Cluster)
	cm.SetGroupStateForTesting(0, cluster.StatePrimary)
	cm.SetGroupStateForTesting(1, cluster.StatePrimary)
	return &Daemon{cluster: cm}, cfg
}

func frrNeighborSet11415(fc *frr.FullConfig) map[string]bool {
	got := make(map[string]bool)
	if fc != nil && fc.BGP != nil {
		for _, neighbor := range fc.BGP.Neighbors {
			if neighbor != nil {
				got[neighbor.Address] = true
			}
		}
	}
	return got
}

// TestDemotedPrimaryWithdrawsDynamicRouting11415 verifies both sides of the
// routing scope: RETH-bound BGP/OSPF state follows its data RG, while a
// loopback-sourced BGP peer follows cluster control ownership and is withdrawn
// when this node has no primary RG. Promotion must restore the same peers.
func TestDemotedPrimaryWithdrawsDynamicRouting11415(t *testing.T) {
	d, cfg := newFRRRGShutdownDaemon11415(t)
	assertNeighbors := func(label string, fc *frr.FullConfig, want ...string) {
		t.Helper()
		got := frrNeighborSet11415(fc)
		if len(got) != len(want) {
			t.Fatalf("%s BGP neighbor count = %d (%v), want %d (%v)", label, len(got), got, len(want), want)
		}
		for _, address := range want {
			if !got[address] {
				t.Errorf("%s omitted BGP neighbor %s: %v", label, address, got)
			}
		}
	}

	// Positive control: both peerings and both OSPF interfaces are active on
	// the local primary before any demotion.
	assertNeighbors("primary", d.assembleFRRConfig(cfg, nil), "198.51.100.2", "203.0.113.2")

	// Demote only data RG1. Its loopback peer remains available because RG0
	// still owns the global/control routing context.
	d.cluster.SetGroupStateForTesting(1, cluster.StateSecondary)
	fc := d.assembleFRRConfig(cfg, nil)
	assertNeighbors("RG1 secondary", fc, "203.0.113.2")
	if fc.OSPF == nil || len(fc.OSPF.Areas) != 1 {
		t.Fatalf("RG1 secondary OSPF config = %+v, want the non-RG interface retained", fc.OSPF)
	}
	var ospfIfaces []string
	for _, area := range fc.OSPF.Areas {
		for _, iface := range area.Interfaces {
			ospfIfaces = append(ospfIfaces, iface.Name)
		}
	}
	if len(ospfIfaces) != 1 || ospfIfaces[0] != "xe-0/0/0.0" {
		t.Errorf("RG1 secondary OSPF interfaces = %v, want only unscoped xe-0/0/0.0", ospfIfaces)
	}

	// Demoting the final primary must withdraw a surviving loopback iBGP
	// session too, rather than continuing to advertise from the old primary.
	d.cluster.SetGroupStateForTesting(0, cluster.StateSecondary)
	fc = d.assembleFRRConfig(cfg, nil)
	assertNeighbors("standby", fc)
	if fc.OSPF == nil || len(fc.OSPF.Areas) != 0 {
		t.Errorf("standby OSPF areas = %+v, want no originated adjacency after RG0 demotion", fc.OSPF)
	}
	// Promotion uses the same declarative render path to restore sessions.
	d.cluster.SetGroupStateForTesting(0, cluster.StatePrimary)
	d.cluster.SetGroupStateForTesting(1, cluster.StatePrimary)
	assertNeighbors("promoted", d.assembleFRRConfig(cfg, nil), "198.51.100.2", "203.0.113.2")

	// Exercise the actual FRR manager's managed-section writer with the demoted
	// assembly: no BGP neighbor stanza may remain in the active managed config.
	d.cluster.SetGroupStateForTesting(0, cluster.StateSecondary)
	d.cluster.SetGroupStateForTesting(1, cluster.StateSecondary)
	path := filepath.Join(t.TempDir(), "frr.conf")
	manager := frr.NewForTest(path, &frr.RecordingExecutor{})
	t.Cleanup(manager.Stop)
	if err := manager.ApplyFull(d.assembleFRRConfig(cfg, nil)); err != nil {
		t.Fatalf("ApplyFull(demoted config): %v", err)
	}
	rendered, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile(%q): %v", path, err)
	}
	for _, peer := range []string{"198.51.100.2", "203.0.113.2"} {
		if strings.Contains(string(rendered), "neighbor "+peer+" remote-as") {
			t.Errorf("demoted managed FRR config still declares neighbor %s", peer)
		}
	}
	if !strings.Contains(string(rendered), "router bgp 65000") {
		t.Fatal("demoted FRR config lost the positive-control local BGP process; neighbor absence would be vacuous")
	}
	if len(cfg.Protocols.BGP.Neighbors) != 2 || len(cfg.Protocols.OSPF.Areas[0].Interfaces) != 2 {
		t.Fatal("HA FRR filtering mutated the committed protocol config")
	}
}

func TestDemotedPrimaryWithdrawsRoutingInstancePeer11415(t *testing.T) {
	d, cfg := newFRRRGShutdownDaemon11415(t)
	cfg.RoutingInstances = []*config.RoutingInstanceConfig{{
		Name:       "tenant",
		Interfaces: []string{"reth0.0"},
		BGP: &config.BGPConfig{LocalAS: 65010, Neighbors: []*config.BGPNeighbor{{
			Address: "198.51.100.2", PeerAS: 65001, LocalAddress: "198.51.100.1",
		}}},
	}}
	assertInstancePeer := func(label string, want bool) {
		t.Helper()
		fc := d.assembleFRRConfig(cfg, nil)
		if len(fc.Instances) != 1 || fc.Instances[0].Name != "tenant" {
			t.Fatalf("%s routing instances = %+v, want tenant", label, fc.Instances)
		}
		neighbors := frrNeighborSet11415(&frr.FullConfig{BGP: fc.Instances[0].BGP})
		if neighbors["198.51.100.2"] != want || len(neighbors) != boolInt11415(want) {
			t.Errorf("%s tenant BGP neighbors = %v, want peer present=%v", label, neighbors, want)
		}
	}
	assertInstancePeer("primary", true)
	d.cluster.SetGroupStateForTesting(1, cluster.StateSecondary)
	assertInstancePeer("RG1 secondary", false)
	d.cluster.SetGroupStateForTesting(1, cluster.StatePrimary)
	assertInstancePeer("promoted", true)
}

func boolInt11415(value bool) int {
	if value {
		return 1
	}
	return 0
}

type frrHAEventExecutor11415 struct {
	reloaded chan struct{}
}

func (*frrHAEventExecutor11415) Vtysh(context.Context, string) (string, error) {
	return "", nil
}

func (e *frrHAEventExecutor11415) FrrReloadPy(context.Context, string) error {
	e.reloaded <- struct{}{}
	return nil
}

func (*frrHAEventExecutor11415) VtyshLoad(context.Context, string) ([]byte, error) {
	return nil, nil
}

func (*frrHAEventExecutor11415) VtyshStream(context.Context, string) (io.ReadCloser, func() error, error) {
	return io.NopCloser(strings.NewReader("")), func() error { return nil }, nil
}

func TestClusterDemotionReconcilesFRR11415(t *testing.T) {
	const setConfig = fenceStartupClusterSet +
		"set chassis cluster no-reth-vrrp\n" +
		"set interfaces ge-0/0/1 gigether-options redundant-parent reth0\n" +
		"set interfaces reth0 redundant-ether-options redundancy-group 1\n" +
		"set interfaces reth0 unit 0 family inet address 198.51.100.1/24\n" +
		"set interfaces lo0 unit 0 family inet address 192.0.2.1/32\n" +
		"set interfaces xe-0/0/0 unit 0 family inet address 203.0.113.1/24\n" +
		"set protocols bgp local-as 65000\n" +
		"set protocols bgp group EXT neighbor 198.51.100.2 peer-as 65001\n" +
		"set protocols bgp group EXT neighbor 198.51.100.2 local-address 198.51.100.1\n" +
		"set protocols bgp group IBGP neighbor 203.0.113.2 peer-as 65000\n" +
		"set protocols bgp group IBGP neighbor 203.0.113.2 local-address 192.0.2.1\n" +
		"set protocols ospf area 0.0.0.0 interface reth0.0\n" +
		"set protocols ospf area 0.0.0.0 interface xe-0/0/0.0\n"
	store := fenceTestStore(t, setConfig)
	d := newActuationDaemon(t, &actuationHA{})
	d.store = store
	d.cluster.UpdateConfig(store.ActiveConfig().Chassis.Cluster)
	d.cluster.SetGroupStateForTesting(0, cluster.StatePrimary)
	d.cluster.SetGroupStateForTesting(1, cluster.StatePrimary)
	d.applySem = semaphore.NewWeighted(1)
	d.directRemoveVIPsFn = func(int) int { return 0 }
	d.directRemoveStableLLFn = func(int) {}

	path := filepath.Join(t.TempDir(), "frr.conf")
	executor := &frrHAEventExecutor11415{reloaded: make(chan struct{}, 2)}
	manager := frr.NewForTest(path, executor)
	t.Cleanup(manager.Stop)
	d.frr = manager

	d.cluster.SetGroupStateForTesting(1, cluster.StateSecondary)
	d.handleClusterEvent(context.Background(), cluster.ClusterEvent{
		GroupID: 1, OldState: cluster.StatePrimary, NewState: cluster.StateSecondary,
	}, nil)
	select {
	case <-executor.reloaded:
	case <-time.After(3 * time.Second):
		t.Fatal("RG1 demotion did not trigger an FRR reload")
	}
	rendered, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile(%q): %v", path, err)
	}
	if strings.Contains(string(rendered), "neighbor 198.51.100.2 remote-as") {
		t.Fatal("RG1 demotion left its RETH-scoped BGP session in managed FRR config")
	}
	if !strings.Contains(string(rendered), "neighbor 203.0.113.2 remote-as") {
		t.Fatal("RG1 demotion removed the loopback peer still owned by RG0")
	}
}
