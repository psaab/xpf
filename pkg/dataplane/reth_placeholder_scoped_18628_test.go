package dataplane

import (
	"net"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/networkd"
)

// TestRethPlaceholderScopedByCluster_18628 pins every networkd emitter using
// the existing isVRRPReth guard. That guard does not classify election mode;
// this test ensures its existing devices get the same cluster/node-scoped
// format: a VLAN parent, its tagged child, and a regular member. It proves
// clusters 22/23 and nodes 0/1 produce distinct addresses.
//
// FAIL-ON-REVERT: restoring 169.254.<rg>.<node+1>/32 (or omitting clusterID
// from any emitter) makes the expected address cells fail; reverting all
// emitters also makes the cluster/node distinction assertions fail.
func TestRethPlaceholderScopedByCluster_18628(t *testing.T) {
	for _, tc := range []struct {
		name               string
		clusterID          int
		nodeID             int
		noRethVRRP         bool
		privateRGElection  bool
		want               string
	}{
		{name: "cluster 22 node 0", clusterID: 22, nodeID: 0, want: "169.254.22.3/32"},
		{name: "cluster 23 node 0", clusterID: 23, nodeID: 0, want: "169.254.23.3/32"},
		{name: "cluster 22 node 1", clusterID: 22, nodeID: 1, want: "169.254.22.4/32"},
		{name: "no-reth-vrrp preserves emission", clusterID: 22, nodeID: 0, noRethVRRP: true, want: "169.254.22.3/32"},
		{name: "private-rg-election preserves emission", clusterID: 22, nodeID: 0, privateRGElection: true, want: "169.254.22.3/32"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			models := placeholderScopeModels18628(t, tc.clusterID, tc.nodeID, tc.noRethVRRP, tc.privateRGElection)
			for _, name := range []string{"ge-0-0-2", "ge-0-0-2.80", "ge-0-0-3"} {
				model, ok := models[name]
				if !ok {
					t.Fatalf("missing model %s", name)
				}
				var addrs []string
				if name == "ge-0-0-2" {
					addrs = model.VLANParentAddresses
				} else {
					addrs = model.Addresses
				}
				if len(addrs) != 1 || addrs[0] != tc.want {
					t.Errorf("%s placeholder = %v, want [%s]", name, addrs, tc.want)
				}
			}
		})
	}

	// Cluster-id 0 means clustering is disabled, and no-cluster configurations
	// have no scope identity either. The helper renders octet 0 literally but
	// makes no uniqueness claim; it cannot distinguish separate such configs.
	// rg term pin (GLM seat): rg*2+node+1 must be injective across
	// (rg, node); the plausible mutant rg+node+2 agrees at rg=1 but
	// collides reth0/node1 with reth1/node0. rg=2 pins it.
	if got, want := config.RethPlaceholderAddress(22, 2, 0), "169.254.22.5/32"; got != want {
		t.Errorf("cluster 22 rg2 node0 placeholder = %q, want %q", got, want)
	}
	if got, want := config.RethPlaceholderAddress(0, 1, 0), "169.254.0.3/32"; got != want {
		t.Errorf("cluster-id-0 placeholder = %q, want %q (not unique)", got, want)
	}
}

func placeholderScopeModels18628(t *testing.T, clusterID, nodeID int, noRethVRRP, privateRGElection bool) map[string]networkd.InterfaceConfig {
	t.Helper()
	cfg := &config.Config{}
	cfg.Chassis.Cluster = &config.ClusterConfig{
		ClusterID: clusterID, NodeID: nodeID, RethCount: 2,
		NoRethVRRP: noRethVRRP, PrivateRGElection: privateRGElection,
	}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"reth0": {
			Name:            "reth0",
			RedundancyGroup: 1,
			VlanTagging:     true,
			Units: map[int]*config.InterfaceUnit{
				0:  {Number: 0, Addresses: []string{"192.0.2.1/24"}},
				80: {Number: 80, VlanID: 80, Addresses: []string{"192.0.2.80/24"}},
			},
		},
		"ge-0/0/2": {Name: "ge-0/0/2", RedundantParent: "reth0"},
		"reth1": {
			Name:            "reth1",
			RedundancyGroup: 1,
			Units:           map[int]*config.InterfaceUnit{0: {Number: 0, Addresses: []string{"198.51.100.1/24"}}},
		},
		"ge-0/0/3": {Name: "ge-0/0/3", RedundantParent: "reth1"},
	}
	result := &CompileResult{ifCache: map[string]*net.Interface{
		"ge-0-0-2": {Index: 2, Name: "ge-0-0-2", HardwareAddr: net.HardwareAddr{0x02, 0, 0, 0, 0, 2}},
		"ge-0-0-3": {Index: 3, Name: "ge-0-0-3", HardwareAddr: net.HardwareAddr{0x02, 0, 0, 0, 0, 3}},
	}}
	buildInterfaceNetworkdModels(cfg, result, map[string]bool{})
	models := make(map[string]networkd.InterfaceConfig, len(result.ManagedInterfaces))
	for _, model := range result.ManagedInterfaces {
		models[model.Name] = model
	}
	return models
}
