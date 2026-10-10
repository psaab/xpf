package dataplane

import (
	"net"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/networkd"
)

func TestManagementVRFVLANNetworkdModels12297(t *testing.T) {
	cfg := &config.Config{}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"fxp0": {
			Name:        "fxp0",
			VlanTagging: true,
			Units: map[int]*config.InterfaceUnit{
				100: {Number: 100, VlanID: 100},
			},
		},
		"ge-0/0/0": {
			Name:        "ge-0/0/0",
			VlanTagging: true,
			Units: map[int]*config.InterfaceUnit{
				100: {Number: 100, VlanID: 100},
			},
		},
	}
	result := &CompileResult{ifCache: map[string]*net.Interface{
		"fxp0":     {Index: 1, Name: "fxp0", HardwareAddr: net.HardwareAddr{0x02, 0, 0, 0, 0, 1}},
		"ge-0-0-0": {Index: 2, Name: "ge-0-0-0", HardwareAddr: net.HardwareAddr{0x02, 0, 0, 0, 0, 2}},
	}}
	buildInterfaceNetworkdModels(cfg, result, map[string]bool{})
	models := make(map[string]string, len(result.ManagedInterfaces))
	for _, model := range result.ManagedInterfaces {
		models[model.Name] = model.VRFName
	}
	for _, name := range []string{"fxp0", "fxp0.100"} {
		if got := models[name]; got != config.ManagementVRFDeviceName {
			t.Errorf("management VLAN networkd model %s VRFName = %q, want %q", name, got, config.ManagementVRFDeviceName)
		}
	}
	for _, name := range []string{"ge-0-0-0", "ge-0-0-0.100"} {
		if got := models[name]; got != "" {
			t.Errorf("ordinary VLAN networkd model %s VRFName = %q, want empty", name, got)
		}
	}
}

func TestManagementVRFNetworkdPreservesLinkControls12297(t *testing.T) {
	cfg := &config.Config{}
	cfg.Chassis.Cluster = &config.ClusterConfig{NodeID: 0, RethCount: 1}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"fxp0": {
			Name:        "fxp0",
			VlanTagging: true,
			Disable:     true,
			Speed:       "1g",
			Duplex:      "full",
			MTU:         9000,
			Description: "management uplink",
			Units: map[int]*config.InterfaceUnit{
				100: {Number: 100, VlanID: 100, MTU: 1400},
			},
		},
		"reth0": {
			Name:            "reth0",
			RedundancyGroup: 1,
			Units: map[int]*config.InterfaceUnit{
				0: {Number: 0, Addresses: []string{"192.0.2.1/24"}},
			},
		},
		"ge-0/0/2": {
			Name:            "ge-0/0/2",
			RedundantParent: "reth0",
			Description:     "wan",
		},
	}
	result := &CompileResult{ifCache: map[string]*net.Interface{
		"fxp0":     {Index: 1, Name: "fxp0", HardwareAddr: net.HardwareAddr{0x02, 0, 0, 0, 0, 1}},
		"ge-0-0-2": {Index: 2, Name: "ge-0-0-2", HardwareAddr: net.HardwareAddr{0x02, 0, 0, 0, 0, 2}},
	}}
	buildInterfaceNetworkdModels(cfg, result, map[string]bool{})

	models := make(map[string]networkd.InterfaceConfig, len(result.ManagedInterfaces))
	for _, model := range result.ManagedInterfaces {
		models[model.Name] = model
	}
	parent, ok := models["fxp0"]
	if !ok {
		t.Fatal("networkd model missing disabled tagged management parent fxp0")
	}
	if parent.VRFName != config.ManagementVRFDeviceName {
		t.Errorf("fxp0 VRFName = %q, want %q", parent.VRFName, config.ManagementVRFDeviceName)
	}
	if !parent.Disable || parent.Speed != "1g" || parent.Duplex != "full" || parent.MTU != 9000 {
		t.Errorf("fxp0 controls = disable:%t speed:%q duplex:%q mtu:%d; want true, 1g, full, 9000",
			parent.Disable, parent.Speed, parent.Duplex, parent.MTU)
	}
	if parent.Description != "management uplink" {
		t.Errorf("fxp0 description = %q, want %q", parent.Description, "management uplink")
	}

	child, ok := models["fxp0.100"]
	if !ok {
		t.Fatal("networkd model missing management VLAN child fxp0.100")
	}
	if child.VRFName != config.ManagementVRFDeviceName || child.MTU != 1400 {
		t.Errorf("fxp0.100 VRFName = %q, MTU = %d; want %q and 1400",
			child.VRFName, child.MTU, config.ManagementVRFDeviceName)
	}

	member, ok := models["ge-0-0-2"]
	if !ok {
		t.Fatal("networkd model missing VRRP RETH member ge-0-0-2")
	}
	if !member.KeepAddresses {
		t.Error("VRRP RETH member lost KeepAddresses")
	}
	if member.Description != "wan" {
		t.Errorf("VRRP RETH member description = %q, want %q", member.Description, "wan")
	}
	if len(member.Addresses) != 1 || member.Addresses[0] != "169.254.1.1/32" {
		t.Errorf("VRRP RETH member addresses = %v, want VRRP link-local base address", member.Addresses)
	}
}
