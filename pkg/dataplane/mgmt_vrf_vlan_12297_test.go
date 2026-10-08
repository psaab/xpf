package dataplane

import (
	"net"
	"testing"

	"github.com/psaab/xpf/pkg/config"
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
