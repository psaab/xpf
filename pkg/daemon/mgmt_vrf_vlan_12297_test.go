package daemon

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

func TestManagementVRFVLANUnits12297(t *testing.T) {
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
	got := managementVRFIfaceSet(cfg)
	for _, name := range []string{"fxp0", "fxp0.100"} {
		if !got[name] {
			t.Errorf("managementVRFIfaceSet omitted %s: %#v", name, got)
		}
	}
	for _, name := range []string{"ge-0-0-0", "ge-0-0-0.100"} {
		if got[name] {
			t.Errorf("non-management VLAN device %s was included: %#v", name, got)
		}
	}
}
