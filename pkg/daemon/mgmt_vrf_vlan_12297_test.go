package daemon

import (
	"testing"

	"github.com/vishvananda/netlink"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/routing"
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

func TestUnzonedManagementVLANUnitDoesNotFailRebind12297(t *testing.T) {
	tree := &config.ConfigTree{}
	for _, line := range []string{
		"set interfaces fxp0 vlan-tagging",
		"set interfaces fxp0 unit 100 vlan-id 100",
		"set interfaces fxp0 unit 100 family inet address 192.0.2.10/24",
	} {
		path, err := config.ParseSetCommand(line)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", line, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", line, err)
		}
	}
	cfg, err := config.CompileConfig(tree)
	if err != nil {
		t.Fatalf("strict compile of unzoned management VLAN config: %v", err)
	}
	mgmtSet := managementVRFIfaceSet(cfg)
	for _, name := range []string{"fxp0", "fxp0.100"} {
		if !mgmtSet[name] {
			t.Fatalf("management VRF set omitted configured device %s: %v", name, mgmtSet)
		}
	}

	ops := newReconcileFakeLinkOps()
	ops.links["fxp0"] = &netlink.Device{
		LinkAttrs: netlink.LinkAttrs{Name: "fxp0", Index: 2},
	}
	ops.links[config.ManagementVRFDeviceName] = &netlink.Vrf{
		LinkAttrs: netlink.LinkAttrs{Name: config.ManagementVRFDeviceName, Index: 9},
		Table:     config.ManagementVRFTableID,
	}
	d := &Daemon{
		routing:      routing.NewManagerWithLinkOpsForTest(ops),
		linkByNameFn: ops.LinkByName,
	}
	d.publishMgmtVRFIfaces(mgmtSet)

	if _, exists := ops.links["fxp0.100"]; exists {
		t.Fatal("fixture unexpectedly materialized the unzoned VLAN child")
	}
	if err := d.rebindManagementVRFIfaces(cfg); err != nil {
		t.Fatalf("confirmed absence of the unzoned VLAN child must not fail commit: %v", err)
	}
}
