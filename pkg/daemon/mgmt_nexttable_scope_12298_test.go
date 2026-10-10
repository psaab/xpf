package daemon

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/routing"
)

// #12298: reconcile of the #12061 next-table scope exclusion against the #12297
// mgmt-VRF child binding. #12061 excludes the management class (including VLAN
// children like fxp0.100) from the next-table ingress scope, assuming mgmt-VRF
// membership; #12297 binds those children to vrf-mgmt (issue outcome (a)).
// Pin the joint invariant so neither side can regress alone: every
// management-class device is bound AND excluded, never one without the other,
// while ordinary transit units (untagged and tagged) stay scoped.
func TestManagementVLANChildrenBoundAndNotIngress12298(t *testing.T) {
	cfg := &config.Config{}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"fxp0": {
			Name:        "fxp0",
			VlanTagging: true,
			Units: map[int]*config.InterfaceUnit{
				100: {Number: 100, VlanID: 100},
			},
		},
		"em0": {
			Name:  "em0",
			Units: map[int]*config.InterfaceUnit{0: {Number: 0}},
		},
		"ge-0/0/1": {
			Name:  "ge-0/0/1",
			Units: map[int]*config.InterfaceUnit{0: {Number: 0}},
		},
		"ge-0/0/2": {
			Name:        "ge-0/0/2",
			VlanTagging: true,
			Units: map[int]*config.InterfaceUnit{
				50: {Number: 50, VlanID: 50},
			},
		},
	}

	// Bound side (#12297 outcome (a)): the tagged mgmt child is a vrf-mgmt
	// member alongside its parent and the untagged mgmt interface.
	bound := managementVRFIfaceSet(cfg)
	for _, name := range []string{"fxp0", "fxp0.100", "em0"} {
		if !bound[name] {
			t.Errorf("managementVRFIfaceSet omitted %s: %#v", name, bound)
		}
	}

	// Excluded side (#12061 stays correct): no management-class device is
	// default-instance ingress, while ordinary transit units still are.
	ingress := routing.DefaultInstanceIngressIfaces(cfg)
	if len(ingress) != 2 || ingress[0] != "ge-0-0-1" || ingress[1] != "ge-0-0-2.50" {
		t.Fatalf("default-instance ingress = %v, want [ge-0-0-1 ge-0-0-2.50]", ingress)
	}

	// Joint invariant: bound and ingress are disjoint — a unit cannot be in
	// both — and no management-class iif survives in the scope set.
	for _, iif := range ingress {
		if bound[iif] {
			t.Errorf("%s is bound to vrf-mgmt AND listed as default-instance "+
				"next-table ingress; a unit cannot be in both", iif)
		}
		if config.IsManagementIfName(iif) {
			t.Errorf("management-class interface %q is in the next-table ingress scope", iif)
		}
	}
}
