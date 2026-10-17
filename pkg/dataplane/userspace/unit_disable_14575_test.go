package userspace

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/vishvananda/netlink"
)

// #14575 (Y02-03): a unit-level `disable` must reach the snapshot as
// AdminDisabled=true with no addresses on that unit's row, while a sibling
// enabled unit and the interface-level disable control behave as before.
//
// RED on master: InterfaceUnit has no Disable field, so the row for
// ge-0/0/1.0 carried AdminDisabled=false and 10.0.1.1/24.
func TestUnitDisableSnapshot14575(t *testing.T) {
	cfg := &config.Config{
		Interfaces: config.InterfacesConfig{Interfaces: map[string]*config.InterfaceConfig{
			"ge-0/0/1": {
				Name: "ge-0/0/1",
				Units: map[int]*config.InterfaceUnit{
					0: {Number: 0, Disable: true, Addresses: []string{"10.0.1.1/24"}},
					1: {Number: 1, VlanID: 100, Addresses: []string{"10.0.2.1/24"}},
				},
			},
		}},
	}
	oldBuild := buildLinkSnapshot
	buildLinkSnapshot = func(string) (int, int, string, []InterfaceAddressSnapshot) {
		return 27, 1500, "02:00:00:00:00:27", []InterfaceAddressSnapshot{{Family: "inet", Address: "198.51.100.9/24"}}
	}
	t.Cleanup(func() { buildLinkSnapshot = oldBuild })
	oldRule := ruleListFn
	ruleListFn = func(int) ([]netlink.Rule, error) { return nil, nil }
	t.Cleanup(func() { ruleListFn = oldRule })

	snaps := buildInterfaceSnapshotsFrom(cfg, map[string]bool{})
	byName := map[string]InterfaceSnapshot{}
	for _, s := range snaps {
		byName[s.Name] = s
	}
	u0, ok := byName["ge-0/0/1.0"]
	if !ok {
		t.Fatalf("ge-0/0/1.0 row missing: %v", byName)
	}
	if !u0.AdminDisabled {
		t.Errorf("ge-0/0/1.0 AdminDisabled=false, want true (unit disable)")
	}
	if len(u0.Addresses) != 0 {
		t.Errorf("ge-0/0/1.0 addresses = %+v, want none", u0.Addresses)
	}
	// Unit 0 collapses onto the base netdev: base row must not republish
	// the live address either.
	if base, ok := byName["ge-0/0/1"]; ok && len(base.Addresses) != 0 {
		t.Errorf("base ge-0/0/1 addresses = %+v, want none (unit 0 collapsed + disabled)", base.Addresses)
	}
	u1, ok := byName["ge-0/0/1.1"]
	if !ok {
		t.Fatalf("ge-0/0/1.1 row missing: %v", byName)
	}
	if u1.AdminDisabled {
		t.Errorf("sibling ge-0/0/1.1 AdminDisabled=true, want false")
	}
	found := false
	for _, a := range u1.Addresses {
		if a.Address == "10.0.2.1/24" {
			found = true
		}
	}
	if !found {
		t.Errorf("sibling ge-0/0/1.1 addresses = %+v, want 10.0.2.1/24", u1.Addresses)
	}

	// No connected/local/FIB state from the disabled unit.
	routes, _, err := buildRouteSnapshots(cfg, snaps, nil)
	if err != nil {
		t.Fatalf("buildRouteSnapshots: %v", err)
	}
	for _, r := range routes {
		if r.Destination == "10.0.1.0/24" {
			t.Errorf("disabled unit prefix leaked into routes: %+v", r)
		}
	}
	if v4 := pickInterfaceSnapshotV4(u0); v4 != nil {
		t.Errorf("disabled unit primary = %v, want nil", v4)
	}

	// Interface-level disable control: still disables the unit row.
	cfg.Interfaces.Interfaces["ge-0/0/1"].Units[0].Disable = false
	cfg.Interfaces.Interfaces["ge-0/0/1"].Disable = true
	ctrl := buildInterfaceSnapshotsFrom(cfg, map[string]bool{})
	for _, s := range ctrl {
		if s.Name == "ge-0/0/1.0" && (!s.AdminDisabled || len(s.Addresses) != 0) {
			t.Errorf("interface-disable control: ge-0/0/1.0 = %+v, want AdminDisabled with no addresses", s)
		}
	}
}
