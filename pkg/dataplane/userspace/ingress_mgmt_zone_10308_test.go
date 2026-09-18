package userspace

import (
	"slices"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #10308: a data NIC placed in a security zone merely NAMED `mgmt` or
// `control` was taken off the adjudicated path by a zone-NAME arm in
// userspaceSkipsIngressInterface (and its Rust mirror
// include_userspace_binding_interface), while receiving none of the vrf-mgmt
// isolation that makes real lifelines safe — a zoned, policy-bearing
// interface acting as a kernel router while armed, committing strict-clean.
//
// The exemption is keyed on lifeline interface IDENTITY, not on zone name:
// fxp*/fab*/em*/lo0 rows stay skipped in ANY zone via netdevExclusionClasses
// (the device half of the same predicate), and a ge-*/reth*/... row in a
// mgmt/control-named zone is now adjudicated like any data NIC. The zone-name
// arm is deleted, not narrowed: nothing about a zone's NAME can describe
// whether its members are lifelines.
//
// Fail-on-revert: restore the `case "mgmt", "control"` arm and every
// adjudicated cell below goes RED while the lifeline controls stay green.

// A data NIC in a mgmt/control-named zone is NOT skipped: it keeps its
// ingress-map entry, its AF_XDP binding and its RSS-allowlist slot.
func TestUserspaceSkipsIngress10308_MgmtNamedDataNICIsAdjudicated(t *testing.T) {
	for _, zone := range []string{"mgmt", "control"} {
		for _, name := range []string{"ge-0/0/0", "ge-0/0/0.0", "reth0.0"} {
			iface := InterfaceSnapshot{Name: name, Zone: zone, LinuxName: "ge-0-0-0", Ifindex: 7}
			if userspaceSkipsIngressInterface(iface) {
				t.Errorf("userspaceSkipsIngressInterface(%s in zone %q) = true, want false — "+
					"a zone NAME grants no exemption; only lifeline interface identity does (#10308)",
					name, zone)
			}
		}
	}
}

// Lifelines stay skipped in EVERY zone, including the empty one: the name
// arms (fxp/em/fab/lo0) are properties of the DEVICE, independent of zoning.
func TestUserspaceSkipsIngress10308_LifelineNameStaysSkippedInAnyZone(t *testing.T) {
	for _, zone := range []string{"mgmt", "control", "trust", ""} {
		for _, name := range []string{"fxp0", "fxp0.0", "em0", "em0.0", "fab0", "fab1.0", "lo0"} {
			iface := InterfaceSnapshot{Name: name, Zone: zone, LinuxName: name, Ifindex: 42}
			if !userspaceSkipsIngressInterface(iface) {
				t.Errorf("userspaceSkipsIngressInterface(%s in zone %q) = false, want true — "+
					"lifeline interfaces must stay off the adjudicated path in any zone (#10308)",
					name, zone)
			}
		}
	}
}

// The ingress map admits mgmt/control-named data NICs and still withholds
// lifelines, wherever each is zoned.
func TestBuildUserspaceIngressIfindexes10308_MgmtNamedDataNICAdmitted(t *testing.T) {
	snap := &ConfigSnapshot{Interfaces: []InterfaceSnapshot{
		{Name: "ge-0/0/0", Zone: "mgmt", LinuxName: "ge-0-0-0", Ifindex: 7},
		{Name: "ge-0/0/1", Zone: "control", LinuxName: "ge-0-0-1", Ifindex: 8},
		{Name: "ge-0/0/2", Zone: "trust", LinuxName: "ge-0-0-2", Ifindex: 11},
		{Name: "fxp0", Zone: "mgmt", LinuxName: "fxp0", Ifindex: 42},
		{Name: "em0", Zone: "trust", LinuxName: "em0", Ifindex: 43},
	}}
	got := buildUserspaceIngressIfindexes(snap)
	for _, want := range []uint32{7, 8, 11} {
		if !slices.Contains(got, want) {
			t.Errorf("ingress set %v missing ifindex %d — a mgmt/control-named data NIC "+
				"must stay on the adjudicated path (#10308)", got, want)
		}
	}
	for _, excluded := range []uint32{42, 43} {
		if slices.Contains(got, excluded) {
			t.Errorf("ingress set %v contains lifeline ifindex %d — lifelines must stay "+
				"exempt in any zone (#10308)", got, excluded)
		}
	}
}

// The D3/RSS allowlist follows the same contract end to end: zone names
// filter nothing; lifeline names filter everywhere.
func TestUserspaceBoundLinuxInterfaces10308_ZoneNameFiltersNothing(t *testing.T) {
	cfg := &config.Config{}
	cfg.System.DataplaneType = "userspace"
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"ge-0/0/0": {Name: "ge-0/0/0", Units: map[int]*config.InterfaceUnit{0: {Number: 0}}},
		"ge-0/0/1": {Name: "ge-0/0/1", Units: map[int]*config.InterfaceUnit{0: {Number: 0}}},
		"ge-0/0/2": {Name: "ge-0/0/2", Units: map[int]*config.InterfaceUnit{0: {Number: 0}}},
		"fxp0":     {Name: "fxp0", Units: map[int]*config.InterfaceUnit{0: {Number: 0}}},
	}
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"mgmt":    {Name: "mgmt", Interfaces: []string{"ge-0/0/0"}},
		"control": {Name: "control", Interfaces: []string{"ge-0/0/1"}},
		"trust":   {Name: "trust", Interfaces: []string{"ge-0/0/2", "fxp0"}},
	}

	got := UserspaceBoundLinuxInterfaces(cfg)
	want := []string{"ge-0-0-0", "ge-0-0-1", "ge-0-0-2"}
	if slices.Compare(got, want) != 0 {
		t.Fatalf("allowlist = %v, want %v — mgmt/control zone names must not filter data "+
			"NICs, while the fxp0 lifeline stays filtered by NAME even in a data zone (#10308)",
			got, want)
	}
}
