package cli

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
)

// session_iface_shared_16065_test.go — #16065 (SI-6) decisive checks on
// the CLI surface (the same sessionFilter backs show AND clear).
//
// F2 shape: wg0.0 and wg0.1 share the one wg0 TUN AND the same zone
// (both units bound to it — the realistic config the first version of
// this test avoided). Their sessions share {ifindex 20, VID 0}, which
// the table REFUSES. A per-unit filter (wg0.0 / wg0.1) must NOT select
// the row — through the narrowed ambiguous fallback it can only be
// reached by naming the parent device itself ("wg0"). A genuinely
// identity-less row (peer-synced, ifindex 0) in the same zone keeps
// the historical zone fallback and DOES match a wg filter.
//
// F1 shape: parent-stamped VLAN ingress. Rows arrive stamped
// {parent 14, VID 50/80} (the AF_XDP bind-port stamp) in ONE zone
// binding both units; clearing/filtering .80 must select only the
// VID-80 row. The opposite (egress) arm is isolated with an unrelated
// precise egress that no filter here names.

const (
	wgSharedZone16065   uint16 = 1
	wgEgressZone16065   uint16 = 2
	vlanZone16065       uint16 = 1
	vlanEgressZone16065 uint16 = 2
)

func wgSharedTable16065(t *testing.T) config.SessionIfaceTable {
	t.Helper()
	cfg := &config.Config{
		Interfaces: config.InterfacesConfig{
			Interfaces: map[string]*config.InterfaceConfig{
				"wg0": {
					Name:   "wg0",
					Tunnel: &config.TunnelConfig{Mode: "wireguard", Name: "wg0"},
					Units: map[int]*config.InterfaceUnit{
						0: {Number: 0},
						1: {Number: 1},
					},
				},
			},
		},
	}
	table := buildSessionTableWithLookup(cfg, func(name string) (int, error) {
		if name == "wg0" {
			return 20, nil
		}
		t.Fatalf("unexpected lookup %q", name)
		return 0, nil
	})
	if !table.IsAmbiguous(sessionIfaceKey{Ifindex: 20, VlanID: 0}) {
		t.Fatal("premise: {20,0} must be refused (wg0.0 and wg0.1 share the TUN)")
	}
	return table
}

func wgSharedFilter16065(t *testing.T, iface string) *sessionFilter {
	t.Helper()
	table := wgSharedTable16065(t)
	return &sessionFilter{
		iface: iface,
		// BOTH wg units bound to the ingress zone — the F2 shape.
		zoneIfaces: map[uint16][]string{
			wgSharedZone16065: {"wg0.0", "wg0.1"},
			// Egress zone binds an unrelated interface so the egress
			// zone fallback cannot supply a wg match either.
			wgEgressZone16065: {"ge-0/0/9.0"},
		},
		ifaceNamesByKey: table.Names,
		ambiguousKeys:   table.Ambiguous,
	}
}

// wgRow16065 is a forward session on the shared TUN with an unrelated
// precise egress (FibIfindex 99 names nothing; egress zone is the
// unrelated zone), so only the ingress arm can select it.
func wgRow16065() (dataplane.SessionKey, dataplane.SessionValue) {
	return dataplane.SessionKey{Protocol: 6}, dataplane.SessionValue{
		IngressZone: wgSharedZone16065, EgressZone: wgEgressZone16065,
		IngressIfindex: 20, IngressVlanID: 0,
		FibIfindex: 99, FibVlanID: 0,
	}
}

func TestClearWgSiblingCannotDeleteOtherUnit16065(t *testing.T) {
	key, val := wgRow16065()
	key6 := dataplane.SessionKeyV6{Protocol: 6}
	val6 := dataplane.SessionValueV6{
		IngressZone: wgSharedZone16065, EgressZone: wgEgressZone16065,
		IngressIfindex: 20, IngressVlanID: 0, FibIfindex: 99,
	}

	for _, iface := range []string{"wg0.0", "wg0.1"} {
		if f := wgSharedFilter16065(t, iface); f.matchesV4(key, val) {
			t.Errorf("v4: filter %q selected a session on the shared wg TUN in a zone binding BOTH units: "+
				"clear %q would delete the sibling unit's sessions through the zone fallback (#16065 F2)", iface, iface)
		}
		if f := wgSharedFilter16065(t, iface); f.matchesV6(key6, val6) {
			t.Errorf("v6: filter %q selected a shared-TUN session (F2)", iface)
		}
	}
	// Naming the shared device as its parent reaches the row: the
	// narrowed candidate is the parent name itself.
	if f := wgSharedFilter16065(t, "wg0"); !f.matchesV4(key, val) {
		t.Error("filter wg0 (parent) must match a shared-TUN session via the narrowed ambiguous candidate")
	}
	// Identity-less (peer-synced) row: keeps the zone fallback, so a
	// per-unit wg filter DOES reach it — the narrowed path applies
	// only to rows carrying a refused identity.
	_, peerVal := wgRow16065()
	peerVal.IngressIfindex = 0
	if f := wgSharedFilter16065(t, "wg0.1"); !f.matchesV4(key, peerVal) {
		t.Error("identity-less peer row must stay reachable by wg0.1 through the zone fallback")
	}
}

func TestWgSharedDisplayNamesNeitherSibling16065(t *testing.T) {
	f := wgSharedFilter16065(t, "wg0.1")
	if name, ok := f.ingressIfaceIdentity(20, 0, wgSharedZone16065); ok || name != "" {
		t.Errorf("ingressIfaceIdentity(20,0) = %q,%v — the shared TUN must name neither sibling", name, ok)
	}
	got := f.resolveIngressIfaces(20, 0, wgSharedZone16065)
	if len(got) != 1 || got[0] != "wg0" {
		t.Errorf("resolveIngressIfaces = %v, want narrowed [wg0] (parent only), not every zone member", got)
	}
	// Display: refused identity prints no unit name.
	if name := f.ingressIfaceDisplay(20, 0, wgSharedZone16065); name == "wg0.0" || name == "wg0.1" {
		t.Errorf("ingressIfaceDisplay named sibling %q for the shared TUN", name)
	}
}

// F1: parent-stamped VLAN ingress in a multi-member zone.
func vlanDualFilter16065(t *testing.T, iface string) *sessionFilter {
	t.Helper()
	cfg := &config.Config{
		Interfaces: config.InterfacesConfig{
			Interfaces: map[string]*config.InterfaceConfig{
				"ge-0/0/3": {
					Name: "ge-0/0/3",
					Units: map[int]*config.InterfaceUnit{
						50: {Number: 50, VlanID: 50},
						80: {Number: 80, VlanID: 80},
					},
				},
			},
		},
	}
	table := buildSessionTableWithLookup(cfg, func(name string) (int, error) {
		switch name {
		case "ge-0-0-3":
			return 14, nil // parent/bind device
		case "ge-0-0-3.50":
			return 15, nil
		case "ge-0-0-3.80":
			return 16, nil
		}
		t.Fatalf("unexpected lookup %q", name)
		return 0, nil
	})
	// Non-vacuous premise: both parent-form entries exist.
	if table.Names[sessionIfaceKey{Ifindex: 14, VlanID: 50}] != "ge-0/0/3.50" ||
		table.Names[sessionIfaceKey{Ifindex: 14, VlanID: 80}] != "ge-0/0/3.80" {
		t.Fatalf("premise: parent-form table incomplete: %v", table.Names)
	}
	return &sessionFilter{
		iface: iface,
		zoneIfaces: map[uint16][]string{
			vlanZone16065:       {"ge-0/0/3.50", "ge-0/0/3.80"},
			vlanEgressZone16065: {"ge-0/0/9.0"},
		},
		ifaceNamesByKey: table.Names,
		ambiguousKeys:   table.Ambiguous,
	}
}

func TestParentStampedVlanIngressClearSelectsOnlyNamedUnit16065(t *testing.T) {
	key := dataplane.SessionKey{Protocol: 6}
	row50 := dataplane.SessionValue{
		IngressZone: vlanZone16065, EgressZone: vlanEgressZone16065,
		IngressIfindex: 14, IngressVlanID: 50, // parent stamp, VID 50
		FibIfindex: 99, // unrelated precise egress, names nothing here
	}
	row80 := row50
	row80.IngressVlanID = 80

	if f := vlanDualFilter16065(t, "ge-0/0/3.80"); f.matchesV4(key, row50) {
		t.Error("filter .80 selected the VID-50 parent-stamped row: parent keying lost, zone fallback widened the clear (#16065 F1)")
	}
	if f := vlanDualFilter16065(t, "ge-0/0/3.80"); !f.matchesV4(key, row80) {
		t.Error("filter .80 must select the VID-80 parent-stamped row")
	}
	if f := vlanDualFilter16065(t, "ge-0/0/3.50"); f.matchesV4(key, row80) {
		t.Error("filter .50 selected the VID-80 row (F1)")
	}
	// Child-stamped egress positive control: FibIfindex 16 (child .80)
	// with ingress kept as the precise .50 identity, so filter .80 can
	// reach the row ONLY via the egress arm.
	egressRow := row50
	egressRow.FibIfindex = 16
	egressRow.FibVlanID = 80
	if f := vlanDualFilter16065(t, "ge-0/0/3.80"); !f.matchesV4(key, egressRow) {
		t.Error("child-stamped egress {16,80} must match filter .80 through the egress arm")
	}
	if got := vlanDualFilter16065(t, "ge-0/0/3.50").resolveEgressIfaces(16, 80, vlanEgressZone16065); len(got) != 1 || got[0] != "ge-0/0/3.80" {
		t.Errorf("resolveEgressIfaces(16,80) = %v, want [ge-0/0/3.80] (child form, no zone broadening)", got)
	}
	// v6 twin.
	key6 := dataplane.SessionKeyV6{Protocol: 6}
	v6_50 := dataplane.SessionValueV6{IngressZone: vlanZone16065, EgressZone: vlanEgressZone16065, IngressIfindex: 14, IngressVlanID: 50, FibIfindex: 99}
	v6_80 := v6_50
	v6_80.IngressVlanID = 80
	if f := vlanDualFilter16065(t, "ge-0/0/3.80"); f.matchesV6(key6, v6_50) {
		t.Error("v6: filter .80 selected VID-50 row (F1)")
	}
	if f := vlanDualFilter16065(t, "ge-0/0/3.80"); !f.matchesV6(key6, v6_80) {
		t.Error("v6: filter .80 must select VID-80 row")
	}
}

// F3 on the CLI surface: tagged unit 0 matches an explicit ".0" filter.
func TestTaggedUnitZeroFilterMatches16065(t *testing.T) {
	cfg := &config.Config{
		Interfaces: config.InterfacesConfig{
			Interfaces: map[string]*config.InterfaceConfig{
				"ge-0/0/0": {Name: "ge-0/0/0", Units: map[int]*config.InterfaceUnit{
					0: {Number: 0, VlanID: 100},
				}},
			},
		},
	}
	table := buildSessionTableWithLookup(cfg, func(name string) (int, error) {
		switch name {
		case "ge-0-0-0":
			return 40, nil
		case "ge-0-0-0.100":
			return 41, nil
		}
		t.Fatalf("unexpected lookup %q", name)
		return 0, nil
	})
	if table.Names[sessionIfaceKey{Ifindex: 41, VlanID: 100}] != "ge-0/0/0.0" {
		t.Fatalf("premise: tagged unit 0 must keep .0 identity, table=%v", table.Names)
	}
	mk := func(iface string) *sessionFilter {
		return &sessionFilter{
			iface: iface,
			zoneIfaces: map[uint16][]string{
				1: {"ge-0/0/0.0", "ge-0/0/9.0"},
				2: {"ge-0/0/8.0"},
			},
			ifaceNamesByKey: table.Names,
			ambiguousKeys:   table.Ambiguous,
		}
	}
	key := dataplane.SessionKey{Protocol: 6}
	// Ingress parent-stamped {40,100}, egress isolated.
	ing := dataplane.SessionValue{IngressZone: 1, EgressZone: 2, IngressIfindex: 40, IngressVlanID: 100, FibIfindex: 99}
	if f := mk("ge-0/0/0.0"); !f.matchesV4(key, ing) {
		t.Error("explicit ge-0/0/0.0 filter must match tagged unit 0 (ingress, parent stamp)")
	}
	// Egress child-stamped {41,100}, ingress isolated.
	egr := dataplane.SessionValue{IngressZone: 1, EgressZone: 2, IngressIfindex: 0, FibIfindex: 41, FibVlanID: 100}
	if f := mk("ge-0/0/0.0"); !f.matchesV4(key, egr) {
		t.Error("explicit ge-0/0/0.0 filter must match tagged unit 0 (egress, child stamp)")
	}
	// Bare parent filter still matches (candidate starts-with equivalence
	// is filter-parent -> candidate-unit; here exact .0 also satisfies
	// parent filter via HasPrefix(candidate, filter+".")).
	if f := mk("ge-0/0/0"); !f.matchesV4(key, ing) {
		t.Error("bare parent filter ge-0/0/0 must still match its tagged unit 0")
	}
}
