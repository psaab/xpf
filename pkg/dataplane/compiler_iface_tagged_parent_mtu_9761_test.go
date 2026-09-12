package dataplane

import (
	"fmt"
	"net"
	"testing"

	"github.com/vishvananda/netlink"

	"github.com/psaab/xpf/pkg/config"
)

// #9761: an interface-level mtu on a vlan-tagging interface whose zone
// references are all tagged units must still reach the parent link.
//
// planPhysDesired used to skip every tagged reference outright, so such a parent
// got no plan, and the MTU write in mapZoneInterface's per-phys setup had nothing
// to write: the commit was clean and changed nothing. A tagged unit still
// contributes nothing else to the parent. Its addresses, DHCP and unit MTU belong
// to its VLAN sub-interface.

const taggedParent9761 = "ge-0-0-2"

func taggedOnlyConfig9761() *config.Config {
	cfg := &config.Config{}
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"trust":   {Name: "trust", Interfaces: []string{taggedParent9761 + ".50"}},
		"untrust": {Name: "untrust", Interfaces: []string{taggedParent9761 + ".80"}},
	}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		taggedParent9761: {
			Name:        taggedParent9761,
			VlanTagging: true,
			MTU:         1400,
			Units: map[int]*config.InterfaceUnit{
				50: {Number: 50, VlanID: 50, Addresses: []string{"172.16.50.8/24"}, MTU: 1300},
				80: {Number: 80, VlanID: 80, Addresses: []string{"172.16.80.8/24"}},
			},
		},
	}
	return cfg
}

func TestTaggedOnlyInterfacePlansTheInterfaceMTUOnTheParent_9761(t *testing.T) {
	pd := planPhysDesired(taggedOnlyConfig9761())[taggedParent9761]
	if pd == nil {
		t.Fatalf("no plan for %s: the interface-level mtu of a vlan-tagging interface with only "+
			"tagged zone units never reaches the parent", taggedParent9761)
	}
	if pd.mtu != 1400 {
		t.Errorf("parent mtu = %d, want the interface-level 1400; a tagged unit's own mtu (1300) "+
			"belongs to its sub-interface", pd.mtu)
	}
	if len(pd.addrs) != 0 {
		t.Errorf("parent addresses = %v, want none: tagged units' addresses belong to their sub-interfaces", pd.addrs)
	}
}

// Without an interface-level mtu a tagged-only parent has nothing to plan, so it
// still gets no plan at all.
func TestTaggedOnlyInterfaceWithoutAnInterfaceMTUPlansNothing_9761(t *testing.T) {
	cfg := taggedOnlyConfig9761()
	cfg.Interfaces.Interfaces[taggedParent9761].MTU = 0
	if pd := planPhysDesired(cfg)[taggedParent9761]; pd != nil {
		t.Errorf("plan for %s = %+v, want none: there is nothing to write on the parent", taggedParent9761, *pd)
	}
}

// An untagged unit on the same interface keeps the pre-existing rule: its unit
// mtu overrides the interface level, whichever zone order names the references.
func TestAnUntaggedUnitStillOverridesTheInterfaceMTU_9761(t *testing.T) {
	cfg := taggedOnlyConfig9761()
	cfg.Interfaces.Interfaces[taggedParent9761].Units[0] = &config.InterfaceUnit{
		Number: 0, Addresses: []string{"10.0.9.1/24"}, MTU: 1500,
	}
	// The zones are walked in sorted order, so one name sorts before the tagged
	// references' zones and one after.
	for _, zone := range []string{"aaa-first", "zzz-last"} {
		cfg.Security.Zones[zone] = &config.ZoneConfig{Name: zone, Interfaces: []string{taggedParent9761 + ".0"}}
		pd := planPhysDesired(cfg)[taggedParent9761]
		delete(cfg.Security.Zones, zone)
		if pd == nil {
			t.Errorf("with the untagged reference in zone %s: no plan", zone)
			continue
		}
		if pd.mtu != 1500 {
			t.Errorf("with the untagged reference in zone %s: mtu = %d, want unit 0's 1500", zone, pd.mtu)
		}
		if len(pd.addrs) != 1 || pd.addrs[0] != "10.0.9.1/24" {
			t.Errorf("with the untagged reference in zone %s: addresses = %v, want only unit 0's", zone, pd.addrs)
		}
	}
}

// For a RETH the parent is the node's local member, so each node plans the RETH's
// interface-level mtu on its own member link and on no other netdev.
func TestTaggedOnlyRETHPlansTheMTUOnTheLocalMember_9761(t *testing.T) {
	for _, tc := range []struct {
		node   int
		member string
		mtu    int
	}{{0, "ge-0-0-2", 1400}, {1, "ge-7-0-2", 9000}} {
		cfg := &config.Config{}
		cfg.Chassis.Cluster = &config.ClusterConfig{NodeID: tc.node}
		cfg.Security.Zones = map[string]*config.ZoneConfig{
			"untrust": {Name: "untrust", Interfaces: []string{"reth0.50", "reth0.80"}},
		}
		cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
			"reth0": {
				Name: "reth0", RedundancyGroup: 1, VlanTagging: true, MTU: tc.mtu,
				Units: map[int]*config.InterfaceUnit{
					50: {Number: 50, VlanID: 50},
					80: {Number: 80, VlanID: 80},
				},
			},
			"ge-0/0/2": {Name: "ge-0/0/2", RedundantParent: "reth0"},
			"ge-7/0/2": {Name: "ge-7/0/2", RedundantParent: "reth0"},
		}
		plan := planPhysDesired(cfg)
		if pd := plan[tc.member]; pd == nil || pd.mtu != tc.mtu {
			t.Errorf("node %d: plan[%s] = %+v, want mtu %d on the local RETH member", tc.node, tc.member, pd, tc.mtu)
		}
		if len(plan) != 1 {
			t.Errorf("node %d: planned %d netdevs, want only the local member %s", tc.node, len(plan), tc.member)
		}
	}
}

// A tagged reference to a fabric interface resolves to its local fabric member,
// whose MTU the fabric setup owns. Master never planned it from a tagged
// reference, and neither does #9761: an interface-level mtu on fab0 must not
// reach the member link through fab0.N.
func TestATaggedFabricReferencePlansNoMTU_9761(t *testing.T) {
	cfg := &config.Config{}
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"fabric": {Name: "fabric", Interfaces: []string{"fab0.10"}},
	}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"fab0": {
			Name: "fab0", MTU: 1400, VlanTagging: true, LocalFabricMember: "ge-0/0/0",
			Units: map[int]*config.InterfaceUnit{10: {Number: 10, VlanID: 10}},
		},
	}
	if phys, _, _, vlan := resolveInterfaceRef("fab0.10", cfg); phys == "" || vlan != 10 {
		t.Fatalf("premise: fab0.10 resolves to phys %q vlan %d, want the fabric member at vlan 10", phys, vlan)
	}

	for name, pd := range planPhysDesired(cfg) {
		if pd.mtu != 0 {
			t.Errorf("a tagged fabric reference planned mtu %d on %s, want none: the fabric setup owns the member's MTU",
				pd.mtu, name)
		}
	}
}

// A tagged per-unit tunnel resolves to its tunnel device, not to the interface's
// own netdev, and keeps its VLAN id. Unit 5 carries VLAN 105, so a planner that
// looks the unit up by VLAN id instead of unit number fails here. The tunnel manager owns that device's MTU,
// so the interface-level mtu must not be planned onto it.
func TestATaggedTunnelUnitPlansNoMTU_9761(t *testing.T) {
	cfg := &config.Config{}
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"tunnels": {Name: "tunnels", Interfaces: []string{"ge-0/0/3.5"}},
	}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"ge-0/0/3": {
			Name: "ge-0/0/3", MTU: 1400, VlanTagging: true,
			Units: map[int]*config.InterfaceUnit{
				5: {Number: 5, VlanID: 105, MTU: 1300, Tunnel: &config.TunnelConfig{Name: "gr-0-0-5", Mode: "gre"}},
			},
		},
	}
	if phys, _, _, vlan := resolveInterfaceRef("ge-0/0/3.5", cfg); phys != "gr-0-0-5" || vlan != 105 {
		t.Fatalf("premise: ge-0/0/3.5 resolves to phys %q vlan %d, want the tunnel device gr-0-0-5 at vlan 105", phys, vlan)
	}

	for name, pd := range planPhysDesired(cfg) {
		if pd.mtu != 0 {
			t.Errorf("a tagged tunnel unit planned mtu %d on %s, want none: the tunnel manager owns the tunnel device's MTU",
				pd.mtu, name)
		}
	}
}

// An ordinary tagged unit whose number differs from its VLAN id must still plan
// the parent. Unit 6 carries VLAN 106, and unit 106 is a sibling tunnel unit, so a
// planner that looks the unit up by VLAN id finds the tunnel and skips the parent.
// So does one that skips a unit it cannot find.
func TestATaggedUnitWhoseNumberIsNotItsVLANPlansTheParent_9761(t *testing.T) {
	cfg := &config.Config{}
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"trust":   {Name: "trust", Interfaces: []string{"ge-0/0/4.6"}},
		"tunnels": {Name: "tunnels", Interfaces: []string{"ge-0/0/4.106"}},
	}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"ge-0/0/4": {
			Name: "ge-0/0/4", MTU: 1400, VlanTagging: true,
			Units: map[int]*config.InterfaceUnit{
				6:   {Number: 6, VlanID: 106},
				106: {Number: 106, VlanID: 206, Tunnel: &config.TunnelConfig{Name: "gr-0-0-106", Mode: "gre"}},
			},
		},
	}
	phys, _, unit, vlan := resolveInterfaceRef("ge-0/0/4.6", cfg)
	if phys == "" || phys == "gr-0-0-106" || unit != 6 || vlan != 106 {
		t.Fatalf("premise: ge-0/0/4.6 resolves to phys %q unit %d vlan %d, want the interface's own netdev, unit 6 at vlan 106",
			phys, unit, vlan)
	}

	plan := planPhysDesired(cfg)
	if pd := plan[phys]; pd == nil || pd.mtu != 1400 {
		t.Errorf("plan[%s] = %+v, want the interface-level mtu 1400 from unit 6 (VLAN 106)", phys, pd)
	}
	if pd := plan["gr-0-0-106"]; pd != nil && pd.mtu != 0 {
		t.Errorf("the sibling tunnel unit planned mtu %d on gr-0-0-106, want none", pd.mtu)
	}
}

// Only LocalFabricMember makes a reference a fabric one. An ordinary interface
// whose name starts with "fab" still plans its own interface-level mtu, so a
// planner that excluded fabric references by name fails here.
func TestATaggedInterfaceNamedLikeAFabricStillPlansItsMTU_9761(t *testing.T) {
	cfg := &config.Config{}
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"uplink": {Name: "uplink", Interfaces: []string{"fabric-uplink.20"}},
	}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"fabric-uplink": {
			Name: "fabric-uplink", MTU: 1400, VlanTagging: true,
			Units: map[int]*config.InterfaceUnit{20: {Number: 20, VlanID: 20}},
		},
	}
	if phys, _, _, vlan := resolveInterfaceRef("fabric-uplink.20", cfg); phys != "fabric-uplink" || vlan != 20 {
		t.Fatalf("premise: fabric-uplink.20 resolves to phys %q vlan %d, want fabric-uplink at vlan 20", phys, vlan)
	}
	if pd := planPhysDesired(cfg)["fabric-uplink"]; pd == nil || pd.mtu != 1400 {
		t.Errorf("plan[fabric-uplink] = %+v, want its interface-level mtu 1400: it has no LocalFabricMember", pd)
	}
}

// TestEveryTaggedReferenceShapePlansByTheTwoExceptionsOnly_9761 closes a class
// rather than one planner at a time. Review rounds 8 to 10 each found a broken
// planner that some cell let through: a unit lookup by VLAN id, a tunnel
// exclusion by device-name prefix or by GRE mode only, a skip of DHCP or unit-MTU
// units, and a special case for fab names.
//
// Here every shape is zoned ALONE, so no sibling reference can supply the plan a
// broken planner skipped. The shapes vary every axis of a tagged reference:
//   - the interface name, including tunnel and fabric lookalikes;
//   - fabric membership, on and off for the same name;
//   - the unit's addressing: static, its own MTU, DHCPv4 or DHCPv6;
//   - no tunnel, or a per-unit tunnel in each mode, on a device whose name looks
//     like no tunnel;
//   - a unit number equal to its VLAN id, one unlike it, and unit 0;
//   - the reference's spelling of the unit: canonical, with a leading zero,
//     with a plus sign, and for unit 0 no suffix at all, since
//     resolveInterfaceRef parses the suffix numerically;
//   - the interface-level mtu itself: a standard 1400 and a jumbo 9000.
//
// The expectation reads only the two real exceptions. A fabric reference and a
// per-unit tunnel plan no MTU anywhere. Every other tagged reference plans the
// interface-level mtu on the interface's own netdev and on nothing else.
func TestEveryTaggedReferenceShapePlansByTheTwoExceptionsOnly_9761(t *testing.T) {
	names := []string{"ge-0/0/4", "gr-eenwich", "ip-lookalike", "wg-lookalike", "fab0", "fab1", "fab9", "fabric-uplink"}
	units := []struct {
		label string
		unit  func(num, vlan int) *config.InterfaceUnit
	}{
		{"static", func(n, v int) *config.InterfaceUnit {
			return &config.InterfaceUnit{Number: n, VlanID: v, Addresses: []string{"192.0.2.1/24"}}
		}},
		{"unit-mtu", func(n, v int) *config.InterfaceUnit { return &config.InterfaceUnit{Number: n, VlanID: v, MTU: 1300} }},
		{"dhcpv4", func(n, v int) *config.InterfaceUnit { return &config.InterfaceUnit{Number: n, VlanID: v, DHCP: true} }},
		{"dhcpv6", func(n, v int) *config.InterfaceUnit { return &config.InterfaceUnit{Number: n, VlanID: v, DHCPv6: true} }},
	}
	type numbering struct {
		unit, vlan, mtu int
		suffix          string
	}
	var numberings []numbering
	for _, mtu := range []int{1400, 9000} {
		for _, uv := range [][2]int{{20, 20}, {6, 106}, {0, 30}} {
			suffixes := []string{fmt.Sprintf(".%d", uv[0]), fmt.Sprintf(".0%d", uv[0]), fmt.Sprintf(".+%d", uv[0])}
			if uv[0] == 0 {
				suffixes = append(suffixes, "")
			}
			for _, suffix := range suffixes {
				numberings = append(numberings, numbering{unit: uv[0], vlan: uv[1], mtu: mtu, suffix: suffix})
			}
		}
	}
	cases, failed := 0, 0
	for _, name := range names {
		for _, fabric := range []bool{false, true} {
			for _, u := range units {
				for _, mode := range []string{"", "gre", "ipip", "wireguard"} {
					for _, nv := range numberings {
						cases++
						label := fmt.Sprintf("%s%s (unit %d, vlan %d, mtu %d, fabric=%v, %s, tunnel %q)", name, nv.suffix, nv.unit, nv.vlan, nv.mtu, fabric, u.label, mode)
						unit := u.unit(nv.unit, nv.vlan)
						if mode != "" {
							unit.Tunnel = &config.TunnelConfig{Name: fmt.Sprintf("tun%d-9761", nv.unit), Mode: mode}
						}
						ifCfg := &config.InterfaceConfig{
							Name: name, MTU: nv.mtu, VlanTagging: true,
							Units: map[int]*config.InterfaceUnit{nv.unit: unit},
						}
						if fabric {
							ifCfg.LocalFabricMember = "ge-0/0/9"
						}
						cfg := &config.Config{}
						cfg.Security.Zones = map[string]*config.ZoneConfig{
							"z": {Name: "z", Interfaces: []string{name + nv.suffix}},
						}
						cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{name: ifCfg}

						plan := planPhysDesired(cfg)
						own := config.LinuxIfName(name)
						exception := fabric || mode != ""
						ok := true
						for dev, pd := range plan {
							if pd.mtu != 0 && (exception || dev != own) {
								t.Errorf("%s: planned mtu %d on %s", label, pd.mtu, dev)
								ok = false
							}
						}
						if !exception {
							if pd := plan[own]; pd == nil || pd.mtu != nv.mtu {
								t.Errorf("%s: plan[%s] = %+v, want the interface-level mtu %d", label, own, pd, nv.mtu)
								ok = false
							}
						}
						if !ok {
							failed++
						}
					}
				}
			}
		}
	}
	if cases != 5120 {
		t.Errorf("premise: enumerated %d shapes, want 5120", cases)
	}
	if failed > 0 {
		t.Errorf("%d of %d tagged reference shapes planned wrongly", failed, cases)
	}
}

// A tagged DHCP unit's DHCP belongs to its VLAN sub-interface. It must not mark
// the parent's addresses as DHCP-owned, or a mixed parent's static untagged
// address would stop being reconciled. The untagged reference's zone sorts before,
// and then after, the tagged ones.
func TestATaggedDHCPUnitLeavesTheParentsStaticAddresses_9761(t *testing.T) {
	cfg := taggedOnlyConfig9761()
	parent := cfg.Interfaces.Interfaces[taggedParent9761]
	parent.Units[50].DHCP = true
	parent.Units[50].Addresses = nil
	parent.Units[0] = &config.InterfaceUnit{Number: 0, Addresses: []string{"10.0.9.1/24"}}
	for _, zone := range []string{"aaa-first", "zzz-last"} {
		cfg.Security.Zones[zone] = &config.ZoneConfig{Name: zone, Interfaces: []string{taggedParent9761 + ".0"}}
		pd := planPhysDesired(cfg)[taggedParent9761]
		delete(cfg.Security.Zones, zone)
		if pd == nil {
			t.Errorf("with the untagged reference in zone %s: no plan", zone)
			continue
		}
		if pd.skipAddrs {
			t.Errorf("with the untagged reference in zone %s: the tagged DHCP unit marked the parent's addresses DHCP-owned", zone)
		}
		if len(pd.addrs) != 1 || pd.addrs[0] != "10.0.9.1/24" {
			t.Errorf("with the untagged reference in zone %s: addresses = %v, want unit 0's static 10.0.9.1/24", zone, pd.addrs)
		}
	}
}

// applyTaggedParent9761 runs one zone apply of cfg through compileZones against
// the #8119 fake host, with the parent and both VLAN children at the given MTUs.
// All three links are cached, so the parent's MTU write and the children's run.
// It returns the host and the MTU writes tried, per link.
func applyTaggedParent9761(t *testing.T, cfg *config.Config, parentMTU, sub50MTU, sub80MTU int) (*fakeHost8119, map[string]int) {
	t.Helper()
	sub50, sub80 := taggedParent9761+".50", taggedParent9761+".80"
	h := &fakeHost8119{
		mtu:   map[string]int{taggedParent9761: parentMTU, sub50: sub50MTU, sub80: sub80MTU},
		addrs: map[string]map[string]bool{taggedParent9761: {"192.0.2.9/24": true}, sub50: {}, sub80: {}},
		index: map[string]int{taggedParent9761: 4212, sub50: 4213, sub80: 4214},
	}
	h.install(t)
	writes := map[string]int{}
	write := linkSetMTUSeam
	t.Cleanup(func() { linkSetMTUSeam = write })
	linkSetMTUSeam = func(l netlink.Link, mtu int) error {
		writes[l.Attrs().Name]++
		return write(l, mtu)
	}
	mockEthtool(t, func(...string) ([]byte, error) { return []byte("rx-vlan-offload: off\n"), nil })
	origVLAN := ensureVLANSubInterfaceFn
	t.Cleanup(func() { ensureVLANSubInterfaceFn = origVLAN })
	ensureVLANSubInterfaceFn = func(parent string, vlanID int) (int, bool, error) {
		return h.index[fmt.Sprintf("%s.%d", parent, vlanID)], false, nil
	}

	result := newValidationResult()
	assignZoneIDs(result, cfg)
	assignScreenIDs(result, cfg)
	result.ifCache[taggedParent9761] = &net.Interface{Index: h.index[taggedParent9761], Name: taggedParent9761}
	for _, name := range []string{taggedParent9761, sub50, sub80} {
		link := h.link(name)
		result.linkCache[name] = link
		result.linkIdxMap[h.index[name]] = link
	}
	if err := compileZones(convergenceTestDP{}, cfg, result); err != nil {
		t.Fatalf("compileZones: %v", err)
	}
	return h, writes
}

// The value must reach the link through the real apply, not only the plan: a
// tagged reference passes through mapZoneInterface's per-phys setup, which is
// where the parent's MTU write lives. The parent's own addresses are left alone,
// because a tagged-only parent is not address-reconciled. Unit 50's own MTU still
// reaches its VLAN sub-interface.
func TestTaggedOnlyInterfaceMTUIsWrittenToTheParentLink_9761(t *testing.T) {
	h, writes := applyTaggedParent9761(t, taggedOnlyConfig9761(), 1500, 1500, 1500)

	if got := h.mtu[taggedParent9761]; got != 1400 {
		t.Errorf("parent link mtu = %d after the apply, want the interface-level 1400", got)
	}
	if got := writes[taggedParent9761]; got != 1 {
		t.Errorf("parent link mtu written %d times in one apply by two tagged references, want once (#8119/#8120)", got)
	}
	if got := h.addrs[taggedParent9761]; len(got) != 1 || !got["192.0.2.9/24"] {
		t.Errorf("parent addresses = %v after the apply, want them untouched", got)
	}
	if got := h.mtu[taggedParent9761+".50"]; got != 1300 {
		t.Errorf("unit 50 mtu = %d after the apply, want its unit-level 1300", got)
	}
}

// An apply that finds every MTU already at its configured value writes none.
func TestAConvergedTaggedParentWritesNoMTU_9761(t *testing.T) {
	_, writes := applyTaggedParent9761(t, taggedOnlyConfig9761(), 1400, 1300, 1400)

	if len(writes) != 0 {
		t.Errorf("a converged apply tried MTU writes %v, want none", writes)
	}
}

// A RETH's tagged units live on the node's local member. With no interface-level
// mtu the member gets no MTU write, and a unit's MTU still reaches the member's
// VLAN sub-interface.
func TestARETHMemberWithoutAParentMTUGetsItsUnitMTU_9761(t *testing.T) {
	cfg := &config.Config{}
	cfg.Chassis.Cluster = &config.ClusterConfig{NodeID: 0}
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"untrust": {Name: "untrust", Interfaces: []string{"reth0.50", "reth0.80"}},
	}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"reth0": {
			Name: "reth0", RedundancyGroup: 1, VlanTagging: true,
			Units: map[int]*config.InterfaceUnit{
				50: {Number: 50, VlanID: 50, MTU: 1300},
				80: {Number: 80, VlanID: 80},
			},
		},
		"ge-0/0/2": {Name: "ge-0/0/2", RedundantParent: "reth0"},
		"ge-7/0/2": {Name: "ge-7/0/2", RedundantParent: "reth0"},
	}
	h, writes := applyTaggedParent9761(t, cfg, 1500, 1500, 1500)

	if got := writes[taggedParent9761]; got != 0 {
		t.Errorf("the member link's MTU was written %d times with no interface-level mtu, want none", got)
	}
	if got := h.mtu[taggedParent9761+".50"]; got != 1300 {
		t.Errorf("the local member's unit 50 mtu = %d, want 1300", got)
	}
}

// TestTaggedParentsPlanWhateverTheZoneAndReferenceOrder_9761: several tagged-only
// parents spread across zones must each be planned, whatever order the zones sort
// in and whatever order a zone lists its references. The expected plan is written
// from the config, not computed with resolveInterfaceRef, so a resolver regression
// cannot hide behind the expectation. The fixture holds:
//   - an ordinary tagged unit and a per-unit tunnel on one interface, in both orders;
//   - a second distinct parent in the other zone;
//   - a RETH and a fabric interface whose members are spelled with dashes;
//   - an unmapped irb interface;
//   - tunnel devices named like real ones, one of them sharing its interface's own
//     device name, as a WireGuard unit can (#6941).
func TestTaggedParentsPlanWhateverTheZoneAndReferenceOrder_9761(t *testing.T) {
	interfaces := map[string]*config.InterfaceConfig{
		"ge-0/0/4": {Name: "ge-0/0/4", MTU: 1400, VlanTagging: true, Units: map[int]*config.InterfaceUnit{
			20:  {Number: 20, VlanID: 20},
			106: {Number: 106, VlanID: 206, Tunnel: &config.TunnelConfig{Name: "ip-0-0-4u106", Mode: "ipip"}},
		}},
		"ge-0/0/5": {Name: "ge-0/0/5", MTU: 9000, VlanTagging: true, Units: map[int]*config.InterfaceUnit{
			30: {Number: 30, VlanID: 30},
		}},
		"wg0": {Name: "wg0", MTU: 1420, VlanTagging: true, Units: map[int]*config.InterfaceUnit{
			7: {Number: 7, VlanID: 70, Tunnel: &config.TunnelConfig{Name: "wg0", Mode: "wireguard"}},
		}},
		"reth1": {Name: "reth1", RedundancyGroup: 1, MTU: 1500, VlanTagging: true, Units: map[int]*config.InterfaceUnit{
			40: {Number: 40, VlanID: 40},
		}},
		"ge-0-0-2": {Name: "ge-0-0-2", RedundantParent: "reth1"},
		"ge-7-0-2": {Name: "ge-7-0-2", RedundantParent: "reth1"},
		"fab0": {Name: "fab0", MTU: 1400, VlanTagging: true, LocalFabricMember: "ge-0-0-9", Units: map[int]*config.InterfaceUnit{
			10: {Number: 10, VlanID: 10},
		}},
		"irb": {Name: "irb", MTU: 1400, VlanTagging: true, Units: map[int]*config.InterfaceUnit{
			50: {Number: 50, VlanID: 50},
		}},
	}
	// The MTU each netdev must be planned with. Every other netdev plans none: the
	// tunnel devices ip-0-0-4u106 and wg0, and the fabric member ge-0-0-9.
	want := map[string]int{"ge-0-0-4": 1400, "ge-0-0-5": 9000, "ge-0-0-2": 1500, "irb": 1400}

	one := []string{"ge-0/0/4.20", "ge-0/0/4.106", "fab0.10", "irb.50"}
	other := []string{"ge-0/0/5.30", "wg0.7", "reth1.40"}
	reverse := func(s []string) []string {
		r := make([]string, len(s))
		for i, v := range s {
			r[len(s)-1-i] = v
		}
		return r
	}
	for _, names := range [][2]string{{"aaa", "zzz"}, {"zzz", "aaa"}} {
		for _, reversed := range []bool{false, true} {
			a, b := one, other
			if reversed {
				a, b = reverse(one), reverse(other)
			}
			cfg := &config.Config{}
			cfg.Chassis.Cluster = &config.ClusterConfig{NodeID: 0}
			cfg.Security.Zones = map[string]*config.ZoneConfig{
				names[0]: {Name: names[0], Interfaces: a},
				names[1]: {Name: names[1], Interfaces: b},
			}
			cfg.Interfaces.Interfaces = interfaces
			label := fmt.Sprintf("zone %s holds %v and zone %s holds %v", names[0], a, names[1], b)

			plan := planPhysDesired(cfg)
			for dev, mtu := range want {
				if pd := plan[dev]; pd == nil || pd.mtu != mtu {
					t.Errorf("%s: plan[%s] = %+v, want mtu %d", label, dev, pd, mtu)
				}
			}
			for dev, pd := range plan {
				if _, planned := want[dev]; !planned && pd.mtu != 0 {
					t.Errorf("%s: planned mtu %d on %s, want none", label, pd.mtu, dev)
				}
			}
		}
	}
}
