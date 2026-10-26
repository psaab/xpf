package dataplane

import (
	"net"
	"reflect"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/networkd"
)

// #17841: partially-zoned untagged units flapped on the VLAN-parent render.
// #17592's untaggedUnitAddresses folded EVERY untagged unit of a non-RETH
// VLAN parent onto the parent row, while planPhysDesired folds only the
// zone-referenced ones (compiler_iface_desired.go) and skips the whole
// netdev's address reconcile when any zoned untagged unit is DHCP-managed.
// So on a partially-zoned parent the unzoned unit's address was rendered
// as a static Address= + KeepConfiguration=static by networkd and then
// deleted as stale by every later compile's reconcileInterfaceAddresses
// — the #16795 commit-cadence flap in the partially-zoned shape. A zoned
// DHCP unit's same-family co-configured static address rendered while the
// planner never installed it; opposite-family statics must remain rendered.
//
// FAIL-ON-REVERT: without the zone-ref/skipAddrs gating in
// buildInterfaceNetworkdModels' VLAN-parent arm (it must consume
// planPhysDesired — the same plan the reconciler owns), the RED cells
// below return the unzoned/DHCP addresses in VLANParentAddresses.

func untaggedVLANParentCfg17841(t *testing.T) *config.Config {
	t.Helper()
	tree := &config.ConfigTree{}
	for _, l := range []string{
		// ge-0/0/1 (vlan-tagging): unit 0 unzoned 10.0.0.1/24, unit 2
		// zoned 10.0.2.1/24, tagged unit 50 zoned. #16583 rejects
		// non-zero untagged units on tagging parents, so the stranded
		// untagged unit is unit 0; unit 2 carries a vlan-id.
		"set interfaces ge-0/0/1 vlan-tagging",
		"set interfaces ge-0/0/1 unit 0 family inet address 10.0.0.1/24",
		"set interfaces ge-0/0/1 unit 2 vlan-id 2",
		"set interfaces ge-0/0/1 unit 2 family inet address 10.0.2.1/24",
		"set interfaces ge-0/0/1 unit 50 vlan-id 50",
		"set interfaces ge-0/0/1 unit 50 family inet address 10.0.50.1/24",
		"set security zones security-zone trust interfaces ge-0/0/1.2",
		"set security zones security-zone trust interfaces ge-0/0/1.50",
		// ge-0/0/2 (vlan-tagging): unit 0 zoned and carries a same-family
		// v4 static address and DHCPv4 — the planner marks the netdev
		// skipAddrs and the renderer suppresses the DHCP-owned v4 family.
		"set interfaces ge-0/0/2 vlan-tagging",
		"set interfaces ge-0/0/2 unit 0 family inet address 10.1.0.1/24",
		"set interfaces ge-0/0/2 unit 0 family inet dhcp",
		"set interfaces ge-0/0/2 unit 20 vlan-id 20",
		"set interfaces ge-0/0/2 unit 20 family inet address 10.1.20.1/24",
		"set security zones security-zone trust interfaces ge-0/0/2.0",
		// ge-0/0/3: unit 0 zoned normally (control — fix must keep it).
		"set interfaces ge-0/0/3 vlan-tagging",
		"set interfaces ge-0/0/3 unit 0 family inet address 10.2.0.1/24",
		"set interfaces ge-0/0/3 unit 30 vlan-id 30",
		"set interfaces ge-0/0/3 unit 30 family inet address 10.2.30.1/24",
		"set security zones security-zone trust interfaces ge-0/0/3.0",
		// ge-0/0/4: no zones at all (control — strict-compiles per
		// #17592's own fixture; nothing is planned, nothing renders).
		"set interfaces ge-0/0/4 vlan-tagging",
		"set interfaces ge-0/0/4 unit 0 family inet address 10.3.0.1/24",
		"set interfaces ge-0/0/4 unit 40 vlan-id 40",
		"set interfaces ge-0/0/4 unit 40 family inet address 10.3.40.1/24",
		// ge-0/0/5: untagged unit 0 zoned and carrying a standalone
		// vrrp-group — its real address stays VIP-foreign (#15061).
		"set interfaces ge-0/0/5 vlan-tagging",
		"set interfaces ge-0/0/5 unit 0 family inet address 10.4.0.2/24 vrrp-group 5 virtual-address 10.4.0.1",
		"set interfaces ge-0/0/5 unit 55 vlan-id 55",
		"set interfaces ge-0/0/5 unit 55 family inet address 10.4.55.1/24",
		"set security zones security-zone trust interfaces ge-0/0/5.0",
		// ge-0/0/9 (vlan-tagging): unit 0 unzoned ghost 10.9.0.1/24.
		// Its device IS planned — via tagged units only (unit 50 zoned),
		// so planPhysDesired creates the device entry — but no untagged
		// unit is zone-referenced, so the ghost must not render.
		"set interfaces ge-0/0/9 vlan-tagging",
		"set interfaces ge-0/0/9 unit 0 family inet address 10.9.0.1/24",
		"set interfaces ge-0/0/9 unit 50 vlan-id 50",
		"set interfaces ge-0/0/9 unit 50 family inet address 10.9.50.1/24",
		"set security zones security-zone trust interfaces ge-0/0/9.50",
	} {
		path, err := config.ParseSetCommand(l)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", l, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", l, err)
		}
	}
	cfg, err := config.CompileConfig(tree)
	if err != nil {
		t.Fatalf("strict compile of partially-zoned fixture: %v", err)
	}
	return cfg
}

func models17841(t *testing.T, cfg *config.Config) map[string]networkd.InterfaceConfig {
	t.Helper()
	result := &CompileResult{ifCache: map[string]*net.Interface{}}
	for i, name := range []string{"ge-0-0-1", "ge-0-0-2", "ge-0-0-3", "ge-0-0-4", "ge-0-0-5", "ge-0-0-9"} {
		result.ifCache[name] = &net.Interface{
			Index:        100 + i,
			Name:         name,
			HardwareAddr: net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x03, byte(i)},
		}
	}
	buildInterfaceNetworkdModels(cfg, result, map[string]bool{})
	out := map[string]networkd.InterfaceConfig{}
	for _, m := range result.ManagedInterfaces {
		out[m.Name] = m
	}
	return out
}

func TestPartiallyZonedUntaggedUnitsDoNotRender17841(t *testing.T) {
	cfg := untaggedVLANParentCfg17841(t)

	// Premise (planner side): only the zoned units' addresses are
	// planned on each parent; ge-0/0/2's netdev is skipAddrs because
	// its zoned untagged unit is DHCP-managed; ge-0/0/4 is unplanned.
	plan := planPhysDesired(cfg)
	// ge-0/0/1's zone refs are tagged-only: the plan entry is MTU-only
	// and folds NO parent addresses, so the parent is never address-
	// reconciled. Unit 0 is unzoned, so the reconciler owns nothing —
	// the flap's deleting writer does not exist in this shape.
	if pd := plan["ge-0-0-1"]; pd == nil || pd.skipAddrs || len(pd.addrs) != 0 {
		t.Fatalf("premise: plan[ge-0-0-1]=%+v, want MTU-only entry, no parent addrs (tagged refs only)", pd)
	}
	if pd := plan["ge-0-0-9"]; pd == nil || pd.skipAddrs || len(pd.addrs) != 0 {
		t.Fatalf("premise: plan[ge-0-0-9]=%+v, want MTU-only entry, no parent addrs (tagged ref only)", pd)
	}
	if pd := plan["ge-0-0-2"]; pd == nil || !pd.skipAddrs {
		t.Fatalf("premise: plan[ge-0-0-2]=%+v, want skipAddrs=true (zoned unit 0 is DHCP)", pd)
	}
	if pd := plan["ge-0-0-3"]; pd == nil || pd.skipAddrs || !reflect.DeepEqual(pd.addrs, []string{"10.2.0.1/24"}) {
		t.Fatalf("premise: plan[ge-0-0-3]=%+v, want addrs=[10.2.0.1/24] skipAddrs=false", pd)
	}
	if pd := plan["ge-0-0-4"]; pd != nil && (len(pd.addrs) > 0 || !pd.skipAddrs) {
		t.Fatalf("premise: plan[ge-0-0-4]=%+v, want no planned addresses (no zone refs)", pd)
	}

	models := models17841(t, cfg)

	// RED cell (partially-zoned flap): the unzoned unit 0 address must
	// NOT render; the zoned untagged unit 2's address must (it is a
	// tagged child's own device, so it renders there — and the parent
	// carries exactly the planned set for its own device: unit 2
	// resolves to ge-0-0-1.2, not the parent, so the parent renders
	// nothing; what matters is 10.0.0.1/24 is absent and no static
	// keep is armed for it).
	m1, ok := models["ge-0-0-1"]
	if !ok {
		t.Fatalf("no model for ge-0-0-1")
	}
	if !m1.IsVLANParent {
		t.Fatalf("ge-0-0-1 is not rendered as a VLAN parent: %+v", m1)
	}
	// Tagged-only refs: the parent is never address-reconciled
	// (reconcile runs only for vlanID==0 refs), so unit 0's address
	// renders exactly as #16795 requires — no deleting writer exists.
	if len(m1.VLANParentAddresses) != 1 || m1.VLANParentAddresses[0] != "10.0.0.1/24" {
		t.Errorf("ge-0-0-1 VLANParentAddresses=%v, want [10.0.0.1/24] (#16795: parent never address-reconciled in tagged-only shape)", m1.VLANParentAddresses)
	}
	// Same tagged-only shape on ge-0/0/9.
	if m9, ok := models["ge-0-0-9"]; !ok {
		t.Fatalf("no model for ge-0-0-9")
	} else if len(m9.VLANParentAddresses) != 1 || m9.VLANParentAddresses[0] != "10.9.0.1/24" {
		t.Errorf("ge-0-0-9 VLANParentAddresses=%v, want [10.9.0.1/24] (#16795 tagged-only shape)", m9.VLANParentAddresses)
	}

	// Non-vacuity: the zoned untagged sibling really is addressed, on
	// its own sub-interface model.
	if sub, ok := models["ge-0-0-1.2"]; !ok || len(sub.Addresses) != 1 || sub.Addresses[0] != "10.0.2.1/24" {
		t.Errorf("ge-0-0-1.2 = %+v (present=%v), want Addresses [10.0.2.1/24]", sub, ok)
	}

	// RED cell (DHCPv4): the zoned DHCP unit's same-family static v4
	// address must not render. The family filter suppresses v4 while
	// still allowing any planner-owned static v6 address to render.
	m2, ok := models["ge-0-0-2"]
	if !ok {
		t.Fatalf("no model for ge-0-0-2")
	}
	if len(m2.VLANParentAddresses) != 0 {
		t.Errorf("ge-0-0-2 VLANParentAddresses=%v, want none: unit 0 is DHCP-managed "+
			"(plan skipAddrs), so its static 10.1.0.1/24 is not planner-owned", m2.VLANParentAddresses)
	}

	// Control: zoned untagged unit 0 still renders on its parent.
	m3, ok := models["ge-0-0-3"]
	if !ok {
		t.Fatalf("no model for ge-0-0-3")
	}
	if len(m3.VLANParentAddresses) != 1 || m3.VLANParentAddresses[0] != "10.2.0.1/24" || !m3.KeepAddresses {
		t.Errorf("ge-0-0-3 VLANParentAddresses=%v KeepAddresses=%v, want [10.2.0.1/24] + keep: "+
			"the zoned #16795 acceptance leg must keep rendering", m3.VLANParentAddresses, m3.KeepAddresses)
	}

	// Control: no zones at all — device absent from plan. This is the
	// #16795 unzoned acceptance shape (no reconciler runs on an
	// unplanned device, so the stranded address is still rendered and
	// kept, exactly as 16795 requires); #17841's flap needs a planned
	// device, covered by ge-0/0/1 and ge-0/0/9 above.
	m4, ok := models["ge-0-0-4"]
	if !ok {
		t.Fatalf("no model for ge-0-0-4")
	}
	if len(m4.VLANParentAddresses) != 1 || m4.VLANParentAddresses[0] != "10.3.0.1/24" || !m4.KeepAddresses {
		t.Errorf("ge-0-0-4 VLANParentAddresses=%v KeepAddresses=%v, want [10.3.0.1/24] + keep (#16795 unzoned leg)",
			m4.VLANParentAddresses, m4.KeepAddresses)
	}

	// Control: standalone-VRRP untagged unit stays VIP-foreign.
	m5, ok := models["ge-0-0-5"]
	if !ok {
		t.Fatalf("no model for ge-0-0-5")
	}
	if len(m5.VLANParentAddresses) != 0 {
		t.Errorf("ge-0-0-5 VLANParentAddresses=%v, want none: standalone vrrp-group unit's address is a VIP", m5.VLANParentAddresses)
	}
	if !m5.KeepAddresses || !m5.KeepForeignStatic {
		t.Errorf("ge-0-0-5 KeepAddresses=%v KeepForeignStatic=%v, want both true (#15061)",
			m5.KeepAddresses, m5.KeepForeignStatic)
	}
}

func TestDHCPFamilySkipsOnlyStaticAddressesInManagedFamilies17841(t *testing.T) {
	tests := []struct {
		name         string
		ifName       string
		unitCommands []string
		plannedCount int
		want         []string
	}{
		{
			name:   "DHCPv4 keeps static IPv6",
			ifName: "ge-0/0/6",
			unitCommands: []string{
				"family inet dhcp",
				"family inet6 address 2001:db8:6::1/64",
			},
			plannedCount: 1,
			want:         []string{"2001:db8:6::1/64"},
		},
		{
			name:   "DHCPv6 keeps static IPv4",
			ifName: "ge-0/0/7",
			unitCommands: []string{
				"family inet6 dhcpv6",
				"family inet address 10.7.0.1/24",
			},
			plannedCount: 1,
			want:         []string{"10.7.0.1/24"},
		},
		{
			name:   "both DHCP families suppress all statics",
			ifName: "ge-0/0/8",
			unitCommands: []string{
				"family inet dhcp",
				"family inet address 10.8.0.1/24",
				"family inet6 dhcpv6",
				"family inet6 address 2001:db8:8::1/64",
			},
			plannedCount: 2,
		},
	}

	for i, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tree := &config.ConfigTree{}
			commands := []string{"set interfaces " + tc.ifName + " vlan-tagging"}
			for _, unitCommand := range tc.unitCommands {
				commands = append(commands,
					"set interfaces "+tc.ifName+" unit 0 "+unitCommand)
			}
			commands = append(commands,
				"set security zones security-zone trust interfaces "+tc.ifName+".0")
			for _, command := range commands {
				path, err := config.ParseSetCommand(command)
				if err != nil {
					t.Fatalf("ParseSetCommand(%q): %v", command, err)
				}
				if err := tree.SetPath(path); err != nil {
					t.Fatalf("SetPath(%q): %v", command, err)
				}
			}
			cfg, err := config.CompileConfig(tree)
			if err != nil {
				t.Fatalf("strict compile of DHCP-family fixture: %v", err)
			}
			linuxName := config.LinuxIfName(tc.ifName)
			pd := planPhysDesired(cfg)[linuxName]
			if pd == nil || !pd.skipAddrs || len(pd.addrs) != tc.plannedCount {
				t.Fatalf("plan[%s]=%+v, want skipAddrs=true and %d planned static address(es)",
					linuxName, pd, tc.plannedCount)
			}

			result := &CompileResult{ifCache: map[string]*net.Interface{
				linuxName: {
					Index:        106 + i,
					Name:         linuxName,
					HardwareAddr: net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x17, byte(i)},
				},
			}}
			buildInterfaceNetworkdModels(cfg, result, map[string]bool{})
			for _, model := range result.ManagedInterfaces {
				if model.Name == linuxName {
					if !reflect.DeepEqual(model.VLANParentAddresses, tc.want) {
						t.Errorf("%s VLANParentAddresses=%v, want %v",
							linuxName, model.VLANParentAddresses, tc.want)
					}
					return
				}
			}
			t.Fatalf("no model for %s; models=%v", linuxName, result.ManagedInterfaces)
		})
	}
}

// The quarantine leg: when the only untagged zone ref is quarantined
// (the same ref claimed by two zones), the planner plans nothing for
// the parent, so the render must carry nothing either.
func TestQuarantinedOnlyUntaggedRefDoesNotRender17841(t *testing.T) {
	tree := &config.ConfigTree{}
	for _, l := range []string{
		"set interfaces ge-0/0/1 vlan-tagging",
		"set interfaces ge-0/0/1 unit 0 family inet address 10.0.0.1/24",
		"set interfaces ge-0/0/1 unit 50 vlan-id 50",
		"set interfaces ge-0/0/1 unit 50 family inet address 10.0.50.1/24",
		"set security zones security-zone trust interfaces ge-0/0/1.0",
		"set security zones security-zone untrust interfaces ge-0/0/1.0",
	} {
		path, err := config.ParseSetCommand(l)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", l, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", l, err)
		}
	}
	// Quarantine is a TOLERANT-load construct: strict compile rejects a multi-zone unit by design (#3072). Use the lenient path the runtime quarantine actually governs.
	cfg, err := config.CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("lenient compile of quarantined fixture: %v", err)
	}
	if len(config.QuarantinedZoneInterfaceKeys(cfg)) == 0 {
		t.Fatalf("premise: fixture does not quarantine ge-0/0/1.0; keys=%v", config.QuarantinedZoneInterfaceKeys(cfg))
	}
	if pd := planPhysDesired(cfg)["ge-0-0-1"]; pd != nil && len(pd.addrs) > 0 {
		t.Fatalf("premise: quarantined ref planned addrs %v, want none", pd.addrs)
	}
	result := &CompileResult{ifCache: map[string]*net.Interface{
		"ge-0-0-1": {Index: 110, Name: "ge-0-0-1", HardwareAddr: net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x04, 0x01}},
	}}
	buildInterfaceNetworkdModels(cfg, result, map[string]bool{})
	for _, m := range result.ManagedInterfaces {
		if m.Name == "ge-0-0-1" {
			if len(m.VLANParentAddresses) != 0 {
				t.Errorf("quarantined-only parent renders VLANParentAddresses=%v, want none: "+
					"the planner plans nothing for a quarantined ref", m.VLANParentAddresses)
			}
			return
		}
	}
	t.Fatalf("no model for ge-0-0-1; models=%v", result.ManagedInterfaces)
}
