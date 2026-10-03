package userspace

import (
	"fmt"
	"net"
	"sort"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

func TestFindUserspaceEgressInterfaceSnapshotPrefersVLANUnit(t *testing.T) {
	snapshot := &ConfigSnapshot{
		Interfaces: []InterfaceSnapshot{
			{
				Name:            "ge-0/0/2",
				Ifindex:         6,
				ParentIfindex:   0,
				RedundancyGroup: 1,
			},
			{
				Name:            "reth0.80",
				Ifindex:         12,
				ParentIfindex:   6,
				VLANID:          80,
				RedundancyGroup: 1,
			},
		},
	}
	iface, ok := findUserspaceEgressInterfaceSnapshot(snapshot, 6, 80)
	if !ok {
		t.Fatal("expected VLAN unit match")
	}
	if iface.Ifindex != 12 || iface.ParentIfindex != 6 || iface.RedundancyGroup != 1 {
		t.Fatalf("unexpected interface snapshot: %+v", iface)
	}
}

func TestUserspaceBootstrapProbeInterfacesIncludesBaseAndVLANUnits(t *testing.T) {
	cfg := &config.Config{}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"ge-7/0/1": {
			Name: "ge-7/0/1",
		},
		"ge-7/0/2": {
			Name: "ge-7/0/2",
			Units: map[int]*config.InterfaceUnit{
				0:  {Number: 0},
				50: {Number: 50, VlanID: 50},
				80: {Number: 80, VlanID: 80},
			},
		},
	}
	got := userspaceBootstrapProbeInterfaces(cfg)
	want := []string{"ge-7-0-1", "ge-7-0-2", "ge-7-0-2.50", "ge-7-0-2.80"}
	if len(got) != len(want) {
		t.Fatalf("len(userspaceBootstrapProbeInterfaces) = %d, want %d (%v)", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("userspaceBootstrapProbeInterfaces[%d] = %q, want %q (%v)", i, got[i], want[i], got)
		}
	}
}

func TestBuildLocalAddressEntries(t *testing.T) {
	snapshot := &ConfigSnapshot{
		Interfaces: []InterfaceSnapshot{
			{
				Name: "reth0.50",
				Zone: "wan",
				Addresses: []InterfaceAddressSnapshot{
					{Family: "inet", Address: "172.16.50.8/24"},
					{Family: "inet6", Address: "2001:559:8585:50::8/64"},
				},
			},
			{
				Name: "reth1.0",
				Zone: "lan",
				Addresses: []InterfaceAddressSnapshot{
					{Family: "inet", Address: "10.0.61.1/24"},
					{Family: "inet6", Address: "fe80::1/128"},
					{Family: "inet6", Address: "2001:559:8585:ef00::1/64"},
				},
			},
		},
	}
	got := buildLocalAddressEntries(snapshot)
	if len(got) != 5 {
		t.Fatalf("len(got) = %d, want 5 (%+v)", len(got), got)
	}
}

func TestPickInterfaceSnapshotFamilyFilters(t *testing.T) {
	iface := InterfaceSnapshot{
		Addresses: []InterfaceAddressSnapshot{
			{Family: "inet6", Address: "192.0.2.10/24"},
			{Family: "inet", Address: "192.0.2.20/24"},
			{Family: "inet", Address: "fe80::20/64"},
			{Family: "inet", Address: "2001:db8::20/64"},
			{Family: "inet6", Address: "fe80::10/64"},
			{Family: "inet6", Address: "2001:db8::10/64"},
		},
	}

	gotV4 := pickInterfaceSnapshotV4(iface)
	if gotV4 == nil || !gotV4.Equal(net.ParseIP("192.0.2.20")) {
		t.Fatalf("pickInterfaceSnapshotV4() = %v, want 192.0.2.20", gotV4)
	}

	gotV6 := pickInterfaceSnapshotV6(iface)
	if gotV6 == nil || !gotV6.Equal(net.ParseIP("2001:db8::10")) {
		t.Fatalf("pickInterfaceSnapshotV6() = %v, want 2001:db8::10", gotV6)
	}
}

func TestBuildLocalAddressEntriesIncludesInterfaceSNATAddressesForFallback(t *testing.T) {
	snapshot := &ConfigSnapshot{
		Interfaces: []InterfaceSnapshot{
			{
				Name: "reth0.80",
				Zone: "wan",
				Addresses: []InterfaceAddressSnapshot{
					{Family: "inet", Address: "172.16.80.8/24"},
					{Family: "inet6", Address: "2001:559:8585:80::8/64"},
				},
			},
			{
				Name: "reth1.0",
				Zone: "lan",
				Addresses: []InterfaceAddressSnapshot{
					{Family: "inet", Address: "10.0.61.1/24"},
					{Family: "inet6", Address: "2001:559:8585:ef00::1/64"},
				},
			},
		},
		SourceNAT: []SourceNATRuleSnapshot{{
			Name:          "snat",
			FromZone:      "lan",
			ToZone:        "wan",
			InterfaceMode: true,
		}},
	}
	got := buildLocalAddressEntries(snapshot)
	if len(got) != 2 {
		t.Fatalf("len(got) = %d, want 2 (%+v)", len(got), got)
	}
	var sawWanV4, sawWanV6, sawLanV4, sawLanV6 bool
	lanV4 := uint32(0x0a003d01)
	var wanV6 [16]byte
	copy(wanV6[:], []byte(net.ParseIP("2001:559:8585:80::8").To16()))
	var lanV6 [16]byte
	copy(lanV6[:], []byte(net.ParseIP("2001:559:8585:ef00::1").To16()))
	for _, entry := range got {
		if entry.v4 && entry.v4Key == 0xac105008 {
			sawWanV4 = true
		}
		if entry.v4 && entry.v4Key == lanV4 {
			sawLanV4 = true
		}
		if !entry.v4 && entry.v6Key.Addr == wanV6 {
			sawWanV6 = true
		}
		if !entry.v4 && entry.v6Key.Addr == lanV6 {
			sawLanV6 = true
		}
	}
	if sawWanV4 || sawWanV6 {
		t.Fatalf("WAN interface NAT addresses unexpectedly included in local map: %+v", got)
	}
	if !sawLanV4 || !sawLanV6 {
		t.Fatalf("missing LAN interface addresses in local map: %+v", got)
	}
}

func TestBuildSnapshotIncludesUnitInterfaces(t *testing.T) {
	cfg := &config.Config{}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"reth0": {
			Name:            "reth0",
			RedundancyGroup: 1,
			Units: map[int]*config.InterfaceUnit{
				0:  {Number: 0, Addresses: []string{"10.0.61.1/24", "2001:559:8585:ef00::1/64"}},
				50: {Number: 50, VlanID: 50, Addresses: []string{"172.16.50.8/24", "2001:559:8585:50::8/64"}},
			},
		},
		"ge-0/0/2": {
			Name:            "ge-0/0/2",
			RedundantParent: "reth0",
		},
	}
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"wan": {Name: "wan", Interfaces: []string{"reth0.50"}},
	}

	snap := mustBuildSnapshot(t, cfg, config.UserspaceConfig{Workers: 2, RingEntries: 2048}, 1, 0)
	got := map[string]InterfaceSnapshot{}
	for _, iface := range snap.Interfaces {
		got[iface.Name] = iface
	}
	for _, name := range []string{"reth0", "reth0.0", "reth0.50"} {
		if _, ok := got[name]; !ok {
			t.Fatalf("snapshot missing interface %s: %+v", name, snap.Interfaces)
		}
	}
	if got["reth0"].LinuxName != "ge-0-0-2" {
		t.Fatalf("reth0 LinuxName = %q, want ge-0-0-2", got["reth0"].LinuxName)
	}
	if got["reth0.0"].LinuxName != "ge-0-0-2" {
		t.Fatalf("reth0.0 LinuxName = %q, want ge-0-0-2", got["reth0.0"].LinuxName)
	}
	if got["reth0.0"].ParentLinuxName != "ge-0-0-2" {
		t.Fatalf("reth0.0 ParentLinuxName = %q, want ge-0-0-2", got["reth0.0"].ParentLinuxName)
	}
	if got["reth0.50"].LinuxName != "ge-0-0-2.50" {
		t.Fatalf("reth0.50 LinuxName = %q, want ge-0-0-2.50", got["reth0.50"].LinuxName)
	}
	if got["reth0.50"].ParentLinuxName != "ge-0-0-2" {
		t.Fatalf("reth0.50 ParentLinuxName = %q, want ge-0-0-2", got["reth0.50"].ParentLinuxName)
	}
	if got["reth0.50"].VLANID != 50 {
		t.Fatalf("reth0.50 VLANID = %d, want 50", got["reth0.50"].VLANID)
	}
	if got["reth0.50"].Zone != "wan" {
		t.Fatalf("reth0.50 Zone = %q, want wan", got["reth0.50"].Zone)
	}
	if len(got["reth0.50"].Addresses) != 2 {
		t.Fatalf("reth0.50 Addresses = %+v, want config fallback addresses", got["reth0.50"].Addresses)
	}
}

func TestMergeInterfaceAddressSnapshots(t *testing.T) {
	live := []InterfaceAddressSnapshot{
		{Family: "inet", Address: "169.254.1.1/32", Scope: 253},
		{Family: "inet6", Address: "fe80::1/128", Scope: 253},
	}
	configured := []InterfaceAddressSnapshot{
		{Family: "inet", Address: "172.16.50.8/24", Scope: 0},
		{Family: "inet6", Address: "2001:559:8585:50::8/64", Scope: 0},
		{Family: "inet", Address: "169.254.1.1/32", Scope: 253},
		// A configured explicit link-local address overlays the identical live
		// row and must retain its Universe source scope for Rust inference.
		{Family: "inet6", Address: "fe80::1/128", Scope: 0},
	}

	got := mergeInterfaceAddressSnapshots(live, configured)
	if len(got) != 4 {
		t.Fatalf("len(got) = %d, want 4 (%+v)", len(got), got)
	}
	want := map[string]bool{
		"inet/169.254.1.1/32":          true,
		"inet/172.16.50.8/24":          true,
		"inet6/2001:559:8585:50::8/64": true,
		"inet6/fe80::1/128":            true,
	}
	for _, addr := range got {
		key := addr.Family + "/" + addr.Address
		if !want[key] {
			t.Fatalf("unexpected address %s in %+v", key, got)
		}
		delete(want, key)
	}
	if len(want) != 0 {
		t.Fatalf("missing addresses: %+v from %+v", want, got)
	}
	foundConfiguredLL := false
	for _, addr := range got {
		if addr.Family == "inet6" && addr.Address == "fe80::1/128" {
			foundConfiguredLL = true
			if addr.Scope != 0 {
				t.Fatalf("configured explicit link-local scope = %d, want Universe (0)", addr.Scope)
			}
		}
	}
	if !foundConfiguredLL {
		t.Fatal("merged addresses lost configured explicit link-local row")
	}
}

func TestBuildInterfaceSnapshotSetsTunnelFlag(t *testing.T) {
	cfg := &config.Config{}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"st0": {
			Name:   "st0",
			Tunnel: &config.TunnelConfig{},
			Units: map[int]*config.InterfaceUnit{
				0: {},
			},
		},
		"ge-0-0-0": {
			Name: "ge-0-0-0",
		},
	}
	snaps := buildInterfaceSnapshots(cfg)
	tunnelFound := false
	nonTunnelFound := false
	for _, snap := range snaps {
		if snap.Name == "st0" || snap.Name == "st0.0" {
			if !snap.Tunnel {
				t.Errorf("interface %s: Tunnel = false, want true", snap.Name)
			}
			tunnelFound = true
		}
		if snap.Name == "ge-0-0-0" {
			if snap.Tunnel {
				t.Errorf("interface %s: Tunnel = true, want false", snap.Name)
			}
			nonTunnelFound = true
		}
	}
	if !tunnelFound {
		t.Error("tunnel interface st0/st0.0 not found in snapshots")
	}
	if !nonTunnelFound {
		t.Error("non-tunnel interface ge-0-0-0 not found in snapshots")
	}
}

func TestBuildInterfaceSnapshotIncludesInputAndOutputFilters(t *testing.T) {
	cfg := &config.Config{}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"ge-0-0-0": {
			Name: "ge-0-0-0",
			Units: map[int]*config.InterfaceUnit{
				0: {
					FilterInputV4:  "ingress-v4",
					FilterOutputV4: "egress-v4",
					FilterInputV6:  "ingress-v6",
					FilterOutputV6: "egress-v6",
				},
			},
		},
	}

	snaps := buildInterfaceSnapshots(cfg)
	var unitSnap *InterfaceSnapshot
	for i := range snaps {
		if snaps[i].Name == "ge-0-0-0.0" {
			unitSnap = &snaps[i]
			break
		}
	}
	if unitSnap == nil {
		t.Fatal("ge-0-0-0.0 snapshot not found")
	}
	if unitSnap.FilterInputV4 != "ingress-v4" {
		t.Fatalf("FilterInputV4 = %q, want ingress-v4", unitSnap.FilterInputV4)
	}
	if unitSnap.FilterOutputV4 != "egress-v4" {
		t.Fatalf("FilterOutputV4 = %q, want egress-v4", unitSnap.FilterOutputV4)
	}
	if unitSnap.FilterInputV6 != "ingress-v6" {
		t.Fatalf("FilterInputV6 = %q, want ingress-v6", unitSnap.FilterInputV6)
	}
	if unitSnap.FilterOutputV6 != "egress-v6" {
		t.Fatalf("FilterOutputV6 = %q, want egress-v6", unitSnap.FilterOutputV6)
	}
}

const maxTestVLANID = 4094

func missingLoopbackVLANID(t *testing.T) int {
	t.Helper()
	for vlan := maxTestVLANID; vlan >= 2; vlan-- {
		if _, err := net.InterfaceByName(fmt.Sprintf("lo.%d", vlan)); err != nil {
			return vlan
		}
	}
	t.Skip("all loopback VLAN names are present")
	return 0
}

func missingLoopbackVLANIDs(t *testing.T, count int) []int {
	t.Helper()
	out := make([]int, 0, count)
	for vlan := maxTestVLANID; vlan >= 2 && len(out) < count; vlan-- {
		if _, err := net.InterfaceByName(fmt.Sprintf("lo.%d", vlan)); err != nil {
			out = append(out, vlan)
		}
	}
	if len(out) < count {
		t.Skipf("need %d missing loopback VLAN names, found %d", count, len(out))
	}
	return out
}

func missingVLANIDForParents(t *testing.T, parentNames ...string) int {
	t.Helper()
	for vlan := maxTestVLANID; vlan >= 2; vlan-- {
		missing := true
		for _, parentName := range parentNames {
			if _, err := net.InterfaceByName(fmt.Sprintf("%s.%d", parentName, vlan)); err == nil {
				missing = false
				break
			}
		}
		if missing {
			return vlan
		}
	}
	t.Skipf("no VLAN ID is missing for parent interfaces %v", parentNames)
	return 0
}

func liveSnapshotParentInterfaces(t *testing.T, count int) []net.Interface {
	t.Helper()
	interfaces, err := net.Interfaces()
	if err != nil {
		t.Skipf("cannot enumerate interfaces: %v", err)
	}
	out := make([]net.Interface, 0, count)
	for _, iface := range interfaces {
		if iface.Index <= 0 || iface.Name == "" || strings.Contains(iface.Name, ".") || strings.HasPrefix(iface.Name, "reth") {
			continue
		}
		out = append(out, iface)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].Name < out[j].Name
	})
	if len(out) < count {
		t.Skipf("need %d live parent interfaces, found %d", count, len(out))
	}
	return out[:count]
}

func TestSyntheticLogicalIfindexDistinguishesSameVIDDifferentReth(t *testing.T) {
	vlanID := maxTestVLANID
	unitA := fmt.Sprintf("reth0.%d", vlanID)
	unitB := fmt.Sprintf("reth1.%d", vlanID)
	firstUsed := make(map[int]struct{})
	firstA := syntheticLogicalIfindex(unitA, vlanID, firstUsed)
	firstB := syntheticLogicalIfindex(unitB, vlanID, firstUsed)
	secondUsed := make(map[int]struct{})
	secondA := syntheticLogicalIfindex(unitA, vlanID, secondUsed)
	secondB := syntheticLogicalIfindex(unitB, vlanID, secondUsed)
	if firstA != secondA || firstB != secondB {
		t.Fatalf("synthetic ifindex allocation changed across builds: first=(%d,%d) second=(%d,%d)", firstA, firstB, secondA, secondB)
	}
	if firstA == firstB {
		t.Fatalf("same-VLAN RETH units collapsed to one synthetic ifindex: %s=%d %s=%d", unitA, firstA, unitB, firstB)
	}
}

func TestBuildInterfaceSnapshotSynthesizesLogicalIfindexForMissingRethVLAN(t *testing.T) {
	parent, err := net.InterfaceByName("lo")
	if err != nil {
		t.Skipf("loopback interface unavailable: %v", err)
	}
	vlanID := missingLoopbackVLANID(t)
	unitName := fmt.Sprintf("reth0.%d", vlanID)
	linuxUnitName := fmt.Sprintf("lo.%d", vlanID)
	cfg := &config.Config{
		Security: config.SecurityConfig{
			Zones: map[string]*config.ZoneConfig{
				"wan": {Name: "wan", Interfaces: []string{unitName}},
			},
		},
		ClassOfService: &config.ClassOfServiceConfig{
			Interfaces: map[string]*config.CoSInterface{
				"reth0": {
					Name: "reth0",
					Units: map[int]*config.CoSInterfaceUnit{
						vlanID: {
							Unit:               vlanID,
							SchedulerMap:       "bandwidth-limit",
							ShapingRateBytes:   25_000_000_000 / 8,
							BurstSizeBytes:     64 * 1024 * 1024,
							DSCPRewriteRule:    "wan-rewrite",
							DSCPClassifier:     "wan-classifier",
							IEEE8021Classifier: "wan-pcp",
						},
					},
				},
			},
		},
		Interfaces: config.InterfacesConfig{
			Interfaces: map[string]*config.InterfaceConfig{
				"lo": {
					Name:            "lo",
					RedundantParent: "reth0",
				},
				"reth0": {
					Name: "reth0",
					Units: map[int]*config.InterfaceUnit{
						vlanID: {
							Number:         vlanID,
							VlanID:         vlanID,
							FilterOutputV4: "bandwidth-output",
							FilterOutputV6: "bandwidth-output",
						},
					},
				},
			},
		},
	}

	snaps := buildInterfaceSnapshots(cfg)
	var unitSnap *InterfaceSnapshot
	for i := range snaps {
		if snaps[i].Name == unitName {
			unitSnap = &snaps[i]
			break
		}
	}
	if unitSnap == nil {
		t.Fatalf("%s snapshot not found", unitName)
	}
	if unitSnap.Ifindex <= 0 || unitSnap.Ifindex == parent.Index {
		t.Fatalf("Ifindex = %d, want unique logical ifindex distinct from parent %d", unitSnap.Ifindex, parent.Index)
	}
	if unitSnap.Ifindex < syntheticInterfaceIfindexMin || unitSnap.Ifindex > syntheticInterfaceIfindexMax {
		t.Fatalf("Ifindex = %d, want synthetic range [%d,%d]", unitSnap.Ifindex, syntheticInterfaceIfindexMin, syntheticInterfaceIfindexMax)
	}
	if !unitSnap.LogicalOnly {
		t.Fatal("LogicalOnly = false, want true for missing parent-bound RETH VLAN")
	}
	if unitSnap.ParentIfindex != parent.Index {
		t.Fatalf("ParentIfindex = %d, want %d", unitSnap.ParentIfindex, parent.Index)
	}
	if unitSnap.LinuxName != linuxUnitName {
		t.Fatalf("LinuxName = %q, want %s logical child name", unitSnap.LinuxName, linuxUnitName)
	}
	if unitSnap.ParentLinuxName != "lo" {
		t.Fatalf("ParentLinuxName = %q, want lo", unitSnap.ParentLinuxName)
	}
	if unitSnap.VLANID != vlanID {
		t.Fatalf("VLANID = %d, want %d", unitSnap.VLANID, vlanID)
	}
	if unitSnap.Zone != "wan" {
		t.Fatalf("Zone = %q, want wan", unitSnap.Zone)
	}
	if unitSnap.FilterOutputV4 != "bandwidth-output" || unitSnap.FilterOutputV6 != "bandwidth-output" {
		t.Fatalf("output filters not preserved: v4=%q v6=%q", unitSnap.FilterOutputV4, unitSnap.FilterOutputV6)
	}
	if unitSnap.CoSSchedulerMap != "bandwidth-limit" {
		t.Fatalf("CoSSchedulerMap = %q, want bandwidth-limit", unitSnap.CoSSchedulerMap)
	}
	if unitSnap.CoSShapingRateBytesPerSec == 0 {
		t.Fatal("CoSShapingRateBytesPerSec = 0, want configured shaper")
	}
	snapshot := &ConfigSnapshot{Interfaces: []InterfaceSnapshot{*unitSnap}}
	aliases := buildUserspaceIngressBindingAliases(snapshot)
	if len(aliases) != 0 {
		t.Fatalf("logical-only VLAN should not create XSK binding aliases: %v", aliases)
	}
	ifindexes := buildUserspaceIngressIfindexes(snapshot)
	if len(ifindexes) != 1 || ifindexes[0] != uint32(parent.Index) {
		t.Fatalf("ingress ifindexes = %v, want only parent %d", ifindexes, parent.Index)
	}
}

func TestBuildInterfaceSnapshotSynthesizesDeterministicLogicalIfindexForSiblingRethVLANs(t *testing.T) {
	parent, err := net.InterfaceByName("lo")
	if err != nil {
		t.Skipf("loopback interface unavailable: %v", err)
	}
	vlans := missingLoopbackVLANIDs(t, 2)
	unitA := fmt.Sprintf("reth0.%d", vlans[0])
	unitB := fmt.Sprintf("reth0.%d", vlans[1])
	cfg := &config.Config{
		Security: config.SecurityConfig{
			Zones: map[string]*config.ZoneConfig{
				"wan": {Name: "wan", Interfaces: []string{unitA}},
				"dmz": {Name: "dmz", Interfaces: []string{unitB}},
			},
		},
		Interfaces: config.InterfacesConfig{
			Interfaces: map[string]*config.InterfaceConfig{
				"lo": {
					Name:            "lo",
					RedundantParent: "reth0",
				},
				"reth0": {
					Name: "reth0",
					Units: map[int]*config.InterfaceUnit{
						vlans[0]: {Number: vlans[0], VlanID: vlans[0]},
						vlans[1]: {Number: vlans[1], VlanID: vlans[1]},
					},
				},
			},
		},
	}
	readUnits := func() map[string]InterfaceSnapshot {
		byName := make(map[string]InterfaceSnapshot)
		for _, snap := range buildInterfaceSnapshots(cfg) {
			if snap.Name == unitA || snap.Name == unitB {
				byName[snap.Name] = snap
			}
		}
		return byName
	}
	first := readUnits()
	second := readUnits()
	if len(first) != 2 || len(second) != 2 {
		t.Fatalf("missing sibling RETH VLAN snapshots: first=%d second=%d", len(first), len(second))
	}
	for _, name := range []string{unitA, unitB} {
		a := first[name]
		b := second[name]
		if a.Ifindex != b.Ifindex {
			t.Fatalf("%s Ifindex changed across builds: first=%d second=%d", name, a.Ifindex, b.Ifindex)
		}
		if a.Ifindex <= 0 {
			t.Fatalf("%s Ifindex = %d, want >0 synthetic logical ifindex", name, a.Ifindex)
		}
		if a.Ifindex < syntheticInterfaceIfindexMin || a.Ifindex > syntheticInterfaceIfindexMax {
			t.Fatalf("%s Ifindex = %d, want synthetic range [%d,%d]", name, a.Ifindex, syntheticInterfaceIfindexMin, syntheticInterfaceIfindexMax)
		}
		if a.Ifindex == parent.Index {
			t.Fatalf("%s Ifindex = parent ifindex %d, want unique logical ifindex", name, parent.Index)
		}
		if !a.LogicalOnly {
			t.Fatalf("%s LogicalOnly = false, want true", name)
		}
		if a.ParentIfindex != parent.Index {
			t.Fatalf("%s ParentIfindex = %d, want %d", name, a.ParentIfindex, parent.Index)
		}
	}
	if first[unitA].Ifindex == first[unitB].Ifindex {
		t.Fatalf("sibling VLANs collapsed to same synthetic ifindex: %d", first[unitA].Ifindex)
	}
}

func TestBuildInterfaceSnapshotSynthesizesDistinctLogicalIfindexesForSameVLANDifferentReth(t *testing.T) {
	parents := liveSnapshotParentInterfaces(t, 2)
	vlanID := missingVLANIDForParents(t, parents[0].Name, parents[1].Name)
	unitA := fmt.Sprintf("reth0.%d", vlanID)
	unitB := fmt.Sprintf("reth1.%d", vlanID)
	cfg := &config.Config{
		Security: config.SecurityConfig{
			Zones: map[string]*config.ZoneConfig{
				"wan": {Name: "wan", Interfaces: []string{unitA}},
				"dmz": {Name: "dmz", Interfaces: []string{unitB}},
			},
		},
		Interfaces: config.InterfacesConfig{
			Interfaces: map[string]*config.InterfaceConfig{
				parents[0].Name: {
					Name:            parents[0].Name,
					RedundantParent: "reth0",
				},
				parents[1].Name: {
					Name:            parents[1].Name,
					RedundantParent: "reth1",
				},
				"reth0": {
					Name: "reth0",
					Units: map[int]*config.InterfaceUnit{
						vlanID: {Number: vlanID, VlanID: vlanID},
					},
				},
				"reth1": {
					Name: "reth1",
					Units: map[int]*config.InterfaceUnit{
						vlanID: {Number: vlanID, VlanID: vlanID},
					},
				},
			},
		},
	}
	readUnits := func() map[string]InterfaceSnapshot {
		byName := make(map[string]InterfaceSnapshot)
		for _, snap := range buildInterfaceSnapshots(cfg) {
			if snap.Name == unitA || snap.Name == unitB {
				byName[snap.Name] = snap
			}
		}
		return byName
	}
	first := readUnits()
	second := readUnits()
	if len(first) != 2 || len(second) != 2 {
		t.Fatalf("missing same-VLAN RETH snapshots: first=%d second=%d", len(first), len(second))
	}
	for _, tc := range []struct {
		name   string
		parent net.Interface
		zone   string
	}{
		{name: unitA, parent: parents[0], zone: "wan"},
		{name: unitB, parent: parents[1], zone: "dmz"},
	} {
		a := first[tc.name]
		b := second[tc.name]
		if a.Ifindex != b.Ifindex {
			t.Fatalf("%s Ifindex changed across builds: first=%d second=%d", tc.name, a.Ifindex, b.Ifindex)
		}
		if a.Ifindex < syntheticInterfaceIfindexMin || a.Ifindex > syntheticInterfaceIfindexMax {
			t.Fatalf("%s Ifindex = %d, want synthetic range [%d,%d]", tc.name, a.Ifindex, syntheticInterfaceIfindexMin, syntheticInterfaceIfindexMax)
		}
		if !a.LogicalOnly {
			t.Fatalf("%s LogicalOnly = false, want true", tc.name)
		}
		if a.ParentIfindex != tc.parent.Index {
			t.Fatalf("%s ParentIfindex = %d, want %d", tc.name, a.ParentIfindex, tc.parent.Index)
		}
		if a.Zone != tc.zone {
			t.Fatalf("%s Zone = %q, want %q", tc.name, a.Zone, tc.zone)
		}
	}
	if first[unitA].Ifindex == first[unitB].Ifindex {
		t.Fatalf("same-VLAN RETH units collapsed to same synthetic ifindex: %s=%d %s=%d", unitA, first[unitA].Ifindex, unitB, first[unitB].Ifindex)
	}
}

func TestBuildInterfaceSnapshotDoesNotSynthesizeLogicalIfindexForGenericMissingVLAN(t *testing.T) {
	parent, err := net.InterfaceByName("lo")
	if err != nil {
		t.Skipf("loopback interface unavailable: %v", err)
	}
	vlanID := missingLoopbackVLANID(t)
	unitName := fmt.Sprintf("lo.%d", vlanID)
	cfg := &config.Config{
		Security: config.SecurityConfig{
			Zones: map[string]*config.ZoneConfig{
				"wan": {Name: "wan", Interfaces: []string{unitName}},
			},
		},
		Interfaces: config.InterfacesConfig{
			Interfaces: map[string]*config.InterfaceConfig{
				"lo": {
					Name: "lo",
					Units: map[int]*config.InterfaceUnit{
						vlanID: {
							Number: vlanID,
							VlanID: vlanID,
						},
					},
				},
			},
		},
	}

	snaps := buildInterfaceSnapshots(cfg)
	var unitSnap *InterfaceSnapshot
	for i := range snaps {
		if snaps[i].Name == unitName {
			unitSnap = &snaps[i]
			break
		}
	}
	if unitSnap == nil {
		t.Fatalf("%s snapshot not found", unitName)
	}
	if unitSnap.Ifindex != 0 {
		t.Fatalf("Ifindex = %d, want 0 for generic missing VLAN child", unitSnap.Ifindex)
	}
	if unitSnap.LogicalOnly {
		t.Fatal("LogicalOnly = true, want false for generic missing VLAN child")
	}
	if unitSnap.ParentIfindex != parent.Index {
		t.Fatalf("ParentIfindex = %d, want %d", unitSnap.ParentIfindex, parent.Index)
	}
}

func TestBuildUserspaceIngressIfindexesIncludesFabricParent(t *testing.T) {
	snapshot := &ConfigSnapshot{
		Interfaces: []InterfaceSnapshot{
			{
				Name:    "ge-0/0/1",
				Zone:    "lan",
				Ifindex: 11,
			},
			{
				Name:    "ge-0/0/2",
				Zone:    "wan",
				Ifindex: 12,
			},
		},
		Fabrics: []FabricSnapshot{
			{
				Name:            "fab0",
				ParentInterface: "ge-0/0/0",
				ParentLinuxName: "ge-0-0-0",
				ParentIfindex:   21,
				OverlayLinux:    "fab0",
				OverlayIfindex:  101,
				RXQueues:        1,
				PeerAddress:     "10.99.13.2",
			},
		},
	}
	ifindexes := buildUserspaceIngressIfindexes(snapshot)
	found := false
	for _, idx := range ifindexes {
		if idx == 21 {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("fabric parent ifindex 21 not in ingress ifindexes: %v", ifindexes)
	}
	if len(ifindexes) != 3 {
		t.Fatalf("expected 3 ingress ifindexes (2 data + 1 fabric), got %d: %v", len(ifindexes), ifindexes)
	}
}

func TestBuildUserspaceIngressIfindexesDeduplicatesFabricParent(t *testing.T) {
	// If the fabric parent is already in the data interface list, it should
	// not be duplicated.
	snapshot := &ConfigSnapshot{
		Interfaces: []InterfaceSnapshot{
			{
				Name:    "ge-0/0/0",
				Zone:    "lan",
				Ifindex: 21,
			},
		},
		Fabrics: []FabricSnapshot{
			{
				Name:            "fab0",
				ParentInterface: "ge-0/0/0",
				ParentLinuxName: "ge-0-0-0",
				ParentIfindex:   21,
				OverlayLinux:    "fab0",
				OverlayIfindex:  101,
				RXQueues:        1,
				PeerAddress:     "10.99.13.2",
			},
		},
	}
	ifindexes := buildUserspaceIngressIfindexes(snapshot)
	count := 0
	for _, idx := range ifindexes {
		if idx == 21 {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("fabric parent ifindex 21 appeared %d times in ingress ifindexes: %v", count, ifindexes)
	}
}

func TestBuildUserspaceIngressIfindexesSkipsTunnelInterfaces(t *testing.T) {
	snapshot := &ConfigSnapshot{
		Interfaces: []InterfaceSnapshot{
			{
				Name:    "reth1.0",
				Zone:    "lan",
				Ifindex: 5,
			},
			{
				Name:      "gr-0/0/0",
				Zone:      "sfmix",
				Ifindex:   586,
				LinuxName: "gr-0-0-0",
				Tunnel:    true,
			},
		},
	}
	ifindexes := buildUserspaceIngressIfindexes(snapshot)
	for _, idx := range ifindexes {
		if idx == 586 {
			t.Fatalf("tunnel ifindex 586 unexpectedly present in ingress ifindexes: %v", ifindexes)
		}
	}
	if len(ifindexes) != 1 || ifindexes[0] != 5 {
		t.Fatalf("unexpected ingress ifindexes: %v", ifindexes)
	}
}

func TestBuildUserspaceIngressIfindexesIncludesVLANChildAndParent(t *testing.T) {
	snapshot := &ConfigSnapshot{
		Interfaces: []InterfaceSnapshot{
			{
				Name:    "ge-0/0/2",
				Zone:    "wan",
				Ifindex: 6,
			},
			{
				Name:          "ge-0/0/2.80",
				Zone:          "wan",
				Ifindex:       12,
				ParentIfindex: 6,
				VLANID:        80,
			},
		},
	}
	ifindexes := buildUserspaceIngressIfindexes(snapshot)
	if len(ifindexes) != 2 || ifindexes[0] != 6 || ifindexes[1] != 12 {
		t.Fatalf("unexpected ingress ifindexes: %v", ifindexes)
	}
}

func TestBuildUserspaceIngressBindingAliasesIncludesVLANChild(t *testing.T) {
	snapshot := &ConfigSnapshot{
		Interfaces: []InterfaceSnapshot{
			{
				Name:    "ge-0/0/2",
				Zone:    "wan",
				Ifindex: 6,
			},
			{
				Name:          "ge-0/0/2.80",
				Zone:          "wan",
				Ifindex:       12,
				ParentIfindex: 6,
				VLANID:        80,
			},
			{
				Name:      "gr-0/0/0",
				Zone:      "sfmix",
				Ifindex:   362,
				Tunnel:    true,
				LinuxName: "gr-0-0-0",
			},
		},
	}
	aliases := buildUserspaceIngressBindingAliases(snapshot)
	if len(aliases) != 1 {
		t.Fatalf("unexpected alias count: %v", aliases)
	}
	if got := aliases[12]; got != 6 {
		t.Fatalf("alias 12 => %d, want 6", got)
	}
	if _, ok := aliases[362]; ok {
		t.Fatalf("tunnel interface unexpectedly aliased: %v", aliases)
	}
}
