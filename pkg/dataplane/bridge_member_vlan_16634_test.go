package dataplane

import (
	"errors"
	"fmt"
	"net"
	"sort"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/networkd"
	"github.com/vishvananda/netlink"
)

// #16634: an unzoned bridge-domain member VLAN unit (the IRB layout:
// members L2-only, only irb.N zoned) was never created as a kernel
// device, so br-<bd> had no ports and the commit was strict-clean.
//
// These tests drive the REAL programZoneMaps (zone loop + the new
// bridge-member pass) and buildBridgeDomainModels over the #9845 fake
// host fixture (applyWithKernelMTU9845), with ensureVLANSubInterfaceFn
// recording every creation attempt. The fixture requires every touched
// device in initialMTU and fails if ManagedInterfaces is appended
// (programZoneMaps must not reach the model builders), so the networkd
// arm is asserted separately via buildBridgeDomainModels below.

type ensureCall16634 struct {
	parent   string
	vlanID   int
	disabled bool
}

type recordingDP16634 struct {
	DataPlane
	vlanInfo [][3]int // {sub, parent, vlan}
	setZone  int
}

func (d *recordingDP16634) SetZoneConfig(uint32, ZoneConfig) error { return nil }
func (d *recordingDP16634) SetZone(int, uint16, uint32, uint32, uint8, uint8, uint32) error {
	d.setZone++
	return nil
}
func (d *recordingDP16634) AddTxPort(int) error { return nil }
func (d *recordingDP16634) SetVlanIfaceInfo(sub, parent int, vlan uint16) error {
	d.vlanInfo = append(d.vlanInfo, [3]int{sub, parent, int(vlan)})
	return nil
}
func (d *recordingDP16634) SetScreenConfig(uint32, ScreenConfig) error { return nil }
func (d *recordingDP16634) DeleteStaleIfaceZone(map[IfaceZoneKey]bool) {}
func (d *recordingDP16634) DeleteStaleVlanIface(map[uint32]bool)       {}
func (d *recordingDP16634) ZeroStaleScreenConfigs(uint32)              {}

// installEnsureRecorder16634 replaces ensureVLANSubInterfaceFn with a
// recorder that models the #9845 fake host: the child must be named in
// index (initialMTU), and creation is recorded. fail, when non-nil, is
// consulted per (parent, vlanID).
func installEnsureRecorder16634(t *testing.T, index map[string]int, fail func(parent string, vlanID int) (bool, error)) *[]ensureCall16634 {
	t.Helper()
	calls := &[]ensureCall16634{}
	orig := ensureVLANSubInterfaceFn
	t.Cleanup(func() { ensureVLANSubInterfaceFn = orig })
	ensureVLANSubInterfaceFn = func(parent string, vlanID int, disabled bool) (int, bool, error) {
		*calls = append(*calls, ensureCall16634{parent: parent, vlanID: vlanID, disabled: disabled})
		if fail != nil {
			if created, err := fail(parent, vlanID); err != nil {
				return 0, created, err
			}
		}
		name := fmt.Sprintf("%s.%d", parent, vlanID)
		idx, ok := index[name]
		if !ok {
			t.Fatalf("premise: %s is not in the fake host index; initialMTU must name every device the apply touches", name)
		}
		return idx, false, nil
	}
	return calls
}

func ensureNames16634(calls []ensureCall16634) []string {
	out := make([]string, 0, len(calls))
	for _, c := range calls {
		out = append(out, fmt.Sprintf("%s.%d", c.parent, c.vlanID))
	}
	sort.Strings(out)
	return out
}

// irbConfig16634 is the issue's DEFECT-arm shape: ge-0/0/1 vlan-tagging
// unit 100 (vlan-id 100, no family), bridge-domain bd0 vlan-id-list 100
// with explicit member ge-0/0/1.100, routing-interface irb.0, and only
// irb.0 zoned.
func irbConfig16634(memberZoned bool) *config.Config {
	cfg := &config.Config{}
	zones := map[string]*config.ZoneConfig{
		"trust": {Name: "trust", Interfaces: []string{"irb.0"}},
	}
	if memberZoned {
		zones["trust"].Interfaces = []string{"irb.0", "ge-0/0/1.100"}
	}
	cfg.Security.Zones = zones
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"ge-0/0/1": {
			Name: "ge-0/0/1", VlanTagging: true,
			Units: map[int]*config.InterfaceUnit{
				100: {Number: 100, VlanID: 100},
			},
		},
		"irb": {
			Name: "irb",
			Units: map[int]*config.InterfaceUnit{
				0: {Number: 0, Addresses: []string{"10.100.0.1/24"}},
			},
		},
	}
	cfg.BridgeDomains = []*config.BridgeDomainConfig{{
		Name: "bd0", VlanIDs: []int{100},
		Members:          []string{"ge-0/0/1.100"},
		RoutingInterface: "irb.0",
	}}
	return cfg
}

// runZoneMaps16634 drives programZoneMaps over the #9845 fake host.
// initialMTU must name the parent and every child the apply may touch;
// the parent link is seeded in ifCache exactly as the fixture does for
// zone refs, plus bridge-member parents the zone loop never visits.
func runZoneMaps16634(t *testing.T, cfg *config.Config, initialMTU map[string]int, dp *recordingDP16634) *CompileResult {
	t.Helper()
	// Index assignment mirrors applyWithKernelMTU9845 (sorted, 4300+).
	names := make([]string, 0, len(initialMTU))
	for n := range initialMTU {
		names = append(names, n)
	}
	sort.Strings(names)
	index := map[string]int{}
	for i, n := range names {
		index[n] = 4300 + i
	}
	// Reuse the fake host for addr/MTU seams, but drive programZoneMaps
	// ourselves (the helper's own driver cannot seed bridge parents).
	// We replicate its host-safety seams minimally: stub MTU/link seams
	// via fakeHost install, ethtool, and link fetch seams.
	h := &fakeHost8119{
		mtu:   map[string]int{},
		addrs: map[string]map[string]bool{},
		index: index,
	}
	for _, n := range names {
		h.mtu[n] = initialMTU[n]
		h.addrs[n] = map[string]bool{}
	}
	h.install(t)
	mockEthtool(t, func(...string) ([]byte, error) { return []byte("rx-vlan-offload: off\n"), nil })
	origByName, origByIndex := linkByNameSeam, linkByIndexSeam
	t.Cleanup(func() { linkByNameSeam, linkByIndexSeam = origByName, origByIndex })
	linkByNameSeam = func(string) (netlink.Link, error) { return nil, fmt.Errorf("no such device (16634 fixture)") }
	linkByIndexSeam = func(int) (netlink.Link, error) { return nil, fmt.Errorf("no such device (16634 fixture)") }
	oldUp, oldDown := zoneLinkSetUpSeam, zoneLinkSetDownSeam
	t.Cleanup(func() { zoneLinkSetUpSeam, zoneLinkSetDownSeam = oldUp, oldDown })
	zoneLinkSetUpSeam = func(netlink.Link) error { return nil }
	zoneLinkSetDownSeam = func(netlink.Link) error { return nil }

	result := newValidationResult()
	assignZoneIDs(result, cfg)
	assignScreenIDs(result, cfg)
	// Seed every parent in ifCache/linkCache so cachedInterfaceByName
	// resolves without a syscall, and skip buffer tuning per phys.
	parents := map[string]bool{}
	for _, zone := range cfg.Security.Zones {
		if zone == nil {
			continue
		}
		for _, ref := range zone.Interfaces {
			phys, _, _, _ := resolveInterfaceRef(ref, cfg)
			parents[phys] = true
		}
	}
	for _, m := range bridgeDomainMemberVLANs(cfg) {
		parents[m.physName] = true
	}
	// The IRB bridge device itself (br-bd0) is a zone surface via irb.0.
	for phys := range parents {
		idx, ok := index[phys]
		if !ok {
			t.Fatalf("premise: parent %q not in initialMTU", phys)
		}
		result.ifCache[phys] = &net.Interface{Index: idx, Name: phys}
		result.ethtoolApplied["buffers:"+phys] = true
		link := h.link(phys)
		// h.link needs mtu/addrs entries; bridge devices have none in
		// the fake host, so synthesise a plain device.
		if _, ok := h.mtu[phys]; !ok {
			link = &netlink.Device{LinkAttrs: netlink.LinkAttrs{Name: phys, Index: idx}}
		}
		result.linkCache[phys] = link
		result.linkIdxMap[idx] = link
	}
	for _, n := range names {
		link := h.link(n)
		if _, ok := result.linkCache[n]; !ok {
			result.linkCache[n] = link
		}
		result.linkIdxMap[index[n]] = link
	}
	if _, err := programZoneMaps(dp, cfg, result); err != nil {
		t.Fatalf("programZoneMaps: %v", err)
	}
	return result
}

func TestUnzonedBridgeMemberVLANCreated16634(t *testing.T) {
	// DEFECT arm: only irb.0 zoned. Pre-fix, ensure was never called for
	// ge-0-0-1.100 (children = [] in the source probe).
	t.Run("defect arm: unzoned IRB member is created", func(t *testing.T) {
		cfg := irbConfig16634(false)
		dp := &recordingDP16634{}
		// The driver assigns ifindexes sorted from 4300:
		// br-bd0, ge-0-0-1, ge-0-0-1.100.
		calls := installEnsureRecorder16634(t, map[string]int{"br-bd0": 4300, "ge-0-0-1": 4301, "ge-0-0-1.100": 4302}, nil)
		result := runZoneMaps16634(t, cfg, map[string]int{"br-bd0": 1500, "ge-0-0-1": 1500, "ge-0-0-1.100": 1500}, dp)
		got := ensureNames16634(*calls)
		if len(got) != 1 || got[0] != "ge-0-0-1.100" {
			t.Fatalf("ensure calls = %v, want exactly [ge-0-0-1.100] — the unzoned bridge member must be created exactly as the zoned control does (#16634)", got)
		}
		if (*calls)[0].parent != "ge-0-0-1" || (*calls)[0].vlanID != 100 {
			t.Fatalf("ensure call = %+v, want parent ge-0-0-1 vlan 100", (*calls)[0])
		}
		// The fake br-bd0 link carries no Ethernet framing, so the zone
		// loop records it as a non-Ethernet surface (#8279) — unrelated
		// to the member. Assert only that no MEMBER surface is unarmed.
		for _, u := range result.unarmedSurfaces {
			if u.Name == "ge-0-0-1.100" {
				t.Fatalf("member surface recorded unarmed despite successful creation: %+v", u)
			}
		}
		// vlan_iface_map must carry the child so DeleteStaleVlanIface
		// does not reap it and the arm proof can resolve delegation.
		found := false
		for _, v := range dp.vlanInfo {
			if v[0] == 4302 && v[1] == 4301 && v[2] == 100 {
				found = true
			}
		}
		if !found {
			t.Fatalf("SetVlanIfaceInfo calls = %v, want the member child (4302, parent 4301, vlan 100)", dp.vlanInfo)
		}
	})

	// CONTROL arm: member also zoned. The zone loop creates it; the
	// bridge pass must not create a second distinct child or double-write
	// the map entry beyond the idempotent adopt.
	t.Run("control arm: zoned member still created exactly once as a surface", func(t *testing.T) {
		cfg := irbConfig16634(true)
		dp := &recordingDP16634{}
		calls := installEnsureRecorder16634(t, map[string]int{"br-bd0": 4300, "ge-0-0-1": 4301, "ge-0-0-1.100": 4302}, nil)
		runZoneMaps16634(t, cfg, map[string]int{"br-bd0": 1500, "ge-0-0-1": 1500, "ge-0-0-1.100": 1500}, dp)
		// Both passes may call ensure (zone loop + bridge adopt), but the
		// child ifindex must be programmed into vlan_iface_map and the
		// zone map exactly as before; assert the member child was ensured
		// at least once and no unarmed surface appeared.
		found := false
		for _, c := range *calls {
			if c.parent == "ge-0-0-1" && c.vlanID == 100 {
				found = true
			}
		}
		if !found {
			t.Fatalf("ensure calls = %v, want the zoned member ge-0-0-1.100 ensured", ensureNames16634(*calls))
		}
		// Exactly one vlan_iface_map write for the child may survive as
		// the written set entry: count SetVlanIfaceInfo for sub 4302.
		writes := 0
		for _, v := range dp.vlanInfo {
			if v[0] == 4302 {
				writes++
			}
		}
		if writes != 1 {
			t.Fatalf("SetVlanIfaceInfo writes for member child = %d (%v), want exactly 1 — the bridge pass must not double-write a zoned member", writes, dp.vlanInfo)
		}
	})

	// L2-only arm: no IRB, member unzoned, sibling unit 200 zoned. Both
	// .100 (bridge) and .200 (zoned) must be created.
	t.Run("l2-only arm: unzoned member and zoned sibling both created", func(t *testing.T) {
		cfg := &config.Config{}
		cfg.Security.Zones = map[string]*config.ZoneConfig{
			"trust": {Name: "trust", Interfaces: []string{"ge-0/0/1.200"}},
		}
		cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
			"ge-0/0/1": {
				Name: "ge-0/0/1", VlanTagging: true,
				Units: map[int]*config.InterfaceUnit{
					100: {Number: 100, VlanID: 100},
					200: {Number: 200, VlanID: 200},
				},
			},
		}
		cfg.BridgeDomains = []*config.BridgeDomainConfig{{
			Name: "bd0", VlanIDs: []int{100}, Members: []string{"ge-0/0/1.100"},
		}}
		dp := &recordingDP16634{}
		calls := installEnsureRecorder16634(t, map[string]int{"ge-0-0-1": 4300, "ge-0-0-1.100": 4301, "ge-0-0-1.200": 4302}, nil)
		runZoneMaps16634(t, cfg, map[string]int{"ge-0-0-1": 1500, "ge-0-0-1.100": 1500, "ge-0-0-1.200": 1500}, dp)
		got := ensureNames16634(*calls)
		want := []string{"ge-0-0-1.100", "ge-0-0-1.200"}
		if strings.Join(got, ",") != strings.Join(want, ",") {
			t.Fatalf("ensure calls = %v, want %v — the L2-only bridge member .100 must be created as well as the zoned sibling .200 (#16634)", got, want)
		}
	})
}

func TestBridgeMemberCreateFailureFailsApply16634(t *testing.T) {
	cfg := irbConfig16634(false)
	dp := &recordingDP16634{}
	installEnsureRecorder16634(t, map[string]int{"br-bd0": 4300, "ge-0-0-1": 4301, "ge-0-0-1.100": 4302},
		func(parent string, vlanID int) (bool, error) {
			return false, errors.Join(errVLANCreateFailed, errors.New("operation not permitted"))
		})
	// runZoneMaps16634 Fatalf's on error, so drive the member pass
	// directly for the failure arm.
	result := newValidationResult()
	assignZoneIDs(result, cfg)
	result.ifCache["ge-0-0-1"] = &net.Interface{Index: 4301, Name: "ge-0-0-1"}
	st := newZoneMapState()
	err := st.ensureBridgeDomainMemberVLANs(dp, cfg, result)
	if err == nil {
		t.Fatal("a bridge member whose VLAN creation is refused (LinkAdd) must fail the apply — otherwise the commit reports success with no bridge port (#16634/#6893)")
	}
	if !strings.Contains(err.Error(), "br-bd0") || !strings.Contains(err.Error(), "100") {
		t.Fatalf("error %q must name the bridge domain and VLAN", err)
	}
}

func TestBridgeMemberSoftFailureRecordsUnarmed16634(t *testing.T) {
	cfg := irbConfig16634(false)
	dp := &recordingDP16634{}
	installEnsureRecorder16634(t, map[string]int{"br-bd0": 4300, "ge-0-0-1": 4301, "ge-0-0-1.100": 4302},
		func(parent string, vlanID int) (bool, error) {
			return false, errors.New("parent interface ge-0-0-1: no such device")
		})
	result := newValidationResult()
	assignZoneIDs(result, cfg)
	result.ifCache["ge-0-0-1"] = &net.Interface{Index: 4301, Name: "ge-0-0-1"}
	st := newZoneMapState()
	if err := st.ensureBridgeDomainMemberVLANs(dp, cfg, result); err != nil {
		t.Fatalf("non-create failure must keep the soft skip, got %v", err)
	}
	if len(result.unarmedSurfaces) != 1 || result.unarmedSurfaces[0].Name != "ge-0-0-1.100" {
		t.Fatalf("unarmed surfaces = %+v, want one record naming ge-0-0-1.100", result.unarmedSurfaces)
	}
	if !strings.Contains(result.unarmedSurfaces[0].Reason, "br-bd0") {
		t.Fatalf("unarmed reason %q must name the bridge domain", result.unarmedSurfaces[0].Reason)
	}
}

func TestBridgeMemberAbsentParentRecordsUnarmed16634(t *testing.T) {
	cfg := irbConfig16634(false)
	dp := &recordingDP16634{}
	calls := installEnsureRecorder16634(t, map[string]int{"ge-0-0-1.100": 4302}, nil)
	result := newValidationResult()
	assignZoneIDs(result, cfg)
	// Deliberately no ifCache entry for ge-0-0-1: parent absent.
	st := newZoneMapState()
	if err := st.ensureBridgeDomainMemberVLANs(dp, cfg, result); err != nil {
		t.Fatalf("absent parent must soft-skip, got %v", err)
	}
	if len(*calls) != 0 {
		t.Fatalf("ensure must not be called when the parent is absent, got %v", *calls)
	}
	if len(result.unarmedSurfaces) != 1 || result.unarmedSurfaces[0].Name != "ge-0-0-1.100" {
		t.Fatalf("unarmed surfaces = %+v, want one record naming ge-0-0-1.100", result.unarmedSurfaces)
	}
}

// The networkd arm: the member row must carry BridgeMaster (pre-existing
// #11387 behaviour, pinned here so the fix's two halves cannot drift).
func TestBridgeMemberNetworkdRowEnslaved16634(t *testing.T) {
	cfg := irbConfig16634(false)
	result := &CompileResult{ManagedInterfaces: []networkd.InterfaceConfig{
		{Name: "ge-0-0-1.100"}, {Name: "br-bd0", IsBridge: true},
	}}
	// buildBridgeDomainModels appends its own br-bd0; start without it.
	result.ManagedInterfaces = []networkd.InterfaceConfig{{Name: "ge-0-0-1.100"}}
	buildBridgeDomainModels(cfg, result, map[string]bool{})
	var member, bridge *networkd.InterfaceConfig
	for i := range result.ManagedInterfaces {
		switch result.ManagedInterfaces[i].Name {
		case "ge-0-0-1.100":
			member = &result.ManagedInterfaces[i]
		case "br-bd0":
			bridge = &result.ManagedInterfaces[i]
		}
	}
	if member == nil || member.BridgeMaster != "br-bd0" {
		t.Fatalf("member row = %+v, want BridgeMaster br-bd0", member)
	}
	if bridge == nil || !bridge.IsBridge {
		t.Fatalf("bridge row = %+v, want IsBridge br-bd0", bridge)
	}
}

// Enumeration identity: only explicit, unambiguous, tagged members.
func TestBridgeDomainMemberVLANsEnumeration16634(t *testing.T) {
	cfg := irbConfig16634(false)
	got := bridgeDomainMemberVLANs(cfg)
	if len(got) != 1 || got[0].subName != "ge-0-0-1.100" || got[0].physName != "ge-0-0-1" || got[0].vlanID != 100 || got[0].bridge != "br-bd0" {
		t.Fatalf("members = %+v, want the single ge-0-0-1.100/br-bd0 member", got)
	}
	// Ambiguous VID shared by two domains creates for neither.
	cfg.BridgeDomains = append(cfg.BridgeDomains, &config.BridgeDomainConfig{
		Name: "bd1", VlanIDs: []int{100}, Members: []string{"ge-0/0/1.100"},
	})
	if got := bridgeDomainMemberVLANs(cfg); len(got) != 0 {
		t.Fatalf("ambiguous VID members = %+v, want none", got)
	}
}
