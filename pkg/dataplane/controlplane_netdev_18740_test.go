package dataplane

import (
	"errors"
	"fmt"
	"io/fs"
	"net"
	"sort"
	"strings"
	"testing"

	"github.com/vishvananda/netlink"

	"github.com/psaab/xpf/pkg/config"
)

// #18740: every commit attached the shim FRESH to fxp0 and em0 (the HA
// control link) and the acceptance detach removed it again 25-142 ms later.
// The cells below pin the property: an unchanged commit makes no XDP
// transition on any link, control-plane netdevs never reach the attach set,
// and a real zone change on a dataplane link still attaches.

type netdev18740 struct {
	name  string
	index int
	zone  string
}

var (
	dataLink18740 = netdev18740{"ge-0-0-9", 18741, "trust"}
	ctrlLink18740 = netdev18740{"em0", 18742, "control"}
	mgmtLink18740 = netdev18740{"fxp0", 18743, "mgmt"}
	newLink18740  = netdev18740{"ge-0-0-8", 18744, "trust"}
)

func cfg18740(links ...netdev18740) *config.Config {
	cfg := &config.Config{}
	cfg.Security.Zones = map[string]*config.ZoneConfig{}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{}
	for _, l := range links {
		z := cfg.Security.Zones[l.zone]
		if z == nil {
			z = &config.ZoneConfig{Name: l.zone}
			cfg.Security.Zones[l.zone] = z
		}
		z.Interfaces = append(z.Interfaces, l.name+".0")
		cfg.Interfaces.Interfaces[l.name] = &config.InterfaceConfig{
			Name:  l.name,
			Units: map[int]*config.InterfaceUnit{0: {Number: 0}},
		}
	}
	return cfg
}

// compile18740 runs compileZones exactly as CompileConfig does on every
// commit: a FRESH result, the same netdevs present.
func compile18740(t *testing.T, cfg *config.Config, present ...netdev18740) *CompileResult {
	t.Helper()
	result := newValidationResult()
	assignZoneIDs(result, cfg)
	assignScreenIDs(result, cfg)
	for _, l := range present {
		result.rxTagStripOffCache[l.name] = true
		link := &netlink.Device{LinkAttrs: netlink.LinkAttrs{Name: l.name, Index: l.index, EncapType: "ether"}}
		result.ifCache[l.name] = &net.Interface{Index: l.index, Name: l.name}
		result.linkCache[l.name] = link
		result.linkIdxMap[l.index] = link
	}
	if err := compileZones(convergenceTestDP{}, cfg, result); err != nil {
		t.Fatalf("compileZones: %v", err)
	}
	return result
}

// transitionRecorder18740 stands in for the kernel half of AttachXDP: a
// FRESH attach (no registered link) is recorded and registered; a registered
// link falls through to the real AttachXDP, whose "already attached"
// short-circuit is what an unchanged commit must hit. Every detach is
// recorded and answered.
type transitionRecorder18740 struct {
	m        *Manager
	attaches []int
	detaches []int
}

func (r *transitionRecorder18740) seam(op string, ifindex int, _ bool) (bool, error) {
	switch op {
	case "attach":
		if _, ok := r.m.xdpLinkFor(ifindex); ok {
			return false, nil
		}
		r.attaches = append(r.attaches, ifindex)
		r.m.setXDPLink(ifindex, nil)
		return true, nil
	case "detach":
		r.detaches = append(r.detaches, ifindex)
		return true, nil
	}
	return true, fmt.Errorf("unexpected op %q", op)
}

func shimManager18740(t *testing.T) (*Manager, *transitionRecorder18740) {
	t.Helper()
	m := New()
	m.loaded.Store(true)
	m.SelectUserspaceXDPShimEntryProgram()
	m.programs[m.XDPEntryProgram()] = nil
	rec := &transitionRecorder18740{m: m}
	t.Cleanup(SetXDPTransitionSeamForTest(rec.seam))
	return m, rec
}

// The wiring: compileZones keeps em0 and fxp0 out of the attach set and
// records them as skipped, while the dataplane link beside them is queued.
// The arm-coverage proof lists all three and gates on none.
func TestCompileZonesKeepsControlPlaneNetdevsOutOfTheAttachSet18740(t *testing.T) {
	links := []netdev18740{dataLink18740, ctrlLink18740, mgmtLink18740}
	result := compile18740(t, cfg18740(links...), links...)

	if got := append([]int(nil), result.pendingXDP...); len(got) != 1 || got[0] != dataLink18740.index {
		t.Fatalf("pendingXDP = %v, want only the dataplane link %d: control-plane netdevs "+
			"must never reach the shim's attach set (#18740)", got, dataLink18740.index)
	}
	for _, ifidx := range result.pendingTC {
		if ifidx == ctrlLink18740.index || ifidx == mgmtLink18740.index {
			t.Fatalf("pendingTC carries control-plane ifindex %d", ifidx)
		}
	}
	for _, want := range []netdev18740{ctrlLink18740, mgmtLink18740} {
		var found *UnarmedSurface
		for i := range result.unarmedSurfaces {
			if result.unarmedSurfaces[i].Ifindex == want.index {
				found = &result.unarmedSurfaces[i]
			}
		}
		if found == nil {
			t.Fatalf("%s kept out of the attach set must still be recorded for the arm-coverage "+
				"proof; surfaces=%+v", want.name, result.unarmedSurfaces)
		}
		if found.StillForwarding || !strings.Contains(found.Reason, "18740") {
			t.Fatalf("%s: record %+v, want a skipped (not StillForwarding) surface naming #18740",
				want.name, *found)
		}
	}
	rep := classifyArmCoverage(result, lookupFrom(map[int]uint32{dataLink18740.index: 1}, nil))
	if rep.Direct != 1 || rep.Skipped != 2 || rep.Uncovered != 0 || rep.WouldGate {
		t.Fatalf("arm-coverage proof = %+v (%s), want 1 direct, 2 skipped, 0 uncovered, no gate",
			rep, rep.SurfaceSummary())
	}
}

// The property: N unchanged commits make exactly one XDP transition, the
// first attach of the dataplane link. em0 and fxp0 never reach AttachXDP or
// DetachXDP. The twin commit at the end adds a dataplane link to a zone, and
// that link, and only that link, is attached.
func TestUnchangedCommitsMakeNoXDPTransitions18740(t *testing.T) {
	const commits = 20
	m, rec := shimManager18740(t)
	links := []netdev18740{dataLink18740, ctrlLink18740, mgmtLink18740}
	cfg := cfg18740(links...)

	for i := 0; i < commits; i++ {
		before := len(rec.attaches)
		if err := m.attachUserspaceShimXDP(compile18740(t, cfg, links...)); err != nil {
			t.Fatalf("commit %d: attach: %v", i+1, err)
		}
		fresh := rec.attaches[before:]
		switch {
		case i == 0 && (len(fresh) != 1 || fresh[0] != dataLink18740.index):
			t.Fatalf("commit 1 attached %v, want only the dataplane link %d", fresh, dataLink18740.index)
		case i > 0 && len(fresh) != 0:
			t.Fatalf("unchanged commit %d attached %v fresh; an unchanged commit must make "+
				"no XDP transition (#18740)", i+1, fresh)
		}
	}
	if len(rec.detaches) != 0 {
		t.Fatalf("%d unchanged commits detached %v", commits, rec.detaches)
	}

	// Twin: a real zone change on a dataplane link still attaches it.
	changed := append(links, newLink18740)
	before := len(rec.attaches)
	if err := m.attachUserspaceShimXDP(compile18740(t, cfg18740(changed...), changed...)); err != nil {
		t.Fatalf("zone-change commit: attach: %v", err)
	}
	if fresh := rec.attaches[before:]; len(fresh) != 1 || fresh[0] != newLink18740.index {
		t.Fatalf("zone-change commit attached %v, want exactly the new dataplane link %d",
			fresh, newLink18740.index)
	}

	all := append(append([]int(nil), rec.attaches...), rec.detaches...)
	sort.Ints(all)
	for _, ifidx := range all {
		if ifidx == ctrlLink18740.index || ifidx == mgmtLink18740.index {
			t.Fatalf("control-plane ifindex %d reached AttachXDP/DetachXDP: %v", ifidx, all)
		}
	}
}

// The name classes: fxp*/em*, judged on the base name, and nothing else. fab0
// in particular stays shimmable: the zone interface resolves to its local
// member's parent, which carries the fabric redirect path.
func TestControlPlaneNetdevNameClass18740(t *testing.T) {
	for name, want := range map[string]string{
		"fxp0": "fxp name", "fxp0.0": "fxp name", "fxp1": "fxp name",
		"em0": "em name", "em0.100": "em name", "em1": "em name",
		"ge-0-0-0": "", "ge-7-0-1": "", "fab0": "", "reth0": "", "lo0": "", "gr-0-0-0": "",
	} {
		got, ok := ControlPlaneNetdevNameClass(name)
		if got != want || ok != (want != "") {
			t.Errorf("ControlPlaneNetdevNameClass(%q) = (%q, %v), want (%q, %v)", name, got, ok, want, want != "")
		}
	}
}

// A VLAN child of a control-plane parent (fxp0.100) stays out of the attach
// set too: its parent is no longer shimmed, so it has nothing to delegate to,
// and the proof must not count it uncovered. The CONTROL is a VLAN child of a
// dataplane parent in the same compile, which is still queued.
func TestControlPlaneVLANChildStaysOutOfTheAttachSet18740(t *testing.T) {
	type vlan struct {
		parent    netdev18740
		vid       int
		subIndex  int
		wantQueue bool
	}
	cases := []vlan{
		{mgmtLink18740, 100, 18751, false},
		{dataLink18740, 50, 18752, true},
	}

	origByName, origAdd, origUp, origDown, origWrite :=
		vlanLinkByNameSeam, vlanLinkAddSeam, vlanLinkSetUpSeam, vlanLinkSetDownSeam, acceptRAWriteSeam
	t.Cleanup(func() {
		vlanLinkByNameSeam, vlanLinkAddSeam, vlanLinkSetUpSeam, vlanLinkSetDownSeam, acceptRAWriteSeam =
			origByName, origAdd, origUp, origDown, origWrite
	})
	acceptRAWriteSeam = func(string, []byte, fs.FileMode) error { return nil }
	vlanLinkAddSeam = func(netlink.Link) error { return errors.New("must not create") }
	vlanLinkSetUpSeam = func(netlink.Link) error { return nil }
	vlanLinkSetDownSeam = func(netlink.Link) error { return nil }
	byName := map[string]netlink.Link{}
	for _, c := range cases {
		byName[c.parent.name] = &netlink.Device{LinkAttrs: netlink.LinkAttrs{
			Name: c.parent.name, Index: c.parent.index, NetNsID: netnsIDLocal, EncapType: "ether"}}
		sub := fmt.Sprintf("%s.%d", c.parent.name, c.vid)
		byName[sub] = &netlink.Vlan{
			LinkAttrs: netlink.LinkAttrs{Name: sub, Index: c.subIndex, ParentIndex: c.parent.index,
				OperState: netlink.OperUp, NetNsID: netnsIDLocal, EncapType: "ether"},
			VlanId:       c.vid,
			VlanProtocol: netlink.VLAN_PROTOCOL_8021Q,
		}
	}
	vlanLinkByNameSeam = func(name string) (netlink.Link, error) {
		if l, ok := byName[name]; ok {
			return l, nil
		}
		return nil, errors.New("no such device")
	}

	cfg := &config.Config{}
	cfg.Security.Zones = map[string]*config.ZoneConfig{}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{}
	var present []netdev18740
	for _, c := range cases {
		z := cfg.Security.Zones[c.parent.zone]
		if z == nil {
			z = &config.ZoneConfig{Name: c.parent.zone}
			cfg.Security.Zones[c.parent.zone] = z
		}
		z.Interfaces = append(z.Interfaces, fmt.Sprintf("%s.%d", c.parent.name, c.vid))
		cfg.Interfaces.Interfaces[c.parent.name] = &config.InterfaceConfig{
			Name: c.parent.name, VlanTagging: true,
			Units: map[int]*config.InterfaceUnit{c.vid: {Number: c.vid, VlanID: c.vid}},
		}
		present = append(present, c.parent)
	}
	result := compile18740(t, cfg, present...)

	queued := map[int]bool{}
	for _, ifidx := range result.pendingXDP {
		queued[ifidx] = true
	}
	for _, c := range cases {
		if queued[c.subIndex] != c.wantQueue {
			t.Fatalf("VLAN child of %s queued=%v, want %v; pendingXDP=%v unarmed=%+v",
				c.parent.name, queued[c.subIndex], c.wantQueue, result.pendingXDP, result.unarmedSurfaces)
		}
	}
	if !queued[dataLink18740.index] || queued[mgmtLink18740.index] {
		t.Fatalf("parents: pendingXDP=%v, want the dataplane parent queued and fxp0 not", result.pendingXDP)
	}
	// Judge the control-plane surfaces by their own rows. The dataplane
	// child's delegation check resolves its parent through the kernel, which
	// a hermetic test cannot answer, so the report's totals are not the
	// subject here.
	rep := classifyArmCoverage(result, lookupFrom(map[int]uint32{dataLink18740.index: 1}, nil))
	kinds := map[int]SurfaceCoverageKind{}
	for _, s := range rep.Surfaces {
		kinds[s.Ifindex] = s.Kind
	}
	for _, ifidx := range []int{mgmtLink18740.index, cases[0].subIndex} {
		if kinds[ifidx] != CoverageSkipped {
			t.Fatalf("control-plane surface %d is %v in the proof, want skipped (%s)",
				ifidx, kinds[ifidx], rep.SurfaceSummary())
		}
	}
}
