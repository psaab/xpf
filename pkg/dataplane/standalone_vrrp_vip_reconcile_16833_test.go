package dataplane

import (
	"fmt"
	"net"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/vishvananda/netlink"
)

// #16833 (R3-F11-04): every commit's netlink address reconcile deleted a
// standalone vrrp-group MASTER's VIP. planPhysDesired desired only
// unit.Addresses and the VLAN arm likewise, so planAddressReconcile
// treated the pkg/vrrp-installed VIP as stale debris. VRRP stays MASTER
// (UpdateInstances sees no change) and nothing re-adds it.
//
// Fix: collect each enabled unit's VRRPGroups[*].VirtualAddresses into a
// per-netdev foreign-keep set (physDesired.keepAddrs for the untagged
// arm, unitStandaloneVRRPVIPs for the VLAN arm) that the planner never
// deletes and never adds. Removing the group removes the keep, so the
// next reconcile deletes a still-present VIP (pkg/vrrp also withdraws
// it on instance removal) — asserted below at planner level.
//
// FAIL-ON-REVERT: drop the keep wiring (keepAddrs collection / keepSet
// exemption) and the MASTER + VLAN cells plan del=[VIP] again.

func mkAddr16833(t *testing.T, cidr string) netlink.Addr {
	t.Helper()
	a, err := netlink.ParseAddr(cidr)
	if err != nil {
		t.Fatalf("ParseAddr(%q): %v", cidr, err)
	}
	return *a
}

func delKeys16833(del []*netlink.Addr) map[string]bool {
	out := map[string]bool{}
	for _, a := range del {
		out[a.IPNet.String()] = true
	}
	return out
}

func addKeys16833(add []*netlink.Addr) map[string]bool {
	out := map[string]bool{}
	for _, a := range add {
		out[a.IPNet.String()] = true
	}
	return out
}

// Planner + planPhysDesired level: untagged MASTER, VLAN MASTER, and the
// controls from the issue probe.
func TestStandaloneVRRPVIPSurvivesReconcile16833(t *testing.T) {
	// Untagged: ge-0/0/1 unit 0, real 10.0.1.10/24, VIP 10.0.1.1/24.
	cfg := &config.Config{}
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"trust": {Name: "trust", Interfaces: []string{"ge-0-0-1.0", "ge-0-0-1.100"}},
	}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"ge-0-0-1": {
			Name: "ge-0-0-1", VlanTagging: true,
			Units: map[int]*config.InterfaceUnit{
				0: {
					Number:    0,
					Addresses: []string{"10.0.1.10/24"},
					VRRPGroups: map[string]*config.VRRPGroup{
						"10.0.1.10/24_grp1": {ID: 1, VirtualAddresses: []string{"10.0.1.1/24"}},
					},
				},
				100: {
					Number:    100,
					VlanID:    100,
					Addresses: []string{"10.0.100.10/24"},
					VRRPGroups: map[string]*config.VRRPGroup{
						"10.0.100.10/24_grp1": {ID: 1, VirtualAddresses: []string{"10.0.100.1/24"}},
					},
				},
			},
		},
	}

	pd := planPhysDesired(cfg)["ge-0-0-1"]
	if pd == nil {
		t.Fatal("no physDesired for ge-0-0-1")
	}
	if pd.skipAddrs {
		t.Fatal("standalone VRRP must not set skipAddrs (that would also spare stale debris)")
	}
	// VIP must be in keep, NOT in desired (BACKUP must not gain it).
	if len(pd.keepAddrs) != 1 || pd.keepAddrs[0] != "10.0.1.1/24" {
		t.Fatalf("keepAddrs=%v, want [10.0.1.1/24]", pd.keepAddrs)
	}
	for _, a := range pd.addrs {
		if a == "10.0.1.1/24" {
			t.Fatalf("VIP leaked into desired addrs %v; reconcile would add it on BACKUP", pd.addrs)
		}
	}

	// MASTER: real + VIP + link-local present -> zero deletes, zero adds.
	existing := []netlink.Addr{
		mkAddr16833(t, "10.0.1.10/24"),
		mkAddr16833(t, "10.0.1.1/24"),
		mkAddr16833(t, "fe80::1/64"),
	}
	del, add, _ := planAddressReconcile(existing, pd.addrs, pd.keepAddrs, "ge-0-0-1")
	if len(del) != 0 || len(add) != 0 {
		t.Fatalf("MASTER untagged: del=%v add=%v, want empty (VIP kept)", delKeys16833(del), addKeys16833(add))
	}

	// BACKUP control: no VIP present -> keep must NOT add it.
	existingBackup := []netlink.Addr{mkAddr16833(t, "10.0.1.10/24")}
	del, add, _ = planAddressReconcile(existingBackup, pd.addrs, pd.keepAddrs, "ge-0-0-1")
	if len(del) != 0 || len(add) != 0 {
		t.Fatalf("BACKUP untagged: del=%v add=%v, want empty (keep never adds)", delKeys16833(del), addKeys16833(add))
	}

	// Stale control: non-VIP debris still deleted even with VIP kept.
	existingStale := []netlink.Addr{
		mkAddr16833(t, "10.0.1.10/24"),
		mkAddr16833(t, "10.0.1.1/24"),
		mkAddr16833(t, "10.0.9.9/24"),
	}
	del, add, _ = planAddressReconcile(existingStale, pd.addrs, pd.keepAddrs, "ge-0-0-1")
	if !delKeys16833(del)["10.0.9.9/24"] || delKeys16833(del)["10.0.1.1/24"] || len(add) != 0 {
		t.Fatalf("stale control: del=%v add=%v, want only 10.0.9.9/24 deleted", delKeys16833(del), addKeys16833(add))
	}

	// Group removed: keep empty -> a still-present VIP is now stale and
	// is deleted by the planner (pkg/vrrp withdraws it too on removal).
	del, _, _ = planAddressReconcile(existing, pd.addrs, nil, "ge-0-0-1")
	if !delKeys16833(del)["10.0.1.1/24"] {
		t.Fatalf("group-removed: del=%v, want VIP deleted once keep is gone", delKeys16833(del))
	}

	// VLAN arm: the tagged unit's VIPs via the same helper the VLAN
	// reconcile passes.
	unit100 := cfg.Interfaces.Interfaces["ge-0-0-1"].Units[100]
	keep100 := unitStandaloneVRRPVIPs(unit100)
	if len(keep100) != 1 || keep100[0] != "10.0.100.1/24" {
		t.Fatalf("VLAN keep=%v, want [10.0.100.1/24]", keep100)
	}
	existingVLAN := []netlink.Addr{
		mkAddr16833(t, "10.0.100.10/24"),
		mkAddr16833(t, "10.0.100.1/24"),
	}
	del, add, _ = planAddressReconcile(existingVLAN, unit100.Addresses, keep100, "ge-0-0-1.100")
	if len(del) != 0 || len(add) != 0 {
		t.Fatalf("MASTER VLAN: del=%v add=%v, want empty (VIP kept)", delKeys16833(del), addKeys16833(add))
	}
	// VLAN stale control still deletes.
	existingVLANStale := append(append([]netlink.Addr{}, existingVLAN...), mkAddr16833(t, "10.0.9.9/24"))
	del, _, _ = planAddressReconcile(existingVLANStale, unit100.Addresses, keep100, "ge-0-0-1.100")
	if !delKeys16833(del)["10.0.9.9/24"] || delKeys16833(del)["10.0.100.1/24"] {
		t.Fatalf("VLAN stale control: del=%v, want only 10.0.9.9/24", delKeys16833(del))
	}

	// Disabled unit contributes no keep (CollectInstances still builds
	// it, but the networkd model arms exclude disabled units; the
	// planner mirrors that: planPhysDesired skips disabled units).
	cfgDisabled := &config.Config{}
	cfgDisabled.Security.Zones = map[string]*config.ZoneConfig{
		"trust": {Name: "trust", Interfaces: []string{"ge-0-0-1.0"}},
	}
	cfgDisabled.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"ge-0-0-1": {
			Name: "ge-0-0-1",
			Units: map[int]*config.InterfaceUnit{
				0: {
					Number: 0, Disable: true, Addresses: []string{"10.0.1.10/24"},
					VRRPGroups: map[string]*config.VRRPGroup{
						"10.0.1.10/24_grp1": {ID: 1, VirtualAddresses: []string{"10.0.1.1/24"}},
					},
				},
			},
		},
	}
	if pdD := planPhysDesired(cfgDisabled)["ge-0-0-1"]; pdD != nil && len(pdD.keepAddrs) != 0 {
		t.Fatalf("disabled unit keepAddrs=%v, want none", pdD.keepAddrs)
	}
}

// Actuation level: drive the real compile (programZoneMaps) over the
// fake host for both arms, exactly as a commit would.
func TestStandaloneVRRPVIPSurvivesApply16833(t *testing.T) {
	const parent = "ge-0-0-1"
	child := parent + ".100"
	cfg := &config.Config{}
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"trust": {Name: "trust", Interfaces: []string{parent + ".0", parent + ".100"}},
	}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		parent: {
			Name: parent, VlanTagging: true,
			Units: map[int]*config.InterfaceUnit{
				0: {
					Number: 0, Addresses: []string{"10.0.1.10/24"},
					VRRPGroups: map[string]*config.VRRPGroup{
						"10.0.1.10/24_grp1": {ID: 1, VirtualAddresses: []string{"10.0.1.1/24"}},
					},
				},
				100: {
					Number: 100, VlanID: 100, Addresses: []string{"10.0.100.10/24"},
					VRRPGroups: map[string]*config.VRRPGroup{
						"10.0.100.10/24_grp1": {ID: 1, VirtualAddresses: []string{"10.0.100.1/24"}},
					},
				},
			},
		},
	}
	h, _, _ := applyWithKernelMTU9845(t, cfg, map[string]int{parent: 1500, child: 1500})
	// Simulate MASTER: pkg/vrrp has installed both VIPs.
	h.addrs[parent]["10.0.1.1/24"] = true
	h.addrs[child]["10.0.100.1/24"] = true
	// Stale debris on both devices must still be removed.
	h.addrs[parent]["10.0.9.9/24"] = true
	h.addrs[child]["10.0.9.9/24"] = true

	// Second apply (the routine commit that used to strip the VIPs).
	applyWithKernelMTU9845Reuse(t, cfg, h)

	if !h.addrs[parent]["10.0.1.1/24"] {
		t.Errorf("untagged MASTER VIP 10.0.1.1/24 deleted by second apply; addrs=%v", h.addrs[parent])
	}
	if !h.addrs[child]["10.0.100.1/24"] {
		t.Errorf("VLAN MASTER VIP 10.0.100.1/24 deleted by second apply; addrs=%v", h.addrs[child])
	}
	if h.addrs[parent]["10.0.9.9/24"] || h.addrs[child]["10.0.9.9/24"] {
		t.Errorf("stale 10.0.9.9/24 survived: parent=%v child=%v (keep must not widen to skipAddrs)", h.addrs[parent], h.addrs[child])
	}
	if !h.addrs[parent]["10.0.1.10/24"] || !h.addrs[child]["10.0.100.10/24"] {
		t.Errorf("real addresses lost: parent=%v child=%v", h.addrs[parent], h.addrs[child])
	}
}

// applyWithKernelMTU9845Reuse re-runs programZoneMaps against an
// already-seeded fake host. applyWithKernelMTU9845 always builds a fresh
// host, so this mirrors its seam setup with the caller's host.
func applyWithKernelMTU9845Reuse(t *testing.T, cfg *config.Config, h *fakeHost8119) {
	t.Helper()
	// Reuse the 9845 helper by seeding via a fresh apply on a host we
	// then discard is not possible; instead drive programZoneMaps with
	// the same seams applyWithKernelMTU9845 installs. Simplest faithful
	// path: call applyWithKernelMTU9845-like setup inline.
	// NOTE: fakeHost8119.install + caches mirror applyOnce8119 /
	// applyWithKernelMTU9845 (programZoneMaps entry, convergence DP).
	h.install(t)
	origVLAN := ensureVLANSubInterfaceFn
	t.Cleanup(func() { ensureVLANSubInterfaceFn = origVLAN })
	ensureVLANSubInterfaceFn = func(p string, vlanID int, _ bool) (int, bool, error) {
		name := fmt.Sprintf("%s.%d", p, vlanID)
		return h.index[name], false, nil
	}
	mockEthtool(t, func(...string) ([]byte, error) { return []byte("rx-vlan-offload: off\n"), nil })
	origByName, origByIndex := linkByNameSeam, linkByIndexSeam
	t.Cleanup(func() { linkByNameSeam, linkByIndexSeam = origByName, origByIndex })
	linkByNameSeam = func(string) (netlink.Link, error) { return nil, errNoDevice16833{} }
	linkByIndexSeam = func(int) (netlink.Link, error) { return nil, errNoDevice16833{} }

	result := newValidationResult()
	assignZoneIDs(result, cfg)
	assignScreenIDs(result, cfg)
	for _, zone := range cfg.Security.Zones {
		if zone == nil {
			continue
		}
		for _, ref := range zone.Interfaces {
			phys, _, _, _ := resolveInterfaceRef(ref, cfg)
			result.ifCache[phys] = &net.Interface{Index: h.index[phys], Name: phys}
			result.ethtoolApplied["buffers:"+phys] = true
		}
	}
	for name, idx := range h.index {
		link := h.link(name)
		result.linkCache[name] = link
		result.linkIdxMap[idx] = link
	}
	if _, err := programZoneMaps(convergenceTestDP{}, cfg, result); err != nil {
		t.Fatalf("programZoneMaps (second apply): %v", err)
	}
}

type errNoDevice16833 struct{}

func (errNoDevice16833) Error() string { return "no such device (16833 fixture)" }
