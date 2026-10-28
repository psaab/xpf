package vrrp

import (
	"net"
	"testing"

	"github.com/psaab/xpf/pkg/cluster"
	"github.com/psaab/xpf/pkg/config"
	"github.com/vishvananda/netlink"
)

// Sub-96 mapped VIP (::ffff:10.0.0.1/95) through vipAddrSet membership,
// netlink actuation, and GARP family classification (#17150 round 2).
// ParseVRRPVIP returns the v4 host identity (10.0.0.1/32) for this
// spelling, so every consumer below must agree it is the IPv4 host
// 10.0.0.1: excluded from IPv4 advert-source selection against the
// kernel's 10.0.0.1 address, actuated as an IPv4 address, and announced
// via the GARP (not NA) burst.
//
// FAIL-ON-REVERT: restoring the kept-mapped sub-96 branch makes
// canonAddr key "::ffff:10.0.0.1" (membership miss below), puts the VIP
// in the v6 advert slice, and — via the raw-string re-parse sinks —
// still actuates/GARPs it as IPv4: the split this test pins shut.

const vipSub96Mapped = "::ffff:10.0.0.1/95"

func TestMappedSub96VIPAddrSetActuationGARP17150(t *testing.T) {
	// Parse-level premise: v4 host identity.
	p, ok := config.ParseVRRPVIP(vipSub96Mapped)
	if !ok || !p.Addr().Is4() || p.Addr().String() != "10.0.0.1" || p.Bits() != 32 {
		t.Fatalf("ParseVRRPVIP(%q) = (%v,%v), want IPv4 host 10.0.0.1/32", vipSub96Mapped, p, ok)
	}

	// (b) vipAddrSet membership against a 10.0.0.1 kernel address: the
	// set must contain exactly the lookup key resolveLocalIPv4 uses
	// (ip4.String() == "10.0.0.1"), and source selection must exclude
	// the VIP, picking the next-lowest non-VIP address instead.
	vi := newInstance(Instance{
		Interface:        "reth0.50",
		GroupID:          1,
		Priority:         200,
		VirtualAddresses: []string{vipSub96Mapped},
	}, &net.Interface{Name: "reth0.50", Index: 42}, make(chan VRRPEvent, 16), nil)
	set := vi.vipAddrSet()
	if !set["10.0.0.1"] {
		t.Errorf("vipAddrSet(%q) = %v, want membership of kernel lookup key %q", vipSub96Mapped, set, "10.0.0.1")
	}
	if set["::ffff:10.0.0.1"] {
		t.Errorf("vipAddrSet(%q) contains mapped key %q — the #2516 leak form; want only the v4 lookup form", vipSub96Mapped, "::ffff:10.0.0.1")
	}
	vi.addrsFn = func() ([]net.Addr, error) {
		return []net.Addr{
			ipnetAddr(t, "10.0.0.1/24"), // the VIP as the kernel reports it (sorts low)
			ipnetAddr(t, "10.0.0.2/24"), // the real per-node source
		}, nil
	}
	if got := vi.resolveLocalIPv4(set); got == nil || got.String() != "10.0.0.2" {
		t.Errorf("resolveLocalIPv4 with /95 VIP = %v, want 10.0.0.2 (VIP 10.0.0.1 excluded)", got)
	}
	if v4, _ := vi.resolveLocalAddrSets(set); len(v4) != 1 || v4[0] != "10.0.0.2" {
		t.Errorf("resolveLocalAddrSets v4 = %v, want [10.0.0.2] (VIP excluded from self set)", v4)
	}

	// (c1) Actuation: addVIPsListLocked must apply the VIP as an IPv4
	// host address. The fake addrAddFn captures the netlink.Addr the
	// production sink builds from the raw string; assert its family
	// agrees with the parse (IPv4), not a v6 /95.
	var added []netlink.Addr
	vi.linkByNameFn = func(name string) (netlink.Link, error) { return fiveZeroEightTwoLink(name), nil }
	vi.addrAddFn = func(_ netlink.Link, a *netlink.Addr) error {
		added = append(added, *a)
		return nil
	}
	vi.addrDelFn = func(netlink.Link, *netlink.Addr) error { return nil }
	res := vi.addVIPsListLocked([]string{vipSub96Mapped})
	if !res.ok() || len(added) != 1 {
		t.Fatalf("addVIPsListLocked(%q) = %+v added=%v, want one applied VIP", vipSub96Mapped, res, added)
	}
	if added[0].IP.To4() == nil || added[0].IP.String() != "10.0.0.1" {
		t.Errorf("actuated address IP = %v (To4=%v), want IPv4 host 10.0.0.1 agreeing with ParseVRRPVIP", added[0].IP, added[0].IP.To4())
	}
	if v4, v6 := splitVIPsByFamily([]string{vipSub96Mapped}); len(v4) != 1 || len(v6) != 0 || v4[0].String() != "10.0.0.1" {
		t.Errorf("splitVIPsByFamily(%q) = v4:%v v6:%v, want v4:[10.0.0.1] only", vipSub96Mapped, v4, v6)
	}

	// (c2) GARP family: sendGARP must take the IPv4 GARP burst for the
	// /95 VIP (with the 10.0.0.1 host), never the IPv6 NA burst.
	var garpIPs, naIPs []string
	oldGARP, oldNA, oldProbe := garpBurstFn, naBurstFn, arpProbeFn
	garpBurstFn = func(_ string, ip net.IP, _ int, _ cluster.BurstStillValid) error {
		garpIPs = append(garpIPs, ip.String())
		return nil
	}
	naBurstFn = func(_ string, ip net.IP, _ int, _ cluster.BurstStillValid) error {
		naIPs = append(naIPs, ip.String())
		return nil
	}
	arpProbeFn = func(string, net.IP, net.IP) error { return nil }
	defer func() { garpBurstFn, naBurstFn, arpProbeFn = oldGARP, oldNA, oldProbe }()

	vi.setState(StateMaster)
	vi.sendGARP(true)
	if len(garpIPs) != 1 || garpIPs[0] != "10.0.0.1" {
		t.Errorf("GARP bursts = %v, want exactly [10.0.0.1] (IPv4 family)", garpIPs)
	}
	if len(naIPs) != 0 {
		t.Errorf("NA bursts = %v, want none — /95 must not announce as IPv6", naIPs)
	}
}
