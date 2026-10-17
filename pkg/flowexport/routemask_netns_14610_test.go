package flowexport

import (
	"errors"
	"net"
	"runtime"
	"testing"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
)

// #14610: IPv4 srcMask/dstMask were always exported as 0 because the
// RTA_IIF route lookup has no source address.
//
// The production fibMatchMask previously built
// RouteGetOptions{FIBMatch:true, IifIndex} with no SrcAddr. Production
// InIf is always >0, so every IPv4 lookup took the input-path branch and
// the kernel rejected it (zero source is martian in ip_route_input_slow,
// EINVAL), yielding (0, false) — cached for the TTL and exported as an
// unresolved 0, indistinguishable from a real /0. The unit tests replaced
// the lookup with a fake, so nothing exercised the real netlink call.
//
// The fix uses an output lookup (RTA_OIF = the ifindex's l3mdev master),
// which needs no source address and follows l3mdev enslavement into the
// flow's VRF table. These tests are netns-gated: they SKIP with an
// explicit reason when a private namespace cannot be created, and
// otherwise exercise the REAL kernel FIB — a fake would prove nothing
// about what the kernel accepts. Run under `unshare -rn` or as root.
//
// IPv6 note: the pre-fix IIF query happened to work for IPv6 (the v6
// input path does not martian-reject a zero source the same way), so the
// v6 case below is a control that must stay green, not a RED cell.

// enterPrivateNetns14610 locks the goroutine to its OS thread and moves it
// into a fresh network namespace, restoring the original on cleanup.
func enterPrivateNetns14610(t *testing.T) {
	t.Helper()
	runtime.LockOSThread()
	orig, err := netns.Get()
	if err != nil {
		runtime.UnlockOSThread()
		t.Skipf("cannot read current netns (%v)", err)
	}
	ns, err := netns.New()
	if err != nil {
		orig.Close()
		runtime.UnlockOSThread()
		t.Skipf("cannot create private netns — needs CAP_NET_ADMIN (run under `unshare -rn` or as root): %v", err)
	}
	t.Cleanup(func() {
		_ = netns.Set(orig)
		ns.Close()
		orig.Close()
		runtime.UnlockOSThread()
	})
}

func mustDummy14610(t *testing.T, name string) netlink.Link {
	t.Helper()
	link := &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: name}}
	if err := netlink.LinkAdd(link); err != nil {
		t.Fatalf("LinkAdd %s: %v", name, err)
	}
	got, err := netlink.LinkByName(name)
	if err != nil {
		t.Fatalf("LinkByName %s: %v", name, err)
	}
	if err := netlink.LinkSetUp(got); err != nil {
		t.Fatalf("LinkSetUp %s: %v", name, err)
	}
	return got
}

func mustRoute14610(t *testing.T, dst *net.IPNet, table, linkIndex int) {
	t.Helper()
	r := &netlink.Route{Dst: dst, Table: table, LinkIndex: linkIndex, Scope: netlink.SCOPE_UNIVERSE}
	if err := netlink.RouteAdd(r); err != nil {
		t.Fatalf("RouteAdd %v table %d: %v", dst, table, err)
	}
}

// TestFibMatchMaskRealNetlink14610 is the decisive #14610 cell: in a
// private netns, the REAL fibMatchMask with a positive ifindex must return
// the true prefix length for IPv4 (the pre-fix code returns (0,false) for
// every such query — RED), with a VRF-enslaved ifindex resolving in the
// VRF table and IPv6 unchanged as a control.
func TestFibMatchMaskRealNetlink14610(t *testing.T) {
	enterPrivateNetns14610(t)

	lo, err := netlink.LinkByName("lo")
	if err != nil {
		t.Fatalf("LinkByName lo: %v", err)
	}
	if err := netlink.LinkSetUp(lo); err != nil {
		t.Fatalf("LinkSetUp lo: %v", err)
	}

	// Main-table topology: a /24 covering 192.0.2.0/24 via a device route,
	// plus an IPv6 /48 covering the query address (control).
	d0 := mustDummy14610(t, "d0")
	_, lan4, _ := net.ParseCIDR("192.0.2.0/24")
	mustRoute14610(t, lan4, 254, d0.Attrs().Index)
	_, lan6, _ := net.ParseCIDR("2001:db8:1::/48")
	mustRoute14610(t, lan6, 254, d0.Attrs().Index)

	dst4 := net.ParseIP("192.0.2.5")
	src4 := net.ParseIP("192.0.2.9")
	dst6 := net.ParseIP("2001:db8:1::5")

	// Control: no ifindex (global/main table) — worked before and after.
	if mask, ok := fibMatchMask(dst4, 0); !ok || mask != 24 {
		t.Fatalf("fibMatchMask(%s, iif=0) = (%d, %v), want (24, true)", dst4, mask, ok)
	}
	// Decisive RED pre-fix: attributed ifindex. The pre-fix RTA_IIF query
	// with no source is EINVAL for IPv4, so this returned (0, false).
	if mask, ok := fibMatchMask(dst4, d0.Attrs().Index); !ok || mask != 24 {
		t.Fatalf("fibMatchMask(%s, iif=%d) = (%d, %v), want (24, true) — IPv4 mask unresolved on attributed interface (#14610)",
			dst4, d0.Attrs().Index, mask, ok)
	}
	// Both halves of a flow must resolve (srcMask and dstMask).
	if mask, ok := fibMatchMask(src4, d0.Attrs().Index); !ok || mask != 24 {
		t.Fatalf("fibMatchMask(src %s, iif=%d) = (%d, %v), want (24, true)", src4, d0.Attrs().Index, mask, ok)
	}
	// IPv6 control: must be unchanged by the fix.
	if mask, ok := fibMatchMask(dst6, d0.Attrs().Index); !ok || mask != 48 {
		t.Fatalf("fibMatchMask(%s, iif=%d) = (%d, %v), want (48, true) — IPv6 control regressed", dst6, d0.Attrs().Index, mask, ok)
	}
	if mask, ok := fibMatchMask(dst6, 0); !ok || mask != 48 {
		t.Fatalf("fibMatchMask(%s, iif=0) = (%d, %v), want (48, true)", dst6, mask, ok)
	}

	// VRF leg: a member enslaved to an l3mdev VRF must resolve in the VRF
	// table (table 100), whose covering prefix is a /16 — deliberately
	// different from the main table's /24 so a main-table leak is visible.
	const vrfTable = 100
	vrf := &netlink.Vrf{LinkAttrs: netlink.LinkAttrs{Name: "vrf0"}, Table: vrfTable}
	if err := netlink.LinkAdd(vrf); err != nil {
		t.Skipf("cannot create VRF (kernel without l3mdev?): %v", err)
	}
	vrfLink, err := netlink.LinkByName("vrf0")
	if err != nil {
		t.Fatalf("LinkByName vrf0: %v", err)
	}
	if err := netlink.LinkSetUp(vrfLink); err != nil {
		t.Fatalf("LinkSetUp vrf0: %v", err)
	}
	m0 := mustDummy14610(t, "m0")
	if err := netlink.LinkSetMaster(m0, vrfLink); err != nil {
		t.Fatalf("LinkSetMaster m0->vrf0: %v", err)
	}
	_, vrfNet, _ := net.ParseCIDR("192.0.0.0/16")
	mustRoute14610(t, vrfNet, vrfTable, m0.Attrs().Index)

	if mask, ok := fibMatchMask(dst4, m0.Attrs().Index); !ok || mask != 16 {
		t.Fatalf("fibMatchMask(%s, vrf-member iif=%d) = (%d, %v), want (16, true) — VRF table not selected (#14610)",
			dst4, m0.Attrs().Index, mask, ok)
	}
}

// TestFibMatchMaskOifScoping14610 pins the query shape without a kernel
// netns: the lookup must use RTA_OIF (the l3mdev master), never RTA_IIF,
// and must carry no source address. Reverting to IifIndex flips this RED
// even in an environment where the netns cell is skipped.
func TestFibMatchMaskOifScoping14610(t *testing.T) {
	origLookup := routeLookupWithOptions
	origLink := routeMasterLinkByIndex
	t.Cleanup(func() {
		routeLookupWithOptions = origLookup
		routeMasterLinkByIndex = origLink
	})

	var gotOpts *netlink.RouteGetOptions
	routeLookupWithOptions = func(_ net.IP, opts *netlink.RouteGetOptions) ([]netlink.Route, error) {
		gotOpts = opts
		_, n, _ := net.ParseCIDR("192.0.2.0/24")
		return []netlink.Route{{Dst: n}}, nil
	}
	routeMasterLinkByIndex = func(index int) (netlink.Link, error) {
		switch index {
		case 6: // enslaved member -> master 100
			return &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: "m0", Index: 6, MasterIndex: 100}}, nil
		case 7: // standalone interface, default instance
			return &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: "d0", Index: 7}}, nil
		}
		return nil, errors.New("no such link")
	}

	// Enslaved member: OIF must be the VRF master, IIF must stay 0.
	if mask, ok := fibMatchMask(net.ParseIP("192.0.2.5"), 6); !ok || mask != 24 {
		t.Fatalf("fibMatchMask via master = (%d, %v), want (24, true)", mask, ok)
	}
	if gotOpts == nil {
		t.Fatal("route lookup not called")
	}
	if gotOpts.IifIndex != 0 {
		t.Fatalf("IifIndex = %d, want 0 — RTA_IIF without a source is the #14610 EINVAL", gotOpts.IifIndex)
	}
	if gotOpts.OifIndex != 100 {
		t.Fatalf("OifIndex = %d, want 100 (the l3mdev master)", gotOpts.OifIndex)
	}
	if gotOpts.SrcAddr != nil {
		t.Fatalf("SrcAddr = %v, want nil (output lookup needs no source)", gotOpts.SrcAddr)
	}
	if !gotOpts.FIBMatch {
		t.Fatal("FIBMatch = false, want true")
	}

	// Non-enslaved interface (default routing instance): no RTA_OIF, so
	// the lookup stays on the main table — bit-identical to pre-#3744.
	gotOpts = nil
	if _, ok := fibMatchMask(net.ParseIP("192.0.2.5"), 7); !ok {
		t.Fatal("fibMatchMask via standalone ifindex not ok")
	}
	if gotOpts.OifIndex != 0 || gotOpts.IifIndex != 0 {
		t.Fatalf("standalone ifindex: OifIndex=%d IifIndex=%d, want 0/0 (main table)", gotOpts.OifIndex, gotOpts.IifIndex)
	}

	// Unknown/torn-down ifindex: fall back to the main table rather than
	// failing the lookup (interface may vanish before the background
	// populate runs).
	gotOpts = nil
	if _, ok := fibMatchMask(net.ParseIP("192.0.2.5"), 99); !ok {
		t.Fatal("fibMatchMask with unresolvable ifindex not ok")
	}
	if gotOpts.OifIndex != 0 {
		t.Fatalf("unresolvable ifindex: OifIndex=%d, want 0 (main-table fallback)", gotOpts.OifIndex)
	}
}
