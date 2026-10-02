package routing

import (
	"sort"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/vishvananda/netlink"
)

// #11443: a tunnel removed while xpfd is DOWN is never reaped on restart.
// ownedNames/wgConfigured/xfrmis start empty, so the tracked-only removal
// diffs (tunnel.go Apply, tunnel_wireguard.go WG prune, xfrm.go Apply) never
// visit the stale device: the link, its addresses, and the kernel connected
// route persist, and a stale kernel GRE device keeps encap/decapping
// kernel-routed traffic outside current policy.
//
// The fix is a bounded LinkList orphan sweep (the #847 VRF precedent):
//   - stale gr-/ip-/wg-named kernel GRE/IPIP links are LinkDel'd;
//   - absent TUNs (including gr-named AnchorOnly or WireGuard devices) are
//     kept and have non-link-local addresses pruned because the kernel TUN
//     type cannot distinguish those ownership modes after restart;
//   - st* xfrmi devices absent from desired are deleted.
//
// linkListFakeOps11443 is the shared fakeLinkOps with a faithful LinkList
// (the shared fake returns nil, nil — every pre-#11443 test relies on that,
// so the sweep stays invisible to them and this wrapper is the only fake
// that exercises it).
type linkListFakeOps11443 struct {
	*fakeLinkOps
	listErr error
}

func (f *linkListFakeOps11443) LinkList() ([]netlink.Link, error) {
	if f.listErr != nil {
		return nil, f.listErr
	}
	out := make([]netlink.Link, 0, len(f.links))
	for _, l := range f.links {
		out = append(out, l)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Attrs().Name < out[j].Attrs().Name })
	return out, nil
}

func seedGretun11443(ops *fakeLinkOps, name string, index int) {
	ops.links[name] = &netlink.Gretun{LinkAttrs: netlink.LinkAttrs{Name: name, Index: index}}
}

func seedIptun11443(ops *fakeLinkOps, name string, index int) {
	ops.links[name] = &netlink.Iptun{LinkAttrs: netlink.LinkAttrs{Name: name, Index: index}}
}

func seedXfrmi11443(ops *fakeLinkOps, name string, index int, ifid uint32) {
	ops.links[name] = &netlink.Xfrmi{LinkAttrs: netlink.LinkAttrs{Name: name, Index: index}, Ifid: ifid}
}

func seedDummy11443(ops *fakeLinkOps, name string, index int) {
	ops.links[name] = &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: name, Index: index}}
}

func mustAddr11443(t *testing.T, s string) netlink.Addr {
	t.Helper()
	a, err := netlink.ParseAddr(s)
	if err != nil {
		t.Fatalf("bad fixture addr %q: %v", s, err)
	}
	return *a
}

// TestTunnelOrphanReapRemoveWhileDown11443 is the remove-while-down →
// gone-on-restart cell: a FRESH manager (empty ownedNames/wgConfigured,
// the restart shape) applying a config that no longer contains the
// tunnels must reap the stale kernel devices — at minimum their
// addresses — while leaving configured, foreign, and wrong-typed links
// alone.
func TestTunnelOrphanReapRemoveWhileDown11443(t *testing.T) {
	base := newFakeLinkOps()
	ops := &linkListFakeOps11443{fakeLinkOps: base}

	// Stale GRE/IPIP devices from tunnels removed while down.
	seedGretun11443(base, "gr-9-9-9", 91)
	seedAnchor(base, "gr-8-8-8", 92, 1500) // TUN ownership is ambiguous after restart
	seedIptun11443(base, "ip-7-7-7", 93)
	base.addrs["gr-9-9-9"] = []netlink.Addr{mustAddr11443(t, "10.9.0.1/24")}
	base.addrs["gr-8-8-8"] = []netlink.Addr{mustAddr11443(t, "10.8.0.1/24")}
	base.addrs["ip-7-7-7"] = []netlink.Addr{mustAddr11443(t, "10.7.0.1/24")}

	// Stale WG TUN removed while down: link KEPT (#1432 S2a), non-LL
	// addresses pruned. Link-locals are ALL kept — applied==nil on the
	// restart pass means the reconcile cannot tell a configured fe80
	// from the kernel's autoconf fe80, and the gate must not delete
	// autoconf (the #1884 r1 Codex F2 contract).
	seedAnchor(base, "wg9", 94, 1412)
	base.addrs["wg9"] = []netlink.Addr{
		mustAddr11443(t, "10.77.9.1/24"),
		mustAddr11443(t, "fe80::9/64"),
	}

	seedGretun11443(base, "wg8", 95) // stale WG-named link with incompatible type
	// Foreign / wrong-typed links that must survive the sweep.
	seedDummy11443(base, "eth9", 96)
	seedDummy11443(base, "gr-dummy", 97) // gr- name, non-tunnel type
	base.links["wgbond0"] = &netlink.Bond{LinkAttrs: netlink.LinkAttrs{Name: "wgbond0", Index: 98}}
	seedVRF(base, "x", 99)
	base.addrs["eth9"] = []netlink.Addr{mustAddr11443(t, "192.0.2.9/24")}

	tm := &tunnelManager{ops: ops, vrfBinder: &fakeVRFBinder{ops: base, fail: map[string]error{}}}
	if err := tm.Apply([]*config.TunnelConfig{anchorTC("gr-0-0-0", "10.1.2.3/32")}); err != nil {
		t.Fatalf("Apply: %v", err)
	}

	for _, gone := range []string{"gr-9-9-9", "ip-7-7-7", "wg8"} {
		if _, err := base.LinkByName(gone); err == nil {
			t.Errorf("orphan %s survived the restart sweep (remove-while-down leak #11443)", gone)
		}
		if addrs := base.addrs[gone]; len(addrs) != 0 {
			t.Errorf("orphan %s left addresses behind: %v", gone, addrs)
		}
	}
	// An absent TUN with a gr- name might have been WireGuard mode, so keep
	// its link and prune the non-link-local address instead.
	if _, err := base.LinkByName("gr-8-8-8"); err != nil {
		t.Errorf("gr-named WG TUN was deleted during startup reap: %v", err)
	}
	if base.hasAddr("gr-8-8-8", "10.8.0.1/24") {
		t.Error("gr-named WG TUN leaked its non-link-local address")
	}
	// The WG TUN persists by design, but its configured routable address is
	// removed while its unknown-to-this-restart link-local is protected.
	if _, err := base.LinkByName("wg9"); err != nil {
		t.Errorf("wg9 link deleted by the sweep (must be kept, #1432 S2a): %v", err)
	}
	if base.hasAddr("wg9", "10.77.9.1/24") {
		t.Error("wg9 leaked its non-link-local address after removal while down")
	}
	if !base.hasAddr("wg9", "fe80::9/64") {
		t.Error("wg9 link-local address was deleted despite unknown restart ownership")
	}

	// Configured + foreign links untouched.
	for _, keep := range []string{"gr-0-0-0", "eth9", "gr-dummy", "wgbond0", "vrf-x"} {
		if _, err := base.LinkByName(keep); err != nil {
			t.Errorf("link %s wrongly reaped: %v", keep, err)
		}
	}
	if !base.hasAddr("eth9", "192.0.2.9/24") {
		t.Error("foreign eth9 address disturbed by the sweep")
	}

	// Second apply is a no-op for the sweep (idempotent, no churn).
	dels := len(base.delNames)
	if err := tm.Apply([]*config.TunnelConfig{anchorTC("gr-0-0-0", "10.1.2.3/32")}); err != nil {
		t.Fatalf("Apply 2: %v", err)
	}
	if got := len(base.delNames); got != dels {
		t.Fatalf("second apply deleted more links (churn): %v", base.delNames[dels:])
	}
}

// TestXfrmOrphanReapRemoveWhileDown11443 is the xfrmi half: a VPN removed
// while down leaves its st* device with no tracking entry; the restart
// Apply must delete it. Non-xfrmi st* links and non-st* xfrmis are
// foreign and must survive.
func TestXfrmOrphanReapRemoveWhileDown11443(t *testing.T) {
	base := newFakeLinkOps()
	ops := &linkListFakeOps11443{fakeLinkOps: base}

	seedXfrmi11443(base, "st0.9", 61, 0x10)
	seedDummy11443(base, "st9", 63)            // st* name, not an xfrmi
	seedXfrmi11443(base, "corp-vpn", 64, 0x99) // xfrmi, not xpf-shaped

	seedXfrmi11443(base, "st0.1", 62, 2) // still desired: adopted
	xm := &xfrmManager{ops: ops}
	vpns := map[string]*config.IPsecVPN{
		"vpn1": {Name: "vpn1", BindInterface: "st0.1"},
	}
	if err := xm.Apply(vpns); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if _, err := base.LinkByName("st0.9"); err == nil {
		t.Error("orphan st0.9 survived the restart sweep (remove-while-down leak #11443)")
	}
	for _, keep := range []string{"st0.1", "st9", "corp-vpn"} {
		if _, err := base.LinkByName(keep); err != nil {
			t.Errorf("link %s wrongly reaped: %v", keep, err)
		}
	}
}

// TestTunnelOrphanReapLinkListFailure11443 pins the non-fatal contract:
// a LinkList failure skips the sweep (retry next Apply) but must not
// fail the commit or disturb the desired reconcile.
func TestTunnelOrphanReapLinkListFailure11443(t *testing.T) {
	base := newFakeLinkOps()
	ops := &linkListFakeOps11443{fakeLinkOps: base}
	ops.listErr = errTestLinkList11443
	seedGretun11443(base, "gr-9-9-9", 91)

	tm := &tunnelManager{ops: ops, vrfBinder: &fakeVRFBinder{ops: base, fail: map[string]error{}}}
	if err := tm.Apply([]*config.TunnelConfig{anchorTC("gr-0-0-0", "10.1.2.3/32")}); err != nil {
		t.Fatalf("Apply with failed LinkList must not fail the commit: %v", err)
	}
	if _, err := base.LinkByName("gr-0-0-0"); err != nil {
		t.Fatalf("desired tunnel not applied when the sweep was skipped: %v", err)
	}
	if _, err := base.LinkByName("gr-9-9-9"); err != nil {
		t.Fatal("orphan deleted without a link enumeration (must be skipped, retried next Apply)")
	}
}

type errTestLinkList11443T struct{}

func (errTestLinkList11443T) Error() string { return "injected LinkList failure" }

var errTestLinkList11443 error = errTestLinkList11443T{}
