package routing

import (
	"errors"
	"github.com/psaab/xpf/pkg/config"
	"github.com/vishvananda/netlink"
	"net"
	"testing"
)

// #13121 (D10-03): orphaned / restarted persistent TUNs retain a stale VRF
// master, IFF_UP, and so an active fe80::/64 connected route, because
// unbindVRFClaimLocked gated on the in-memory appliedRI claim which is
// always empty for untracked orphans, after Clear(), and across restarts.
//
// Fix contract:
//   - Orphan TUN prune: unbind whenever the observed master is a managed
//     vrf-* device (claim or no claim) and take the link down so its
//     link-local connected route leaves the kernel FIB.
//   - Configured tunnel with no desired RI: same observed-master unbind
//     when no claim survives, but a foreign (non-VRF) master is untouched
//     and the configured link is still brought up by finishTunnelLocked.

func TestOrphanTUNUnboundFromObservedVRFAndSetDown13121(t *testing.T) {
	base := newFakeLinkOps()
	ops := &linkListFakeOps11443{fakeLinkOps: base}
	seedVRF(base, "x", 99)
	wg9 := &netlink.Tuntap{
		LinkAttrs: netlink.LinkAttrs{Name: "wg9", Index: 94, Flags: net.FlagUp, MasterIndex: 99, MTU: 1412},
		Mode:      netlink.TUNTAP_MODE_TUN,
		Flags:     netlink.TUNTAP_NO_PI,
	}
	base.links["wg9"] = wg9
	base.addrs["wg9"] = []netlink.Addr{
		mustAddr11443(t, "10.77.9.1/24"),
		mustAddr11443(t, "fe80::9/64"),
	}

	tm := &tunnelManager{ops: ops, vrfBinder: &fakeVRFBinder{ops: base, fail: map[string]error{}}}
	if err := tm.Apply([]*config.TunnelConfig{anchorTC("gr-0-0-0", "10.1.2.3/32")}); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	after := base.links["wg9"].Attrs()
	if after.MasterIndex != 0 {
		t.Fatalf("orphan wg9 MasterIndex = %d, want 0 (stale vrf-x binding retained)", after.MasterIndex)
	}
	if after.Flags&net.FlagUp != 0 {
		t.Fatalf("orphan wg9 still up: Flags = %v, want down so fe80::/64 route is withdrawn", after.Flags)
	}
}

func TestOrphanTUNCleanupFailuresFailApply13121(t *testing.T) {
	for _, tc := range []struct {
		name       string
		failDown   bool
		failUnbind bool
	}{
		{name: "LinkSetDown", failDown: true},
		{name: "VRF unbind", failUnbind: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			base := newFakeLinkOps()
			ops := &linkListFakeOps11443{fakeLinkOps: base}
			seedVRF(base, "x", 99)
			base.links["wg9"] = &netlink.Tuntap{
				LinkAttrs: netlink.LinkAttrs{Name: "wg9", Index: 94, Flags: net.FlagUp, MasterIndex: 99},
				Mode:      netlink.TUNTAP_MODE_TUN,
				Flags:     netlink.TUNTAP_NO_PI,
			}
			if tc.failDown {
				ops.downErr = errors.New("injected LinkSetDown failure")
			}
			if tc.failUnbind {
				base.noMasterErr = errors.New("injected LinkSetNoMaster failure")
			}
			tm := &tunnelManager{ops: ops, vrfBinder: &fakeVRFBinder{ops: base, fail: map[string]error{}}}
			if err := tm.Apply(nil); err == nil {
				t.Fatal("Apply succeeded despite incomplete orphan TUN cleanup")
			}
		})
	}
}

func TestConfiguredTunnelUnboundFromObservedVRFWithoutClaim13121(t *testing.T) {
	// wg0 bound to vrf-x, then Clear() wipes appliedRI, then Apply with no
	// routing-instance: the stale master must be released even with no claim.
	base := newFakeLinkOps()
	ops := &linkListFakeOps11443{fakeLinkOps: base}
	seedVRF(base, "x", 99)
	tm := &tunnelManager{ops: ops, vrfBinder: &fakeVRFBinder{ops: base, fail: map[string]error{}}, keepalives: map[string]*keepaliveRunner{}}

	inVRF := &config.TunnelConfig{Name: "wg0", Mode: "wireguard", RoutingInstance: "x", Addresses: []string{"10.88.0.1/24"}}
	if err := tm.Apply([]*config.TunnelConfig{inVRF}); err != nil {
		t.Fatalf("Apply wg0 in VRF x: %v", err)
	}
	if got := base.links["wg0"].Attrs().MasterIndex; got != 99 {
		t.Fatalf("precondition: wg0 MasterIndex = %d, want 99", got)
	}
	if err := tm.Clear(); err != nil {
		t.Fatalf("Clear: %v", err)
	}
	if len(tm.appliedRI) != 0 {
		t.Fatalf("precondition: appliedRI not wiped by Clear: %v", tm.appliedRI)
	}
	inMain := &config.TunnelConfig{Name: "wg0", Mode: "wireguard", RoutingInstance: "", Addresses: []string{"10.88.0.1/24"}}
	if err := tm.Apply([]*config.TunnelConfig{inMain}); err != nil {
		t.Fatalf("Apply wg0 in main: %v", err)
	}
	if got := base.links["wg0"].Attrs().MasterIndex; got != 0 {
		t.Fatalf("wg0 MasterIndex after Clear+Apply(main) = %d, want 0 (stale VRF master retained without claim)", got)
	}
}

func TestConfiguredTunnelForeignMasterUntouched13121(t *testing.T) {
	// A master that is NOT a managed vrf-* device must never be detached,
	// even when no claim exists (identity gate preserved for foreign binds).
	base := newFakeLinkOps()
	ops := &linkListFakeOps11443{fakeLinkOps: base}
	base.links["br-foreign"] = &netlink.Bridge{LinkAttrs: netlink.LinkAttrs{Name: "br-foreign", Index: 77}}
	tt := seedAnchor(base, "gr-0-0-0", 50, 1400)
	tt.LinkAttrs.MasterIndex = 77
	tm := &tunnelManager{ops: ops, vrfBinder: &fakeVRFBinder{ops: base, fail: map[string]error{}}, keepalives: map[string]*keepaliveRunner{}}
	if err := tm.Apply([]*config.TunnelConfig{anchorTC("gr-0-0-0", "10.1.2.3/32")}); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if len(base.noMaster) != 0 {
		t.Fatalf("foreign master detached: LinkSetNoMaster calls = %v", base.noMaster)
	}
	if got := base.links["gr-0-0-0"].Attrs().MasterIndex; got != 77 {
		t.Fatalf("gr-0-0-0 MasterIndex = %d, want 77 (foreign master preserved)", got)
	}
}
