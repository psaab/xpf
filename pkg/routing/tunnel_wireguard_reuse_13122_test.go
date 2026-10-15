package routing

import (
	"errors"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/vishvananda/netlink"
)

// #13122 (D10-04): applyWireguardTunLocked must not reuse an incompatible
// pre-existing wg TUN and must not misclassify a transient LinkByName error
// as link absence.

func wgTun(tcName string, flags netlink.TuntapFlag, nonPersist bool) *netlink.Tuntap {
	return &netlink.Tuntap{
		LinkAttrs:  netlink.LinkAttrs{Name: tcName, Index: 50, MTU: 1412},
		Mode:       netlink.TUNTAP_MODE_TUN,
		Flags:      flags,
		NonPersist: nonPersist,
	}
}

func TestWireguardIncompatibleTunRecreated13122(t *testing.T) {
	cases := []struct {
		name       string
		flags      netlink.TuntapFlag
		nonPersist bool
	}{
		{"pi-enabled", 0, false},
		{"non-persistent", netlink.TUNTAP_NO_PI, true},
		{"pi-enabled-and-non-persistent", 0, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ops := newFakeLinkOps()
			ops.links["wg0"] = wgTun("wg0", c.flags, c.nonPersist)
			if anchorReusable(ops.links["wg0"]) {
				t.Fatal("precondition: seeded wg0 must not be anchorReusable")
			}
			tm, _ := newReconcileManager(ops)
			if err := tm.Apply([]*config.TunnelConfig{wgTC("10.0.0.1/24")}); err != nil {
				t.Fatalf("Apply wg0: %v", err)
			}
			foundDel := false
			for _, d := range ops.delNames {
				if d == "wg0" {
					foundDel = true
				}
			}
			if !foundDel {
				t.Fatalf("incompatible wg0 not deleted for recreate; delNames=%v", ops.delNames)
			}
			got, ok := ops.links["wg0"].(*netlink.Tuntap)
			if !ok {
				t.Fatalf("wg0 after Apply is %T, want *netlink.Tuntap", ops.links["wg0"])
			}
			if !anchorReusable(got) {
				t.Fatalf("wg0 after Apply not reusable: Flags=0x%x NonPersist=%v", got.Flags, got.NonPersist)
			}
			if ops.addCount != 1 {
				t.Fatalf("expected exactly 1 LinkAdd recreate, got addCount=%d", ops.addCount)
			}
		})
	}
}

// Compatible control: a persistent NO_PI TUN is reused in place.
func TestWireguardCompatibleTunReused13122(t *testing.T) {
	ops := newFakeLinkOps()
	good := wgTun("wg0", netlink.TUNTAP_NO_PI, false)
	ops.links["wg0"] = good
	if !anchorReusable(good) {
		t.Fatal("precondition: seeded wg0 must be anchorReusable")
	}
	tm, _ := newReconcileManager(ops)
	if err := tm.Apply([]*config.TunnelConfig{wgTC("10.0.0.1/24")}); err != nil {
		t.Fatalf("Apply wg0: %v", err)
	}
	if len(ops.delNames) != 0 || ops.addCount != 0 {
		t.Fatalf("compatible wg0 must be reused in place; delNames=%v addCount=%d", ops.delNames, ops.addCount)
	}
	if ops.links["wg0"] != netlink.Link(good) {
		t.Fatal("compatible wg0 link object replaced instead of reused")
	}
}

// Transient LinkByName error must surface as a NON-sentinel wrapped lookup
// error (errors.Is matches injected), with no LinkAdd attempt, and recovery
// on the next Apply.
func TestWireguardTransientLookupFailsWithoutCreate13122(t *testing.T) {
	ops := newFakeLinkOps()
	good := wgTun("wg0", netlink.TUNTAP_NO_PI, false)
	ops.links["wg0"] = good
	tm, _ := newReconcileManager(ops)
	if err := tm.Apply([]*config.TunnelConfig{wgTC("10.0.0.1/24")}); err != nil {
		t.Fatalf("Apply 1: %v", err)
	}
	injected := errors.New("EBUSY: transient netlink error")
	ops.byNameHardErr["wg0"] = injected
	addAttemptsBefore := ops.addAttempts
	err := tm.Apply([]*config.TunnelConfig{wgTC("10.0.0.1/24")})
	if err == nil {
		t.Fatal("transient lookup must fail Apply (fail-closed)")
	}
	if !errors.Is(err, injected) {
		t.Fatalf("Apply error %v does not wrap injected transient error", err)
	}
	if errors.Is(err, errWGIncompatibleLinkRetained) {
		t.Fatalf("transient lookup error must not be the retain sentinel: %v", err)
	}
	if ops.addAttempts != addAttemptsBefore {
		t.Fatalf("transient lookup must not attempt LinkAdd; addAttempts %d -> %d", addAttemptsBefore, ops.addAttempts)
	}
	tm.mu.Lock()
	owned := tm.ownedNames["wg0"]
	tm.mu.Unlock()
	if owned {
		t.Fatal("healthy WG link re-tracked in ownedNames on transient lookup")
	}
	// Recovery: next Apply reuses the still-present compatible TUN.
	delete(ops.byNameHardErr, "wg0")
	if err := tm.Apply([]*config.TunnelConfig{wgTC("10.0.0.1/24")}); err != nil {
		t.Fatalf("Apply after recovery: %v", err)
	}
	if ops.links["wg0"] != netlink.Link(good) {
		t.Fatal("wg0 not reused after transient recovery")
	}
}

// Genuine not-found still creates the TUN.
func TestWireguardNotFoundCreatesTun13122(t *testing.T) {
	ops := newFakeLinkOps()
	tm, _ := newReconcileManager(ops)
	if err := tm.Apply([]*config.TunnelConfig{wgTC("10.0.0.1/24")}); err != nil {
		t.Fatalf("Apply wg0: %v", err)
	}
	got, ok := ops.links["wg0"].(*netlink.Tuntap)
	if !ok || !anchorReusable(got) {
		t.Fatalf("created wg0 not a reusable TUN: %#v", ops.links["wg0"])
	}
	if ops.addCount != 1 {
		t.Fatalf("expected 1 LinkAdd, got %d", ops.addCount)
	}
}

// Failed replacement LinkDel on an incompatible TUN wraps the retain
// sentinel so Apply re-retains ownedNames for retry (#1919 r5/r6 preserved).
func TestWireguardIncompatibleDelFailureRetainsSentinel13122(t *testing.T) {
	ops := newFakeLinkOps()
	tm, _ := newReconcileManager(ops)
	// First establish ownership with a non-WG anchor, then transition its
	// same-name link to WireGuard while replacement is blocked.
	if err := tm.Apply([]*config.TunnelConfig{anchorTC("wg0")}); err != nil {
		t.Fatalf("Apply anchor: %v", err)
	}
	ops.links["wg0"] = wgTun("wg0", 0, true)
	ops.delFail["wg0"] = errors.New("EBUSY")
	err := tm.Apply([]*config.TunnelConfig{wgTC("10.0.0.1/24")})
	if err == nil || !errors.Is(err, errWGIncompatibleLinkRetained) {
		t.Fatalf("incompatible TUN with failing LinkDel must wrap retain sentinel, got %v", err)
	}
	tm.mu.Lock()
	owned := tm.ownedNames["wg0"]
	tm.mu.Unlock()
	if !owned {
		t.Fatal("failed incompatible-link deletion did not retain ownership for retry")
	}
}
