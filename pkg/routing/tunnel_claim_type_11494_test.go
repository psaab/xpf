package routing

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/vishvananda/netlink"
)

func TestTunnelVRFClaimIgnoresSameIndexNonVRFMaster11494(t *testing.T) {
	ops := newFakeLinkOps()
	link := seedAnchor(ops, "gr-0-0-0", 42, 1500)
	foreign := &netlink.Bridge{LinkAttrs: netlink.LinkAttrs{Name: "vrf-red", Index: 100}}
	ops.links[foreign.Attrs().Name] = foreign
	link.Attrs().MasterIndex = foreign.Attrs().Index
	tm, _ := newReconcileManager(ops)
	tm.appliedRI = map[string]string{link.Attrs().Name: "red"}

	tm.mu.Lock()
	retry := tm.unbindVRFClaimLocked(link.Attrs().Name, link)
	tm.mu.Unlock()
	if retry {
		t.Fatal("same-name non-VRF master should clear the stale claim without retry")
	}
	if got := link.Attrs().MasterIndex; got != foreign.Attrs().Index {
		t.Fatalf("foreign bridge was detached: master index = %d, want %d", got, foreign.Attrs().Index)
	}
	if got := tm.appliedRI[link.Attrs().Name]; got != "" {
		t.Fatalf("stale claim = %q, want cleared", got)
	}

	// A list observation must not promote a same-name bridge into a claim,
	// either; otherwise a later claim lapse would detach that foreign master.
	tm.appliedRI[link.Attrs().Name] = "prior"
	tc := &config.TunnelConfig{Name: link.Attrs().Name, RIListMember: "red"}
	tm.mu.Lock()
	tm.observeListClaimLocked(tc, link)
	tm.mu.Unlock()
	if got := tm.appliedRI[link.Attrs().Name]; got != "prior" {
		t.Fatalf("list observation claim = %q, want prior claim retained", got)
	}
}
