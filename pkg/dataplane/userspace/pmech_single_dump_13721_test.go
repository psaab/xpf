package userspace

import (
	"encoding/binary"
	"net/netip"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netlink/nl"
	"golang.org/x/sys/unix"
)

func assertPMechMainTableRequest13721(t *testing.T, request *nl.NetlinkRequest) {
	t.Helper()
	if request.NlMsghdr.Flags&unix.NLM_F_DUMP == 0 {
		t.Fatalf("#13721: selector query is not a dump request: flags=%#x", request.NlMsghdr.Flags)
	}
	if len(request.Data) != 2 {
		t.Fatalf("#13721: selector dump should contain rtmsg and RTA_TABLE, got %d payloads", len(request.Data))
	}
	serialized := request.Serialize()[unix.SizeofNlMsghdr:]
	msg := nl.DeserializeRtMsg(serialized)
	if msg.Table != uint8(pmechMainTable) {
		t.Fatalf("#13721: selector dump rtmsg table=%d, want main=%d", msg.Table, pmechMainTable)
	}
	attrs, err := nl.ParseRouteAttr(serialized[msg.Len():])
	if err != nil || len(attrs) != 1 || attrs[0].Attr.Type != unix.RTA_TABLE ||
		len(attrs[0].Value) != 4 || binary.NativeEndian.Uint32(attrs[0].Value) != pmechMainTable {
		t.Fatalf("#13721: selector dump RTA_TABLE is not main-scoped: attrs=%v err=%v", attrs, err)
	}
}

func TestPMechSelectorDumpRequestFiltersMainTable13721(t *testing.T) {
	assertPMechMainTableRequest13721(t, pmechMainRouteSourceSelectorRequest())
}

// Execute the production selector scanner and capture the actual request it
// hands to the netlink executor. This distinguishes table filtering from a
// post-dump userspace table check and exercises raw source-selector detection.
func TestPMechSelectorScannerUsesFilteredRequest13721(t *testing.T) {
	previous := pmechMainRouteSourceRequestIterFn
	t.Cleanup(func() { pmechMainRouteSourceRequestIterFn = previous })
	var captured *nl.NetlinkRequest
	pmechMainRouteSourceRequestIterFn = func(request *nl.NetlinkRequest, visit func([]byte) bool) error {
		captured = request
		source := netip.MustParseAddr("2001:db8:20::").As16()
		visit(rawPMechRouteMessage(64, source[:]))
		return nil
	}
	found, err := pmechMainRouteHasSourceSelector()
	if err != nil || !found {
		t.Fatalf("#13721: production scanner failed to detect main-table source selector: found=%v err=%v", found, err)
	}
	if captured == nil {
		t.Fatal("#13721: production scanner did not pass its request to the netlink executor")
	}
	assertPMechMainTableRequest13721(t, captured)
}
func TestPMechSelectorScanRunsWithOneMainTableTraversal13721(t *testing.T) {
	route := netlink.Route{
		Table: int(pmechMainTable), Family: unix.AF_INET6, Type: unix.RTN_UNICAST,
		Protocol: unix.RTPROT_STATIC, LinkIndex: 10,
	}
	iterCalls := new(int)
	prevIter := pmechMainRouteIterFn
	t.Cleanup(func() { pmechMainRouteIterFn = prevIter })
	pmechMainRouteIterFn = func(visit func(netlink.Route) bool) error {
		*iterCalls++
		visit(route)
		return nil
	}
	sourceCalls := new(int)
	prevSource := pmechMainRouteSourceSelectorFn
	t.Cleanup(func() { pmechMainRouteSourceSelectorFn = prevSource })
	pmechMainRouteSourceSelectorFn = func() (bool, error) {
		*sourceCalls++
		return false, nil
	}
	prefetch := dumpPMechMainRoutes(&config.Config{}, []IpsecTunnelRowSnapshot{
		{STN: "st0", IfID: 9, LogicalIfindex: 10},
	})
	if *iterCalls != 1 || *sourceCalls != 1 {
		t.Fatalf("#13721: expected one main-table traversal and one bounded selector check, got main=%d selector=%d",
			*iterCalls, *sourceCalls)
	}
	if prefetch.err != nil || prefetch.sourceSpecific {
		t.Fatalf("#13721: ordinary main route incorrectly invalidated inventory: err=%v sourceSpecific=%v",
			prefetch.err, prefetch.sourceSpecific)
	}
}

func TestPMechLockedCaptureRefreshReusesInventoryWithoutDump13721(t *testing.T) {
	m, _, _ := pmechDedupManager9506(t)
	dumpCalls := new(int)
	previous := pmechMainRouteIterFn
	t.Cleanup(func() { pmechMainRouteIterFn = previous })
	pmechMainRouteIterFn = func(visit func(netlink.Route) bool) error {
		*dumpCalls++
		return nil
	}
	next := *m.lastSnapshot
	next.Generation++
	oldInventory := m.lastSnapshot.PMechInventory
	m.mu.Lock()
	m.refreshCaptureAuthorityLocked(&next)
	m.mu.Unlock()
	if *dumpCalls != 0 {
		t.Fatalf("#13721: locked refresh attempted %d route dumps", *dumpCalls)
	}
	if next.PMechInventory == nil || !next.PMechInventory.Complete ||
		next.PMechInventory.Generation != next.Generation {
		t.Fatalf("#13721: unchanged, current inventory was not reused: %+v", next.PMechInventory)
	}
	if next.PMechInventory == oldInventory || oldInventory.Generation != m.lastSnapshot.Generation {
		t.Fatal("#13721: locked refresh mutated the retained snapshot's inventory")
	}
}

func TestPMechLockedCaptureRefreshWithChangedTunnelFailsClosedWithoutDump13721(t *testing.T) {
	m, _, _ := pmechDedupManager9506(t)
	m.SetCaptureEpochProvider(func(uint64, uint32) (uint64, []QueueEpochSnapshot, uint64, []IpsecTunnelRowSnapshot) {
		return 2, nil, 4, []IpsecTunnelRowSnapshot{{STN: "st0", IfID: 9, LogicalIfindex: 4}}
	})
	dumpCalls := new(int)
	previous := pmechMainRouteIterFn
	t.Cleanup(func() { pmechMainRouteIterFn = previous })
	pmechMainRouteIterFn = func(visit func(netlink.Route) bool) error {
		*dumpCalls++
		return nil
	}
	m.mu.Lock()
	m.refreshCaptureAuthorityLocked(m.lastSnapshot)
	m.mu.Unlock()
	if *dumpCalls != 0 {
		t.Fatalf("#13721: mismatched tunnel refresh attempted %d route dumps under lock", *dumpCalls)
	}
	inventory := m.lastSnapshot.PMechInventory
	if inventory == nil || inventory.Complete || inventory.TunnelRows[0].InventoryValid ||
		inventory.TunnelRows[0].InventoryReason != "MAIN_ROUTE_INVENTORY_STALE" {
		t.Fatalf("#13721: changed tunnel identity did not fail closed without a dump: %+v", inventory)
	}
}

func TestPMechLockedStalePrefetchFailsClosedWithoutDump13721(t *testing.T) {
	m, _, _ := pmechDedupManager9506(t)
	dumpCalls := new(int)
	previous := pmechMainRouteIterFn
	t.Cleanup(func() { pmechMainRouteIterFn = previous })
	pmechMainRouteIterFn = func(visit func(netlink.Route) bool) error {
		*dumpCalls++
		return nil
	}
	m.mu.Lock()
	stampCaptureAuthorityWithRoutesNoFallback(m.lastSnapshot, m.captureEpochProvider, nil)
	m.mu.Unlock()
	if *dumpCalls != 0 {
		t.Fatalf("#13721: stale locked prefetch attempted %d route dumps", *dumpCalls)
	}
	inventory := m.lastSnapshot.PMechInventory
	if inventory == nil || inventory.Complete ||
		inventory.TunnelRows[0].InventoryReason != "MAIN_ROUTE_INVENTORY_STALE" {
		t.Fatalf("#13721: missing locked prefetch did not fail closed: %+v", inventory)
	}
}
