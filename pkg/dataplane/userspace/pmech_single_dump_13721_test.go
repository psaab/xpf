package userspace

import (
	"encoding/binary"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netlink/nl"
	"golang.org/x/sys/unix"
)

// #13721 (D19-12): source-selector dump request must be explicitly filtered
// to the main table; an in-process table check after an unfiltered dump is
// insufficient because it still walks every VRF/table in the kernel.
func TestPMechSelectorDumpRequestFiltersMainTable13721(t *testing.T) {
	request := pmechMainRouteSourceSelectorRequest()
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
