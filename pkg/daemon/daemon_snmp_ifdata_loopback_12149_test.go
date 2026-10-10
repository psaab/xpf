package daemon

import (
	"net"
	"testing"

	"github.com/psaab/xpf/pkg/snmp"
	"github.com/vishvananda/netlink"
)

func TestBuildSNMPIfDataIncludesLoopback12149(t *testing.T) {
	previousLister := snmpLinkLister
	previousSpeedReader := snmpLinkSpeedReader
	t.Cleanup(func() {
		snmpLinkLister = previousLister
		snmpLinkSpeedReader = previousSpeedReader
	})
	snmpLinkSpeedReader = func([]netlink.Link) map[int]uint32 { return nil }
	links := []netlink.Link{
		&testLink{attrs: netlink.LinkAttrs{Index: 1, Name: "lo", Flags: net.FlagUp, OperState: netlink.OperUp}},
		&testLink{attrs: netlink.LinkAttrs{Index: 2, Name: "test0", Flags: net.FlagUp, OperState: netlink.OperUp}},
	}
	snmpLinkLister = func() ([]netlink.Link, error) { return links, nil }

	got := buildSNMPIfData()
	if ifNumber := len(got); ifNumber != len(links) {
		t.Fatalf("ifNumber/ifTable count = %d, want %d interfaces including lo; rows: %+v", ifNumber, len(links), got)
	}
	byName := make(map[string]snmp.IfData, len(got))
	for _, iface := range got {
		byName[iface.IfName] = iface
	}
	if loopback, ok := byName["lo"]; !ok || loopback.IfIndex != 1 || loopback.IfDescr != "lo" || loopback.IfType != 24 {
		t.Fatalf("lo row = %+v (present %t), want ifIndex 1, ifDescr/ifName lo, softwareLoopback ifType 24", loopback, ok)
	}
	if other, ok := byName["test0"]; !ok || other.IfType != 6 {
		t.Fatalf("non-loopback row = %+v (present %t), want unchanged ethernetCsmacd ifType 6", other, ok)
	}
}
