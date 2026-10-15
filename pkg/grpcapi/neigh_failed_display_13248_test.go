package grpcapi

import (
	"net"
	"strings"
	"testing"

	"github.com/vishvananda/netlink"
)

func TestNeighDisplayable13248(t *testing.T) {
	mac := net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}
	cases := []struct {
		name string
		n    netlink.Neigh
		want bool
	}{
		{"incomplete without MAC", netlink.Neigh{IP: net.ParseIP("10.0.0.1"), State: netlink.NUD_INCOMPLETE}, true},
		{"failed without MAC", netlink.Neigh{IP: net.ParseIP("10.0.0.2"), State: netlink.NUD_FAILED}, true},
		{"reachable with MAC", netlink.Neigh{IP: net.ParseIP("10.0.0.3"), HardwareAddr: mac, State: netlink.NUD_REACHABLE}, true},
		{"noarp with MAC", netlink.Neigh{IP: net.ParseIP("10.0.0.4"), HardwareAddr: mac, State: netlink.NUD_NOARP}, true},
		{"unknown with MAC", netlink.Neigh{IP: net.ParseIP("10.0.0.5"), HardwareAddr: mac}, true},
		{"nil IP", netlink.Neigh{HardwareAddr: mac, State: netlink.NUD_REACHABLE}, false},
		{"unresolved state without MAC not rendered", netlink.Neigh{IP: net.ParseIP("10.0.0.6"), State: netlink.NUD_STALE}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := neighDisplayable(tc.n); got != tc.want {
				t.Fatalf("neighDisplayable = %v, want %v", got, tc.want)
			}
		})
	}
	if got := neighMACDisplay(netlink.Neigh{State: netlink.NUD_INCOMPLETE}); got != "(incomplete)" {
		t.Errorf("incomplete MAC display = %q", got)
	}
	if got := neighMACDisplay(netlink.Neigh{State: netlink.NUD_FAILED}); got != "(failed)" {
		t.Errorf("failed MAC display = %q", got)
	}
}

func TestWriteNeighSummaryIncludesEveryDisplayableState13248(t *testing.T) {
	mac := net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}
	neighbors := []netlink.Neigh{
		{IP: net.ParseIP("10.0.0.1"), State: netlink.NUD_INCOMPLETE},
		{IP: net.ParseIP("10.0.0.2"), State: netlink.NUD_FAILED},
		{IP: net.ParseIP("10.0.0.3"), HardwareAddr: mac, State: netlink.NUD_REACHABLE},
		{IP: net.ParseIP("10.0.0.4"), HardwareAddr: mac, State: netlink.NUD_NOARP},
		{IP: net.ParseIP("10.0.0.5"), HardwareAddr: mac, State: 0},
	}
	var buf strings.Builder
	writeNeighSummary(&buf, neighbors, neighStateStr, nil)
	out := buf.String()
	for _, want := range []string{
		"Total entries: 5", "incomplete: 1", "failed: 1", "reachable: 1", "noarp: 1", "unknown: 1",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("summary %q missing %q", out, want)
		}
	}
}

func TestNeighborLinkNamesResolvesEachIndexOnce13248(t *testing.T) {
	neighbors := []netlink.Neigh{
		{IP: net.ParseIP("10.0.0.1"), State: netlink.NUD_INCOMPLETE, LinkIndex: 42},
		{IP: net.ParseIP("10.0.0.2"), State: netlink.NUD_FAILED, LinkIndex: 42},
		{IP: net.ParseIP("10.0.0.3"), State: netlink.NUD_REACHABLE, HardwareAddr: net.HardwareAddr{1, 2, 3, 4, 5, 6}, LinkIndex: 42},
	}
	calls := 0
	names := neighborLinkNames(neighbors, func(index int) (netlink.Link, error) {
		calls++
		if index != 42 {
			t.Fatalf("resolved unexpected link index %d", index)
		}
		return &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: "eth0"}}, nil
	})
	if calls != 1 {
		t.Fatalf("LinkByIndex called %d times for repeated index, want once", calls)
	}
	if names[42] != "eth0" {
		t.Fatalf("resolved interface name %q, want eth0", names[42])
	}
}
