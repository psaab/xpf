package cli

import (
	"net"
	"testing"

	"github.com/vishvananda/netlink"
)

func TestNeighDisplayable13248(t *testing.T) {
	mac := net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}
	for _, tc := range []struct {
		name  string
		neigh netlink.Neigh
		want  bool
	}{
		{"incomplete without MAC", netlink.Neigh{IP: net.ParseIP("10.0.0.1"), State: netlink.NUD_INCOMPLETE}, true},
		{"failed without MAC", netlink.Neigh{IP: net.ParseIP("10.0.0.2"), State: netlink.NUD_FAILED}, true},
		{"reachable with MAC", netlink.Neigh{IP: net.ParseIP("10.0.0.3"), HardwareAddr: mac, State: netlink.NUD_REACHABLE}, true},
		{"nil IP", netlink.Neigh{HardwareAddr: mac, State: netlink.NUD_REACHABLE}, false},
		{"unresolved stale entry", netlink.Neigh{IP: net.ParseIP("10.0.0.4"), State: netlink.NUD_STALE}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := neighDisplayable(tc.neigh); got != tc.want {
				t.Fatalf("neighDisplayable = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestNeighborLinkNamesResolvesEachIndexOnce13248(t *testing.T) {
	neighbors := []netlink.Neigh{
		{IP: net.ParseIP("10.0.0.1"), State: netlink.NUD_INCOMPLETE, LinkIndex: 42},
		{IP: net.ParseIP("10.0.0.2"), State: netlink.NUD_FAILED, LinkIndex: 42},
	}
	calls := 0
	names := neighborLinkNames(neighbors, func(index int) (netlink.Link, error) {
		calls++
		if index != 42 {
			t.Fatalf("resolved unexpected link index %d", index)
		}
		return &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: "eth0"}}, nil
	})
	if calls != 1 || names[42] != "eth0" {
		t.Fatalf("calls=%d names=%v, want one lookup for eth0", calls, names)
	}
}
