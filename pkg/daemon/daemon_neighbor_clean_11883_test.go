package daemon

import (
	"net"
	"strconv"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/vishvananda/netlink"
)

type snapshotNeighborIfindexes11883 []int

func (ifindexes snapshotNeighborIfindexes11883) ForEachSnapshotNeighbor(fn func(int, net.IP)) {
	for _, ifindex := range ifindexes {
		fn(ifindex, nil)
	}
}

func TestMonitoredNeighborIfindexesIncludesLoopbackAndSnapshot11883(t *testing.T) {
	loopback, err := netlink.LinkByName("lo")
	if err != nil {
		t.Fatalf("resolve loopback link: %v", err)
	}
	loopbackIfindex := loopback.Attrs().Index
	cfg := &config.Config{
		Interfaces: config.InterfacesConfig{
			Interfaces: map[string]*config.InterfaceConfig{"lo": {}},
		},
	}

	allowed := monitoredNeighborIfindexes(cfg, snapshotNeighborIfindexes11883{99, 0})
	if _, ok := allowed[loopbackIfindex]; !ok {
		t.Fatalf("allowlist %v does not contain loopback ifindex %d", allowed, loopbackIfindex)
	}
	if _, ok := allowed[99]; !ok {
		t.Fatalf("allowlist %v does not contain snapshot ifindex 99", allowed)
	}
	if _, ok := allowed[0]; ok {
		t.Fatalf("allowlist %v contains invalid ifindex 0", allowed)
	}
}

func TestCleanFailedNeighborsOnIfindexes11883(t *testing.T) {
	ip7 := net.ParseIP("192.0.2.7").To4()
	ip99 := net.ParseIP("192.0.2.99").To4()
	ip100 := net.ParseIP("192.0.2.100").To4()
	ipWrongLink := net.ParseIP("192.0.2.8").To4()
	neighbors := []netlink.Neigh{
		{LinkIndex: 7, IP: ip7, State: netlink.NUD_FAILED},
		{LinkIndex: 99, IP: ip99, State: netlink.NUD_FAILED},
		{LinkIndex: 100, IP: ip100, State: netlink.NUD_FAILED},
		{LinkIndex: 8, IP: ipWrongLink, State: netlink.NUD_FAILED},
	}
	listed := make(map[int]int)
	var deleted []int
	var reprobed []struct {
		ip    net.IP
		iface string
	}
	ops := failedNeighborCleanupOps{
		listNeigh: func(ifindex, family int) ([]netlink.Neigh, error) {
			listed[ifindex]++
			if family != netlink.FAMILY_V4 {
				return nil, nil
			}
			return neighbors, nil
		},
		linkByIndex: func(ifindex int) (netlink.Link, error) {
			return &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Index: ifindex, Name: "if-" + strconv.Itoa(ifindex)}}, nil
		},
		deleteNeigh: func(neigh *netlink.Neigh) error {
			deleted = append(deleted, neigh.LinkIndex)
			return nil
		},
		probe: func(ip net.IP, iface string) {
			reprobed = append(reprobed, struct {
				ip    net.IP
				iface string
			}{ip: append(net.IP(nil), ip...), iface: iface})
		},
	}

	if got := cleanFailedNeighborsOnIfindexes(map[int]struct{}{7: {}, 99: {}}, ops); got != 2 {
		t.Fatalf("cleaned = %d, want only allowed ifindexes 7 and 99", got)
	}
	if len(listed) != 2 || listed[7] != 2 || listed[99] != 2 || listed[100] != 0 {
		t.Fatalf("listed interface/family counts = %v, want only 7 and 99", listed)
	}
	deletedSet := make(map[int]struct{}, len(deleted))
	for _, ifindex := range deleted {
		deletedSet[ifindex] = struct{}{}
	}
	if len(deletedSet) != 2 {
		t.Fatalf("deleted ifindexes = %v, want only 7 and 99", deleted)
	}
	for _, ifindex := range []int{7, 99} {
		if _, ok := deletedSet[ifindex]; !ok {
			t.Fatalf("deleted ifindexes = %v, missing allowed ifindex %d", deleted, ifindex)
		}
	}
	wantProbes := map[string]string{"192.0.2.7": "if-7", "192.0.2.99": "if-99"}
	if len(reprobed) != len(wantProbes) {
		t.Fatalf("reprobes = %+v, want only %v", reprobed, wantProbes)
	}
	for _, probe := range reprobed {
		wantIface, ok := wantProbes[probe.ip.String()]
		if !ok || probe.iface != wantIface {
			t.Fatalf("unexpected reprobe = %s on %q", probe.ip, probe.iface)
		}
		delete(wantProbes, probe.ip.String())
	}
	if len(wantProbes) != 0 {
		t.Fatalf("missing reprobes: %v", wantProbes)
	}
}
