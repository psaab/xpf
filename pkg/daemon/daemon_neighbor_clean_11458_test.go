package daemon

import (
	"net"
	"path/filepath"
	"testing"

	"github.com/psaab/xpf/pkg/dataplane"
	"github.com/psaab/xpf/pkg/dataplane/userspace"
	"github.com/vishvananda/netlink"
)

func TestCleanFailedNeighborsMonitoredOnly11458(t *testing.T) {
	store := newConfigStore(t, filepath.Join(t.TempDir(), "config.db"))
	cfg, err := store.SyncApply(`interfaces {
    lo {
        unit 0 {
            family inet {
                address 127.0.0.1/8;
            }
        }
    }
}`, nil)
	if err != nil {
		t.Fatalf("SyncApply loopback config: %v", err)
	}
	monitored := userspace.MonitoredInterfaceLinkIndexes(cfg)
	if _, ok := monitored[1]; !ok {
		t.Fatalf("test precondition: loopback ifindex 1 is not monitored: %v", monitored)
	}

	monitoredIP := net.ParseIP("192.0.2.1").To4()
	unmonitoredIP := net.ParseIP("198.51.100.99").To4()
	neighbors := []netlink.Neigh{
		{LinkIndex: 1, IP: monitoredIP, State: netlink.NUD_FAILED},
		{LinkIndex: 99, IP: unmonitoredIP, State: netlink.NUD_FAILED},
	}
	var listed []int
	var deleted []int
	var reprobed []struct {
		ip    net.IP
		iface string
	}
	d := &Daemon{
		store: store,
		neighListFn: func(ifindex, family int) ([]netlink.Neigh, error) {
			listed = append(listed, ifindex)
			if family != netlink.FAMILY_V4 {
				return nil, nil
			}
			var out []netlink.Neigh
			for _, neigh := range neighbors {
				if ifindex == 0 || neigh.LinkIndex == ifindex {
					out = append(out, neigh)
				}
			}
			return out, nil
		},
		linkByIndexFn: func(ifindex int) (netlink.Link, error) {
			return &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Index: ifindex, Name: "test"}}, nil
		},
		neighDelFn: func(neigh *netlink.Neigh) error {
			deleted = append(deleted, neigh.LinkIndex)
			return nil
		},
		failedNeighborProbeFn: func(ip net.IP, iface string) {
			reprobed = append(reprobed, struct {
				ip    net.IP
				iface string
			}{ip: append(net.IP(nil), ip...), iface: iface})
		},
	}

	if got := d.cleanFailedNeighbors(); got != 1 {
		t.Fatalf("cleaned = %d, want only monitored interface's failed neighbor", got)
	}
	if len(listed) == 0 {
		t.Fatal("cleanFailedNeighbors did not list a monitored interface")
	}
	for _, ifindex := range listed {
		if ifindex != 1 {
			t.Fatalf("listed ifindex %d, want only monitored ifindex 1", ifindex)
		}
	}
	if len(deleted) != 1 || deleted[0] != 1 {
		t.Fatalf("deleted ifindexes = %v, want [1]", deleted)
	}
	if len(reprobed) != 1 || !reprobed[0].ip.Equal(monitoredIP) || reprobed[0].iface != "test" {
		t.Fatalf("reprobes = %+v, want only the monitored neighbor", reprobed)
	}
}

type snapshotNeighborRuntime11458 struct {
	dataplane.RuntimeDataPlane
}

func (*snapshotNeighborRuntime11458) ForEachSnapshotNeighbor(fn func(ifindex int, ip net.IP)) {
	fn(99, net.ParseIP("203.0.113.1").To4())
}

func TestCleanFailedNeighborsSnapshotInterface11458(t *testing.T) {
	store := newConfigStore(t, filepath.Join(t.TempDir(), "config.db"))
	cfg, err := store.SyncApply(`interfaces {
    lo {
        unit 0 {
            family inet {
                address 127.0.0.1/8;
            }
        }
    }
}`, nil)
	if err != nil {
		t.Fatalf("SyncApply loopback config: %v", err)
	}
	if _, ok := userspace.MonitoredInterfaceLinkIndexes(cfg)[1]; !ok {
		t.Fatal("test precondition: loopback ifindex 1 is not monitored")
	}

	snapshotIP := net.ParseIP("203.0.113.1").To4()
	unmonitoredIP := net.ParseIP("198.51.100.100").To4()
	neighbors := []netlink.Neigh{
		{LinkIndex: 99, IP: snapshotIP, State: netlink.NUD_FAILED},
		{LinkIndex: 100, IP: unmonitoredIP, State: netlink.NUD_FAILED},
	}
	listed := make(map[int]int)
	var deleted []int
	var reprobed []struct {
		ip    net.IP
		iface string
	}
	d := &Daemon{
		store: store,
		neighListFn: func(ifindex, family int) ([]netlink.Neigh, error) {
			listed[ifindex]++
			if family != netlink.FAMILY_V4 {
				return nil, nil
			}
			var out []netlink.Neigh
			for _, neigh := range neighbors {
				if neigh.LinkIndex == ifindex {
					out = append(out, neigh)
				}
			}
			return out, nil
		},
		linkByIndexFn: func(ifindex int) (netlink.Link, error) {
			return &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Index: ifindex, Name: "snapshot"}}, nil
		},
		neighDelFn: func(neigh *netlink.Neigh) error {
			deleted = append(deleted, neigh.LinkIndex)
			return nil
		},
		failedNeighborProbeFn: func(ip net.IP, iface string) {
			reprobed = append(reprobed, struct {
				ip    net.IP
				iface string
			}{ip: append(net.IP(nil), ip...), iface: iface})
		},
	}
	d.setDataplane(&snapshotNeighborRuntime11458{})

	if got := d.cleanFailedNeighbors(); got != 1 {
		t.Fatalf("cleaned = %d, want only snapshot interface's failed neighbor", got)
	}
	if listed[1] != 2 || listed[99] != 2 || listed[100] != 0 {
		t.Fatalf("listed interface/family counts = %v, want only configured 1 and snapshot 99", listed)
	}
	if len(deleted) != 1 || deleted[0] != 99 {
		t.Fatalf("deleted ifindexes = %v, want [99]", deleted)
	}
	if len(reprobed) != 1 || !reprobed[0].ip.Equal(snapshotIP) || reprobed[0].iface != "snapshot" {
		t.Fatalf("reprobes = %+v, want only the snapshot neighbor", reprobed)
	}
}
