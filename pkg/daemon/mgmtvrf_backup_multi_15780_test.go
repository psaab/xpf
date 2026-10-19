package daemon

import (
	"sort"
	"testing"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// #15780: the daemon installed exactly one table-999 backup-router route
// (the scalar first destination). Every explicit destination must now
// install its own route at metric 250 via the same gateway.
//
// FAIL-ON-REVERT: restoring the single mgmtBackupRouterRoute call in
// mgmtStaticRoutesDesired leaves only 0.0.0.0/1 desired.

func backupDsts15780(t *testing.T, cmds []string) []string {
	t.Helper()
	store := testStoreWithSetConfig(t, cmds)
	cfg := store.ActiveConfig()
	if cfg == nil {
		t.Fatal("no active config")
	}
	fake := &mgmtStaticRouteFake11449{links: map[string]int{"fxp0": 7}}
	current := [2][]netlink.Route{}
	desired := mgmtStaticRoutesDesired(fake, cfg, map[string]bool{"fxp0": true}, current)
	var dsts []string
	for _, target := range desired {
		if target.route.Priority != 250 || target.route.Table != mgmtVRFTableID {
			continue
		}
		if target.route.Gw == nil || target.route.Gw.String() != "192.0.2.1" {
			continue
		}
		dsts = append(dsts, target.route.Dst.String())
	}
	sort.Strings(dsts)
	return dsts
}

func TestBackupRouterInstallsRoutePerDestination15780(t *testing.T) {
	got := backupDsts15780(t, []string{
		"set interfaces fxp0 unit 0 family inet address 192.0.2.2/24",
		"set system backup-router 192.0.2.1 destination [ 0.0.0.0/1 128.0.0.0/1 ]",
	})
	want := []string{"0.0.0.0/1", "128.0.0.0/1"}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("desired backup-router destinations = %v, want %v (one route per destination)", got, want)
	}
}

func TestBackupRouterRepeatedLeavesInstallPerDestination15780(t *testing.T) {
	got := backupDsts15780(t, []string{
		"set interfaces fxp0 unit 0 family inet address 192.0.2.2/24",
		"set system backup-router 192.0.2.1 destination 10.0.0.0/8",
		"set system backup-router 192.0.2.1 destination 172.16.0.0/12",
	})
	want := []string{"10.0.0.0/8", "172.16.0.0/12"}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("desired backup-router destinations = %v, want %v", got, want)
	}
}

// The empty-destination default still installs exactly one route, and
// its family follows the next-hop (::/0 for IPv6).
func TestBackupRouterDefaultFamilies15780(t *testing.T) {
	store := testStoreWithSetConfig(t, []string{
		"set interfaces fxp0 unit 0 family inet6 address 2001:db8:10::2/64",
		"set system backup-router 2001:db8:10::1",
	})
	cfg := store.ActiveConfig()
	fake := &mgmtStaticRouteFake11449{links: map[string]int{"fxp0": 7}}
	desired := mgmtStaticRoutesDesired(fake, cfg, map[string]bool{"fxp0": true}, [2][]netlink.Route{})
	found := 0
	for _, target := range desired {
		if target.route.Priority == 250 {
			found++
			if target.route.Dst.String() != "::/0" || target.family != netlink.FAMILY_V6 {
				t.Fatalf("IPv6 default backup route = %s family %d, want ::/0 v6", target.route.Dst, target.family)
			}
			if target.route.Protocol != 0x58 {
				t.Fatalf("protocol = %d, want 0x58", target.route.Protocol)
			}
			_ = unix.RTN_UNICAST
		}
	}
	if found != 1 {
		t.Fatalf("IPv6 empty-destination backup routes = %d, want exactly 1 (::/0)", found)
	}
}
