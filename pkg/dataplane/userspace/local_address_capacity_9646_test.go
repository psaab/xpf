package userspace

import (
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/vishvananda/netlink"
)

// hostAddrs9646 returns n distinct host addresses of one family, the shape the
// netlink enumeration hands buildDesiredLocalAddressSets.
func hostAddrs9646(n int, v6 bool) []netlink.Addr {
	out := make([]netlink.Addr, 0, n)
	for i := 0; i < n; i++ {
		var ip net.IP
		if v6 {
			ip = net.IP{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, byte(i >> 16), byte(i >> 8), byte(i)}
		} else {
			ip = net.IPv4(10, byte(i>>16), byte(i>>8), byte(i)).To4()
		}
		out = append(out, netlink.Addr{IPNet: &net.IPNet{IP: ip, Mask: net.CIDRMask(len(ip)*8, len(ip)*8)}})
	}
	return out
}

// managerWithHostAddrs9646 builds a manager whose host enumeration returns v4
// and v6 addresses and whose userspace_ctrl row is a fake seeded Enabled=1, so a
// fail-closed write is observable rather than indistinguishable from a no-op.
func managerWithHostAddrs9646(v4, v6 int) (*Manager, *fakeCtrlMap) {
	m := New()
	v4Addrs, v6Addrs := hostAddrs9646(v4, false), hostAddrs9646(v6, true)
	m.addrListForLocalSyncHook = func(_ netlink.Link, family int) ([]netlink.Addr, error) {
		if family == netlink.FAMILY_V6 {
			return v6Addrs, nil
		}
		return v4Addrs, nil
	}
	ctrl := &fakeCtrlMap{
		stored:     userspaceCtrlValue{Enabled: 1, MetadataVersion: userspaceMetadataVersion, Workers: 1, QueueCount: 1},
		haveStored: true,
	}
	m.failClosedCtrlMapHook = ctrl
	return m, ctrl
}

// TestLocalAddressSetPastCapacityDoesNotDisableCtrl9646 is the cell the defect
// fails: before the fix the oversized set reached the map updates, the first
// E2BIG (here: the unloaded map) failed the sync, and the sync failure wrote
// Enabled=0.
func TestLocalAddressSetPastCapacityDoesNotDisableCtrl9646(t *testing.T) {
	for _, tc := range []struct {
		name    string
		v4, v6  int
		mapName string
	}{
		{"v4", userspaceLocalAddressMapCapacity + 1, 0, mapNameUserspaceLocalV4},
		{"v6", 0, userspaceLocalAddressMapCapacity + 1, mapNameUserspaceLocalV6},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m, ctrl := managerWithHostAddrs9646(tc.v4, tc.v6)
			err := m.syncUserspaceClassifierMapsFailClosedLocked(&ConfigSnapshot{})
			if err == nil {
				t.Fatal("an oversized local-address set synced without error")
			}
			if !isLocalAddressCapacityError(err) {
				t.Fatalf("error is not the capacity refusal: %v", err)
			}
			for _, want := range []string{strconv.Itoa(userspaceLocalAddressMapCapacity), tc.mapName} {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("capacity error does not name %q: %v", want, err)
				}
			}
			if ctrl.updates != 0 || ctrl.stored.Enabled != 1 {
				t.Fatalf("a capacity refusal wrote userspace_ctrl (updates=%d, Enabled=%d); one address past the map capacity must not drop all transit",
					ctrl.updates, ctrl.stored.Enabled)
			}
		})
	}
}

// TestLocalAddressSetAtCapacityStillFailsClosedOnAnOrdinaryError9646: a set of
// exactly the capacity passes the preflight (so the next step, here the unloaded
// ingress map, is reached), and that ordinary failure still fails closed. It is
// the control that stops the cell above from passing on "never fail closed".
func TestLocalAddressSetAtCapacityStillFailsClosedOnAnOrdinaryError9646(t *testing.T) {
	m, ctrl := managerWithHostAddrs9646(userspaceLocalAddressMapCapacity, userspaceLocalAddressMapCapacity)
	err := m.syncUserspaceClassifierMapsFailClosedLocked(&ConfigSnapshot{})
	if err == nil {
		t.Fatal("expected the unloaded-map failure")
	}
	if isLocalAddressCapacityError(err) {
		t.Fatalf("a set of exactly the capacity was refused: %v", err)
	}
	if ctrl.stored.Enabled != 0 {
		t.Fatalf("an ordinary classifier sync failure did not fail closed (Enabled=%d)", ctrl.stored.Enabled)
	}
}

// TestLocalAddressMapCapacityMatchesTheShim9646 binds the Go preflight to the
// shim declarations it describes.
func TestLocalAddressMapCapacityMatchesTheShim9646(t *testing.T) {
	src, err := os.ReadFile("../../../userspace-xdp/src/lib.rs")
	if err != nil {
		t.Fatalf("read shim source: %v", err)
	}
	for _, name := range []string{"USERSPACE_LOCAL_V4", "USERSPACE_LOCAL_V6"} {
		re := regexp.MustCompile(`static ` + name + `: [^=]*= HashMap::with_max_entries\((\d+),`)
		match := re.FindSubmatch(src)
		if match == nil {
			t.Fatalf("no with_max_entries declaration found for %s", name)
		}
		got, _ := strconv.Atoi(string(match[1]))
		if got != userspaceLocalAddressMapCapacity {
			t.Errorf("%s max_entries is %d in the shim but the Go preflight checks %d", name, got, userspaceLocalAddressMapCapacity)
		}
	}
}

// TestStatusPollKeepsCtrlOnACapacityRefusal9646 binds the second carve-out. The
// status poll re-syncs the enforced snapshot every second, so host address
// growth past the capacity used to drop all transit on the next tick. It must
// keep the ready helper's ctrl enabled, raise the alarm once, and clear it when
// a sync fits again. The control arm shows the carve-out is scoped to the
// capacity refusal: a set that fits reaches the unloaded ingress map and that
// ordinary failure still fails closed.
func TestStatusPollKeepsCtrlOnACapacityRefusal9646(t *testing.T) {
	withHostAddrs := func(m *Manager, v4 int) {
		addrs := hostAddrs9646(v4, false)
		m.addrListForLocalSyncHook = func(_ netlink.Link, family int) ([]netlink.Addr, error) {
			if family == netlink.FAMILY_V6 {
				return nil, nil
			}
			return addrs, nil
		}
		m.syncClassifierMapsHook = nil
		m.lastSnapshot = &ConfigSnapshot{}
	}

	m, ctrl := seamedManager(t)
	withHostAddrs(m, userspaceLocalAddressMapCapacity+1)
	if err := m.applyHelperStatusLocked(readyHelperStatus()); err != nil {
		t.Fatalf("a capacity refusal failed the status apply: %v", err)
	}
	if !ctrl.haveStored || ctrl.stored.Enabled != 1 {
		t.Fatalf("the status poll did not keep a ready helper's ctrl enabled on a capacity refusal (stored=%v, Enabled=%d)",
			ctrl.haveStored, ctrl.stored.Enabled)
	}
	if !strings.Contains(m.localAddressCapacityAlarm, strconv.Itoa(userspaceLocalAddressMapCapacity)) {
		t.Fatalf("no capacity alarm latched: %q", m.localAddressCapacityAlarm)
	}
	m.syncClassifierMapsHook = func(*ConfigSnapshot) error { return nil }
	if err := m.applyHelperStatusLocked(readyHelperStatus()); err != nil {
		t.Fatalf("applyHelperStatusLocked after the set fits: %v", err)
	}
	if m.localAddressCapacityAlarm != "" {
		t.Fatalf("the capacity alarm did not clear once a sync fit: %q", m.localAddressCapacityAlarm)
	}

	control, controlCtrl := seamedManager(t)
	withHostAddrs(control, userspaceLocalAddressMapCapacity)
	if err := control.applyHelperStatusLocked(readyHelperStatus()); err == nil {
		t.Fatal("control: the unloaded ingress map did not fail the status apply")
	}
	if controlCtrl.haveStored && controlCtrl.stored.Enabled != 0 {
		t.Fatalf("control: an ordinary classifier sync failure left ctrl enabled (Enabled=%d)", controlCtrl.stored.Enabled)
	}
	if control.localAddressCapacityAlarm != "" {
		t.Fatalf("control: an ordinary failure latched the capacity alarm: %q", control.localAddressCapacityAlarm)
	}
}
