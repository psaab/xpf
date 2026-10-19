package daemon

import (
	"net"
	"testing"

	"github.com/vishvananda/netlink"
)

// splitDefaultDst builds a route destination for a split-default (or true
// default) prefix, e.g. "0.0.0.0/1" / "::/0".
func routeDst15220(cidr string) *net.IPNet {
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		panic(err)
	}
	return ipnet
}

// TestIsDefaultRoute15220 pins the pure predicate: only a nil destination or
// an unspecified destination with prefix length 0 is a default route. A
// split-default route (0.0.0.0/1, 128.0.0.0/1, ::/1, ...) carries an
// unspecified or half-space address with a non-zero mask and must NOT qualify.
//
// FAIL-ON-REVERT: reverting to the old unspecified-only check makes the
// split-default rows return true.
func TestIsDefaultRoute15220(t *testing.T) {
	tests := []struct {
		name string
		dst  *net.IPNet
		want bool
	}{
		{"nil-dst", nil, true},
		{"empty-ip", &net.IPNet{}, true},
		{"v4-default", routeDst15220("0.0.0.0/0"), true},
		{"v6-default", routeDst15220("::/0"), true},
		{"v4-split-1", routeDst15220("0.0.0.0/1"), false},
		{"v4-split-128", routeDst15220("128.0.0.0/1"), false},
		{"v6-split-1", routeDst15220("::/1"), false},
		{"v6-split-8000", routeDst15220("8000::/1"), false},
		{"v4-host", routeDst15220("192.0.2.1/32"), false},
		{"v4-subnet", routeDst15220("192.0.2.0/24"), false},
		{"v6-subnet", routeDst15220("2001:db8::/32"), false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := isDefaultRoute(&netlink.Route{Dst: tc.dst}); got != tc.want {
				t.Errorf("isDefaultRoute(Dst=%v) = %v, want %v", tc.dst, got, tc.want)
			}
		})
	}
}

// installDetectSeams15220 stubs the netlink seams detectLifelineInterface
// reads, restoring them on cleanup. linkNames maps LinkIndex -> name.
func installDetectSeams15220(t *testing.T, routes func(family int) []netlink.Route, linkNames map[int]string) {
	t.Helper()
	oldRoute, oldIdx := lifelineRouteList, lifelineLinkByIndex
	t.Cleanup(func() { lifelineRouteList, lifelineLinkByIndex = oldRoute, oldIdx })
	lifelineRouteList = func(_ netlink.Link, family int) ([]netlink.Route, error) {
		return routes(family), nil
	}
	lifelineLinkByIndex = func(idx int) (netlink.Link, error) {
		name, ok := linkNames[idx]
		if !ok {
			name = defaultMgmtInterface
		}
		return &netlink.Device{LinkAttrs: netlink.LinkAttrs{Name: name, Index: idx}}, nil
	}
}

// TestDetectLifelineIgnoresSplitDefault15220 is the selection regression:
// a host whose only "default-looking" routes are split-default VPN routes
// (0.0.0.0/1 + 128.0.0.0/1, and ::/1) has NO default route, so the detector
// must report none — the tunnel NIC must not be chosen as the management
// lifeline.
//
// FAIL-ON-REVERT: the old unspecified-only predicate returns the tunnel NIC
// (ok=true). The netns probe in the issue returns d0 (no lifeline) only with
// the /1 routes present and ignored.
func TestDetectLifelineIgnoresSplitDefault15220(t *testing.T) {
	installDetectSeams15220(t, func(family int) []netlink.Route {
		if family == netlink.FAMILY_V4 {
			return []netlink.Route{
				{Dst: routeDst15220("0.0.0.0/1"), LinkIndex: 9, Gw: net.ParseIP("10.8.0.1")},
				{Dst: routeDst15220("128.0.0.0/1"), LinkIndex: 9, Gw: net.ParseIP("10.8.0.1")},
			}
		}
		return []netlink.Route{
			{Dst: routeDst15220("::/1"), LinkIndex: 9, Gw: net.ParseIP("fd00::1")},
			{Dst: routeDst15220("8000::/1"), LinkIndex: 9, Gw: net.ParseIP("fd00::1")},
		}
	}, map[int]string{9: "tun0"})

	name, ok, err := detectLifelineInterface()
	if err != nil {
		t.Fatalf("split-default-only route table must be a confident none, got err: %v", err)
	}
	if ok || name != "" {
		t.Errorf("split-default routes must NOT select a lifeline: got name=%q ok=%v, want none. "+
			"A 0.0.0.0/1 tunnel was treated as the default route and its NIC admitted as the "+
			"management lifeline (#15220)", name, ok)
	}
}

// TestDetectLifelineSplitDefaultDoesNotShadowRealDefault15220 pins ordering:
// split-default routes listed BEFORE the real default must be skipped, and
// the real default's NIC selected.
//
// FAIL-ON-REVERT: the old predicate returns the first (tunnel) route's NIC.
func TestDetectLifelineSplitDefaultDoesNotShadowRealDefault15220(t *testing.T) {
	installDetectSeams15220(t, func(family int) []netlink.Route {
		if family == netlink.FAMILY_V4 {
			return []netlink.Route{
				{Dst: routeDst15220("0.0.0.0/1"), LinkIndex: 9, Gw: net.ParseIP("10.8.0.1")},
				{Dst: routeDst15220("0.0.0.0/0"), LinkIndex: 2, Gw: net.ParseIP("192.0.2.1")},
			}
		}
		return nil
	}, map[int]string{9: "tun0", 2: "eth-mgmt"})

	name, ok, err := detectLifelineInterface()
	if err != nil || !ok {
		t.Fatalf("a real 0.0.0.0/0 behind a split-default must be found: name=%q ok=%v err=%v", name, ok, err)
	}
	if name != "eth-mgmt" {
		t.Errorf("lifeline = %q, want eth-mgmt (the 0.0.0.0/0 NIC); the split-default tunnel must be skipped (#15220)", name)
	}
}

// TestDetectLifelineTrueDefaultsStillSelect15220 is the legitimate control:
// nil-dst, 0.0.0.0/0 and ::/0 routes still select their NIC, in v4-then-v6
// order. Without it a fix that rejected every route would pass the cells above.
func TestDetectLifelineTrueDefaultsStillSelect15220(t *testing.T) {
	tests := []struct {
		name   string
		routes func(family int) []netlink.Route
		want   string
	}{
		{
			name: "nil-dst-v4",
			routes: func(family int) []netlink.Route {
				if family == netlink.FAMILY_V4 {
					return []netlink.Route{{LinkIndex: 2}}
				}
				return nil
			},
			want: "eth-mgmt",
		},
		{
			name: "v4-zero-zero",
			routes: func(family int) []netlink.Route {
				if family == netlink.FAMILY_V4 {
					return []netlink.Route{{Dst: routeDst15220("0.0.0.0/0"), LinkIndex: 2}}
				}
				return nil
			},
			want: "eth-mgmt",
		},
		{
			name: "v6-zero-zero-only",
			routes: func(family int) []netlink.Route {
				if family == netlink.FAMILY_V6 {
					return []netlink.Route{{Dst: routeDst15220("::/0"), LinkIndex: 3}}
				}
				return nil
			},
			want: "eth6-mgmt",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			installDetectSeams15220(t, tc.routes, map[int]string{2: "eth-mgmt", 3: "eth6-mgmt"})
			name, ok, err := detectLifelineInterface()
			if err != nil || !ok || name != tc.want {
				t.Errorf("true default must select %q: got name=%q ok=%v err=%v", tc.want, name, ok, err)
			}
		})
	}
}

// installSnapshotSeams15220 stubs the seams snapshotLifelineAddrs reads for a
// statically-addressed lifeline NIC.
func installSnapshotSeams15220(t *testing.T, routes func(family int) []netlink.Route) {
	t.Helper()
	oldLink, oldAddr, oldRoute := lifelineLinkByName, lifelineAddrList, lifelineRouteList
	t.Cleanup(func() { lifelineLinkByName, lifelineAddrList, lifelineRouteList = oldLink, oldAddr, oldRoute })
	lifelineLinkByName = func(string) (netlink.Link, error) { return okLink(), nil }
	lifelineAddrList = func(netlink.Link, int) ([]netlink.Addr, error) {
		return []netlink.Addr{
			staticAddr("192.0.2.10/24"),
			staticAddr("2001:db8::10/64"),
		}, nil
	}
	lifelineRouteList = func(_ netlink.Link, family int) ([]netlink.Route, error) {
		return routes(family), nil
	}
}

// TestSnapshotGatewayIgnoresSplitDefault15220 is the gateway-snapshot
// regression (second site): split-default routes on the lifeline NIC must not
// supply the snapshot Gateway=. Only the true /0 gateways may be recorded.
//
// FAIL-ON-REVERT: the old predicate records the tunnel gateways (10.8.0.1 /
// fd00::1) because they appear first.
func TestSnapshotGatewayIgnoresSplitDefault15220(t *testing.T) {
	installSnapshotSeams15220(t, func(family int) []netlink.Route {
		if family == netlink.FAMILY_V4 {
			return []netlink.Route{
				{Dst: routeDst15220("0.0.0.0/1"), Gw: net.ParseIP("10.8.0.1")},
				{Dst: routeDst15220("128.0.0.0/1"), Gw: net.ParseIP("10.8.0.1")},
				{Dst: routeDst15220("0.0.0.0/0"), Gw: net.ParseIP("192.0.2.1")},
			}
		}
		return []netlink.Route{
			{Dst: routeDst15220("::/1"), Gw: net.ParseIP("fd00::1")},
			{Dst: routeDst15220("::/0"), Gw: net.ParseIP("2001:db8::1")},
		}
	})

	snap, err := snapshotLifelineAddrs(defaultMgmtInterface)
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	if snap.gw4 != "192.0.2.1" {
		t.Errorf("gw4 = %q, want 192.0.2.1 (the 0.0.0.0/0 gateway); a split-default tunnel gateway must not be snapshotted (#15220)", snap.gw4)
	}
	if snap.gw6 != "2001:db8::1" {
		t.Errorf("gw6 = %q, want 2001:db8::1 (the ::/0 gateway); a split-default tunnel gateway must not be snapshotted (#15220)", snap.gw6)
	}
}

// TestSnapshotGatewaySplitDefaultOnlyRecordsNone15220: with ONLY split-default
// routes present, no gateway is recorded at all.
//
// FAIL-ON-REVERT: the old predicate records 10.8.0.1 / fd00::1.
func TestSnapshotGatewaySplitDefaultOnlyRecordsNone15220(t *testing.T) {
	installSnapshotSeams15220(t, func(family int) []netlink.Route {
		if family == netlink.FAMILY_V4 {
			return []netlink.Route{{Dst: routeDst15220("0.0.0.0/1"), Gw: net.ParseIP("10.8.0.1")}}
		}
		return []netlink.Route{{Dst: routeDst15220("::/1"), Gw: net.ParseIP("fd00::1")}}
	})

	snap, err := snapshotLifelineAddrs(defaultMgmtInterface)
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	if snap.gw4 != "" || snap.gw6 != "" {
		t.Errorf("split-default-only routes must record no gateway: got gw4=%q gw6=%q (#15220)", snap.gw4, snap.gw6)
	}
}
