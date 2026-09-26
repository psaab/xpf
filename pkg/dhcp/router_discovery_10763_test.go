package dhcp

import (
	"bytes"
	"context"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/insomniacslk/dhcp/dhcpv6"
	"github.com/mdlayher/ndp"
	"golang.org/x/net/ipv6"
)

// TestParseV6ReplyUsesSolicitedRouterAdvertisements10763 is a RED-on-revert
// guard: parseV6Reply must solicit and choose an advertised default router by
// RFC 4191 preference, ignoring router-lifetime-0 advertisers. The former
// neighbor-table scan did not invoke the RA exchange and left Gateway empty
// for this test Manager (or could select the lifetime-0 neighbour in service).
func TestParseV6ReplyUsesSolicitedRouterAdvertisements10763(t *testing.T) {
	called := false
	m := &Manager{
		routerAdvertisementsForTest: func(_ context.Context, iface string) []observedRouter {
			called = true
			if iface != "wan0" {
				t.Errorf("router solicitation interface = %q, want wan0", iface)
			}
			return []observedRouter{
				{addr: netip.MustParseAddr("fe80::1"), lifetime: 0, pref: raPrefHigh},
				{addr: netip.MustParseAddr("fe80::2"), lifetime: time.Hour, pref: raPrefMedium},
				{addr: netip.MustParseAddr("fe80::3"), lifetime: time.Second, pref: raPrefHigh},
			}
		},
	}
	adv := iaNAReply(t, &dhcpv6.OptIAAddress{
		IPv6Addr:          mustIP(t, "2001:db8::10"),
		PreferredLifetime: time.Hour,
		ValidLifetime:     2 * time.Hour,
	})
	res, err := m.parseV6Reply(context.Background(), "wan0", adv, nil)
	if err != nil {
		t.Fatalf("parseV6Reply: %v", err)
	}
	if !called {
		t.Fatal("DHCPv6 reply did not trigger Router Solicitation/RA discovery")
	}
	if got, want := res.lease.Gateway, netip.MustParseAddr("fe80::3"); got != want {
		t.Errorf("lease gateway = %v, want highest-preference eligible RA source %v", got, want)
	}
}

func TestParseV6ReplyDoesNotUseLifetimeZeroRouter10763(t *testing.T) {
	m := &Manager{
		routerAdvertisementsForTest: func(context.Context, string) []observedRouter {
			return []observedRouter{{addr: netip.MustParseAddr("fe80::1"), lifetime: 0, pref: raPrefHigh}}
		},
	}
	adv := iaNAReply(t, &dhcpv6.OptIAAddress{
		IPv6Addr:          mustIP(t, "2001:db8::10"),
		PreferredLifetime: time.Hour,
		ValidLifetime:     2 * time.Hour,
	})
	res, err := m.parseV6Reply(context.Background(), "wan0", adv, nil)
	if err != nil {
		t.Fatalf("parseV6Reply: %v", err)
	}
	if res.lease.Gateway.IsValid() {
		t.Errorf("lease gateway = %v, want none: lifetime-0 RA is not a default router", res.lease.Gateway)
	}
}
func TestRouterPreferenceRank10763(t *testing.T) {
	for _, tc := range []struct {
		pref ndp.Preference
		want int
	}{
		{ndp.Low, raPrefLow},
		{ndp.Medium, raPrefMedium},
		{ndp.High, raPrefHigh},
	} {
		if got := raPreferenceRank(tc.pref); got != tc.want {
			t.Errorf("raPreferenceRank(%v) = %d, want %d", tc.pref, got, tc.want)
		}
	}
}

type routerAdvertisementRead struct {
	message ndp.Message
	cm      *ipv6.ControlMessage
	source  netip.Addr
}

type fakeRouterDiscoveryConn struct {
	reads        []routerAdvertisementRead
	onRead       func()
	groups       []netip.Addr
	writes       []ndp.Message
	destinations []netip.Addr
}

func (c *fakeRouterDiscoveryConn) SetICMPFilter(*ipv6.ICMPFilter) error { return nil }
func (c *fakeRouterDiscoveryConn) SetControlMessage(ipv6.ControlFlags, bool) error {
	return nil
}
func (c *fakeRouterDiscoveryConn) JoinGroup(group netip.Addr) error {
	c.groups = append(c.groups, group)
	return nil
}
func (c *fakeRouterDiscoveryConn) WriteTo(msg ndp.Message, _ *ipv6.ControlMessage, dst netip.Addr) error {
	c.writes = append(c.writes, msg)
	c.destinations = append(c.destinations, dst)
	return nil
}
func (*fakeRouterDiscoveryConn) SetReadDeadline(time.Time) error { return nil }
func (c *fakeRouterDiscoveryConn) ReadFrom() (ndp.Message, *ipv6.ControlMessage, netip.Addr, error) {
	read := c.reads[0]
	c.reads = c.reads[1:]
	if c.onRead != nil {
		c.onRead()
	}
	return read.message, read.cm, read.source, nil
}

func TestCollectRouterAdvertisementsSolicitsAndSelects10763(t *testing.T) {
	ifi := &net.Interface{
		Name:         "wan0",
		Index:        7,
		HardwareAddr: net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x07},
	}
	cm := &ipv6.ControlMessage{IfIndex: ifi.Index, HopLimit: ndp.HopLimit}
	conn := &fakeRouterDiscoveryConn{reads: []routerAdvertisementRead{
		{message: &ndp.RouterAdvertisement{RouterLifetime: 0, RouterSelectionPreference: ndp.High}, cm: cm, source: netip.MustParseAddr("fe80::1%wan0")},
		{message: &ndp.RouterAdvertisement{RouterLifetime: time.Hour, RouterSelectionPreference: ndp.Medium}, cm: cm, source: netip.MustParseAddr("fe80::2%wan0")},
		{message: &ndp.RouterAdvertisement{RouterLifetime: time.Second, RouterSelectionPreference: ndp.High}, cm: cm, source: netip.MustParseAddr("fe80::3%wan0")},
	}}
	routers := collectRouterAdvertisements(context.Background(), ifi, conn)
	if len(conn.writes) != 1 {
		t.Fatalf("Router Solicitations sent = %d, want 1", len(conn.writes))
	}
	rs, ok := conn.writes[0].(*ndp.RouterSolicitation)
	if !ok {
		t.Fatalf("sent message = %T, want Router Solicitation", conn.writes[0])
	}
	if len(rs.Options) != 1 {
		t.Fatalf("Router Solicitation options = %v, want source link-layer address", rs.Options)
	}
	lla, ok := rs.Options[0].(*ndp.LinkLayerAddress)
	if !ok || lla.Direction != ndp.Source || !bytes.Equal(lla.Addr, ifi.HardwareAddr) {
		t.Fatalf("Router Solicitation source link-layer option = %#v, want %v", rs.Options[0], ifi.HardwareAddr)
	}
	if got, want := conn.destinations[0], netip.MustParseAddr("ff02::2"); got != want {
		t.Errorf("Router Solicitation destination = %v, want %v", got, want)
	}
	if len(conn.groups) != 1 || conn.groups[0] != netip.MustParseAddr("ff02::1") {
		t.Errorf("joined groups = %v, want all-nodes ff02::1", conn.groups)
	}
	if got, want := selectRAObservedRouter(routers), netip.MustParseAddr("fe80::3"); got != want {
		t.Errorf("selected gateway = %v, want highest-preference eligible router %v", got, want)
	}
}

func TestCollectRouterAdvertisementsRejectsLifetimeZero10763(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ifi := &net.Interface{Name: "wan0", Index: 7}
	conn := &fakeRouterDiscoveryConn{
		reads: []routerAdvertisementRead{{
			message: &ndp.RouterAdvertisement{RouterLifetime: 0, RouterSelectionPreference: ndp.High},
			cm:      &ipv6.ControlMessage{IfIndex: ifi.Index, HopLimit: ndp.HopLimit},
			source:  netip.MustParseAddr("fe80::1%wan0"),
		}},
		onRead: cancel,
	}
	routers := collectRouterAdvertisements(ctx, ifi, conn)
	if got := selectRAObservedRouter(routers); got.IsValid() {
		t.Errorf("selected gateway = %v, want none for lifetime-0 RA", got)
	}
}
