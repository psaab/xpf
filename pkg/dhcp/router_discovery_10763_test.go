package dhcp

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/insomniacslk/dhcp/dhcpv6"
	"github.com/mdlayher/ndp"
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
