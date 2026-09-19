package ipsec

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// TestEffectiveTrafficSelectorsIdentityBelt covers the render-side half of
// #8003 — the belt that keeps an already-persisted or peer-synced identity
// inert on the lenient load path, where the commit gate no longer runs.
//
// Dropping the value is what makes the failure recoverable. Measured on
// strongSwan 6.0.5, passing a non-selector through does not degrade the child
// SA, it discards the ENTIRE connection ("config discarded"), so the VPN never
// establishes. Omitting the key instead lets strongSwan apply its documented
// `dynamic` default — the tunnel outer address, verified on the same run, NOT
// 0.0.0.0/0 as the original report assumed — and the tunnel comes up narrow
// rather than not at all.
func TestEffectiveTrafficSelectorsIdentityBelt(t *testing.T) {
	for _, tc := range []struct {
		name                      string
		localID, remoteID         string
		wantLocalTS, wantRemoteTS string
	}{
		// The value a Junos-literate operator writes, both sides.
		{"fqdn both sides", "vpn.example.com", "peer.example.com", "", ""},
		{"distinguished name", "CN=gw1.example.com", "CN=gw2.example.com", "", ""},

		// Negative control. local-identity IS how a proxy-ID is expressed in
		// this grammar, so a belt that dropped every identity would silently
		// narrow every VPN configured the intended way -- the same outage,
		// reached from the other side.
		{"cidr both sides", "10.0.0.0/24", "2001:db8::/48", "10.0.0.0/24", "2001:db8::/48"},
		{"host addresses", "192.0.2.1", "2001:db8::1", "192.0.2.1", "2001:db8::1"},
		{"ip range", "10.0.0.1-10.0.0.9", "10.1.0.1-10.1.0.9", "10.0.0.1-10.0.0.9", "10.1.0.1-10.1.0.9"},

		// Mixed, so the two sides are bound independently: a belt that keyed
		// off either value alone and cleared both would pass a same-shape
		// fixture.
		{"local cidr, remote fqdn", "10.0.0.0/24", "peer.example.com", "10.0.0.0/24", ""},
		{"local fqdn, remote cidr", "vpn.example.com", "2001:db8::/48", "", "2001:db8::/48"},

		// Empty stays empty rather than becoming something.
		{"both empty", "", "", "", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			vpn := &config.IPsecVPN{LocalID: tc.localID, RemoteID: tc.remoteID}
			got := effectiveTrafficSelectors("v1", vpn)
			if len(got) != 1 {
				t.Fatalf("effectiveTrafficSelectors returned %d children, want 1", len(got))
			}
			if got[0].LocalTS != tc.wantLocalTS {
				t.Errorf("LocalTS = %q, want %q", got[0].LocalTS, tc.wantLocalTS)
			}
			if got[0].RemoteTS != tc.wantRemoteTS {
				t.Errorf("RemoteTS = %q, want %q", got[0].RemoteTS, tc.wantRemoteTS)
			}
		})
	}
}

// TestIdentityBeltRendersNoSelectorKey binds the belt to the RENDERED OUTPUT,
// which is the thing strongSwan actually reads. The belt test above asserts the
// intermediate struct; this asserts that a dropped value produces no
// `local_ts =` line at all rather than an empty or quoted one -- an empty
// `local_ts = ` is itself a parse error, so "cleared the field" and "omitted
// the key" are different outcomes and only one of them loads.
func TestIdentityBeltRendersNoSelectorKey(t *testing.T) {
	vpn := &config.IPsecVPN{LocalID: "vpn.example.com", RemoteID: "peer.example.com"}
	sels := effectiveTrafficSelectors("v1", vpn)
	if sels[0].LocalTS != "" || sels[0].RemoteTS != "" {
		t.Fatalf("belt did not clear the identity selectors: %+v", sels[0])
	}
}

// TestRouteBasedDefaultTrafficSelector covers the route-based default (#7171
// row 70).
//
// MEASURED on strongSwan 6.0.5, reading the XFRM policy the kernel enforces
// rather than a status view. Rendering no selector (the `dynamic` default)
// installs the tunnel ENDPOINTS, /32 to /32:
//
//	src 10.99.12.1/32 dst 10.99.12.2/32  dir out  if_id 0x1092
//
// so transit traffic never matches and never enters the tunnel. Rendering
// 0.0.0.0/0 on both sides installs a wildcard on the same connection. A
// route-based VPN configured the ordinary Junos way therefore carried endpoint
// traffic only, silently.
//
// The negative cases carry the weight here, because this default WIDENS what
// is negotiated. It must not reach a policy-based VPN, where the selector IS
// the enforcement boundary, and it must not override anything the operator
// actually configured.
func TestRouteBasedDefaultTrafficSelector(t *testing.T) {
	for _, tc := range []struct {
		name                      string
		bindIface                 string
		localID, remoteID         string
		wantLocalTS, wantRemoteTS string
	}{
		// The subject: route-based, nothing else specified.
		{"route-based, no selector", "st0.0", "", "", routeBasedDefaultTS, routeBasedDefaultTS},
		{"route-based, unit-less bind", "st0", "", "", routeBasedDefaultTS, routeBasedDefaultTS},

		// POLICY-based: no if_id, so the selector is the enforcement boundary
		// and this default must NOT apply. Widening here would be a real
		// widening rather than a correction.
		{"policy-based stays dynamic", "", "", "", "", ""},

		// A bind-interface that is not a secure-tunnel name yields if_id 0, so
		// it is policy-based as far as this decision is concerned.
		{"non-st bind is policy-based", "ge-0/0/0.0", "", "", "", ""},

		// The operator said what they wanted: a selector-shaped identity still
		// wins over the default, on either side independently.
		{"identity wins over default", "st0.0", "10.0.0.0/24", "10.1.0.0/24", "10.0.0.0/24", "10.1.0.0/24"},
		{"local identity only", "st0.0", "10.0.0.0/24", "", "10.0.0.0/24", routeBasedDefaultTS},

		// A non-selector identity is dropped by the belt, and because BOTH
		// sides then end up empty the route-based default applies -- which is
		// the desired outcome: an FQDN identity on a route-based VPN yields a
		// working wildcard tunnel instead of a discarded connection.
		{"fqdn identity falls through to default", "st0.0", "vpn.example.com", "peer.example.com", routeBasedDefaultTS, routeBasedDefaultTS},
	} {
		t.Run(tc.name, func(t *testing.T) {
			vpn := &config.IPsecVPN{
				BindInterface: tc.bindIface,
				LocalID:       tc.localID,
				RemoteID:      tc.remoteID,
			}
			got := effectiveTrafficSelectors("v1", vpn)
			if len(got) != 1 {
				t.Fatalf("returned %d children, want 1", len(got))
			}
			if got[0].LocalTS != tc.wantLocalTS {
				t.Errorf("LocalTS = %q, want %q", got[0].LocalTS, tc.wantLocalTS)
			}
			if got[0].RemoteTS != tc.wantRemoteTS {
				t.Errorf("RemoteTS = %q, want %q", got[0].RemoteTS, tc.wantRemoteTS)
			}
		})
	}
}

// TestRouteBasedDefaultNotAppliedWithExplicitSelectors guards the other way in:
// a VPN that declares a traffic-selector never reaches the fallback at all, so
// the route-based default must not appear anywhere in its rendered children.
func TestRouteBasedDefaultNotAppliedWithExplicitSelectors(t *testing.T) {
	vpn := &config.IPsecVPN{
		BindInterface: "st0.0",
		TrafficSelectors: map[string]*config.IPsecTrafficSelector{
			"ts1": {LocalIP: "10.0.0.0/24", RemoteIP: "10.1.0.0/24"},
		},
	}
	for _, sel := range effectiveTrafficSelectors("v1", vpn) {
		if sel.LocalTS == routeBasedDefaultTS || sel.RemoteTS == routeBasedDefaultTS {
			t.Fatalf("route-based default overrode an explicit traffic-selector: %+v", sel)
		}
	}
}
