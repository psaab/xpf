package frr

import (
	"strings"
	"testing"
)

func TestFRRNextHoplessForwardingActionKeepsItsPreference12084(t *testing.T) {
	cases := []struct {
		name        string
		text        string
		destination string
		want        string
	}{
		{
			name: "v4-discard-action-first",
			text: `routing-options { static {
				route 10.8.0.0/16 { discard; preference 250; }
				route 10.8.0.1/16 { preference 5; }
			} }`,
			destination: "10.8.0.0/16", want: "ip route 10.8.0.0/16 Null0 250\n",
		},
		{
			name: "v4-discard-action-last",
			text: `routing-options { static {
				route 10.8.0.1/16 { preference 5; }
				route 10.8.0.0/16 { discard; preference 250; }
			} }`,
			destination: "10.8.0.1/16", want: "ip route 10.8.0.1/16 Null0 250\n",
		},
		{
			name: "v6-cross-rib",
			text: `routing-options { static { route 2001:db8:8::/48 { discard; preference 250; } }
				rib inet6.0 { static { route 2001:db8:8::/48 { preference 5; } } } }`,
			destination: "2001:db8:8::/48", want: "ipv6 route 2001:db8:8::/48 Null0 250\n",
		},
		{
			name: "reject",
			text: `routing-options { static {
				route 10.11.0.0/16 { reject; preference 250; }
				route 10.11.0.1/16 { preference 5; }
			} }`,
			destination: "10.11.0.0/16", want: "ip route 10.11.0.0/16 reject 250\n",
		},
		{
			name: "discard-default-beats-preference-only-alias",
			text: `routing-options { static {
				route 10.13.0.0/16 { preference 2; }
				route 10.13.0.1/16 { discard; }
			} }`,
			destination: "10.13.0.0/16", want: "ip route 10.13.0.0/16 Null0 5\n",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := compileFoldText(t, false, tc.text)
			route := routeFromFoldConfig(t, cfg, tc.destination)
			got := New().generateStaticRoute(route, "", nil, nil, nil)
			if !strings.Contains(got, tc.want) {
				t.Fatalf("rendered route = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestFRRTolerantNoInstallConflictInstallsOnlyInstallableNextHops12084(t *testing.T) {
	cases := []struct {
		name string
		text string
	}{
		{
			name: "installable-first",
			text: `routing-options { static { route 2001:db8:2::/48 { next-hop 2001:db8::1; } }
				rib inet6.0 { static { route 2001:db8:2::/48 { next-hop 2001:db8::2; no-install; } } } }`,
		},
		{
			name: "no-install-first",
			text: `routing-options { static { route 2001:db8:2::/48 { next-hop 2001:db8::2; no-install; } }
				rib inet6.0 { static { route 2001:db8:2::/48 { next-hop 2001:db8::1; } } } }`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := compileFoldText(t, true, tc.text)
			route := routeFromFoldConfig(t, cfg, "2001:db8:2::/48")
			got := New().generateStaticRoute(route, "", nil, nil, nil)
			if !strings.Contains(got, "ipv6 route 2001:db8:2::/48 2001:db8::1 5\n") ||
				strings.Contains(got, "2001:db8::2") {
				t.Fatalf("tolerant FRR route = %q, want only installable gateway ::1", got)
			}
		})
	}
}
