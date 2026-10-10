package frr

import (
	"strings"
	"testing"
)

func TestFRRTolerantNoInstallConflictKeepsInstallableActions12084(t *testing.T) {
	cases := []struct {
		name string
		text string
		dest string
		want string
		bad  []string
	}{
		{
			name: "discard-noinstall-after-hop",
			text: `routing-options { static {
				route 10.20.0.0/16 { next-hop 192.0.2.1; }
				route 10.20.0.1/16 { discard; no-install; }
			} }`,
			dest: "10.20.0.0/16", want: "ip route 10.20.0.0/16 192.0.2.1 5\n", bad: []string{"Null0", "reject"},
		},
		{
			name: "discard-noinstall-before-hop",
			text: `routing-options { static {
				route 10.20.0.1/16 { discard; no-install; }
				route 10.20.0.0/16 { next-hop 192.0.2.1; }
			} }`,
			dest: "10.20.0.1/16", want: "192.0.2.1 5\n", bad: []string{"Null0", "reject"},
		},
		{
			name: "reject-noinstall-after-hop",
			text: `routing-options { static {
				route 10.21.0.0/16 { next-hop 192.0.2.1; }
				route 10.21.0.1/16 { reject; no-install; }
			} }`,
			dest: "10.21.0.0/16", want: "ip route 10.21.0.0/16 192.0.2.1 5\n", bad: []string{"Null0", "reject"},
		},
		{
			name: "reject-noinstall-before-hop",
			text: `routing-options { static {
				route 10.21.0.1/16 { reject; no-install; }
				route 10.21.0.0/16 { next-hop 192.0.2.1; }
			} }`,
			dest: "10.21.0.1/16", want: "192.0.2.1 5\n", bad: []string{"Null0", "reject"},
		},
		{
			name: "nexttable-noinstall-after-hop",
			text: `interfaces { ge-0/0/0 { unit 0; } }
				routing-instances { blue { instance-type virtual-router; } }
				routing-options { static {
				route 10.22.0.0/16 { next-hop 192.0.2.1; }
				route 10.22.0.1/16 { next-table blue.inet.0; no-install; }
			} }`,
			dest: "10.22.0.0/16", want: "ip route 10.22.0.0/16 192.0.2.1 5\n",
		},
		{
			name: "nexttable-noinstall-before-hop",
			text: `interfaces { ge-0/0/0 { unit 0; } }
				routing-instances { blue { instance-type virtual-router; } }
				routing-options { static {
				route 10.22.0.1/16 { next-table blue.inet.0; no-install; }
				route 10.22.0.0/16 { next-hop 192.0.2.1; }
			} }`,
			dest: "10.22.0.1/16", want: "192.0.2.1 5\n",
		},
		{
			name: "discard-preference-does-not-inherit-noinstall-five",
			text: `routing-options { static {
				route 10.23.0.0/16 { discard; preference 250; }
				route 10.23.0.1/16 { discard; no-install; preference 5; }
			} }`,
			dest: "10.23.0.0/16", want: "ip route 10.23.0.0/16 Null0 250\n", bad: []string{"Null0 5"},
		},
		{
			name: "discard-preference-noinstall-first",
			text: `routing-options { static {
				route 10.23.0.1/16 { discard; no-install; preference 5; }
				route 10.23.0.0/16 { discard; preference 250; }
			} }`,
			dest: "10.23.0.1/16", want: "Null0 250\n", bad: []string{"Null0 5"},
		},
		{
			name: "v6-cross-rib-discard-noinstall-after-hop",
			text: `routing-options { static { route 2001:db8:60::/48 { next-hop 2001:db8::1; } }
				rib inet6.0 { static { route 2001:db8:60::/48 { discard; no-install; } } } }`,
			dest: "2001:db8:60::/48", want: "ipv6 route 2001:db8:60::/48 2001:db8::1 5\n", bad: []string{"Null0", "reject"},
		},
		{
			name: "v6-cross-rib-discard-noinstall-before-hop",
			text: `routing-options { static { route 2001:db8:60::/48 { discard; no-install; } }
				rib inet6.0 { static { route 2001:db8:60::/48 { next-hop 2001:db8::1; } } } }`,
			dest: "2001:db8:60::/48", want: "ipv6 route 2001:db8:60::/48 2001:db8::1 5\n", bad: []string{"Null0", "reject"},
		},
		{
			name: "default-route-discard-noinstall-does-not-blackhole-gateway",
			text: `routing-options { static {
				route 0.0.0.0/0 { next-hop 192.0.2.1; }
				route 0.0.0.1/0 { discard; no-install; }
			} }`,
			dest: "0.0.0.0/0", want: "ip route 0.0.0.0/0 192.0.2.1 5\n", bad: []string{"Null0", "reject"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := compileFoldText(t, true, tc.text)
			got := New().generateStaticRoute(routeFromFoldConfig(t, cfg, tc.dest), "", nil, nil, nil)
			if !strings.Contains(got, tc.want) {
				t.Fatalf("tolerant FRR route = %q, want %q", got, tc.want)
			}
			for _, bad := range tc.bad {
				if strings.Contains(got, bad) {
					t.Errorf("tolerant FRR route = %q, must not contain %q", got, bad)
				}
			}
		})
	}
}

func TestFRRTolerantNoInstallDefaultRouteKeepsGatewayInManagedSection12084(t *testing.T) {
	cfg := compileFoldText(t, true, `routing-options { static {
		route 0.0.0.0/0 { next-hop 192.0.2.1; }
		route 0.0.0.1/0 { discard; no-install; }
	} }`)
	got := New().buildManagedSection(&FullConfig{
		StaticRoutes: cfg.RoutingOptions.StaticRoutes,
		DHCPRoutes:   []DHCPRoute{{Gateway: "192.0.2.254"}},
	})
	if !strings.Contains(got, "ip route 0.0.0.0/0 192.0.2.1 5\n") || strings.Contains(got, "Null0") {
		t.Fatalf("managed default-route section = %q, want forwarding static gateway, not no-install discard", got)
	}
}
