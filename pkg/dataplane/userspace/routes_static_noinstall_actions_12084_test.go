package userspace

import (
	"reflect"
	"testing"
)

func TestRouteSnapshotsTolerantNoInstallConflictKeepsInstallableActions12084(t *testing.T) {
	cases := []struct {
		name        string
		text        string
		destination string
		family      string
		gateway     string
		preference  int
		discard     bool
	}{
		{
			name: "discard-noinstall-after-hop",
			text: `routing-options { static {
				route 10.20.0.0/16 { next-hop 192.0.2.1; }
				route 10.20.0.1/16 { discard; no-install; }
			} }`,
			destination: "10.20.0.0/16", family: "inet", gateway: "192.0.2.1", preference: 5,
		},
		{
			name: "discard-noinstall-before-hop",
			text: `routing-options { static {
				route 10.20.0.1/16 { discard; no-install; }
				route 10.20.0.0/16 { next-hop 192.0.2.1; }
			} }`,
			destination: "10.20.0.1/16", family: "inet", gateway: "192.0.2.1", preference: 5,
		},
		{
			name: "reject-noinstall-after-hop",
			text: `routing-options { static {
				route 10.21.0.0/16 { next-hop 192.0.2.1; }
				route 10.21.0.1/16 { reject; no-install; }
			} }`,
			destination: "10.21.0.0/16", family: "inet", gateway: "192.0.2.1", preference: 5,
		},
		{
			name: "reject-noinstall-before-hop",
			text: `routing-options { static {
				route 10.21.0.1/16 { reject; no-install; }
				route 10.21.0.0/16 { next-hop 192.0.2.1; }
			} }`,
			destination: "10.21.0.1/16", family: "inet", gateway: "192.0.2.1", preference: 5,
		},
		{
			name: "nexttable-noinstall-after-hop",
			text: `interfaces { ge-0/0/0 { unit 0; } }
				routing-instances { blue { instance-type virtual-router; } }
				routing-options { static {
				route 10.22.0.0/16 { next-hop 192.0.2.1; }
				route 10.22.0.1/16 { next-table blue.inet.0; no-install; }
			} }`,
			destination: "10.22.0.0/16", family: "inet", gateway: "192.0.2.1", preference: 5,
		},
		{
			name: "nexttable-noinstall-before-hop",
			text: `interfaces { ge-0/0/0 { unit 0; } }
				routing-instances { blue { instance-type virtual-router; } }
				routing-options { static {
				route 10.22.0.1/16 { next-table blue.inet.0; no-install; }
				route 10.22.0.0/16 { next-hop 192.0.2.1; }
			} }`,
			destination: "10.22.0.1/16", family: "inet", gateway: "192.0.2.1", preference: 5,
		},
		{
			name: "discard-preference-noinstall-after",
			text: `routing-options { static {
				route 10.23.0.0/16 { discard; preference 250; }
				route 10.23.0.1/16 { discard; no-install; preference 5; }
			} }`,
			destination: "10.23.0.0/16", family: "inet", preference: 250, discard: true,
		},
		{
			name: "discard-preference-noinstall-before",
			text: `routing-options { static {
				route 10.23.0.1/16 { discard; no-install; preference 5; }
				route 10.23.0.0/16 { discard; preference 250; }
			} }`,
			destination: "10.23.0.1/16", family: "inet", preference: 250, discard: true,
		},
		{
			name: "v6-cross-rib-noinstall-after-hop",
			text: `routing-options { static { route 2001:db8:60::/48 { next-hop 2001:db8::1; } }
				rib inet6.0 { static { route 2001:db8:60::/48 { discard; no-install; } } } }`,
			destination: "2001:db8:60::/48", family: "inet6", gateway: "2001:db8::1", preference: 5,
		},
		{
			name: "v6-cross-rib-noinstall-before-hop",
			text: `routing-options { static { route 2001:db8:60::/48 { discard; no-install; } }
				rib inet6.0 { static { route 2001:db8:60::/48 { next-hop 2001:db8::1; } } } }`,
			destination: "2001:db8:60::/48", family: "inet6", gateway: "2001:db8::1", preference: 5,
		},
		{
			name: "default-route-discard-noinstall",
			text: `routing-options { static {
				route 0.0.0.0/0 { next-hop 192.0.2.1; }
				route 0.0.0.1/0 { discard; no-install; }
			} }`,
			destination: "0.0.0.0/0", family: "inet", gateway: "192.0.2.1", preference: 5,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := compileSnapshotFoldText(t, true, tc.text)
			rows := routeSnapshotsForDestination12084(t, cfg, tc.destination)
			if len(rows) != 1 {
				t.Fatalf("snapshot rows = %+v, want one installable route", rows)
			}
			row := rows[0]
			var wantHops []string
			if tc.gateway != "" {
				wantHops = []string{tc.gateway}
			}
			if row.Family != tc.family || row.Discard != tc.discard || row.NextTable != "" || row.Preference != tc.preference ||
				!reflect.DeepEqual(row.NextHops, wantHops) {
				t.Fatalf("tolerant snapshot = %+v, want family=%s discard=%v next-table empty pref=%d hops=%v",
					row, tc.family, tc.discard, tc.preference, wantHops)
			}
		})
	}
}
