package userspace

import (
	"reflect"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/vishvananda/netlink"
)

func routeSnapshotsForDestination12084(t *testing.T, cfg *config.Config, destination string) []RouteSnapshot {
	t.Helper()
	oldRuleList := ruleListFn
	t.Cleanup(func() { ruleListFn = oldRuleList })
	ruleListFn = func(int) ([]netlink.Rule, error) { return nil, nil }
	routes, _, err := buildRouteSnapshots(cfg, nil, nil)
	if err != nil {
		t.Fatalf("buildRouteSnapshots: %v", err)
	}
	var rows []RouteSnapshot
	for _, route := range routes {
		if route.Destination == destination {
			rows = append(rows, route)
		}
	}
	return rows
}

func TestRouteSnapshotsKeepActionPreferenceAgainstActionlessAliases12084(t *testing.T) {
	cases := []struct {
		name        string
		text        string
		destination string
		preference  int
		discard     bool
		nextTable   string
	}{
		{
			name: "v4-discard",
			text: `routing-options { static { route 10.8.0.0/16 { discard; preference 250; }
				route 10.8.0.1/16 { preference 5; } } }`,
			destination: "10.8.0.0/16", preference: 250, discard: true,
		},
		{
			name: "v6-cross-rib",
			text: `routing-options { static { route 2001:db8:8::/48 { discard; preference 250; } }
				rib inet6.0 { static { route 2001:db8:8::/48 { preference 5; } } } }`,
			destination: "2001:db8:8::/48", preference: 250, discard: true,
		},
		{
			name: "reject",
			text: `routing-options { static { route 10.11.0.0/16 { reject; preference 250; }
				route 10.11.0.1/16 { preference 5; } } }`,
			destination: "10.11.0.0/16", preference: 250, discard: true,
		},
		{
			name: "next-table",
			text: `interfaces { ge-0/0/0 { unit 0; } }
				routing-instances { blue { instance-type virtual-router; } }
				routing-options { static { route 10.12.0.0/16 { next-table blue.inet.0; preference 250; }
				route 10.12.0.1/16 { preference 5; } } }`,
			destination: "10.12.0.0/16", preference: 250, nextTable: "blue",
		},
		{
			name: "discard-default",
			text: `routing-options { static { route 10.13.0.0/16 { preference 2; }
				route 10.13.0.1/16 { discard; } } }`,
			destination: "10.13.0.0/16", preference: 5, discard: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root, parseErrs := config.NewParser(tc.text).Parse()
			if len(parseErrs) != 0 {
				t.Fatalf("parse: %v", parseErrs)
			}
			cfg, err := config.CompileConfig(&config.ConfigTree{Children: root.Children})
			if err != nil {
				t.Fatalf("CompileConfig: %v", err)
			}
			rows := routeSnapshotsForDestination12084(t, cfg, tc.destination)
			if len(rows) != 1 {
				t.Fatalf("snapshot rows = %+v, want exactly one route", rows)
			}
			if rows[0].Preference != tc.preference || rows[0].Discard != tc.discard || rows[0].NextTable != tc.nextTable {
				t.Fatalf("snapshot = %+v, want pref=%d discard=%v next-table=%q", rows[0], tc.preference, tc.discard, tc.nextTable)
			}
		})
	}
}

func TestRouteSnapshotsTolerantNoInstallConflictKeepsInstallableHops12084(t *testing.T) {
	cases := []struct {
		name        string
		sets        []string
		destination string
		family      string
		preference  int
		gateway     string
	}{
		{
			name: "ipv6-installable-first",
			sets: []string{
				"set routing-options static route 2001:db8:2::/48 next-hop 2001:db8::1",
				"set routing-options rib inet6.0 static route 2001:db8:2::/48 next-hop 2001:db8::2 no-install",
			},
			destination: "2001:db8:2::/48", family: "inet6", preference: 5, gateway: "2001:db8::1",
		},
		{
			name: "ipv6-no-install-first",
			sets: []string{
				"set routing-options rib inet6.0 static route 2001:db8:2::/48 next-hop 2001:db8::2 no-install",
				"set routing-options static route 2001:db8:2::/48 next-hop 2001:db8::1",
			},
			destination: "2001:db8:2::/48", family: "inet6", preference: 5, gateway: "2001:db8::1",
		},
		{
			name: "ipv4-installable-first",
			sets: []string{
				"set routing-options static route 10.2.0.0/16 next-hop 10.0.0.1 preference 200",
				"set routing-options static route 10.2.0.1/16 next-hop 10.0.0.2 no-install",
			},
			destination: "10.2.0.0/16", family: "inet", preference: 200, gateway: "10.0.0.1",
		},
		{
			name: "ipv4-no-install-first",
			sets: []string{
				"set routing-options static route 10.2.0.1/16 next-hop 10.0.0.2 no-install",
				"set routing-options static route 10.2.0.0/16 next-hop 10.0.0.1 preference 200",
			},
			destination: "10.2.0.1/16", family: "inet", preference: 200, gateway: "10.0.0.1",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := compileSnapshotFoldConfig(t, true, tc.sets...)
			rows := routeSnapshotsForDestination12084(t, cfg, tc.destination)
			if len(rows) != 1 || rows[0].Family != tc.family || rows[0].Preference != tc.preference ||
				!reflect.DeepEqual(rows[0].NextHops, []string{tc.gateway}) {
				t.Fatalf("tolerant snapshots = %+v, want one pref=%d route with only %s", rows, tc.preference, tc.gateway)
			}
		})
	}
}
