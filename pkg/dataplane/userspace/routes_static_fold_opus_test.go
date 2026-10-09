package userspace

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/vishvananda/netlink"
)

func compileSnapshotFoldConfig(t *testing.T, lenient bool, sets ...string) *config.Config {
	t.Helper()
	tree := &config.ConfigTree{}
	for _, set := range sets {
		path, err := config.ParseSetCommand(set)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", set, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", set, err)
		}
	}
	var (
		cfg *config.Config
		err error
	)
	if lenient {
		cfg, err = config.CompileConfigLenient(tree)
	} else {
		cfg, err = config.CompileConfig(tree)
	}
	if err != nil {
		t.Fatalf("compile static-route fixture: %v", err)
	}
	return cfg
}

func TestRouteSnapshotsPreserveFoldPreferenceTiers_12084(t *testing.T) {
	oldRuleList := ruleListFn
	t.Cleanup(func() { ruleListFn = oldRuleList })
	ruleListFn = func(int) ([]netlink.Rule, error) { return nil, nil }

	cases := []struct {
		name        string
		sets        []string
		destination string
		table       string
		family      string
		gateways    []string
	}{
		{
			name: "cross-rib-floating-static",
			sets: []string{
				"set routing-options static route 2001:db8:1::/48 next-hop 2001:db8::1",
				"set routing-options static route 2001:db8:1::/48 preference 5",
				"set routing-options rib inet6.0 static route 2001:db8:1::/48 next-hop 2001:db8::2",
				"set routing-options rib inet6.0 static route 2001:db8:1::/48 preference 200",
			},
			destination: "2001:db8:1::/48",
			table:       "inet6.0",
			family:      "inet6",
			gateways:    []string{"2001:db8::1", "2001:db8::2"},
		},
		{
			name: "same-list-alias-floating-static",
			sets: []string{
				"set routing-options static route 10.2.0.0/16 next-hop 10.0.0.1",
				"set routing-options static route 10.2.0.0/16 preference 5",
				"set routing-options static route 10.2.0.1/16 next-hop 10.0.0.2",
				"set routing-options static route 10.2.0.1/16 preference 200",
			},
			destination: "10.2.0.0/16",
			table:       "inet.0",
			family:      "inet",
			gateways:    []string{"10.0.0.1", "10.0.0.2"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := compileSnapshotFoldConfig(t, false, tc.sets...)
			routes, _, err := buildRouteSnapshots(cfg, nil, nil)
			if err != nil {
				t.Fatalf("buildRouteSnapshots: %v", err)
			}
			var rows []RouteSnapshot
			for _, route := range routes {
				if route.Destination == tc.destination {
					rows = append(rows, route)
				}
			}
			if len(rows) != 2 {
				t.Fatalf("snapshot rows = %+v, want separate preference 5 and 200 rows", rows)
			}
			for i, preference := range []int{5, 200} {
				if rows[i].Preference != preference || rows[i].Table != tc.table ||
					rows[i].Family != tc.family || len(rows[i].NextHops) != 1 ||
					rows[i].NextHops[0] != tc.gateways[i] {
					t.Fatalf("snapshot row[%d] = %+v, want pref=%d table=%s family=%s next-hop=%s",
						i, rows[i], preference, tc.table, tc.family, tc.gateways[i])
				}
			}
		})
	}
}

func TestRouteSnapshotNoInstallConflictDoesNotWithdrawInstalledSource_12084(t *testing.T) {
	oldRuleList := ruleListFn
	t.Cleanup(func() { ruleListFn = oldRuleList })
	ruleListFn = func(int) ([]netlink.Rule, error) { return nil, nil }

	cfg := compileSnapshotFoldConfig(t, true,
		"set routing-options static route 2001:db8:2::/48 next-hop 2001:db8::1",
		"set routing-options rib inet6.0 static route 2001:db8:2::/48 next-hop 2001:db8::1 no-install",
	)
	routes, _, err := buildRouteSnapshots(cfg, nil, nil)
	if err != nil {
		t.Fatalf("buildRouteSnapshots: %v", err)
	}
	for _, route := range routes {
		if route.Destination == "2001:db8:2::/48" && route.Table == "inet6.0" &&
			route.Family == "inet6" && route.Preference == 5 && len(route.NextHops) > 0 {
			return
		}
	}
	t.Fatalf("installed source route was withdrawn from helper snapshot: %+v", routes)
}
