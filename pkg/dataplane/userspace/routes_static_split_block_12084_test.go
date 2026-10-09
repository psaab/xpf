package userspace

import (
	"reflect"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/vishvananda/netlink"
)

func compileSnapshotFoldText(t *testing.T, lenient bool, text string) *config.Config {
	t.Helper()
	root, parseErrs := config.NewParser(text).Parse()
	if len(parseErrs) > 0 {
		t.Fatalf("parse static-route fixture: %v", parseErrs)
	}
	tree := &config.ConfigTree{Children: root.Children}
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

func TestRouteSnapshotsSameSpellingSplitBlocksKeepBaseTiers_12084(t *testing.T) {
	oldRuleList := ruleListFn
	t.Cleanup(func() { ruleListFn = oldRuleList })
	ruleListFn = func(int) ([]netlink.Rule, error) { return nil, nil }

	cases := []struct {
		name        string
		text        string
		sets        []string
		destination string
		family      string
		table       string
		want        []struct {
			preference int
			gateways   []string
		}
	}{
		{
			name: "9125-explicit-default-last",
			text: `routing-options { static {
				route 10.0.0.0/8 { next-hop 192.0.2.1; preference 10; }
				route 10.0.0.0/8 { preference 5; }
			} }`,
			destination: "10.0.0.0/8", family: "inet", table: "inet.0",
			want: []struct {
				preference int
				gateways   []string
			}{{preference: 5, gateways: []string{"192.0.2.1"}}},
		},
		{
			name: "9125-later-next-hop-inherits-prior-preference",
			text: `routing-options { static {
				route 10.1.0.0/16 { next-hop 192.0.2.1; preference 10; }
				route 10.1.0.0/16 { next-hop 192.0.2.2; }
			} }`,
			destination: "10.1.0.0/16", family: "inet", table: "inet.0",
			want: []struct {
				preference int
				gateways   []string
			}{{preference: 10, gateways: []string{"192.0.2.1", "192.0.2.2"}}},
		},
		{
			name: "preference-block-before-next-hop",
			text: `routing-options { static {
				route 10.2.0.0/16 { preference 200; }
				route 10.2.0.0/16 { next-hop 192.0.2.1; }
			} }`,
			destination: "10.2.0.0/16", family: "inet", table: "inet.0",
			want: []struct {
				preference int
				gateways   []string
			}{{preference: 200, gateways: []string{"192.0.2.1"}}},
		},
		{
			name: "preference-block-after-next-hop",
			text: `routing-options { static {
				route 10.3.0.0/16 { next-hop 192.0.2.1; }
				route 10.3.0.0/16 { preference 200; }
			} }`,
			destination: "10.3.0.0/16", family: "inet", table: "inet.0",
			want: []struct {
				preference int
				gateways   []string
			}{{preference: 200, gateways: []string{"192.0.2.1"}}},
		},
		{
			name: "rib-inet0-plus-bare-preference",
			sets: []string{
				"set routing-options rib inet.0 static route 10.5.0.0/16 next-hop 10.0.0.1",
				"set routing-options static route 10.5.0.0/16 preference 200",
			},
			destination: "10.5.0.0/16", family: "inet", table: "inet.0",
			want: []struct {
				preference int
				gateways   []string
			}{{preference: 200, gateways: []string{"10.0.0.1"}}},
		},
		{
			name: "rib-inet0-plus-bare-ecmp",
			sets: []string{
				"set routing-options rib inet.0 static route 10.6.0.0/16 next-hop 10.0.0.1",
				"set routing-options rib inet.0 static route 10.6.0.0/16 preference 200",
				"set routing-options static route 10.6.0.0/16 next-hop 10.0.0.2",
			},
			destination: "10.6.0.0/16", family: "inet", table: "inet.0",
			want: []struct {
				preference int
				gateways   []string
			}{{preference: 200, gateways: []string{"10.0.0.1", "10.0.0.2"}}},
		},
		{
			name: "inet6-split-block",
			text: `routing-options { rib inet6.0 { static {
				route 2001:db8:1::/48 { next-hop 2001:db8::1; preference 200; }
				route 2001:db8:1::/48 { next-hop 2001:db8::2; }
			} } }`,
			destination: "2001:db8:1::/48", family: "inet6", table: "inet6.0",
			want: []struct {
				preference int
				gateways   []string
			}{{preference: 200, gateways: []string{"2001:db8::1", "2001:db8::2"}}},
		},
		{
			name: "same-spelling-alias-interleave",
			text: `routing-options { static {
				route 10.9.0.0/16 { next-hop 192.0.2.1; preference 10; }
				route 10.9.0.1/16 { next-hop 192.0.2.2; preference 200; }
				route 10.9.0.0/16 { next-hop 192.0.2.3; }
			} }`,
			destination: "10.9.0.0/16", family: "inet", table: "inet.0",
			want: []struct {
				preference int
				gateways   []string
			}{{preference: 10, gateways: []string{"192.0.2.1", "192.0.2.3"}},
				{preference: 200, gateways: []string{"192.0.2.2"}}},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var cfg *config.Config
			if tc.text != "" {
				cfg = compileSnapshotFoldText(t, false, tc.text)
			} else {
				cfg = compileSnapshotFoldConfig(t, false, tc.sets...)
			}
			routes, _, err := buildRouteSnapshots(cfg, nil, nil)
			if err != nil {
				t.Fatalf("buildRouteSnapshots: %v", err)
			}
			var got []RouteSnapshot
			for _, route := range routes {
				if route.Destination == tc.destination {
					got = append(got, route)
				}
			}
			if len(got) != len(tc.want) {
				t.Fatalf("snapshot rows = %+v, want %d preference tier(s)", got, len(tc.want))
			}
			for i, want := range tc.want {
				if got[i].Preference != want.preference || got[i].Table != tc.table ||
					got[i].Family != tc.family || !reflect.DeepEqual(got[i].NextHops, want.gateways) {
					t.Fatalf("snapshot tier[%d] = %+v, want preference=%d table=%s family=%s gateways=%v",
						i, got[i], want.preference, tc.table, tc.family, want.gateways)
				}
			}
		})
	}
}

func TestRouteSnapshotSameSpellingNoInstallRemainsExcluded_12084(t *testing.T) {
	oldRuleList := ruleListFn
	t.Cleanup(func() { ruleListFn = oldRuleList })
	ruleListFn = func(int) ([]netlink.Rule, error) { return nil, nil }

	cfg := compileSnapshotFoldText(t, true, `routing-options { static {
		route 10.0.0.0/8 { next-hop 192.0.2.1; }
		route 10.0.0.0/8 { no-install; }
	} }`)
	var route *config.StaticRoute
	for _, candidate := range cfg.RoutingOptions.StaticRoutes {
		if candidate != nil && candidate.Destination == "10.0.0.0/8" {
			route = candidate
			break
		}
	}
	if route == nil || !route.NoInstall {
		t.Fatalf("tolerant split-block route = %+v, want no-install", route)
	}
	if reason := config.StaticRouteExclusions(cfg)[route]; reason != "route has the `no-install` option set" {
		t.Fatalf("tolerant exclusion reason = %q", reason)
	}
	snapshots, _, err := buildRouteSnapshots(cfg, nil, nil)
	if err != nil {
		t.Fatalf("buildRouteSnapshots: %v", err)
	}
	for _, snapshot := range snapshots {
		if snapshot.Destination == route.Destination {
			t.Fatalf("no-install route was published to helper: %+v", snapshot)
		}
	}
}
