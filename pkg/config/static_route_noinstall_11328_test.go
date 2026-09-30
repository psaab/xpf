package config

import (
	"reflect"
	"testing"
)

func TestCompileStaticRouteNoInstall11328(t *testing.T) {
	tests := []struct {
		name string
		sets []string
		hier string
		want []string
	}{
		{
			name: "single gateway inline",
			sets: []string{"set routing-options static route 10.99.0.0/16 next-hop 10.0.0.1 no-install"},
			want: []string{"10.0.0.1"},
		},
		{
			name: "single-line inline ECMP",
			sets: []string{"set routing-options static route 10.99.0.0/16 next-hop [ 10.0.0.1 10.0.0.2 ] no-install"},
			want: []string{"10.0.0.1", "10.0.0.2"},
		},
		{
			name: "separate set statements",
			sets: []string{
				"set routing-options static route 10.99.0.0/16 next-hop 10.0.0.1",
				"set routing-options static route 10.99.0.0/16 no-install",
			},
			want: []string{"10.0.0.1"},
		},
		{
			name: "hierarchical child",
			hier: `routing-options {
				static {
					route 10.99.0.0/16 {
						next-hop 10.0.0.1;
						no-install;
					}
				}
			}`,
			want: []string{"10.0.0.1"},
		},
		{
			name: "hierarchical inline",
			hier: `routing-options {
				static {
					route 10.99.0.0/16 next-hop 10.0.0.1 no-install;
				}
			}`,
			want: []string{"10.0.0.1"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var c *Config
			if tc.hier != "" {
				c = compileHier3881(t, tc.hier)
			} else {
				c = compileSets3870(t, tc.sets)
			}
			if len(c.Warnings) != 0 {
				t.Fatalf("warnings = %v, want none", c.Warnings)
			}
			r := findStaticRoute3871(t, c.RoutingOptions.StaticRoutes, "10.99.0.0/16")
			if !r.NoInstall {
				t.Fatal("NoInstall=false, want true")
			}
			var got []string
			for _, nh := range r.NextHops {
				got = append(got, nh.Address)
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("next-hop addresses = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestStaticRouteNoInstallIsStickyAcrossMergedBlocks11328(t *testing.T) {
	c := compileSets3870(t, []string{
		"set routing-options static route 10.99.0.0/16 no-install",
		"set routing-options static route 10.99.0.0/16 next-hop 10.0.0.1",
	})
	r := findStaticRoute3871(t, c.RoutingOptions.StaticRoutes, "10.99.0.0/16")
	if !r.NoInstall || len(r.NextHops) != 1 || r.NextHops[0].Address != "10.0.0.1" {
		t.Fatalf("merged route = %+v, want no-install plus only the configured gateway", r)
	}
}

func TestNoInstallNextTableDoesNotConsumeWindowCount11328(t *testing.T) {
	cfg := &Config{}
	cfg.RoutingOptions.StaticRoutes = []*StaticRoute{
		{Destination: "10.99.0.0/16", NextTable: "blue", NoInstall: true},
		{Destination: "10.100.0.0/16", NextTable: "blue"},
	}
	if got := nextTableRouteCount(cfg); got != 1 {
		t.Fatalf("next-table route count = %d, want only the installable route", got)
	}
}
