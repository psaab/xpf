package config

import (
	"reflect"
	"testing"
)

// TestUnnamedRoutingContainersPreserveTypedStateAt12043Sites retains the three
// original #12043 behavioral fixtures. Global routing-options static is now
// folded by the broader #12120 "any" registration, so only the two
// instance-scope sites remain in the #12043 registry.
func TestUnnamedRoutingContainersPreserveTypedStateAt12043Sites(t *testing.T) {
	cases := []struct {
		name      string
		site      string
		dup       string
		merged    string
		read      func(*Config) any
		populated func(any) bool
	}{
		{
			name: "routing-options static",
			site: "",
			dup: `routing-options {
				static { route 10.10.0.0/16 { next-hop 192.0.2.1; } }
				static { route 192.0.2.0/24 { next-hop 192.0.2.2; } }
			}`,
			merged: `routing-options {
				static {
					route 10.10.0.0/16 { next-hop 192.0.2.1; }
					route 192.0.2.0/24 { next-hop 192.0.2.2; }
				}
			}`,
			read: func(c *Config) any { return c.RoutingOptions.StaticRoutes },
			populated: func(v any) bool {
				routes, ok := v.([]*StaticRoute)
				return ok && len(routes) == 2
			},
		},
		{
			name: "routing-instances routing-options",
			site: "instance routing-instances routing-options",
			dup: `routing-instances { blue {
				instance-type virtual-router;
				routing-options { static { route 10.20.0.0/16 { next-hop 192.0.2.1; } } }
				routing-options { static { route 192.0.2.0/24 { next-hop 192.0.2.2; } } }
			} }`,
			merged: `routing-instances { blue {
				instance-type virtual-router;
				routing-options { static {
					route 10.20.0.0/16 { next-hop 192.0.2.1; }
					route 192.0.2.0/24 { next-hop 192.0.2.2; }
				} }
			} }`,
			read: func(c *Config) any {
				for _, instance := range c.RoutingInstances {
					if instance.Name == "blue" {
						return instance.StaticRoutes
					}
				}
				return nil
			},
			populated: func(v any) bool {
				routes, ok := v.([]*StaticRoute)
				return ok && len(routes) == 2
			},
		},
		{
			name: "routing-instances protocols",
			site: "instance routing-instances protocols",
			dup: `routing-instances { blue {
				instance-type virtual-router;
				protocols { ospf { area 0.0.0.0 { interface ge-0/0/0.0; } } }
				protocols { bgp { local-as 65001; group external { peer-as 65002; neighbor 192.0.2.1; } } }
			} }`,
			merged: `routing-instances { blue {
				instance-type virtual-router;
				protocols {
					ospf { area 0.0.0.0 { interface ge-0/0/0.0; } }
					bgp { local-as 65001; group external { peer-as 65002; neighbor 192.0.2.1; } }
				}
			} }`,
			read: func(c *Config) any {
				for _, instance := range c.RoutingInstances {
					if instance.Name == "blue" {
						return struct {
							OSPF *OSPFConfig
							BGP  *BGPConfig
						}{instance.OSPF, instance.BGP}
					}
				}
				return nil
			},
			populated: func(v any) bool {
				protocols, ok := v.(struct {
					OSPF *OSPFConfig
					BGP  *BGPConfig
				})
				return ok && protocols.OSPF != nil && protocols.BGP != nil
			},
		},
	}

	covered := make(map[string]bool, len(cases))
	silent := 0
	for _, tc := range cases {
		if tc.site != "" {
			if covered[tc.site] {
				t.Fatalf("duplicate site fixture for %q", tc.site)
			}
			covered[tc.site] = true
		}
		t.Run(tc.name, func(t *testing.T) {
			want := compileText(t, tc.merged)
			if want == nil {
				t.Fatal("merged control did not compile; this scoped site check would compare against an empty result")
			}
			got := compileText(t, tc.dup)
			if got == nil {
				t.Fatal("duplicate form did not compile leniently")
			}
			wantState, gotState := tc.read(want), tc.read(got)
			if !tc.populated(wantState) {
				t.Fatalf("merged control has no observable state: %#v", wantState)
			}
			if !reflect.DeepEqual(gotState, wantState) {
				silent++
				t.Errorf("SILENT: duplicate form does not conserve typed state:\n duplicate: %#v\n merged:    %#v", gotState, wantState)
			}
		})
	}
	for _, site := range dupUnnamedRoutingMergeSites12043 {
		key := site.scope + " " + site.parent + " " + site.keyword
		if !covered[key] {
			t.Errorf("unnamed routing merge site %q has no #12043 conservation fixture", key)
		}
	}
	if len(covered) != len(dupUnnamedRoutingMergeSites12043) {
		t.Errorf("#12043 site list has %d fixtures for %d listed sites", len(covered), len(dupUnnamedRoutingMergeSites12043))
	}
	t.Logf("unnamed routing containers in the #12043 fixtures: SILENT: %d (checked %d retained registry sites; global static is covered by #12120)", silent, len(covered))
}
