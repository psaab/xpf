package config

import (
	"reflect"
	"strings"
	"testing"
)

// TestUnnamedRoutingContainersMergeAt12120Sites checks the additional
// repeated-unnamed routing sites against their single-container twins on both
// compiler paths. The registry coverage at the end makes a new fold site
// require a behavioral fixture.
func TestUnnamedRoutingContainersMergeAt12120Sites(t *testing.T) {
	cases := []struct {
		name            string
		site            string
		diagnostic      string
		warningFragment string
		strictReject    string
		dup             string
		merged          string
		read            func(*Config) any
		populated       func(any) bool
	}{
		{
			name:            "routing-options generate",
			site:            "any routing-options generate",
			diagnostic:      "routing-options generate",
			warningFragment: "routing-options generate",
			dup: `routing-options {
				generate { route 10.30.0.0/16 { discard; } }
				generate { route 192.0.2.0/24 { discard; } }
			}`,
			merged: `routing-options {
				generate {
					route 10.30.0.0/16 { discard; }
					route 192.0.2.0/24 { discard; }
				}
			}`,
			read: func(c *Config) any { return c.RoutingOptions.GenerateRoutes },
			populated: func(v any) bool {
				routes, ok := v.([]*GenerateRoute)
				return ok && len(routes) == 2
			},
		},
		{
			name:            "global routing-options interface-routes",
			site:            "any routing-options interface-routes",
			diagnostic:      "routing-options interface-routes",
			warningFragment: "routing-options interface-routes",
			strictReject:    "not implemented",
			dup: `routing-options {
				interface-routes { rib-group { inet RG4; } }
				interface-routes { rib-group { inet6 RG6; } }
			}`,
			merged: `routing-options {
				interface-routes { rib-group { inet RG4; inet6 RG6; } }
			}`,
			read: func(c *Config) any {
				return struct {
					V4 string
					V6 string
				}{c.RoutingOptions.InterfaceRoutesRibGroup, c.RoutingOptions.InterfaceRoutesRibGroupV6}
			},
			populated: func(v any) bool {
				groups, ok := v.(struct {
					V4 string
					V6 string
				})
				return ok && groups.V4 == "RG4" && groups.V6 == "RG6"
			},
		},
		{
			name:            "routing-instance interface-routes",
			site:            "any routing-options interface-routes",
			diagnostic:      "routing-options interface-routes",
			warningFragment: "routing-options interface-routes",
			dup: `routing-options { rib-groups { leak { import-rib inet.0; import-rib blue.inet.0; } } }
			routing-instances { blue {
				instance-type virtual-router;
				routing-options {
					interface-routes { rib-group { inet leak; } }
					interface-routes { rib-group { inet6 leak; } }
				}
			} }`,
			merged: `routing-options { rib-groups { leak { import-rib inet.0; import-rib blue.inet.0; } } }
			routing-instances { blue {
				instance-type virtual-router;
				routing-options { interface-routes { rib-group { inet leak; inet6 leak; } } }
			} }`,
			read: func(c *Config) any {
				for _, instance := range c.RoutingInstances {
					if instance.Name == "blue" {
						return struct {
							V4 string
							V6 string
						}{instance.InterfaceRoutesRibGroup, instance.InterfaceRoutesRibGroupV6}
					}
				}
				return nil
			},
			populated: func(v any) bool {
				groups, ok := v.(struct {
					V4 string
					V6 string
				})
				return ok && groups.V4 == "leak" && groups.V6 == "leak"
			},
		},
		{
			name:            "routing-options rib inet.0 static",
			site:            "any rib static",
			diagnostic:      "rib static",
			warningFragment: "`static` containers under `rib`",
			dup: `routing-options {
				rib inet.0 {
					static { route 10.40.0.0/16 { next-hop 192.0.2.1; } }
					static { route 192.0.2.0/24 { next-hop 192.0.2.2; } }
				}
			}`,
			merged: `routing-options {
				rib inet.0 { static {
					route 10.40.0.0/16 { next-hop 192.0.2.1; }
					route 192.0.2.0/24 { next-hop 192.0.2.2; }
				} }
			}`,
			read: func(c *Config) any { return c.RoutingOptions.StaticRoutes },
			populated: func(v any) bool {
				routes, ok := v.([]*StaticRoute)
				return ok && len(routes) == 2
			},
		},
		{
			name:            "protocols ospf",
			site:            "any protocols ospf",
			diagnostic:      "protocols ospf",
			warningFragment: "`ospf` containers under `protocols`",
			dup: `protocols {
				ospf { area 0.0.0.0 { interface ge-0/0/0.0; } }
				ospf { area 0.0.0.1 { interface ge-0/0/1.0; } }
			}`,
			merged: `protocols {
				ospf {
					area 0.0.0.0 { interface ge-0/0/0.0; }
					area 0.0.0.1 { interface ge-0/0/1.0; }
				}
			}`,
			read: func(c *Config) any { return c.Protocols.OSPF },
			populated: func(v any) bool {
				ospf, ok := v.(*OSPFConfig)
				return ok && ospf != nil && len(ospf.Areas) == 2
			},
		},
		{
			name:            "protocols bgp",
			site:            "any protocols bgp",
			diagnostic:      "protocols bgp",
			warningFragment: "`bgp` containers under `protocols`",
			dup: `protocols {
				bgp { local-as 65001; group one { peer-as 65002; neighbor 192.0.2.1; } }
				bgp { group two { peer-as 65003; neighbor 192.0.2.2; } }
			}`,
			merged: `protocols {
				bgp { local-as 65001;
					group one { peer-as 65002; neighbor 192.0.2.1; }
					group two { peer-as 65003; neighbor 192.0.2.2; }
				}
			}`,
			read: func(c *Config) any { return c.Protocols.BGP },
			populated: func(v any) bool {
				bgp, ok := v.(*BGPConfig)
				return ok && bgp != nil && len(bgp.Neighbors) == 2
			},
		},
		{
			name:            "protocols roots",
			site:            "root root protocols",
			diagnostic:      "protocols",
			warningFragment: "top-level `protocols`",
			dup: `protocols {
				ospf { area 0.0.0.0 { interface ge-0/0/0.0; } }
			}
			protocols {
				ospf { area 0.0.0.1 { interface ge-0/0/1.0; } }
			}`,
			merged: `protocols {
				ospf {
					area 0.0.0.0 { interface ge-0/0/0.0; }
					area 0.0.0.1 { interface ge-0/0/1.0; }
				}
			}`,
			read: func(c *Config) any { return c.Protocols.OSPF },
			populated: func(v any) bool {
				ospf, ok := v.(*OSPFConfig)
				return ok && ospf != nil && len(ospf.Areas) == 2
			},
		},
	}

	compile := func(t *testing.T, text string, lenient bool) (*Config, error) {
		t.Helper()
		tree, parseErrs := NewParser(text).Parse()
		if len(parseErrs) > 0 || tree == nil {
			t.Fatalf("fixture did not parse: %v", parseErrs)
		}
		if lenient {
			return CompileConfigLenient(tree)
		}
		return CompileConfig(tree)
	}

	compileOK := func(t *testing.T, text string, lenient bool) *Config {
		t.Helper()
		cfg, err := compile(t, text, lenient)
		if err != nil {
			t.Fatalf("compile (lenient=%v): %v", lenient, err)
		}
		return cfg
	}

	strictError := func(t *testing.T, text, want string) {
		t.Helper()
		_, err := compile(t, text, false)
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Fatalf("strict compile error = %v, want it to contain %q", err, want)
		}
	}

	covered := make(map[string]bool, len(cases))
	for _, tc := range cases {
		covered[tc.site] = true
		t.Run(tc.name, func(t *testing.T) {
			for _, path := range []struct {
				name    string
				lenient bool
			}{{"strict", false}, {"lenient", true}} {
				t.Run(path.name, func(t *testing.T) {
					if tc.strictReject != "" && !path.lenient {
						strictError(t, tc.dup, tc.strictReject)
						strictError(t, tc.merged, tc.strictReject)
						tree, parseErrs := NewParser(tc.dup).Parse()
						if len(parseErrs) != 0 {
							t.Fatalf("duplicate fixture did not parse for strict fold check: %v", parseErrs)
						}
						var warning string
						for _, what := range mergeDuplicateBlocks9023(tree) {
							if what == tc.diagnostic {
								warning = duplicateBlockMergeWarning9023(what)
								break
							}
						}
						if !strings.Contains(warning, "#12120") {
							t.Errorf("strict merge fold warning = %q, want #12120", warning)
						}
						return
					}
					want := compileOK(t, tc.merged, path.lenient)
					got := compileOK(t, tc.dup, path.lenient)
					wantState, gotState := tc.read(want), tc.read(got)
					if !tc.populated(wantState) {
						t.Fatalf("merged control has no observable state: %#v", wantState)
					}
					if !reflect.DeepEqual(gotState, wantState) {
						t.Errorf("SILENT: duplicate form does not conserve typed state:\n duplicate: %#v\n merged:    %#v", gotState, wantState)
					}
					if !warningsContain12120Site(got.Warnings, tc.warningFragment) {
						t.Errorf("duplicate container warning does not name %q and #12120: %v", tc.warningFragment, got.Warnings)
					}
					if warningsContain12120(want.Warnings) {
						t.Errorf("single-container control received a #12120 merge diagnostic: %v", want.Warnings)
					}
				})
			}
		})
	}
	for _, site := range dupUnnamedRoutingMergeSites12120 {
		key := site.scope + " " + site.parent + " " + site.keyword
		if !covered[key] {
			t.Errorf("#12120 unnamed routing merge site %q has no strict+lenient conservation fixture", key)
		}
	}
	if len(covered) != len(dupUnnamedRoutingMergeSites12120) {
		t.Errorf("#12120 census has %d fixture sites for %d registered sites", len(covered), len(dupUnnamedRoutingMergeSites12120))
	}
	t.Logf("unnamed routing containers at the #12120 sites: checked %d registered sites", len(covered))
}

func warningsContain12120(warnings []string) bool {
	for _, warning := range warnings {
		if strings.Contains(warning, "#12120") {
			return true
		}
	}
	return false
}

func warningsContain12120Site(warnings []string, site string) bool {
	for _, warning := range warnings {
		if strings.Contains(warning, "#12120") && strings.Contains(warning, site) {
			return true
		}
	}
	return false
}
