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
		strictReject    []string
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
			strictReject:    []string{"not implemented", `inet "RG4"`, `inet6 "RG6"`},
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
			name:            "routing-instance static (global registration subsumes #12043)",
			site:            "any routing-options static",
			diagnostic:      "routing-options static",
			warningFragment: "routing-options static",
			dup: `routing-instances { blue {
				instance-type virtual-router;
				routing-options {
					static { route 10.40.0.0/16 { next-hop 192.0.2.1; } }
					static { route 192.0.2.0/24 { next-hop 192.0.2.2; } }
				}
			} }`,
			merged: `routing-instances { blue {
				instance-type virtual-router;
				routing-options { static {
					route 10.40.0.0/16 { next-hop 192.0.2.1; }
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
			name:            "protocols ospf3",
			site:            "any protocols ospf3",
			diagnostic:      "protocols ospf3",
			warningFragment: "`ospf3` containers under `protocols`",
			dup: `protocols {
				ospf3 { area 0.0.0.0 { interface ge-0/0/0.0; } }
				ospf3 { area 0.0.0.1 { interface ge-0/0/1.0; } }
			}`,
			merged: `protocols { ospf3 {
				area 0.0.0.0 { interface ge-0/0/0.0; }
				area 0.0.0.1 { interface ge-0/0/1.0; }
			} }`,
			read: func(c *Config) any { return c.Protocols.OSPFv3 },
			populated: func(v any) bool {
				ospf3, ok := v.(*OSPFv3Config)
				return ok && ospf3 != nil && len(ospf3.Areas) == 2
			},
		},
		{
			name:            "routing-instance protocols ospf3",
			site:            "any protocols ospf3",
			diagnostic:      "protocols ospf3",
			warningFragment: "routing-instances blue protocols",
			dup: `routing-instances { blue {
				instance-type virtual-router;
				protocols {
					ospf3 { area 0.0.0.0 { interface ge-0/0/0.0; } }
					ospf3 { area 0.0.0.1 { interface ge-0/0/1.0; } }
				}
			} }`,
			merged: `routing-instances { blue {
				instance-type virtual-router;
				protocols { ospf3 {
					area 0.0.0.0 { interface ge-0/0/0.0; }
					area 0.0.0.1 { interface ge-0/0/1.0; }
				} }
			} }`,
			read: func(c *Config) any {
				for _, instance := range c.RoutingInstances {
					if instance.Name == "blue" {
						return instance.OSPFv3
					}
				}
				return nil
			},
			populated: func(v any) bool {
				ospf3, ok := v.(*OSPFv3Config)
				return ok && ospf3 != nil && len(ospf3.Areas) == 2
			},
		},
		{
			name:            "protocols rip",
			site:            "any protocols rip",
			diagnostic:      "protocols rip",
			warningFragment: "`rip` containers under `protocols`",
			dup: `protocols {
				rip { group g1 { neighbor ge-0/0/1.0; } }
				rip { group g2 { neighbor ge-0/0/2.0; } }
			}`,
			merged: `protocols { rip {
				group g1 { neighbor ge-0/0/1.0; }
				group g2 { neighbor ge-0/0/2.0; }
			} }`,
			read: func(c *Config) any { return c.Protocols.RIP },
			populated: func(v any) bool {
				rip, ok := v.(*RIPConfig)
				return ok && rip != nil && len(rip.Interfaces) == 2
			},
		},
		{
			name:            "protocols isis",
			site:            "any protocols isis",
			diagnostic:      "protocols isis",
			warningFragment: "`isis` containers under `protocols`",
			dup: `protocols {
				isis { interface ge-0/0/1.0; }
				isis { interface ge-0/0/2.0; }
			}`,
			merged: `protocols { isis {
				interface ge-0/0/1.0;
				interface ge-0/0/2.0;
			} }`,
			read: func(c *Config) any { return c.Protocols.ISIS },
			populated: func(v any) bool {
				isis, ok := v.(*ISISConfig)
				return ok && isis != nil && len(isis.Interfaces) == 2
			},
		},
		{
			name:            "protocols lldp",
			site:            "any protocols lldp",
			diagnostic:      "protocols lldp",
			warningFragment: "`lldp` containers under `protocols`",
			dup: `protocols {
				lldp { interface ge-0/0/1; }
				lldp { interface ge-0/0/2; }
			}`,
			merged: `protocols { lldp {
				interface ge-0/0/1;
				interface ge-0/0/2;
			} }`,
			read: func(c *Config) any { return c.Protocols.LLDP },
			populated: func(v any) bool {
				lldp, ok := v.(*LLDPConfig)
				return ok && lldp != nil && len(lldp.Interfaces) == 2
			},
		},
		{
			name:            "protocols router-advertisement",
			site:            "any protocols router-advertisement",
			diagnostic:      "protocols router-advertisement",
			warningFragment: "`router-advertisement` containers under `protocols`",
			dup: `protocols {
				router-advertisement { interface ge-0/0/1.0 { prefix 2001:db8:1::/64; } }
				router-advertisement { interface ge-0/0/2.0 { prefix 2001:db8:2::/64; } }
			}`,
			merged: `protocols { router-advertisement {
				interface ge-0/0/1.0 { prefix 2001:db8:1::/64; }
				interface ge-0/0/2.0 { prefix 2001:db8:2::/64; }
			} }`,
			read: func(c *Config) any { return c.Protocols.RouterAdvertisement },
			populated: func(v any) bool {
				ra, ok := v.([]*RAInterfaceConfig)
				return ok && len(ra) == 2
			},
		},
		{
			name:            "isis md5 authentication split across containers",
			diagnostic:      "protocols isis",
			warningFragment: "`isis` containers under `protocols`",
			dup: `protocols {
				isis { interface ge-0/0/1.0; }
				isis { authentication-key "k123"; authentication-type md5; }
			}`,
			merged: `protocols { isis {
				interface ge-0/0/1.0;
				authentication-key "k123";
				authentication-type md5;
			} }`,
			read: func(c *Config) any {
				if c.Protocols.ISIS == nil {
					return nil
				}
				return struct {
					AuthType string
					AuthKey  string
				}{c.Protocols.ISIS.AuthType, c.Protocols.ISIS.AuthKey.Reveal()}
			},
			populated: func(v any) bool {
				auth, ok := v.(struct {
					AuthType string
					AuthKey  string
				})
				return ok && auth.AuthType == "md5" && auth.AuthKey == "k123"
			},
		},
		{
			name:            "rip md5 authentication split across containers",
			diagnostic:      "protocols rip",
			warningFragment: "`rip` containers under `protocols`",
			dup: `protocols {
				rip { group g1 { neighbor ge-0/0/1.0; } }
				rip { authentication-key "k123"; authentication-type md5; }
			}`,
			merged: `protocols { rip {
				group g1 { neighbor ge-0/0/1.0; }
				authentication-key "k123";
				authentication-type md5;
			} }`,
			read: func(c *Config) any {
				if c.Protocols.RIP == nil {
					return nil
				}
				return struct {
					AuthType string
					AuthKey  string
				}{c.Protocols.RIP.AuthType, c.Protocols.RIP.AuthKey.Reveal()}
			},
			populated: func(v any) bool {
				auth, ok := v.(struct {
					AuthType string
					AuthKey  string
				})
				return ok && auth.AuthType == "md5" && auth.AuthKey == "k123"
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

	strictError := func(t *testing.T, text string, wants ...string) {
		t.Helper()
		_, err := compile(t, text, false)
		if err == nil {
			t.Fatalf("strict compile error = nil, want substrings %q", wants)
		}
		for _, want := range wants {
			if !strings.Contains(err.Error(), want) {
				t.Fatalf("strict compile error = %v, want it to contain %q", err, want)
			}
		}
	}

	covered := make(map[string]bool, len(cases))
	for _, tc := range cases {
		if tc.site != "" {
			covered[tc.site] = true
		}
		t.Run(tc.name, func(t *testing.T) {
			for _, path := range []struct {
				name    string
				lenient bool
			}{{"strict", false}, {"lenient", true}} {
				t.Run(path.name, func(t *testing.T) {
					if len(tc.strictReject) > 0 && !path.lenient {
						strictError(t, tc.dup, tc.strictReject...)
						strictError(t, tc.merged, tc.strictReject...)
						tree, parseErrs := NewParser(tc.dup).Parse()
						if len(parseErrs) != 0 {
							t.Fatalf("duplicate fixture did not parse for strict fold check: %v", parseErrs)
						}
						var warning string
						for _, merge := range mergeDuplicateBlocks9023(tree) {
							what := strings.TrimSpace(merge.parent + " " + merge.keyword)
							if merge.parent == "" {
								what = merge.keyword
							}
							if merge.parent == "routing-instances" {
								what = strings.TrimSpace(merge.parent + " " + merge.name + " " + merge.keyword)
							}
							if what == tc.diagnostic {
								warning = duplicateBlockMergeWarning9023(merge)
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

func TestUnnamedRoutingContainerDiagnosticsNameScope12120(t *testing.T) {
	const text = `protocols {
		ospf { area 0.0.0.0 { interface ge-0/0/0.0; } }
		ospf { area 0.0.0.1 { interface ge-0/0/1.0; } }
	}
	routing-options {
		generate { route 10.30.0.0/16 { discard; } }
		generate { route 192.0.2.0/24 { discard; } }
	}
	routing-instances {
		red { instance-type virtual-router;
			protocols {
				ospf { area 0.0.0.0 { interface ge-0/0/2.0; } }
				ospf { area 0.0.0.1 { interface ge-0/0/3.0; } }
			}
		}
		blue { instance-type virtual-router;
			routing-options {
				generate { route 10.31.0.0/16 { discard; } }
				generate { route 192.0.3.0/24 { discard; } }
			}
		}
	}`
	cfg := compileMergeDiagnostics12120(t, text)
	var ospf, generate []string
	for _, warning := range cfg.Warnings {
		if strings.Contains(warning, "#12120") && strings.Contains(warning, "`ospf` containers") {
			ospf = append(ospf, warning)
		}
		if strings.Contains(warning, "#12120") && strings.Contains(warning, "routing-options generate") {
			generate = append(generate, warning)
		}
	}
	if len(ospf) != 2 || ospf[0] == ospf[1] {
		t.Fatalf("OSPF merge diagnostics must distinguish top-level and instance scopes, got %q", ospf)
	}
	if !strings.Contains(ospf[0], "protocols") ||
		!(strings.Contains(ospf[0], "routing-instances red protocols") ||
			strings.Contains(ospf[1], "routing-instances red protocols")) {
		t.Errorf("OSPF diagnostics do not identify both scopes: %q", ospf)
	}
	if len(generate) != 2 || generate[0] == generate[1] {
		t.Fatalf("generate diagnostics must distinguish global and instance scopes, got %q", generate)
	}
	if !strings.Contains(generate[0], "routing-options") ||
		!(strings.Contains(generate[0], "routing-instances blue") ||
			strings.Contains(generate[1], "routing-instances blue")) {
		t.Errorf("generate diagnostics do not identify both scopes: %q", generate)
	}
}

func TestUnnamedRoutingContainerGroupDiagnostics12120(t *testing.T) {
	const repeated = `protocols {
		ospf { area 0.0.0.0 { interface ge-0/0/0.0; } }
		ospf { area 0.0.0.1 { interface ge-0/0/1.0; } }
	}`
	for _, tc := range []struct {
		name, text, want string
	}{
		{
			name: "directly applied group",
			text: `groups { "group blue" { ` + repeated + ` } } apply-groups "group blue";`,
			want: `groups "group blue" protocols`,
		},
		{
			name: "transitively applied group",
			text: `groups { G { apply-groups H; } H { ` + repeated + ` } } apply-groups G;`,
			want: "groups H protocols",
		},
		{
			name: "unapplied group",
			text: `groups { G { ` + repeated + ` } }`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := compileMergeDiagnostics12120(t, tc.text)
			var warnings []string
			for _, warning := range cfg.Warnings {
				if strings.Contains(warning, "#12120") {
					warnings = append(warnings, warning)
				}
			}
			if tc.want == "" {
				if len(warnings) != 0 {
					t.Fatalf("unapplied group body emitted merge diagnostics: %v", warnings)
				}
				return
			}
			if len(warnings) == 0 {
				t.Fatalf("applied group body emitted no merge diagnostic")
			}
			found := false
			for _, warning := range warnings {
				found = found || strings.Contains(warning, tc.want)
			}
			if !found {
				t.Errorf("applied-group diagnostic does not name %q: %v", tc.want, warnings)
			}
		})
	}
}

func TestRegisteredRoutingMergeIndependentOfUnrelatedStanzas12120(t *testing.T) {
	compile := func(t *testing.T, text string) *Config {
		t.Helper()
		return compileMergeDiagnostics12120(t, text)
	}
	areaIDs := func(t *testing.T, text string) ([]string, []string) {
		t.Helper()
		cfg := compile(t, text)
		if cfg.Protocols.OSPFv3 == nil {
			t.Fatal("OSPFv3 config missing")
		}
		var areas []string
		for _, area := range cfg.Protocols.OSPFv3.Areas {
			areas = append(areas, area.ID)
		}
		return areas, cfg.Warnings
	}
	ospf3Base := `protocols { ospf3 {
		area 0.0.0.0 { interface ge-0/0/0.0; }
	} ospf3 {
		area 0.0.0.1 { interface ge-0/0/1.0; }
	} }`
	ospf3Extra := ospf3Base + ` protocols { lldp { interface ge-0/0/2; } }`
	baseAreas, baseWarnings := areaIDs(t, ospf3Base)
	extraAreas, extraWarnings := areaIDs(t, ospf3Extra)
	if !reflect.DeepEqual(baseAreas, extraAreas) ||
		!reflect.DeepEqual(baseAreas, []string{"0.0.0.0", "0.0.0.1"}) {
		t.Fatalf("ospf3 fold changed with an unrelated root: base=%v extra=%v", baseAreas, extraAreas)
	}
	if !warningsContain12120Site(baseWarnings, "`ospf3` containers") ||
		!warningsContain12120Site(extraWarnings, "`ospf3` containers") {
		t.Fatalf("ospf3 fold is not named in both root shapes: base=%v extra=%v", baseWarnings, extraWarnings)
	}

	staticBase := `routing-instances { blue {
		instance-type virtual-router;
		routing-options {
			static { route 10.40.0.0/16 { next-hop 192.0.2.1; } }
			static { route 192.0.2.0/24 { next-hop 192.0.2.2; } }
		}
	} }`
	staticExtra := `routing-instances { blue {
		instance-type virtual-router;
		routing-options {
			static { route 10.40.0.0/16 { next-hop 192.0.2.1; } }
			static { route 192.0.2.0/24 { next-hop 192.0.2.2; } }
		}
		routing-options { autonomous-system 65001; }
	} }`
	routeDestinations := func(t *testing.T, text string) ([]string, []string) {
		t.Helper()
		cfg := compile(t, text)
		for _, instance := range cfg.RoutingInstances {
			if instance.Name != "blue" {
				continue
			}
			var destinations []string
			for _, route := range instance.StaticRoutes {
				destinations = append(destinations, route.Destination)
			}
			return destinations, cfg.Warnings
		}
		t.Fatal("routing-instance blue missing")
		return nil, nil
	}
	baseRoutes, baseWarnings := routeDestinations(t, staticBase)
	extraRoutes, extraWarnings := routeDestinations(t, staticExtra)
	if !reflect.DeepEqual(baseRoutes, extraRoutes) ||
		!reflect.DeepEqual(baseRoutes, []string{"10.40.0.0/16", "192.0.2.0/24"}) {
		t.Fatalf("instance static fold changed with an unrelated routing-options stanza: base=%v extra=%v",
			baseRoutes, extraRoutes)
	}
	if !warningsContain12120Site(baseWarnings, "routing-options static") ||
		!warningsContain12120Site(extraWarnings, "routing-options static") {
		t.Fatalf("instance static fold is not named in both shapes: base=%v extra=%v", baseWarnings, extraWarnings)
	}
}

func compileMergeDiagnostics12120(t *testing.T, text string) *Config {
	t.Helper()
	tree, parseErrs := NewParser(text).Parse()
	if len(parseErrs) != 0 || tree == nil {
		t.Fatalf("fixture parse: %v", parseErrs)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("strict compile: %v", err)
	}
	return cfg
}
