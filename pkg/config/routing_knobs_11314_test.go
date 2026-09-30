package config

import (
	"strings"
	"testing"
)

func hasRoutingKnobWarning11314(cfg *Config, parts ...string) bool {
	for _, warning := range cfg.Warnings {
		matched := true
		for _, part := range parts {
			if !strings.Contains(warning, part) {
				matched = false
				break
			}
		}
		if matched {
			return true
		}
	}
	return false
}

func TestRoutingOptionsRouterIDInheritsIntoProtocols11314(t *testing.T) {
	cfg, err := CompileConfig(buildTree(t, []string{
		"set routing-options router-id 10.255.0.1",
		"set routing-options autonomous-system 65000",
		"set interfaces ge-0/0/0 unit 0 family inet address 192.0.2.1/24",
		"set interfaces ge-0/0/0 unit 0 family inet6 address 2001:db8::1/64",
		"set protocols ospf area 0.0.0.0 interface ge-0/0/0.0",
		"set protocols ospf router-id 10.255.0.2",
		"set protocols ospf3 area 0.0.0.0 interface ge-0/0/0.0",
		"set protocols bgp local-as 65000",
		"set routing-instances edge instance-type vrf",
		"set routing-instances edge protocols ospf area 0.0.0.0 interface ge-0/0/0.0",
		"set routing-instances edge protocols bgp local-as 65001",
		"set routing-instances edge protocols bgp router-id 10.255.0.3",
	}))
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	if got := cfg.Protocols.OSPF.RouterID; got != "10.255.0.2" {
		t.Errorf("explicit global OSPF router-id = %q, want override 10.255.0.2", got)
	}
	if got := cfg.Protocols.OSPFv3.RouterID; got != "10.255.0.1" {
		t.Errorf("global OSPFv3 router-id = %q, want inherited 10.255.0.1", got)
	}
	if got := cfg.Protocols.BGP.RouterID; got != "10.255.0.1" {
		t.Errorf("global BGP router-id = %q, want inherited 10.255.0.1", got)
	}
	if len(cfg.RoutingInstances) != 1 {
		t.Fatalf("compiled %d routing instances, want 1", len(cfg.RoutingInstances))
	}
	ri := cfg.RoutingInstances[0]
	if got := ri.OSPF.RouterID; got != "10.255.0.1" {
		t.Errorf("instance OSPF router-id = %q, want inherited 10.255.0.1", got)
	}
	if got := ri.BGP.RouterID; got != "10.255.0.3" {
		t.Errorf("explicit instance BGP router-id = %q, want override 10.255.0.3", got)
	}
}

func TestRoutingOptionsRouterIDHierarchical11314(t *testing.T) {
	tree := parseHierarchical(t, `routing-options { router-id 10.255.0.4; }
protocols { bgp { local-as 65000; } }`)
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	if got := cfg.Protocols.BGP.RouterID; got != "10.255.0.4" {
		t.Fatalf("hierarchical global router-id = %q, want 10.255.0.4", got)
	}
}

func TestRoutingOptionsRouterIDInvalidStrictAndTolerant11314(t *testing.T) {
	tree := func() *ConfigTree {
		return buildTree(t, []string{"set routing-options router-id not-an-ip"})
	}
	if _, err := CompileConfig(tree()); err == nil ||
		!strings.Contains(err.Error(), "routing-options") ||
		!strings.Contains(err.Error(), "not-an-ip") {
		t.Fatalf("strict compile error = %v, want routing-options router-id rejection", err)
	}
	cfg, err := CompileConfigLenient(tree())
	if err != nil {
		t.Fatalf("tolerant compile rejected a persisted router-id: %v", err)
	}
	if !hasRoutingKnobWarning11314(cfg, "routing-options", "router-id", "not-an-ip") {
		t.Fatalf("tolerant warnings do not name the malformed global router-id: %v", cfg.Warnings)
	}
}

func TestStaticRouteRibGroupHasSpecificWarning11314(t *testing.T) {
	cases := []struct {
		name string
		tree func(*testing.T) *ConfigTree
	}{
		{
			name: "flat-set",
			tree: func(t *testing.T) *ConfigTree {
				return buildTree(t, []string{
					"set routing-options static route 192.0.2.0/24 next-hop 192.0.2.1",
					"set routing-options static route 192.0.2.0/24 rib-group leak",
				})
			},
		},
		{
			name: "hierarchical",
			tree: func(t *testing.T) *ConfigTree {
				return parseHierarchical(t, `routing-options {
					static {
						route 192.0.2.0/24 {
							next-hop 192.0.2.1;
							rib-group leak;
						}
					}
				}`)
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			for _, compile := range []struct {
				name string
				fn   func(*ConfigTree) (*Config, error)
			}{
				{name: "strict", fn: CompileConfig},
				{name: "tolerant", fn: CompileConfigLenient},
			} {
				t.Run(compile.name, func(t *testing.T) {
					cfg, err := compile.fn(tc.tree(t))
					if err != nil {
						t.Fatalf("compile: %v", err)
					}
					if !hasRoutingKnobWarning11314(cfg, "static route", "rib-group", "only") {
						t.Fatalf("missing specific static-route rib-group warning: %v", cfg.Warnings)
					}
					if len(cfg.RoutingOptions.StaticRoutes) != 1 || cfg.RoutingOptions.StaticRoutes[0].Destination != "192.0.2.0/24" || len(cfg.RoutingOptions.StaticRoutes[0].NextHops) != 1 {
						t.Fatalf("rib-group diagnostic changed the local static route: %+v", cfg.RoutingOptions.StaticRoutes)
					}
				})
			}
		})
	}
}

func TestInstanceRoutingOptionsDroppedKnobsHaveSpecificWarnings11314(t *testing.T) {
	cases := []struct {
		name string
		tree func(*testing.T) *ConfigTree
	}{
		{
			name: "flat-set",
			tree: func(t *testing.T) *ConfigTree {
				return buildTree(t, []string{
					"set routing-instances edge instance-type vrf",
					"set routing-instances edge routing-options rib-groups leaked import-rib inet.0",
					"set routing-instances edge routing-options generate route 198.51.100.0/24 discard",
				})
			},
		},
		{
			name: "hierarchical",
			tree: func(t *testing.T) *ConfigTree {
				return parseHierarchical(t, `routing-instances {
					edge {
						instance-type vrf;
						routing-options {
							rib-groups { leaked { import-rib inet.0; } }
							generate { route 198.51.100.0/24 discard; }
						}
					}
				}`)
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			for _, compile := range []struct {
				name string
				fn   func(*ConfigTree) (*Config, error)
			}{
				{name: "strict", fn: CompileConfig},
				{name: "tolerant", fn: CompileConfigLenient},
			} {
				t.Run(compile.name, func(t *testing.T) {
					cfg, err := compile.fn(tc.tree(t))
					if err != nil {
						t.Fatalf("compile: %v", err)
					}
					if !hasRoutingKnobWarning11314(cfg, "routing-options", "rib-groups", "not copied") {
						t.Errorf("missing specific per-instance rib-groups warning: %v", cfg.Warnings)
					}
					if !hasRoutingKnobWarning11314(cfg, "routing-options", "generate", "not applied") {
						t.Errorf("missing specific per-instance generate warning: %v", cfg.Warnings)
					}
				})
			}
		})
	}
}

func TestRibGroupImportPolicyIsRejectedOrWarned11314(t *testing.T) {
	cases := []struct {
		name string
		tree func(*testing.T) *ConfigTree
	}{
		{
			name: "flat-set",
			tree: func(t *testing.T) *ConfigTree {
				return buildTree(t, []string{
					"set routing-options rib-groups leak import-rib inet.0",
					"set routing-options rib-groups leak import-policy FILTER",
				})
			},
		},
		{
			name: "hierarchical",
			tree: func(t *testing.T) *ConfigTree {
				return parseHierarchical(t, `routing-options {
					rib-groups { leak { import-rib inet.0; import-policy FILTER; } }
				}`)
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := CompileConfig(tc.tree(t))
			if err == nil || !strings.Contains(err.Error(), "import-policy") || !strings.Contains(err.Error(), "leak") {
				t.Fatalf("strict error = %v, want targeted import-policy rejection", err)
			}
			cfg, err := CompileConfigLenient(tc.tree(t))
			if err != nil {
				t.Fatalf("tolerant compile rejected a persisted rib-group: %v", err)
			}
			if !hasRoutingKnobWarning11314(cfg, "import-policy", "leak", "not implemented") {
				t.Fatalf("tolerant warnings do not identify the ignored import-policy: %v", cfg.Warnings)
			}
		})
	}
}
