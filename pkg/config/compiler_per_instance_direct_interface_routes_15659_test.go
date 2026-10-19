package config

import (
	"strings"
	"testing"
)

// TestPerInstanceDirectInterfaceRoutesRibGroupCompiledAndValidated is the
// #15659 regression: the Junos-canonical direct placement
// `routing-instances <name> interface-routes rib-group (inet|inet6) <group>`
// was admitted by the schema and the #9323 closed-world gate but never read
// by compileRoutingInstances, so the selector silently vanished, no leak
// prefixes were generated, and an undefined group was not strict-rejected.
func TestPerInstanceDirectInterfaceRoutesRibGroupCompiledAndValidated(t *testing.T) {
	t.Run("flat-set direct inet and inet6 compiled and generate leak prefixes", func(t *testing.T) {
		cfg, err := CompileConfig(buildTree(t, []string{
			"set routing-instances dmz-vr instance-type virtual-router",
			"set routing-instances dmz-vr interface ge-0/0/1.0",
			"set routing-instances dmz-vr interface-routes rib-group inet dmz-leak-v4",
			"set routing-instances dmz-vr interface-routes rib-group inet6 dmz-leak-v6",
			"set routing-options rib-groups dmz-leak-v4 import-rib inet.0",
			"set routing-options rib-groups dmz-leak-v6 import-rib inet6.0",
			"set interfaces ge-0/0/1 unit 0 family inet address 10.0.30.1/24",
			"set interfaces ge-0/0/1 unit 0 family inet6 address 2001:db8:30::1/64",
		}))
		if err != nil {
			t.Fatalf("direct RI interface-routes must commit: %v", err)
		}
		if len(cfg.RoutingInstances) != 1 {
			t.Fatalf("RoutingInstances = %d, want 1", len(cfg.RoutingInstances))
		}
		ri := cfg.RoutingInstances[0]
		if ri.InterfaceRoutesRibGroup != "dmz-leak-v4" {
			t.Fatalf("InterfaceRoutesRibGroup = %q, want dmz-leak-v4", ri.InterfaceRoutesRibGroup)
		}
		if ri.InterfaceRoutesRibGroupV6 != "dmz-leak-v6" {
			t.Fatalf("InterfaceRoutesRibGroupV6 = %q, want dmz-leak-v6", ri.InterfaceRoutesRibGroupV6)
		}
		got := RibGroupConnectedPrefixes(cfg)["dmz-vr"]
		want := map[string]bool{"10.0.30.0/24": true, "2001:db8:30::/64": true}
		if len(got) != len(want) {
			t.Fatalf("RibGroupConnectedPrefixes[dmz-vr] = %v, want %v", got, want)
		}
		for _, p := range got {
			if !want[p] {
				t.Fatalf("unexpected leak prefix %q in %v", p, got)
			}
		}
	})

	t.Run("hierarchical direct inet compiled", func(t *testing.T) {
		input := `routing-instances {
    dmz-vr {
        instance-type virtual-router;
        interface ge-0/0/1.0;
        interface-routes {
            rib-group inet dmz-leak-v4;
        }
    }
}
routing-options {
    rib-groups {
        dmz-leak-v4 {
            import-rib inet.0;
        }
    }
}
interfaces {
    ge-0/0/1 {
        unit 0 {
            family inet {
                address 10.0.30.1/24;
            }
        }
    }
}
`
		parser := NewParser(input)
		tree, errs := parser.Parse()
		if len(errs) > 0 {
			t.Fatalf("parse errors: %v", errs)
		}
		cfg, err := CompileConfig(tree)
		if err != nil {
			t.Fatalf("hierarchical direct RI interface-routes must commit: %v", err)
		}
		if len(cfg.RoutingInstances) != 1 {
			t.Fatalf("RoutingInstances = %d, want 1", len(cfg.RoutingInstances))
		}
		if got := cfg.RoutingInstances[0].InterfaceRoutesRibGroup; got != "dmz-leak-v4" {
			t.Fatalf("InterfaceRoutesRibGroup = %q, want dmz-leak-v4", got)
		}
		got := RibGroupConnectedPrefixes(cfg)["dmz-vr"]
		if len(got) != 1 || got[0] != "10.0.30.0/24" {
			t.Fatalf("RibGroupConnectedPrefixes[dmz-vr] = %v, want [10.0.30.0/24]", got)
		}
	})

	t.Run("direct undefined group strict-rejected and lenient-warned", func(t *testing.T) {
		for _, family := range []string{"inet", "inet6"} {
			t.Run(family, func(t *testing.T) {
				lines := []string{
					"set routing-instances dmz-vr instance-type virtual-router",
					"set routing-instances dmz-vr interface-routes rib-group " + family + " missing-group",
				}
				_, err := CompileConfig(buildTree(t, lines))
				if err == nil {
					t.Fatal("strict compile accepted an undefined direct RI rib-group")
				}
				for _, want := range []string{"routing-instance", "dmz-vr", family, "missing-group", "undefined rib-group"} {
					if !strings.Contains(err.Error(), want) {
						t.Fatalf("strict error %q does not name %q", err, want)
					}
				}
				cfg, err := CompileConfigLenient(buildTree(t, lines))
				if err != nil {
					t.Fatalf("tolerant compile rejected dangling direct selector: %v", err)
				}
				if !warningsContain(cfg.Warnings, "missing-group") || !warningsContain(cfg.Warnings, "undefined rib-group") {
					t.Fatalf("tolerant warnings = %v, want undefined rib-group warning", cfg.Warnings)
				}
			})
		}
	})

	t.Run("direct does not overwrite nested routing-options selector", func(t *testing.T) {
		cfg, err := CompileConfig(buildTree(t, []string{
			"set routing-instances dmz-vr instance-type virtual-router",
			"set routing-instances dmz-vr interface-routes rib-group inet direct-v4",
			"set routing-instances dmz-vr routing-options interface-routes rib-group inet6 nested-v6",
			"set routing-options rib-groups direct-v4 import-rib inet.0",
			"set routing-options rib-groups nested-v6 import-rib inet6.0",
		}))
		if err != nil {
			t.Fatalf("direct+nested RI interface-routes must commit: %v", err)
		}
		ri := cfg.RoutingInstances[0]
		if ri.InterfaceRoutesRibGroup != "direct-v4" || ri.InterfaceRoutesRibGroupV6 != "nested-v6" {
			t.Fatalf("selectors = inet %q inet6 %q, want direct-v4/nested-v6", ri.InterfaceRoutesRibGroup, ri.InterfaceRoutesRibGroupV6)
		}
	})

	t.Run("nested does not overwrite direct selector when nested is empty for family", func(t *testing.T) {
		// routing-options block present but only sets inet6; direct inet must survive.
		cfg, err := CompileConfig(buildTree(t, []string{
			"set routing-instances dmz-vr instance-type virtual-router",
			"set routing-instances dmz-vr routing-options interface-routes rib-group inet6 nested-v6",
			"set routing-instances dmz-vr interface-routes rib-group inet direct-v4",
			"set routing-options rib-groups direct-v4 import-rib inet.0",
			"set routing-options rib-groups nested-v6 import-rib inet6.0",
		}))
		if err != nil {
			t.Fatalf("nested-then-direct RI interface-routes must commit: %v", err)
		}
		ri := cfg.RoutingInstances[0]
		if ri.InterfaceRoutesRibGroup != "direct-v4" || ri.InterfaceRoutesRibGroupV6 != "nested-v6" {
			t.Fatalf("selectors = inet %q inet6 %q, want direct-v4/nested-v6", ri.InterfaceRoutesRibGroup, ri.InterfaceRoutesRibGroupV6)
		}
	})
}
