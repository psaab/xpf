package config

import (
	"reflect"
	"testing"
)

func assertInstanceRoutingOptions15065(t *testing.T, cfg *Config) {
	t.Helper()
	if len(cfg.RoutingInstances) != 1 || cfg.RoutingInstances[0] == nil {
		t.Fatalf("compiled routing instances = %+v, want one edge instance", cfg.RoutingInstances)
	}
	ri := cfg.RoutingInstances[0]
	if len(ri.GenerateRoutes) != 1 || ri.GenerateRoutes[0] == nil {
		t.Errorf("per-instance GenerateRoutes = %+v, want one generated route", ri.GenerateRoutes)
	} else if got := *ri.GenerateRoutes[0]; !reflect.DeepEqual(got, GenerateRoute{Prefix: "198.51.100.0/24", Discard: true}) {
		t.Errorf("per-instance generate route = %+v, want prefix and discard preserved", got)
	}
	if got, want := ri.ForwardingTableExport, "export-policy"; got != want {
		t.Errorf("per-instance ForwardingTableExport = %q, want %q", got, want)
	}
	if got, want := ri.ForwardingTableExports, []string{"export-policy"}; !reflect.DeepEqual(got, want) {
		t.Errorf("per-instance ForwardingTableExports = %q, want %q", got, want)
	}
	if len(cfg.RoutingOptions.GenerateRoutes) != 0 || cfg.RoutingOptions.ForwardingTableExport != "" || len(cfg.RoutingOptions.ForwardingTableExports) != 0 {
		t.Errorf("instance routing-options leaked into global config: %+v", cfg.RoutingOptions)
	}
}

// #15065: flat routing-instances routing-options was a drifted subset of the
// global schema, so SetPath packed generate/forwarding-table tails where the
// compiler never reads them.
func TestRoutingInstanceRoutingOptionsFlatMatchesHierarchical15065(t *testing.T) {
	flat, err := CompileConfig(buildTree(t, []string{
		"set routing-instances edge instance-type virtual-router",
		"set routing-instances edge routing-options generate route 198.51.100.0/24 discard",
		"set routing-instances edge routing-options forwarding-table export export-policy",
		"set policy-options policy-statement export-policy term t then accept",
	}))
	if err != nil {
		t.Fatalf("CompileConfig(flat): %v", err)
	}
	assertInstanceRoutingOptions15065(t, flat)

	hier, err := CompileConfig(parseHierarchical(t, `policy-options {
		policy-statement export-policy { term t { then accept; } }
	}
	routing-instances {
		edge {
			instance-type virtual-router;
			routing-options {
				generate { route 198.51.100.0/24 discard; }
				forwarding-table { export export-policy; }
			}
		}
	}`))
	if err != nil {
		t.Fatalf("CompileConfig(hierarchical): %v", err)
	}
	assertInstanceRoutingOptions15065(t, hier)

	// Global controls: the same statements outside an instance must produce
	// the same values, proving the flat fixture reaches the compiler.
	global, err := CompileConfig(buildTree(t, []string{
		"set routing-options generate route 198.51.100.0/24 discard",
		"set routing-options forwarding-table export export-policy",
		"set policy-options policy-statement export-policy term t then accept",
	}))
	if err != nil {
		t.Fatalf("CompileConfig(global): %v", err)
	}
	if len(global.RoutingOptions.GenerateRoutes) != 1 || len(flat.RoutingInstances) != 1 ||
		!reflect.DeepEqual(global.RoutingOptions.GenerateRoutes, flat.RoutingInstances[0].GenerateRoutes) {
		t.Errorf("global GenerateRoutes = %+v, instance GenerateRoutes = %+v, want identical", global.RoutingOptions.GenerateRoutes, flat.RoutingInstances[0].GenerateRoutes)
	}
	if global.RoutingOptions.ForwardingTableExport != flat.RoutingInstances[0].ForwardingTableExport ||
		!reflect.DeepEqual(global.RoutingOptions.ForwardingTableExports, flat.RoutingInstances[0].ForwardingTableExports) {
		t.Errorf("global forwarding-table export = %q/%q, instance = %q/%q, want identical",
			global.RoutingOptions.ForwardingTableExport, global.RoutingOptions.ForwardingTableExports,
			flat.RoutingInstances[0].ForwardingTableExport, flat.RoutingInstances[0].ForwardingTableExports)
	}

	// Display-set restore: serializing the good hierarchical tree to flat
	// `set` lines and replaying them must compile identically.
	tree := parseHierarchical(t, `policy-options {
		policy-statement export-policy { term t { then accept; } }
	}
	routing-instances {
		edge {
			instance-type virtual-router;
			routing-options {
				generate { route 198.51.100.0/24 discard; }
				forwarding-table { export export-policy; }
			}
		}
	}`)
	replayed := &ConfigTree{}
	for _, line := range splitLines(tree.FormatSet()) {
		if line == "" {
			continue
		}
		path, err := ParseSetCommand(line)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", line, err)
		}
		if err := replayed.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", line, err)
		}
	}
	restored, err := CompileConfig(replayed)
	if err != nil {
		t.Fatalf("CompileConfig(display-set replay): %v", err)
	}
	assertInstanceRoutingOptions15065(t, restored)
}

func TestRoutingInstanceRoutingOptionsShareGlobalGrammar15065(t *testing.T) {
	instanceRO := schemaRoutingInstances.wildcard.children["routing-options"]
	if instanceRO == nil {
		t.Fatalf("per-instance routing-options schema missing")
	}
	// Compiler-carried fields (compileRoutingOptions -> compileRoutingInstances
	// copy) must be declared; fields deliberately not carried must not be.
	carried := []string{"static", "rib", "autonomous-system", "rib-groups", "interface-routes", "generate", "forwarding-table"}
	for _, kw := range carried {
		got := instanceRO.children[kw]
		if got == nil {
			t.Errorf("per-instance routing-options does not declare %q, but the compiler carries it into the instance — its flat-set spelling packs and drops silently (#15065)", kw)
			continue
		}
		if got != schemaRoutingOptions.children[kw] {
			t.Errorf("per-instance routing-options %q is a separate schema node from the global one — they must be the same pointer (the #9351 drift class)", kw)
		}
	}
	for _, kw := range []string{"router-id"} {
		if _, ok := instanceRO.children[kw]; ok {
			t.Errorf("per-instance routing-options declares %q, but compileRoutingOptions does not carry it into the instance (global-only) — completion would offer a discarded keyword", kw)
		}
	}
}
