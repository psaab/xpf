package config

import (
	"strings"
	"testing"
)

// #15777 — hierarchical `rib { <name> { static { ... } } }` silently dropped
// 100% of its static routes, and compact multi-clause static routes fused
// onto a single child node corrupted preferences / backup next-hops.
//
// The hierarchical spelling nests the table name as an unnamed child of
// `rib` (`rib` -> `inet.0` -> `static`), so the compiler's direct
// FindChild("static") on the named rib node missed it in both strict and
// lenient compilation while SchemaValidate returned nil. The compact
// spelling packs route-level clauses (`preference`, `discard`, ...) onto
// the `next-hop` leaf, where the child reader consumed them as gateway
// addresses.

func hier15777(t *testing.T, src string) *Config {
	t.Helper()
	cfg, err := CompileConfig(hierTree(t, src))
	if err != nil {
		t.Fatalf("strict compile: %v\n%s", err, src)
	}
	return cfg
}

func lenient15777(t *testing.T, src string) *Config {
	t.Helper()
	cfg, err := CompileConfigLenient(hierTree(t, src))
	if err != nil {
		t.Fatalf("lenient compile: %v\n%s", err, src)
	}
	return cfg
}

func findRoute15777(t *testing.T, routes []*StaticRoute, dst string) *StaticRoute {
	t.Helper()
	for _, r := range routes {
		if r != nil && r.Destination == dst {
			return r
		}
	}
	t.Fatalf("route %s not found in %v", dst, routes)
	return nil
}

func TestHierarchicalRibStaticRoutes15777(t *testing.T) {
	const src = `routing-options { rib { inet.0 { static { route 10.77.0.0/16 { next-hop 10.0.0.1; } route 10.78.0.0/16 { next-hop 10.0.0.2; preference 77; } } } inet6.0 { static { route 2001:db8:77::/48 { next-hop 2001:db8::1; } } } } }`
	if err := SchemaValidate(hierTree(t, src), nil); err != nil {
		t.Fatalf("SchemaValidate must accept hierarchical rib: %v", err)
	}
	for _, compile := range []struct {
		name string
		fn   func(*testing.T, string) *Config
	}{{"strict", hier15777}, {"lenient", lenient15777}} {
		t.Run(compile.name, func(t *testing.T) {
			cfg := compile.fn(t, src)
			if len(cfg.RoutingOptions.StaticRoutes) != 2 {
				t.Fatalf("StaticRoutes = %v, want 2 routes", cfg.RoutingOptions.StaticRoutes)
			}
			r := findRoute15777(t, cfg.RoutingOptions.StaticRoutes, "10.78.0.0/16")
			if r.Preference != 77 || !r.HasPreference || len(r.NextHops) != 1 || r.NextHops[0].Address != "10.0.0.2" {
				t.Fatalf("route 10.78 = %+v, want preference 77 via 10.0.0.2", r)
			}
			if len(cfg.RoutingOptions.Inet6StaticRoutes) != 1 {
				t.Fatalf("Inet6StaticRoutes = %v, want 1 route", cfg.RoutingOptions.Inet6StaticRoutes)
			}
			if got := cfg.RoutingOptions.Inet6StaticRoutes[0]; got.Destination != "2001:db8:77::/48" || len(got.NextHops) != 1 || got.NextHops[0].Address != "2001:db8::1" {
				t.Fatalf("inet6 route = %+v", got)
			}
			if len(cfg.RoutingOptions.UnhandledRibs) != 0 {
				t.Fatalf("UnhandledRibs = %v, want none for in-scope tables", cfg.RoutingOptions.UnhandledRibs)
			}
		})
	}
}

func TestHierarchicalRibDoesNotRegressFlat15777(t *testing.T) {
	flat := hier15777(t, `routing-options { rib inet.0 { static { route 10.77.0.0/16 { next-hop 10.0.0.1; } } } }`)
	if len(flat.RoutingOptions.StaticRoutes) != 1 {
		t.Fatalf("flat rib StaticRoutes = %v, want 1", flat.RoutingOptions.StaticRoutes)
	}
	hier := hier15777(t, `routing-options { rib { inet.0 { static { route 10.77.0.0/16 { next-hop 10.0.0.1; } } } } }`)
	if len(hier.RoutingOptions.StaticRoutes) != 1 || hier.RoutingOptions.StaticRoutes[0].Destination != flat.RoutingOptions.StaticRoutes[0].Destination {
		t.Fatalf("hierarchical rib disagrees with flat: hier=%v flat=%v", hier.RoutingOptions.StaticRoutes, flat.RoutingOptions.StaticRoutes)
	}
}

func TestHierarchicalRibRoutingInstance15777(t *testing.T) {
	cfg := hier15777(t, `routing-instances { blue { routing-options { rib { blue.inet.0 { static { route 10.96.0.0/16 { next-hop 10.0.0.1; } } } } } } }`)
	if len(cfg.RoutingInstances) != 1 {
		t.Fatalf("RoutingInstances = %v, want blue", cfg.RoutingInstances)
	}
	ri := cfg.RoutingInstances[0]
	if len(ri.StaticRoutes) != 1 || ri.StaticRoutes[0].Destination != "10.96.0.0/16" {
		t.Fatalf("instance StaticRoutes = %v, want 10.96.0.0/16", ri.StaticRoutes)
	}
	if len(ri.UnhandledRibs) != 0 {
		t.Fatalf("instance UnhandledRibs = %v, want none", ri.UnhandledRibs)
	}
}

func TestHierarchicalRibOutOfScopeWarns15777(t *testing.T) {
	cfg := hier15777(t, `routing-options { rib { inet.2 { static { route 10.97.0.0/16 { next-hop 10.0.0.1; } } } } }`)
	if len(cfg.RoutingOptions.StaticRoutes) != 0 {
		t.Fatalf("out-of-scope rib installed routes: %v", cfg.RoutingOptions.StaticRoutes)
	}
	if len(cfg.RoutingOptions.UnhandledRibs) != 1 || cfg.RoutingOptions.UnhandledRibs[0].Name != "inet.2" || cfg.RoutingOptions.UnhandledRibs[0].Routes != 1 {
		t.Fatalf("UnhandledRibs = %v, want inet.2 with 1 route", cfg.RoutingOptions.UnhandledRibs)
	}
	found := false
	for _, w := range ValidateConfig(cfg) {
		if strings.Contains(w, "inet.2") {
			found = true
		}
	}
	if !found {
		t.Fatalf("ValidateConfig must warn about discarded inet.2 rib, got %v", ValidateConfig(cfg))
	}
}

func TestCompactFusedStaticRoutePreference15777(t *testing.T) {
	for _, src := range []string{
		`routing-options { static { route 10.83.0.0/16 { next-hop 10.0.0.1 preference 123; } } }`,
		`routing-options { static { route 10.83.0.0/16 next-hop 10.0.0.1 preference 123; } }`,
		`routing-options { rib { inet.0 { static { route 10.83.0.0/16 { next-hop 10.0.0.1 preference 123; } } } } }`,
	} {
		cfg := hier15777(t, src)
		r := findRoute15777(t, cfg.RoutingOptions.StaticRoutes, "10.83.0.0/16")
		if r.Preference != 123 || !r.HasPreference {
			t.Fatalf("%s: preference = %d has=%v, want 123", src, r.Preference, r.HasPreference)
		}
		if len(r.NextHops) != 1 || r.NextHops[0].Address != "10.0.0.1" {
			t.Fatalf("%s: NextHops = %+v, want only 10.0.0.1 (fused tokens must not become gateways)", src, r.NextHops)
		}
	}
}

func TestCompactFusedStaticRouteDiscardAndNextTable15777(t *testing.T) {
	// A fused preference on a forwarding route must land on the route, not
	// become phantom gateways named "preference"/"123".
	cfg := hier15777(t, `routing-options { static { route 10.85.0.0/16 { next-hop 10.0.0.1 preference 123; } } }`)
	r := findRoute15777(t, cfg.RoutingOptions.StaticRoutes, "10.85.0.0/16")
	if r.Discard || r.Preference != 123 || len(r.NextHops) != 1 {
		t.Fatalf("fused preference route = %+v, want preference 123 with one next-hop", r)
	}
	// next-hop + discard on one prefix is a contradictory disposition and
	// must stay rejected even when fused onto the next-hop leaf — the
	// fused tail must not smuggle a second disposition past #5633.
	if _, err := CompileConfig(hierTree(t, `routing-options { static { route 10.85.0.0/16 { next-hop 10.0.0.1 discard; } } }`)); err == nil || !strings.Contains(err.Error(), "contradictory dispositions") {
		t.Fatalf("fused discard+next-hop must reject as contradictory, got %v", err)
	}
	// A fused next-table tail must not become a phantom gateway either;
	// assert the compiled next-hops directly on the lenient path, where
	// the kernel-rule scoping gate does not apply.
	cfg2 := lenient15777(t, `routing-options { static { route 10.92.0.0/16 { next-hop 10.0.0.1 next-table blue.inet.0; } } } routing-instances { blue { instance-type virtual-router; } }`)
	r2 := findRoute15777(t, cfg2.RoutingOptions.StaticRoutes, "10.92.0.0/16")
	if len(r2.NextHops) != 1 || r2.NextHops[0].Address != "10.0.0.1" {
		t.Fatalf("fused next-table NextHops = %+v, want only 10.0.0.1", r2.NextHops)
	}
}

func TestCompactHierarchicalRibQualifiedNextHop15777(t *testing.T) {
	cfg := hier15777(t, `routing-options { rib { inet.0 { static { route 10.80.0.0/16 next-hop 10.0.0.1 qualified-next-hop 10.0.0.2 preference 250; } } } }`)
	r := findRoute15777(t, cfg.RoutingOptions.StaticRoutes, "10.80.0.0/16")
	if len(r.NextHops) != 2 {
		t.Fatalf("NextHops = %+v, want primary + qualified backup", r.NextHops)
	}
	var backup *NextHopEntry
	for i := range r.NextHops {
		if r.NextHops[i].Address == "10.0.0.2" {
			backup = &r.NextHops[i]
		}
	}
	if backup == nil || !backup.HasPreference || backup.Preference != 250 {
		t.Fatalf("qualified backup = %+v, want preference 250", backup)
	}
}
