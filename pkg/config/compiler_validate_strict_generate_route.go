package config

import "fmt"

// generateRouteInvalidPrefixes reports every generate-route prefix that
// ValidateRouteDestination (the #15658 schema keyValidator, reusing the
// #2448 static-route destination grammar) rejects, one message per route.
//
// The schema gate covers candidate commits, but the compiler is the second
// layer: configs reaching CompileConfig without SchemaValidate — and the
// tolerant load / peer-sync ingress, which downgrades schema violations —
// must not publish a malformed prefix. Before #15658 the FRR renderer
// silently skipped such a prefix (validFRRRoutePrefix) while the userspace
// snapshot builder passed it to the helper, which refuses the whole
// snapshot (RouteDestinationUnparseable): FRR-vs-userspace split-brain on
// one committed line. Strict compilation rejects the first offender; the
// tolerant path warns per offender and keeps the route, so the published
// snapshot still fails closed in the helper instead of silently losing a
// blackhole. Global routes are walked first, then each routing instance.
func generateRouteInvalidPrefixes(cfg *Config) []string {
	if cfg == nil {
		return nil
	}
	var out []string
	check := func(scope string, routes []*GenerateRoute) {
		for _, gr := range routes {
			if gr == nil {
				continue
			}
			if err := ValidateRouteDestination(gr.Prefix); err != nil {
				out = append(out, fmt.Sprintf("%s %q: %v", scope, gr.Prefix, err))
			}
		}
	}
	check("routing-options generate route", cfg.RoutingOptions.GenerateRoutes)
	for _, ri := range cfg.RoutingInstances {
		if ri == nil {
			continue
		}
		check(fmt.Sprintf("routing-instances %s generate route", ri.Name), ri.GenerateRoutes)
	}
	return out
}

// generateRouteHelperRefusedMaskSpellings reports every authored
// generate-route prefix spelling whose zero-padded mask the userspace
// helper cannot parse (#15658, extending the #12507 static-route gate).
//
// A published "/008" generate prefix fails the whole helper snapshot
// closed (RouteDestinationUnparseable) while FRR's netip belt simply omits
// the blackhole — the split-brain this issue files. Helper-supported
// padding ("/08", "/032") is not reported: canonicalizeGenerateRoutes has
// already written it canonically. Each folded alias is checked as well as
// the surviving prefix. The per-spelling logic is the shared
// helperRefusedMaskSpellings (#17211); only scope and tag differ.
func generateRouteHelperRefusedMaskSpellings(cfg *Config) []string {
	if cfg == nil {
		return nil
	}
	var out []string
	check := func(scope string, routes []*GenerateRoute) {
		for _, gr := range routes {
			if gr == nil {
				continue
			}
			out = append(out, helperRefusedMaskSpellings(scope, "#15658", gr.Prefix, gr.prefixAliases)...)
		}
	}
	check("routing-options generate route", cfg.RoutingOptions.GenerateRoutes)
	for _, ri := range cfg.RoutingInstances {
		if ri == nil {
			continue
		}
		check(fmt.Sprintf("routing-instances %s generate route", ri.Name), ri.GenerateRoutes)
	}
	return out
}
