package config

import "fmt"

// staticRouteHelperRefusedMaskSpellings reports every authored static-route
// destination spelling whose zero-padded mask the userspace helper cannot parse
// (#12507, follow-up to #12047/#12122/#12178), one message per spelling.
//
// The helper's ipnet parser reads at most two IPv4 and three IPv6 mask digits
// (CIDRMaskHelperRefusesPadding). A published route with a longer mask fails the
// whole helper snapshot closed (RouteDestinationUnparseable). Shorter padding
// ("/08", "/032") is not reported: canonicalizeStaticRouteDestinationMasks has
// already written it canonically, and refusing it would brick the next commit
// on a box that installed it (#12178).
//
// Each route's folded aliases are checked as well as its destination.
// "10.0.0.0/8" and "10.0.0.0/008" fold into one route, so checking only the
// surviving spelling would let the refused one commit.
//
// Strict commit rejects the first spelling. The tolerant path warns once per
// spelling and keeps the config: a published route that keeps a refused
// spelling fails the helper snapshot closed, and the snapshot refusal stamps
// (userspace.PolicyContentRejectionReasons) name it. Global routes are walked
// first, then each routing instance in RoutingInstances order. Mirrors
// validateStaticNextHopFamilyStrict.
func staticRouteHelperRefusedMaskSpellings(cfg *Config) []string {
	if cfg == nil {
		return nil
	}
	var out []string
	check := func(scope string, routes []*StaticRoute) {
		for _, sr := range routes {
			if sr == nil {
				continue
			}
			for i, spelling := range append([]string{sr.Destination}, sr.destinationAliases...) {
				if !CIDRMaskHelperRefusesPadding(spelling) {
					continue
				}
				merged := ""
				if i > 0 {
					merged = fmt.Sprintf(" (merged into %q)", sr.Destination)
				}
				out = append(out, fmt.Sprintf(
					"%s %q%s has redundant leading-zero CIDR mask digits the userspace helper cannot parse; write it as %q (#12507)",
					scope, spelling, merged, normalizeCIDRMaskPadding(spelling)))
			}
		}
	}
	check("routing-options static route", cfg.RoutingOptions.StaticRoutes)
	check("routing-options static route", cfg.RoutingOptions.Inet6StaticRoutes)
	for _, ri := range cfg.RoutingInstances {
		if ri == nil {
			continue
		}
		scope := fmt.Sprintf("routing-instances %s static route", ri.Name)
		check(scope, ri.StaticRoutes)
		check(scope, ri.Inet6StaticRoutes)
	}
	return out
}
