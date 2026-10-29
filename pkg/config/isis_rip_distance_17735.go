package config

import (
	"fmt"
	"log/slog"
)

const (
	junosISISBestDistance17735 = 15
	frrISISFixedDistance17735  = 115
)

// ISISDistanceActive reports whether the config can form an IS-IS adjacency
// in this RIB. A merely declared or disabled stanza with no enabled interface
// cannot contribute an IS-IS route to same-prefix arbitration.
func ISISDistanceActive(isis *ISISConfig) bool {
	if isis == nil || isis.Disable || !ValidISISNET(isis.NET) {
		return false
	}
	for _, iface := range isis.Interfaces {
		if iface != nil && !iface.Disable && iface.Name != "" {
			return true
		}
	}
	return false
}

func ripDistanceActive17735(rip *RIPConfig) bool {
	if rip == nil || rip.Disable {
		return false
	}
	if len(rip.Interfaces) > 0 {
		return true
	}
	for _, group := range rip.Groups {
		if group != nil && len(group.Interfaces) > 0 {
			return true
		}
	}
	return false
}

// RIPISISDistanceConflict reports a same-RIB active RIP/IS-IS pair. FRR has
// no IS-IS distance knob: zebra fixes IS-IS at 115, while xpf pins RIP to its
// Junos distance 100. This reverses Junos's IS-IS 15/18 < RIP 100 ordering.
func RIPISISDistanceConflict(rip *RIPConfig, isis *ISISConfig) bool {
	return ripDistanceActive17735(rip) && ISISDistanceActive(isis)
}

// ISISStaticDistanceConflict reports static preferences in the range where
// FRR's fixed IS-IS distance 115 differs from Junos IS-IS 15/18. In this
// interval FRR would select the static while Junos selects IS-IS (for at
// least the level-1 case); there is no safe way to translate the static into
// FRR's distance scale while preserving its preference relative to both
// protocols. Omitted preference is Junos 5 and is outside the interval.
func ISISStaticDistanceConflict(preference int) bool {
	if preference == 0 {
		preference = 5
	}
	return preference >= junosISISBestDistance17735 && preference < frrISISFixedDistance17735
}

// validateISISDistanceOrderingStrict17735 rejects same-RIB configurations
// whose rendered FRR administrative distances contradict Junos. On tolerant
// load it warns; the FRR render belt withholds RIP, or the conflicting
// static tier, while retaining the Junos-preferred IS-IS route.
func validateISISDistanceOrderingStrict17735(cfg *Config, lenient bool) ([]string, error) {
	if cfg == nil {
		return nil, nil
	}
	var warnings []string
	report := func(message string) error {
		if lenient {
			slog.Warn("config: IS-IS distance ordering cannot be represented by FRR; conflicting route will be withheld (#17735)",
				"detail", message)
			warnings = append(warnings, message)
			return nil
		}
		return fmt.Errorf("%s", message)
	}
	check := func(scope string, rip *RIPConfig, isis *ISISConfig, routes ...*StaticRoute) error {
		isisActive := ISISDistanceActive(isis)
		if RIPISISDistanceConflict(rip, isis) {
			return report(fmt.Sprintf("%s: active RIP and IS-IS share a routing table, but FRR fixes IS-IS at distance 115 while RIP is rendered at 100; Junos prefers IS-IS 15/18 over RIP 100. Disable one protocol or separate them into different routing instances (#17735)", scope))
		}
		if !isisActive {
			return nil
		}
		for _, route := range routes {
			if route == nil || route.NoInstall || route.NextTable != "" {
				continue
			}
			if len(route.NextHops) == 0 {
				if ISISStaticDistanceConflict(route.Preference) {
					return report(fmt.Sprintf("%s: static route %s preference %d conflicts with FRR's fixed IS-IS distance 115; Junos IS-IS preference is 15/18 and the static cannot be ordered consistently (#17735)", scope, route.Destination, route.Preference))
				}
				continue
			}
			for _, hop := range route.NextHops {
				preference := route.Preference
				if hop.HasPreference {
					preference = hop.Preference
				}
				if ISISStaticDistanceConflict(preference) {
					return report(fmt.Sprintf("%s: static route %s next-hop preference %d conflicts with FRR's fixed IS-IS distance 115; Junos IS-IS preference is 15/18 and the static cannot be ordered consistently (#17735)", scope, route.Destination, preference))
				}
			}
		}
		return nil
	}
	if err := check("protocols", cfg.Protocols.RIP, cfg.Protocols.ISIS,
		append(append([]*StaticRoute(nil), cfg.RoutingOptions.StaticRoutes...), cfg.RoutingOptions.Inet6StaticRoutes...)...); err != nil {
		return warnings, err
	}
	for _, ri := range cfg.RoutingInstances {
		if ri == nil {
			continue
		}
		if ri.InstanceType == "forwarding" {
			continue
		}
		routes := append(append([]*StaticRoute(nil), ri.StaticRoutes...), ri.Inet6StaticRoutes...)
		if err := check(fmt.Sprintf("routing-instance %s", ri.Name), ri.RIP, ri.ISIS, routes...); err != nil {
			return warnings, err
		}
	}
	return warnings, nil
}
