package userspace

import (
	"fmt"
	"strings"

	"github.com/psaab/xpf/pkg/termsafe"
)

// FormatFIBDump renders a helper-side FIB snapshot for both CLI entry points.
// Every wire value is treated as a single-line terminal field.
func FormatFIBDump(generation uint32, routes []FibRouteWire) string {
	var out strings.Builder
	fmt.Fprintf(&out, "Fast-path FIB (generation %d):\n", generation)
	if len(routes) == 0 {
		out.WriteString("  (no routes)\n")
		return out.String()
	}
	fmt.Fprintf(&out, "  %-20s %-6s %-24s %-12s %-32s %-10s %s\n",
		"Table", "Family", "Destination", "Type", "Next-hop / action", "Preference", "MTU")
	for _, route := range routes {
		action := ""
		if route.Discard {
			action = "discard"
		} else if route.NextTable != "" {
			action = fmt.Sprintf("next-table %s priority %d",
				termsafe.SanitizeForDisplay(route.NextTable), route.RulePriority)
		} else {
			legs := make([]string, 0, len(route.NextHops))
			for _, hop := range route.NextHops {
				leg := termsafe.SanitizeForDisplay(hop.NextHop)
				if hop.Interface != "" {
					if leg != "" {
						leg += " via "
					}
					leg += termsafe.SanitizeForDisplay(hop.Interface)
				} else if leg == "" && hop.Ifindex != 0 {
					leg = fmt.Sprintf("ifindex %d", hop.Ifindex)
				}
				if hop.TunnelEndpointID != 0 {
					leg += fmt.Sprintf(" tunnel %d", hop.TunnelEndpointID)
				}
				if hop.Weight > 1 {
					leg += fmt.Sprintf(" weight %d", hop.Weight)
				}
				legs = append(legs, leg)
			}
			action = strings.Join(legs, ", ")
			if action == "" {
				action = "-"
			}
		}
		fmt.Fprintf(&out, "  %-20s %-6s %-24s %-12s %-32s %-10d %d\n",
			termsafe.SanitizeForDisplay(route.Table),
			termsafe.SanitizeForDisplay(route.Family),
			termsafe.SanitizeForDisplay(route.Destination),
			termsafe.SanitizeForDisplay(route.Kind),
			action,
			route.Preference,
			route.MTU,
		)
	}
	return out.String()
}
