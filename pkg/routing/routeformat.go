package routing

import (
	"fmt"
	"net"
	"sort"
	"strings"
)

// protoTag returns a single-letter Junos-style route protocol marker.
func protoTag(proto string) string {
	switch proto {
	case "static":
		return "S"
	case "connected":
		return "C"
	case "bgp":
		return "B"
	case "ospf":
		return "O"
	case "isis":
		return "I"
	case "rip":
		return "R"
	case "dhcp":
		return "D"
	default:
		return "?"
	}
}

// FormatRouteTerse formats routes in Junos "show route terse" style.
// An ECMP route emits one row per leg so no equal-cost path is hidden
// (#15774); a single-path route emits exactly one row as before.
func FormatRouteTerse(entries []RouteEntry) string {
	sorted := make([]RouteEntry, len(entries))
	copy(sorted, entries)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].Destination < sorted[j].Destination
	})

	var buf strings.Builder
	fmt.Fprintf(&buf, "%-3s %-40s %-4s %-20s %s\n", "A/S", "Destination", "P", "Next-hop", "Interface")
	for _, e := range sorted {
		tag := protoTag(e.Protocol)
		marker := "* "
		if len(e.NextHops) > 0 {
			for _, nh := range e.NextHops {
				gw := nh.Gateway
				if gw == "" {
					gw = ">"
				}
				fmt.Fprintf(&buf, "%-3s %-40s %-4s %-20s %s\n", marker, e.Destination, tag, gw, nh.Interface)
			}
			continue
		}
		nh := e.NextHop
		if nh == "" {
			nh = ">"
		}
		fmt.Fprintf(&buf, "%-3s %-40s %-4s %-20s %s\n", marker, e.Destination, tag, nh, e.Interface)
	}
	return buf.String()
}

// FlattenTableRoutes returns every entry across all tables in order.
// Terse views share this flattening so VRF tables are not omitted
// merely because the caller started from the main table (#15774).
func FlattenTableRoutes(allTables []TableRoutes) []RouteEntry {
	var entries []RouteEntry
	for _, table := range allTables {
		entries = append(entries, table.Entries...)
	}
	return entries
}

// FormatRouteEntriesTerse formats all tables in terse style.
func FormatRouteEntriesTerse(allTables []TableRoutes) string {
	return FormatRouteTerse(FlattenTableRoutes(allTables))
}

// appendSplitAF splits routes into inet.0 and inet6.0 tables and appends them.
func appendSplitAF(tables []TableRoutes, prefix string, entries []RouteEntry) []TableRoutes {
	var v4, v6 []RouteEntry
	for _, e := range entries {
		if strings.Contains(e.Destination, ":") {
			v6 = append(v6, e)
		} else {
			v4 = append(v4, e)
		}
	}
	inetName := "inet.0"
	inet6Name := "inet6.0"
	if prefix != "" {
		inetName = prefix + "." + inetName
		inet6Name = prefix + "." + inet6Name
	}
	if len(v4) > 0 {
		tables = append(tables, TableRoutes{Name: inetName, Entries: v4})
	}
	if len(v6) > 0 {
		tables = append(tables, TableRoutes{Name: inet6Name, Entries: v6})
	}
	return tables
}

// FormatRouteDestination formats matching routes across all tables in Junos style.
// The destination is an IP address (or CIDR prefix). For each table that has a
// matching route, it prints a Junos-style header and route entries.
// The modifier controls matching behavior:
//   - "" (empty) with a bare IP: LPM — routes whose prefix contains the IP
//   - "" (empty) with a CIDR: routes contained within or equal to the prefix
//     (docs/junos-cli-reference.md:2821, #15774)
//   - "exact": only show routes matching the exact prefix (network + mask)
//   - "longer": show routes with a strictly more-specific prefix (longer mask)
//   - "orlonger": show routes with equal or more-specific prefix (equal or longer mask)
func FormatRouteDestination(allTables []TableRoutes, destination, modifier string) string {
	// Parse the destination for matching.
	destIP := net.ParseIP(destination)
	var destNet *net.IPNet
	if strings.Contains(destination, "/") {
		_, destNet, _ = net.ParseCIDR(destination)
	} else if destIP != nil {
		if destIP.To4() != nil {
			destNet = &net.IPNet{IP: destIP, Mask: net.CIDRMask(32, 32)}
		} else {
			destNet = &net.IPNet{IP: destIP, Mask: net.CIDRMask(128, 128)}
		}
	}
	if destNet == nil {
		return fmt.Sprintf("invalid destination: %s\n", destination)
	}
	destOnes, destBits := destNet.Mask.Size()

	var buf strings.Builder
	for _, table := range allTables {
		var matches []RouteEntry
		for _, e := range table.Entries {
			_, routeNet, err := net.ParseCIDR(e.Destination)
			if err != nil {
				continue
			}
			routeOnes, _ := routeNet.Mask.Size()

			switch modifier {
			case "exact":
				// Route must match the exact prefix (network + mask length).
				if routeOnes == destOnes && destNet.IP.Equal(routeNet.IP) {
					matches = append(matches, e)
				}
			case "longer":
				// Route must be strictly more-specific (contained within dest, longer mask).
				if routeOnes > destOnes && destNet.Contains(routeNet.IP) {
					matches = append(matches, e)
				}
			case "orlonger":
				// Route must be equal or more-specific (contained within dest, equal or longer mask).
				if routeOnes >= destOnes && destNet.Contains(routeNet.IP) {
					matches = append(matches, e)
				}
			default:
				if strings.Contains(destination, "/") {
					// Bare CIDR: routes contained within or equal to the
					// query prefix (Junos reference :2821).
					if routeOnes >= destOnes && destNet.Contains(routeNet.IP) {
						matches = append(matches, e)
					}
				} else if destBits > 0 && routeOnes <= destOnes && routeNet.Contains(destNet.IP) {
					// Bare IP: LPM covering routes.
					matches = append(matches, e)
				}
			}
		}
		if len(matches) == 0 {
			continue
		}

		// Sort by prefix length (longest first), then by preference.
		sort.Slice(matches, func(i, j int) bool {
			_, ni, _ := net.ParseCIDR(matches[i].Destination)
			_, nj, _ := net.ParseCIDR(matches[j].Destination)
			oi, _ := ni.Mask.Size()
			oj, _ := nj.Mask.Size()
			if oi != oj {
				return oi > oj
			}
			return matches[i].Preference < matches[j].Preference
		})

		formatTableJunos(&buf, table.Name, matches)
	}

	if buf.Len() == 0 {
		return fmt.Sprintf("no routes matching %s\n", destination)
	}
	return buf.String()
}

// FormatRouteSummary formats a Junos-style route summary across all tables.
// Output matches Junos: right-aligned protocol names, right-aligned counts,
// separate inet.0/inet6.0 sections per table, plus Highwater Mark section.
func FormatRouteSummary(allTables []TableRoutes, routerID string) string {
	var buf strings.Builder
	if routerID != "" {
		fmt.Fprintf(&buf, "Router ID: %s\n", routerID)
	}

	totalRoutes := 0
	totalFIB := 0
	for _, table := range allTables {
		if len(table.Entries) == 0 {
			continue
		}
		byProto := make(map[string]int)
		for _, e := range table.Entries {
			byProto[junosProtoName(e.Protocol)]++
		}
		fmt.Fprintf(&buf, "\n%s: %d destinations, %d routes (%d active, 0 holddown, 0 hidden)\n",
			table.Name, distinctDestinationCount(table.Entries), len(table.Entries), len(table.Entries))
		formatSummaryProtos(&buf, byProto)
		totalRoutes += len(table.Entries)
		totalFIB += len(table.Entries)
	}

	// Highwater Mark section — since we don't track historical peaks,
	// report current counts as the highwater mark.
	if totalRoutes > 0 {
		buf.WriteString("\nHighwater Mark:\n")
		fmt.Fprintf(&buf, "  %d routes, %d FIB (currently active)\n", totalRoutes, totalFIB)
	}

	return buf.String()
}

// formatSummaryProtos writes sorted protocol summary lines in Junos format.
func formatSummaryProtos(buf *strings.Builder, byProto map[string]int) {
	protos := make([]string, 0, len(byProto))
	for p := range byProto {
		protos = append(protos, p)
	}
	sort.Strings(protos)
	for _, p := range protos {
		fmt.Fprintf(buf, "%21s%7d routes,%7d active\n", p+":", byProto[p], byProto[p])
	}
}

// FormatAllRoutes formats all routes across all tables in Junos style.
func FormatAllRoutes(allTables []TableRoutes) string {
	var buf strings.Builder
	for _, table := range allTables {
		if len(table.Entries) == 0 {
			continue
		}
		// Sort: by destination prefix, then preference.
		sorted := make([]RouteEntry, len(table.Entries))
		copy(sorted, table.Entries)
		sort.Slice(sorted, func(i, j int) bool {
			if sorted[i].Destination != sorted[j].Destination {
				return sorted[i].Destination < sorted[j].Destination
			}
			return sorted[i].Preference < sorted[j].Preference
		})
		formatTableJunos(&buf, table.Name, sorted)
	}
	if buf.Len() == 0 {
		return "no routes\n"
	}
	return buf.String()
}

// distinctDestinationCount returns the number of distinct destination strings
// in the entries. Multiple route rows for a destination are distinct routes,
// but do not represent additional destinations (#11696).
func distinctDestinationCount(entries []RouteEntry) int {
	destinations := make(map[string]struct{}, len(entries))
	for _, entry := range entries {
		destinations[entry.Destination] = struct{}{}
	}
	return len(destinations)
}

// formatTableJunos writes a Junos-style routing table section.
func formatTableJunos(buf *strings.Builder, tableName string, entries []RouteEntry) {
	routes := len(entries)
	fmt.Fprintf(buf, "\n%s: %d destinations, %d routes (%d active, 0 holddown, 0 hidden)\n",
		tableName, distinctDestinationCount(entries), routes, routes)
	buf.WriteString("+ = Active Route, - = Last Active, * = Both\n\n")

	for _, e := range entries {
		proto := junosProtoName(e.Protocol)
		dest := e.Destination
		// Pad short destinations, let long ones flow naturally.
		if len(dest) < 19 {
			dest = fmt.Sprintf("%-19s", dest)
		}
		fmt.Fprintf(buf, "%s *[%s/%d]\n", dest, proto, e.Preference)
		switch {
		case len(e.NextHops) > 0:
			// ECMP route: one next-hop line per equal-cost path.
			for _, nh := range e.NextHops {
				switch {
				case nh.Gateway != "" && nh.Interface != "":
					fmt.Fprintf(buf, "                    >  to %s via %s\n", nh.Gateway, nh.Interface)
				case nh.Gateway != "":
					fmt.Fprintf(buf, "                    >  to %s\n", nh.Gateway)
				case nh.Interface != "":
					fmt.Fprintf(buf, "                    >  via %s\n", nh.Interface)
				}
			}
		case e.NextHop == "discard":
			buf.WriteString("                    Discard\n")
		case e.NextHop == "reject":
			buf.WriteString("                    Reject\n")
		case e.NextHop != "" && e.NextHop != "direct" && e.Interface != "":
			fmt.Fprintf(buf, "                    >  to %s via %s\n", e.NextHop, e.Interface)
		case e.NextHop != "" && e.NextHop != "direct":
			fmt.Fprintf(buf, "                    >  to %s\n", e.NextHop)
		case e.Interface != "":
			fmt.Fprintf(buf, "                    >  via %s\n", e.Interface)
		}
	}
}

// FormatRouteEntryRows renders the tabular Destination/Next-hop/Interface/
// Proto/Pref rows shared by the local and gRPC protocol/instance views.
// An ECMP entry emits one row per leg; discard/reject entries emit their
// disposition label with no interface (#15774).
func FormatRouteEntryRows(entries []RouteEntry) string {
	var buf strings.Builder
	for _, e := range entries {
		if len(e.NextHops) > 0 {
			for _, nh := range e.NextHops {
				fmt.Fprintf(&buf, "  %-24s %-20s %-14s %-12s %d\n",
					e.Destination, nh.Gateway, nh.Interface, e.Protocol, e.Preference)
			}
			continue
		}
		fmt.Fprintf(&buf, "  %-24s %-20s %-14s %-12s %d\n",
			e.Destination, e.NextHop, e.Interface, e.Protocol, e.Preference)
	}
	return buf.String()
}

// FilterRouteEntriesByProtocol returns entries matching an already
// normalized protocol via RouteProtocolMatches (#15774).
func FilterRouteEntriesByProtocol(entries []RouteEntry, normalized string) []RouteEntry {
	var out []RouteEntry
	for _, e := range entries {
		if RouteProtocolMatches(e.Protocol, normalized) {
			out = append(out, e)
		}
	}
	return out
}

// NormalizeRouteProtocol maps an operator `show route protocol <p>` token to
// the internal protocol name rtProtoName emits, or "" for an unknown token
// (#15236 A52-02). The completion offers Junos/display spellings (direct,
// local, kernel, Access-internal) that never equal the internal names
// (connected, dhcp, ...), so the filter must translate before comparing and
// reject unknown protocols instead of printing a false "(no routes)".
func NormalizeRouteProtocol(token string) string {
	switch strings.ToLower(strings.TrimSpace(token)) {
	case "connected", "direct", "local", "kernel":
		return "connected"
	case "dhcp", "access-internal", "access_internal", "access internal":
		return "dhcp"
	case "static", "bgp", "ospf", "isis", "is-is", "rip", "redirect":
		return strings.ReplaceAll(strings.ToLower(strings.TrimSpace(token)), "is-is", "isis")
	default:
		return ""
	}
}

// RouteProtocolMatches reports whether an entry's internal protocol name
// matches an already-normalized operator protocol.
func RouteProtocolMatches(entryProtocol, normalized string) bool {
	return normalized != "" && strings.EqualFold(entryProtocol, normalized)
}

// junosProtoName maps protocol names to Junos-style names.
func junosProtoName(proto string) string {
	switch proto {
	case "static":
		return "Static"
	case "connected":
		return "Direct"
	case "bgp":
		return "BGP"
	case "ospf":
		return "OSPF"
	case "isis":
		return "IS-IS"
	case "rip":
		return "RIP"
	case "dhcp":
		return "Access-internal"
	case "redirect":
		return "Redirect"
	default:
		return proto
	}
}
