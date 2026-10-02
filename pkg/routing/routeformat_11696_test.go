package routing

import (
	"strings"
	"testing"
)

// #11696: destinations must count distinct Destination strings, not rows.
// Two entries sharing a prefix (differing Preference) render as separate
// rows but are one destination; routes/active stay per-row (every kernel
// FIB row IS installed/active, so active==routes is defensible and kept).
func TestFormatAllRoutesCountsDistinctDestinations11696(t *testing.T) {
	tables := []TableRoutes{{
		Name: "inet.0",
		Entries: []RouteEntry{
			{Destination: "10.0.0.0/24", NextHop: "192.0.2.1", Interface: "ge-0-0-0", Protocol: "static", Preference: 5},
			{Destination: "10.0.0.0/24", NextHop: "192.0.2.2", Interface: "ge-0-0-1", Protocol: "ospf", Preference: 10},
			{Destination: "10.0.1.0/24", NextHop: "192.0.2.1", Interface: "ge-0-0-0", Protocol: "static", Preference: 5},
		},
	}}
	out := FormatAllRoutes(tables)
	want := "inet.0: 2 destinations, 3 routes (3 active, 0 holddown, 0 hidden)"
	if !strings.Contains(out, want) {
		t.Errorf("FormatAllRoutes header = %q, want substring %q\nfull output:\n%s", out, want, out)
	}
}

// #11696: the summary header has the same per-row fabrication.
func TestFormatRouteSummaryCountsDistinctDestinations11696(t *testing.T) {
	tables := []TableRoutes{{
		Name: "inet.0",
		Entries: []RouteEntry{
			{Destination: "10.0.0.0/24", NextHop: "192.0.2.1", Interface: "ge-0-0-0", Protocol: "static", Preference: 5},
			{Destination: "10.0.0.0/24", NextHop: "192.0.2.2", Interface: "ge-0-0-1", Protocol: "ospf", Preference: 10},
		},
	}}
	out := FormatRouteSummary(tables, "")
	want := "inet.0: 1 destinations, 2 routes (2 active, 0 holddown, 0 hidden)"
	if !strings.Contains(out, want) {
		t.Errorf("FormatRouteSummary header = %q, want substring %q\nfull output:\n%s", out, want, out)
	}
}

// #11696: a prefix query must count the FILTERED rows, not the whole table.
// The table holds 3 routes but only 2 match 10.0.0.0/16 orlonger.
func TestFormatRouteDestinationHeaderCountsFilteredRows11696(t *testing.T) {
	tables := []TableRoutes{{
		Name: "inet.0",
		Entries: []RouteEntry{
			{Destination: "10.0.0.0/24", NextHop: "192.0.2.1", Interface: "ge-0-0-0", Protocol: "static", Preference: 5},
			{Destination: "10.0.1.0/24", NextHop: "192.0.2.1", Interface: "ge-0-0-0", Protocol: "static", Preference: 5},
			{Destination: "192.168.0.0/24", NextHop: "192.0.2.1", Interface: "ge-0-0-0", Protocol: "static", Preference: 5},
		},
	}}
	out := FormatRouteDestination(tables, "10.0.0.0/16", "orlonger")
	want := "inet.0: 2 destinations, 2 routes (2 active, 0 holddown, 0 hidden)"
	if !strings.Contains(out, want) {
		t.Errorf("FormatRouteDestination header = %q, want substring %q\nfull output:\n%s", out, want, out)
	}
	if strings.Contains(out, "192.168.0.0/24") {
		t.Errorf("unmatched route leaked into destination view:\n%s", out)
	}
}

// #11696: distinct counting applies inside the filtered match set too:
// 3 matching rows over 2 distinct destinations.
func TestFormatRouteDestinationCountsDistinctMatches11696(t *testing.T) {
	tables := []TableRoutes{{
		Name: "inet.0",
		Entries: []RouteEntry{
			{Destination: "10.0.0.0/24", NextHop: "192.0.2.1", Interface: "ge-0-0-0", Protocol: "static", Preference: 5},
			{Destination: "10.0.0.0/24", NextHop: "192.0.2.2", Interface: "ge-0-0-1", Protocol: "ospf", Preference: 10},
			{Destination: "10.0.1.0/24", NextHop: "192.0.2.1", Interface: "ge-0-0-0", Protocol: "static", Preference: 5},
		},
	}}
	out := FormatRouteDestination(tables, "10.0.0.0/16", "orlonger")
	want := "inet.0: 2 destinations, 3 routes (3 active, 0 holddown, 0 hidden)"
	if !strings.Contains(out, want) {
		t.Errorf("FormatRouteDestination header = %q, want substring %q\nfull output:\n%s", out, want, out)
	}
}
