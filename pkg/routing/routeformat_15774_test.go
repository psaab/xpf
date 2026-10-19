package routing

import (
	"strings"
	"testing"
)

// #15774: bare-CIDR default query must list routes contained within (or
// equal to) the query prefix per docs/junos-cli-reference.md:2821, not
// covering supernets.
func TestFormatRouteDestinationBareCIDR15774(t *testing.T) {
	tables := []TableRoutes{{Name: "inet.0", Entries: []RouteEntry{
		{Destination: "0.0.0.0/0", NextHop: "192.0.2.1", Interface: "ge-0-0-0", Protocol: "static", Preference: 5},
		{Destination: "10.0.0.0/8", NextHop: "192.0.2.1", Interface: "ge-0-0-0", Protocol: "static", Preference: 5},
		{Destination: "10.1.0.0/16", NextHop: "192.0.2.1", Interface: "ge-0-0-0", Protocol: "static", Preference: 5},
		{Destination: "10.1.2.0/24", NextHop: "192.0.2.1", Interface: "ge-0-0-0", Protocol: "static", Preference: 5},
		{Destination: "192.168.0.0/24", NextHop: "192.0.2.1", Interface: "ge-0-0-0", Protocol: "static", Preference: 5},
	}}}
	out := FormatRouteDestination(tables, "10.0.0.0/8", "")
	for _, want := range []string{"10.0.0.0/8", "10.1.0.0/16", "10.1.2.0/24"} {
		if !strings.Contains(out, want) {
			t.Errorf("bare CIDR 10.0.0.0/8 missing contained route %s:\n%s", want, out)
		}
	}
	for _, unwanted := range []string{"0.0.0.0/0", "192.168.0.0/24"} {
		if strings.Contains(out, unwanted) {
			t.Errorf("bare CIDR 10.0.0.0/8 leaked non-contained route %s:\n%s", unwanted, out)
		}
	}
	// Bare IP keeps LPM: covering routes only.
	outIP := FormatRouteDestination(tables, "10.1.2.3", "")
	for _, want := range []string{"0.0.0.0/0", "10.0.0.0/8", "10.1.0.0/16", "10.1.2.0/24"} {
		if !strings.Contains(outIP, want) {
			t.Errorf("bare IP LPM missing covering route %s:\n%s", want, outIP)
		}
	}
	if strings.Contains(outIP, "192.168.0.0/24") {
		t.Errorf("bare IP LPM leaked unrelated route:\n%s", outIP)
	}
	// explicit modifiers unchanged
	if out := FormatRouteDestination(tables, "10.0.0.0/8", "exact"); !strings.Contains(out, "10.0.0.0/8") || strings.Contains(out, "10.1.0.0/16") {
		t.Errorf("exact changed:\n%s", out)
	}
}

// #15774: discard/reject must render Junos Discard/Reject lines, never
// dangling ">  to discard via ".
func TestFormatTableJunosDiscardReject15774(t *testing.T) {
	tables := []TableRoutes{{Name: "inet.0", Entries: []RouteEntry{
		{Destination: "198.51.100.0/24", NextHop: "discard", Protocol: "static", Preference: 5},
		{Destination: "198.51.101.0/24", NextHop: "reject", Protocol: "static", Preference: 5},
		{Destination: "10.0.0.0/24", NextHop: "192.0.2.1", Interface: "ge-0-0-0", Protocol: "static", Preference: 5},
	}}}
	out := FormatAllRoutes(tables)
	if !strings.Contains(out, "Discard") {
		t.Errorf("discard route missing Discard line:\n%s", out)
	}
	if !strings.Contains(out, "Reject") {
		t.Errorf("reject route missing Reject line:\n%s", out)
	}
	if strings.Contains(out, "to discard") || strings.Contains(out, "to reject") || strings.Contains(out, "via \n") || strings.Contains(out, "via  \n") {
		t.Errorf("discard/reject rendered as gateway line:\n%s", out)
	}
	if !strings.Contains(out, "to 192.0.2.1 via ge-0-0-0") {
		t.Errorf("ordinary route regressed:\n%s", out)
	}
}

// #15774: terse must list every ECMP leg.
func TestFormatRouteTerseECMP15774(t *testing.T) {
	entries := []RouteEntry{{
		Destination: "10.20.0.0/16", NextHop: "192.0.2.1", Interface: "ge-0-0-0", Protocol: "static", Preference: 5,
		NextHops: []NextHop{{Gateway: "192.0.2.1", Interface: "ge-0-0-0", Weight: 1}, {Gateway: "192.0.2.2", Interface: "ge-0-0-1", Weight: 1}},
	}, {
		Destination: "198.51.100.0/24", NextHop: "discard", Protocol: "static", Preference: 5,
	}}
	out := FormatRouteTerse(entries)
	if strings.Count(out, "10.20.0.0/16") != 2 {
		t.Errorf("terse ECMP rows = %d, want 2:\n%s", strings.Count(out, "10.20.0.0/16"), out)
	}
	if !strings.Contains(out, "192.0.2.2") || !strings.Contains(out, "ge-0-0-1") {
		t.Errorf("terse missing second ECMP leg:\n%s", out)
	}
	if !strings.Contains(out, "discard") {
		t.Errorf("terse discard disposition lost:\n%s", out)
	}
}
