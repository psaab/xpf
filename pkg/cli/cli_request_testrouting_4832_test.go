package cli

// #4832: (*CLI).testRouting (cli_request_testcmd.go) backs
// `run test routing destination <ip-or-prefix> [instance <name>]`. It performs
// a longest-prefix-match route lookup: it normalizes a bare address to a /32
// (v4) or /128 (v6) host CIDR, walks every route the routing Manager returns,
// and keeps the most-specific route whose network contains the destination.
// That arithmetic (the `ones > bestLen` selection, the v4/v6 padding, the
// global-vs-VRF table choice, and the #5125 partial-family warning) can regress
// silently — no test exercised it before this file.
//
// These tests drive the REAL routing.Manager: routing exposes the exported test
// seam NewManagerWithRouteListerForTest, which builds a Manager whose route-read
// domain is backed by a fake netlink read surface (routeLister — unexported, but
// its methods are all exported so a fake in this package satisfies it
// structurally). No root, no live netlink handle. testRouting therefore runs its
// production GetRoutes/GetVRFRoutes path over a synthetic table, and we assert
// which route it selects from the captured stdout.
//
// RED-on-revert: flip the LPM comparison (`>` -> `<`, or `>=` losing the tie
// order), drop the v6 /128 padding, or read GetRoutes() for an `instance` query
// and the destination-specific assertions below fail.

import (
	"fmt"
	"net"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/routing"
	"github.com/vishvananda/netlink"
)

// routeCIDR parses a CIDR string into the masked *net.IPNet, panicking on a
// malformed literal (test-only; the inputs are compile-time constants).
func routeCIDR(s string) *net.IPNet {
	_, n, err := net.ParseCIDR(s)
	if err != nil {
		panic(fmt.Sprintf("routeCIDR: bad CIDR %q: %v", s, err))
	}
	return n
}

// mkRoute builds a netlink.Route with a destination network and gateway. A
// zero-value cidr ("") leaves Dst nil, which routeToEntry renders as the
// family default (0.0.0.0/0 or ::/0).
func mkRoute(cidr, gw string) netlink.Route {
	r := netlink.Route{Gw: net.ParseIP(gw)}
	if cidr != "" {
		r.Dst = routeCIDR(cidr)
	}
	return r
}

// stdV4Routes is a nested-prefix v4 table: a default plus /8 ⊃ /16 ⊃ /24 ⊃ /32
// that all cover 10.1.2.3, so longest-prefix selection is unambiguous per query.
func stdV4Routes() []netlink.Route {
	return []netlink.Route{
		mkRoute("", "203.0.113.1"),          // 0.0.0.0/0 (Dst nil)
		mkRoute("10.0.0.0/8", "10.0.0.254"), // /8
		mkRoute("10.1.0.0/16", "10.1.0.254"),
		mkRoute("10.1.2.0/24", "10.1.2.254"),
		mkRoute("10.1.2.3/32", "10.1.2.3"),
	}
}

// stdV6Routes is the v6 mirror: default plus /32 ⊃ /64 ⊃ /128 covering
// 2001:db8:0:1::5.
func stdV6Routes() []netlink.Route {
	return []netlink.Route{
		mkRoute("", "2001:db8:ffff::1"), // ::/0 (Dst nil)
		mkRoute("2001:db8::/32", "2001:db8::254"),
		mkRoute("2001:db8:0:1::/64", "2001:db8:0:1::254"),
		mkRoute("2001:db8:0:1::5/128", "2001:db8:0:1::5"),
	}
}

// fakeRouteLister is a routeLister double (satisfied structurally). RouteList
// serves the main table (global lookups); RouteListFiltered serves the VRF
// table (instance lookups); LinkByName resolves the VRF device. Each read is
// split by address family exactly as the kernel dump path is, so the reader's
// per-family concatenation is exercised end to end.
type fakeRouteLister struct {
	v4, v6       []netlink.Route // main table
	vrfV4, vrfV6 []netlink.Route // VRF (instance) table
	failV6       bool            // simulate a per-family (v6) main-table dump failure (#5125)
	vrfLink      netlink.Link    // returned by LinkByName when non-nil
	vrfLinkErr   error           // if set, LinkByName fails (VRF not found)
}

func (f fakeRouteLister) RouteList(_ netlink.Link, family int) ([]netlink.Route, error) {
	if family == netlink.FAMILY_V6 {
		if f.failV6 {
			return nil, fmt.Errorf("simulated netlink dump failure for IPv6")
		}
		return f.v6, nil
	}
	return f.v4, nil
}
func (f fakeRouteLister) RouteListFilteredIter(family int, _ *netlink.Route, _ uint64, fn func(netlink.Route) bool) error {
	routes, err := f.RouteList(nil, family)
	if err != nil {
		return err
	}
	for _, route := range routes {
		if !fn(route) {
			break
		}
	}
	return nil
}

func (f fakeRouteLister) RouteListFiltered(family int, _ *netlink.Route, _ uint64) ([]netlink.Route, error) {
	if family == netlink.FAMILY_V6 {
		return f.vrfV6, nil
	}
	return f.vrfV4, nil
}

func (f fakeRouteLister) LinkByIndex(int) (netlink.Link, error) {
	return &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: "ge-0-0-0"}}, nil
}

func (f fakeRouteLister) LinkByName(name string) (netlink.Link, error) {
	if f.vrfLinkErr != nil {
		return nil, f.vrfLinkErr
	}
	if f.vrfLink != nil {
		return f.vrfLink, nil
	}
	return nil, fmt.Errorf("link %q not found", name)
}

// cliWithRoutes wires a real routing.Manager (route-read domain backed by the
// fake) into a bare CLI so testRouting runs its production lookup path.
func cliWithRoutes(f fakeRouteLister) *CLI {
	return &CLI{routing: routing.NewManagerWithRouteListerForTest(f)}
}

// TestTestRoutingLongestPrefix4832 is the core table-driven LPM assertion: for
// each destination the MOST-SPECIFIC covering route must win, across v4, v6,
// the default fallback, and an already-CIDR input (which skips /32 padding).
func TestTestRoutingLongestPrefix4832(t *testing.T) {
	c := cliWithRoutes(fakeRouteLister{v4: stdV4Routes(), v6: stdV6Routes()})

	cases := []struct {
		name     string
		dest     string
		wantDest string // expected "Destination:" line value
	}{
		{"v4 exact host wins over covering /24,/16,/8,default", "10.1.2.3", "10.1.2.3/32"},
		{"v4 /24 wins when no /32 covers", "10.1.2.99", "10.1.2.0/24"},
		{"v4 /16 wins when no /24 covers", "10.1.99.99", "10.1.0.0/16"},
		{"v4 /8 wins when no /16 covers", "10.200.0.1", "10.0.0.0/8"},
		{"v4 default is the last resort", "8.8.8.8", "0.0.0.0/0"},
		{"v4 CIDR input matches its own /24 (no /32 padding)", "10.1.2.0/24", "10.1.2.0/24"},
		{"v6 exact host wins over covering /64,/32,default", "2001:db8:0:1::5", "2001:db8:0:1::5/128"},
		{"v6 /64 wins when no /128 covers", "2001:db8:0:1::99", "2001:db8:0:1::/64"},
		{"v6 /32 wins when no /64 covers", "2001:db8:1::1", "2001:db8::/32"},
		{"v6 default is the last resort", "2001:dead::1", "::/0"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out := captureStdout(t, func() {
				if err := c.testRouting([]string{"destination", tc.dest}); err != nil {
					t.Fatalf("testRouting(%q) error = %v", tc.dest, err)
				}
			})
			if !strings.Contains(out, "Routing lookup for "+tc.dest+":") {
				t.Errorf("missing lookup header for %q\n%s", tc.dest, out)
			}
			wantLine := "Destination: " + tc.wantDest
			if !strings.Contains(out, wantLine) {
				t.Errorf("dest %q: want selected route %q\n%s", tc.dest, wantLine, out)
			}
			// Guard against a false pass where a broader route also renders:
			// the selected line must be the ONLY "Destination:" line.
			if n := strings.Count(out, "Destination:"); n != 1 {
				t.Errorf("dest %q: expected exactly one Destination line, got %d\n%s", tc.dest, n, out)
			}
		})
	}
}

// TestTestRoutingNoMatch4832 proves the no-covering-route path: with a table
// that has NO default and NO covering prefix, the lookup reports no match
// rather than picking an unrelated route or panicking.
func TestTestRoutingNoMatch4832(t *testing.T) {
	c := cliWithRoutes(fakeRouteLister{
		v4: []netlink.Route{mkRoute("10.1.2.0/24", "10.1.2.254")},
		v6: []netlink.Route{mkRoute("2001:db8::/32", "2001:db8::254")},
	})

	for _, dest := range []string{"8.8.8.8", "2001:dead::1"} {
		out := captureStdout(t, func() {
			if err := c.testRouting([]string{"destination", dest}); err != nil {
				t.Fatalf("testRouting(%q) error = %v", dest, err)
			}
		})
		if !strings.Contains(out, "No matching route found") {
			t.Errorf("dest %q: expected no-match message\n%s", dest, out)
		}
		if strings.Contains(out, "Destination:") {
			t.Errorf("dest %q: no route should have been selected\n%s", dest, out)
		}
	}
}

// TestTestRoutingInstanceUsesVRFTable4832 proves an `instance <name>` query
// reads the VRF table (RouteListFiltered), NOT the global table: the VRF-only
// route is selected, the global 10.x route is invisible, and the header names
// the instance.
func TestTestRoutingInstanceUsesVRFTable4832(t *testing.T) {
	f := fakeRouteLister{
		v4:      stdV4Routes(), // global table — must be ignored for instance queries
		vrfV4:   []netlink.Route{mkRoute("172.16.0.0/16", "172.16.0.254"), mkRoute("172.16.5.0/24", "172.16.5.254")},
		vrfLink: &netlink.Vrf{LinkAttrs: netlink.LinkAttrs{Name: "vrf-red"}, Table: 100},
	}
	c := cliWithRoutes(f)

	// Instance lookup selects the most-specific VRF route.
	out := captureStdout(t, func() {
		if err := c.testRouting([]string{"destination", "172.16.5.9", "instance", "red"}); err != nil {
			t.Fatalf("testRouting instance error = %v", err)
		}
	})
	if !strings.Contains(out, "Routing lookup in instance red for 172.16.5.9:") {
		t.Errorf("instance header missing\n%s", out)
	}
	if !strings.Contains(out, "Destination: 172.16.5.0/24") {
		t.Errorf("expected VRF /24 to win\n%s", out)
	}

	// A destination only in the GLOBAL table must NOT resolve via the instance,
	// proving the VRF table (not GetRoutes) was consulted.
	out = captureStdout(t, func() {
		if err := c.testRouting([]string{"destination", "10.1.2.3", "instance", "red"}); err != nil {
			t.Fatalf("testRouting instance (global dest) error = %v", err)
		}
	})
	if !strings.Contains(out, "No matching route found") {
		t.Errorf("global-only destination must not resolve inside the VRF\n%s", out)
	}
}

// TestTestRoutingInstanceNotFound4832 proves a VRF-resolution failure (empty
// table) stays fatal: testRouting returns the wrapped error.
func TestTestRoutingInstanceNotFound4832(t *testing.T) {
	c := cliWithRoutes(fakeRouteLister{vrfLinkErr: fmt.Errorf("no such device")})
	err := c.testRouting([]string{"destination", "10.0.0.1", "instance", "ghost"})
	if err == nil {
		t.Fatalf("expected a fatal error when the VRF cannot be resolved")
	}
	if !strings.Contains(err.Error(), "get routes") {
		t.Errorf("error should wrap the route-read failure, got %v", err)
	}
}

// TestTestRoutingPartialFamilyWarning4832 proves the #5125 contract: when one
// address family's dump fails but the other succeeds, testRouting warns and
// STILL completes the lookup against the usable partial table (it does not bail).
func TestTestRoutingPartialFamilyWarning4832(t *testing.T) {
	c := cliWithRoutes(fakeRouteLister{v4: stdV4Routes(), failV6: true})

	out := captureStdout(t, func() {
		if err := c.testRouting([]string{"destination", "10.1.2.3"}); err != nil {
			t.Fatalf("testRouting must not bail on a partial-family failure; got %v", err)
		}
	})
	if !strings.Contains(out, "warning: partial route data") {
		t.Errorf("expected a partial-data warning\n%s", out)
	}
	if !strings.Contains(out, "Destination: 10.1.2.3/32") {
		t.Errorf("lookup must still resolve against the usable v4 partial\n%s", out)
	}
}

// TestTestRoutingUsageAndNilManager4832 covers the two guard paths: no
// routing Manager, and a missing destination argument.
func TestTestRoutingUsageAndNilManager4832(t *testing.T) {
	// Nil routing Manager: report unavailable, no error.
	out := captureStdout(t, func() {
		if err := (&CLI{}).testRouting([]string{"destination", "10.0.0.1"}); err != nil {
			t.Fatalf("nil-manager path should not error; got %v", err)
		}
	})
	if !strings.Contains(out, "Routing manager not available") {
		t.Errorf("expected unavailable message\n%s", out)
	}

	// Missing destination: usage line.
	c := cliWithRoutes(fakeRouteLister{v4: stdV4Routes()})
	out = captureStdout(t, func() {
		if err := c.testRouting([]string{"instance", "red"}); err != nil {
			t.Fatalf("usage path should not error; got %v", err)
		}
	})
	if !strings.Contains(out, "usage: test routing destination") {
		t.Errorf("expected usage message\n%s", out)
	}
}
