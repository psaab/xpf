package cli

import (
	"net"
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/routing"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// #15723: dangling selectors, unknown subcommands and unrecognised trailing
// filters in `show route` must error instead of widening to a full-table dump
// (or silently dropping the trailing token and running the narrower view the
// operator did not ask for).
//
// RED on base: handleShowRoute(["table"]) fell through to showRoutes();
// ["terse","junk"] ran terse; ["10.0.0.0/24","bogus"] ran the prefix view
// with an empty modifier; ["bogusword"] dumped the full table.

func routeStrictCLI15723(t *testing.T) *CLI {
	t.Helper()
	mk := func(cidr string, proto int) netlink.Route {
		_, n, _ := net.ParseCIDR(cidr)
		return netlink.Route{Dst: n, Protocol: netlink.RouteProtocol(proto), LinkIndex: 1, Gw: net.ParseIP("192.0.2.1")}
	}
	lister := fakeRouteLister{
		v4:    []netlink.Route{mk("10.1.0.0/24", unix.RTPROT_STATIC), mk("10.20.0.0/16", unix.RTPROT_STATIC)},
		vrfV4: []netlink.Route{mk("10.9.0.0/24", unix.RTPROT_STATIC)},
	}
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if _, err := store.SyncApply("routing-instances { blue { instance-type virtual-router; interface reth0.0; routing-options { static { route 10.9.0.0/24 next-hop 192.0.2.1; } } } }", nil); err != nil {
		t.Fatalf("syncapply: %v", err)
	}
	return &CLI{store: store, routing: routing.NewManagerWithRouteListerForTest(lister)}
}

func TestShowRouteRejectsDanglingAndUnknown15723(t *testing.T) {
	cases := [][]string{
		{"table"},
		{"instance"},
		{"protocol"},
		{"bogusword"},
		{"terse", "junk"},
		{"summary", "junk"},
		{"detail", "junk"},
		{"fib", "junk"},
		{"table", "inet.0", "junk"},
		{"table", "inet.0", "protocol", "bgp"},
		{"instance", "blue", "junk"},
		{"protocol", "static", "junk"},
		{"10.0.0.0/24", "bogus"},
		{"10.0.0.0/24", "exact", "junk"},
		{"10.0.0.0/24", "exact", "longer"},
	}
	for _, args := range cases {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			c := routeStrictCLI15723(t)
			var err error
			out := captureStdout(t, func() { err = c.handleShowRoute(args) })
			if err == nil {
				t.Fatalf("handleShowRoute(%v) must error, got nil; output:\n%s", args, out)
			}
			if !strings.Contains(err.Error(), "usage: show route") {
				t.Errorf("error must carry usage, got: %v", err)
			}
			// The full-table dump renders the main-table header; a scoped
			// error path must not emit any route destination.
			if strings.Contains(out, "10.1.0.0/24") || strings.Contains(out, "10.20.0.0/16") || strings.Contains(out, "10.9.0.0/24") {
				t.Errorf("rejected form must not dump routes, got:\n%s", out)
			}
		})
	}
}

func TestShowRouteValidFormsStillRender15723(t *testing.T) {
	valid := []struct {
		args []string
		want string
	}{
		{[]string{"table", "inet.0"}, "10.1.0.0/24"},
		{[]string{"instance", "blue"}, "10.9.0.0/24"},
		{[]string{"protocol", "static"}, "10.1.0.0/24"},
		{[]string{"terse"}, "10.1.0.0/24"},
		{[]string{"summary"}, "inet.0"},
		{[]string{"10.0.0.0/8"}, "10.1.0.0/24"},
		{[]string{"10.1.0.0/24", "exact"}, "10.1.0.0/24"},
		{[]string{"10.0.0.0/8", "longer"}, "10.1.0.0/24"},
		{[]string{"10.0.0.0/8", "orlonger"}, "10.1.0.0/24"},
		{[]string{"10.1.0.1"}, "10.1.0.0/24"},
	}
	for _, tc := range valid {
		t.Run(strings.Join(tc.args, " "), func(t *testing.T) {
			c := routeStrictCLI15723(t)
			var err error
			out := captureStdout(t, func() { err = c.handleShowRoute(tc.args) })
			if err != nil {
				t.Fatalf("handleShowRoute(%v): %v; output:\n%s", tc.args, err, out)
			}
			if !strings.Contains(out, tc.want) {
				t.Errorf("handleShowRoute(%v) output missing %q:\n%s", tc.args, tc.want, out)
			}
		})
	}
	// Bare form still renders the full table.
	c := routeStrictCLI15723(t)
	var err error
	out := captureStdout(t, func() { err = c.handleShowRoute(nil) })
	if err != nil {
		t.Fatalf("bare show route: %v", err)
	}
	if !strings.Contains(out, "10.1.0.0/24") {
		t.Errorf("bare show route must render full table:\n%s", out)
	}
}
