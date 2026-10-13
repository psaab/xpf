package userspace

import (
	"slices"
	"strings"
	"syscall"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/vishvananda/netlink"
)

// #12507: end to end from a compiled config to the published snapshot.
// Helper-supported mask padding is written canonically and published with no
// refusal; helper-refused padding is published verbatim, so the helper fails
// the snapshot closed, and the snapshot stamps name exactly those rows.

func hasPaddedMask12507(value string) bool {
	slash := strings.LastIndexByte(value, '/')
	return slash >= 0 && len(value)-slash-1 > 1 && value[slash+1] == '0'
}

func hasRoute12507(routes []RouteSnapshot, table, destination string, discard bool) bool {
	return slices.ContainsFunc(routes, func(route RouteSnapshot) bool {
		return route.Table == table && route.Destination == destination && route.Discard == discard
	})
}

func TestPaddedMaskHelperSupportedPublishesCanonical12507(t *testing.T) {
	// A bind-less (policy-based) VPN only arrives through a tolerant load:
	// strict commit requires bind-interface (#10638).
	cfg := compileLenientSet9523(t, []string{
		"set routing-options static route 10.0.0.0/08 discard",
		"set routing-options rib inet6.0 static route 2001:db8::/032 discard",
		"set security ipsec vpn pv traffic-selector t4 local-ip 10.0.0.0/08",
		"set security ipsec vpn pv traffic-selector t4 remote-ip 192.0.2.0/24",
		"set security ipsec vpn pv traffic-selector t6 local-ip 2001:db8:1::/048",
		"set security ipsec vpn pv traffic-selector t6 remote-ip 2001:db8:2::/048",
	})
	snap := mustBuildSnapshot(t, cfg, config.UserspaceConfig{}, 1, 0)
	if !hasRoute12507(snap.Routes, "inet.0", "10.0.0.0/8", true) ||
		!hasRoute12507(snap.Routes, "inet6.0", "2001:db8::/32", true) {
		t.Fatalf("canonical discard routes not published: %+v", snap.Routes)
	}
	for _, route := range snap.Routes {
		if hasPaddedMask12507(route.Destination) {
			t.Fatalf("padded destination reached the wire: %+v", route)
		}
	}
	for _, want := range []IpsecBindlessSelectorSnapshot{
		{LocalTS: "10.0.0.0/8", RemoteTS: "192.0.2.0/24"},
		{LocalTS: "2001:db8:1::/48", RemoteTS: "2001:db8:2::/48"},
	} {
		if !snap.BindlessSelectorFenceEnabled || !slices.Contains(snap.BindlessSelectorRows, want) {
			t.Fatalf("fence row %+v missing: enabled=%v rows=%+v",
				want, snap.BindlessSelectorFenceEnabled, snap.BindlessSelectorRows)
		}
	}
	// No refusal anywhere: the simulator and the commit-confirmed rollback
	// preflight read PolicyContentRejectionReasons.
	if reasons := PolicyContentRejectionReasons(cfg, nil); len(reasons) != 0 {
		t.Fatalf("helper-supported padding reported as a refusal: %v", reasons)
	}
	if got := snap.Capabilities.PolicyContentRejected; len(got) != 0 {
		t.Fatalf("snapshot stamp claims a refusal: %v", got)
	}
}

func TestPaddedMaskHelperRefusedStampParity12507(t *testing.T) {
	cfg := compileLenientSet9523(t, []string{
		"set routing-options static route 10.0.0.0/008 discard",
		"set routing-options rib inet6.0 static route 2001:db8::/0032 next-hop 2001:db8:ffff::1",
		// Excluded from the FIB, so never sent to the helper: no stamp. (A
		// distinct /8: "10.2.0.0/008" would fold into 10.0.0.0/008 above.)
		"set routing-options static route 11.0.0.0/008 next-hop 192.0.2.1 no-install",
		"set routing-instances blue instance-type virtual-router",
		"set routing-instances blue routing-options static route 10.1.0.0/008 discard",
		"set security ipsec vpn pv traffic-selector t1 local-ip 10.20.0.0/016",
		"set security ipsec vpn pv traffic-selector t1 remote-ip 192.0.2.0/24",
		// Route-based: no fence row, so its selector never reaches the helper.
		"set security ipsec vpn rb bind-interface st0",
		"set security ipsec vpn rb traffic-selector t1 local-ip 10.30.0.0/016",
		"set security ipsec vpn rb traffic-selector t1 remote-ip 192.0.2.0/24",
	})
	want := PolicyContentRejectionReasons(cfg, nil)
	for _, fragment := range []string{
		`static route "10.0.0.0/008" in table "inet.0"`,
		`static route "2001:db8::/0032" in table "inet6.0"`,
		`static route "10.1.0.0/008" in table "blue.inet.0"`,
		`IPsec VPN "pv" bind-less selector fence row local_ts "10.20.0.0/016"`,
	} {
		if !slices.ContainsFunc(want, func(reason string) bool { return strings.Contains(reason, fragment) }) {
			t.Errorf("mirror omitted %s: %v", fragment, want)
		}
	}
	if len(want) != 4 {
		t.Fatalf("mirror must name exactly the four published refusals, got %d: %v", len(want), want)
	}
	noInstall := false
	for _, route := range cfg.RoutingOptions.StaticRoutes {
		if route.Destination == "11.0.0.0/008" {
			noInstall = config.StaticRouteExclusions(cfg)[route] != ""
		}
	}
	if !noInstall {
		t.Fatal("fixture: the no-install helper-refused route must exist and be excluded")
	}

	snap := mustBuildSnapshot(t, cfg, config.UserspaceConfig{}, 1, 0)
	if !slices.Equal(snap.Capabilities.PolicyContentRejected, want) {
		t.Fatalf("full-build stamp = %v, want mirror %v", snap.Capabilities.PolicyContentRejected, want)
	}
	if scheduled := publishCIDRMaskSchedulerSnapshot12122(t, cfg); !slices.Equal(scheduled.Capabilities.PolicyContentRejected, want) {
		t.Fatalf("scheduler-republish stamp = %v, want mirror %v", scheduled.Capabilities.PolicyContentRejected, want)
	}

	// Fail-closed, never fail-open: the discard route and the fence row are
	// published verbatim, so the helper refuses the snapshot rather than
	// forwarding 10/8 via a less-specific route or leaving cleartext unfenced.
	if !hasRoute12507(snap.Routes, "inet.0", "10.0.0.0/008", true) {
		t.Fatalf("helper-refused discard route was not published: %+v", snap.Routes)
	}
	if !slices.Contains(snap.BindlessSelectorRows,
		IpsecBindlessSelectorSnapshot{LocalTS: "10.20.0.0/016", RemoteTS: "192.0.2.0/24"}) {
		t.Fatalf("helper-refused fence row was not published: %+v", snap.BindlessSelectorRows)
	}

	// Truthfulness: every stamped value is on the wire, and every
	// helper-refused value on the wire is stamped.
	var wire []string
	for _, route := range snap.Routes {
		if config.CIDRMaskHelperRefusesPadding(route.Destination) {
			wire = append(wire, route.Destination)
		}
	}
	for _, row := range snap.BindlessSelectorRows {
		for _, value := range []string{row.LocalTS, row.RemoteTS} {
			if config.CIDRMaskHelperRefusesPadding(value) {
				wire = append(wire, value)
			}
		}
	}
	if len(wire) != len(want) {
		t.Fatalf("wire carries %d helper-refused values %v, stamps name %d: %v", len(wire), wire, len(want), want)
	}
	for _, value := range wire {
		if !slices.ContainsFunc(want, func(reason string) bool { return strings.Contains(reason, `"`+value+`"`) }) {
			t.Fatalf("published helper-refused value %q has no stamp: %v", value, want)
		}
	}
}

// The refusal must not depend on runtime state the cfg-only mirror cannot
// see. Each case pairs a helper-refused route with a canonical control that
// the same runtime filter drops, proving the filter is active.
func TestHelperRefusedRoutePublishedPastRuntimeFilters12507(t *testing.T) {
	t.Run("unresolved-recursive-gateway", func(t *testing.T) {
		cfg := &config.Config{}
		cfg.RoutingOptions.StaticRoutes = []*config.StaticRoute{
			{Destination: "10.0.0.0/008", NextHops: []config.NextHopEntry{{Address: "203.0.113.1"}}},
			{Destination: "10.9.0.0/16", NextHops: []config.NextHopEntry{{Address: "203.0.113.1"}}},
		}
		routes, _, err := buildRouteSnapshots(cfg, []InterfaceSnapshot{{Name: "ge-0-0-0", Ifindex: 2}}, nil)
		if err != nil {
			t.Fatalf("buildRouteSnapshots: %v", err)
		}
		if _, ok := findRouteSnapshot9955(routes, "10.9.0.0/16", ""); ok {
			t.Fatalf("control: recursive-only route should be skipped (#11317): %+v", routes)
		}
		if _, ok := findRouteSnapshot9955(routes, "10.0.0.0/008", ""); !ok {
			t.Fatalf("helper-refused route dropped by gateway resolution: %+v", routes)
		}
	})
	t.Run("ip-monitoring-overlay", func(t *testing.T) {
		cfg := &config.Config{}
		cfg.RoutingOptions.StaticRoutes = []*config.StaticRoute{
			{Destination: "10.0.0.0/008", Discard: true},
			{Destination: "10.9.0.0/16", Discard: true},
		}
		routes, _, err := buildRouteSnapshots(cfg, nil, []config.RouteOverlayEntry{
			{Destination: "10.0.0.0/8", NextHop: "172.16.80.1", Policy: "p"},
			{Destination: "10.9.0.0/16", NextHop: "172.16.80.1", Policy: "p"},
		})
		if err != nil {
			t.Fatalf("buildRouteSnapshots: %v", err)
		}
		if hasRoute12507(routes, "inet.0", "10.9.0.0/16", true) {
			t.Fatalf("control: overlay should replace the discard route: %+v", routes)
		}
		if !hasRoute12507(routes, "inet.0", "10.0.0.0/008", true) {
			t.Fatalf("helper-refused route removed by the overlay: %+v", routes)
		}
	})
	t.Run("live-ip-rule-mirror", func(t *testing.T) {
		orig := ruleListFn
		t.Cleanup(func() { ruleListFn = orig })
		ruleListFn = func(family int) ([]netlink.Rule, error) {
			if family != syscall.AF_INET {
				return nil, nil
			}
			return []netlink.Rule{
				{Dst: mustCIDR9955(t, "10.0.0.0/8"), Table: 501, Priority: 32001},
				{Dst: mustCIDR9955(t, "10.9.0.0/16"), Table: 501, Priority: 32002},
			}, nil
		}
		cfg := defaultIngressConfig9955(1)
		cfg.RoutingOptions.StaticRoutes = []*config.StaticRoute{
			{Destination: "10.0.0.0/008", NextTable: "red"},
			{Destination: "10.9.0.0/16", NextTable: "red"},
		}
		routes, _, err := buildRouteSnapshots(cfg, nil, nil)
		if err != nil {
			t.Fatalf("buildRouteSnapshots: %v", err)
		}
		control := 0
		for _, route := range routes {
			if route.Destination == "10.9.0.0/16" {
				control++
				if route.RulePriority != 32002 {
					t.Fatalf("control: live rule should replace the config leak row: %+v", route)
				}
			}
		}
		if control != 1 {
			t.Fatalf("control: want only the live leak row, got %d: %+v", control, routes)
		}
		if _, ok := findRouteSnapshot9955(routes, "10.0.0.0/008", "red"); !ok {
			t.Fatalf("helper-refused leak removed by the live ip-rule mirror: %+v", routes)
		}
	})
	// The cfg-only mirror reports the same route the gateway-resolution case
	// published, with no interface or overlay input.
	cfg := &config.Config{}
	cfg.RoutingOptions.StaticRoutes = []*config.StaticRoute{
		{Destination: "10.0.0.0/008", NextHops: []config.NextHopEntry{{Address: "203.0.113.1"}}},
	}
	if got := collectStaticRouteCIDRMaskRejections(cfg); len(got) != 1 {
		t.Fatalf("mirror must report the published helper-refused route once, got %v", got)
	}
}
