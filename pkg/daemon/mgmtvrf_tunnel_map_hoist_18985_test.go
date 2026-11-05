package daemon

import (
	"go/ast"
	"go/parser"
	"go/token"
	"net"
	"os"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/vishvananda/netlink"
)

// mgmtStaticRoutes18985Config builds a config whose management walks resolve
// many refs: the FRR scoped check walks explicit next-hop interfaces and,
// for address-only next-hops, every interface unit; the desired-route walk
// does the same for its own statics. Tunnel units carry custom devices so a
// wrong (unshared or stale) map changes the resolved names observably.
func mgmtStaticRoutes18985Config() *config.Config {
	return &config.Config{
		Interfaces: config.InterfacesConfig{Interfaces: map[string]*config.InterfaceConfig{
			"fxp0": {
				Name: "fxp0",
				Units: map[int]*config.InterfaceUnit{
					0: {Number: 0, Addresses: []string{"192.0.2.2/24", "2001:db8:10::2/64"}},
					5: {Number: 5, Tunnel: &config.TunnelConfig{Name: "fxp-tun0"}, Addresses: []string{"192.0.3.2/24"}},
				},
			},
			"em0": {
				Name: "em0",
				Units: map[int]*config.InterfaceUnit{
					0: {Number: 0, Addresses: []string{"198.51.100.2/24"}},
					1: {Number: 1, VlanID: 7, Addresses: []string{"203.0.113.2/24"}},
				},
			},
			"ge-0/0/0": {
				Name: "ge-0/0/0",
				Units: map[int]*config.InterfaceUnit{
					0: {Number: 0, Addresses: []string{"203.0.114.2/24"}},
				},
			},
		}},
		RoutingOptions: config.RoutingOptionsConfig{
			StaticRoutes: []*config.StaticRoute{
				{Destination: "10.1.0.0/24", NextHops: []config.NextHopEntry{{Address: "192.0.2.1", Interface: "fxp0"}}},
				{Destination: "10.2.0.0/24", NextHops: []config.NextHopEntry{{Address: "192.0.2.1"}}},
				{Destination: "10.3.0.0/24", NextHops: []config.NextHopEntry{{Address: "192.0.3.1", Interface: "fxp0.5"}}},
				{Destination: "10.4.0.0/24", NextHops: []config.NextHopEntry{{Address: "203.0.114.1"}}},
			},
			Inet6StaticRoutes: []*config.StaticRoute{
				{Destination: "2001:db8:100::/64", NextHops: []config.NextHopEntry{{Address: "2001:db8:10::1", Interface: "fxp0"}}},
				{Destination: "2001:db8:101::/64", NextHops: []config.NextHopEntry{{Address: "2001:db8:10::1"}}},
			},
		},
	}
}

func installMgmtTunnelCount18985(t *testing.T) *int {
	t.Helper()
	orig := mgmtStaticTunnelNameMapFn
	builds := new(int)
	mgmtStaticTunnelNameMapFn = func(c *config.Config) map[string]string {
		*builds++
		return orig(c)
	}
	t.Cleanup(func() { mgmtStaticTunnelNameMapFn = orig })
	return builds
}

// TestMgmtStaticRoutesForFRRBuildsTunnelNameMapOnce18985 pins the FRR
// exclusion walk's cost contract: explicit next-hop interfaces, the
// per-unit connected-interface walk, and IPv6 inference refs share one
// tunnel-name map build per mgmtStaticRoutesForFRR call, and the resolved
// management names (plain, VLAN, and tunnel devices) stay canonical.
func TestMgmtStaticRoutesForFRRBuildsTunnelNameMapOnce18985(t *testing.T) {
	builds := installMgmtTunnelCount18985(t)
	cfg := mgmtStaticRoutes18985Config()
	mgmtSet := map[string]bool{"fxp0": true, "fxp-tun0": true}

	v4, v6 := mgmtStaticRoutesForFRR(cfg, mgmtSet, nil, [2][]netlink.Route{})
	// Only the data-connected static (ge-0/0/0) survives the FRR input;
	// fxp0-explicit, fxp0-connected, and tunnel-connected statics are
	// management-scoped and excluded.
	if len(v4) != 1 || v4[0].Destination != "10.4.0.0/24" {
		t.Errorf("FRR v4 statics = %+v, want only 10.4.0.0/24", v4)
	}
	if len(v6) != 0 {
		t.Errorf("FRR v6 statics = %+v, want none (all management-scoped)", v6)
	}
	if *builds != 1 {
		t.Errorf("built the tunnel-name map %d times across FRR interfaces/units/next-hops, want exactly 1", *builds)
	}

	// Expected resolved names backing the verdicts above.
	tunMap := cfg.TunnelNameMap()
	for ref, want := range map[string]string{
		"fxp0":   "fxp0",
		"fxp0.0": "fxp0",
		"em0.7":  "em0.7",
		"fxp0.5": "fxp-tun0",
	} {
		if got := cfg.ResolveKernelIfNameWith(ref, tunMap); got != want {
			t.Errorf("ResolveKernelIfNameWith(%q) = %q, want %q", ref, got, want)
		}
	}
	if got, ok := mgmtStaticConfigConnectedInterface(cfg, net.ParseIP("192.0.3.1"), mgmtSet, mgmtStaticKernelIfNameResolver(cfg)); !ok || got != "fxp-tun0" {
		t.Errorf("connected interface for tunnel gateway = %q,%v, want fxp-tun0,true", got, ok)
	}

	*builds = 0
	if v4, v6 := mgmtStaticRoutesForFRR(nil, mgmtSet, nil, [2][]netlink.Route{}); v4 != nil || v6 != nil {
		t.Errorf("nil cfg = %v,%v, want nil,nil", v4, v6)
	}
	if *builds != 0 {
		t.Errorf("nil cfg built the tunnel-name map %d times, want 0", *builds)
	}

	*builds = 0
	mgmtStaticRoutesForFRR(&config.Config{}, map[string]bool{}, nil, [2][]netlink.Route{})
	mgmtStaticRoutesForFRR(&config.Config{}, mgmtSet, nil, [2][]netlink.Route{})
	if *builds != 0 {
		t.Errorf("empty mgmt/route shapes built the tunnel-name map %d times, want 0", *builds)
	}
}

// TestMgmtStaticRoutesDesiredBuildsTunnelNameMapOnce18985 pins the
// desired-route walk's cost contract across explicit next-hop interfaces
// in both static families.
func TestMgmtStaticRoutesDesiredBuildsTunnelNameMapOnce18985(t *testing.T) {
	builds := installMgmtTunnelCount18985(t)
	fake := &mgmtStaticRouteFake11449{links: map[string]int{"fxp0": 7, "fxp-tun0": 9}}
	cfg := mgmtStaticRoutes18985Config()
	mgmtSet := map[string]bool{"fxp0": true, "fxp-tun0": true}

	desired := mgmtStaticRoutesDesired(fake, cfg, mgmtSet, [2][]netlink.Route{})
	if len(desired) != 4 {
		t.Errorf("desired routes = %d (%+v), want 4 management-scoped routes", len(desired), desired)
	}
	links := map[int]bool{}
	for _, target := range desired {
		links[target.route.LinkIndex] = true
		for _, hop := range target.route.MultiPath {
			links[hop.LinkIndex] = true
		}
	}
	if !links[7] || !links[9] {
		t.Errorf("desired link indexes = %v, want fxp0 (7) and tunnel device (9) resolutions", links)
	}
	if *builds != 1 {
		t.Errorf("built the tunnel-name map %d times across desired-route next-hops, want exactly 1", *builds)
	}

	*builds = 0
	mgmtStaticRoutesDesired(fake, nil, mgmtSet, [2][]netlink.Route{})
	mgmtStaticRoutesDesired(fake, &config.Config{}, map[string]bool{}, [2][]netlink.Route{})
	mgmtStaticRoutesDesired(fake, &config.Config{}, mgmtSet, [2][]netlink.Route{})
	if *builds != 0 {
		t.Errorf("nil/empty desired shapes built the tunnel-name map %d times, want 0", *builds)
	}
}

// TestMgmtStaticHelpersBuildTunnelNameMapOnce18985 pins the per-call cost
// contract of the three helper walks: the scoped check (explicit interface
// + inferred-IPv6 refs), the connected-interface unit walk, and the
// implicit-link resolver each build the map at most once.
func TestMgmtStaticHelpersBuildTunnelNameMapOnce18985(t *testing.T) {
	builds := installMgmtTunnelCount18985(t)
	cfg := mgmtStaticRoutes18985Config()
	mgmtSet := map[string]bool{"fxp0": true, "fxp-tun0": true}
	fake := &mgmtStaticRouteFake11449{links: map[string]int{"fxp0": 7, "fxp-tun0": 9}}

	route := &config.StaticRoute{Destination: "2001:db8:100::/64", NextHops: []config.NextHopEntry{
		{Address: "2001:db8:10::1", Interface: "fxp0"},
		{Address: "2001:db8:99::1"},
	}}
	inferred := map[string]string{"2001:db8:99::1": "fxp0.5"}
	resolveIfName := mgmtStaticKernelIfNameResolver(cfg)
	if !mgmtStaticRouteIsManagementScoped(cfg, route, mgmtSet, nil, inferred, [2][]netlink.Route{}, resolveIfName) {
		t.Errorf("route with fxp0 + inferred tunnel next-hops not management-scoped")
	}
	if *builds != 1 {
		t.Errorf("scoped check built the tunnel-name map %d times, want exactly 1", *builds)
	}

	*builds = 0
	if got, ok := mgmtStaticConfigConnectedInterface(cfg, net.ParseIP("192.0.3.1"), mgmtSet, mgmtStaticKernelIfNameResolver(cfg)); !ok || got != "fxp-tun0" {
		t.Errorf("connected interface = %q,%v, want fxp-tun0,true", got, ok)
	}
	if *builds != 1 {
		t.Errorf("connected-interface walk built the tunnel-name map %d times, want exactly 1", *builds)
	}

	*builds = 0
	if idx, ok := mgmtStaticImplicitLinkIndex(fake, mgmtSet, net.ParseIP("2001:db8:10::1"),
		netlink.FAMILY_V6, nil, "fxp0.5", mgmtStaticKernelIfNameResolver(cfg)); !ok || idx != 9 {
		t.Errorf("implicit link index = %d,%v, want 9,true (tunnel device)", idx, ok)
	}
	if *builds != 1 {
		t.Errorf("implicit-link resolver built the tunnel-name map %d times, want exactly 1", *builds)
	}

	*builds = 0
	mgmtStaticImplicitLinkIndex(fake, mgmtSet, net.ParseIP("2001:db8:10::1"), netlink.FAMILY_V6, nil, "", mgmtStaticKernelIfNameResolver(cfg))
	if got, ok := mgmtStaticConfigConnectedInterface(&config.Config{}, net.ParseIP("192.0.2.1"), mgmtSet, mgmtStaticKernelIfNameResolver(&config.Config{})); ok || got != "" {
		t.Errorf("empty connected walk = %q,%v, want \"\",false", got, ok)
	}
	if *builds != 0 {
		t.Errorf("empty helper shapes built the tunnel-name map %d times, want 0", *builds)
	}
}

// TestMgmtStaticNoDirectResolveKernelIfNameCensus18985 is the source guard the
// counting seam cannot provide: a site reverted to cfg.ResolveKernelIfName(
// would bypass mgmtStaticTunnelNameMapFn. It uses the existing AST census
// idiom (rather than a new convention), ignores comments, and floors the
// function set plus the shared ResolveKernelIfNameWith resolver so a broken
// scan cannot pass vacuously. The IfNameResolver method-value handoff is not
// a call and is intentionally outside this source file's census.
func TestMgmtStaticNoDirectResolveKernelIfNameCensus18985(t *testing.T) {
	body, err := os.ReadFile("mgmtvrf_static_routes.go")
	if err != nil {
		t.Fatalf("read mgmtvrf_static_routes.go: %v", err)
	}
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "mgmtvrf_static_routes.go", body, 0)
	if err != nil {
		t.Fatalf("parse mgmtvrf_static_routes.go: %v — the scan is broken", err)
	}
	hoisted := map[string]bool{
		"mgmtStaticRoutesDesired":            true,
		"mgmtStaticRouteIsManagementScoped":  true,
		"mgmtStaticConfigConnectedInterface": true,
		"mgmtStaticImplicitLinkIndex":        true,
	}
	found := map[string]bool{}
	resolverFound, resolverUsesWith := false, false
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		if fn.Name.Name == "mgmtStaticKernelIfNameResolver" {
			resolverFound = true
		}
		if !hoisted[fn.Name.Name] && fn.Name.Name != "mgmtStaticKernelIfNameResolver" {
			continue
		}
		found[fn.Name.Name] = true
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			switch sel.Sel.Name {
			case "ResolveKernelIfName":
				t.Errorf("%s contains a direct ResolveKernelIfName( call; resolve via the shared lazy tunnel-name map", fn.Name.Name)
			case "ResolveKernelIfNameWith":
				if fn.Name.Name == "mgmtStaticKernelIfNameResolver" {
					resolverUsesWith = true
				}
			}
			return true
		})
	}
	if len(found) != len(hoisted)+1 {
		t.Errorf("census found %d of %d hoisted functions plus resolver (%v) — the scan is broken", len(found), len(hoisted)+1, found)
	}
	if !resolverFound || !resolverUsesWith {
		t.Error("mgmtStaticKernelIfNameResolver does not call ResolveKernelIfNameWith — the scan or hoist is broken")
	}
}
