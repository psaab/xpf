package grpcapi

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #10235: the gRPC `routing-instances-detail` render looped over
// ri.StaticRoutes only — a per-instance `rib inet6.0` static
// (ri.Inet6StaticRoutes, populated by compileRoutingInstances and classified
// by StaticRouteExclusions) counted nowhere and rendered nowhere. The v6
// per-instance sibling of the #10001 gap.
//
// RED-ON-REVERT: drop the Inet6StaticRoutes block (or its exclusion
// consultation) from showRoutingInstancesDetail and the row assertions fail —
// the v6 rows vanish while the v4 twin keeps rendering.
func TestRoutingInstancesDetailShowsInet6StaticsWithReason_10235(t *testing.T) {
	v6leak := &config.StaticRoute{Destination: "2001:db8:100::/48", NextTable: "target"}
	v6healthy := &config.StaticRoute{
		Destination: "2001:db8:200::/48",
		NextHops:    []config.NextHopEntry{{Address: "2001:db8::1"}},
	}
	v6discard := &config.StaticRoute{Destination: "2001:db8:300::/48", Discard: true}
	v4healthy := &config.StaticRoute{
		Destination: "192.168.0.0/16",
		NextHops:    []config.NextHopEntry{{Address: "10.0.0.1"}},
	}
	cfg := &config.Config{
		RoutingInstances: []*config.RoutingInstanceConfig{
			{Name: "target", InstanceType: "virtual-router"},
			{
				Name:             "holder",
				InstanceType:     "virtual-router",
				StaticRoutes:     []*config.StaticRoute{v4healthy},
				Inet6StaticRoutes: []*config.StaticRoute{v6leak, v6healthy, v6discard},
			},
		},
	}
	// Ground truth. Without these pins a predicate that stopped recognising
	// the shape would make every assertion below agree on "installed" and the
	// whole cell would pass over an empty set.
	const wantReason = "next-table is not supported under a routing-instance — no ip rule is installed for it"
	excluded := config.StaticRouteExclusions(cfg)
	if got := excluded[v6leak]; got != wantReason {
		t.Fatalf("fixture no longer constructs a dropped v6 next-table leak: reason = %q, want %q", got, wantReason)
	}
	for name, sr := range map[string]*config.StaticRoute{"v6healthy": v6healthy, "v6discard": v6discard, "v4healthy": v4healthy} {
		if got := excluded[sr]; got != "" {
			t.Fatalf("fixture's %s route is not healthy: reason = %q", name, got)
		}
	}

	s := &Server{}
	var buf strings.Builder
	s.showRoutingInstancesDetail(cfg, &buf)
	out := buf.String()

	// 1. Keep the existing v4 block byte-identical and add a sibling v6 block.
	if !strings.Contains(out, "Static routes: 1") ||
		!strings.Contains(out, "Static routes (inet6.0): 3") {
		t.Fatalf("gRPC `routing-instances-detail` does not preserve the v4 block and add a v6 block:\n%s", out)
	}
	// 2. Every configured v6 row is VISIBLE in the same row format as v4.
	for _, row := range []string{
		"2001:db8:100::/48 -> next-table target",
		"2001:db8:200::/48 -> 2001:db8::1",
		"2001:db8:300::/48 -> discard",
	} {
		if !strings.Contains(out, row) {
			t.Fatalf("gRPC `routing-instances-detail` omits the configured v6 row %q:\n%s", row, out)
		}
	}
	// 3. ... WITH the leak's refusal reason on the adjacent line — the CLI
	//    twin's shape (v4 next-table arm + printStaticRouteNotInstalled).
	lines := strings.Split(out, "\n")
	row := -1
	for i, l := range lines {
		if strings.Contains(l, "2001:db8:100::/48 -> next-table target") {
			row = i
			break
		}
	}
	if row < 0 || row+1 >= len(lines) || !strings.Contains(lines[row+1], "NOT INSTALLED: "+wantReason) {
		t.Fatalf("gRPC detail shows the v6 leak without its exclusion reason — a dropped route "+
			"rendered as configured reads as installed (#6534 archetype):\n%s", out)
	}
	// 4. Negative controls: exactly ONE annotation (the leak; every healthy
	//    row stays quiet), and the v4 twin still renders in the same block.
	if n := strings.Count(out, "NOT INSTALLED"); n != 1 {
		t.Errorf("NOT INSTALLED annotations = %d, want exactly 1 (the v6 leak; the healthy "+
			"routes must stay quiet):\n%s", n, out)
	}
	if !strings.Contains(out, "192.168.0.0/16 -> 10.0.0.1") {
		t.Errorf("v4 instance static no longer renders beside the v6 rows:\n%s", out)
	}
}
