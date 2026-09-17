package grpcapi

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #10001: the gRPC `routing-instances-detail` render handled
// Discard/Reject/NextHops only. A next-table static has no NextHops, so it
// counted toward "Static routes: N" but emitted no row — and the loop never
// consulted StaticRouteExclusions, so even the refusal reason was invisible.
// Tolerant-config visibility gap: the state is reachable only via the lenient
// load / peer-sync path (#5830 hard-rejects a per-instance next-table at
// strict commit), which is exactly when the operator most needs the surface
// to say what was dropped and why. Installation is unaffected.
//
// RED-ON-REVERT: drop the NextTable arm (or the exclusion consultation) from
// showRoutingInstancesDetail and the row assertion fails — the leak counts
// toward the total but renders nothing.
func TestRoutingInstancesDetailShowsNextTableWithReason_10001(t *testing.T) {
	leak := &config.StaticRoute{Destination: "10.0.0.0/8", NextTable: "target"}
	healthy := &config.StaticRoute{
		Destination: "192.168.0.0/16",
		NextHops:    []config.NextHopEntry{{Address: "10.0.0.1"}},
	}
	cfg := &config.Config{
		RoutingInstances: []*config.RoutingInstanceConfig{
			{Name: "target", InstanceType: "virtual-router"},
			{
				Name:         "leaker",
				InstanceType: "virtual-router",
				StaticRoutes: []*config.StaticRoute{leak, healthy},
			},
		},
	}

	// Ground truth. Without these pins a predicate that stopped recognising
	// the shape would make every assertion below agree on "installed" and the
	// whole cell would pass over an empty set.
	const wantReason = "next-table is not supported under a routing-instance — no ip rule is installed for it"
	excluded := config.StaticRouteExclusions(cfg)
	if got := excluded[leak]; got != wantReason {
		t.Fatalf("fixture no longer constructs a dropped next-table leak: reason = %q, want %q", got, wantReason)
	}
	if got := excluded[healthy]; got != "" {
		t.Fatalf("fixture's healthy route is not healthy: reason = %q", got)
	}

	s := &Server{}
	var buf strings.Builder
	s.showRoutingInstancesDetail(cfg, &buf)
	out := buf.String()

	// 1. The configured row is VISIBLE — it counts toward the total, so it
	//    must account for itself with a row.
	if !strings.Contains(out, "10.0.0.0/8 -> next-table target") {
		t.Fatalf("gRPC `routing-instances-detail` omits the configured next-table row "+
			"(it still counts toward \"Static routes: N\"):\n%s", out)
	}
	// 2. ... WITH its refusal reason on the adjacent line — the CLI twin's
	//    shape (`cli_show_routing.go` next-table arm + printStaticRouteNotInstalled).
	lines := strings.Split(out, "\n")
	row := -1
	for i, l := range lines {
		if strings.Contains(l, "10.0.0.0/8 -> next-table target") {
			row = i
			break
		}
	}
	if row < 0 || row+1 >= len(lines) || !strings.Contains(lines[row+1], "NOT INSTALLED: "+wantReason) {
		t.Fatalf("gRPC detail shows the leak without its exclusion reason — a dropped route "+
			"rendered as configured reads as installed (#6534 archetype):\n%s", out)
	}
	// 3. Negative control: exactly ONE annotation — the healthy route must
	//    stay quiet. A renderer annotating unconditionally would pass 1+2.
	if n := strings.Count(out, "NOT INSTALLED"); n != 1 {
		t.Errorf("NOT INSTALLED annotations = %d, want exactly 1 (the leak; the healthy "+
			"route must stay quiet):\n%s", n, out)
	}
}
