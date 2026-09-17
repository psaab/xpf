package grpcapi

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// TestShowRoutingInstancesDetailRendersOrdinaryStaticExclusions10000 covers
// the remote routing-instance detail loop. Its discard/reject arms and plain
// next-hop rows used to render without consulting the shared verdict map; the
// next-table arm is owned by #10001.
//
// FAIL-ON-REVERT: remove the ordinary verdict consults in
// server_show_routes_text.go and the reason count below goes RED.
func TestShowRoutingInstancesDetailRendersOrdinaryStaticExclusions10000(t *testing.T) {
	instanceDefault := &config.StaticRoute{Destination: "default", Discard: true}
	instanceGarbage := &config.StaticRoute{
		Destination: "not-a-prefix",
		NextHops:    []config.NextHopEntry{{Address: "10.0.0.1"}},
	}
	instanceValid := &config.StaticRoute{Destination: "10.9.0.0/16", Discard: true}
	cfg := &config.Config{
		RoutingInstances: []*config.RoutingInstanceConfig{
			{Name: "vrf-a", StaticRoutes: []*config.StaticRoute{instanceDefault, instanceGarbage, instanceValid}},
		},
	}

	var buf strings.Builder
	(&Server{}).showRoutingInstancesDetail(cfg, &buf)
	out := buf.String()

	const reason = "is neither a CIDR prefix nor a bare IP address"
	if got := strings.Count(out, reason); got != 2 {
		t.Fatalf("ordinary unusable routing-instance routes were not each annotated: reason count = %d, want 2\n%s", got, out)
	}
	if !strings.Contains(out, "default -> discard") || !strings.Contains(out, "not-a-prefix -> 10.0.0.1") {
		t.Fatalf("ordinary routing-instance rows are missing:\n%s", out)
	}
	if strings.Contains(out, `destination "10.9.0.0/16"`) {
		t.Fatalf("a valid routing-instance discard CIDR was annotated as unusable:\n%s", out)
	}
}
