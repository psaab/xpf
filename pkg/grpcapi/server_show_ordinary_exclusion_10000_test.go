package grpcapi

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// TestShowRoutingOptionsRendersOrdinaryStaticExclusions10000 binds the remote
// show surface to the shared verdict map for both global address families.
// Discard/reject arms and ordinary next-hop rows used to continue without
// consulting StaticRouteExclusions, so the operator saw an active row even
// after the userspace builder dropped its unusable destination.
//
// FAIL-ON-REVERT: remove either the ordinary verdict consults in
// server_show_routes_text.go or restore the blanket NextTable=="" early return
// and the reason count below goes RED.
func TestShowRoutingOptionsRendersOrdinaryStaticExclusions10000(t *testing.T) {
	globalV4Default := &config.StaticRoute{Destination: "default", Discard: true}
	globalV4Garbage := &config.StaticRoute{
		Destination: "not-a-prefix",
		NextHops:    []config.NextHopEntry{{Address: "10.0.0.1"}},
	}
	globalV4Valid := &config.StaticRoute{Destination: "10.9.0.0/16", Discard: true}
	globalV6Default := &config.StaticRoute{Destination: "default", Discard: true}
	globalV6Garbage := &config.StaticRoute{
		Destination: "not-a-prefix",
		NextHops:    []config.NextHopEntry{{Address: "2001:db8::1"}},
	}
	cfg := &config.Config{}
	cfg.RoutingOptions.StaticRoutes = []*config.StaticRoute{globalV4Default, globalV4Garbage, globalV4Valid}
	cfg.RoutingOptions.Inet6StaticRoutes = []*config.StaticRoute{globalV6Default, globalV6Garbage}

	var buf strings.Builder
	(&Server{}).showRoutingOptions(cfg, &buf)
	out := buf.String()

	const reason = "is neither a CIDR prefix nor a bare IP address"
	if got := strings.Count(out, reason); got != 4 {
		t.Fatalf("ordinary unusable routes were not each annotated in both global families: "+
			"reason count = %d, want 4 (two default-discard + two malformed next-hop)\n%s", got, out)
	}
	if !strings.Contains(out, `destination "default"`) || !strings.Contains(out, `discard`) {
		t.Fatalf("default-discard row is missing its diagnostic:\n%s", out)
	}
	if !strings.Contains(out, `destination "not-a-prefix"`) || !strings.Contains(out, `10.0.0.1`) {
		t.Fatalf("malformed ordinary next-hop row is missing its diagnostic:\n%s", out)
	}
	if strings.Contains(out, `destination "10.9.0.0/16"`) {
		t.Fatalf("a valid discard CIDR was annotated as unusable:\n%s", out)
	}
}
