package frr

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #9820: the ip-monitoring preferred-route overlay reuses
// generateStaticRouteInTable, so it inherits the family belt through its
// own entry point — and a forwarding-type instance keeps its `table <id>`
// target on rows the belt retains.

func TestPreferredOverlayInheritsFamilyBelt_9820(t *testing.T) {
	m := &Manager{}
	fc := &FullConfig{
		PreferredRoutes: []config.RouteOverlayEntry{
			{Destination: "2001:db8::/32", NextHop: "192.0.2.1"},
			{Destination: "2001:db8::/32", NextHop: "2001:db8::1"},
		},
	}
	var b strings.Builder
	m.renderPreferredRoutes(&b, fc)
	got := b.String()
	if strings.Contains(got, "192.0.2.1") {
		t.Fatalf("overlay inherited no belt; bad member rendered:\n%s", got)
	}
	if !strings.Contains(got, "ipv6 route 2001:db8::/32 2001:db8::1 1\n") {
		t.Fatalf("overlay dropped the exact good member:\n%s", got)
	}
}

func TestForwardingInstanceTablePreservedOnKeptRow_9820(t *testing.T) {
	m := &Manager{}
	kept := m.generateStaticRouteInTable(staticRoute9820("2001:db8::/32",
		config.NextHopEntry{Address: "2001:db8::1"},
	), "", 100, nil, nil, nil)
	if kept != "ipv6 route 2001:db8::/32 2001:db8::1 5 table 100\n" {
		t.Fatalf("forwarding-instance kept row = %q", kept)
	}
	dropped := m.generateStaticRouteInTable(staticRoute9820("2001:db8::/32",
		config.NextHopEntry{Address: "192.0.2.1"},
	), "", 100, nil, nil, nil)
	if strings.TrimSpace(dropped) != "" {
		t.Fatalf("forwarding-instance bad row must render nothing, got:\n%s", dropped)
	}
}
