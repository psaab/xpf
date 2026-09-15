package frr

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// TestGenerateStaticRoute_SanitizesVRFName_5557 pins that the routing-instance
// name interpolated into a static route's `vrf <name>` clause is routed through
// sanitizeFRRValue — the render-side belt every other free-text FRR
// interpolation already uses. The name is validated at commit, but the tolerant
// load / HA config-sync paths only warn (#1960 no-brick), so a control
// character reaching the renderer could otherwise inject a second vtysh line
// into the managed frr.conf.
//
// FAIL-ON-REVERT: drop the sanitizeFRRValue call on vrfName in
// generateStaticRouteInTable and the embedded newline survives, splitting the
// route line into an injected second line.
func TestGenerateStaticRoute_SanitizesVRFName_5557(t *testing.T) {
	m := &Manager{}
	sr := &config.StaticRoute{
		Destination: "10.0.0.0/24",
		NextHops:    []config.NextHopEntry{{Address: "10.0.2.254"}},
	}

	got := m.generateStaticRoute(sr, "red\ninjected", nil, nil, nil)

	if strings.Contains(got, "vrf red\ninjected") {
		t.Fatalf("vrfName newline not sanitized (frr.conf line injection); rendered:\n%q", got)
	}
	if !strings.Contains(got, "vrf red injected") {
		t.Fatalf("expected sanitized 'vrf red injected' in output; rendered:\n%q", got)
	}
}
