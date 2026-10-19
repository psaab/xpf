package ipmon

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #15705: a policy whose PreferredRoutes carried the same
// (routing-instance, canonical destination) twice — the shape the
// pre-fix compiler produced for repeated `policy <name>` blocks — must
// actuate exactly one route, and the entry the compiler's merge would
// have produced (last writer for the next-hop, metric from whichever
// block set it) is what wins. The compiler now dedups, so this pins the
// downstream contract the fix relies on: one overlay entry per key.
func TestOverlaySingleRouteAfterCompilerMerge15705(t *testing.T) {
	cfg := &config.IPMonitoringConfig{Policies: map[string]*config.IPMonitoringPolicy{
		"wan-failover": {
			Name:          "wan-failover",
			MatchRPMProbe: "WAN",
			PreferredRoutes: []*config.PreferredRoute{
				{Destination: "0.0.0.0/0", NextHop: "192.0.2.2", PreferredMetric: 10},
			},
		},
	}}
	e, _ := newTestEngine(nil)
	e.Apply(cfg, passResults())
	e.HandleTransition(transition("WAN", "wan-a", "fail", passResults()))
	overlay := e.ActiveOverlay()
	if len(overlay) != 1 {
		t.Fatalf("overlay = %+v, want exactly 1 entry for the merged route", overlay)
	}
	if overlay[0].NextHop != "192.0.2.2" || overlay[0].Metric != 10 {
		t.Fatalf("overlay[0] = %+v, want the merged next-hop 192.0.2.2 metric 10", overlay[0])
	}
}
