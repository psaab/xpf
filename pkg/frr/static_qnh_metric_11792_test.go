package frr

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// FRR 10.6 has no static-route metric operand. Metric-bearing qualified next-
// hops therefore keep the existing route-level distance and remain ECMP in
// FRR; only an explicit per-next-hop preference changes that distance. This
// pin prevents the renderer from inventing administrative preferences to
// approximate the unsupported metric behavior (#11792).
func TestQualifiedNextHopMetricDoesNotChangeFRRDistance_11792(t *testing.T) {
	m := New()
	route := &config.StaticRoute{
		Destination: "198.51.100.0/24",
		Preference:  5,
		NextHops: []config.NextHopEntry{
			{Address: "192.0.2.1"},
			{Address: "192.0.2.2", Metric: 10, HasMetric: true},
			{Address: "192.0.2.3", Metric: 20, HasMetric: true},
			{Address: "192.0.2.4", Preference: 6, HasPreference: true, Metric: 30, HasMetric: true},
		},
	}

	got := m.generateStaticRoute(route, "", nil, nil, nil)
	for _, want := range []string{
		"ip route 198.51.100.0/24 192.0.2.1 5\n",
		"ip route 198.51.100.0/24 192.0.2.2 5\n",
		"ip route 198.51.100.0/24 192.0.2.3 5\n",
		"ip route 198.51.100.0/24 192.0.2.4 6\n",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing existing static route %q; got:\n%s", want, got)
		}
	}
}
