package frr

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// A plain multi next-hop list renders EVERY gateway as an equal-cost line so
// FRR installs multipath. RED-on-revert: only the first gateway is compiled,
// so only one line renders (multipath lost) (#3872).
func TestStaticNextHopListRendersECMP_3872(t *testing.T) {
	m := New()
	sr := &config.StaticRoute{
		Destination: "10.1.0.0/16",
		Preference:  5,
		NextHops: []config.NextHopEntry{
			{Address: "10.0.0.1"},
			{Address: "10.0.0.2"},
		},
	}
	got := m.generateStaticRoute(sr, "", nil, nil, nil)
	for _, want := range []string{
		"ip route 10.1.0.0/16 10.0.0.1 5\n",
		"ip route 10.1.0.0/16 10.0.0.2 5\n",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing equal-cost ECMP line %q\n got: %q", want, got)
		}
	}
}
