package frr

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// A floating static renders the primary next-hop at the route-level distance
// and the qualified-next-hop at its OWN (higher) distance, so FRR installs the
// primary and floats the backup in only when the primary is down. RED-on-
// revert: both next-hops render at equal cost → equal-cost ECMP over the
// backup (#3871).
func TestFloatingStaticQualifiedNextHopDistance_3871(t *testing.T) {
	m := New()
	sr := &config.StaticRoute{
		Destination: "10.5.0.0/16",
		Preference:  5, // route-level default (Junos static preference 5)
		NextHops: []config.NextHopEntry{
			{Address: "10.0.0.1"}, // primary
			{Address: "10.0.0.2", Preference: 250, HasPreference: true}, // floating backup
		},
	}
	got := m.generateStaticRoute(sr, "", nil, nil, nil)
	wantPrimary := "ip route 10.5.0.0/16 10.0.0.1 5\n"
	wantBackup := "ip route 10.5.0.0/16 10.0.0.2 250\n"
	if !strings.Contains(got, wantPrimary) {
		t.Errorf("missing primary at distance 5.\n got: %q", got)
	}
	if !strings.Contains(got, wantBackup) {
		t.Errorf("missing floating backup at distance 250.\n got: %q", got)
	}
}

// A plain multi next-hop list renders every gateway at the SAME route-level
// distance — equal-cost ECMP — with no per-next-hop distance divergence.
func TestPlainNextHopListEqualCost_3871(t *testing.T) {
	m := New()
	sr := &config.StaticRoute{
		Destination: "10.6.0.0/16",
		Preference:  5,
		NextHops: []config.NextHopEntry{
			{Address: "10.0.0.1"},
			{Address: "10.0.0.2"},
		},
	}
	got := m.generateStaticRoute(sr, "", nil, nil, nil)
	for _, want := range []string{
		"ip route 10.6.0.0/16 10.0.0.1 5\n",
		"ip route 10.6.0.0/16 10.0.0.2 5\n",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing equal-cost line %q\n got: %q", want, got)
		}
	}
}
