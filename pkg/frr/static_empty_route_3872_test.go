package frr

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// A non-discard route with 0 next-hops (e.g. every ECMP gateway was deleted,
// #3872 delete side) must render NOTHING — NOT a Null0 blackhole. RED-on-
// revert: renders "ip route <dst> Null0 5" (blackhole).
func TestZeroNextHopRouteNotBlackholed_3872(t *testing.T) {
	m := New()
	sr := &config.StaticRoute{Destination: "10.1.0.0/16", Preference: 5}
	if got := m.generateStaticRoute(sr, "", nil, nil, nil); got != "" {
		t.Fatalf("0-next-hop non-discard route rendered %q, want \"\" (must not blackhole)", got)
	}
}

// An EXPLICIT discard route still renders Null0 (unchanged).
func TestExplicitDiscardStillNull0_3872(t *testing.T) {
	m := New()
	sr := &config.StaticRoute{Destination: "10.0.99.0/24", Discard: true}
	want := "ip route 10.0.99.0/24 Null0\n"
	if got := m.generateStaticRoute(sr, "", nil, nil, nil); got != want {
		t.Fatalf("discard route = %q, want %q", got, want)
	}
}
