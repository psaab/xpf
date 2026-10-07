package api

import (
	"testing"
)

// metrics_frr_routemap_quarantine_6807_test.go — #6807.
//
// A policy too large to render is replaced with a bounded explicit DENY under
// the name its BGP attachment still uses, so the attachment resolves
// deliberately instead of dangling (FRR denies a route-map name it cannot
// resolve). That keeps the reload safe — but it is still an OUTAGE: every route
// on a neighbor carrying such an attachment is withdrawn until the policy is
// reduced.
//
// R68's invariant note is the reason this gauge exists: "operators also need
// apply failure/health rather than silent accepted outage". Before it, the only
// signal was one slog.Warn at render time, which nothing alerts on — a total
// route withdrawal that looks exactly like a healthy box to every dashboard.
//
// This binds the WIRING. `QuarantinedRouteMaps()` can be exported and correct
// and the operator still sees nothing if the accessor never reaches a Desc.

// TestFRRRouteMapsQuarantinedGauge6807 is PAIRED across three points, not two.
//
// The healthy leg is load-bearing in a way that is easy to get wrong: the gauge
// must publish an explicit 0, not go ABSENT, on a healthy box. An alert written
// as `xpf_frr_route_maps_quarantined > 0` cannot distinguish "no quarantine"
// from "this series stopped being reported", so a gauge that simply vanishes
// when healthy is the same blindness the metric exists to remove.
//
// The two-quarantined leg rejects a gauge hardwired to 1 — which would look
// correct against a single-policy fixture and under-report incidents when an
// oversized policy quarantines both its base BGP map and a per-protocol map.
func TestFRRRouteMapsQuarantinedGauge6807(t *testing.T) {
	for _, tc := range []struct {
		name        string
		quarantined []string
		want        float64
	}{
		{"healthy", nil, 0},
		{"one-policy", []string{"BIG"}, 1},
		{"policy-and-protocol-map", []string{"BIG", "BIG-static-xpf-redist"}, 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := &Server{ // dp intentionally nil — FRR renders in config-only mode too
				frrQuarantinedRouteMapsFn: func() []string { return tc.quarantined },
			}
			got, ok := gatherSingleSample6802(t, s, "xpf_frr_route_maps_quarantined")
			if !ok {
				t.Fatal("xpf_frr_route_maps_quarantined was not emitted — a policy " +
					"too large to render withdraws every route on the neighbors " +
					"carrying its attachments, and an operator cannot see it (#6807)")
			}
			if got != tc.want {
				t.Errorf("gauge = %v, want %v — the gauge does not track the wired "+
					"fn, so it reports the same value whether or not routes are "+
					"being withdrawn", got, tc.want)
			}
		})
	}
}

// TestFRRRouteMapsQuarantinedGaugeAbsentWhenUnwired6807 pins the OTHER half of
// the optional-hook contract: with no hook wired the series must not be
// published at all, rather than published as a constant 0.
//
// A hardcoded 0 on a daemon that never consulted FRR is worse than silence — it
// asserts "no policy is quarantined" on a process that has no idea, and an
// operator alerting on this series would read that as an all-clear.
func TestFRRRouteMapsQuarantinedGaugeAbsentWhenUnwired6807(t *testing.T) {
	s := &Server{} // frrQuarantinedRouteMapsFn deliberately nil
	if _, ok := gatherSingleSample6802(t, s, "xpf_frr_route_maps_quarantined"); ok {
		t.Fatal("xpf_frr_route_maps_quarantined was published with no FRR hook " +
			"wired — that reports a confident 'nothing quarantined' from a " +
			"process that never asked FRR")
	}
}
