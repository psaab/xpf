package userspace

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// TestRouteSnapshotRejectPreserved13949 verifies a `reject` static route
// keeps its distinct disposition on the userspace snapshot wire instead
// of being folded into the silent `discard` blackhole (#13949): Junos
// reject must be answered with a rate-limited ICMP unreachable, discard
// must stay silent. RED on current master: Reject is folded away by
// `Discard: route.Discard || route.Reject` in routes.go, so the reject
// rows arrive with Discard=true and Reject=false.
func TestRouteSnapshotRejectPreserved13949(t *testing.T) {
	cfg := &config.Config{}
	cfg.RoutingOptions.StaticRoutes = []*config.StaticRoute{
		{Destination: "10.9.0.0/16", Reject: true, Preference: 5},
		{Destination: "10.10.0.0/16", Discard: true, Preference: 5},
	}
	cfg.RoutingOptions.Inet6StaticRoutes = []*config.StaticRoute{
		{Destination: "2001:db8:9::/48", Reject: true, Preference: 5},
		{Destination: "2001:db8:10::/48", Discard: true, Preference: 5},
	}
	cfg.RoutingInstances = []*config.RoutingInstanceConfig{
		{
			Name:         "vrf-a",
			InstanceType: "vrf",
			StaticRoutes: []*config.StaticRoute{
				{Destination: "192.0.2.0/24", Reject: true, Preference: 5},
			},
			Inet6StaticRoutes: []*config.StaticRoute{
				{Destination: "2001:db8:c0::/48", Discard: true, Preference: 5},
			},
		},
	}

	routes, _, err := buildRouteSnapshots(cfg, nil, nil)
	if err != nil {
		t.Fatal(err)
	}

	byDest := make(map[string]RouteSnapshot, len(routes))
	for _, r := range routes {
		byDest[r.Destination] = r
	}
	cases := []struct {
		dest        string
		wantReject  bool
		wantDiscard bool
	}{
		{"10.9.0.0/16", true, false},
		{"10.10.0.0/16", false, true},
		{"2001:db8:9::/48", true, false},
		{"2001:db8:10::/48", false, true},
		{"192.0.2.0/24", true, false},
		{"2001:db8:c0::/48", false, true},
	}
	for _, tc := range cases {
		got, ok := byDest[tc.dest]
		if !ok {
			t.Errorf("%s: route missing from snapshot", tc.dest)
			continue
		}
		if got.Reject != tc.wantReject || got.Discard != tc.wantDiscard {
			t.Errorf("%s: Reject=%v Discard=%v, want Reject=%v Discard=%v",
				tc.dest, got.Reject, got.Discard, tc.wantReject, tc.wantDiscard)
		}
	}
}
