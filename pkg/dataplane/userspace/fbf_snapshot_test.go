package userspace

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #1827 PR-2 — FBF (filter-based forwarding) compiled-snapshot shape.
//
// The dataplane side of FBF predates PR-2: buildRouteSnapshots files
// EVERY routing instance's statics under `<ri>.inet.0` regardless of
// instance-type (routes.go does not branch on InstanceType), and the
// Rust PBR path looks up `<ri>.inet.0` for `then routing-instance`
// filter hits. PR-2 fixed the KERNEL side (FRR `table <id>`) to agree
// with this. These tests pin the dataplane half of that contract so a
// future routes.go refactor cannot silently re-open the divergence.

func fbfTestConfig() *config.Config {
	cfg := &config.Config{}
	cfg.RoutingOptions.StaticRoutes = []*config.StaticRoute{
		{Destination: "0.0.0.0/0", NextHops: []config.NextHopEntry{{Address: "172.16.50.1"}}},
	}
	cfg.RoutingInstances = []*config.RoutingInstanceConfig{
		{
			Name:         "ISP-B",
			InstanceType: "forwarding",
			TableID:      100,
			StaticRoutes: []*config.StaticRoute{
				{Destination: "0.0.0.0/0", NextHops: []config.NextHopEntry{{Address: "172.16.80.1"}}},
			},
			Inet6StaticRoutes: []*config.StaticRoute{
				{Destination: "::/0", NextHops: []config.NextHopEntry{{Address: "2001:db8:80::1"}}},
			},
		},
	}
	cfg.Firewall.FiltersInet = map[string]*config.FirewallFilter{
		"fbf-steer": {
			Name: "fbf-steer",
			Terms: []*config.FirewallFilterTerm{
				{
					Name:            "to-isp-b",
					SourceAddresses: []string{"10.0.61.0/24"},
					Count:           "fbf-isp-b",
					RoutingInstance: "ISP-B",
				},
				{Name: "default", Action: "accept"},
			},
		},
	}
	return cfg
}

// TestFBFForwardingInstanceRouteSnapshots: forwarding-instance statics
// land in `<ri>.inet.0` / `<ri>.inet6.0` — the table the Rust PBR
// lookup targets — and never in the master tables.
func TestFBFForwardingInstanceRouteSnapshots(t *testing.T) {
	routes, _, err := buildRouteSnapshots(fbfTestConfig(), nil, nil)
	if err != nil {
		t.Fatal(err)
	}

	var v4, v6 *RouteSnapshot
	for i := range routes {
		r := &routes[i]
		if r.Table == "ISP-B.inet.0" && r.Destination == "0.0.0.0/0" {
			v4 = r
		}
		if r.Table == "ISP-B.inet6.0" && r.Destination == "::/0" {
			v6 = r
		}
		if (r.Table == "inet.0" || r.Table == "inet6.0") &&
			len(r.NextHops) == 1 &&
			(r.NextHops[0] == "172.16.80.1" || r.NextHops[0] == "2001:db8:80::1") {
			t.Fatalf("forwarding-instance static leaked into master table: %+v", r)
		}
	}
	if v4 == nil || len(v4.NextHops) != 1 || v4.NextHops[0] != "172.16.80.1" {
		t.Fatalf("ISP-B.inet.0 default = %+v, want 172.16.80.1", v4)
	}
	if v6 == nil || len(v6.NextHops) != 1 || v6.NextHops[0] != "2001:db8:80::1" {
		t.Fatalf("ISP-B.inet6.0 default = %+v, want 2001:db8:80::1", v6)
	}
}

// TestFBFFilterTermSnapshotCarriesSteeringAndCounter: the FBF steering
// term reaches the dataplane with BOTH the routing-instance action and
// its per-policy counter name — the counter is how operators verify
// per-uplink steering (`xpf_filter_hits_total{filter,term}`).
func TestFBFFilterTermSnapshotCarriesSteeringAndCounter(t *testing.T) {
	snaps := buildFirewallFilterSnapshots(fbfTestConfig())
	if len(snaps) != 1 {
		t.Fatalf("filter snapshots = %+v, want 1", snaps)
	}
	if snaps[0].Name != "fbf-steer" || snaps[0].Family != "inet" {
		t.Fatalf("filter snapshot header = %+v", snaps[0])
	}
	if len(snaps[0].Terms) != 2 {
		t.Fatalf("terms = %+v, want 2", snaps[0].Terms)
	}
	steer := snaps[0].Terms[0]
	if steer.RoutingInstance != "ISP-B" {
		t.Fatalf("steer term RoutingInstance = %q, want ISP-B", steer.RoutingInstance)
	}
	if steer.Count != "fbf-isp-b" {
		t.Fatalf("steer term Count = %q, want fbf-isp-b", steer.Count)
	}
	if len(steer.SourceAddresses) != 1 || steer.SourceAddresses[0] != "10.0.61.0/24" {
		t.Fatalf("steer term sources = %+v", steer.SourceAddresses)
	}
}

// TestFBFOverlayIntoForwardingInstance: an ip-monitoring overlay entry
// targeting a forwarding instance replaces that instance's
// (table, family, prefix) entry — same whole-entry-replacement rule as
// virtual-router instances (PR-2 lifts the PR-1b rejection; the
// snapshot path needs no instance-type branch).
func TestFBFOverlayIntoForwardingInstance(t *testing.T) {
	overlay := []config.RouteOverlayEntry{
		{RoutingInstance: "ISP-B", Destination: "0.0.0.0/0", NextHop: "172.16.80.254", Policy: "wan-failover"},
	}
	routes, _, err := buildRouteSnapshots(fbfTestConfig(), nil, overlay)
	if err != nil {
		t.Fatal(err)
	}

	var defaults []RouteSnapshot
	for _, r := range routes {
		if r.Table == "ISP-B.inet.0" && r.Destination == "0.0.0.0/0" {
			defaults = append(defaults, r)
		}
	}
	if len(defaults) != 1 {
		t.Fatalf("ISP-B.inet.0 defaults = %+v, want exactly one", defaults)
	}
	if len(defaults[0].NextHops) != 1 || defaults[0].NextHops[0] != "172.16.80.254" {
		t.Fatalf("ISP-B.inet.0 default = %+v, want overlay next-hop 172.16.80.254", defaults[0])
	}
	// Master table untouched.
	for _, r := range routes {
		if r.Table == "inet.0" && r.Destination == "0.0.0.0/0" {
			if len(r.NextHops) != 1 || r.NextHops[0] != "172.16.50.1" {
				t.Fatalf("master default disturbed: %+v", r)
			}
		}
	}
}
