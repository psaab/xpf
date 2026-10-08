package userspace

import (
	"reflect"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/routing"
)

// #12183: a mixed static ECMP row remains in the snapshot when A is connected
// but has no live neighbor and R can be reached through a second static. The
// imported kernel route records the terminal gateway reached by recursive
// resolution; the Rust FIB must make the retained static's R member equivalent
// to this selected kernel path for both address families.
func TestMixedStaticRecursiveBackupSnapshotMatchesKernelPath12183(t *testing.T) {
	const (
		v4Static    = "10.20.0.0/24"
		v4Direct    = "192.0.2.99"
		v4Recursive = "10.10.0.1"
		v4Terminal  = "192.0.2.1"
		v6Static    = "2001:db8:20::/64"
		v6Direct    = "2001:db8:1::99"
		v6Recursive = "2001:db8:10::1"
		v6Terminal  = "2001:db8:1::2"
	)
	cfg := &config.Config{}
	cfg.RoutingOptions.StaticRoutes = []*config.StaticRoute{
		{Destination: "10.10.0.0/24", Preference: 250, NextHops: []config.NextHopEntry{{Address: v4Terminal}}},
		{Destination: v4Static, Preference: 250, NextHops: []config.NextHopEntry{{Address: v4Direct}, {Address: v4Recursive}}},
		{Destination: "2001:db8:10::/64", Preference: 250, NextHops: []config.NextHopEntry{{Address: v6Terminal}}},
		{Destination: v6Static, Preference: 250, NextHops: []config.NextHopEntry{{Address: v6Direct}, {Address: v6Recursive}}},
	}
	interfaces := []InterfaceSnapshot{{
		Name:    "eth0",
		Ifindex: 42,
		Addresses: []InterfaceAddressSnapshot{
			{Family: "inet", Address: "192.0.2.10/24"},
			{Family: "inet6", Address: "2001:db8:1::1/64"},
		},
	}}
	// These synthetic learned rows are the kernel-selected terminal paths after
	// resolving the recursive gateway through the second static.
	withLearnedRoutes(t, fixedLearned(
		learnedV4(v4Static, v4Terminal),
		learnedV6(v6Static, v6Terminal),
	))
	out, _, err := buildRouteSnapshots(cfg, interfaces, nil)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	for _, tc := range []struct {
		name, table, family, destination, direct, recursive, terminal string
	}{
		{"IPv4", "inet.0", "inet", v4Static, v4Direct, v4Recursive, v4Terminal},
		{"IPv6", "inet6.0", "inet6", v6Static, v6Direct, v6Recursive, v6Terminal},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rows := snapshotFor(t, tc.table, tc.family, tc.destination, out)
			var configured, kernel *RouteSnapshot
			for i := range rows {
				row := &rows[i]
				if reflect.DeepEqual(row.NextHops, []string{tc.direct, tc.recursive}) {
					configured = row
				}
				if reflect.DeepEqual(row.NextHops, []string{tc.terminal}) {
					kernel = row
				}
			}
			if configured == nil {
				t.Fatalf("mixed config row must stay with disconnected A and recursive R; got %+v", rows)
			}
			if kernel == nil {
				t.Fatalf("kernel-selected terminal route must be represented; got %+v", rows)
			}
			if kernel.Preference >= configured.Preference {
				t.Fatalf("kernel-selected route preference %d must outrank static fallback %d", kernel.Preference, configured.Preference)
			}
		})
	}
}

// #12183 retains the existing all-bare suppression rule: without a connected
// gateway or a second static that resolves it, the config row yields to the
// kernel-selected route instead of shadowing it with ifindex 0.
func TestAllBareUnresolvedStaticStillYieldsToKernelRoute12183(t *testing.T) {
	cfg := &config.Config{}
	cfg.RoutingOptions.StaticRoutes = []*config.StaticRoute{{
		Destination: "10.30.0.0/24",
		NextHops:    []config.NextHopEntry{{Address: "10.99.0.1"}},
	}}
	interfaces := []InterfaceSnapshot{{
		Name:    "eth0",
		Ifindex: 42,
		Addresses: []InterfaceAddressSnapshot{{
			Family: "inet", Address: "192.0.2.10/24",
		}},
	}}
	withLearnedRoutes(t, fixedLearned(learnedV4("10.30.0.0/24", "192.0.2.1")))
	out, _, err := buildRouteSnapshots(cfg, interfaces, nil)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	hits := snapshotFor(t, "inet.0", "inet", "10.30.0.0/24", out)
	if len(hits) != 1 || hits[0].Preference != routing.LearnedRouteImportPreference ||
		!reflect.DeepEqual(hits[0].NextHops, []string{"192.0.2.1"}) {
		t.Fatalf("all-bare unresolved config row must yield to kernel route, got %+v", hits)
	}
}
