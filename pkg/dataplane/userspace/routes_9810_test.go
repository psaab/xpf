package userspace

import (
	"fmt"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/vishvananda/netlink"
)

// TestBuildRouteSnapshotsNextTableWindowCostsPerIngress_9810 is the FIB half
// of SYN-WIN-01: with N=4 ingress interfaces and L=30 leaks the kernel
// installs 25, so the userspace FIB must publish exactly those 25 —
// mirroring TestBuildRouteSnapshotsCapsConfigStaticNextTableLeaks' hermetic
// shape (stubbed ip-rule dump, distinct destinations, TableID>0).
func TestBuildRouteSnapshotsNextTableWindowCostsPerIngress_9810(t *testing.T) {
	orig := ruleListFn
	t.Cleanup(func() { ruleListFn = orig })
	ruleListFn = func(family int) ([]netlink.Rule, error) { return nil, nil }

	cfg := &config.Config{}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{}
	for i := 0; i < 4; i++ {
		name := fmt.Sprintf("ge-0/0/%d", i)
		cfg.Interfaces.Interfaces[name] = &config.InterfaceConfig{
			Name:  name,
			Units: map[int]*config.InterfaceUnit{0: {Number: 0}},
		}
	}
	cfg.RoutingInstances = []*config.RoutingInstanceConfig{{Name: "blue", TableID: 100}}
	for i := 0; i < 30; i++ {
		cfg.RoutingOptions.StaticRoutes = append(cfg.RoutingOptions.StaticRoutes,
			&config.StaticRoute{
				Destination: fmt.Sprintf("10.%d.%d.0/24", i/256, i%256),
				NextTable:   "blue",
			})
	}

	routes, _, err := buildRouteSnapshots(cfg, nil, nil)
	if err != nil {
		t.Fatalf("buildRouteSnapshots: %v", err)
	}
	leaks := 0
	for _, r := range routes {
		if r.NextTable == "blue" {
			leaks++
		}
	}
	if leaks != 25 {
		t.Fatalf("FIB published %d leaks, want exactly the 25 the kernel installs "+
			"(N=4, L=30 over the 100-slot window)", leaks)
	}
}
