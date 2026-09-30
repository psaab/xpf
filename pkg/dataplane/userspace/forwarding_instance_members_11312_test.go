package userspace

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

func TestForwardingInstanceMembersStayInDefaultForIPv4AndIPv6_11312(t *testing.T) {
	cfg := fbfTestConfig()
	cfg.RoutingInstances[0].Interfaces = []string{"reth0.80"}

	v4Tables, v6Tables := buildInterfaceRouteTables(cfg)
	if got := v4Tables["reth0.80"]; got != "" {
		t.Errorf("forwarding member IPv4 table = %q, want default table", got)
	}
	if got := v6Tables["reth0.80"]; got != "" {
		t.Errorf("forwarding member IPv6 table = %q, want default table", got)
	}
	if got := buildInterfaceRoutingInstances(cfg)["reth0.80"]; got != "" {
		t.Errorf("forwarding member routing domain = %q, want default domain", got)
	}

	routes, _, err := buildRouteSnapshots(cfg, fbfTestInterfaces(), nil)
	if err != nil {
		t.Fatalf("buildRouteSnapshots: %v", err)
	}
	wantRoutes := []struct {
		destination string
		table       string
	}{
		{destination: "172.16.80.0/24", table: "inet.0"},
		{destination: "2001:db8:80::/64", table: "inet6.0"},
	}
	gotTables := make(map[string][]string, len(wantRoutes))
	for _, route := range routes {
		for _, want := range wantRoutes {
			if route.Destination == want.destination {
				gotTables[route.Destination] = append(gotTables[route.Destination], route.Table)
			}
		}
	}
	for _, want := range wantRoutes {
		got := gotTables[want.destination]
		if len(got) != 1 || got[0] != want.table {
			t.Errorf(
				"connected prefix %s tables = %v, want exactly [%s]",
				want.destination, got, want.table)
		}
	}
}

func TestVirtualRouterMembersStillOwnBothFamilyTables11312(t *testing.T) {
	cfg := &config.Config{RoutingInstances: []*config.RoutingInstanceConfig{{
		Name:         "VRF-A",
		InstanceType: "virtual-router",
		Interfaces:   []string{"reth0.80"},
	}}}

	v4Tables, v6Tables := buildInterfaceRouteTables(cfg)
	if got := v4Tables["reth0.80"]; got != "VRF-A.inet.0" {
		t.Errorf("virtual-router IPv4 table = %q, want VRF-A.inet.0", got)
	}
	if got := v6Tables["reth0.80"]; got != "VRF-A.inet6.0" {
		t.Errorf("virtual-router IPv6 table = %q, want VRF-A.inet6.0", got)
	}
	if got := buildInterfaceRoutingInstances(cfg)["reth0.80"]; got != "VRF-A" {
		t.Errorf("virtual-router routing domain = %q, want VRF-A", got)
	}
}
