package userspace

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

func TestForwardingAndVRFDeviceConflictQuarantinesEitherOrder11060(t *testing.T) {
	for _, order := range []struct {
		name string
		ris  []*config.RoutingInstanceConfig
	}{
		{
			name: "forwarding-first",
			ris: []*config.RoutingInstanceConfig{
				{Name: "forwarding", InstanceType: "forwarding", Interfaces: []string{"ge-0/0/7"}},
				{Name: "blue", InstanceType: "vrf", Interfaces: []string{"ge-0/0/7"}},
			},
		},
		{
			name: "vrf-first",
			ris: []*config.RoutingInstanceConfig{
				{Name: "blue", InstanceType: "vrf", Interfaces: []string{"ge-0/0/7"}},
				{Name: "forwarding", InstanceType: "forwarding", Interfaces: []string{"ge-0/0/7"}},
			},
		},
	} {
		t.Run(order.name, func(t *testing.T) {
			cfg := &config.Config{RoutingInstances: order.ris}
			conflicts := config.RoutingInstanceMemberDeviceConflicts(cfg, cfg.TunnelNameMap())
			if len(conflicts) != 1 || conflicts[0].LinuxName != "ge-0-0-7" {
				t.Fatalf("forwarding/VRF conflict = %+v, want ge-0-0-7", conflicts)
			}
			if got := buildInterfaceRoutingInstances(cfg); len(got) != 0 {
				t.Fatalf("ambiguous forwarding/VRF interface was assigned: %v", got)
			}
			v4, v6 := buildInterfaceRouteTables(cfg)
			if len(v4) != 0 || len(v6) != 0 {
				t.Fatalf("ambiguous forwarding/VRF route-table membership survived: v4=%v v6=%v", v4, v6)
			}
		})
	}
}
