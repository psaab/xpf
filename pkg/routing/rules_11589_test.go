package routing

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

func TestPBROnVRFMemberIsDroppedAndDegraded11589(t *testing.T) {
	cfg := &config.Config{
		RoutingInstances: []*config.RoutingInstanceConfig{
			{Name: "member-ri", InstanceType: "vrf", Interfaces: []string{"ge-0/0/1.0"}},
			{Name: "steer-ri", InstanceType: "forwarding", TableID: 101},
		},
	}
	filter := &config.FirewallFilter{
		Name: "member-fbf",
		Terms: []*config.FirewallFilterTerm{{
			Name:            "steer",
			SourceAddresses: []string{"192.0.2.0/24"},
			RoutingInstance: "steer-ri",
		}},
	}
	cfg.Firewall.FiltersInet = map[string]*config.FirewallFilter{filter.Name: filter}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"ge-0/0/1": {
			Name: "ge-0/0/1",
			Units: map[int]*config.InterfaceUnit{
				0: {Number: 0, FilterInputV4: filter.Name},
			},
		},
	}

	rules, degraded := PBRBuildRulesAndStats(cfg)
	if len(rules) != 0 {
		t.Fatalf("VRF-member FBF must not install a preempted PBR steer: %+v", rules)
	}
	if degraded != 1 {
		t.Fatalf("dropped VRF-member FBF degraded count = %d, want 1", degraded)
	}

	// Forwarding instances do not bind Linux VRFs and their member interfaces
	// can reach the PBR priority band, so retain the existing steering path.
	cfg.RoutingInstances[0].InstanceType = "forwarding"
	rules, degraded = PBRBuildRulesAndStats(cfg)
	if len(rules) != 1 || rules[0].Instance != "steer-ri" {
		t.Fatalf("forwarding-instance member FBF rules = %+v, want one steer-ri rule", rules)
	}
	if degraded != 0 {
		t.Fatalf("forwarding-instance member degraded count = %d, want 0", degraded)
	}
}
