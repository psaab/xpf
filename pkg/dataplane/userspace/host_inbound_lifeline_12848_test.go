package userspace

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

func TestBuildZoneHostInboundViewsDoesNotPromoteDottedSiblings12848(t *testing.T) {
	cfg := &config.Config{}
	cfg.Chassis.Cluster = &config.ClusterConfig{ControlInterface: "hb.1"}
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"trust": {Interfaces: []string{"hb.1", "hb.2"}},
	}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"hb.1": {Name: "hb.1"},
		"hb.2": {Name: "hb.2"},
	}
	snaps := []InterfaceSnapshot{
		{Name: "hb.1", LinuxName: "hb.1", Zone: "trust", Addresses: []InterfaceAddressSnapshot{{Family: "inet", Address: "192.0.2.1/32"}}},
		{Name: "hb.2", LinuxName: "hb.2", Zone: "trust", Addresses: []InterfaceAddressSnapshot{{Family: "inet", Address: "192.0.2.2/32"}}},
	}
	views := BuildZoneHostInboundViewsFromSnapshots(cfg, snaps)
	var foundLifeline, foundSibling bool
	for _, view := range views {
		for _, addr := range view.V4Addrs {
			switch addr {
			case "192.0.2.1":
				foundLifeline = true
			case "192.0.2.2":
				foundSibling = true
			}
		}
	}
	if foundLifeline {
		t.Errorf("host-inbound deny view contains configured lifeline address 192.0.2.1")
	}
	if !foundSibling {
		t.Errorf("host-inbound deny view omitted sibling interface address 192.0.2.2")
	}
}

func TestHostInboundLifelineIngressNetdevsIncludesUnitless12848(t *testing.T) {
	cfg := &config.Config{}
	cfg.Chassis.Cluster = &config.ClusterConfig{ControlInterface: "hb.1"}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"hb.1": {Name: "hb.1"},
	}
	got := HostInboundLifelineIngressNetdevs(cfg)
	for _, want := range []string{"fxp0", "hb.1"} {
		found := false
		for _, name := range got {
			if name == want {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("HostInboundLifelineIngressNetdevs = %v, missing unit-less lifeline %q", got, want)
		}
	}
}

func TestHostInboundLifelineIngressNetdevsDoesNotAddUnitParent12848(t *testing.T) {
	cfg := &config.Config{}
	cfg.Chassis.Cluster = &config.ClusterConfig{ControlInterface: "hb.1"}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"hb.1": {Name: "hb.1", Units: map[int]*config.InterfaceUnit{7: {Number: 7}}},
	}
	got := HostInboundLifelineIngressNetdevs(cfg)
	hasParent, hasUnit := false, false
	for _, name := range got {
		hasParent = hasParent || name == "hb.1"
		hasUnit = hasUnit || name == "hb.1.7"
	}
	if hasParent || !hasUnit {
		t.Errorf("ingress = %v, want unit netdev hb.1.7 without unrelated parent hb.1", got)
	}
}
