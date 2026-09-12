package userspace

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// ingressCfg9637 has one of each netdev kind the #9637 ingress scope must
// classify:
//   - lan on an untagged unit, with a per-interface override on a second
//     interface (#3362), so lan yields two views;
//   - wan on two VLAN units of one trunk parent;
//   - sfmix on a unit that a virtual-router instance enslaves to its VRF;
//   - mgmt on fxp0, a lifeline.
func ingressCfg9637() *config.Config {
	cfg := &config.Config{}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"ge-0/0/0": {Name: "ge-0/0/0", Units: map[int]*config.InterfaceUnit{
			0: {Number: 0, Addresses: []string{"10.0.61.1/24"}},
		}},
		"ge-0/0/1": {Name: "ge-0/0/1", Units: map[int]*config.InterfaceUnit{
			50: {Number: 50, VlanID: 50, Addresses: []string{"172.16.50.8/24"}},
			80: {Number: 80, VlanID: 80, Addresses: []string{"172.16.80.8/24"}},
		}},
		"ge-0/0/2": {Name: "ge-0/0/2", Units: map[int]*config.InterfaceUnit{
			0: {Number: 0, Addresses: []string{"10.255.192.42/30"}},
		}},
		"ge-0/0/3": {Name: "ge-0/0/3", Units: map[int]*config.InterfaceUnit{
			0: {Number: 0, Addresses: []string{"10.0.62.1/24"}},
		}},
		"fxp0": {Name: "fxp0", Units: map[int]*config.InterfaceUnit{
			0: {Number: 0, Addresses: []string{"192.168.1.1/24"}},
		}},
	}
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"lan": {
			Name:               "lan",
			Interfaces:         []string{"ge-0/0/0.0", "ge-0/0/3.0"},
			HostInboundTraffic: &config.HostInboundTraffic{SystemServices: []string{"ssh", "ping"}},
			InterfaceHostInbound: map[string]*config.HostInboundTraffic{
				"ge-0/0/3.0": {SystemServices: []string{"ping"}},
			},
		},
		"wan":   {Name: "wan", Interfaces: []string{"ge-0/0/1.50", "ge-0/0/1.80"}, HostInboundTraffic: &config.HostInboundTraffic{SystemServices: []string{"ping"}}},
		"sfmix": {Name: "sfmix", Interfaces: []string{"ge-0/0/2.0"}, HostInboundTraffic: &config.HostInboundTraffic{SystemServices: []string{"ping"}}},
		"mgmt":  {Name: "mgmt", Interfaces: []string{"fxp0.0"}, HostInboundTraffic: &config.HostInboundTraffic{SystemServices: []string{"ssh"}}},
	}
	cfg.RoutingInstances = []*config.RoutingInstanceConfig{
		{Name: "sfmix", InstanceType: "virtual-router", Interfaces: []string{"ge-0/0/2.0"}},
	}
	return cfg
}

// TestZoneHostInboundViewIngressNetdevs9637 pins which netdevs each view
// judges by ingress, through the real builder. Every exclusion is checked
// beside a sibling the builder keeps, so a scope that came back empty for some
// other reason cannot pass.
func TestZoneHostInboundViewIngressNetdevs9637(t *testing.T) {
	views := BuildZoneHostInboundViews(ingressCfg9637())
	got := map[string]string{}
	for _, v := range views {
		key := v.Zone + "/" + strings.Join(v.SystemServices, ",")
		got[key] = strings.Join(v.IngressNetdevs, " ")
		for _, nd := range v.IngressNetdevs {
			if strings.HasPrefix(nd, "fxp") {
				t.Errorf("view %s claims lifeline netdev %q", key, nd)
			}
		}
	}
	for key, want := range map[string]string{
		// lan's zone-level view keeps its own unit's netdev, and the override
		// interface's netdev goes to the override's view instead.
		"lan/ssh,ping": "ge-0-0-0",
		"lan/ping":     "ge-0-0-3",
		// Both VLAN units are claimed; their trunk parent ge-0-0-1 is not.
		"wan/ping": "ge-0-0-1.50 ge-0-0-1.80",
		// Enslaved to vrf-sfmix: iifname at LOCAL_IN names the master (#6619).
		"sfmix/ping": "",
		// Lifeline.
		"mgmt/ssh": "",
	} {
		if g, ok := got[key]; !ok {
			t.Errorf("no view %s; views: %v", key, got)
		} else if g != want {
			t.Errorf("view %s IngressNetdevs = %q, want %q", key, g, want)
		}
	}
}

// TestHostInboundViewIngressNetdevsExcludesSharedClaims9637 drives the claim
// rule directly. A netdev claimed by two groups goes to neither, because
// whichever group's rules came first would decide. Lifeline and VRF-enslaved
// netdevs go to no group. A netdev claimed by this group alone is kept.
func TestHostInboundViewIngressNetdevsExcludesSharedClaims9637(t *testing.T) {
	lan, wan := "lan\x00ping,ssh", "wan\x00ping"
	claims := map[string]map[string]bool{
		"own-lan":  {lan: true},
		"own-wan":  {wan: true},
		"shared":   {lan: true, wan: true},
		"lifeline": {lan: true},
		"enslaved": {lan: true},
	}
	lifelines := map[string]bool{"lifeline": true}
	enslaved := map[string]bool{"enslaved": true}
	if got := strings.Join(hostInboundViewIngressNetdevs(lan, claims, lifelines, enslaved), " "); got != "own-lan" {
		t.Errorf("lan scope = %q, want %q", got, "own-lan")
	}
	if got := strings.Join(hostInboundViewIngressNetdevs(wan, claims, lifelines, enslaved), " "); got != "own-wan" {
		t.Errorf("wan scope = %q, want %q", got, "own-wan")
	}
}
