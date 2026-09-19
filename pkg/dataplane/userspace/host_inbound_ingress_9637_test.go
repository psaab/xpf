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
		// Enslaved to vrf-sfmix: LOCAL_IN names the VRF master (#6619).
		"sfmix/ping": "vrf-sfmix",
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

// TestZoneHostInboundViewIngressVRFMaster10431 is the #10431 narrow-residual
// cell: a VRF-enslaved-only zone keeps matchable LOCAL_IN scope via the VRF
// master device, not the enslaved names (which match nothing, #6619). Pre-fix
// RED: sfmix scope is empty, so its ingress drop is gone and cross-zone
// host-bound packets reach another zone's bare-daddr accept.
func TestZoneHostInboundViewIngressVRFMaster10431(t *testing.T) {
	views := BuildZoneHostInboundViews(ingressCfg9637())
	for _, v := range views {
		if v.Zone == "sfmix" {
			if got := strings.Join(v.IngressNetdevs, " "); got != "vrf-sfmix" {
				t.Errorf("sfmix IngressNetdevs = %q, want %q (VRF master, #10431)", got, "vrf-sfmix")
			}
			return
		}
	}
	t.Fatal("no sfmix view; views missing")
}

// TestZoneHostInboundViewLifelineOnlyHasNoAddrs10431 pins the lifeline-only
// control: a zone on lifeline interfaces contributes no addresses, so it
// emits no bare-daddr accepts (#10431 lifeline shape is already closed).
func TestZoneHostInboundViewLifelineOnlyHasNoAddrs10431(t *testing.T) {
	views := BuildZoneHostInboundViews(ingressCfg9637())
	for _, v := range views {
		if v.Zone == "mgmt" {
			if len(v.V4Addrs) != 0 || len(v.V6Addrs) != 0 {
				t.Errorf("mgmt addrs = %v/%v, want empty (lifeline contributes no host-inbound scope)", v.V4Addrs, v.V6Addrs)
			}
			if len(v.IngressNetdevs) != 0 {
				t.Errorf("mgmt IngressNetdevs = %v, want empty (lifeline never scoped)", v.IngressNetdevs)
			}
			return
		}
	}
	t.Fatal("no mgmt view; views missing")
}

// TestZoneHostInboundViewLifelineSharedVRFMasterIsNotScoped10431 drives the
// production builder with a real lifeline member and data member in one VRF.
// The effective VRF master must not appear in either normal or fail-closed
// ingress scopes, because LOCAL_IN sees the same master for both members.
func TestZoneHostInboundViewLifelineSharedVRFMasterIsNotScoped10431(t *testing.T) {
	cfg := ingressCfg9637()
	cfg.RoutingInstances[0].Interfaces = append(cfg.RoutingInstances[0].Interfaces, "fxp0.0")
	views := BuildZoneHostInboundViews(cfg)
	foundSfmix := false
	for _, view := range views {
		if view.Zone == "sfmix" {
			foundSfmix = true
		}
		for _, netdev := range view.IngressNetdevs {
			if netdev == "vrf-sfmix" {
				t.Fatalf("view %s has shared lifeline VRF master in ingress scope: %+v", view.Zone, view)
			}
		}
		for _, netdev := range view.IngressDenyNetdevs {
			if netdev == "vrf-sfmix" {
				t.Fatalf("view %s has shared lifeline VRF master in deny scope: %+v", view.Zone, view)
			}
		}
	}
	if !foundSfmix {
		t.Fatal("no sfmix view; views missing")
	}
}

// TestZoneHostInboundViewSharedVRFClaimsFailClosed10431 drives the
// production builder with two zone views whose members resolve to one VRF
// master. Neither view may claim that shared LOCAL_IN identity; the builder
// instead attaches one destination-scoped deny guard.
func TestZoneHostInboundViewSharedVRFClaimsFailClosed10431(t *testing.T) {
	cfg := ingressCfg9637()
	cfg.Interfaces.Interfaces["ge-0/0/4"] = &config.InterfaceConfig{
		Name: "ge-0/0/4",
		Units: map[int]*config.InterfaceUnit{
			0: {Number: 0, Addresses: []string{"10.0.63.1/24"}},
		},
	}
	cfg.Security.Zones["sfother"] = &config.ZoneConfig{
		Name:               "sfother",
		Interfaces:         []string{"ge-0/0/4.0"},
		HostInboundTraffic: &config.HostInboundTraffic{SystemServices: []string{"ssh"}},
	}
	cfg.RoutingInstances[0].Interfaces = append(cfg.RoutingInstances[0].Interfaces, "ge-0/0/4.0")
	views := BuildZoneHostInboundViews(cfg)
	foundDeny := false
	foundSfmix, foundOther := false, false
	for _, view := range views {
		if view.Zone == "sfmix" {
			foundSfmix = true
		}
		if view.Zone == "sfother" {
			foundOther = true
		}
		for _, netdev := range view.IngressNetdevs {
			if netdev == "vrf-sfmix" {
				t.Fatalf("view %s claims ambiguous VRF master: %+v", view.Zone, view)
			}
		}
		for _, netdev := range view.IngressDenyNetdevs {
			if netdev == "vrf-sfmix" {
				foundDeny = true
			}
		}
	}
	if !foundSfmix || !foundOther {
		t.Fatalf("missing shared-VRF views: sfmix=%v sfother=%v views=%+v", foundSfmix, foundOther, views)
	}
	if !foundDeny {
		t.Fatalf("shared VRF master has no fail-closed deny guard: %+v", views)
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
	if got := strings.Join(hostInboundViewIngressDenyNetdevs(claims, lifelines, enslaved, nil), " "); got != "shared" {
		t.Errorf("ambiguous effective scope = %q, want %q", got, "shared")
	}
}

// TestHostInboundViewIngressBareVRFMemberFansDownTaggedUnits10431 covers the
// production binder's bare-member fan-down: every tagged child is attached to
// the VRF master at LOCAL_IN, not left to destination-only fallback.
func TestHostInboundViewIngressBareVRFMemberFansDownTaggedUnits10431(t *testing.T) {
	cfg := &config.Config{
		RoutingInstances: []*config.RoutingInstanceConfig{{
			Name:         "sfmix",
			InstanceType: "virtual-router",
			Interfaces:   []string{"ge-0/0/2"},
		}},
	}
	snaps := []InterfaceSnapshot{
		{Name: "ge-0/0/2", LinuxName: "ge-0-0-2", RoutingInstance: "sfmix"},
		{Name: "ge-0/0/2.50", LinuxName: "ge-0-0-2.50", RoutingInstance: "sfmix"},
	}
	masters := hostInboundVRFMasterNetdevs(cfg, snaps)
	if got := masters["ge-0-0-2.50"]; got != "vrf-sfmix" {
		t.Fatalf("tagged bare-member netdev master = %q, want %q", got, "vrf-sfmix")
	}
	sig := "sfmix\x00ping"
	claims := map[string]map[string]bool{
		"ge-0-0-2":    {sig: true},
		"ge-0-0-2.50": {sig: true},
	}
	enslaved := map[string]bool{"ge-0-0-2": true, "ge-0-0-2.50": true}
	if got := strings.Join(hostInboundViewIngressNetdevsWithMasters(sig, claims, nil, enslaved, masters), " "); got != "vrf-sfmix" {
		t.Fatalf("bare-member ingress scope = %q, want %q", got, "vrf-sfmix")
	}
}

// TestHostInboundViewIngressLifelineVRFMasterIsNotScoped10431 ensures a
// lifeline and data member sharing a VRF master do not turn that master into a
// deny scope that catches management traffic.
func TestHostInboundViewIngressLifelineVRFMasterIsNotScoped10431(t *testing.T) {
	sig := "data\x00ping"
	claims := map[string]map[string]bool{
		"lifeline-slave": {sig: true},
		"data-slave":     {sig: true},
	}
	lifelines := map[string]bool{"lifeline-slave": true}
	enslaved := map[string]bool{"lifeline-slave": true, "data-slave": true}
	masters := map[string]string{"lifeline-slave": "vrf-shared", "data-slave": "vrf-shared"}
	if got := hostInboundViewIngressNetdevsWithMasters(sig, claims, lifelines, enslaved, masters); len(got) != 0 {
		t.Fatalf("shared lifeline VRF scope = %v, want empty", got)
	}
	if got := hostInboundViewIngressDenyNetdevs(claims, lifelines, enslaved, masters); len(got) != 0 {
		t.Fatalf("shared lifeline VRF deny scope = %v, want empty", got)
	}
}
