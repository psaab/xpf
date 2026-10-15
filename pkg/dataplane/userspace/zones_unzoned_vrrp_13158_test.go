package userspace

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

func TestUnzonedHostInboundIncludesUnzonedAndQuarantinedVRRPVIPs13158(t *testing.T) {
	tree := &config.ConfigTree{}
	for _, cmd := range []string{
		"set interfaces ge-0/0/0 unit 0 family inet address 192.0.2.1/24 vrrp-group 1 virtual-address 192.0.2.254",
		"set interfaces ge-0/0/1 unit 0 family inet address 198.51.100.1/24 vrrp-group 1 virtual-address 198.51.100.254",
		"set security zones security-zone bad interfaces ge-0/0/1.0",
		"set security zones security-zone bad unknown-knob bar",
		"set interfaces ge-0/0/2 unit 0 family inet address 203.0.113.1/24 vrrp-group 1 virtual-address 203.0.113.254",
		"set security zones security-zone z174 host-inbound-traffic system-services ssh",
		"set security zones security-zone z214 interfaces ge-0-0-2.0",
		"set interfaces ge-0/0/3 unit 0 family inet address 10.0.0.1/24 vrrp-group 1 virtual-address 10.0.0.254",
		"set security zones security-zone live interfaces ge-0/0/3.0",
		"set security zones security-zone live host-inbound-traffic system-services ssh",
	} {
		p, err := config.ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(p); err != nil {
			t.Fatalf("SetPath(%q): %v", cmd, err)
		}
	}
	cfg, err := config.CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("CompileConfigLenient: %v", err)
	}
	if z := cfg.Security.Zones["bad"]; z == nil || !z.DroppedEnforcementChild {
		t.Fatalf("fixture: bad zone must be dropped from enforcement, got %+v", z)
	}
	snaps := buildInterfaceSnapshots(cfg)
	views := BuildZoneHostInboundViewsFromSnapshots(cfg, snaps)
	got, _ := BuildUnzonedHostInboundAddrsFromSnapshots(cfg, snaps)
	want := []string{"192.0.2.254", "198.51.100.254", "203.0.113.254"}
	if containsHostInboundAddr(got, "10.0.0.254") {
		t.Fatalf("surviving zone VIP leaked into unzoned host-inbound addresses: %v", got)
	}
	foundZonedVIP := false
	for _, view := range views {
		if view.Zone == "live" && containsHostInboundAddr(view.V4Addrs, "10.0.0.254") {
			foundZonedVIP = true
			break
		}
	}
	if !foundZonedVIP {
		t.Fatalf("positive control: surviving live zone view omits VIP 10.0.0.254: %+v", views)
	}
	for _, vip := range want {
		if !containsHostInboundAddr(got, vip) {
			t.Errorf("unzoned host-inbound addresses %v omit VRRP VIP %s", got, vip)
		}
	}
	fence := buildFenceAddrSetsFromSnaps(cfg, snaps, views)
	for _, vip := range want {
		if !containsHostInboundAddr(fence.UnzonedV4, vip) {
			t.Errorf("positive control: fence unzoned addresses %v omit VRRP VIP %s", fence.UnzonedV4, vip)
		}
	}
}

func containsHostInboundAddr(addrs []string, want string) bool {
	for _, addr := range addrs {
		if addr == want {
			return true
		}
	}
	return false
}
