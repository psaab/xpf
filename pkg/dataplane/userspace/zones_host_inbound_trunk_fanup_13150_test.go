package userspace

import (
	"reflect"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #13150 (D3-04): a tagged-only VLAN trunk's fan-up base row must not claim
// the untagged parent netdev or its kernel addresses for the tagged unit's
// zone. Untagged frames on the parent are unzoned (#8553/#11574/#12855).
func compileTrunkFanUp13150(t *testing.T, cmds []string) *config.Config {
	t.Helper()
	tree := &config.ConfigTree{}
	for _, cmd := range cmds {
		p, err := config.ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(p); err != nil {
			t.Fatalf("SetPath(%q): %v", cmd, err)
		}
	}
	cfg, err := config.CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	return cfg
}

func TestTaggedOnlyTrunkFanUpBaseRowIsUnzoned13150(t *testing.T) {
	cfg := compileTrunkFanUp13150(t, []string{
		"set interfaces ge-0/0/0 vlan-tagging",
		"set interfaces ge-0/0/0 unit 100 vlan-id 100",
		"set interfaces ge-0/0/0 unit 100 family inet address 10.100.0.1/24",
		"set security zones security-zone lan interfaces ge-0/0/0.100",
		"set security zones security-zone lan host-inbound-traffic system-services ssh",
	})
	snaps := buildInterfaceSnapshots(cfg)
	for i := range snaps {
		if !snaps[i].IsUnit && snaps[i].Name == "ge-0/0/0" {
			snaps[i].Addresses = []InterfaceAddressSnapshot{
				{Family: "inet", Address: "192.0.2.99/24"},
				{Family: "inet6", Address: "2001:db8::99/64"},
			}
		}
	}
	views := BuildZoneHostInboundViewsFromSnapshots(cfg, snaps)
	if len(views) != 1 {
		t.Fatalf("expected 1 view, got %+v", views)
	}
	// Positive control: the tagged unit still claims its own netdev/address.
	if !reflect.DeepEqual(views[0].IngressNetdevs, []string{"ge-0-0-0.100"}) {
		t.Fatalf("expected IngressNetdevs=[ge-0-0-0.100], got %v", views[0].IngressNetdevs)
	}
	if !contains(views[0].V4Addrs, "10.100.0.1") {
		t.Fatalf("expected lan V4Addrs to contain 10.100.0.1, got %v", views[0].V4Addrs)
	}
	unzonedIngress, _ := BuildUnzonedHostInboundIngressNetdevsFromSnapshots(cfg, snaps, views)
	if !contains(unzonedIngress, "ge-0-0-0") {
		t.Errorf("untagged trunk parent ge-0-0-0 must be in unzoned ingress netdevs, got %v", unzonedIngress)
	}
	if contains(views[0].V4Addrs, "192.0.2.99") || contains(views[0].V6Addrs, "2001:db8::99") {
		t.Errorf("parent kernel addresses stolen into lan view: v4=%v v6=%v", views[0].V4Addrs, views[0].V6Addrs)
	}
	unzonedV4, unzonedV6 := BuildUnzonedHostInboundAddrsFromSnapshots(cfg, snaps)
	if !contains(unzonedV4, "192.0.2.99") || !contains(unzonedV6, "2001:db8::99") {
		t.Errorf("parent kernel addresses must be unzoned: v4=%v v6=%v", unzonedV4, unzonedV6)
	}
}

// Positive control: an untagged unit 0 collapsing onto the parent netdev
// keeps that netdev and its addresses zoned (no regression to #5699 shape).
func TestUntaggedUnit0ParentStaysZoned13150(t *testing.T) {
	cfg := compileTrunkFanUp13150(t, []string{
		"set interfaces ge-0/0/1 unit 0 family inet address 10.0.0.1/24",
		"set security zones security-zone lan interfaces ge-0/0/1.0",
		"set security zones security-zone lan host-inbound-traffic system-services ssh",
	})
	snaps := buildInterfaceSnapshots(cfg)
	views := BuildZoneHostInboundViewsFromSnapshots(cfg, snaps)
	if len(views) != 1 || !contains(views[0].V4Addrs, "10.0.0.1") {
		t.Fatalf("expected lan view with 10.0.0.1, got %+v", views)
	}
	unzonedIngress, _ := BuildUnzonedHostInboundIngressNetdevsFromSnapshots(cfg, snaps, views)
	if contains(unzonedIngress, "ge-0-0-1") {
		t.Errorf("unit-0 parent netdev must stay zoned, got unzoned %v", unzonedIngress)
	}
	unzonedV4, _ := BuildUnzonedHostInboundAddrsFromSnapshots(cfg, snaps)
	if contains(unzonedV4, "10.0.0.1") {
		t.Errorf("unit-0 address must stay zoned, got unzoned %v", unzonedV4)
	}
}
