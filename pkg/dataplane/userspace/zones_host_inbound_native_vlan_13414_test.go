package userspace

import (
	"reflect"
	"testing"
)

// #13414: with native-vlan-id 100 and a unique zoned unit 100 (no unit 0),
// untagged parent frames belong to that unit's zone (#11434). The #13150
// fan-up classifier must not mark the parent unzoned — doing so makes the
// host-inbound builder drop native-VLAN host traffic before zone policy.
// But unresolved/ambiguous native selections (no matching unit, or an
// out-of-range native VID) must stay unzoned so unzoned ingress is dropped.
func TestNativeVLANTrunkParentStaysZoned13414(t *testing.T) {
	baseSnaps := func(cfgCmds []string) []InterfaceSnapshot {
		t.Helper()
		cfg := compileTrunkFanUp13150(t, cfgCmds)
		snaps := buildInterfaceSnapshots(cfg)
		for i := range snaps {
			if !snaps[i].IsUnit && snaps[i].Name == "ge-0/0/0" {
				snaps[i].Addresses = []InterfaceAddressSnapshot{
					{Family: "inet", Address: "192.0.2.99/24"},
					{Family: "inet6", Address: "2001:db8::99/64"},
				}
			}
		}
		return snaps
	}
	zonedCmds := []string{
		"set interfaces ge-0/0/0 vlan-tagging",
		"set interfaces ge-0/0/0 native-vlan-id 100",
		"set interfaces ge-0/0/0 unit 100 vlan-id 100",
		"set interfaces ge-0/0/0 unit 100 family inet address 10.100.0.1/24",
		"set security zones security-zone lan interfaces ge-0/0/0.100",
		"set security zones security-zone lan host-inbound-traffic system-services ssh",
	}

	t.Run("valid native keeps parent zoned", func(t *testing.T) {
		cfg := compileTrunkFanUp13150(t, zonedCmds)
		snaps := baseSnaps(zonedCmds)
		views := BuildZoneHostInboundViewsFromSnapshots(cfg, snaps)
		if len(views) != 1 {
			t.Fatalf("expected 1 view, got %+v", views)
		}
		if !reflect.DeepEqual(views[0].IngressNetdevs, []string{"ge-0-0-0", "ge-0-0-0.100"}) {
			t.Fatalf("expected native parent and unit ingress claims, got %v", views[0].IngressNetdevs)
		}
		if !contains(views[0].V4Addrs, "192.0.2.99") {
			t.Errorf("native-VLAN parent address must be scoped by the native unit zone, got %v", views[0].V4Addrs)
		}
		unzonedIngress, _ := BuildUnzonedHostInboundIngressNetdevsFromSnapshots(cfg, snaps, views)
		if contains(unzonedIngress, "ge-0-0-0") {
			t.Errorf("native-VLAN parent ge-0-0-0 must not be unzoned ingress, got %v", unzonedIngress)
		}
		unzonedV4, unzonedV6 := BuildUnzonedHostInboundAddrsFromSnapshots(cfg, snaps)
		if contains(unzonedV4, "192.0.2.99") || contains(unzonedV6, "2001:db8::99") {
			t.Errorf("native-VLAN parent addresses must not be unzoned: v4=%v v6=%v", unzonedV4, unzonedV6)
		}
	})

	t.Run("no native stays unzoned", func(t *testing.T) {
		cmds := []string{
			"set interfaces ge-0/0/0 vlan-tagging",
			"set interfaces ge-0/0/0 unit 100 vlan-id 100",
			"set interfaces ge-0/0/0 unit 100 family inet address 10.100.0.1/24",
			"set security zones security-zone lan interfaces ge-0/0/0.100",
			"set security zones security-zone lan host-inbound-traffic system-services ssh",
		}
		cfg := compileTrunkFanUp13150(t, cmds)
		snaps := baseSnaps(cmds)
		views := BuildZoneHostInboundViewsFromSnapshots(cfg, snaps)
		unzonedIngress, _ := BuildUnzonedHostInboundIngressNetdevsFromSnapshots(cfg, snaps, views)
		if !contains(unzonedIngress, "ge-0-0-0") {
			t.Errorf("no-native trunk parent must stay unzoned, got %v", unzonedIngress)
		}
	})

	t.Run("unresolved native stays unzoned", func(t *testing.T) {
		cmds := []string{
			"set interfaces ge-0/0/0 vlan-tagging",
			"set interfaces ge-0/0/0 native-vlan-id 100",
			"set interfaces ge-0/0/0 unit 200 vlan-id 200",
			"set interfaces ge-0/0/0 unit 200 family inet address 10.200.0.1/24",
			"set security zones security-zone lan interfaces ge-0/0/0.200",
			"set security zones security-zone lan host-inbound-traffic system-services ssh",
		}
		cfg := compileTrunkFanUp13150(t, cmds)
		snaps := baseSnaps(cmds)
		views := BuildZoneHostInboundViewsFromSnapshots(cfg, snaps)
		unzonedIngress, _ := BuildUnzonedHostInboundIngressNetdevsFromSnapshots(cfg, snaps, views)
		if !contains(unzonedIngress, "ge-0-0-0") {
			t.Errorf("unresolved-native trunk parent must stay unzoned, got %v", unzonedIngress)
		}
	})

	t.Run("out-of-range native stays unzoned", func(t *testing.T) {
		cmds := []string{
			"set interfaces ge-0/0/0 vlan-tagging",
			"set interfaces ge-0/0/0 native-vlan-id 4095",
			"set interfaces ge-0/0/0 unit 100 vlan-id 100",
			"set interfaces ge-0/0/0 unit 100 family inet address 10.100.0.1/24",
			"set security zones security-zone lan interfaces ge-0/0/0.100",
			"set security zones security-zone lan host-inbound-traffic system-services ssh",
		}
		cfg := compileTrunkFanUp13150(t, cmds)
		snaps := baseSnaps(cmds)
		views := BuildZoneHostInboundViewsFromSnapshots(cfg, snaps)
		unzonedIngress, _ := BuildUnzonedHostInboundIngressNetdevsFromSnapshots(cfg, snaps, views)
		if !contains(unzonedIngress, "ge-0-0-0") {
			t.Errorf("invalid-native trunk parent must stay unzoned, got %v", unzonedIngress)
		}
	})
	t.Run("ambiguous native stays unzoned", func(t *testing.T) {
		cfg := compileTrunkFanUp13150(t, zonedCmds)
		unit := *cfg.Interfaces.Interfaces["ge-0/0/0"].Units[100]
		cfg.Interfaces.Interfaces["ge-0/0/0"].Units[101] = &unit
		snaps := baseSnaps(zonedCmds)
		if !hostInboundUnzonedFanUpBaseRows(cfg, snaps)["ge-0/0/0"] {
			t.Fatal("ambiguous native-VLAN selection must leave the parent unzoned")
		}
	})
}
