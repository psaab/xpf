package userspace

import (
	"strings"
	"testing"
)

// #17749 fold: a distinct physical-parent snapshot carries its own live
// address under the zone-level set when no unit 0 collapses onto it, even
// though a tagged unit replaces that set. The commit advisory must name the
// zone for SSH reachable through this parent address.
func TestUnmanagedSSHAdvisoryWarnsForDistinctParentCarrier17749(t *testing.T) {
	cfg := compileTrunkFanUp13150(t, []string{
		"set interfaces ge-0/0/0 vlan-tagging",
		"set interfaces ge-0/0/0 unit 1 vlan-id 1",
		"set security zones security-zone trust host-inbound-traffic system-services all",
		"set security zones security-zone trust interfaces ge-0/0/0",
		"set security zones security-zone trust interfaces ge-0/0/0.1 host-inbound-traffic system-services ping",
	})

	snaps := buildInterfaceSnapshots(cfg)
	parentFound := false
	for i := range snaps {
		if snaps[i].Name == "ge-0/0/0" && !snaps[i].IsUnit {
			snaps[i].Addresses = []InterfaceAddressSnapshot{{
				Family:  "inet",
				Address: "10.0.9.9/24",
			}}
			parentFound = true
		}
	}
	if !parentFound {
		t.Fatal("fixture did not produce the physical-parent snapshot")
	}
	views := BuildZoneHostInboundViewsFromSnapshots(cfg, snaps)
	parentView := false
	for _, view := range views {
		if view.Zone != "trust" {
			continue
		}
		var hasAddress, hasAll, hasParent bool
		for _, addr := range view.V4Addrs {
			hasAddress = hasAddress || addr == "10.0.9.9"
		}
		for _, svc := range view.SystemServices {
			hasAll = hasAll || svc == "all"
		}
		for _, ref := range view.Interfaces {
			hasParent = hasParent || ref == "ge-0/0/0"
		}
		if hasAddress && hasAll && hasParent {
			parentView = true
		}
	}
	if !parentView {
		t.Fatalf("physical parent address must be scoped by trust's zone-level all view; views=%+v", views)
	}
	for _, warning := range cfg.Warnings {
		if strings.Contains(warning, "#16737") {
			return
		}
	}
	t.Fatalf("the parent view admits SSH but the unmanaged-SSH commit advisory is absent; warnings=%q", cfg.Warnings)
}

// #17749: native-VLAN enforcement maps a distinct parent's address to its
// uniquely selected native unit's effective policy. A parent-key advisory
// must not use the zone fallback when that unit replaces `all` with `ping`.
func TestUnmanagedSSHAdvisoryUsesNativeVLANPolicy17749(t *testing.T) {
	cfg := compileTrunkFanUp13150(t, []string{
		"set interfaces ge-0/0/0 vlan-tagging",
		"set interfaces ge-0/0/0 native-vlan-id 1",
		"set interfaces ge-0/0/0 unit 1 vlan-id 1",
		"set interfaces ge-0/0/0 unit 1 family inet address 10.100.0.1/24",
		"set security zones security-zone trust host-inbound-traffic system-services all",
		"set security zones security-zone trust interfaces ge-0/0/0",
		"set security zones security-zone trust interfaces ge-0/0/0.1 host-inbound-traffic system-services ping",
	})

	snaps := buildInterfaceSnapshots(cfg)
	parentFound := false
	for i := range snaps {
		if snaps[i].Name == "ge-0/0/0" && !snaps[i].IsUnit {
			snaps[i].Addresses = []InterfaceAddressSnapshot{{
				Family:  "inet",
				Address: "10.0.9.9/24",
			}}
			parentFound = true
		}
	}
	if !parentFound {
		t.Fatal("fixture did not produce the physical-parent snapshot")
	}
	views := BuildZoneHostInboundViewsFromSnapshots(cfg, snaps)
	parentAddressViews := 0
	for _, view := range views {
		var hasAddress, hasPing, hasAll bool
		for _, addr := range view.V4Addrs {
			hasAddress = hasAddress || addr == "10.0.9.9"
		}
		for _, svc := range view.SystemServices {
			hasPing = hasPing || svc == "ping"
			hasAll = hasAll || svc == "all"
		}
		if !hasAddress {
			continue
		}
		parentAddressViews++
		if view.Zone != "trust" || !hasPing || hasAll || !contains(view.IngressNetdevs, "ge-0-0-0") {
			t.Fatalf("parent address must be owned exactly by trust's native-unit ping view; view=%+v all=%+v", view, views)
		}
	}
	if parentAddressViews != 1 {
		t.Fatalf("native parent address must have exactly one owning view, got %d: %+v", parentAddressViews, views)
	}
	for _, warning := range cfg.Warnings {
		if strings.Contains(warning, "#16737") {
			t.Fatalf("native parent follows unit 1's non-SSH override; must not warn; warnings=%q", cfg.Warnings)
		}
	}
}

// #17749: a zone label fanned up from a tagged-only unit is not a parent
// enforcement identity. The parent address stays in the unzoned catch-all,
// so the member's zone must not inherit a warning from that address.
func TestUnmanagedSSHAdvisoryIgnoresTaggedOnlyParentFanUp17749(t *testing.T) {
	cfg := compileTrunkFanUp13150(t, []string{
		"set interfaces ge-0/0/0 vlan-tagging",
		"set interfaces ge-0/0/0 unit 1 vlan-id 1",
		"set security zones security-zone trust host-inbound-traffic system-services all",
		"set security zones security-zone trust interfaces ge-0/0/0.1 host-inbound-traffic system-services ping",
	})

	snaps := buildInterfaceSnapshots(cfg)
	parentFound := false
	for i := range snaps {
		if snaps[i].Name == "ge-0/0/0" && !snaps[i].IsUnit {
			snaps[i].Addresses = []InterfaceAddressSnapshot{{
				Family:  "inet",
				Address: "10.0.9.9/24",
			}}
			parentFound = true
		}
	}
	if !parentFound {
		t.Fatal("fixture did not produce the physical-parent snapshot")
	}
	views := BuildZoneHostInboundViewsFromSnapshots(cfg, snaps)
	for _, view := range views {
		if contains(view.V4Addrs, "10.0.9.9") {
			t.Fatalf("tagged-only fan-up must not scope the parent address into zone %q: views=%+v", view.Zone, views)
		}
	}
	unzonedV4, _ := BuildUnzonedHostInboundAddrsFromSnapshots(cfg, snaps)
	if !contains(unzonedV4, "10.0.9.9") {
		t.Fatalf("tagged-only parent address must remain in unzoned catch-all; got %v", unzonedV4)
	}
	for _, warning := range cfg.Warnings {
		if strings.Contains(warning, "#16737") {
			t.Fatalf("tagged-only parent address is unzoned, so trust must not warn; warnings=%q", cfg.Warnings)
		}
	}
}

// #17749: a configured VLAN unit 0 can be a distinct parent carrier. Its
// zone label may come from the unit member, while the physical parent keeps
// the zone-level service set rather than unit 0's replacing override.
func TestUnmanagedSSHAdvisoryWarnsForDistinctUnitZeroParentCarrier17749(t *testing.T) {
	cfg := compileTrunkFanUp13150(t, []string{
		"set interfaces ge-0/0/0 vlan-tagging",
		"set interfaces ge-0/0/0 unit 0 vlan-id 100",
		"set interfaces ge-0/0/0 unit 0 family inet address 192.0.2.1/24",
		"set security zones security-zone trust host-inbound-traffic system-services all",
		"set security zones security-zone trust interfaces ge-0/0/0.0 host-inbound-traffic system-services ping",
	})

	snaps := buildInterfaceSnapshots(cfg)
	var parentFound, unitZeroFound bool
	var parentLinux, unitZeroLinux string
	for i := range snaps {
		switch {
		case snaps[i].Name == "ge-0/0/0" && !snaps[i].IsUnit:
			parentLinux = snaps[i].LinuxName
			snaps[i].Addresses = []InterfaceAddressSnapshot{{
				Family:  "inet",
				Address: "10.0.9.9/24",
			}}
			parentFound = true
		case snaps[i].Name == "ge-0/0/0.0" && snaps[i].IsUnit:
			unitZeroLinux = snaps[i].LinuxName
			unitZeroFound = true
		}
	}
	if !parentFound || !unitZeroFound {
		t.Fatalf("fixture snapshots must contain parent and unit 0: %+v", snaps)
	}
	if parentLinux == unitZeroLinux {
		t.Fatalf("unit 0 must be a distinct Linux carrier, parent=%q unit0=%q", parentLinux, unitZeroLinux)
	}
	views := BuildZoneHostInboundViewsFromSnapshots(cfg, snaps)
	parentAddressViews := 0
	for _, view := range views {
		if !contains(view.V4Addrs, "10.0.9.9") {
			continue
		}
		parentAddressViews++
		if view.Zone != "trust" || !contains(view.SystemServices, "all") {
			t.Fatalf("distinct parent address must use trust's zone-level all set; view=%+v", view)
		}
	}
	if parentAddressViews != 1 {
		t.Fatalf("parent address must have exactly one trust all view, got %d: %+v", parentAddressViews, views)
	}
	for _, warning := range cfg.Warnings {
		if strings.Contains(warning, "#16737") {
			return
		}
	}
	t.Fatalf("distinct unit-0 parent carries trust zone-level all; unmanaged-SSH advisory is absent; warnings=%q", cfg.Warnings)
}
