package config

import (
	"reflect"
	"testing"
)

// #11463: an administratively disabled routing-instance member must not leak
// its addresses into connected-prefix derivation. RoutingInstanceConnectedPrefixes
// collected every configured address on member units with no Disable check, so
// a disabled member's subnet entered the rib-group leak set and the kernel
// ip rules ApplyRibGroupRules installs from it (daemon_apply_routing.go), as
// well as the userspace FIB's connected routes.
//
// RED-before: the disabled member's prefix is present in both derivations.
func TestDisabledMemberExcludedFromConnectedDerivation11463(t *testing.T) {
	cfg := ribGroupLeakConfig([]string{"inet.0"}, []string{"10.0.30.1/24"})
	// The ribGroupLeakConfig member is enabled; add a DISABLED sibling member
	// carrying a distinct subnet, referenced both bare and as a unit so both
	// member spellings are covered.
	cfg.Interfaces.Interfaces["ge-0/0/2"] = &InterfaceConfig{
		Name:    "ge-0/0/2",
		Disable: true,
		Units: map[int]*InterfaceUnit{
			0: {Number: 0, Addresses: []string{"10.9.9.1/24"}},
			1: {Number: 1, Addresses: []string{"10.9.10.1/24"}},
		},
	}
	cfg.Interfaces.Interfaces["ge-0/0/3"] = &InterfaceConfig{
		Name:    "ge-0/0/3",
		Disable: true,
		Units: map[int]*InterfaceUnit{
			0: {Number: 0, Addresses: []string{"10.9.11.1/24"}},
		},
	}
	cfg.RoutingInstances = append(cfg.RoutingInstances,
		&RoutingInstanceConfig{
			Name:                    "parked-vr",
			TableID:                 103,
			Interfaces:              []string{"ge-0/0/2", "ge-0/0/3.0"},
			InterfaceRoutesRibGroup: "leak",
		})

	// The enabled control still derives.
	if got := RoutingInstanceConnectedPrefixes(cfg)["dmz-vr"]; !reflect.DeepEqual(got, []string{"10.0.30.0/24"}) {
		t.Fatalf("enabled-member control RoutingInstanceConnectedPrefixes[dmz-vr] = %q, want [10.0.30.0/24]", got)
	}
	// The disabled members derive nothing — neither the bare fan-down
	// (ge-0/0/2 units 0+1) nor the unit spelling (ge-0/0/3.0).
	if got := RoutingInstanceConnectedPrefixes(cfg)["parked-vr"]; len(got) != 0 {
		t.Fatalf("disabled-member RoutingInstanceConnectedPrefixes[parked-vr] = %q, want empty (leak into derivation)", got)
	}
	if got := RibGroupConnectedPrefixes(cfg)["parked-vr"]; len(got) != 0 {
		t.Fatalf("disabled-member RibGroupConnectedPrefixes[parked-vr] = %q, want empty (leak into rib-group rules)", got)
	}
	if got := RibGroupConnectedPrefixes(cfg)["dmz-vr"]; !reflect.DeepEqual(got, []string{"10.0.30.0/24"}) {
		t.Fatalf("enabled-member control RibGroupConnectedPrefixes[dmz-vr] = %q, want [10.0.30.0/24]", got)
	}
}
