package cli

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
)

// #16065: the wire-VID rule lives in config.SessionIfaceNames now: a
// unit keys on uint16(unit.VlanID) only, never its number. The table
// below is exercised end-to-end by the egress-map test; the old
// sessionDisplayVLANID helper is gone with the shared derivation.

// #7153/#16065: keys on the WIRE vlan-id through the unit's OWN device.
// It was TestBuildSessionEgressIfaces_UsesUnitNumberWhenVlanIDUnset and
// synthesized `50: {Number: 50}` with no VlanID — a config the compiler
// treats as UNTAGGED, so it asserted a map shape no session row could
// match. The cluster it cites sets `vlan-id 50`/`vlan-id 80` explicitly
// (docs/ha-cluster-userspace.conf). #16065: the lookup receives the
// VLAN CHILD device ("ge-0-0-2.50"), which owns its ifindex — the
// parent netdev is never looked up for a unit with its own child.
func TestBuildSessionEgressIfaces_KeysOnWireVLANID_7153(t *testing.T) {
	cfg := &config.Config{
		Chassis: config.ChassisConfig{
			Cluster: &config.ClusterConfig{NodeID: 0},
		},
		Interfaces: config.InterfacesConfig{
			Interfaces: map[string]*config.InterfaceConfig{
				"reth0": {
					Name: "reth0",
					Units: map[int]*config.InterfaceUnit{
						50: {Number: 50, VlanID: 50},
						80: {Number: 80, VlanID: 80},
					},
				},
				"ge-0/0/2": {
					Name:            "ge-0/0/2",
					RedundantParent: "reth0",
				},
				"ge-7/0/2": {
					Name:            "ge-7/0/2",
					RedundantParent: "reth0",
				},
			},
		},
	}

	m := buildSessionEgressIfacesWithLookup(cfg, func(name string) (int, error) {
		switch name {
		case "ge-0-0-2.50":
			return 16, nil
		case "ge-0-0-2.80":
			return 18, nil
		default:
			t.Fatalf("unexpected lookup name %q (want the VLAN child device)", name)
			return 0, nil
		}
	})
	if len(m) == 0 {
		t.Fatal("expected non-empty egress interface map")
	}

	var found50, found80 bool
	for key, name := range m {
		if key.Ifindex == 16 && key.VlanID == 50 && name == "reth0.50" {
			found50 = true
		}
		if key.Ifindex == 18 && key.VlanID == 80 && name == "reth0.80" {
			found80 = true
		}
	}
	if !found50 {
		t.Fatalf("missing reth0.50 mapping at {16,50}: %v", m)
	}
	if !found80 {
		t.Fatalf("missing reth0.80 mapping at {18,80}: %v", m)
	}
}

func TestIfaceMatches(t *testing.T) {
	f := &sessionFilter{iface: "ge-0/0/0"}
	tests := []struct {
		name   string
		ifName string
		want   bool
	}{
		{"exact match", "ge-0/0/0", true},
		{"subinterface match", "ge-0/0/0.50", true},
		{"different interface", "ge-0/0/1", false},
		{"empty string", "", false},
		{"partial name", "ge-0/0/0x", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := f.ifaceMatches(tt.ifName); got != tt.want {
				t.Errorf("ifaceMatches(%q) = %v, want %v", tt.ifName, got, tt.want)
			}
		})
	}
}

func TestMatchesV4_InterfaceFilter(t *testing.T) {
	// Zone 1 = trust (ge-0/0/0), Zone 2 = untrust (ge-0/0/1)
	zoneIfaces := map[uint16][]string{1: {"ge-0/0/0"}, 2: {"ge-0/0/1"}}
	egressIfaces := map[sessionIfaceKey]string{
		{Ifindex: 10, VlanID: 0}: "ge-0/0/1",
		{Ifindex: 20, VlanID: 0}: "ge-0/0/2",
	}

	t.Run("matches ingress interface", func(t *testing.T) {
		f := &sessionFilter{
			iface:           "ge-0/0/0",
			zoneIfaces:      zoneIfaces,
			ifaceNamesByKey: egressIfaces,
		}
		key := dataplane.SessionKey{Protocol: 6}
		val := dataplane.SessionValue{IngressZone: 1, EgressZone: 2, FibIfindex: 10}
		if !f.matchesV4(key, val) {
			t.Error("expected match on ingress interface ge-0/0/0")
		}
	})

	t.Run("matches egress interface", func(t *testing.T) {
		f := &sessionFilter{
			iface:           "ge-0/0/1",
			zoneIfaces:      zoneIfaces,
			ifaceNamesByKey: egressIfaces,
		}
		key := dataplane.SessionKey{Protocol: 6}
		val := dataplane.SessionValue{IngressZone: 1, EgressZone: 2, FibIfindex: 10}
		if !f.matchesV4(key, val) {
			t.Error("expected match on egress interface ge-0/0/1")
		}
	})

	t.Run("no match when interface differs", func(t *testing.T) {
		f := &sessionFilter{
			iface:           "ge-0/0/2",
			zoneIfaces:      zoneIfaces,
			ifaceNamesByKey: egressIfaces,
		}
		key := dataplane.SessionKey{Protocol: 6}
		val := dataplane.SessionValue{IngressZone: 1, EgressZone: 2, FibIfindex: 10}
		if f.matchesV4(key, val) {
			t.Error("expected no match for ge-0/0/2")
		}
	})

	t.Run("matches egress via FIB lookup", func(t *testing.T) {
		f := &sessionFilter{
			iface:           "ge-0/0/2",
			zoneIfaces:      zoneIfaces,
			ifaceNamesByKey: egressIfaces,
		}
		key := dataplane.SessionKey{Protocol: 6}
		// FibIfindex 20 resolves to ge-0/0/2 via egressIfaces map
		val := dataplane.SessionValue{IngressZone: 1, EgressZone: 2, FibIfindex: 20}
		if !f.matchesV4(key, val) {
			t.Error("expected match on egress interface ge-0/0/2 via FIB")
		}
	})

	t.Run("no interface filter passes all", func(t *testing.T) {
		f := &sessionFilter{
			zoneIfaces:      zoneIfaces,
			ifaceNamesByKey: egressIfaces,
		}
		key := dataplane.SessionKey{Protocol: 6}
		val := dataplane.SessionValue{IngressZone: 1, EgressZone: 2, FibIfindex: 10}
		if !f.matchesV4(key, val) {
			t.Error("expected match when no interface filter set")
		}
	})
}
