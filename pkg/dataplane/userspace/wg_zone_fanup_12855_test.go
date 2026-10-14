// Issue #12855 (D4-10): buildUserspaceWGZoneMaps must not let a fan-up-zoned
// physical trunk base row claim untagged ingress or WireGuard address ownership.
package userspace

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

func wgZone12855Key(ifindex uint32, vlan uint16) userspaceWGIngressZoneKey {
	return userspaceWGIngressZoneKey{Ifindex: ifindex, VLANID: vlan}
}

// The base row's lan zone comes only from unit .100. Unit 0 is the genuine
// untagged owner on the same netdev and its primary address is a WG endpoint.
func wg12855TrunkSnapshot() *ConfigSnapshot {
	return &ConfigSnapshot{
		ZoneSetValidated: true,
		Zones:            []ZoneSnapshot{{Name: "lan", ID: 1}, {Name: "wan", ID: 2}},
		wgFanUpBaseRows:  map[string]bool{"ge-0/0/0": true},
		Interfaces: []InterfaceSnapshot{
			{Name: "ge-0/0/0", Zone: "lan", Ifindex: 10},
			{Name: "ge-0/0/0.0", IsUnit: true, Zone: "wan", Ifindex: 10, ParentIfindex: 10,
				Addresses: []InterfaceAddressSnapshot{{Family: "inet", Address: "198.51.100.1/24"}}},
			{Name: "ge-0/0/0.100", IsUnit: true, Zone: "lan", Ifindex: 11, ParentIfindex: 10, VLANID: 100,
				Addresses: []InterfaceAddressSnapshot{{Family: "inet", Address: "192.0.2.1/24"}}},
		},
		TunnelEndpoints:      []TunnelEndpointSnapshot{{Mode: "wireguard", Zone: "lan", Source: "198.51.100.1", WgListenPort: 51820}},
		WgSteeredListenPorts: []uint16{51820},
	}
}

func TestBuildUserspaceWGZoneMapsFanUpBaseDoesNotPoison12855(t *testing.T) {
	plan, err := buildUserspaceWGZoneMaps(wg12855TrunkSnapshot())
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if got, ok := plan.ingress[wgZone12855Key(10, userspaceWGUnTaggedVLANID)]; !ok || got != 2 {
		t.Fatalf("untagged ingress {10,0xffff} = %d (present=%v), want wan(2); full=%v", got, ok, plan.ingress)
	}
	if got := plan.ingress[wgZone12855Key(10, 100)]; got != 1 {
		t.Fatalf("tagged ingress {10,100} = %d, want lan(1)", got)
	}
	if got := plan.admission[wgAdmissionTestKey(2, wgAdmissionTestAddress)]; got != 1 {
		t.Fatalf("WG admission for unit-0 address = %d, want 1; admission=%v", got, plan.admission)
	}
}

func TestBuildUserspaceWGZoneMapsFanUpBaseAddressDoesNotPoison12855(t *testing.T) {
	snap := wg12855TrunkSnapshot()
	// The base row snapshots the shared unit-0 netdev address too.
	snap.Interfaces[0].Addresses = []InterfaceAddressSnapshot{{Family: "inet", Address: "198.51.100.1/24"}}
	plan, err := buildUserspaceWGZoneMaps(snap)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if got := plan.admission[wgAdmissionTestKey(2, wgAdmissionTestAddress)]; got != 1 {
		t.Fatalf("fan-up base address poisoned WG admission: got %d, want 1; admission=%v", got, plan.admission)
	}
	if got := plan.ingress[wgZone12855Key(10, userspaceWGUnTaggedVLANID)]; got != 2 {
		t.Fatalf("untagged ingress = %d, want wan(2)", got)
	}
}

func TestBuildUserspaceWGZoneMapsStandaloneBaseKeepsUntagged12855(t *testing.T) {
	snap := &ConfigSnapshot{
		ZoneSetValidated: true,
		Zones:            []ZoneSnapshot{{Name: "lan", ID: 1}, {Name: "wan", ID: 2}},
		Interfaces: []InterfaceSnapshot{{Name: "ge-0/0/1", Zone: "wan", Ifindex: 20,
			Addresses: []InterfaceAddressSnapshot{{Family: "inet", Address: "198.51.100.1/24"}}}},
		TunnelEndpoints:      []TunnelEndpointSnapshot{{Mode: "wireguard", Zone: "lan", Source: "198.51.100.1", WgListenPort: 51820}},
		WgSteeredListenPorts: []uint16{51820},
	}
	plan, err := buildUserspaceWGZoneMaps(snap)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if got := plan.ingress[wgZone12855Key(20, userspaceWGUnTaggedVLANID)]; got != 2 {
		t.Fatalf("standalone untagged ingress = %d, want wan(2)", got)
	}
	if got := plan.admission[wgAdmissionTestKey(2, wgAdmissionTestAddress)]; got != 1 {
		t.Fatalf("standalone WG admission = %d, want 1", got)
	}
}

func TestBuildUserspaceWGZoneMapsNativeVLANStillOwnsUntagged12855(t *testing.T) {
	snap := wg12855TrunkSnapshot()
	snap.Interfaces[0].NativeVLANID = 100
	// Native VLAN owns untagged arrivals even with no unit-0 row.
	snap.Interfaces = append(snap.Interfaces[:1], snap.Interfaces[2])
	plan, err := buildUserspaceWGZoneMaps(snap)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if got := plan.ingress[wgZone12855Key(10, userspaceWGUnTaggedVLANID)]; got != 1 {
		t.Fatalf("native-VLAN untagged ingress = %d, want lan(1)", got)
	}
}

func TestBuildUserspaceWGZoneMapsAuthoredBaseRetainsUntagged12855(t *testing.T) {
	snap := wg12855TrunkSnapshot()
	delete(snap.wgFanUpBaseRows, "ge-0/0/0")
	snap.Interfaces[0].Zone = "wan"
	plan, err := buildUserspaceWGZoneMaps(snap)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if got := plan.ingress[wgZone12855Key(10, userspaceWGUnTaggedVLANID)]; got != 2 {
		t.Fatalf("authored base untagged ingress = %d, want wan(2)", got)
	}
	if got := plan.ingress[wgZone12855Key(10, 100)]; got != 1 {
		t.Fatalf("tagged ingress = %d, want lan(1)", got)
	}
}

func TestBuildUserspaceWGZoneMapsLegacySnapshotZoneStillWorks12855(t *testing.T) {
	snap := wgAdmissionTestSnapshot("wan", "lan")
	plan, err := buildUserspaceWGZoneMaps(snap)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if got := plan.ingress[wgZone12855Key(20, userspaceWGUnTaggedVLANID)]; got != 2 {
		t.Fatalf("legacy snapshot untagged ingress = %d, want wan(2)", got)
	}
}

func TestBuildUserspaceWGZoneMapsNilSnapshot12855(t *testing.T) {
	plan, err := buildUserspaceWGZoneMaps(nil)
	if err != nil {
		t.Fatalf("build nil snapshot: %v", err)
	}
	if len(plan.ingress) != 0 || len(plan.admission) != 0 {
		t.Fatalf("nil snapshot produced WG maps: %+v", plan)
	}
}

func TestWGFanUpBaseRowsDerivation12855(t *testing.T) {
	// Derivation wiring (review F1): a compiled config zoning only the
	// .100 unit must flag exactly the physical base; an authored bare
	// base ref must NOT be flagged.
	tree := &config.ConfigTree{}
	for _, l := range []string{
		"set interfaces ge-0/0/0 unit 0 family inet address 10.0.0.1/24",
		"set interfaces ge-0/0/0 unit 100 vlan-id 100 family inet address 10.0.100.1/24",
		"set security zones security-zone wan interfaces ge-0/0/0.0",
		"set security zones security-zone lan interfaces ge-0/0/0.100",
	} {
		p, err := config.ParseSetCommand(l)
		if err != nil {
			t.Fatalf("parse %q: %v", l, err)
		}
		if err := tree.SetPath(p); err != nil {
			t.Fatalf("setpath %q: %v", l, err)
		}
	}
	cfg, err := config.CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	rows := wgFanUpBaseRows(cfg)
	if len(rows) != 1 || !rows["ge-0/0/0"] {
		t.Fatalf("fan-up base rows = %v, want exactly {ge-0/0/0}", rows)
	}
}
