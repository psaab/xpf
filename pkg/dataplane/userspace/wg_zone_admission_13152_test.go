// Issue #13152 (D3-06): buildUserspaceWGZoneMaps must fail closed (zone 0)
// when an unzoned or contested unit shares an (Ifindex, VLANID) ingress key
// with a zoned sibling, or when unit 0 is contested under a bare-zoned parent.
package userspace

import "testing"

func TestWGIngressUnzonedSiblingPoisonsUntagged13152(t *testing.T) {
	snap := &ConfigSnapshot{
		ZoneSetValidated: true,
		Zones:            []ZoneSnapshot{{Name: "wan", ID: 2}},
		Interfaces: []InterfaceSnapshot{
			{Name: "ge-0/0/0.0", IsUnit: true, Zone: "wan", Ifindex: 10, ParentIfindex: 10},
			{Name: "ge-0/0/0.1", IsUnit: true, Zone: "", Ifindex: 10, ParentIfindex: 10},
		},
	}
	plan, err := buildUserspaceWGZoneMaps(snap)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if got := plan.ingress[wgZone12855Key(10, userspaceWGUnTaggedVLANID)]; got != 0 {
		t.Fatalf("untagged ingress with unzoned sibling = %d, want 0 (fail-closed); full=%v", got, plan.ingress)
	}
}

func TestWGIngressUnzonedSiblingPoisonsTagged13152(t *testing.T) {
	snap := &ConfigSnapshot{
		ZoneSetValidated: true,
		Zones:            []ZoneSnapshot{{Name: "wan", ID: 2}},
		Interfaces: []InterfaceSnapshot{
			{Name: "ge-0/0/0.100", IsUnit: true, Zone: "wan", Ifindex: 11, ParentIfindex: 10, VLANID: 100},
			{Name: "ge-0/0/1.100", IsUnit: true, Zone: "", Ifindex: 11, ParentIfindex: 10, VLANID: 100},
		},
	}
	plan, err := buildUserspaceWGZoneMaps(snap)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if got := plan.ingress[wgZone12855Key(10, 100)]; got != 0 {
		t.Fatalf("tagged ingress with unzoned sibling = %d, want 0 (fail-closed); full=%v", got, plan.ingress)
	}
}

func TestWGIngressUnzonedNativeVLANSiblingPoisons13152(t *testing.T) {
	snap := &ConfigSnapshot{
		ZoneSetValidated: true,
		Zones:            []ZoneSnapshot{{Name: "wan", ID: 2}},
		Interfaces: []InterfaceSnapshot{
			{Name: "ge-0/0/0", Zone: "", Ifindex: 10, NativeVLANID: 100},
			{Name: "ge-0/0/0.100", IsUnit: true, Zone: "wan", Ifindex: 11, ParentIfindex: 10, VLANID: 100},
			{Name: "ge-0/0/1.100", IsUnit: true, Zone: "", Ifindex: 11, ParentIfindex: 10, VLANID: 100},
		},
	}
	plan, err := buildUserspaceWGZoneMaps(snap)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if got := plan.ingress[wgZone12855Key(10, userspaceWGUnTaggedVLANID)]; got != 0 {
		t.Fatalf("native-VLAN untagged ingress with unzoned sibling = %d, want 0 (fail-closed); full=%v", got, plan.ingress)
	}
}

func TestWGIngressContestedUnit0UnderBareZonedParent13152(t *testing.T) {
	// Bare parent authored in wan; unit 0 scrubbed to "" by quarantine.
	// wgFanUpBaseRows does NOT flag the authored base, so base claims untagged.
	snap := &ConfigSnapshot{
		ZoneSetValidated: true,
		Zones:            []ZoneSnapshot{{Name: "wan", ID: 2}, {Name: "dmz", ID: 3}},
		Interfaces: []InterfaceSnapshot{
			{Name: "ge-0/0/0", Zone: "wan", Ifindex: 10},
			{Name: "ge-0/0/0.0", IsUnit: true, Zone: "", Ifindex: 10, ParentIfindex: 10},
		},
	}
	plan, err := buildUserspaceWGZoneMaps(snap)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if got := plan.ingress[wgZone12855Key(10, userspaceWGUnTaggedVLANID)]; got != 0 {
		t.Fatalf("untagged ingress with contested unit 0 = %d, want 0 (fail-closed); full=%v", got, plan.ingress)
	}
}

// Positive controls: unanimous zoned ownership still admitted.
func TestWGIngressUnanimousZonedStillAdmitted13152(t *testing.T) {
	snap := &ConfigSnapshot{
		ZoneSetValidated: true,
		Zones:            []ZoneSnapshot{{Name: "wan", ID: 2}},
		Interfaces: []InterfaceSnapshot{
			{Name: "ge-0/0/0.0", IsUnit: true, Zone: "wan", Ifindex: 10, ParentIfindex: 10},
			{Name: "ge-0/0/0.1", IsUnit: true, Zone: "wan", Ifindex: 10, ParentIfindex: 10},
		},
	}
	plan, err := buildUserspaceWGZoneMaps(snap)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if got := plan.ingress[wgZone12855Key(10, userspaceWGUnTaggedVLANID)]; got != 2 {
		t.Fatalf("unanimous untagged ingress = %d, want wan(2)", got)
	}
}
