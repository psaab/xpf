package userspace

import "testing"

// #7509: pin the Go-side facts the Rust INGRESS refusal rests on.
//
// #6727 and #8407 both recorded that separating a base row whose zone the
// operator AUTHORED from one that merely INHERITED a sibling unit's zone needs
// a fact that "is not on the wire", and #8407 stopped at the zoned-vs-zoned
// contest for that reason. The fact is on the wire — just not on the row that
// needs it. It is in the row's UNIT SIBLINGS on the same ifindex:
//
//   - `InterfaceZoneMap` (pkg/config/host_inbound_effective_view.go) fans a
//     BARE `security-zone <z> interfaces <ifc>` reference DOWN onto every
//     configured unit, so an AUTHORED base has unit rows carrying its zone.
//   - It fans a UNIT-SUFFIXED reference UP to the base and NOT down to the
//     base's other units, so an INHERITED base has unit rows that do not.
//
// The base row is byte-identical in both. The unit siblings are not. Every cell
// below measures one half of that, plus the scope boundary that keeps the
// #921/#3618 trunk-parent inheritance intact.
//
// FAIL-ON-REVERT: restore the fan-DOWN's `continue` for a bare reference (or
// add a fan-down for a unit-suffixed one) in InterfaceZoneMap and
// TestUnitSiblingsCarryTheAuthoredVsInheritedFact_7509 goes RED on the arm that
// changed. That is the signal the Rust-side refusal in
// `forwarding_build/interfaces.rs` has lost its discriminator, not a reason to
// re-point this test.

// TestUnitSiblingsCarryTheAuthoredVsInheritedFact_7509 is the discriminator
// itself, stated as the one thing that differs between two configs whose BASE
// rows are identical.
func TestUnitSiblingsCarryTheAuthoredVsInheritedFact_7509(t *testing.T) {
	ifindexes := map[string]int{"ge-0-0-1": 24, "st0": 42, "st0.1": 43}
	macs := map[string]string{"ge-0-0-1": "02:bf:72:01:00:01"}

	// INHERITED: the operator named only st0.1. buildInterfaceZoneMap's fan-UP
	// writes out["st0"], so the BASE row carries vpnb — but unit 0, which the
	// operator deliberately left out of every zone, does not.
	_, inherited := buildSnapshotsFromSet6722(t, []string{
		"set interfaces ge-0/0/1 unit 0 family inet address 10.0.61.1/24",
		"set interfaces st0 unit 0 family inet address 10.5.5.1/30",
		"set interfaces st0 unit 1 family inet address 10.6.6.1/30",
		"set security zones security-zone lan interfaces ge-0/0/1.0",
		"set security zones security-zone vpnb interfaces st0.1",
	}, ifindexes, macs)

	// AUTHORED: the operator named the BARE interface. The fan-DOWN reaches
	// every configured unit, so unit 0 carries vpnb too.
	_, authoredSnaps := buildSnapshotsFromSet6722(t, []string{
		"set interfaces ge-0/0/1 unit 0 family inet address 10.0.61.1/24",
		"set interfaces st0 unit 0 family inet address 10.5.5.1/30",
		"set interfaces st0 unit 1 family inet address 10.6.6.1/30",
		"set security zones security-zone lan interfaces ge-0/0/1.0",
		"set security zones security-zone vpnb interfaces st0",
	}, ifindexes, macs)

	inheritedBase := snapByName6722(t, inherited, "st0")
	authoredBase := snapByName6722(t, authoredSnaps, "st0")
	inheritedUnit0 := snapByName6722(t, inherited, "st0.0")
	authoredUnit0 := snapByName6722(t, authoredSnaps, "st0.0")

	// THE POINT: the base rows are indistinguishable.
	if inheritedBase.Zone != "vpnb" || authoredBase.Zone != "vpnb" {
		t.Fatalf("base Zone inherited=%q authored=%q, want %q for both: if the two "+
			"base rows differ, the Rust side would not need the unit siblings and "+
			"this whole cell is measuring the wrong thing",
			inheritedBase.Zone, authoredBase.Zone, "vpnb")
	}
	if inheritedBase.Ifindex != 42 || authoredBase.Ifindex != 42 {
		t.Fatalf("base ifindex inherited=%d authored=%d, want 42 each (the primed "+
			"value): 0 means the row resolved no link at all",
			inheritedBase.Ifindex, authoredBase.Ifindex)
	}

	// THE DISCRIMINATOR: the unit row on that same ifindex is not.
	if inheritedUnit0.Ifindex != 42 || authoredUnit0.Ifindex != 42 {
		t.Fatalf("st0.0 ifindex inherited=%d authored=%d, want 42 each — the unit "+
			"row must share the base netdev or it cannot contradict the base row",
			inheritedUnit0.Ifindex, authoredUnit0.Ifindex)
	}
	if inheritedUnit0.Zone != "" {
		t.Errorf("INHERITED st0.0 Zone = %q, want empty: a unit-suffixed reference "+
			"speaks for st0.1 only, so unit 0 stays out of every zone and its row "+
			"is what tells the dataplane the base's vpnb was not authored here",
			inheritedUnit0.Zone)
	}
	if authoredUnit0.Zone != "vpnb" {
		t.Errorf("AUTHORED st0.0 Zone = %q, want %q: a BARE reference fans DOWN "+
			"onto every configured unit, so the unit row AGREES with the base and "+
			"nothing is refused", authoredUnit0.Zone, "vpnb")
	}
}

// TestTrunkWithNoUnitZeroPutsNoUnitRowOnTheParentIfindex_7509 is the SCOPE
// boundary: the Rust refusal is keyed on a unit row sharing the parent's
// ifindex, and a trunk whose units all have netdevs of their own puts none
// there. That is what keeps #921/#3618 — a parent inheriting its unit's zone
// for untagged traffic — working, and it is why "a zoned row plus an unzoned
// row on one ifindex is a contest" could not simply be widened into the rule.
//
// Both halves are measured in one cell on purpose. The absence claim ("no unit
// row lands on ifindex 90") is only evidence next to the positive control that
// the SAME builder does put one there when unit 0 is configured.
func TestTrunkWithNoUnitZeroPutsNoUnitRowOnTheParentIfindex_7509(t *testing.T) {
	ifindexes := map[string]int{"ge-0-0-9": 90, "ge-0-0-9.100": 91}
	macs := map[string]string{"ge-0-0-9": "02:bf:72:09:00:00", "ge-0-0-9.100": "02:bf:72:09:00:00"}

	unitsOn := func(snaps []InterfaceSnapshot, ifindex int) []string {
		var out []string
		for _, s := range snaps {
			if s.Ifindex != ifindex {
				continue
			}
			// Same test the Rust side applies (`is_logical_unit_row`): a Junos
			// interface name never contains a dot, so a numeric dotted suffix
			// is exactly a logical unit.
			for i := len(s.Name) - 1; i >= 0; i-- {
				if s.Name[i] == '.' {
					if i > 0 && i < len(s.Name)-1 {
						out = append(out, s.Name)
					}
					break
				}
			}
		}
		return out
	}

	// TAGGED-ONLY: no unit 0 in the config at all.
	_, taggedOnly := buildSnapshotsFromSet6722(t, []string{
		"set interfaces ge-0/0/9 vlan-tagging",
		"set interfaces ge-0/0/9 unit 100 vlan-id 100 family inet address 10.100.9.1/24",
		"set security zones security-zone lan interfaces ge-0/0/9.100",
	}, ifindexes, macs)

	if got := unitsOn(taggedOnly, 90); len(got) != 0 {
		t.Errorf("unit rows on the parent ifindex 90 = %v, want none: with unit 0 "+
			"absent the parent carries only its base row, so the #7509 refusal "+
			"cannot reach it and the child->parent propagation still applies", got)
	}
	base := snapByName6722(t, taggedOnly, "ge-0/0/9")
	if base.Ifindex != 90 {
		t.Fatalf("ge-0/0/9 base ifindex = %d, want the primed 90: 0 means nothing "+
			"resolved and the absence above is the failure default", base.Ifindex)
	}
	if base.Zone != "lan" {
		t.Errorf("ge-0/0/9 base Zone = %q, want %q — the fan-UP is what the "+
			"propagation corroborates; without it there is no inheritance to "+
			"preserve", base.Zone, "lan")
	}

	// POSITIVE CONTROL: declare unit 0 and the same builder DOES put a unit row
	// on ifindex 90. Without this the absence above is not evidence.
	_, withUnit0 := buildSnapshotsFromSet6722(t, []string{
		"set firewall family inet filter guard term t1 then accept",
		"set interfaces ge-0/0/9 unit 0 family inet filter input guard",
		"set interfaces ge-0/0/9 vlan-tagging",
		"set interfaces ge-0/0/9 unit 100 vlan-id 100 family inet address 10.100.9.1/24",
		"set security zones security-zone lan interfaces ge-0/0/9.100",
	}, ifindexes, macs)

	got := unitsOn(withUnit0, 90)
	if len(got) != 1 || got[0] != "ge-0/0/9.0" {
		t.Fatalf("control: unit rows on ifindex 90 with unit 0 declared = %v, want "+
			"exactly [ge-0/0/9.0] — if the builder never puts a unit row there, "+
			"the absence asserted above proves nothing", got)
	}
	if z := snapByName6722(t, withUnit0, "ge-0/0/9.0").Zone; z != "" {
		t.Errorf("control: ge-0/0/9.0 Zone = %q, want empty — the operator zoned "+
			"only the tagged unit, and that disagreement is what #7509 refuses", z)
	}
}

// TestTwoInterfacesOnOneIfindexAgreeingOnAZoneEgressToNothing_7509 measures the
// row shapes behind `reused_ifindex_agreeing_zones_snapshot_7509`
// (userspace-dp/src/afxdp/test_fixtures.rs).
//
// It is the LAST state in which the two Rust zone maps still disagree after
// #7509, which is what
// `unzoned_interface_with_egress_row_stays_zone_zero_6713` was retargeted onto:
// every row on the ifindex carries `vpnb`, so ingress admits it, while
// `stampEgressZones` refuses because `egressIdentitiesCohere` sees two
// INDEPENDENT interfaces claiming one device and agreement between two
// unrelated claimants is not authorisation.
//
// A hand-built Rust fixture cannot be trusted for this: the `v5()` helper
// stamps `egress_zone` whenever an ifindex's rows are unanimous, which is a
// convenience, not the Go rule. This cell is why that fixture overrides it.
func TestTwoInterfacesOnOneIfindexAgreeingOnAZoneEgressToNothing_7509(t *testing.T) {
	_, snaps := buildSnapshotsFromSet6722(t, []string{
		"set interfaces ge-0/0/1 unit 0 family inet address 10.0.61.1/24",
		"set interfaces st0 unit 0 family inet address 10.5.5.1/30",
		"set interfaces st1 unit 0 family inet address 10.9.9.1/30",
		"set security zones security-zone lan interfaces ge-0/0/1.0",
		"set security zones security-zone vpnb interfaces st0",
		"set security zones security-zone vpnb interfaces st1",
	}, map[string]int{"ge-0-0-1": 24, "st0": 42, "st1": 42},
		map[string]string{"ge-0-0-1": "02:bf:72:01:00:01"})

	lan := snapByName6722(t, snaps, "ge-0/0/1.0")
	// POSITIVE CONTROL first: an ifindex only ONE interface claims must still
	// resolve its zone, or "EgressZone is empty" below is the failure default.
	if lan.EgressZone != "lan" {
		t.Fatalf("control: ge-0/0/1.0 EgressZone = %q, want %q — stampEgressZones "+
			"resolved nothing at all, so the empty values below prove nothing",
			lan.EgressZone, "lan")
	}

	for _, name := range []string{"st0", "st0.0", "st1", "st1.0"} {
		row := snapByName6722(t, snaps, name)
		if row.Ifindex != 42 {
			t.Fatalf("%s ifindex = %d, want the primed 42 — the shape under test is "+
				"two interfaces sharing ONE ifindex", name, row.Ifindex)
		}
		if row.Zone != "vpnb" {
			t.Errorf("%s Zone = %q, want %q: every row on the shared ifindex must "+
				"AGREE, or ingress would refuse it too and the divergence this "+
				"fixture exists for would not exist", name, row.Zone, "vpnb")
		}
		if row.EgressZone != "" {
			t.Errorf("%s EgressZone = %q, want empty: two interfaces claim ifindex "+
				"42 and neither is the other's reth member, so the DEVICE identifies "+
				"no zone however much its rows agree", name, row.EgressZone)
		}
	}
}
