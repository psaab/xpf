package userspace

import (
	"sort"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #6722 final-gate regression guards. The master-parity oracle is retained for
// unambiguous identities; it is intentionally not the oracle for the contested
// key in TestGoNeverNamesAZoneNoRowOnTheIfindexCarries_6722, where master chose
// an arbitrary sorted-name owner and the required tolerant result is no zone.
// The remaining cells pin the independently measured egress behaviors below.
//
// FAIL-ON-REVERT, measured with each hunk reverted ALONE:

//	drop the bare-ref fan-down in authoredZoneRefs (zones.go)
//	  -> RED: TestBareInterfaceZoneRefReachesItsOwnNetdevUnits_6722, all 3 cells;
//	     TestBareRefFanDownAgreesWithTheDerivedMap_6722
//	drop the egressOneOwnerUnitsAgree arm (interfaces.go, rule 1)
//	  -> RED: TestOneOwnersAgreeingUnitsStillResolveOneZone_6722/agreeing
//	let egressOneOwnerUnitsAgree ignore the OWNER test (accept identities of two
//	  different interfaces)
//	  -> RED: TestContestedNetdevOwnershipFailsClosed_6722 (3 of 5 cells),
//	     TestUnitlessRethNamedAsAMemberFailsClosedOnTheLenientPath_6722,
//	     TestNilUnitSlotOnARethMemberIsNotAnL3Identity_6722,
//	     TestBarePortOfADifferentRethDoesNotDeferToThisOne_6722

// One clause of egressOneOwnerUnitsAgree is a MEASURED SURVIVOR — the `z != ""`
// test on the agreed value — and the structural reason it cannot fire is
// recorded on the function itself rather than papered over with a fixture. The
// `unitRefs` recording of "" for an unauthored unit row is NOT a survivor: it is
// what makes /one-unit-unzoned and the E5 cell of
// TestContestedNetdevOwnershipFailsClosed_6722 fail closed, since it takes the
// set to size two.
//
// #6722 final-gate regression guards. A bare `aaa` reference and a dotted `zzz`
// reference both claim ge-0/0/1.100: the bare ref fans down to every configured
// unit. The strict compiler rejects this ambiguity; tolerant loads quarantine
// that logical key in both zone maps, so neither sorted name wins and the unit
// has no zone. An unambiguous single-zone control below still resolves `aaa`.
//
// The Rust corroboration remains relevant: `populate_interfaces` (userspace-dp/
// src/afxdp/forwarding_build/interfaces.rs) honors `egress_zone` only when some
// row on that ifindex carries that zone name. Quarantining the contested key
// leaves no uncorroborated answer for Rust to silently turn into the 0 sentinel.
//
// FAIL-ON-REVERT: restoring any first-writer ownership for a contested logical
// key makes the zero-zone assertions below RED.
//

// masterEgressZoneOfIfindex6722 replays origin/master's egress-zone answer for
// one ifindex from the rows this builder emits: the LAST row on that ifindex
// that would have received an `EgressInterface`, taking its own `Zone`.
//
// The `src_mac` gate is `parse_mac(hardware_addr)`, else the MAC of the BIND
// ifindex (parent_ifindex when set, else the row's own), else `[0;6]` for a
// tunnel row — see `populate_egress` in
// userspace-dp/src/afxdp/forwarding_build/interfaces.rs.
func masterEgressZoneOfIfindex6722(snaps []InterfaceSnapshot, ifindex int) (string, bool) {
	macOfIfindex := map[int]string{}
	for _, s := range snaps {
		if s.Ifindex > 0 && s.HardwareAddr != "" {
			macOfIfindex[s.Ifindex] = s.HardwareAddr
		}
	}
	zone, found := "", false
	for _, s := range snaps {
		if s.Ifindex != ifindex || s.Ifindex <= 0 {
			continue
		}
		bind := s.Ifindex
		if s.ParentIfindex > 0 {
			bind = s.ParentIfindex
		}
		if s.HardwareAddr == "" && macOfIfindex[bind] == "" && !s.Tunnel {
			continue
		}
		zone, found = s.Zone, true
	}
	return zone, found
}

// assertNoEgressZoneLostVsMaster6722 fails when master resolved a zone for
// `ifindex` and this tree resolves none. It deliberately does NOT assert
// equality: this PR's whole point is that master's answer could be a naming
// accident on a genuinely contested ifindex, and changing THAT is the fix. What
// is never right is losing a zone master had on an ifindex nothing contests.
func assertNoEgressZoneLostVsMaster6722(t *testing.T, snaps []InterfaceSnapshot, ifindex int, why string) {
	t.Helper()
	masterZone, reached := masterEgressZoneOfIfindex6722(snaps, ifindex)
	if !reached {
		t.Fatalf("precondition: no row on ifindex %d would have received an "+
			"EgressInterface on origin/master, so this cell cannot show a "+
			"regression against it", ifindex)
	}
	if masterZone == "" {
		t.Fatalf("precondition: origin/master resolved NO egress zone for "+
			"ifindex %d either, so a \"\" answer here is not a regression and "+
			"this cell proves nothing", ifindex)
	}
	got := egressZoneOfIfindex6722(t, snaps, ifindex)
	if got == "" {
		t.Errorf("egress zone of ifindex %d = \"\" (the 0 sentinel), but "+
			"origin/master resolved %q for it: %s. A to-zone of 0 matches no "+
			"exact, wildcard or junos-global rule, so every transit flow out of "+
			"this interface falls to the default policy — #6713 again, for a "+
			"different interface class", ifindex, masterZone, why)
	}
}

// P: a BARE `security-zone <z> interfaces <ifc>` reference must reach the
// interface's units that land on their OWN netdev.
//
// In xpf a bare interface reference MEANS "every unit of this interface is in
// this zone" — `buildInterfaceZoneMap` fans it down onto every configured unit,
// and the INGRESS half has always honoured that. A unit on its own netdev (any
// VLAN unit; any non-zero unit of a non-tunnel interface) has only its own row
// on that ifindex, so rule 2 needs the fan-down to see it and rule 3 is skipped
// by design because a unit row IS on the ifindex.
//
// Without the fan-down the ifindex resolves NO egress zone while its rows carry
// the operator's zone: ingress attributes arriving traffic to `lan` and egress
// answers 0 for the SAME ifindex. That asymmetry is the #6713 blackhole.
func TestBareInterfaceZoneRefReachesItsOwnNetdevUnits_6722(t *testing.T) {
	cases := []struct {
		name    string
		lines   []string
		links   map[string]int
		macs    map[string]string
		ifindex int
		want    string
		why     string
	}{
		{
			// P1: the ordinary Junos trunk — vlan-tagging parent, VLAN unit on
			// its own `<dev>.<vlan>` netdev, zone written on the PARENT.
			name: "vlan-tagging-trunk",
			lines: []string{
				"set interfaces ge-0/0/1 vlan-tagging",
				"set interfaces ge-0/0/1 unit 100 vlan-id 100",
				"set interfaces ge-0/0/1 unit 100 family inet address 10.0.100.1/24",
				"set security zones security-zone lan interfaces ge-0/0/1",
			},
			links:   map[string]int{"ge-0-0-1": 24, "ge-0-0-1.100": 25},
			macs:    map[string]string{"ge-0-0-1": "02:bf:72:01:00:01", "ge-0-0-1.100": "02:bf:72:01:00:01"},
			ifindex: 25,
			want:    "lan",
			why: "the operator put ge-0/0/1 in lan and unit 100 is a unit of " +
				"ge-0/0/1; nothing else claims ge-0-0-1.100",
		},
		{
			// P2: no VLAN involved — a plain interface with unit 0 AND unit 1.
			// Unit 0 collapses onto the base netdev, unit 1 does not.
			name: "second-unit-of-a-plain-interface",
			lines: []string{
				"set interfaces ge-0/0/1 unit 0 family inet address 10.0.1.1/24",
				"set interfaces ge-0/0/1 unit 1 family inet address 10.0.2.1/24",
				"set security zones security-zone lan interfaces ge-0/0/1",
			},
			links:   map[string]int{"ge-0-0-1": 24, "ge-0-0-1.1": 25},
			macs:    map[string]string{"ge-0-0-1": "02:bf:72:01:00:01", "ge-0-0-1.1": "02:bf:72:01:00:01"},
			ifindex: 25,
			want:    "lan",
			why:     "unit 1 is a unit of the bare-referenced ge-0/0/1",
		},
		{
			// P3: the shipped spelling. docs/ha-cluster-userspace.conf writes
			// `security-zone lan { interfaces { reth1; } }` — bare — and that
			// works today only because reth1's only unit is 0 and
			// collapses onto the base netdev. Give the reth a VLAN unit and the
			// same sentence has to keep working.
			name: "bare-reth-ref-with-a-vlan-unit",
			lines: []string{
				"set interfaces ge-0/0/1 gigether-options redundant-parent reth1",
				"set interfaces reth1 redundant-ether-options redundancy-group 1",
				"set interfaces reth1 vlan-tagging",
				"set interfaces reth1 unit 10 vlan-id 10",
				"set interfaces reth1 unit 10 family inet address 10.0.10.1/24",
				"set security zones security-zone lan interfaces reth1",
			},
			links:   map[string]int{"ge-0-0-1": 24, "ge-0-0-1.10": 25},
			macs:    map[string]string{"ge-0-0-1": "02:bf:72:01:00:01", "ge-0-0-1.10": "02:bf:72:01:00:01"},
			ifindex: 25,
			want:    "lan",
			why:     "`interfaces { reth1; }` is the spelling the reference cluster ships",
		},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			_, snaps := buildSnapshotsFromSet6722(t, tc.lines, tc.links, tc.macs)
			// The regression is defined against master, not against a constant.
			assertNoEgressZoneLostVsMaster6722(t, snaps, tc.ifindex, tc.why)
			assertEgressZone6722(t, snaps, tc.ifindex, tc.want, tc.why)
			// And the two DIRECTIONS must agree here: this ifindex is claimed by
			// exactly one identity, so there is no ambiguity for the egress half
			// to fail closed on.
			for _, s := range snaps {
				if s.Ifindex == tc.ifindex && s.Zone != s.EgressZone {
					t.Errorf("row %q on ifindex %d: ingress zone %q != egress zone %q; "+
						"an ifindex nothing contests must answer the same zone in "+
						"both directions", s.Name, s.Ifindex, s.Zone, s.EgressZone)
				}
			}
		})
	}
}

// Q: two logical units of ONE interface on ONE netdev that AGREE on a zone
// still resolve it; one that leaves a sibling unzoned still fails closed.
//
// `TunnelNameMap` maps every unit of an interface-level tunnel onto the tunnel
// device, so `gr-0/0/0`, `gr-0/0/0.0` and `gr-0/0/0.1` are one ifindex and two
// egress identities. Rule 1 refuses a multi-identity ifindex, which is right
// when the identities disagree (that refusal is
// TestContestedNetdevOwnershipFailsClosed_6722/two-tunnel-units-on-one-device,
// a measured fail-open otherwise) and wrong when every claimant on the device
// names the SAME zone — there is nothing to be ambiguous about, and refusing
// costs the tunnel every transit flow it has.
//
// The two sub-cells differ in ONE line: whether unit 1 is put in the same zone
// or left out of every zone. That is the discriminator, so neither cell can be
// passing for a fixture reason.
func TestOneOwnersAgreeingUnitsStillResolveOneZone_6722(t *testing.T) {
	base := []string{
		"set interfaces gr-0/0/0 tunnel source 10.0.61.1",
		"set interfaces gr-0/0/0 tunnel destination 10.0.61.2",
		"set interfaces gr-0/0/0 unit 0 family inet address 10.255.1.1/30",
		"set interfaces gr-0/0/0 unit 1 family inet address 10.255.2.1/30",
		"set security zones security-zone sfmix interfaces gr-0/0/0.0",
	}
	links := map[string]int{"gr-0-0-0": 30}

	t.Run("agreeing", func(t *testing.T) {
		lines := append(append([]string{}, base...),
			"set security zones security-zone sfmix interfaces gr-0/0/0.1")
		_, snaps := buildSnapshotsFromSet6722(t, lines, links, nil)
		assertNoEgressZoneLostVsMaster6722(t, snaps, 30,
			"both units of the tunnel are in sfmix, so the device identifies "+
				"exactly one zone and there is nothing to fail closed about")
		assertEgressZone6722(t, snaps, 30, "sfmix",
			"every identity on the netdev names sfmix")
	})

	t.Run("one-unit-unzoned", func(t *testing.T) {
		// The control, and the fail-closed this must not trade away: the
		// operator zoned unit 0 and left unit 1 out. The two units share one
		// kernel device, so honouring unit 0's zone would adjudicate unit 1's
		// transit under a policy written for its sibling.
		_, snaps := buildSnapshotsFromSet6722(t, base, links, nil)
		zoned := false
		for _, s := range snaps {
			if s.Ifindex == 30 && s.Zone != "" {
				zoned = true
			}
		}
		if !zoned {
			t.Fatalf("precondition: no row on ifindex 30 carries a zone, so a " +
				"\"\" answer proves nothing")
		}
		assertEgressZone6722(t, snaps, 30, "",
			"gr-0/0/0.1 was left out of every zone and that omission is a statement")
	})
}

// R: authoredZoneRefs' fan-down must not introduce a SECOND OPINION about a
// reference buildInterfaceZoneMap also holds. For unambiguous keys both maps
// fan a bare reference down over the same unit set and retain its owner; keys
// claimed by multiple zones are omitted from both. Otherwise the Rust
// corroboration (a claim is honoured only when some row on the ifindex literally
// carries that zone NAME) could refuse a disagreement the Go side decided,
// failing closed without identifying the underlying conflict.
func TestBareRefFanDownAgreesWithTheDerivedMap_6722(t *testing.T) {
	lines := []string{
		"set interfaces ge-0/0/1 vlan-tagging",
		"set interfaces ge-0/0/1 unit 0 family inet address 10.0.1.1/24",
		"set interfaces ge-0/0/1 unit 100 vlan-id 100",
		"set interfaces ge-0/0/1 unit 100 family inet address 10.0.100.1/24",
		"set interfaces ge-0/0/2 unit 0 family inet address 10.0.2.1/24",
		"set security zones security-zone lan interfaces ge-0/0/1",
		"set security zones security-zone wan interfaces ge-0/0/2",
	}
	cfg := compileWithStubbedLinks6722(t, lines,
		map[string]int{"ge-0-0-1": 24, "ge-0-0-1.100": 25, "ge-0-0-2": 26},
		map[string]string{"ge-0-0-1": "02:bf:72:01:00:01", "ge-0-0-2": "02:bf:72:01:00:02"},
		false)
	authored := authoredZoneRefs(cfg)
	derived := buildInterfaceZoneMap(cfg)
	if len(authored) == 0 {
		t.Fatalf("precondition: authoredZoneRefs is empty, so this cell is vacuous")
	}
	fannedDown := 0
	refs := make([]string, 0, len(authored))
	for ref := range authored {
		refs = append(refs, ref)
	}
	sort.Strings(refs)
	for _, ref := range refs {
		if got, want := derived[ref], authored[ref]; got != want {
			t.Errorf("buildInterfaceZoneMap[%q] = %q but authoredZoneRefs[%q] = %q; "+
				"the two maps must not hold a second opinion about one reference",
				ref, got, ref, want)
		}
		if ref == "ge-0/0/1.100" || ref == "ge-0/0/1.0" || ref == "ge-0/0/2.0" {
			fannedDown++
		}
	}
	if fannedDown != 3 {
		t.Fatalf("precondition: expected the bare refs to fan down onto 3 unit "+
			"references, got %d (%v); without the fan-down this cell compares "+
			"only the two literal refs and cannot see a disagreement about a "+
			"derived one", fannedDown, refs)
	}
}

// S: a bare `aaa` reference and a dotted `zzz` reference both claim the same
// logical VLAN unit. The strict path rejects the conflict; tolerant loads
// quarantine the unit in both the derived and authored zone maps. Neither map
// may retain a sorted-name winner, and the snapshot/egress views must stay
// unzoned for that unit.
//
// The parent's bare interface key remains unambiguous and keeps `aaa`. A
// single-zone control below verifies the ordinary fan-down still reaches the
// VLAN unit and produces a usable egress zone.
//
// FAIL-ON-REVERT: restoring any first-writer owner for the contested unit makes
// its zero-zone assertions RED.
func TestGoNeverNamesAZoneNoRowOnTheIfindexCarries_6722(t *testing.T) {
	lines := []string{
		"set interfaces ge-0/0/1 vlan-tagging",
		"set interfaces ge-0/0/1 unit 100 vlan-id 100",
		"set interfaces ge-0/0/1 unit 100 family inet address 10.0.100.1/24",
		"set security zones security-zone aaa interfaces ge-0/0/1",
		"set security zones security-zone zzz interfaces ge-0/0/1.100",
	}
	cfg := compileWithStubbedLinks6722(t, lines,
		map[string]int{"ge-0-0-1": 24, "ge-0-0-1.100": 25},
		map[string]string{"ge-0-0-1": "02:bf:72:01:00:01", "ge-0-0-1.100": "02:bf:72:01:00:01"},
		true)

	// Precondition: ge-0/0/1.100 is claimed by both zones and therefore belongs
	// to the quarantined logical-key set.
	if len(cfg.Security.Zones) != 2 {
		t.Fatalf("precondition: expected 2 zones, got %d", len(cfg.Security.Zones))
	}
	if _, conflicted := config.QuarantinedZoneInterfaceKeys(cfg)["ge-0/0/1.100"]; !conflicted {
		t.Fatalf("precondition: ge-0/0/1.100 is not marked as a contested key")
	}
	if got := buildInterfaceZoneMap(cfg)["ge-0/0/1.100"]; got != "" {
		t.Fatalf("contested derived map key ge-0/0/1.100 = %q, want no zone", got)
	}
	if got := authoredZoneRefs(cfg)["ge-0/0/1.100"]; got != "" {
		t.Fatalf("contested authored map key ge-0/0/1.100 = %q, want no zone", got)
	}

	snaps := buildInterfaceSnapshots(cfg)
	unit := snapByName6722(t, snaps, "ge-0/0/1.100")
	if unit.Zone != "" {
		t.Fatalf("contested unit Zone = %q, want no zone", unit.Zone)
	}
	if unit.EgressZone != "" {
		t.Fatalf("contested unit EgressZone = %q, want no zone", unit.EgressZone)
	}
	// The unrelated physical/base key remains a valid owner and retains its
	// egress zone; this guards against quarantining an entire interface family.
	assertNoEgressZoneLostVsMaster6722(t, snaps, 24,
		"the bare physical key itself is not contested")
	assertEgressZone6722(t, snaps, 24, "aaa",
		"the bare physical key remains owned by aaa")

	// Positive control: removing only the dotted zzz claim restores one owner.
	controlLines := lines[:4]
	control := compileWithStubbedLinks6722(t, controlLines,
		map[string]int{"ge-0-0-1": 24, "ge-0-0-1.100": 25},
		map[string]string{"ge-0-0-1": "02:bf:72:01:00:01", "ge-0-0-1.100": "02:bf:72:01:00:01"},
		false)
	if got := buildInterfaceZoneMap(control)["ge-0/0/1.100"]; got != "aaa" {
		t.Fatalf("single-owner control derived map key ge-0/0/1.100 = %q, want aaa", got)
	}
	assertEgressZone6722(t, buildInterfaceSnapshots(control), 25, "aaa",
		"the ordinary single-owner bare-ref fan-down still zones the VLAN egress")
}
