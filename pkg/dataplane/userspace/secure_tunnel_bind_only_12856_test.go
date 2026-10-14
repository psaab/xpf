package userspace

// #12856 (D4-13): the #7949 bind-only synthesis skipped the unit-0 row
// whenever an earlier row already carried the bind netdev's LinuxName —
// which is exactly what a `interfaces st0 unit <N> (N > 0)` stanza
// produces: a base row `st0` on netdev `st0` whose Zone is fan-up
// inherited from some other unit (first sorted zone wins), so
// `st0.0`'s own authored zone never governed its own ifindex. The
// synthesized row also never inherited interface-level CoS for a bare
// `st0` ref, because the lookup was gated on the ref being dotted.
//
// The fix reconciles OWNERSHIP instead of appending a duplicate: the
// synthesized unit row replaces the stanza base row iff that base's
// zone ref is not itself literally authored and the unit ref is. A
// bare-authored `interfaces st0` zone line keeps its base row
// untouched (explicit bare-authored zone member control).

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// stubD413Links makes the st0-family device and the LAN device exist.
func stubD413Links(t *testing.T) {
	t.Helper()
	restore := stubLinkSnapshot5619(t, map[string]int{"st0": 42, "ge-0-0-0": 11})
	t.Cleanup(restore)
}

func coSLines12856() []string {
	return []string{
		"set class-of-service forwarding-classes queue 0 best-effort",
		"set class-of-service schedulers be-sched transmit-rate 5g",
		"set class-of-service scheduler-maps edge-map forwarding-class best-effort scheduler be-sched",
	}
}

func countName12856(rows []InterfaceSnapshot, name string) int {
	n := 0
	for _, r := range rows {
		if r.Name == name {
			n++
		}
	}
	return n
}

// Core RED: unit>0 stanza present, st0.0 authored in vpn, base row is the
// ONLY row on the st0 ifindex and it must be replaced by the st0.0 row.
func TestBindOnlyUnitZeroRowDespiteUnitNStanza12856(t *testing.T) {
	cfg := compileForTest5619(t,
		"set security ipsec vpn v bind-interface st0",
		"set interfaces st0 unit 1 family inet address 10.5.5.1/30",
		"set security zones security-zone vpn interfaces st0.0",
		"set security zones security-zone vpn interfaces st0.1",
		"set interfaces ge-0/0/0 unit 0 family inet address 10.0.1.1/24",
		"set security zones security-zone trust interfaces ge-0/0/0.0",
	)
	stubD413Links(t)
	rows := buildInterfaceSnapshots(cfg)
	row, ok := rowByName7949(rows, "st0.0")
	if !ok {
		t.Fatalf("no st0.0 row: bind device st0 was suppressed by the unit-1 stanza's base row; rows=%v", rows)
	}
	if row.LinuxName != "st0" || row.Ifindex != 42 || row.Zone != "vpn" || row.EgressZone != "vpn" || !row.SecureTunnel || !row.IsUnit {
		t.Errorf("st0.0 row = %+v, want LinuxName st0, Ifindex 42, Zone/EgressZone vpn, SecureTunnel, IsUnit", row)
	}
	if n := countName12856(rows, "st0"); n != 0 {
		t.Errorf("base st0 row still present (%d): it would share ifindex 42 and conflict egress with st0.0", n)
	}
	// Exactly one row owns the bare st0 netdev: the unit-0 replacement.
	perIfx := 0
	for _, r := range rows {
		if r.Ifindex == 42 {
			perIfx++
		}
	}
	if perIfx != 1 {
		t.Errorf("rows on st0 ifindex = %d, want exactly one (avoids duplicate device ownership)", perIfx)
	}
}

// Alphabetical trap: unit0 in `lan`, unit1 in `dmz` (dmz sorts first, so
// the pre-fix base row Zone was "dmz" while its EgressZone was "lan").
// With units 0 AND 1 stanza'd, st0.0 must keep its own zone end-to-end.
func TestBindOnlyUnitZeroZoneNotAlphabeticalTrap12856(t *testing.T) {
	cfg := compileForTest5619(t,
		"set security ipsec vpn v bind-interface st0",
		"set interfaces st0 unit 0 family inet address 10.5.5.5/30",
		"set interfaces st0 unit 1 family inet address 10.5.5.1/30",
		"set security zones security-zone lan interfaces st0.0",
		"set security zones security-zone dmz interfaces st0.1",
		"set interfaces ge-0/0/0 unit 0 family inet address 10.0.1.1/24",
		"set security zones security-zone trust interfaces ge-0/0/0.0",
	)
	stubD413Links(t)
	rows := buildInterfaceSnapshots(cfg)
	row, ok := rowByName7949(rows, "st0.0")
	if !ok {
		t.Fatalf("no st0.0 row (it is the stanza unit 0; must exist)")
	}
	if row.Zone != "lan" || row.EgressZone != "lan" {
		t.Errorf("st0.0 Zone/EgressZone = %q/%q, want lan/lan (base-row fan-up must not win)", row.Zone, row.EgressZone)
	}
}

// Explicit bare-authored zone control: `interfaces st0` literally in the
// zone — the base row is authored and must NOT be replaced, and no
// st0.0 row is synthesized on top of it.
func TestBindOnlyBareAuthoredZoneKeepsBaseRow12856(t *testing.T) {
	cfg := compileForTest5619(t,
		"set security ipsec vpn v bind-interface st0",
		"set interfaces st0 unit 1 family inet address 10.5.5.1/30",
		"set security zones security-zone vpn interfaces st0",
		"set interfaces ge-0/0/0 unit 0 family inet address 10.0.1.1/24",
		"set security zones security-zone trust interfaces ge-0/0/0.0",
	)
	stubD413Links(t)
	rows := buildInterfaceSnapshots(cfg)
	if _, ok := rowByName7949(rows, "st0.0"); ok {
		t.Errorf("st0.0 synthesized although only bare st0 was zone-authored; the bare row owns the device")
	}
	base, ok := rowByName7949(rows, "st0")
	if !ok || base.Zone != "vpn" || base.EgressZone != "vpn" || base.Ifindex != 42 {
		t.Errorf("bare-authored base row = %+v (found=%v), want Zone/EgressZone vpn, Ifindex 42", base, ok)
	}
}

// The mixed shape WITHOUT a stanza anywhere: bind st0, zones st0.0+st0.1,
// no `interfaces st0` stanza at all — st0.0 already synthesized today;
// keep it and do not also emit a bare st0 row.
func TestBindOnlyDottedZonesNoBareRow12856(t *testing.T) {
	cfg := compileForTest5619(t,
		"set security ipsec vpn v bind-interface st0",
		"set interfaces st0 unit 1 family inet address 10.5.5.1/30",
		"set security zones security-zone vpn interfaces st0.0",
		"set security zones security-zone vpn interfaces st0.1",
		"set interfaces ge-0/0/0 unit 0 family inet address 10.0.1.1/24",
		"set security zones security-zone trust interfaces ge-0/0/0.0",
	)
	stubD413Links(t)
	rows := buildInterfaceSnapshots(cfg)
	if _, ok := rowByName7949(rows, "st0.0"); !ok {
		t.Errorf("st0.0 row missing for stanza-less bind")
	}
	if _, ok := rowByName7949(rows, "st0"); ok {
		t.Errorf("bare st0 row emitted although st0 was never zone-authored")
	}
}

// Bare-ref CoS: bind-only `st0` zoned as bare `st0` with an
// interface-level CoS binding — the synthesized base row must carry it.
func TestBindOnlyBareRefCarriesInterfaceLevelCoS12856(t *testing.T) {
	lines := []string{
		"set security ipsec vpn v bind-interface st0",
		"set security zones security-zone vpn interfaces st0",
		"set class-of-service interfaces st0 scheduler-map edge-map",
		"set class-of-service interfaces st0 shaping-rate 9g",
		"set interfaces ge-0/0/0 unit 0 family inet address 10.0.1.1/24",
		"set security zones security-zone trust interfaces ge-0/0/0.0",
	}
	lines = append(lines[:2:2], append(coSLines12856(), lines[2:]...)...)
	cfg := compileForTest5619(t, lines...)
	stubD413Links(t)
	rows := buildInterfaceSnapshots(cfg)
	row, ok := rowByName7949(rows, "st0")
	if !ok {
		t.Fatalf("no bare st0 row for bind-only tunnel; rows=%v", rows)
	}
	if row.CoSSchedulerMap != "edge-map" || row.CoSShapingRateBytesPerSec == 0 {
		t.Errorf("bare st0 row CoS = map %q rate %d, want edge-map / >0 (interface-level CoS dropped by the dotted gate)",
			row.CoSSchedulerMap, row.CoSShapingRateBytesPerSec)
	}
}

// Unit-level CoS still beats the interface level for the dotted ref.
func TestBindOnlyUnitCoSBeatsInterfaceLevel12856(t *testing.T) {
	lines := []string{
		"set security ipsec vpn v bind-interface st0.0",
		"set security zones security-zone vpn interfaces st0.0",
		"set class-of-service interfaces st0 scheduler-map edge-map",
		"set class-of-service interfaces st0 unit 0 scheduler-map unit-map",
		"set interfaces ge-0/0/0 unit 0 family inet address 10.0.1.1/24",
		"set security zones security-zone trust interfaces ge-0/0/0.0",
	}
	lines = append(lines[:2:2], append(coSLines12856(), lines[2:]...)...)
	// unit-map must exist as a scheduler-map too
	cfg := compileForTest5619(t, append(lines,
		"set class-of-service scheduler-maps unit-map forwarding-class best-effort scheduler be-sched")...)
	stubD413Links(t)
	rows := buildInterfaceSnapshots(cfg)
	row, ok := rowByName7949(rows, "st0.0")
	if !ok {
		t.Fatalf("no st0.0 row; rows=%v", rows)
	}
	if row.CoSSchedulerMap != "unit-map" {
		t.Errorf("st0.0 CoSSchedulerMap = %q, want unit-map (unit-level wins over interface level)", row.CoSSchedulerMap)
	}
}

// Non-zero bind unit cloned shape: bind st0.1, only st0.1 zoned — st0.0
// must NOT be synthesized (it is not authored).
func TestBindOnlyNonZeroBindDoesNotSynthesizeUnitZero12856(t *testing.T) {
	cfg := compileForTest5619(t,
		"set security ipsec vpn v bind-interface st0.1",
		"set security zones security-zone vpn interfaces st0.1",
		"set interfaces ge-0/0/0 unit 0 family inet address 10.0.1.1/24",
		"set security zones security-zone trust interfaces ge-0/0/0.0",
	)
	stubD413Links(t)
	rows := buildInterfaceSnapshots(cfg)
	if _, ok := rowByName7949(rows, "st0.0"); ok {
		t.Errorf("st0.0 synthesized for bind st0.1 although st0.0 was never authored")
	}
	if row, ok := rowByName7949(rows, "st0.1"); !ok || row.Zone != "vpn" {
		t.Errorf("st0.1 row = %+v (found=%v), want Zone vpn", row, ok)
	}
}

// Sanity: the synthesized replacement row is a config-derived device,
// not a reconstruction — derived-name check via XFRMIfNameAndID.
func TestBindOnlyUnitZeroDeviceDerived12856(t *testing.T) {
	cfg := compileForTest5619(t,
		"set security ipsec vpn v bind-interface st0",
		"set interfaces st0 unit 1 family inet address 10.5.5.1/30",
		"set security zones security-zone vpn interfaces st0.0",
		"set interfaces ge-0/0/0 unit 0 family inet address 10.0.1.1/24",
		"set security zones security-zone trust interfaces ge-0/0/0.0",
	)
	wantDev, ifID := config.XFRMIfNameAndID("st0")
	if ifID == 0 {
		t.Fatal("premise: st0 derives no if_id")
	}
	stubD413Links(t)
	rows := buildInterfaceSnapshots(cfg)
	row, ok := rowByName7949(rows, "st0.0")
	if !ok {
		t.Fatalf("no st0.0 row")
	}
	if row.LinuxName != wantDev {
		t.Errorf("st0.0 LinuxName = %q, want %q (derived from bind-interface)", row.LinuxName, wantDev)
	}
}

// The missing st0.0 row must not be replaced by the earlier base row's
// alphabetically inherited unit-1 zone.
func TestBindOnlyUnitZeroDoesNotInheritSiblingZone12856(t *testing.T) {
	cfg := compileForTest5619(t,
		"set security ipsec vpn v bind-interface st0",
		"set interfaces st0 unit 1 family inet address 10.5.5.1/30",
		"set security zones security-zone vpn interfaces st0.0",
		"set security zones security-zone dmz interfaces st0.1",
		"set interfaces ge-0/0/0 unit 0 family inet address 10.0.1.1/24",
		"set security zones security-zone trust interfaces ge-0/0/0.0",
	)
	stubD413Links(t)
	rows := buildInterfaceSnapshots(cfg)
	row, ok := rowByName7949(rows, "st0.0")
	if !ok {
		t.Fatalf("no synthesized st0.0 row; rows=%v", rows)
	}
	if row.Zone != "vpn" || row.EgressZone != "vpn" {
		t.Errorf("st0.0 Zone/EgressZone = %q/%q, want vpn/vpn; sibling zone dmz must not own unit 0",
			row.Zone, row.EgressZone)
	}
}
