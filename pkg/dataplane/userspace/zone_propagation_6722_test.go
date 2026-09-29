package userspace

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #6722: pin the Go-side facts the Rust egress-zone resolver's design rests on.
// `ForwardingState::egress_zone_id` (userspace-dp/src/afxdp/types/forwarding.rs)
// falls back for an interface with no `egress` row — a MAC-less xfrmi — and the
// userspace-dp fixtures that exercise that path
// (`sibling_tunnel_units_snapshot_6722` and its siblings in
// userspace-dp/src/afxdp/test_fixtures.rs) hand-build ConfigSnapshot rows.
// A hand-built row can model a snapshot this builder never emits, and a fixture
// the builder cannot produce is not evidence — that is exactly how #6722's
// first two rounds went wrong.
//
// The facts:
//
//  1. A unit-suffixed zone reference zones the BASE interface too
//     (buildInterfaceZoneMap). Zoning st0.1 zones st0.
//  2. A non-VLAN unit 0 COLLAPSES onto the base netdev (snapshotLinuxName), so
//     the base row and the unit-0 row carry ONE ifindex.
//  3. StableZoneID quarantine exclusions are applied by InterfaceZoneMap before
//     snapshots are built. A losing zone remains in the authored config but
//     contributes no runtime interface-zone mapping; the published zone set
//     also excludes it.
//
// Facts 1 + 2 mean an ifindex is not a unit identity: a MAC-less unit 0 shares
// its base's ifindex with a differently-zoned sibling. That is why the egress
// half reads `ifindex_unambiguous_zone_id` — an ifindex whose rows DISAGREE
// resolves the 0 sentinel rather than inheriting an unambiguous sibling's zone.
//
// The loser-exclusion precondition below checks the raw authored membership as
// well as the runtime map. A zero-zone result therefore proves the configured
// losing claim was dropped, not that the test accidentally omitted it.
//
// FAIL-ON-REVERT: drop the `out[base] = zoneName` write in
// buildInterfaceZoneMap (zones.go) — a plausible move toward Junos per-unit
// zoning — and case A goes RED on the base row's zone. That is the signal to
// revisit the Rust-side reasoning, not to re-point this test.

// compileWithStubbedLinks6722 installs the buildLinkSnapshot stub for the
// duration of the test and compiles `lines` into a config. An interface absent
// from ifindexOf resolves to ifindex 0 / empty MAC, exactly as an unresolvable
// link does on the real path — which is why the callers pin the EXPECTED
// ifindex rather than comparing two rows to each other.
func treeFromSet6722(t *testing.T, lines []string) *config.ConfigTree {
	t.Helper()
	tree := &config.ConfigTree{}
	for _, cmd := range lines {
		path, err := config.ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", cmd, err)
		}
	}
	return tree
}

func compileWithStubbedLinks6722(t *testing.T, lines []string, ifindexOf map[string]int, macOf map[string]string, lenient bool) *config.Config {
	t.Helper()
	prev := buildLinkSnapshot
	t.Cleanup(func() { buildLinkSnapshot = prev })
	buildLinkSnapshot = func(linuxName string) (int, int, string, []InterfaceAddressSnapshot) {
		idx, ok := ifindexOf[linuxName]
		if !ok {
			return 0, 0, "", nil
		}
		return idx, 1500, macOf[linuxName], nil
	}

	tree := treeFromSet6722(t, lines)
	compile := config.CompileConfig
	name := "CompileConfig"
	if lenient {
		compile = config.CompileConfigLenient
		name = "CompileConfigLenient"
	}
	cfg, err := compile(tree)
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	return cfg
}

func buildSnapshotsFromSet6722(t *testing.T, lines []string, ifindexOf map[string]int, macOf map[string]string) (map[string]string, []InterfaceSnapshot) {
	t.Helper()
	cfg := compileWithStubbedLinks6722(t, lines, ifindexOf, macOf, false)
	return buildInterfaceZoneMap(cfg), buildInterfaceSnapshots(cfg)
}

func snapByName6722(t *testing.T, snaps []InterfaceSnapshot, name string) InterfaceSnapshot {
	t.Helper()
	for _, s := range snaps {
		if s.Name == name {
			return s
		}
	}
	t.Fatalf("no interface snapshot named %q (have %d rows)", name, len(snaps))
	return InterfaceSnapshot{}
}

// A: two secure tunnels on one st0, zone on st0.1 only. Mirrors
// `sibling_tunnel_units_snapshot_6722`.
func TestSiblingTunnelUnitsZoneTheBaseRow_6722(t *testing.T) {
	zoneByIface, snaps := buildSnapshotsFromSet6722(t, []string{
		"set interfaces ge-0/0/1 unit 0 family inet address 10.0.61.1/24",
		"set interfaces st0 unit 0 family inet address 10.5.5.1/30",
		"set interfaces st0 unit 1 family inet address 10.6.6.1/30",
		"set security zones security-zone lan interfaces ge-0/0/1.0",
		"set security zones security-zone vpnb interfaces st0.1",
	}, map[string]int{"ge-0-0-1": 24, "st0": 42, "st0.1": 43},
		map[string]string{"ge-0-0-1": "02:bf:72:01:00:01"})

	if got := zoneByIface["st0"]; got != "vpnb" {
		t.Fatalf("buildInterfaceZoneMap[st0] = %q, want %q: a unit-suffixed zone "+
			"reference must zone the base interface too", got, "vpnb")
	}

	base := snapByName6722(t, snaps, "st0")
	unit0 := snapByName6722(t, snaps, "st0.0")
	unit1 := snapByName6722(t, snaps, "st0.1")
	lan := snapByName6722(t, snaps, "ge-0/0/1.0")

	if base.Zone != "vpnb" {
		t.Errorf("st0 base row Zone = %q, want %q: the userspace-dp fixture models "+
			"this row as zoned, and it is what makes unit 0's shared ifindex "+
			"AMBIGUOUS", base.Zone, "vpnb")
	}
	// Pin the ifindexes to the values the stub was primed with, not merely to
	// each other. `buildLinkSnapshot` returns 0 for a link it does not know, so
	// a bare `unit0.Ifindex != base.Ifindex` check passes as 0 == 0 for a
	// snapshot in which NEITHER row resolved — the failure default. The Rust
	// fixtures use 42 for the shared ifindex and 43 for st0.1.
	if base.Ifindex != 42 {
		t.Errorf("st0 base ifindex = %d, want 42 (the value the buildLinkSnapshot "+
			"stub was primed with): 0 here means the row resolved no link at all",
			base.Ifindex)
	}
	if unit0.Ifindex != 42 {
		t.Errorf("st0.0 ifindex = %d, want 42 == the base ifindex: a non-VLAN unit 0 "+
			"must collapse onto the base netdev", unit0.Ifindex)
	}
	if unit0.Zone != "" {
		t.Errorf("st0.0 Zone = %q, want empty: the operator referenced only st0.1, "+
			"so unit 0 gets no direct entry — that DISAGREEMENT with the base row "+
			"on one ifindex is what the Rust ambiguity gate keys on", unit0.Zone)
	}
	if unit1.Ifindex != 43 {
		t.Errorf("st0.1 ifindex = %d, want 43 and NOT the base's 42: "+
			"bind-interface st0.1 is its own xfrmi netdev", unit1.Ifindex)
	}
	if unit1.Zone != "vpnb" {
		t.Errorf("st0.1 Zone = %q, want %q", unit1.Zone, "vpnb")
	}
	// POSITIVE CONTROL for the MAC assertions below. An empty HardwareAddr is
	// also what the stub returns for a link it cannot resolve, so "the xfrmi
	// rows are MAC-less" is only evidence once some row in the SAME snapshot,
	// through the SAME stub, carries a non-empty MAC.
	if lan.HardwareAddr != "02:bf:72:01:00:01" {
		t.Fatalf("control: ge-0/0/1.0 HardwareAddr = %q, want %q — the MAC never "+
			"reached the snapshot, so the empty xfrmi MACs below prove nothing",
			lan.HardwareAddr, "02:bf:72:01:00:01")
	}
	if base.HardwareAddr != "" || unit0.HardwareAddr != "" || unit1.HardwareAddr != "" {
		t.Errorf("the xfrmi rows must be MAC-less (ARPHRD_NONE) — that is what denies "+
			"them a populate_egress row and makes the #6713 fallback the only "+
			"resolver: base=%q unit0=%q unit1=%q",
			base.HardwareAddr, unit0.HardwareAddr, unit1.HardwareAddr)
	}
}

// B: a zoned trunk with a declared-but-unzoned unit 0. Mirrors the scoping
// control in `secure_tunnel_snapshot_6713` — the shape that makes
// `egress_zone_id`'s `Some(0)` short-circuit load-bearing, because both rows on
// the shared ifindex are MAC-ful and populate_egress is last-write-wins.
func TestZonedTrunkEmitsUnzonedUnit0OnTheSharedIfindex_6722(t *testing.T) {
	_, snaps := buildSnapshotsFromSet6722(t, []string{
		"set firewall family inet filter guard term t1 then accept",
		"set interfaces ge-0/0/9 unit 0 family inet filter input guard",
		"set interfaces ge-0/0/9 unit 100 vlan-id 100 family inet address 10.100.9.1/24",
		"set security zones security-zone lan interfaces ge-0/0/9.100",
	}, map[string]int{"ge-0-0-9": 90, "ge-0-0-9.100": 91},
		map[string]string{"ge-0-0-9": "02:bf:72:09:00:00", "ge-0-0-9.100": "02:bf:72:09:00:00"})

	base := snapByName6722(t, snaps, "ge-0/0/9")
	unit0 := snapByName6722(t, snaps, "ge-0/0/9.0")
	unit100 := snapByName6722(t, snaps, "ge-0/0/9.100")

	if base.Zone != "lan" {
		t.Errorf("ge-0/0/9 base row Zone = %q, want %q: the VLAN unit's zone "+
			"reference zones the base", base.Zone, "lan")
	}
	if unit0.Zone != "" {
		t.Errorf("ge-0/0/9.0 Zone = %q, want empty", unit0.Zone)
	}
	// Pinned to the primed values, not merely to each other: an unresolved link
	// yields ifindex 0 from the stub, so `unit0.Ifindex != base.Ifindex` alone
	// passes as 0 == 0 on a snapshot where nothing resolved.
	if base.Ifindex != 90 {
		t.Errorf("ge-0/0/9 base ifindex = %d, want 90 (the primed value)", base.Ifindex)
	}
	if unit0.Ifindex != 90 {
		t.Errorf("ge-0/0/9.0 ifindex = %d, want 90 == base: unit 0 must collapse onto "+
			"the base netdev, which is what makes populate_egress overwrite the base "+
			"row's zone_id with 0", unit0.Ifindex)
	}
	if base.HardwareAddr == "" || unit0.HardwareAddr == "" {
		t.Errorf("both rows on the shared ifindex must be MAC-ful so BOTH reach "+
			"populate_egress: base=%q unit0=%q", base.HardwareAddr, unit0.HardwareAddr)
	}
	if unit100.Ifindex != 91 {
		t.Errorf("the tagged unit must have its OWN ifindex, want the primed 91, got "+
			"%d (base is %d)", unit100.Ifindex, base.Ifindex)
	}
	if unit100.Zone != "lan" {
		t.Errorf("ge-0/0/9.100 Zone = %q, want %q", unit100.Zone, "lan")
	}

	// The ordering populate_egress depends on: the base row is emitted BEFORE
	// its unit rows, so the unzoned unit-0 row is the last write on ifindex 90.
	baseIdx, unit0Idx := -1, -1
	for i, s := range snaps {
		switch s.Name {
		case "ge-0/0/9":
			baseIdx = i
		case "ge-0/0/9.0":
			unit0Idx = i
		}
	}
	if !(baseIdx >= 0 && unit0Idx > baseIdx) {
		t.Errorf("emission order base=%d unit0=%d: the unit-0 row must follow its "+
			"base row for populate_egress's last-write-wins to leave zone_id 0 on "+
			"the shared ifindex", baseIdx, unit0Idx)
	}
}

// C: the StableZoneID QUARANTINE shape, measured through the FULL buildSnapshot
// rather than through buildInterfaceSnapshots alone. Mirrors
// `quarantined_base_tunnel_snapshot_6722` in
// userspace-dp/src/afxdp/test_fixtures.rs.
//
// The z174/z214 collision is real: z214 is the later-sorting name and is
// excluded from runtime zone maps before snapshot construction. Its authored
// st0.0 claim therefore leaves no unit-0 owner; the unrelated st0.1 claim in
// zzzz remains a positive control. The base key may be derived from that
// surviving unit, but the shared base/unit-0 ifindex must not acquire an egress
// zone from the sibling.
func TestQuarantineDoesNotPromoteSiblingEgressZone_6722(t *testing.T) {
	if config.StableZoneID("z174") != config.StableZoneID("z214") {
		t.Fatalf("test premise broken: z174/z214 no longer collide under the frozen fold")
	}
	lines := []string{
		"set interfaces ge-0/0/1 unit 0 family inet address 10.0.61.1/24",
		"set interfaces st0 unit 0 family inet address 10.5.5.1/30",
		"set interfaces st0 unit 1 family inet address 10.6.6.1/30",
		"set security zones security-zone lan interfaces ge-0/0/1.0",
		"set security zones security-zone z174 host-inbound-traffic system-services ping",
		"set security zones security-zone z214 interfaces st0.0",
		"set security zones security-zone zzzz interfaces st0.1",
		"set security policies default-policy deny-all",
	}
	// The quarantine can only ever see a colliding config on the LENIENT path.
	// The strict compiler — the interactive `commit` gate — rejects the pair
	// outright (#3075), which is why the shape below is reachable on boot, HA
	// peer-sync and pre-#3075-persisted loads and nowhere else. Pinning the
	// rejection here keeps the lenient compile from silently becoming the only
	// path anyone tests.
	if _, err := config.CompileConfig(treeFromSet6722(t, lines)); err == nil {
		t.Fatalf("strict CompileConfig accepted the z174/z214 collision: the " +
			"commit-time gate is gone and this test no longer describes the only " +
			"way a colliding snapshot reaches the quarantine")
	}
	cfg := compileWithStubbedLinks6722(t, lines,
		map[string]int{"ge-0-0-1": 24, "st0": 42, "st0.1": 43},
		map[string]string{"ge-0-0-1": "02:bf:72:01:00:01"}, true)

	// The authored claim remains present but a StableZoneID loser is omitted
	// from runtime maps before snapshot construction. Verify both halves so the
	// empty unit-0 result below cannot pass because the config lacked the claim.
	losingZone := cfg.Security.Zones["z214"]
	authoredUnit0 := false
	if losingZone != nil {
		for _, ref := range losingZone.Interfaces {
			if ref == "st0.0" {
				authoredUnit0 = true
				break
			}
		}
	}
	if !authoredUnit0 {
		t.Fatalf("precondition: z214 does not author the st0.0 membership")
	}
	if _, excluded := quarantinedZoneNames(cfg)["z214"]; !excluded {
		t.Fatalf("precondition: z214 is not excluded by StableZoneID quarantine")
	}
	if got := buildInterfaceZoneMap(cfg)["st0.0"]; got != "" {
		t.Fatalf("quarantined st0.0 runtime zone = %q, want no owner", got)
	}

	snap, err := buildSnapshot(cfg, config.UserspaceConfig{}, 1, 0)
	if err != nil {
		t.Fatalf("buildSnapshot: %v", err)
	}
	if len(snap.zoneIDCollisions) == 0 {
		t.Fatalf("no collision reported: the quarantine did not exclude the "+
			"colliding zone from the published set (zones=%d)", len(snap.Zones))
	}

	base := snapByName6722(t, snap.Interfaces, "st0")
	unit0 := snapByName6722(t, snap.Interfaces, "st0.0")
	unit1 := snapByName6722(t, snap.Interfaces, "st0.1")

	if base.Zone != "zzzz" {
		t.Errorf("st0 base Zone = %q, want zzzz from the surviving st0.1 claim",
			base.Zone)
	}
	if unit0.Zone != "" {
		t.Errorf("post-quarantine st0.0 Zone = %q, want empty", unit0.Zone)
	}
	if unit1.Zone != "zzzz" {
		t.Fatalf("st0.1 Zone = %q, want %q: the surviving unit remains a "+
			"positive control while the losing unit-0 membership is omitted",
			unit1.Zone, "zzzz")
	}
	if base.EgressZone != "" || unit0.EgressZone != "" {
		t.Errorf("st0/st0.0 EgressZone = %q/%q, want empty: the surviving "+
			"st0.1 claim must not become an egress owner for the shared "+
			"base/unit-0 ifindex", base.EgressZone, unit0.EgressZone)
	}
	if unit1.EgressZone != "zzzz" {
		t.Errorf("st0.1 EgressZone = %q, want zzzz: the surviving unit remains "+
			"the positive control", unit1.EgressZone)
	}
	if base.Ifindex != 42 || unit0.Ifindex != 42 {
		t.Errorf("st0 base / st0.0 ifindexes = %d / %d, want 42 each: the base "+
			"and losing unit 0 share ONE ifindex, whose egress owner must stay empty",
			base.Ifindex, unit0.Ifindex)
	}
	if unit1.Ifindex != 43 {
		t.Errorf("st0.1 ifindex = %d, want 43 (its own netdev)", unit1.Ifindex)
	}
	// The surviving zone must remain published so the unit-1 positive control
	// can resolve it.
	surviving := false
	for _, z := range snap.Zones {
		if z.Name == "zzzz" {
			surviving = true
		}
		if z.Name == "z214" {
			t.Errorf("quarantined zone z214 is still published with id %d", z.ID)
		}
	}
	if !surviving {
		t.Errorf("surviving zone zzzz missing from the published zone set")
	}
}

// D: the QUARANTINE x RETH-MEMBER-EXEMPTION interaction.
//
// The two mechanisms compose into a shape neither was designed for, and the
// result is CORRECT — this test exists so a later reader does not "fix" it.
//
// The exemption's trigger has two halves: the row being a projection of a
// declared RETH's netdev, and the row's own zone being empty. Tolerant runtime
// maps omit the losing z214 membership before snapshots are built, so the
// member row has no zone and the exemption covers it. It casts no vote, and the
// ledger resolves the shared ifindex to the RETH's surviving zone.
//
// Reading that as a bug is the trap. The quarantine contract drops the
// colliding zone AS IF IT HAD NEVER BEEN CONFIGURED, so a member zoned only into
// that zone is a member with no runtime zone — exactly the case the exemption
// exists for. Resolving to `0` here would mean honouring a zone the operator
// was just told was discarded.
//
// An earlier revision justified the same outcome a second way, by claiming it
// RESTORES master: emission is name-sorted, so master's last-write-wins
// `populate_egress` supposedly already answered Y. That argument is NAME
// DEPENDENT and was removed rather than reworded. `buildInterfaceSnapshots`
// sorts interface names, and whether the member precedes its RETH is a fact
// about the member's prefix: `ge-0/0/1` and `et-0/0/1` sort BEFORE `reth1`
// (member first, master answers Y), but `xe-0/0/1` sorts AFTER it (member
// last, master answers 0). Junos names 10G ports `xe-`, so the "master already
// said Y" half is false for a real and ordinary member name. The pinned
// outcome below is unchanged — it rests on the quarantine contract above,
// which is name-independent.
//
// The collision is REAL, not simulated: z174 and z214 genuinely fold to one
// StableZoneID, and the premise is asserted so a change to the fold turns this
// into a loud failure rather than a silently vacuous test.
func TestQuarantinedMemberZoneLetsTheRethZoneResolve_6722(t *testing.T) {
	if config.StableZoneID("z174") != config.StableZoneID("z214") {
		t.Fatalf("test premise broken: z174/z214 no longer collide under the frozen fold")
	}
	lines := []string{
		"set interfaces ge-0/0/1 gigether-options redundant-parent reth1",
		// The redundancy group is declared because a real bondless-RETH LAN
		// declares one — NOT because the projection mark depends on it. Measured:
		// drop this line and strict CompileConfig still accepts, and ge-0/0/1 is
		// still marked, because `ResolveReth` resolves a `reth*` onto its member
		// regardless of the redundancy group and the predicate IS that
		// resolution. An earlier `redundancy-group N` clause was removed for
		// exactly that reason (docs/userspace-dataplane-architecture.md). The
		// adjacent `rethRG` lookup still keys on the group, for its own purpose:
		// inheriting the HA flow-cache redundancy group onto member rows.
		"set interfaces reth1 redundant-ether-options redundancy-group 2",
		"set interfaces reth1 unit 0 family inet address 10.0.61.1/24",
		// The MEMBER is explicitly zoned into the doomed zone, and the reference
		// is on the member's BASE name rather than a `.0` unit. That matters:
		// `ge-0/0/1` configures no logical unit, so a `ge-0/0/1.0` reference
		// names a row that does not exist and lands on no ifindex. Keeping the
		// base claim proves the quarantine removes a real membership for the
		// RETH-shared ifindex rather than passing vacuously.
		"set security zones security-zone z214 interfaces ge-0/0/1",
		"set security zones security-zone z174 host-inbound-traffic system-services ping",
		// The RETH carries the SURVIVING zone — the one the ledger must resolve.
		"set security zones security-zone lan interfaces reth1.0",
		"set security policies default-policy deny-all",
	}
	if _, err := config.CompileConfig(treeFromSet6722(t, lines)); err == nil {
		t.Fatalf("strict CompileConfig accepted the z174/z214 collision: the " +
			"commit-time gate is gone and this shape no longer reaches the quarantine")
	}
	cfg := compileWithStubbedLinks6722(t, lines,
		map[string]int{"ge-0-0-1": 24, "reth1": 24},
		map[string]string{"ge-0-0-1": "02:bf:72:01:00:01"}, true)

	// The authored member claim remains present, but z214 is a StableZoneID
	// loser and must be omitted from runtime zone maps before snapshots. Check
	// the raw config and the exclusion set so an empty row is not vacuous.
	losingZone := cfg.Security.Zones["z214"]
	authoredMember := false
	if losingZone != nil {
		for _, ref := range losingZone.Interfaces {
			if ref == "ge-0/0/1" {
				authoredMember = true
				break
			}
		}
	}
	if !authoredMember {
		t.Fatalf("precondition: z214 does not author ge-0/0/1")
	}
	if _, excluded := quarantinedZoneNames(cfg)["z214"]; !excluded {
		t.Fatalf("precondition: z214 is not excluded by StableZoneID quarantine")
	}
	if got := buildInterfaceZoneMap(cfg)["ge-0/0/1"]; got != "" {
		t.Fatalf("quarantined ge-0/0/1 runtime zone = %q, want no owner", got)
	}

	snap, err := buildSnapshot(cfg, config.UserspaceConfig{}, 1, 0)
	if err != nil {
		t.Fatalf("buildSnapshot: %v", err)
	}
	if len(snap.zoneIDCollisions) == 0 {
		t.Fatalf("no collision reported: the quarantine did not exclude the "+
			"colliding zone from the published set (zones=%d)", len(snap.Zones))
	}

	member := snapByName6722(t, snap.Interfaces, "ge-0/0/1")
	reth := snapByName6722(t, snap.Interfaces, "reth1.0")

	if member.Zone != "" {
		t.Fatalf("runtime map still assigns ge-0/0/1 Zone=%q, want empty: the stable "+
			"losing membership must not reach the member row", member.Zone)
	}
	if member.EgressZone != "lan" {
		t.Fatalf("ge-0/0/1 EgressZone = %q, want %q: omitting the losing member "+
			"zone leaves the RETH's surviving lan claim as the sole owner for this "+
			"ifindex, so the egress answer remains lan", member.EgressZone, "lan")
	}
	for _, s := range snap.Interfaces {
		if s.EgressZone == "z214" {
			t.Fatalf("interface %q carries EgressZone %q, a QUARANTINED zone; the "+
				"quarantine drops that zone from the published set, so the Rust "+
				"corroboration would reject it and the ifindex would silently lose "+
				"its zone — the answer must never name a dropped zone", s.Name, s.EgressZone)
		}
	}
	if reth.Zone != "lan" {
		t.Fatalf("reth1.0 Zone = %q, want %q: the surviving zone must still be on "+
			"the reth row, or there is nothing for the ledger to resolve",
			reth.Zone, "lan")
	}
	if member.Ifindex != reth.Ifindex {
		t.Fatalf("ge-0/0/1 ifindex %d != reth1.0 ifindex %d: the member and its "+
			"reth must share ONE netdev for the ledger to have a collision to "+
			"resolve at all", member.Ifindex, reth.Ifindex)
	}

	// The surviving zone must still be published, or the Rust side resolves it
	// to InterfaceUnknownZone instead of propagating it.
	published := false
	for _, z := range snap.Zones {
		if z.Name == "lan" {
			published = true
			break
		}
	}
	if !published {
		t.Fatalf("zone %q is not in the published zone set, so the Rust ledger "+
			"could not resolve it even with the member exempted", "lan")
	}

	// CONTROL: exactly ONE of the colliding pair is excluded from runtime
	// installation — the later-sorting name. z214 is gone; z174 survives.
	//
	// This control corrected a wrong assertion in this test's first draft,
	// which required BOTH names to vanish. Checking the exact published set
	// distinguishes dropping the loser from dropping both colliders, and the
	// earlier raw-membership/map preconditions ensure the member's empty zone is
	// not a missing-input default.
	var sawDoomed, sawWinner bool
	for _, z := range snap.Zones {
		switch z.Name {
		case "z214":
			sawDoomed = true
		case "z174":
			sawWinner = true
		}
	}
	if sawDoomed {
		t.Fatalf("quarantined zone %q is still published; the zone exclusion "+
			"did not run to completion", "z214")
	}
	if !sawWinner {
		t.Fatalf("collision winner %q was also excluded; exactly the later-sorting "+
			"collider must be dropped", "z174")
	}
}
