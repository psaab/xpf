package userspace

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #6722, the GO half — the DECIDING half. `stampEgressZones` (interfaces.go)
// answers, per ifindex, which security zone that ifindex EGRESSES into, and the
// Rust resolver (`ForwardingState::egress_zone_id`) reads the answer instead of
// adjudicating one from the rows.
//
// WHY THE ANSWER MOVED HERE. Rounds 4 through 9 built the answer on the Rust
// side by polling the snapshot rows — "does every row on this ifindex agree?" —
// and exempting the rows whose agreement or dissent turned out to be an
// artefact. NINE spellings of that exemption were holed in turn, each by a
// config shape it had not enumerated:
//
//	the raw `redundant-parent` string on the wire, re-derived from row names
//	co-resident row names
//	the SET of netdevs the parent's rows occupy
//	`snapshotLinuxName` of the parent's BASE row  (round 9)
//	  ... holed by: `ge-0/0/1` with units 0 and 1 in different zones, where the
//	      BASE row's zone is fanned up from unit 1 and votes against unit 0
//	  ... holed by: an AUTHORED dotted name `ge-0/0/1.100` aliasing `reth1.100`
//	  ... holed by: a WireGuard interface named as a reth member (fail-OPEN)
//	  ... holed by: #5832 + reth-member warnings combining on the tolerant path
//
// The pattern, not any one case, is the finding. A row's `Zone` is the OUTCOME
// of `buildInterfaceZoneMap`'s fan-up/fan-down derivation, and the outcome
// cannot say whether the operator zoned THIS identity or whether the row
// inherited another identity's words. Provenance is not reconstructible
// downstream, so it is carried: `authoredZoneRefs` records the literal
// `security-zone <z> interfaces <ref>` bindings, and the builder resolves them
// through the same aliasing it performs.
//
// The producible facts this file pins:
//
//  1. AUTHORED beats DERIVED on a shared ifindex. `ge-0/0/1` units 0/1 in `lan`
//     and `dmz`: ifindex 10 egresses `lan`, unit 0's authored zone, NOT the base
//     row's fanned-up `dmz` — and not a function of which zone name sorts first.
//  2. The reference bondless-RETH cluster still resolves its zone: `[ge-0/0/1=""
//     reth1="lan" reth1.0="lan"]` on ONE ifindex egresses `lan`.
//  3. An authored dotted member name aliasing a RETH's VLAN unit resolves the
//     RETH unit's authored zone rather than going ambiguous.
//  4. A tagged-parent netdev with no unit on it inherits its units' unanimous
//     zone (the reference cluster's `reth0`).
//  5. Contested ownership fails CLOSED: a tunnel named as a member, a reth named
//     as a member, a member carrying its own units, a canonicalization collision
//     with no reth in it, and two units of one interface on one netdev.
//  6. The four incoherent memberships are commit REJECTIONS.
//
// FAIL-ON-REVERT, per production hunk. Each row was MEASURED by reverting that
// hunk alone and recording which cell fires; the cells named are the ones that
// actually reddened, not the ones the hunk looks like it should reach.
//
//	rule 2 reads the ROW's zone instead of authored[]            -> A1, A2, J
//	authoredZoneRefs also fans a unit ref up to the base         -> A1, A2, J
//	drop the egressIdentitiesCohere gate                         -> E1/E2/E3/E4/E5
//	drop `ifc.Tunnel != nil` from egressMemberIsBarePort         -> E1 only
//	drop the unit check from egressMemberIsBarePort              -> E3 only
//	drop `HasPrefix(reth, "reth")` from egressRethMemberOf       -> E4 only
//	drop the unanimousUnitZone arm (rule 3)                      -> D
//	fire rule 3 even when a unit row IS on the ifindex           -> J
//	drop the `unitNum == 0` conjunct in the identity fold        -> E5 only
//	drop the quarantine exclusion from the authored bindings     -> the quarantine
//	                                                                cell in
//	                                                                zone_propagation_6722_test.go,
//	                                                                and F2
//	drop the unit clause of validateRethMemberStrict             -> G1/G2 (accepts)
//	drop the tunnel clause of validateRethMemberStrict           -> G3 (accepts)
//	drop the self clause of validateRethMemberStrict             -> H1 (accepts)
//	drop the parent-exists clause                                -> I1/I2 (accepts)
//	drop the reth clause of validateRethMemberStrict             -> L1/L2/L3 (accepts)
//	drop the `opts.lenientRethMember` downgrade                  -> G/H/I/L lenient halves
//
// That table is INCOMPLETE as written, and round 12 says so here rather than
// leaving the omission to be rediscovered: it names the hunks this file was
// built around, not every guard the change introduces. Re-running the predicate
// over ALL of them found seven clauses whose removal left the whole Go suite
// green and one whose binder fired in 1 run out of 8. The continuation of this
// table, the cells that close those, and the structural reasons for the five
// that stay unbound are in the ROUND 12 section at the foot of this file.
//
// The Rust half of the matrix is in userspace-dp/src/afxdp/forwarding/tests.rs:
// the corroboration, the DECIDED-empty override of unanimous rows, the
// conflicting-claim fail-close, the compatibility arm (both halves), and the
// resolver reading `ifindex_to_zone_id` instead of the ledger.

// egressZoneOfIfindex6722 returns the EgressZone every row on `ifindex` carries,
// failing if the rows disagree — the invariant the Rust side relies on (it
// treats a disagreement as version drift and fails closed) — or if no row
// resolved to that ifindex at all, which would otherwise let a "no zone"
// assertion pass against an empty snapshot.
func egressZoneOfIfindex6722(t *testing.T, snaps []InterfaceSnapshot, ifindex int) string {
	t.Helper()
	seen := map[string][]string{}
	for _, s := range snaps {
		if s.Ifindex == ifindex {
			seen[s.EgressZone] = append(seen[s.EgressZone], s.Name)
		}
	}
	if len(seen) == 0 {
		t.Fatalf("no snapshot row resolved to ifindex %d; the stub was primed with "+
			"a Linux name no row carries, so this cell is asserting about nothing",
			ifindex)
	}
	if len(seen) > 1 {
		keys := make([]string, 0, len(seen))
		for z := range seen {
			keys = append(keys, z)
		}
		sort.Strings(keys)
		t.Fatalf("rows on ifindex %d carry DIFFERENT EgressZone values %v (%v); "+
			"stampEgressZones must stamp one answer per ifindex, and the Rust "+
			"builder reads a disagreement as version drift and fails closed",
			ifindex, keys, seen)
	}
	for z := range seen {
		return z
	}
	return ""
}

func assertEgressZone6722(t *testing.T, snaps []InterfaceSnapshot, ifindex int, want, why string) {
	t.Helper()
	if got := egressZoneOfIfindex6722(t, snaps, ifindex); got != want {
		t.Errorf("egress zone of ifindex %d = %q, want %q: %s", ifindex, got, want, why)
	}
}

// A: AUTHORED beats DERIVED on a shared ifindex.
//
// A1 is the round-10 blocking regression in its own right. `buildInterfaceZoneMap`
// writes `out[base]` first-write-wins over SORTED ZONE NAMES, so the `ge-0/0/1`
// base row carries "dmz" — a zone no identity on that netdev was ever put in —
// purely because "dmz" sorts before "lan". Unit 0 collapses onto the base netdev
// and carries the operator's real "lan". The row-polling ledger read that as a
// disagreement and answered the 0 sentinel, turning every permit to that
// interface into a deny; origin/master answered `lan`.
//
// A2 and A3 are the two CONTROLS the round-10 report asked for, and they are
// what separates "the fix works" from "the fix hard-codes lan":
//
//	A2 renames dmz to "aaa" so the OTHER unit's zone sorts first. The derived
//	   base zone changes from "dmz" to "aaa"; the answer must not move.
//	A3 drops unit 1 entirely. A single-unit interface was never affected and
//	   must still resolve lan.
func TestAuthoredUnitZoneBeatsTheDerivedBaseZone_6722(t *testing.T) {
	// A1.
	zoneMap, snaps := buildSnapshotsFromSet6722(t, []string{
		"set interfaces ge-0/0/1 unit 0 family inet address 10.0.61.1/24",
		"set interfaces ge-0/0/1 unit 1 family inet address 10.0.62.1/24",
		"set security zones security-zone lan interfaces ge-0/0/1.0",
		"set security zones security-zone dmz interfaces ge-0/0/1.1",
	}, map[string]int{"ge-0-0-1": 10, "ge-0-0-1.1": 11},
		map[string]string{"ge-0-0-1": "02:bf:72:01:00:01"})

	// The precondition, measured rather than assumed: the base row really does
	// carry a zone the operator never wrote for it. Without this the cell below
	// would pass on a snapshot where nothing ever disagreed.
	if got := zoneMap["ge-0/0/1"]; got != "dmz" {
		t.Fatalf("precondition: buildInterfaceZoneMap[ge-0/0/1] = %q, want %q — the "+
			"fanned-up base zone is the whole subject of this cell", got, "dmz")
	}
	if got := snapByName6722(t, snaps, "ge-0/0/1").Zone; got != "dmz" {
		t.Fatalf("precondition: the ge-0/0/1 BASE row's Zone = %q, want %q", got, "dmz")
	}
	if base, unit0 := snapByName6722(t, snaps, "ge-0/0/1"), snapByName6722(t, snaps, "ge-0/0/1.0"); base.Ifindex != 10 || unit0.Ifindex != 10 {
		t.Fatalf("precondition: ge-0/0/1 ifindex = %d and ge-0/0/1.0 ifindex = %d, "+
			"want 10 and 10 — a non-VLAN unit 0 collapses onto its base netdev, "+
			"which is what puts a derived zone and an authored one on ONE ifindex",
			base.Ifindex, unit0.Ifindex)
	}
	assertEgressZone6722(t, snaps, 10, "lan",
		"unit 0 is the identity the operator zoned on this netdev; the base row's "+
			"\"dmz\" is a restatement of the sentence written about ge-0/0/1.1, which "+
			"lives on its own netdev. Answering 0 here is the round-10 fail-CLOSED "+
			"regression (master answers lan); answering dmz would make the "+
			"adjudicated to-zone a function of zone NAMING")
	assertEgressZone6722(t, snaps, 11, "dmz",
		"unit 1 is alone on its own VLAN-less netdev and keeps its authored zone")

	// A2 — the alphabetical control. Rename dmz to "aaa" so the derived base
	// zone flips; the answer must not.
	zoneMapA, snapsA := buildSnapshotsFromSet6722(t, []string{
		"set interfaces ge-0/0/1 unit 0 family inet address 10.0.61.1/24",
		"set interfaces ge-0/0/1 unit 1 family inet address 10.0.62.1/24",
		"set security zones security-zone lan interfaces ge-0/0/1.0",
		"set security zones security-zone aaa interfaces ge-0/0/1.1",
	}, map[string]int{"ge-0-0-1": 10, "ge-0-0-1.1": 11},
		map[string]string{"ge-0-0-1": "02:bf:72:01:00:01"})
	if got := zoneMapA["ge-0/0/1"]; got != "aaa" {
		t.Fatalf("control A2 precondition: buildInterfaceZoneMap[ge-0/0/1] = %q, "+
			"want %q — the derived base zone must actually have CHANGED, or this "+
			"control is not varying the thing it claims to vary", got, "aaa")
	}
	assertEgressZone6722(t, snapsA, 10, "lan",
		"renaming the sibling's zone so it sorts FIRST must not move the answer; "+
			"the answer comes from the authored binding on ge-0/0/1.0, not from the "+
			"sort order buildInterfaceZoneMap used to pick a base zone")

	// A3 — the single-unit control. Never affected, must stay lan.
	_, snapsS := buildSnapshotsFromSet6722(t, []string{
		"set interfaces ge-0/0/1 unit 0 family inet address 10.0.61.1/24",
		"set security zones security-zone lan interfaces ge-0/0/1.0",
	}, map[string]int{"ge-0-0-1": 10},
		map[string]string{"ge-0-0-1": "02:bf:72:01:00:01"})
	assertEgressZone6722(t, snapsS, 10, "lan",
		"an interface with a single unit 0 has one identity on its netdev and "+
			"resolves its authored zone, exactly as before this change")
}

// B: the reference bondless-RETH LAN — the shape #6722 exists to protect.
// `ResolveReth` collapses `reth1` onto its member's netdev, so the UNZONED
// member row and the zoned `reth1` / `reth1.0` rows are ONE ifindex. The member
// is a bare L2 port of the reth, so the two identities cohere and the reth's
// authored zone decides.
//
// Counting the member's "no zone" as dissent is what blackholed every WAN->LAN,
// sfmix->LAN and tunnel->LAN transit flow on the reference cluster: zone 0 is
// the sentinel `evaluate_policy_result_l3_aware` matches no rule against.
func TestBondlessRethMemberDoesNotContestTheRethsZone_6722(t *testing.T) {
	_, snaps := buildSnapshotsFromSet6722(t, []string{
		"set interfaces ge-0/0/1 gigether-options redundant-parent reth1",
		"set interfaces reth1 redundant-ether-options redundancy-group 2",
		"set interfaces reth1 unit 0 family inet address 10.0.61.1/24",
		"set security zones security-zone lan interfaces reth1",
	}, map[string]int{"ge-0-0-1": 24},
		map[string]string{"ge-0-0-1": "02:bf:72:01:00:01"})

	member := snapByName6722(t, snaps, "ge-0/0/1")
	base := snapByName6722(t, snaps, "reth1")
	unit0 := snapByName6722(t, snaps, "reth1.0")
	if member.Ifindex != 24 || base.Ifindex != 24 || unit0.Ifindex != 24 {
		t.Fatalf("precondition: ge-0/0/1=%d reth1=%d reth1.0=%d, want 24/24/24 — "+
			"three rows on ONE netdev is the whole subject",
			member.Ifindex, base.Ifindex, unit0.Ifindex)
	}
	if member.Zone != "" {
		t.Fatalf("precondition: the member row's Zone = %q, want empty — Junos "+
			"zones the RETH, not the port", member.Zone)
	}
	assertEgressZone6722(t, snaps, 24, "lan",
		"the member is a bare L2 port of reth1, so the two identities describe ONE "+
			"device coherently and the reth's authored zone decides. Answering 0 here "+
			"blackholes every WAN->LAN transit flow on the reference HA cluster")
}

// C: an authored DOTTED member name that aliases the RETH's VLAN unit.
//
// Authored dotted interface NAMES are legal, and `ResolveReth("reth1")` selects
// `ge-0/0/1`, so `reth1.100` resolves onto `ge-0-0-1.100` — exactly where the
// authored interface named `ge-0/0/1.100` lands. The round-9 predicate compared
// only BASE rows, so it never exempted the dotted name and the ifindex went
// ambiguous where master resolved the operator's zone.
//
// This is the cell that shows why the answer had to stop being a row
// classification: the dotted name is a real, separate configured interface AND
// an alias of a reth unit, and no amount of inspecting the two rows
// distinguishes it from a genuine conflict. Resolving the AUTHORED binding
// through the aliasing does.
func TestAuthoredDottedMemberNameResolvesTheRethUnitsZone_6722(t *testing.T) {
	_, snaps := buildSnapshotsFromSet6722(t, []string{
		"set interfaces ge-0/0/1 gigether-options redundant-parent reth1",
		"set interfaces ge-0/0/1.100 gigether-options redundant-parent reth1",
		"set interfaces reth1 redundant-ether-options redundancy-group 2",
		"set interfaces reth1 vlan-tagging",
		"set interfaces reth1 unit 100 vlan-id 100 family inet address 10.0.61.1/24",
		"set security zones security-zone lan interfaces reth1.100",
	}, map[string]int{"ge-0-0-1": 31, "ge-0-0-1.100": 32},
		map[string]string{"ge-0-0-1": "02:bf:72:01:00:01"})

	dotted := snapByName6722(t, snaps, "ge-0/0/1.100")
	rethUnit := snapByName6722(t, snaps, "reth1.100")
	if dotted.Ifindex != 32 || rethUnit.Ifindex != 32 {
		t.Fatalf("precondition: ge-0/0/1.100=%d reth1.100=%d, want 32/32 — the "+
			"authored dotted NAME and the reth's VLAN unit must land on one netdev",
			dotted.Ifindex, rethUnit.Ifindex)
	}
	if dotted.Zone != "" || rethUnit.Zone != "lan" {
		t.Fatalf("precondition: ge-0/0/1.100 Zone=%q reth1.100 Zone=%q, want \"\" "+
			"and \"lan\" — the rows must genuinely DISAGREE, or a row-polling "+
			"ledger would never have gone ambiguous here", dotted.Zone, rethUnit.Zone)
	}
	assertEgressZone6722(t, snaps, 32, "lan",
		"the operator EXPLICITLY zoned reth1.100; ge-0/0/1.100 is a bare port of "+
			"reth1 and adds no competing L3 identity. Answering 0 strips the "+
			"destination zone from an explicitly zoned interface (master: lan)")
}

// D: the TRUNK-CARRIER rule, and the reason it exists.
//
// The reference cluster's `reth0` is `vlan-tagging` with units 50 and 80, both
// zoned `wan`. Neither unit is on the base netdev — a VLAN unit lands on
// `<dev>.<vlan>` — so ifindex 25 carries only BASE rows and no authored binding
// resolves to it. Master answers `wan` there, from the base row's fanned-up
// zone. Rule 3 keeps that answer without reopening cell A, because it fires only
// when NO unit row is on the ifindex.
//
// This cell is the reason rule 3 is not folded into rule 2: with rule 3 removed,
// ifindex 25 fails closed against both master and round 9's head.
func TestTaggedParentNetdevInheritsItsUnitsUnanimousZone_6722(t *testing.T) {
	_, snaps := buildSnapshotsFromSet6722(t, []string{
		"set interfaces ge-0/0/1 gigether-options redundant-parent reth1",
		"set interfaces ge-0/0/2 gigether-options redundant-parent reth0",
		"set interfaces reth0 redundant-ether-options redundancy-group 1",
		"set interfaces reth0 vlan-tagging",
		"set interfaces reth0 unit 50 vlan-id 50 family inet address 172.16.50.8/24",
		"set interfaces reth0 unit 80 vlan-id 80 family inet address 172.16.80.8/24",
		"set interfaces reth1 redundant-ether-options redundancy-group 2",
		"set interfaces reth1 unit 0 family inet address 10.0.61.1/24",
		"set security zones security-zone wan interfaces reth0.50",
		"set security zones security-zone wan interfaces reth0.80",
		"set security zones security-zone lan interfaces reth1",
	}, map[string]int{"ge-0-0-1": 24, "ge-0-0-2": 25, "ge-0-0-2.50": 26, "ge-0-0-2.80": 27},
		map[string]string{"ge-0-0-1": "02:bf:72:01:00:01", "ge-0-0-2": "02:bf:72:01:00:02"})

	for _, name := range []string{"reth0.50", "reth0.80"} {
		if got := snapByName6722(t, snaps, name).Ifindex; got == 25 {
			t.Fatalf("precondition: %s resolved to ifindex 25, the BASE netdev; a "+
				"VLAN unit must land on its own <dev>.<vlan> device or rule 3's "+
				"'no unit row on this ifindex' condition is not being exercised", name)
		}
	}
	assertEgressZone6722(t, snaps, 25, "wan",
		"reth0's base netdev carries no logical unit of its own, so it is a bare "+
			"tagged-parent carrier and takes the zone its units unanimously name — "+
			"the same answer origin/master gives")
	assertEgressZone6722(t, snaps, 24, "lan", "the reference LAN reth is unaffected")
	assertEgressZone6722(t, snaps, 26, "wan", "reth0.50 owns its own netdev")
	assertEgressZone6722(t, snaps, 27, "wan", "reth0.80 owns its own netdev")
}

// D2: the TRUNK-CARRIER rule, driven from the SHIPPED cluster config itself.
//
// Cell D above builds the shape by hand. This one parses
// `docs/ha-cluster-userspace.conf` — the file
// `test/incus/loss-userspace-cluster.env` points every HA smoke at — through
// the real parser, the real `${node}` group expansion and the real
// `CompileConfig`, and asserts the two ifindexes the reference topology
// depends on.
//
// It exists because rule 3 made that file a LIVE DEPENDENCY of a rule this
// round introduces, not merely a regression check: an edit to the conf that
// moved a zone binding off `reth0.50`/`reth0.80`, or added an untagged unit to
// `reth0`, would silently take ifindex 25's zone away. Without this cell that
// shows up as a smoke failure on a cluster; with it, as a unit-test failure
// here.
func TestShippedClusterConfigResolvesBothRethIfindexes_6722(t *testing.T) {
	src, err := os.ReadFile("../../../docs/ha-cluster-userspace.conf")
	if err != nil {
		t.Fatalf("read the shipped cluster config: %v", err)
	}
	tree, errs := config.NewParser(string(src)).Parse()
	if len(errs) > 0 {
		t.Fatalf("parse docs/ha-cluster-userspace.conf: %v", errs)
	}
	// The file is `apply-groups "${node}"`; node 0 is the topology the smoke
	// targets and the one every #6722 measurement in this issue quotes.
	if err := tree.ExpandGroupsWithVars(map[string]string{"node": "node0"}); err != nil {
		t.Fatalf("ExpandGroupsWithVars: %v", err)
	}

	prev := buildLinkSnapshot
	t.Cleanup(func() { buildLinkSnapshot = prev })
	ifindexOf := map[string]int{
		"ge-0-0-1": 24, "ge-0-0-2": 25, "ge-0-0-2.50": 26, "ge-0-0-2.80": 27,
	}
	buildLinkSnapshot = func(linuxName string) (int, int, string, []InterfaceAddressSnapshot) {
		idx, ok := ifindexOf[linuxName]
		if !ok {
			return 0, 0, "", nil
		}
		return idx, 1500, "02:bf:72:01:00:01", nil
	}
	cfg, err := config.CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig on the shipped cluster config: %v", err)
	}
	snaps := buildInterfaceSnapshots(cfg)

	// Preconditions, so a conf edit that moves these bindings fails LOUDLY here
	// rather than making the assertions below vacuous.
	if got := snapByName6722(t, snaps, "reth1").Zone; got != "lan" {
		t.Fatalf("precondition: reth1 Zone = %q, want %q — the shipped config no "+
			"longer zones the LAN reth and cell D2 is measuring something else", got, "lan")
	}
	for _, unit := range []string{"reth0.50", "reth0.80"} {
		row := snapByName6722(t, snaps, unit)
		if row.Zone != "wan" {
			t.Fatalf("precondition: %s Zone = %q, want %q", unit, row.Zone, "wan")
		}
		if row.Ifindex == 25 {
			t.Fatalf("precondition: %s landed on ifindex 25, the BASE netdev; rule 3 "+
				"requires the tagged units to live on their OWN devices", unit)
		}
	}

	assertEgressZone6722(t, snaps, 24, "lan",
		"the LAN reth and its member port are one device; this is the ifindex whose "+
			"loss blackholed every WAN->LAN, sfmix->LAN and tunnel->LAN transit flow")
	assertEgressZone6722(t, snaps, 25, "wan",
		"reth0 is `vlan-tagging` with only tagged units, so its base netdev carries "+
			"no logical unit and takes the zone its units unanimously name — the same "+
			"answer origin/master gives. Losing it is a fail-CLOSED regression against "+
			"both master and the previous head")
}

// E: CONTESTED OWNERSHIP fails closed. Five shapes in which two identities
// claim one netdev without a valid reth membership between them. All five are
// admitted on the TOLERANT load / peer-sync path (#1960 no-brick), where the
// gates that reject them at commit are downgraded to warnings — so this is not a
// theoretical set, it is what a grandfathered config presents.
//
// E1 and E4 are the two the round-10 report measured as DELTAS against master in
// the permissive direction on the previous head.
func TestContestedNetdevOwnershipFailsClosed_6722(t *testing.T) {
	cases := []struct {
		name    string
		lines   []string
		ifindex int
		links   map[string]int
		why     string
	}{
		{
			// E1: a WireGuard tunnel named as a reth member. The reth validator
			// rejected member UNITS but not a base-level tunnel, and WireGuard's
			// own interface-level validation accepts the shape. `ResolveReth`
			// then puts reth1's rows on the TUN, whose MAC gate admits it via
			// `iface.tunnel.then_some([0; 6])` — so wg0 RECEIVED reth1's zone.
			// Master answers 0. This was the round's only FAIL-OPEN.
			name: "wireguard-tunnel-as-member",
			lines: []string{
				"set interfaces wg0 gigether-options redundant-parent reth1",
				"set interfaces wg0 tunnel mode wireguard",
				"set interfaces wg0 tunnel wireguard listen-port 51820",
				"set interfaces wg0 tunnel wireguard private-key b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2",
				"set interfaces wg0 tunnel wireguard peer a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1 allowed-ips 10.66.0.0/24",
				"set interfaces reth1 redundant-ether-options redundancy-group 2",
				"set interfaces reth1 unit 0 family inet address 10.0.61.1/24",
				"set security zones security-zone lan interfaces reth1",
				"set routing-options static route 10.66.0.0/24 next-hop wg0",
			},
			ifindex: 41,
			links:   map[string]int{"wg0": 41},
			why: "a WireGuard endpoint is an independently ROUTED L3 identity, not " +
				"an L2 port; inheriting reth1's zone would adjudicate its transit " +
				"under a policy written for the LAN reth",
		},
		{
			// E2: a reth naming a redundant parent of its own, combined with a
			// #5832 canonicalization collision. R(reth0)=ge-0/0/1 and
			// R(reth1)=ge-0-0-1 both canonicalize onto ONE netdev, so reth0's
			// authored zone would cross onto the independently authored reth1
			// side. Master answers 0.
			name: "reth-as-member-plus-canonical-collision",
			lines: []string{
				"set interfaces ge-0/0/1 gigether-options redundant-parent reth0",
				"set interfaces ge-0-0-1 gigether-options redundant-parent reth1",
				"set interfaces reth1 gigether-options redundant-parent reth0",
				"set interfaces reth0 redundant-ether-options redundancy-group 1",
				"set interfaces reth0 unit 0 family inet address 10.0.62.1/24",
				"set security zones security-zone lan interfaces reth0",
			},
			ifindex: 31,
			links:   map[string]int{"ge-0-0-1": 31},
			why: "a reth is the L3 OWNER of a redundant pair and never a member " +
				"port, so reth1 is not a bare port of reth0 and the two sides are " +
				"independent claims on one device",
		},
		{
			// E3: a member carrying its OWN addressed unit. Two independently
			// addressed L3 units on one netdev, only one of them zoned. This was
			// the measured round-7 fail-open.
			name: "member-with-its-own-addressed-unit",
			lines: []string{
				"set interfaces ge-0/0/1 gigether-options redundant-parent reth1",
				"set interfaces ge-0/0/1 unit 0 family inet address 10.9.9.1/30",
				"set interfaces reth1 redundant-ether-options redundancy-group 2",
				"set interfaces reth1 unit 0 family inet address 10.0.61.1/24",
				"set security zones security-zone lan interfaces reth1",
			},
			ifindex: 24,
			links:   map[string]int{"ge-0-0-1": 24},
			why: "the member's unit installs its own connected route and local " +
				"address on the shared ifindex, so its lack of a zone is a real " +
				"operator statement about a real L3 interface",
		},
		{
			// E4: a canonicalization collision with NO reth anywhere (#5832 row
			// 2). The deference premise — "the member is a port, the reth owns
			// the L3" — is simply absent when neither side is a reth.
			//
			// This cell is a DELIBERATE behaviour change beyond #6722's four
			// round-10 findings, argued separately and measured on all three
			// trees rather than predicted:
			//
			//	origin/master (edefb7570)   egress_zone_id(24) = 0
			//	PR head c9b020695           resolves `lan`   <-- fail-OPEN
			//	here                        egress_zone_id(24) = 0
			//
			// At c9b020695 the collision row is MARKED
			// (`RethProjection = true`, measured), its empty vote is withheld,
			// and the ledger resolves the zone the operator wrote on the OTHER
			// name for that same device. The PR's own doc admitted that as a
			// fail-OPEN delta. So this RESTORES master rather than changing it:
			// what it retires is a delta an earlier round of this PR introduced.
			// It is called out because the config is ACCEPTED on the tolerant
			// path, so the change is observable to an operator who has one.
			name: "canonical-collision-without-a-reth",
			lines: []string{
				"set interfaces ge-0/0/1 gigether-options redundant-parent ge-0-0-1",
				"set interfaces ge-0-0-1 unit 0 family inet address 10.0.61.1/24",
				"set security zones security-zone lan interfaces ge-0-0-1",
			},
			ifindex: 24,
			links:   map[string]int{"ge-0-0-1": 24},
			why: "neither name is a reth, so nothing designates either as the " +
				"other's port; two independently authored interfaces on one device " +
				"identify no single zone",
		},
		{
			// E5: two units of ONE interface-level tunnel on one netdev.
			// `TunnelNameMap` maps every unit of `wg0` onto the `wg0` device, so
			// `wg0`, `wg0.0` and `wg0.1` are one ifindex — and the operator zoned
			// only one of the two logical interfaces.
			name: "two-tunnel-units-on-one-device",
			lines: []string{
				"set interfaces wg0 tunnel mode wireguard",
				"set interfaces wg0 tunnel wireguard listen-port 51820",
				"set interfaces wg0 tunnel wireguard private-key b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2",
				"set interfaces wg0 tunnel wireguard peer a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1 allowed-ips 10.66.0.0/24",
				"set interfaces wg0 unit 0 family inet address 10.5.5.1/30",
				"set interfaces wg0 unit 1 family inet address 10.6.6.1/30",
				"set security zones security-zone vpnb interfaces wg0.1",
			},
			ifindex: 41,
			links:   map[string]int{"wg0": 41},
			why: "wg0.0 and wg0.1 are two logical interfaces the kernel gives one " +
				"device; the operator zoned one of them and left the other out, and " +
				"that omission is a statement",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := compileWithStubbedLinks6722(t, tc.lines, tc.links,
				map[string]string{"ge-0-0-1": "02:bf:72:01:00:01"}, true)
			snaps := buildInterfaceSnapshots(cfg)
			// The precondition that makes the cell non-vacuous: some row on the
			// ifindex must carry a NONZERO zone, or "no egress zone" would be
			// indistinguishable from a snapshot with no zones in it at all.
			zoned := false
			for _, s := range snaps {
				if s.Ifindex == tc.ifindex && s.Zone != "" {
					zoned = true
				}
			}
			if !zoned {
				t.Fatalf("precondition: no row on ifindex %d carries a zone, so a "+
					"\"\" answer here proves nothing", tc.ifindex)
			}
			assertEgressZone6722(t, snaps, tc.ifindex, "", tc.why)

			// ORDER STABILITY (round 12). The assertion above, run once, is a
			// FLAKY binder for `egressIdentitiesCohere`'s `len(identities) > 2`
			// refusal. With that clause removed, the function falls through to
			// the two-identity logic and reads `owners[0]`/`owners[1]` — the
			// first two entries of a slice built by ranging a MAP. On
			// `reth-as-member-plus-canonical-collision`, which puts FOUR
			// identities on ifindex 31, two of the six pairs cohere, so the
			// mutant answers `lan` only in the iteration orders that put such a
			// pair first. MEASURED at 6e62cd01d: with the clause deleted, this
			// case reddened in 1 of 8 whole-suite runs and passed in the other
			// 7. The round-11 table recorded it as bound; it was bound one time
			// in eight.
			//
			// Rebuilding N times samples N iteration orders, which turns the
			// binder deterministic and — more to the point — asserts the
			// property production actually needs: a contested netdev must fail
			// closed on EVERY boot, not on most of them. An egress zone that
			// depends on Go's map seed is a to-zone that changes across daemon
			// restarts with the config untouched.
			const builds = 128
			for i := 0; i < builds; i++ {
				if got := egressZoneOfIfindex6722(t, buildInterfaceSnapshots(cfg), tc.ifindex); got != "" {
					t.Fatalf("egress zone of ifindex %d = %q on build %d of %d, "+
						"want \"\" on every build: %s. A contested netdev that "+
						"fails closed only in some map iteration orders is not "+
						"failing closed", tc.ifindex, got, i+1, builds, tc.why)
				}
			}
		})
	}
}

// N: TWO AUTHORED ZONES on one COHERENT netdev — rule 2's conflict arm.
//
// Every other fail-closed cell in this file reaches "" through rule 1
// (`egressIdentitiesCohere`). This one does not, and that distinction is the
// reason it exists: here the two identities DO cohere — `ge-0/0/1` is a bare
// port of `reth1` — and the answer is refused one step later, because the
// operator wrote a `security-zone ... interfaces` binding for BOTH of them.
//
// Reachable by an ORDINARY COMMIT, not only on the tolerant path. This cell
// compiles through the STRICT `CompileConfig`: `validateRethMemberStrict`
// rejects a member that carries units, a tunnel, or is itself a reth, but it
// says nothing about a member the operator also put in a zone. So an operator
// who zones the port as well as the reth — a plausible mistake, since Junos
// accepts the words — reaches this arm at commit.
//
// Why the answer must be "": the reth's LAN transit and the member's `wan`
// binding name the same netdev, and `st.authored` is a SET with no ordering.
// Picking either one would adjudicate one identity's traffic under the other's
// policy, and picking "whichever the map iterator yields" would make the
// to-zone NONDETERMINISTIC across restarts — Go randomises map iteration order.
//
// The Rust corroboration cannot cover this. `ge-0/0/1`'s row literally carries
// `wan`, so `carried.contains("wan")` succeeds and a claim of `wan` would be
// honoured; the helper has no way to know the reth's `lan` was equally
// authored. This arm is the only thing that refuses.
//
// FAIL-ON-REVERT: replace `case len(st.authored) > 1: zone = ""` with any arm
// that picks one of the authored zones and N1 goes RED (the control N2 stays
// green either way, which is what makes N1's failure specific to the conflict).
func TestTwoAuthoredZonesOnOneCoherentNetdevFailClosed_6722(t *testing.T) {
	lines := []string{
		"set interfaces ge-0/0/1 gigether-options redundant-parent reth1",
		"set interfaces reth1 redundant-ether-options redundancy-group 1",
		"set interfaces reth1 unit 0 family inet address 10.0.61.1/24",
		"set security zones security-zone lan interfaces reth1",
		"set security zones security-zone wan interfaces ge-0/0/1",
	}
	links := map[string]int{"ge-0-0-1": 24}
	macs := map[string]string{"ge-0-0-1": "02:bf:72:01:00:01"}

	// N1. `compileWithStubbedLinks6722(..., lenient=false)` fatals if the STRICT
	// compiler rejects, so reaching the assertion is itself the proof that an
	// ordinary `commit` admits this config.
	cfg := compileWithStubbedLinks6722(t, lines, links, macs, false)
	snaps := buildInterfaceSnapshots(cfg)

	// The preconditions that separate this cell from every rule-1 cell above.
	member := snapByName6722(t, snaps, "ge-0/0/1")
	base := snapByName6722(t, snaps, "reth1")
	if member.Ifindex != 24 || base.Ifindex != 24 {
		t.Fatalf("precondition: ge-0/0/1=%d reth1=%d, want 24/24 — the two "+
			"authored identities must share ONE netdev", member.Ifindex, base.Ifindex)
	}
	if member.Zone != "wan" || base.Zone != "lan" {
		t.Fatalf("precondition: ge-0/0/1 Zone=%q reth1 Zone=%q, want \"wan\" and "+
			"\"lan\" — BOTH identities must be authored into a zone, or this is a "+
			"single-binding shape rule 2 resolves normally",
			member.Zone, base.Zone)
	}
	// Rule 1 does NOT fire here, which is the whole point. Asserted directly
	// against the predicate so a future change that starts refusing this shape
	// at rule 1 fails loudly rather than silently re-pointing the cell at a
	// different mechanism.
	if !egressIdentitiesCohere(cfg, map[string]string{
		"ge-0/0/1": "ge-0/0/1",
		"reth1":    "reth1",
	}) {
		t.Fatalf("precondition: egressIdentitiesCohere refused {ge-0/0/1, reth1}; " +
			"a bare member port and its reth MUST cohere, and if they no longer do " +
			"then this cell is measuring rule 1 and the conflict arm is once again " +
			"unbound")
	}
	assertEgressZone6722(t, snaps, 24, "",
		"the operator authored `lan` on reth1 and `wan` on its member port, and "+
			"the two name ONE netdev. `st.authored` is an unordered set, so any "+
			"answer other than \"\" adjudicates one identity's transit under the "+
			"other's policy — and a map-iteration pick would vary between restarts")

	// N2 — the CONTROL, and the thing that makes N1's failure specific. Drop the
	// second authored binding and NOTHING else: the same netdev, the same two
	// coherent identities, one authored zone. It must resolve `lan`. Without
	// this, a mutation that broke coherence entirely would red N1 and look like
	// the conflict arm was bound.
	_, ctlSnaps := buildSnapshotsFromSet6722(t, lines[:4], links, macs)
	assertEgressZone6722(t, ctlSnaps, 24, "lan",
		"removing ONLY the member's zone binding leaves one authored zone on a "+
			"coherent netdev, which rule 2 resolves; if this control also answers "+
			"\"\" then the cell above is measuring coherence, not the conflict arm")
}

// O: a UNIT-LESS reth named as another reth's member — the `HasPrefix(name,
// "reth")` conjunct of `egressMemberIsBarePort`, on the path it exists for.
//
// The three sibling cells that exercise "a reth is never a member port" (L, and
// the two rejection cells) all measure the COMMIT GATE: they assert that strict
// `CompileConfig` refuses the shape. The runtime clause is a different guarantee
// — `egressMemberIsBarePort`'s own comment says it "is the runtime half that
// must hold on the tolerant load / peer-sync path, where those rejections are
// downgraded to warnings (#1960 no-brick)" — and until this cell nothing bound
// it. The one lenient-path cell (J) uses `st0`, a name with no `reth` prefix, so
// the conjunct is irrelevant to it.
//
// The clause only bites for a reth with NO configured unit. A member-named reth
// that carries units is already refused by the `hasConfiguredUnit` conjunct,
// which is why every fixture written before this one reached the answer through
// a different clause and this one stayed unbound.
//
// FAIL-ON-REVERT: drop `strings.HasPrefix(name, "reth")` from
// `egressMemberIsBarePort` and O1 goes RED (it resolves `lan`); O2 stays green,
// which is what shows the failure is caused by the member's NAME and not by
// anything else in the shape.
func TestUnitlessRethNamedAsAMemberFailsClosedOnTheLenientPath_6722(t *testing.T) {
	lines := []string{
		"set interfaces reth1 gigether-options redundant-parent reth0",
		"set interfaces reth0 redundant-ether-options redundancy-group 1",
		"set interfaces reth0 unit 0 family inet address 10.0.61.1/24",
		"set security zones security-zone lan interfaces reth0",
	}
	links := map[string]int{"reth1": 24}

	// The commit gate refuses this shape, so the TOLERANT path is the only way
	// it reaches the builder. Pinned rather than assumed: if strict ever started
	// admitting it, "only reachable leniently" would be false and the reader
	// would be misled about which surface this clause defends.
	if _, err := config.CompileConfig(treeFromSet6722(t, lines)); err == nil {
		t.Fatalf("precondition: strict CompileConfig ADMITTED a reth naming " +
			"another reth as its redundant parent; this cell claims the shape only " +
			"arrives via the tolerant load / peer-sync path, and that claim is now " +
			"false")
	}

	cfg := compileWithStubbedLinks6722(t, lines, links, map[string]string{}, true)
	snaps := buildInterfaceSnapshots(cfg)

	// The precondition that makes the clause the ONLY thing answering: reth1
	// carries no configured unit, so `hasConfiguredUnit` does not refuse it
	// and `ifc.Tunnel` is nil.
	if member := cfg.Interfaces.Interfaces["reth1"]; member == nil {
		t.Fatalf("precondition: reth1 is absent from the compiled config")
	} else if hasConfiguredUnit(member) {
		t.Fatalf("precondition: reth1 carries a configured unit, so the " +
			"hasConfiguredUnit conjunct refuses it and the reth-prefix clause is " +
			"not what this cell measures")
	}
	base := snapByName6722(t, snaps, "reth0")
	unit0 := snapByName6722(t, snaps, "reth0.0")
	member := snapByName6722(t, snaps, "reth1")
	if base.Ifindex != 24 || unit0.Ifindex != 24 || member.Ifindex != 24 {
		t.Fatalf("precondition: reth0=%d reth0.0=%d reth1=%d, want 24/24/24 — "+
			"reth0 resolves onto its declared member reth1, which is what puts the "+
			"L3 owner and the supposed port on ONE netdev",
			base.Ifindex, unit0.Ifindex, member.Ifindex)
	}
	if base.Zone != "lan" || member.Zone != "" {
		t.Fatalf("precondition: reth0 Zone=%q reth1 Zone=%q, want \"lan\" and \"\" "+
			"— a zone must actually be on the netdev, or a \"\" answer proves "+
			"nothing", base.Zone, member.Zone)
	}
	assertEgressZone6722(t, snaps, 24, "",
		"a reth is the L3 OWNER of a redundant pair and is never a member port, "+
			"so reth1 does not defer to reth0 and the two are independent claims on "+
			"one device. Resolving `lan` here would put reth1's transit — an "+
			"interface the operator zoned into nothing — under the LAN policy, on "+
			"exactly the tolerant path where the commit-time rejection is a warning")

	// O2 — the CONTROL. The same shape with an ordinary port name in place of
	// `reth1`: one bare member, one reth, one authored zone. It must resolve
	// `lan`. This is what isolates the failure above to the member's NAME.
	//
	// It runs through the SAME compile path as O1 — `CompileConfigLenient` with
	// no MACs — deliberately. An earlier spelling of this control went through
	// `buildSnapshotsFromSet6722`, which is the STRICT compiler, and primed a
	// MAC; the two runs then differed on three axes and the sentence below
	// ("changing nothing else") was false as written. All four combinations of
	// strict/lenient x MAC/no-MAC were measured and all answer `lan`, so the
	// conclusion was never in doubt — but a control that varies more than it
	// claims is not a control, and correcting the claim is cheaper than
	// defending it. The only remaining difference is the member's name and the
	// link key that name forces (`reth1` -> `ge-0-0-1`), which is not an
	// independent variation but the rename itself: `snapshotLinuxName` resolves
	// a member to its own name.
	ctlCfg := compileWithStubbedLinks6722(t, []string{
		"set interfaces ge-0/0/1 gigether-options redundant-parent reth0",
		"set interfaces reth0 redundant-ether-options redundancy-group 1",
		"set interfaces reth0 unit 0 family inet address 10.0.61.1/24",
		"set security zones security-zone lan interfaces reth0",
	}, map[string]int{"ge-0-0-1": 24}, map[string]string{}, true)
	assertEgressZone6722(t, buildInterfaceSnapshots(ctlCfg), 24, "lan",
		"renaming the member from `reth1` to `ge-0/0/1` — through the same "+
			"lenient compile, with the same empty MAC table — must resolve the "+
			"reth's zone; if this control also answers \"\" then the cell above is "+
			"measuring something other than the reth-prefix clause")
}

// F: the field must survive the wire, and the StableZoneID quarantine must
// reach it.
//
// F1: the Rust resolver reads a JSON key. A rename or an `omitempty` that
// dropped a real answer would leave the helper reading "" and failing closed on
// every reth cluster — green in Go, blackholed in production.
//
// F2: `quarantineCollidingZones` unzones the interfaces of a colliding zone
// expressly so they fail CLOSED. It runs AFTER buildInterfaceSnapshots, so it
// must blank the EGRESS answer too — the answer is a separate field and rule 3
// can put a zone on an ifindex whose rows are all unzoned.
func TestEgressZoneCrossesTheWireAndTheQuarantine_6722(t *testing.T) {
	_, snaps := buildSnapshotsFromSet6722(t, []string{
		"set interfaces ge-0/0/1 gigether-options redundant-parent reth1",
		"set interfaces reth1 redundant-ether-options redundancy-group 2",
		"set interfaces reth1 unit 0 family inet address 10.0.61.1/24",
		"set security zones security-zone lan interfaces reth1",
	}, map[string]int{"ge-0-0-1": 24},
		map[string]string{"ge-0-0-1": "02:bf:72:01:00:01"})

	raw, err := json.Marshal(snapByName6722(t, snaps, "ge-0/0/1"))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	blob := string(raw)
	if !strings.Contains(blob, `"egress_zone":"lan"`) {
		t.Fatalf("serialized member row does not carry egress_zone=lan; the Rust "+
			"resolver reads this key (`InterfaceSnapshot::egress_zone`, "+
			"userspace-dp/src/protocol/snapshot.rs) and an absent one fails CLOSED "+
			"on every bondless RETH cluster. Got: %s", truncate6722(blob, 400))
	}

	// F2 — the quarantine. Two zone names that collide on the same StableZoneID
	// slot; the later-sorting one is quarantined and its interfaces unzoned.
	// Lenient: a StableZoneID collision is REJECTED at commit (#3075), so the
	// quarantine only ever sees a config that arrived through the tolerant load /
	// peer-sync path.
	cfgQ := compileWithStubbedLinks6722(t, quarantineCollisionLines6722(t), map[string]int{
		"ge-0-0-1": 24, "ge-0-0-2": 25,
	}, map[string]string{
		"ge-0-0-1": "02:bf:72:01:00:01", "ge-0-0-2": "02:bf:72:01:00:02",
	}, true)
	ucfg := deriveUserspaceConfig(cfgQ)
	snapQ, err := buildSnapshot(cfgQ, ucfg, 0, 0)
	if err != nil {
		t.Fatalf("buildSnapshot: %v", err)
	}
	if len(snapQ.zoneIDCollisions) == 0 {
		t.Fatalf("precondition: no zone-ID collision was quarantined, so this cell " +
			"is not exercising the quarantine at all")
	}
	dropped := snapQ.zoneIDCollisions[0].Quarantined
	for _, s := range snapQ.Interfaces {
		if s.EgressZone == dropped {
			t.Errorf("interface %q still carries EgressZone %q, a zone the "+
				"StableZoneID quarantine DROPS from the published set. "+
				"stampEgressZones excludes a to-be-quarantined binding before it "+
				"decides, precisely so these interfaces fail CLOSED; naming a "+
				"dropped zone here would also fail the Rust corroboration, so the "+
				"ifindex would lose its zone for the wrong reason", s.Name, dropped)
		}
	}
}

// G: incoherent memberships as COMMIT REJECTIONS. G1/G2 put two independently
// addressed L3 units on one netdev; G3 is the round-10 addition — a base-level
// TUNNEL on a member, which the unit clause cannot see because a WireGuard
// interface configures no logical unit at all.
func TestRethMemberWithItsOwnL3IdentityIsRejected_6722(t *testing.T) {
	cases := []struct {
		name     string
		lines    []string
		fragment string
	}{
		{
			name: "unit-0-collapse",
			lines: []string{
				"set interfaces ge-0/0/1 gigether-options redundant-parent reth1",
				"set interfaces ge-0/0/1 unit 0 family inet address 10.9.9.1/30",
				"set interfaces reth1 redundant-ether-options redundancy-group 2",
				"set interfaces reth1 unit 0 family inet address 10.0.61.1/24",
				"set security zones security-zone lan interfaces reth1",
			},
			fragment: "also configures `unit",
		},
		{
			name: "vlan-unit-aliases-the-reths",
			lines: []string{
				"set interfaces ge-0/0/1 gigether-options redundant-parent reth1",
				"set interfaces ge-0/0/1 vlan-tagging",
				"set interfaces ge-0/0/1 unit 100 vlan-id 100 family inet address 10.9.100.1/30",
				"set interfaces reth1 redundant-ether-options redundancy-group 2",
				"set interfaces reth1 vlan-tagging",
				"set interfaces reth1 unit 100 vlan-id 100 family inet address 10.0.61.1/24",
				"set security zones security-zone lan interfaces reth1",
			},
			fragment: "also configures `unit",
		},
		{
			// G3: no logical unit anywhere on wg0, so the unit clause cannot
			// reach it — this sub-case is what makes the tunnel clause
			// independently load-bearing.
			name: "wireguard-tunnel-as-member",
			lines: []string{
				"set interfaces wg0 gigether-options redundant-parent reth1",
				"set interfaces wg0 tunnel mode wireguard",
				"set interfaces wg0 tunnel wireguard listen-port 51820",
				"set interfaces wg0 tunnel wireguard private-key b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2",
				"set interfaces wg0 tunnel wireguard peer a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1 allowed-ips 10.66.0.0/24",
				"set interfaces reth1 redundant-ether-options redundancy-group 2",
				"set interfaces reth1 unit 0 family inet address 10.0.61.1/24",
				"set security zones security-zone lan interfaces reth1",
			},
			fragment: "also configures a `tunnel`",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assertRethMemberRejected6722(t, tc.lines, tc.fragment)
		})
	}
}

// H: a member naming ITSELF. `RethToPhysical` maps the name to itself, so
// `ResolveReth` is a no-op and the interface is a member of nothing — while
// still presenting as one.
//
// H1 carries NO units, and it is the sub-case that makes the self clause
// independently load-bearing: the other three would be rejected by the unit
// clause even with the self clause gone, so on its own each of them proves only
// that SOME clause fires. Measured — drop the self clause and H1 compiles
// cleanly while H2/H3/H4 are still rejected, by a different clause and with a
// different message.
func TestSelfNamedRedundantParentIsRejected_6722(t *testing.T) {
	cases := []struct {
		name  string
		lines []string
	}{
		{
			name: "no-units",
			lines: []string{
				"set interfaces ge-0/0/1 gigether-options redundant-parent ge-0/0/1",
				"set interfaces ge-0/0/2 unit 0 family inet address 10.0.61.1/24",
				"set security zones security-zone lan interfaces ge-0/0/2.0",
			},
		},
		{
			name: "no-redundancy-group",
			lines: []string{
				"set interfaces st0 gigether-options redundant-parent st0",
				"set interfaces st0 unit 0 family inet address 10.5.5.1/30",
				"set interfaces st0 unit 1 family inet address 10.6.6.1/30",
				"set security zones security-zone vpnb interfaces st0.1",
			},
		},
		{
			name: "with-redundancy-group",
			lines: []string{
				"set interfaces st0 gigether-options redundant-parent st0",
				"set interfaces st0 redundant-ether-options redundancy-group 1",
				"set interfaces st0 unit 0 family inet address 10.5.5.1/30",
				"set interfaces st0 unit 1 family inet address 10.6.6.1/30",
				"set security zones security-zone vpnb interfaces st0.1",
			},
		},
		{
			name: "reth-names-itself",
			lines: []string{
				"set interfaces reth1 gigether-options redundant-parent reth1",
				"set interfaces reth1 redundant-ether-options redundancy-group 1",
				"set interfaces reth1 unit 0 family inet address 10.0.61.1/24",
				"set security zones security-zone lan interfaces reth1",
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assertRethMemberRejected6722(t, tc.lines, "names itself")
		})
	}
}

// I: a parent that is not configured at all. There is no RETH row on the shared
// netdev to take the L3 identity from, so the ifindex is left with no zone and
// every transit flow out of it is dropped — silently, behind a
// `redundant-parent` line that looks correct.
//
// The `bare-prefix` sub-case is the one an earlier string re-derivation was
// holed by: `reth10` is an ordinary Junos reth name that textually contains
// `reth1`. It is rejected here for the plain reason that `reth1` is undefined,
// and the sibling that names the DECLARED `reth10` compiles and resolves its
// zone — the control that keeps this cell from passing by nothing ever
// compiling.
func TestUnconfiguredRedundantParentIsRejected_6722(t *testing.T) {
	cases := []struct {
		name  string
		lines []string
	}{
		{
			name: "dangling-parent",
			lines: []string{
				"set interfaces ge-0/0/1 gigether-options redundant-parent reth1",
				"set security zones security-zone lan interfaces ge-0/0/2",
				"set interfaces ge-0/0/2 unit 0 family inet address 10.0.61.1/24",
			},
		},
		{
			name: "bare-prefix-sibling",
			lines: []string{
				"set interfaces ge-0/0/1 gigether-options redundant-parent reth1",
				"set interfaces ge-0/0/2 gigether-options redundant-parent reth10",
				"set interfaces reth10 redundant-ether-options redundancy-group 2",
				"set interfaces reth10 unit 0 family inet address 10.0.61.1/24",
				"set security zones security-zone lan interfaces reth10",
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assertRethMemberRejected6722(t, tc.lines, "is not a configured interface")
		})
	}
	_, snaps := buildSnapshotsFromSet6722(t, []string{
		"set interfaces ge-0/0/2 gigether-options redundant-parent reth10",
		"set interfaces reth10 redundant-ether-options redundancy-group 2",
		"set interfaces reth10 unit 0 family inet address 10.0.61.1/24",
		"set security zones security-zone lan interfaces reth10",
	}, map[string]int{"ge-0-0-2": 25},
		map[string]string{"ge-0-0-2": "02:bf:72:01:00:02"})
	assertEgressZone6722(t, snaps, 25, "lan",
		"reth10 IS configured and resolves onto ge-0/0/2, so the rejection "+
			"sub-tests above are measuring the parent's identity rather than a "+
			"blanket refusal to compile")
}

// J: the SELF-PARENT lenient-path cell. `RethToPhysical` maps a self-naming
// interface to itself, so any comparison of "does the parent resolve where this
// interface resolves" is trivially true. The commit gate rejects the shape (cell
// H); on the tolerant path it is admitted with a warning, and what holds the
// line there is that `egressRethMemberOf` requires a `reth*` PARENT — `st0` is
// not one, so `st0` is not a member of itself and the identities on its netdev
// are judged on their own.
//
// The measured consequence: `st0` (base, zone fanned up from st0.1) and `st0.0`
// (unzoned) share ifindex 42, no authored binding resolves there, and a unit row
// IS on the ifindex, so rule 3 does not fire either. Fails closed.
func TestSelfParentOnTheLenientPathStillFailsClosed_6722(t *testing.T) {
	cfg := compileWithStubbedLinks6722(t, []string{
		"set interfaces st0 gigether-options redundant-parent st0",
		"set interfaces st0 unit 0 family inet address 10.5.5.1/30",
		"set interfaces st0 unit 1 family inet address 10.6.6.1/30",
		"set security zones security-zone vpnb interfaces st0.1",
	}, map[string]int{"st0": 42, "st0.1": 43}, map[string]string{}, true)
	snaps := buildInterfaceSnapshots(cfg)

	if got := snapByName6722(t, snaps, "st0").Zone; got != "vpnb" {
		t.Fatalf("precondition: the st0 BASE row's Zone = %q, want %q — "+
			"buildInterfaceZoneMap's out[base] write is what makes this shape "+
			"interesting", got, "vpnb")
	}
	assertEgressZone6722(t, snaps, 42, "",
		"st0.0 is in no zone and the base row's vpnb is fanned up from st0.1, "+
			"which lives on its own netdev; a self-named redundant parent is not a "+
			"reth membership and cannot make one identity the other's port")
	assertEgressZone6722(t, snaps, 43, "vpnb",
		"st0.1 owns its own netdev and keeps its authored zone — the gate must be "+
			"scoped to the contested ifindex")
}

// L: a `reth*` interface that declares a `redundant-parent` of its OWN. A reth
// is the L3 OWNER of a redundant pair and never a member port, so this inverts
// the relation the whole model rests on.
//
// Measured at 195fcad51 with strict `CompileConfig`, against origin/master
// (edefb7570) as the control, all three were ACCEPTED — and the first two put a
// reth's rows on a netdev name no NIC carries, or marked the L3 owner as a
// projection of its own supposed parent. The third splits the two resolvers:
// `ResolveKernelIfName` (types.go) reads `RethToPhysical` UNGATED for a dotted
// ref, so `ge-0/0/1.0` DISPLAYS as `reth1` while the dataplane binds
// `ge-0-0-1`.
//
// FAIL-ON-REVERT: drop the reth clause from `validateRethMemberStrict` and all
// three sub-cases compile. The control at the end keeps that from passing by
// nothing ever compiling.
func TestRethNamingARedundantParentIsRejected_6722(t *testing.T) {
	cases := []struct {
		name  string
		lines []string
	}{
		{
			name: "reth-names-a-reth",
			lines: []string{
				"set interfaces reth1 gigether-options redundant-parent reth0",
				"set interfaces reth0 redundant-ether-options redundancy-group 1",
				"set interfaces reth0 unit 0 family inet address 10.0.61.1/24",
				"set security zones security-zone lan interfaces reth0",
			},
		},
		{
			name: "two-cycle",
			lines: []string{
				"set interfaces ge-0/0/1 gigether-options redundant-parent reth1",
				"set interfaces reth1 gigether-options redundant-parent ge-0/0/1",
				"set security zones security-zone lan interfaces ge-0/0/1",
			},
		},
		{
			name: "reth-names-a-physical",
			lines: []string{
				"set interfaces ge-0/0/1 unit 0 family inet address 10.0.61.1/24",
				"set interfaces reth1 gigether-options redundant-parent ge-0/0/1",
				"set security zones security-zone lan interfaces ge-0/0/1",
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assertRethMemberRejected6722(t, tc.lines, "is a redundant-ethernet interface")
		})
	}

	_, snaps := buildSnapshotsFromSet6722(t, []string{
		"set interfaces ge-0/0/1 gigether-options redundant-parent reth1",
		"set interfaces reth1 redundant-ether-options redundancy-group 2",
		"set interfaces reth1 unit 0 family inet address 10.0.61.1/24",
		"set security zones security-zone lan interfaces reth1",
	}, map[string]int{"ge-0-0-1": 24},
		map[string]string{"ge-0-0-1": "02:bf:72:01:00:01"})
	assertEgressZone6722(t, snaps, 24, "lan",
		"the reth clause must reject a reth that declares a redundant-parent "+
			"WITHOUT rejecting the ordinary membership that declares it on the "+
			"physical port — without this control the sub-tests above would pass on "+
			"a blanket refusal to compile anything with a reth in it")
}

// M: the PEER NODE's member. A two-node cluster config declares BOTH nodes'
// members, and only the one `ResolveReth` actually selects on this node shares
// the reth's netdev. The peer's member resolves to a Linux name that does not
// exist here, so it never reaches an ifindex at all — which is why "declares
// redundant-parent" was never the right question and the answer had to come
// from the resolver.
func TestPeerNodeRethMemberDoesNotReachAnIfindex_6722(t *testing.T) {
	_, snaps := buildSnapshotsFromSet6722(t, []string{
		"set interfaces ge-0/0/1 gigether-options redundant-parent reth1",
		"set interfaces ge-7/0/1 gigether-options redundant-parent reth1",
		"set interfaces reth1 redundant-ether-options redundancy-group 2",
		"set interfaces reth1 unit 0 family inet address 10.0.61.1/24",
		"set security zones security-zone lan interfaces reth1",
	}, map[string]int{"ge-0-0-1": 24},
		map[string]string{"ge-0-0-1": "02:bf:72:01:00:01"})

	peer := snapByName6722(t, snaps, "ge-7/0/1")
	if peer.Ifindex != 0 {
		t.Fatalf("precondition: ge-7/0/1 resolved to ifindex %d; the peer node's "+
			"netdev does not exist locally and must resolve to 0, or this cell is "+
			"not modelling a two-node config", peer.Ifindex)
	}
	assertEgressZone6722(t, snaps, 24, "lan",
		"the LOCAL member is the one reth1 resolves onto; declaring both nodes' "+
			"members must not make the shared ifindex contested")
}

// quarantineCollisionLines6722 builds a config with two zone names that collide
// on one StableZoneID slot, so quarantineCollidingZones drops the later-sorting
// one. Searching for the pair rather than hard-coding it keeps the cell from
// going vacuous if the hash changes.
func quarantineCollisionLines6722(t *testing.T) []string {
	t.Helper()
	base := []string{
		"set interfaces ge-0/0/1 unit 0 family inet address 10.0.61.1/24",
		"set interfaces ge-0/0/2 unit 0 family inet address 10.0.62.1/24",
	}
	for _, pair := range zoneIDCollisionPairs6722() {
		names := []string{pair[0], pair[1]}
		if len(config.QuarantinedZoneNames(names)) == 0 {
			continue
		}
		return append(append([]string{}, base...),
			"set security zones security-zone "+pair[0]+" interfaces ge-0/0/1.0",
			"set security zones security-zone "+pair[1]+" interfaces ge-0/0/2.0",
		)
	}
	t.Skip("no StableZoneID collision pair found in the search space; the " +
		"quarantine cell cannot be built without one")
	return nil
}

func zoneIDCollisionPairs6722() [][2]string {
	byID := map[uint16]string{}
	out := [][2]string{}
	for i := 0; i < 4096; i++ {
		name := "z" + itoa6722(i)
		id := config.StableZoneID(name)
		if prev, ok := byID[id]; ok {
			out = append(out, [2]string{prev, name})
			if len(out) >= 4 {
				return out
			}
			continue
		}
		byID[id] = name
	}
	return out
}

func itoa6722(i int) string {
	if i == 0 {
		return "0"
	}
	var buf [8]byte
	pos := len(buf)
	for i > 0 {
		pos--
		buf[pos] = byte('0' + i%10)
		i /= 10
	}
	return string(buf[pos:])
}

func assertRethMemberRejected6722(t *testing.T, lines []string, wantFragment string) {
	t.Helper()
	tree := treeFromSet6722(t, lines)
	_, err := config.CompileConfig(tree)
	if err == nil {
		t.Fatalf("CompileConfig accepted an incoherent reth membership; it must "+
			"be rejected at commit so the operator sees it before it mis-zones "+
			"traffic. Config: %v", lines)
	}
	if !strings.Contains(err.Error(), wantFragment) {
		t.Errorf("CompileConfig error = %q, want it to contain %q: the rejection "+
			"must come from the reth-member coherence gate, not from an unrelated "+
			"validator that happens to fire on this config too", err, wantFragment)
	}
	cfg, lerr := config.CompileConfigLenient(treeFromSet6722(t, lines))
	if lerr != nil {
		t.Fatalf("CompileConfigLenient rejected the same config (%v); the tolerant "+
			"load / peer-sync path must DOWNGRADE this gate to a warning or an "+
			"already-committed config stops booting (#1960 no-brick)", lerr)
	}
	if !warnsAboutRethMember6722(cfg.Warnings) {
		t.Errorf("CompileConfigLenient admitted the config but recorded no "+
			"reth-member warning; a silent tolerant admission leaves the operator "+
			"with no signal at all. Warnings: %v", cfg.Warnings)
	}
}

func warnsAboutRethMember6722(warnings []string) bool {
	for _, w := range warnings {
		if strings.Contains(w, "reth member (downgraded to warning on tolerant path)") {
			return true
		}
	}
	return false
}

func truncate6722(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

// ===========================================================================
// ROUND 12 — THE SURVIVORS.
//
// Every cell below exists because reverting ONE production clause left the
// whole Go suite green at 6e62cd01d. The round-11 matrix recorded those clauses
// as benign; the measurement says otherwise, and a clause whose removal changes
// no test is a clause the suite does not own.
//
// The predicate that produced them, stated so the next round can re-run it:
// every conditional or guard expression this PR introduces or changes in
// interfaces.go and zones.go, mutated ONE AT A TIME against
// `go test -count=1 ./pkg/dataplane/userspace/...`. Sixteen ran. Three were
// already bound (x1/x4/x8 in the table below). Eight are bound by the cells in
// this section. Five are inert for a STRUCTURAL reason, recorded rather than
// bound — a guard that cannot fire needs an explanation, not a fixture.
//
// FAIL-ON-REVERT, round-12 additions:
//
//	authoredZoneRefs first-write-wins -> last-write-wins          -> P, Q
//	authoredZoneRefs drops CanonicalInterfaceUnitRef              -> R (and P)
//	unanimousUnitZone drops `if z == "" { continue }`             -> S
//	unanimousUnitZone drops `if seen != "" && seen != z`          -> T
//	hasConfiguredUnit drops its `unit != nil` skip                -> U
//	unanimousUnitZone drops `if unit == nil { continue }`         -> V
//	egressRethMemberOf drops `ifc.RedundantParent != reth`        -> W
//	egressIdentitiesCohere drops `len(identities) > 2`            -> E/reth-as-member-plus-canonical-collision, but ONLY after the
//	                                                                 order-stability loop added to that cell in this round: measured
//	                                                                 1 red in 8 whole-suite runs before it, 6 in 6 after
//	rule 2 admits an empty authored zone as a claim               -> A1/B/C/D/D2/N1 (already bound)
//	stampEgressZones never records hasUnitRow                     -> the self-parent lenient cell (already bound)
//
// INERT BY CONSTRUCTION, measured green and NOT bound, each with its reason:
//
//	`if ifx <= 0 { continue }` in stampEgressZones. An unresolved netdev would
//	  be stamped on ifindex 0, and `populate_interfaces`
//	  (userspace-dp/src/afxdp/forwarding_build/interfaces.rs) opens its own walk
//	  with `if iface.ifindex <= 0 { continue; }`, so no ifindex-0 row reaches
//	  any zone state on the far side of the wire. It is a redundant belt in
//	  front of a Rust guard that is itself bound, and duplicating that guard's
//	  fixture here would bind the copy rather than the agreement. Kept, and
//	  recorded as redundant rather than dressed up as load-bearing.
//
//	`cfg.Interfaces.Interfaces[reth] == nil` in egressRethMemberOf, `ifc == nil`
//	  in egressRethMemberOf/egressMemberIsBarePort, and `ifc == nil` in
//	  unanimousUnitZone. Every name these four see is an `owner` recorded in
//	  `idents`, and buildInterfaceSnapshots emits no row at all for a
//	  present-but-nil InterfaceConfig (`if iface == nil { continue }`, the
//	  #3494/#5068 tolerant-load slot). So no owner can name a nil slot and none
//	  of the four can fire. They are nil-safety on a path that cannot deliver
//	  nil; the thing that makes that true is the row loop's own skip, which is
//	  where a fixture would have to bind it.
//
//	`len(out) != len(idents)` in stampEgressZones. `idents` is appended in
//	  lock-step with `out` at both append sites in one function; the assert
//	  cannot fire without the same edit that breaks the pairing, so no mutation
//	  of the assert alone is observable. A construction invariant, not a guard.
//
//	`num < lowest` in firstConfiguredUnit. RESOLVED in #7026, so this row no
//	  longer describes the tree. The selection was dead rather than unbound —
//	  the int had no consumer at any of its three call sites — and this row
//	  said it was worth collapsing in a round allowed to move production.
//	  #7026 was that round: the function is now `hasConfiguredUnit(ifc) bool`
//	  and there is no selection left to mutate. Kept as a row so the next
//	  reader of this table sees the disposition rather than re-deriving it.
//
//	`if rawIface == "" { continue }` in authoredZoneRefs. No `set` line produces
//	  an empty zone-interface reference, so the clause is unreachable from the
//	  parser. It is retained because buildInterfaceZoneMap carries the identical
//	  clause and cell P binds the two maps' agreement — dropping it from one
//	  side alone is the shape P exists to catch, if a config ever reaches it.
//
//	`len(cfg.Security.Zones) < 2` in quarantinedZoneNames. Widening it to `< 1`
//	  changes nothing: `config.QuarantinedZoneNames` returns a collision set,
//	  and one name collides with nothing. An early-out, not a policy.
// ===========================================================================

// zoneMapCorpus6722 is the shared corpus for the AGREEMENT cell below: the
// config shapes this PR reasons about, each with the compile path that admits
// it. The doubly-claimed-ref shape is STRICT-rejected, which is why the corpus
// carries a lenient flag rather than compiling everything one way.
func zoneMapCorpus6722() []struct {
	name    string
	lines   []string
	lenient bool
} {
	return []struct {
		name    string
		lines   []string
		lenient bool
	}{
		{"reference-bondless-reth", []string{
			"set interfaces ge-0/0/1 gigether-options redundant-parent reth1",
			"set interfaces reth1 redundant-ether-options redundancy-group 2",
			"set interfaces reth1 unit 0 family inet address 10.0.61.1/24",
			"set security zones security-zone lan interfaces reth1",
		}, false},
		{"two-units-two-zones", []string{
			"set interfaces ge-0/0/1 unit 0 family inet address 10.0.61.1/24",
			"set interfaces ge-0/0/1 unit 1 family inet address 10.0.62.1/24",
			"set security zones security-zone lan interfaces ge-0/0/1.0",
			"set security zones security-zone dmz interfaces ge-0/0/1.1",
		}, false},
		{"noncanonical-unit-ref", []string{
			"set interfaces ge-0/0/1 vlan-tagging",
			"set interfaces ge-0/0/1 unit 1 vlan-id 1 family inet address 10.0.61.1/24",
			"set security zones security-zone lan interfaces ge-0/0/1.01",
		}, false},
		{"tagged-trunk", []string{
			"set interfaces ge-0/0/1 vlan-tagging",
			"set interfaces ge-0/0/1 unit 50 vlan-id 50 family inet address 172.16.50.8/24",
			"set interfaces ge-0/0/1 unit 80 vlan-id 80 family inet address 172.16.80.8/24",
			"set security zones security-zone wan interfaces ge-0/0/1.50",
			"set security zones security-zone wan interfaces ge-0/0/1.80",
		}, false},
		{"bare-ref-fans-down-onto-units", []string{
			"set interfaces ge-0/0/1 unit 0 family inet address 10.0.61.1/24",
			"set interfaces ge-0/0/1 unit 1 family inet address 10.0.62.1/24",
			"set security zones security-zone lan interfaces ge-0/0/1",
		}, false},
		// The shape round 11's survivor ledger reasoned about, and the reason
		// this corpus exists. STRICT rejects a doubly-claimed reference
		// outright, so it is reachable only on the #1960 no-brick / HA
		// peer-sync path.
		{"member-claimed-by-two-zones", []string{
			"set interfaces ge-0/0/1 gigether-options redundant-parent reth1",
			"set interfaces reth1 redundant-ether-options redundancy-group 2",
			"set interfaces reth1 unit 0 family inet address 10.0.61.1/24",
			"set security zones security-zone aaa interfaces ge-0/0/1",
			"set security zones security-zone zzz interfaces ge-0/0/1",
			"set security zones security-zone zzz interfaces reth1",
		}, true},
		// #7024: THE FALSIFYING SHAPE. A BARE reference in one zone and a
		// DOTTED reference from a DIFFERENT zone naming the same interface.
		// buildInterfaceZoneMap fans the dotted ref UP to the base
		// (first-write-wins over sorted zone names, so `aaa` beats `zzz`);
		// authoredZoneRefs deliberately does not fan up, and records the bare
		// sentence. The two therefore give different answers for `ge-0/0/1`.
		//
		// This is the ONLY shape that falsifies the old unconditional
		// agreement claim, and the corpus had nothing like it: the five strict
		// shapes never double-claim, and `member-claimed-by-two-zones` uses TWO
		// BARE refs, so no fan-up is involved.
		{"base-and-unit-claimed-by-different-zones", []string{
			"set interfaces ge-0/0/1 unit 0 family inet address 10.0.1.1/24",
			"set security zones security-zone aaa interfaces ge-0/0/1.0",
			"set security zones security-zone zzz interfaces ge-0/0/1",
		}, true},
		// ...and its MIRROR, with the zone names swapped so the fan-up winner
		// is also the bare ref's zone. This samples the BENIGN side of the same
		// axis: no divergence. Both are here because a fixture that picked only
		// this order would prove nothing — the ordering is what makes the shape
		// falsifying, and a corpus sitting on the passing point of an axis it
		// varies is the defect this issue is about.
		{"base-and-unit-same-zone-wins-fanup", []string{
			"set interfaces ge-0/0/1 unit 0 family inet address 10.0.1.1/24",
			"set security zones security-zone zzz interfaces ge-0/0/1.0",
			"set security zones security-zone aaa interfaces ge-0/0/1",
		}, true},
	}
}

// P: `authoredZoneRefs` and `buildInterfaceZoneMap` must AGREE about every
// reference the operator literally wrote.
//
// The two maps are built by separate code for separate consumers —
// authoredZoneRefs records PROVENANCE for stampEgressZones, buildInterfaceZoneMap
// derives the per-row INGRESS attribution and fans a reference up to the base
// and down onto the units — but they read the same
// `security-zone <z> interfaces <ref>` sentences through the same canonicalizer
// and pick a winner the same way: zone names sorted, first write wins. Round 11
// recorded a last-write-wins mutation of authoredZoneRefs as benign, on the
// reason that "buildInterfaceZoneMap applies the same first-write-wins, so both
// maps pick the same winner". That reason is circular — the two agree BECAUSE of
// the line the mutation deletes — and the agreement had no binder.
//
// This is deliberately an AGREEMENT test rather than a collapse of the two
// functions into one. They may legitimately diverge later; a move toward Junos
// per-unit zoning would want buildInterfaceZoneMap to stop fanning up to the
// base while authoredZoneRefs went on recording the literal reference. What must
// not happen silently is the two DISAGREEING about a reference both of them
// hold, because stampEgressZones resolves rule 2 from one map while the Rust
// corroboration check reads the other, and a disagreement is exactly a claim the
// helper will corroborate against a zone the operator did not write for that
// identity.
//
// FAIL-ON-REVERT, measured: authoredZoneRefs last-write-wins reds this on
// `member-claimed-by-two-zones` (authored says `zzz`, the zone map says `aaa`);
// dropping CanonicalInterfaceUnitRef from authoredZoneRefs reds it on
// `noncanonical-unit-ref` (authored keys `.01`, the zone map keys `.1`).
func TestAuthoredAndDerivedZoneMapsAgreeOnEveryAuthoredRef_6722(t *testing.T) {
	// #7024 ANTI-VACUITY. The narrowing below tolerates a base-reference
	// divergence, which is only safe to tolerate if the corpus actually
	// CONTAINS one — otherwise the loop degrades to the old unconditional
	// claim and the tolerance is untested prose. The old corpus had no such
	// shape, which is exactly how the guard passed while its claim was false.
	sawExplainedBaseDivergence := false
	for _, tc := range zoneMapCorpus6722() {
		t.Run(tc.name, func(t *testing.T) {
			cfg := compileWithStubbedLinks6722(t, tc.lines, map[string]int{}, map[string]string{}, tc.lenient)
			authored := authoredZoneRefs(cfg)
			derived := buildInterfaceZoneMap(cfg)

			// Anti-vacuity: an empty authored map would make the loop below a
			// no-op and the subtest green for the wrong reason.
			if len(authored) == 0 {
				t.Fatalf("precondition: authoredZoneRefs is EMPTY for %q, so the "+
					"agreement loop asserts nothing", tc.name)
			}
			refs := make([]string, 0, len(authored))
			for ref := range authored {
				refs = append(refs, ref)
			}
			sort.Strings(refs)
			for _, ref := range refs {
				got, want := derived[ref], authored[ref]
				if got == want {
					continue
				}
				// #7024: a UNIT reference must ALWAYS agree. Both maps record a
				// unit ref from the operator's literal sentence and neither
				// synthesizes one, so a disagreement here really is one of them
				// changing its write policy or canonicalization alone.
				if strings.Contains(ref, ".") {
					t.Errorf("the two zone maps DISAGREE about the authored UNIT "+
						"reference %q: authoredZoneRefs=%q buildInterfaceZoneMap=%q. "+
						"Neither map synthesizes a unit reference, so this is one of "+
						"them changing its write policy or its canonicalization "+
						"alone.\n  authored=%v\n  derived =%v",
						ref, want, got, authored, derived)
					continue
				}
				// A BASE reference MAY diverge, and #7024 is the record of why.
				// buildInterfaceZoneMap fans a unit reference UP to its base;
				// authoredZoneRefs deliberately does not, because it is
				// PROVENANCE — what the operator literally wrote. When a bare
				// ref in one zone and a dotted ref from an alphabetically
				// earlier zone name the same interface, the derived map answers
				// with the fan-up winner and the authored map answers with the
				// bare sentence. Both are correct for their own consumer.
				//
				// What must hold is that the divergence is EXPLAINED by the
				// fan-up rather than arbitrary: the derived value has to be the
				// zone of some authored UNIT under this base. A derived value
				// from nowhere would mean the fan-up itself had changed.
				explained := false
				for other, otherZone := range authored {
					if other == ref || !strings.HasPrefix(other, ref+".") {
						continue
					}
					if otherZone == got {
						explained = true
						break
					}
				}
				if !explained {
					t.Errorf("the two zone maps disagree about the authored BASE "+
						"reference %q (authoredZoneRefs=%q buildInterfaceZoneMap=%q) "+
						"and the derived value is NOT the zone of any authored unit "+
						"under it, so the fan-up does not explain it. A base "+
						"divergence is tolerated ONLY as the fan-up of a unit "+
						"reference (#7024); this one came from somewhere else.\n"+
						"  authored=%v\n  derived =%v",
						ref, want, got, authored, derived)
					continue
				}
				sawExplainedBaseDivergence = true
			}
		})
	}
	if !sawExplainedBaseDivergence {
		t.Fatalf("no corpus shape produced a base-reference divergence, so the #7024 " +
			"tolerance above was never exercised and this guard has silently " +
			"reverted to the unconditional agreement claim it replaced. Restore " +
			"`base-and-unit-claimed-by-different-zones` (a BARE ref in one zone and " +
			"a DOTTED ref from an alphabetically EARLIER zone naming one interface) " +
			"— note the zone ORDER is what makes it falsifying")
	}
}

// Q: a member port claimed by TWO zones, one of which also holds its RETH, must
// fail CLOSED — the OUTCOME half of cell P, on the shape that makes the
// disagreement dangerous rather than merely untidy.
//
// `ge-0/0/1` in `aaa` and `zzz`, `reth1` in `zzz`, all three rows on one netdev.
// Two DISTINCT authored zones resolve to that ifindex, so rule 2's conflict arm
// fires and the device identifies no single zone. Under a last-write-wins
// authoredZoneRefs both references resolve `zzz`, rule 2 sees a singleton, and
// the ifindex adjudicates as `zzz` — a zone the reth was put in but the member
// was not, and the Rust corroboration check cannot catch it because the rows
// carry `aaa` AND `zzz` between them, so `zzz` IS corroborated.
//
// Strict rejects this config, so the surface it defends is the tolerant load /
// HA peer-sync path where that rejection is a warning (#1960 no-brick) — the
// same surface cell O defends, and the reason cell P's corpus carries a lenient
// flag.
func TestMemberClaimedByTwoZonesFailsClosedOnTheLenientPath_6722(t *testing.T) {
	lines := []string{
		"set interfaces ge-0/0/1 gigether-options redundant-parent reth1",
		"set interfaces reth1 redundant-ether-options redundancy-group 2",
		"set interfaces reth1 unit 0 family inet address 10.0.61.1/24",
		"set security zones security-zone aaa interfaces ge-0/0/1",
		"set security zones security-zone zzz interfaces ge-0/0/1",
		"set security zones security-zone zzz interfaces reth1",
	}
	links := map[string]int{"ge-0-0-1": 24}
	macs := map[string]string{"ge-0-0-1": "02:bf:72:01:00:01"}

	// Pinned rather than assumed: if strict ever admitted a doubly-claimed
	// reference, "only reachable leniently" would be false and the reader would
	// be misled about which surface this cell defends.
	if _, err := config.CompileConfig(treeFromSet6722(t, lines)); err == nil {
		t.Fatalf("precondition: strict CompileConfig ADMITTED an interface " +
			"claimed by two security zones; this cell claims the shape reaches " +
			"the builder only on the tolerant path, and that claim is now false")
	}

	cfg := compileWithStubbedLinks6722(t, lines, links, macs, true)
	snaps := buildInterfaceSnapshots(cfg)

	if got := authoredZoneRefs(cfg)["ge-0/0/1"]; got != "aaa" {
		t.Fatalf("precondition: authoredZoneRefs[ge-0/0/1] = %q, want %q — the "+
			"member's first-written zone is what makes TWO distinct zones resolve "+
			"to this ifindex; if it were %q there would be only one and rule 2 "+
			"would resolve normally", got, "aaa", "zzz")
	}
	member := snapByName6722(t, snaps, "ge-0/0/1")
	base := snapByName6722(t, snaps, "reth1")
	if member.Ifindex != 24 || base.Ifindex != 24 {
		t.Fatalf("precondition: ge-0/0/1=%d reth1=%d, want 24/24 — the claims "+
			"must land on ONE netdev", member.Ifindex, base.Ifindex)
	}
	if member.Zone != "aaa" || base.Zone != "zzz" {
		t.Fatalf("precondition: ge-0/0/1 Zone=%q reth1 Zone=%q, want \"aaa\" and "+
			"\"zzz\" — BOTH zone names must be carried on this ifindex, or the "+
			"Rust corroboration check would refuse a `zzz` answer on its own and "+
			"this cell would not be measuring the Go conflict arm",
			member.Zone, base.Zone)
	}
	assertEgressZone6722(t, snaps, 24, "",
		"the operator's sentences put `aaa` and `zzz` on this one netdev, so it "+
			"identifies no single egress zone. Answering `zzz` adjudicates the "+
			"member's transit under a zone it was never placed in — and `zzz` is "+
			"carried by the reth rows, so the helper's corroboration check would "+
			"honour it")

	// CONTROL. Drop the `aaa` binding and nothing else: one authored zone on a
	// coherent netdev, which rule 2 resolves. Without it, a mutation that broke
	// coherence outright would red the assertion above and look like the
	// conflict arm was bound.
	ctl := compileWithStubbedLinks6722(t, []string{
		lines[0], lines[1], lines[2], lines[4], lines[5],
	}, links, macs, true)
	assertEgressZone6722(t, buildInterfaceSnapshots(ctl), 24, "zzz",
		"removing ONLY the second claim on the member leaves one authored zone "+
			"on a coherent netdev; if this control also answers \"\" then the "+
			"assertion above is measuring coherence, not the conflict arm")
}

// R: an authored `.01` unit reference must be canonicalised the same way the
// snapshot's row NAMES are.
//
// #5878 phase 2 made buildInterfaceZoneMap bind a zone reference on its
// CANONICAL logical-unit identity so `ge-0/0/1.01` and `ge-0/0/1.1` resolve to
// the same runtime unit. authoredZoneRefs must do the same, and the #5878 cell
// cannot see whether it does: that cell binds buildInterfaceZoneMap only, and
// this PR introduced a SECOND map keyed the same way.
//
// This is an ORDINARY STRICT COMMIT — `compileWithStubbedLinks6722(...,
// lenient=false)` fatals on rejection, so reaching the assertions is itself the
// proof. Without the canonicalization the authored key is `ge-0/0/1.01`, which
// matches no row name, and BOTH ifindexes lose their zone: the unit's own
// (rule 2 finds no authored reference for `ge-0/0/1.1`) and the base's (rule 3
// looks up `ge-0/0/1.1` in the same map and misses). A silent
// `default-policy deny-all` blackhole of an explicitly zoned interface, from a
// leading zero.
func TestAuthoredUnitRefIsCanonicalisedLikeTheRowNames_6722(t *testing.T) {
	cfg := compileWithStubbedLinks6722(t, []string{
		"set interfaces ge-0/0/1 vlan-tagging",
		"set interfaces ge-0/0/1 unit 1 vlan-id 1 family inet address 10.0.61.1/24",
		"set security zones security-zone lan interfaces ge-0/0/1.01",
	}, map[string]int{"ge-0-0-1": 24, "ge-0-0-1.1": 26},
		map[string]string{"ge-0-0-1": "02:bf:72:01:00:01"}, false)
	snaps := buildInterfaceSnapshots(cfg)

	authored := authoredZoneRefs(cfg)
	if got := authored["ge-0/0/1.1"]; got != "lan" {
		t.Fatalf("authoredZoneRefs[ge-0/0/1.1] = %q, want %q — the operator wrote "+
			"`.01` and the snapshot names the row `.1`, so the authored map must "+
			"be keyed on the CANONICAL unit identity or it matches no row at all. "+
			"Full map: %v", got, "lan", authored)
	}
	if _, raw := authored["ge-0/0/1.01"]; raw {
		t.Errorf("authoredZoneRefs still carries the RAW key `ge-0/0/1.01`; the " +
			"key must be canonicalised, not merely duplicated, or a second " +
			"spelling of the same unit becomes a second authored claim and rule " +
			"2's conflict arm fires on one operator sentence")
	}
	if unit := snapByName6722(t, snaps, "ge-0/0/1.1"); unit.Ifindex != 26 {
		t.Fatalf("precondition: ge-0/0/1.1 ifindex = %d, want 26 — a VLAN unit "+
			"must land on its own netdev, or the base ifindex would carry a unit "+
			"row and rule 3 would not be exercised", unit.Ifindex)
	}
	assertEgressZone6722(t, snaps, 26, "lan",
		"the operator explicitly zoned this unit, spelling it `.01`; rule 2 must "+
			"resolve it through the same canonicalization the row name went "+
			"through")
	assertEgressZone6722(t, snaps, 24, "lan",
		"the base netdev carries no unit row of its own, so rule 3 takes its "+
			"units' unanimous zone — and rule 3 reads the SAME authored map, so a "+
			"raw `.01` key strips the zone from the trunk parent too")
}

// S: a trunk carrier whose units are only PARTLY zoned takes its zoned units'
// zone, stably.
//
// unanimousUnitZone skips an unzoned unit rather than counting it as dissent:
// such a unit is not on this netdev and says nothing about it. The existing
// trunk cell (D) zones EVERY unit, so it cannot see the skip.
//
// WHY THE LOOP. Removing the skip does not produce a single wrong answer — it
// produces an ORDER-DEPENDENT one. `seen == ""` then means both "nothing seen
// yet" and "an unzoned unit was seen", so the mutant answers `wan` when Go's
// randomized map iteration happens to walk the unzoned unit first and "" when it
// does not. One build is a coin flip; N independent builds asserting a SINGLE
// answer is what makes the binding deterministic, and "the answer varied between
// builds" is the more useful failure to report anyway, since the production
// consequence of the mutation is an egress zone that changes across daemon
// restarts on an unchanged config.
func TestPartlyZonedTrunkTakesItsZonedUnitsZoneStably_6722(t *testing.T) {
	cfg := compileWithStubbedLinks6722(t, []string{
		"set interfaces ge-0/0/1 vlan-tagging",
		"set interfaces ge-0/0/1 unit 50 vlan-id 50 family inet address 172.16.50.8/24",
		"set interfaces ge-0/0/1 unit 80 vlan-id 80 family inet address 172.16.80.8/24",
		"set interfaces ge-0/0/1 unit 90 vlan-id 90 family inet address 172.16.90.8/24",
		"set security zones security-zone wan interfaces ge-0/0/1.50",
		"set security zones security-zone wan interfaces ge-0/0/1.80",
	}, map[string]int{"ge-0-0-1": 25, "ge-0-0-1.50": 26, "ge-0-0-1.80": 27, "ge-0-0-1.90": 28},
		map[string]string{"ge-0-0-1": "02:bf:72:01:00:02"}, false)

	// The precondition that separates this cell from cell D: one unit must be
	// genuinely UNZONED, or the skip is never reached.
	authored := authoredZoneRefs(cfg)
	if authored["ge-0/0/1.50"] != "wan" || authored["ge-0/0/1.80"] != "wan" {
		t.Fatalf("precondition: units 50/80 must both be authored into `wan`; "+
			"authored=%v", authored)
	}
	if z, ok := authored["ge-0/0/1.90"]; ok {
		t.Fatalf("precondition: unit 90 carries an authored zone %q, so this cell "+
			"is cell D again and the unzoned-unit skip is not exercised", z)
	}

	const builds = 64
	answers := map[string][]int{}
	for i := 0; i < builds; i++ {
		snaps := buildInterfaceSnapshots(cfg)
		answers[egressZoneOfIfindex6722(t, snaps, 25)] = append(
			answers[egressZoneOfIfindex6722(t, snaps, 25)], i)
	}
	if len(answers) != 1 || len(answers["wan"]) != builds {
		got := make([]string, 0, len(answers))
		for z, at := range answers {
			got = append(got, fmt.Sprintf("%q on %d/%d builds", z, len(at), builds))
		}
		sort.Strings(got)
		t.Fatalf("the trunk parent's egress zone must be %q on every one of %d "+
			"independent builds; got %v. An unzoned unit is not on this netdev "+
			"and says nothing about it, so counting it as dissent makes the "+
			"answer a function of Go's randomized map iteration order — the same "+
			"config would adjudicate differently across daemon restarts",
			"wan", builds, got)
	}
}

// T: a trunk carrier whose units DISAGREE fails closed.
//
// The other half of unanimousUnitZone, and an entirely ordinary operator config:
// one tagged interface, two VLANs, two zones. Neither unit is on the base
// netdev, so rule 3 fires there and must find no unanimity.
//
// Deterministic where cell S needs a loop, because both of the mutant's possible
// answers are wrong: with the disagreement arm removed the base takes `wan` or
// `dmz` depending on map order, and the correct answer is neither.
func TestTrunkCarrierWithDisagreeingUnitsFailsClosed_6722(t *testing.T) {
	_, snaps := buildSnapshotsFromSet6722(t, []string{
		"set interfaces ge-0/0/1 vlan-tagging",
		"set interfaces ge-0/0/1 unit 50 vlan-id 50 family inet address 172.16.50.8/24",
		"set interfaces ge-0/0/1 unit 80 vlan-id 80 family inet address 172.16.80.8/24",
		"set security zones security-zone wan interfaces ge-0/0/1.50",
		"set security zones security-zone dmz interfaces ge-0/0/1.80",
	}, map[string]int{"ge-0-0-1": 25, "ge-0-0-1.50": 26, "ge-0-0-1.80": 27},
		map[string]string{"ge-0-0-1": "02:bf:72:01:00:02"})

	for _, name := range []string{"ge-0/0/1.50", "ge-0/0/1.80"} {
		if got := snapByName6722(t, snaps, name).Ifindex; got == 25 {
			t.Fatalf("precondition: %s resolved to the BASE ifindex 25; a VLAN "+
				"unit must land on its own netdev or rule 3 never fires here", name)
		}
	}
	assertEgressZone6722(t, snaps, 25, "",
		"the two units name DIFFERENT zones, so their carrier identifies no "+
			"single one. Taking either would adjudicate the trunk parent's "+
			"transit under one VLAN's policy, chosen by Go map order — a "+
			"to-zone that changes across daemon restarts on an unchanged config")
	assertEgressZone6722(t, snaps, 26, "wan", "unit 50 owns its own netdev")
	assertEgressZone6722(t, snaps, 27, "dmz", "unit 80 owns its own netdev")
}

// U: a PRESENT-BUT-NIL unit slot on a reth member does not give it an L3
// identity.
//
// `egressMemberIsBarePort` asks `hasConfiguredUnit`, which skips a nil unit
// slot — the tolerant load / HA config-sync shape of #3494/#5068, a key present
// in `ifc.Units` with a nil value. That skip decides, in the PERMISSIVE
// direction, whether such a member is still a bare port; it is the input to
// exactly the predicate cell B2 exists to bind, and nothing bound it.
//
// Counting the nil slot as a configured unit un-coheres the reference cluster's
// LAN ifindex and blackholes every WAN->LAN transit flow on it — on the peer-sync
// path, which is where nil slots come from in the first place.
func TestNilUnitSlotOnARethMemberIsNotAnL3Identity_6722(t *testing.T) {
	lines := []string{
		"set interfaces ge-0/0/1 gigether-options redundant-parent reth1",
		"set interfaces reth1 redundant-ether-options redundancy-group 2",
		"set interfaces reth1 unit 0 family inet address 10.0.61.1/24",
		"set security zones security-zone lan interfaces reth1",
	}
	links := map[string]int{"ge-0-0-1": 24}
	macs := map[string]string{"ge-0-0-1": "02:bf:72:01:00:01"}

	cfg := compileWithStubbedLinks6722(t, lines, links, macs, false)
	member := cfg.Interfaces.Interfaces["ge-0/0/1"]
	if member == nil {
		t.Fatalf("precondition: ge-0/0/1 is absent from the compiled config")
	}
	if member.Units == nil {
		member.Units = map[int]*config.InterfaceUnit{}
	}
	// The #3494/#5068 slot, injected the way every other nil-slot cell in this
	// tree injects it (pkg/grpcapi/server_sessions_nil_5813_test.go,
	// pkg/cli/cli_show_interfaces_nil_5068_test.go): a tolerantly loaded or
	// peer-synced config carries the KEY with a nil value. No `set` line
	// produces one.
	member.Units[7] = nil
	if u, ok := member.Units[7]; !ok || u != nil {
		t.Fatalf("precondition: ge-0/0/1 Units[7] present=%v nil=%v, want a "+
			"PRESENT slot holding nil", ok, u == nil)
	}
	if hasConfiguredUnit(member) {
		t.Fatalf("hasConfiguredUnit reports a configured unit on a member whose " +
			"only unit slot is nil; a nil slot is an artefact of the tolerant " +
			"load, not an operator statement, and treating it as one makes the " +
			"member an L3 identity of its own")
	}
	assertEgressZone6722(t, buildInterfaceSnapshots(cfg), 24, "lan",
		"a member carrying only a nil unit slot is still a bare L2 port, so it "+
			"coheres with reth1 and the reth's authored zone decides. Answering "+
			"\"\" blackholes every WAN->LAN transit flow on the reference cluster, "+
			"on the peer-sync path that produced the nil slot")

	// CONTROL 1 — the same config with NO nil slot. Isolates the assertion above
	// to the slot rather than to anything else in the shape.
	assertEgressZone6722(t,
		buildInterfaceSnapshots(compileWithStubbedLinks6722(t, lines, links, macs, false)),
		24, "lan", "control: without the nil slot the answer is unchanged")

	// CONTROL 2 — a REAL unit in the same slot must fail CLOSED. This is what
	// shows the cell measures the slot's NIL-ness and not merely the presence of
	// a key: a member with its own addressed unit is an independent L3 identity
	// on the shared device (cell E3), and it must keep being one.
	ctl := compileWithStubbedLinks6722(t, append(append([]string{}, lines...),
		"set interfaces ge-0/0/1 unit 7 family inet address 10.9.9.1/30"),
		links, macs, true)
	assertEgressZone6722(t, buildInterfaceSnapshots(ctl), 24, "",
		"control: a member carrying a REAL unit 7 has an L3 identity of its own "+
			"and must NOT cohere with the reth; if this also answers `lan` then "+
			"the bare-port predicate has stopped discriminating altogether")
}

// V: a PRESENT-BUT-NIL unit slot casts no vote in rule 3.
//
// The unanimity walk skips nil slots for the same reason U's does: a nil slot is
// an artefact of a tolerant load, not an operator statement. The two skips are
// separate clauses in separate functions, and this one bites where the nil slot
// happens to carry an AUTHORED zone reference — which is producible, because a
// `security-zone <z> interfaces <ifc>.<n>` reference to a unit that does not
// exist is admitted by the STRICT compiler.
//
// Deterministic in every map order: the nil slot's zone disagrees with the real
// units' zone, so counting it always collapses the carrier to "" whichever unit
// is walked first.
func TestNilUnitSlotCastsNoTrunkZoneVote_6722(t *testing.T) {
	lines := []string{
		"set interfaces ge-0/0/1 vlan-tagging",
		"set interfaces ge-0/0/1 unit 50 vlan-id 50 family inet address 172.16.50.8/24",
		"set interfaces ge-0/0/1 unit 80 vlan-id 80 family inet address 172.16.80.8/24",
		"set security zones security-zone wan interfaces ge-0/0/1.50",
		"set security zones security-zone wan interfaces ge-0/0/1.80",
		"set security zones security-zone dmz interfaces ge-0/0/1.99",
	}
	links := map[string]int{"ge-0-0-1": 25, "ge-0-0-1.50": 26, "ge-0-0-1.80": 27}
	macs := map[string]string{"ge-0-0-1": "02:bf:72:01:00:02"}

	cfg := compileWithStubbedLinks6722(t, lines, links, macs, false)
	if got := authoredZoneRefs(cfg)["ge-0/0/1.99"]; got != "dmz" {
		t.Fatalf("precondition: authoredZoneRefs[ge-0/0/1.99] = %q, want %q — the "+
			"zone reference to the not-yet-existing unit is what the nil slot "+
			"would vote with, and without it this cell asserts nothing", got, "dmz")
	}
	trunk := cfg.Interfaces.Interfaces["ge-0/0/1"]
	if trunk == nil {
		t.Fatalf("precondition: ge-0/0/1 is absent from the compiled config")
	}
	trunk.Units[99] = nil
	if u, ok := trunk.Units[99]; !ok || u != nil {
		t.Fatalf("precondition: ge-0/0/1 Units[99] present=%v nil=%v, want a "+
			"PRESENT slot holding nil", ok, u == nil)
	}
	assertEgressZone6722(t, buildInterfaceSnapshots(cfg), 25, "wan",
		"unit 99 is a present-but-nil slot from a tolerant load, not a unit the "+
			"operator configured, so it casts no vote about this carrier. "+
			"Counting it makes the stray `dmz` reference dissent against the two "+
			"real `wan` units and strips the trunk parent's zone")

	// CONTROL — the same shape with unit 99 REAL and zoned `dmz`. Then the
	// dissent is genuine and the carrier must fail closed. Without this the cell
	// above could not tell "nil slots are skipped" from "rule 3 ignores dissent".
	ctl := compileWithStubbedLinks6722(t, append(append([]string{}, lines...),
		"set interfaces ge-0/0/1 unit 99 vlan-id 99 family inet address 172.16.99.8/24"),
		map[string]int{"ge-0-0-1": 25, "ge-0-0-1.50": 26, "ge-0-0-1.80": 27, "ge-0-0-1.99": 29},
		macs, false)
	assertEgressZone6722(t, buildInterfaceSnapshots(ctl), 25, "",
		"control: with unit 99 REAL and zoned `dmz` the disagreement is a genuine "+
			"operator statement and the carrier must fail closed; if this also "+
			"answers `wan` then rule 3 has stopped hearing dissent at all")
}

// W: a bare port that names a DIFFERENT reth does not defer to this one.
//
// `egressRethMemberOf` requires the member to name the reth as its
// `gigether-options redundant-parent`. Cell C is the positive case — the authored
// dotted name `ge-0/0/1.100` IS a member of `reth1`, aliases `reth1.100`, and the
// reth unit's authored zone decides. This cell is the same config with ONE token
// changed: the dotted member names `reth2` instead. It is then a port of another
// redundant pair that merely happens to land on `reth1.100`'s netdev, the
// deference premise ("the reth owns the L3, the member is only a port of it") is
// absent, and the ifindex must fail closed.
//
// Without the parent match, ANY bare port sharing a netdev with a reth is taken
// for its member: `ge-0/0/1.100`, an interface the operator put in no zone at
// all, would have its transit adjudicated as `lan`.
func TestBarePortOfADifferentRethDoesNotDeferToThisOne_6722(t *testing.T) {
	links := map[string]int{"ge-0-0-0": 30, "ge-0-0-1": 31, "ge-0-0-1.100": 32}
	macs := map[string]string{"ge-0-0-1": "02:bf:72:01:00:01"}
	base := []string{
		"set interfaces ge-0/0/0 gigether-options redundant-parent reth2",
		"set interfaces ge-0/0/1 gigether-options redundant-parent reth1",
		"set interfaces reth1 redundant-ether-options redundancy-group 2",
		"set interfaces reth1 vlan-tagging",
		"set interfaces reth1 unit 100 vlan-id 100 family inet address 10.0.61.1/24",
		"set interfaces reth2 redundant-ether-options redundancy-group 1",
		"set interfaces reth2 unit 0 family inet address 10.0.62.1/24",
		"set security zones security-zone lan interfaces reth1.100",
	}
	foreign := append([]string{"set interfaces ge-0/0/1.100 gigether-options redundant-parent reth2"}, base...)

	cfg := compileWithStubbedLinks6722(t, foreign, links, macs, false)
	snaps := buildInterfaceSnapshots(cfg)

	dotted := snapByName6722(t, snaps, "ge-0/0/1.100")
	rethUnit := snapByName6722(t, snaps, "reth1.100")
	if dotted.Ifindex != 32 || rethUnit.Ifindex != 32 {
		t.Fatalf("precondition: ge-0/0/1.100=%d reth1.100=%d, want 32/32 — the "+
			"foreign port and the reth's VLAN unit must share ONE netdev, or "+
			"there is no deference question to answer",
			dotted.Ifindex, rethUnit.Ifindex)
	}
	if got := snapByName6722(t, snaps, "reth2").Ifindex; got == 32 {
		t.Fatalf("precondition: reth2 resolved onto ifindex 32 as well, making " +
			"THREE identities there; this cell must exercise the two-identity " +
			"deference test, not the >2 refusal")
	}
	if ifc := cfg.Interfaces.Interfaces["ge-0/0/1.100"]; ifc == nil || ifc.RedundantParent != "reth2" {
		t.Fatalf("precondition: ge-0/0/1.100 redundant-parent is not `reth2`; the " +
			"whole cell is that the port names a DIFFERENT reth")
	}
	if egressRethMemberOf(cfg, "ge-0/0/1.100", "reth1") {
		t.Errorf("egressRethMemberOf accepted ge-0/0/1.100 as a member of reth1, " +
			"which it does not name; every bare port sharing a netdev with a reth " +
			"is then taken for its member")
	}
	assertEgressZone6722(t, snaps, 32, "",
		"ge-0/0/1.100 is a port of reth2, not of reth1, so the two identities on "+
			"this netdev are independent claims and it identifies no single zone. "+
			"Answering `lan` adjudicates a foreign redundant pair's port under the "+
			"zone the operator wrote for reth1.100")

	// CONTROL — cell C's config, reached by changing the SAME line to name
	// `reth1`. One token, and the answer must flip to `lan`; that is what makes
	// the failure above specific to the parent name rather than to the aliasing.
	ctl := compileWithStubbedLinks6722(t,
		append([]string{"set interfaces ge-0/0/1.100 gigether-options redundant-parent reth1"}, base...),
		links, macs, false)
	assertEgressZone6722(t, buildInterfaceSnapshots(ctl), 32, "lan",
		"control: with the dotted port naming `reth1` it IS a member port of the "+
			"reth whose unit it aliases, the two cohere, and the authored zone "+
			"resolves; if this control also answers \"\" then the cell above is "+
			"measuring the aliasing, not the redundant-parent match")
}

// #7024: the OUTCOME half. A base/unit divergence must resolve FAIL-CLOSED.
//
// Cell P now TOLERATES a base-reference divergence, which is only defensible if
// the divergence cannot produce a wrong answer. This is the cell that shows it
// cannot: the ifindex resolves to no zone at all, so nothing forwards under a
// zone the operator did not write for it.
//
// Tolerating a divergence without pinning its outcome would be the same defect
// this issue is about, moved one step: a claim that reads as safe with nothing
// asserting the safety.
//
// Strict rejects the doubly-claimed interface, so — like cells O, P's sixth
// shape and Q — the surface this defends is the tolerant load / HA peer-sync
// path (#1960 no-brick).
func TestBaseAndUnitClaimedByDifferentZonesFailsClosed_7024(t *testing.T) {
	lines := []string{
		"set interfaces ge-0/0/1 unit 0 family inet address 10.0.1.1/24",
		"set security zones security-zone aaa interfaces ge-0/0/1.0",
		"set security zones security-zone zzz interfaces ge-0/0/1",
	}
	links := map[string]int{"ge-0-0-1": 24}
	macs := map[string]string{"ge-0-0-1": "02:bf:72:01:00:01"}

	// Pinned rather than assumed, mirroring cell Q: if strict ever admitted
	// this, "reachable only leniently" would be false and a reader would be
	// misled about which surface this defends.
	if _, err := config.CompileConfig(treeFromSet6722(t, lines)); err == nil {
		t.Fatalf("precondition: strict CompileConfig ADMITTED an interface whose " +
			"base and unit are claimed by different zones; this cell claims the " +
			"shape reaches the builder only on the tolerant path")
	}

	cfg := compileWithStubbedLinks6722(t, lines, links, macs, true)

	// The divergence itself, pinned here too so this cell fails for its OWN
	// reason if the maps are ever made to agree — rather than quietly becoming
	// a test of a shape that no longer exists.
	authored, derived := authoredZoneRefs(cfg), buildInterfaceZoneMap(cfg)
	if authored["ge-0/0/1"] != "zzz" || derived["ge-0/0/1"] != "aaa" {
		t.Fatalf("precondition: authored[ge-0/0/1]=%q derived[ge-0/0/1]=%q, want "+
			"\"zzz\" and \"aaa\" — the fan-up winner must differ from the bare "+
			"sentence, or there is no divergence here to fail closed on",
			authored["ge-0/0/1"], derived["ge-0/0/1"])
	}

	snaps := buildInterfaceSnapshots(cfg)
	assertEgressZone6722(t, snaps, 24, "",
		"the operator's sentences put `aaa` on ge-0/0/1.0 and `zzz` on ge-0/0/1, "+
			"and both land on one netdev, so it identifies no single egress zone. "+
			"Answering either one adjudicates transit under a zone the operator "+
			"did not write for that identity — and cell P now TOLERATES this "+
			"divergence, so if the outcome stops being fail-closed the tolerance "+
			"becomes a hole rather than a documented limit (#7024)")
}
