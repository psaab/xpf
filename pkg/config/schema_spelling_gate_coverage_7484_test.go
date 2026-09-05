package config

import (
	"fmt"
	"sort"
	"strings"
	"testing"
)

// #7484 — COVERAGE OF THE SPELLING GATE IS ITSELF A GATED PROPERTY.
//
// TestSchemaSpellingDifferentialGate is the one gate built to find the #2419
// compact-leaf/multi-value class. It passed green while 430 of the 1049 leaves
// it enumerates carried NO verdict at all, and among those 430 sat
// `security log stream <*> transport protocol` / `tls-profile` — the exact leaf
// #6821 reports as broken. So the gate was reporting "no spelling
// inconsistencies" over a leaf where one is already filed.
//
// That is the failure shape a review cannot see: 619-compared and 1049-compared
// both render as PASS. The coverage number existed, but only as a t.Logf, and
// nothing in the suite failed when it moved. This file makes it fail.
//
// WHAT "UNCOMPARED" ACTUALLY MEANS — measured, not assumed. The differential
// needs at least two spellings to return a usable drop/keep verdict. A leaf
// falls out for one of four reasons, and they are NOT the same diagnosis:
//
//	flag         the compiler READS the leaf but no value ever moves the
//	             output — a boolean. It has no value dimension, so a
//	             two-value differential is meaningless for it. Not a defect,
//	             and not a coverage gap either.
//	unreachable  the leaf changed nothing at all: the synthetic parent stanza
//	             compiled, but the compiler discarded the container, so the
//	             leaf never reached it. THIS is the real gap.
//	err          the synthetic parent/bare stanza does not compile at all.
//	valueMoves   a value DOES move the output, yet fewer than two spellings
//	             produced a verdict — the gate lost it some other way.
//
// WHY THE CLASSIFIER IS BEHAVIOURAL AND NOT `args == 0`. The obvious shortcut
// is to drop leaves the schema declares value-less. It is wrong, and measurably
// so: of the 232 `args == 0` leaves, 15 are compared TODAY and are genuinely
// value-bearing lists — `firewall … from source-prefix-list`,
// `interfaces <*> fabric-options member-interfaces`,
// `routing-options rib-groups <*> import-rib`, `event-options policy <*> events`,
// `security ike gateway <*> local-identity`. Those leaves are under-declared in
// setSchema, not value-less. Excluding by `args` would have RETIRED 15 live
// cells to make a number look better — the exact move #7484 says not to make.
// The behavioural test cannot do that: a leaf that produces verdicts is already
// `compared` and never reaches the classifier.
//
// This is also why no leaf is allowlisted here. An allowlist row asserts a
// DEFECT exists, and for these none has been demonstrated. #6693's
// mixedChildIsAModifierBlock is the precedent: where a verdict carries no
// information, drop the verdict — do not claim a defect.

// gateBlindClass names why an enumerated leaf carries no verdict.
type gateBlindClass string

const (
	gateBlindFlag        gateBlindClass = "flag (read, but value-less)"
	gateBlindUnreachable gateBlindClass = "unreachable (leaf changed nothing)"
	gateBlindErr         gateBlindClass = "err (parent stanza does not compile)"
	gateBlindValueMoves  gateBlindClass = "valueMoves (value moves output, gate still lost it)"
)

// gateLeafCompared reports whether the differential got at least two usable
// spelling verdicts for this leaf under ANY value pair — the same condition
// TestSchemaSpellingDifferentialGate uses to count a leaf as compared.
func gateLeafCompared(g gateLeaf) bool {
	for _, vp := range gateValuePairs {
		state := spellingVerdicts(g, vp.v1, vp.v2)
		cmpSet := gateSpellingsScalar
		if g.multi {
			cmpSet = gateSpellingsMulti
		}
		usable := 0
		for _, name := range cmpSet {
			// A MISSING key is not a verdict. spellingVerdicts populates its map
			// by ranging gateSpellingsMulti, while a scalar leaf compares over
			// gateSpellingsScalar; the two are consistent today but nothing
			// enforces it, and `state[name]` for an unpopulated spelling yields
			// "" — which matches none of the discard cases and would be counted
			// as a usable verdict. Measured: removing two entries from
			// gateSpellingsMulti made coverage "rise" 619 -> 1034, because every
			// scalar leaf then scored two phantom verdicts. A missing verdict
			// reading as a passing one is the same failure shape this whole file
			// exists to close, so it is rejected explicitly rather than by
			// convention. TestGateSpellingSetsAreConsistent_7484 guards the
			// invariant itself.
			switch state[name] {
			case "keep", "drop":
				usable++
			}
		}
		if usable >= 2 {
			return true
		}
	}
	return false
}

// classifyGateBlindLeaf diagnoses an UNCOMPARED leaf. Order matters: `err`
// first because the later probes are meaningless if nothing compiles, then
// valueMoves (a value demonstrably reaching the compiler outranks any
// explanation that says it did not), then the flag/unreachable split.
func classifyGateBlindLeaf(g gateLeaf) gateBlindClass {
	// #7492: apply the same parent prerequisite the differential uses, or the
	// classifier reasons about a different config than the gate it explains —
	// a leaf the prerequisite rescued would still be reported as unreachable.
	pre, _ := gateLeafPrereq(g)
	epath := gateEffectivePath(g)
	withPre := func(stmt string) (string, error) {
		if pre != "" {
			stmt = pre + " " + stmt
		}
		return gateCompileBrace(gateBraceConfig(epath, stmt))
	}
	noLeaf, errNo := withPre("")
	bare, errBare := withPre(g.leaf + ";")
	if errNo != nil || errBare != nil {
		return gateBlindErr
	}
	for _, vp := range gateValuePairs {
		withVal, err := withPre(g.leaf + " " + vp.v1 + ";")
		if err != nil {
			continue
		}
		if withVal != bare {
			return gateBlindValueMoves
		}
	}
	// No value ever moved the output. Did the leaf reach the compiler at all?
	// If naming it bare changes the config, it did — it is a flag.
	if noLeaf != bare {
		return gateBlindFlag
	}
	return gateBlindUnreachable
}

// ---------------------------------------------------------------------------
// The ratchet.
//
// coverageFloor is a FLOOR: coverage may rise freely, and a rise is the fix
// working, not a regression — never carry a pre-fix number forward as a target.
// The per-class ceilings are CEILINGS: a blind spot may shrink freely but not
// grow. Together they mean a new schema leaf that lands COVERED costs nothing,
// while one that lands BLIND reds this test and forces a deliberate decision
// instead of silently enlarging the gap.
//
// Measured at 6b47801de. Raising a ceiling is a real decision: it says a leaf
// the #2419 class can hide in was added on purpose.
// ---------------------------------------------------------------------------
// #7448 raised this 687 -> 689. Declaring `chassis cluster fabric1-interface`
// and `fabric1-peer-address` in schemaChassis added two leaves that COMPARE —
// neither landed in a blind class, so no ceiling moved. That is the shape a
// coverage ratchet is supposed to see when a gap is closed rather than papered
// over: the floor rises and the blind spots stay put.
//
// #7132 raised it 689 -> 691. Modeling the `system ntp server` modifiers as
// schema children made `key`, `version` and `routing-instance` COMPARE (+3),
// while `prefer` moved into `flag` (+1 there, see the ceiling below) — a net
// +2 here. The gate itself asked for this: it reports a floor it can now beat
// as "COVERAGE IMPROVED — TIGHTEN THE RATCHET (this is a good failure)", and
// leaving it slack would let a later regression drop back to 689 unnoticed.
// LOWERED 705 -> 701 for the #8781-follow-up IKE identity fix. The value was
// RE-MEASURED after merging another lane's increase to 705, not arithmetically
// adjusted from the pre-merge number — the two happen to agree here (705 minus
// exactly these four leaves), and agreeing is the evidence rather than the
// method., and the cause was
// found rather than the floor moved to make a red go away — which is what the
// failure message demands.
//
// The four leaves are `local-identity` and `remote-identity` on each of the two
// `gateway` containers (security ike, security ipsec). They did not stop
// compiling; they left this gate's ENUMERABLE POPULATION, because it enumerates
// leaves of arity <= 1 and those four now correctly declare `args: 2`. The
// compiler reads two tokens after the keyword and the schema description says
// "type and value" — the arity was the thing that was wrong, and with it wrong
// a packed gateway body silently dropped the IKE identity.
//
// So this is a real trade and it is recorded as one: four leaves lose a
// spelling-gate verdict, and in exchange their packed spelling stops discarding
// an IKE peer identity. TestIKEGatewayPackedTailCarriesIdentity covers them
// directly instead, asserting the compiled struct rather than a spelling
// comparison — a narrower guard on a specific pair, not a replacement for this
// one's breadth.
//
// #8800 then raised it by one. Declaring `address` under `security nat source
// pool` -- the compiler had read it since #4521 but the schema never declared
// it, so the brace-elision pass was never asked about the pair and the packed
// spelling compiled to a ZERO-address pool -- made that spelling COMPARE.
// Every blind bucket held at its ceiling, so the new leaf is genuinely
// gate-covered rather than having moved into a blind class. The value below
// was RE-MEASURED on the merge of the two changes, not obtained by adding one
// to either side's number.
//
// Then 702 -> 703 for the DESTINATION pool half of #8800: the same leaf was
// undeclared at the sibling path, and declaring it made that spelling
// COMPARE as well. Blind held at 364 across both steps.
const gateCoverageFloor = 703

var gateBlindCeiling = map[gateBlindClass]int{
	// #7492 moved leaves out of `unreachable` in two rounds. The parent
	// prerequisite moved 13 (10 compared, 3 revealed as flags); the typed
	// path-identifier fallback then moved 72 more (58 compared, 14 revealed as
	// flags) by giving `interfaces <if> unit <n>` a NUMERIC unit instead of a
	// synthetic word. That is why the flag ceiling RISES here — the population
	// changed, and a blind-spot count going up after a fix is the fix working,
	// not a regression. Never carry a pre-fix number forward as a target.
	// #6875 raised this 143 -> 144, deliberately, for
	// `security log stream <*> source-interface`.
	//
	// Measured before raising it rather than assumed: a stream with ONLY that
	// leaf and no sibling `host` compiles to NOTHING —
	// `cfg.Security.Log.Streams["s"]` is nil — so the differential, which
	// probes one leaf at a time, sees no output change and can carry no
	// verdict. That is a property of this stanza requiring a sibling to
	// materialise, not of the leaf: EVERY existing `stream` leaf
	// (`severity`, `facility`, `category`, `source-address`) is blind here for
	// the same reason and is already inside the 143.
	//
	// So this cannot be made to compare without changing how the probe
	// constructs the parent stanza — the #7492-style fix, which is a change to
	// the gate and not to #6875. The leaf itself is covered behaviourally by
	// TestStreamSourceInterfaceCompiles_6875, its validator by
	// TestStreamSourceInterfaceIsValidated_6875, and both apply paths by the
	// daemon and CLI cells; it is blind to THIS instrument only.
	// #7492 lowered this 144 -> 137: a `security log stream <*>` parent
	// prerequisite (`host`) rescued all seven of that parent's leaves. See the
	// row in schema_spelling_differential_gate_test.go for the measurement.
	//
	// WHAT THE REMAINING 137 ACTUALLY ARE, measured rather than assumed —
	// because this number reads as a debt to pay down and a quarter of it can
	// never be paid. The 137 span 66 parents and are TWO populations, counted:
	//
	//   - DECLARED INERT — 33 leaves. The schema itself says nothing reads
	//     them, so "varying it changed nothing" is the TRUTH rather than a gap.
	//     NO prerequisite can ever rescue these; only implementing the feature
	//     would, and that is not gate work. Counted by the project's own
	//     phrasings: "not implemented" 21 (the 20 leaves under
	//     `dhcp-local-server`/`dhcpv6-local-server group <*> interface <*>`,
	//     plus `security log profile <*> category session field-extra-name`),
	//     "retired, ignored" 9 (the legacy DPDK `system dataplane` tree),
	//     "(ignored)" 1, "accepted-but-inert" 1, "accepted but not yet
	//     enforced" 1.
	//
	//   - NOT DECLARED INERT — 104 leaves, and this is an UPPER BOUND on what
	//     prereq rows could ever recover, not a count of recoverable work. The
	//     parent stanza compiles to nothing without a sibling, so the leaf
	//     varied its value against an absent object; a gateParentPrereq row
	//     fixes that, and they come in clumps — one row rescued 13 (bgp group),
	//     another 7 (security log stream). But absence of an inertness marker
	//     only proves a leaf was never DECLARED dead: a leaf nothing reads,
	//     whose description does not admit it, is silently inert and sits in
	//     this bucket looking rescuable. Treat 104 as a ceiling on the
	//     opportunity, never as a backlog.
	//
	// So do NOT read this ceiling as 137 missing tests. At least 33 are
	// correctly reported and always will be. #7492's original plan — a GENERAL
	// per-parent prerequisite synthesis — was tried and refuted by measurement:
	// it recovered 2 while one hand-written row recovered 13. The productive
	// path is hand-written rows for clumped parents in the second bucket.
	//
	// This constant is the tracker. #7492 was CLOSED rather than retitled
	// because the ratchet above enforces on every run what an open issue would
	// only describe: a new row must tighten gateCoverageFloor, and a regression
	// cannot pass. The issue's own count rotted four times (228 -> 215 -> 144
	// -> 137); a number that lives beside the code it measures cannot.
	// #8445 tightened this 137 -> 136. `firewall policer <*> then discard` was
	// in this class because reading the leaf set `ThenAction = "discard"`,
	// which is ALSO the field's default — so mutating the leaf's spelling
	// changed nothing observable and the differential could not see it.
	// Recording the AUTHORED action set (`ThenActions`) for the #8445 gate made
	// the leaf observable, so it left this class. Tightening rather than
	// leaving it loose is the point of the ratchet: the slack would otherwise
	// be room for the next regression to hide in.
	// #7971 raised this 136 -> 140, deliberately, for the four
	// `system login class <*> {allow,deny}-{commands,configuration}-regexps`
	// leaves. They are modeled SOLELY so they are refused at commit
	// (schema_login_regexps_7971.go), so both spellings of each produce the same
	// rejection and the differential can observe no difference between them.
	// That is not a gap the differential could close: a leaf whose every value
	// is refused has no output for a spelling to move. The blindness here is a
	// property of the leaf's purpose, not slack — and if the `-regexps` family
	// is ever implemented, these four must LEAVE this class and the ceiling must
	// come back down by four.
	// #8443 raised this 140 -> 142, deliberately, for the two
	// `protocols ospf ... interface <*> authentication-type` leaves (top-level
	// and the routing-instances copy). Like the #7971 `-regexps` family above,
	// they are modeled SOLELY so they are refused at commit
	// (schema_ospf_authentication_8443.go) — OSPF has no such leaf, and leaving
	// it unmodeled meant it committed clean and left the adjacency
	// UNAUTHENTICATED. Both spellings of a refused leaf produce the same
	// rejection, so the differential can observe no difference between them.
	// Not a gap it could close: a leaf whose every value is refused has no
	// output for a spelling to move. If OSPF ever gains a real
	// `authentication-type`, these two must LEAVE this class and the ceiling
	// must come back down by two.
	// 142 -> 141 (#8768): declaring `args: 2` on the IKE policy
	// `pre-shared-key` leaf — the shape its description and compileIPsec always
	// stated — moved it out of the unreachable class. The ratchet is tightened
	// here rather than left loose, per this cell's own instruction.
	gateBlindUnreachable: 141,
	// #7132 raised this 175 -> 176 for `system ntp server ... prefer`.
	//
	// Raised deliberately, and it is the one kind of raise that is not a
	// concession: this class is "read, but value-less", and the spelling
	// differential works by VARYING a leaf's value. Junos `prefer` takes no
	// argument, so it has no value to vary — it cannot be made to compare by
	// any change to the gate or to the schema, the way a #7492-style
	// parent-stanza fix can rescue an `unreachable` leaf. It is in this class
	// by construction, not by omission.
	//
	// It is not untested: both spellings of `prefer` are pinned by the #7132
	// cells, which is also how its compact-spelling blindness was found. That
	// blindness was invisible to TestCompactBlockEquivalenceInventory2419 for
	// exactly the reason it is invisible here — that gate detects "the compact
	// spelling drops the VALUE", and a value-less flag has none to drop.
	//
	// #7441 raised this 176 -> 177 for `chassis cluster strict-session-auth`,
	// on the SAME reasoning and not as a concession. The leaf is a valueless
	// flag — like `control-link-recovery`, `hitless-restart` and every other
	// `chassis cluster` flag already inside this number, four of which the
	// failure message samples — so the spelling differential, which works by
	// VARYING a leaf's value, has nothing to vary. No change to the gate or to
	// the schema can rescue it; it is in this class by construction.
	//
	// It is not untested. Both spellings compile
	// (TestStrictSessionAuthCompiles7441, which asserts presence AND absence),
	// the packed-line splitter knows its arity
	// (TestClusterSplitterAndSchemaAgree_6672 / #6672 — that gate is what
	// catches a valueless flag folding onto its neighbour, which is the actual
	// hazard for this shape), the config-mode grammar offers it
	// (TestStrictSessionAuthIsInTheSetSchema7441), and the strict/tolerant
	// split is pinned by its own two cells.
	// #8445 raised this 177 -> 178, and it is the SAME leaf as the -1 above,
	// not a new blind spot: `firewall policer <*> then discard` moved out of
	// "unreachable" and into this class. It is a value-less flag, so the
	// spelling differential — which works by VARYING a leaf's value — has
	// nothing to vary, exactly like the `chassis cluster` flags this number
	// already holds. No change to the gate or the schema can rescue it.
	//
	// It is not untested: both orders of the conflicting `then` are rejected at
	// `configstore.CheckText` and every valid form still commits
	// (policer_then_conflict_8445_test.go), and the compiled ThenAction /
	// ThenActions are asserted directly on the tolerant path.
	//
	// #8296 raises this 178 -> 179 for `security flow tcp-session
	// strict-syn-check`. Same shape and the same unrescuable reason: it is a
	// PRESENCE-only flag, so the spelling differential — which works by VARYING
	// a leaf's value — has nothing to vary. Modelling it as anything else would
	// misrepresent the Junos grammar to buy a gate reading.
	//
	// It is not untested, and #8296 is precisely the change that made it
	// testable: before it the keyword was in no schema, read by no compiler and
	// named by no advisory, so there was nothing to assert. Now
	// `flow_session_closed_world_8296_test.go` asserts it reaches the typed
	// config AND produces its accepted-only advisory, and it is a member of the
	// accept-side keyword corpus that guards the tcp-session closed-world flip
	// against false-rejecting it.
	gateBlindFlag:       179,
	gateBlindErr:        43,
	gateBlindValueMoves: 1,
}

func TestSchemaSpellingGateCoverageIsGated_7484(t *testing.T) {
	leaves := enumerateGateLeaves()
	compared := 0
	blind := map[gateBlindClass]int{}
	sample := map[gateBlindClass][]string{}

	for _, g := range leaves {
		if gateLeafCompared(g) {
			compared++
			continue
		}
		c := classifyGateBlindLeaf(g)
		blind[c]++
		if len(sample[c]) < 4 {
			sample[c] = append(sample[c], g.siteKey())
		}
	}

	classes := []gateBlindClass{gateBlindUnreachable, gateBlindFlag, gateBlindErr, gateBlindValueMoves}
	total := 0
	for _, c := range classes {
		total += blind[c]
	}
	t.Logf("COVERAGE: %d enumerated, %d compared, %d blind", len(leaves), compared, total)
	for _, c := range classes {
		t.Logf("    %-52s %4d  (ceiling %d)", c, blind[c], gateBlindCeiling[c])
		for _, s := range sample[c] {
			t.Logf("          e.g. %s", s)
		}
	}

	if compared < gateCoverageFloor {
		t.Errorf("SPELLING-GATE COVERAGE REGRESSED: %d leaves compared, floor is %d.\n"+
			"  %d fewer leaves now carry a verdict, so the #2419 class has that much\n"+
			"  more room to hide — and TestSchemaSpellingDifferentialGate still passes\n"+
			"  green, because a leaf with no verdict cannot fail it. Find what stopped\n"+
			"  compiling rather than lowering this floor.",
			compared, gateCoverageFloor, gateCoverageFloor-compared)
	}
	for _, c := range classes {
		if blind[c] > gateBlindCeiling[c] {
			t.Errorf("BLIND SPOT GREW: class %q is %d, ceiling %d (+%d).\n"+
				"  Leaves in this class carry NO verdict from the spelling differential.\n"+
				"  Sample: %v\n"+
				"  Either make them compare, or raise the ceiling DELIBERATELY and say why.",
				c, blind[c], gateBlindCeiling[c], blind[c]-gateBlindCeiling[c], sample[c])
		}
	}

	// The other direction. A ceiling nobody lowers rots into a rubber stamp, so
	// an IMPROVEMENT is reported as a failing instruction to tighten it. This is
	// not "coverage got worse" — it is the ratchet advancing, and the fix is one
	// line.
	var slack []string
	for _, c := range classes {
		if blind[c] < gateBlindCeiling[c] {
			slack = append(slack, fmt.Sprintf("%s: %d -> %d", c, gateBlindCeiling[c], blind[c]))
		}
	}
	if compared > gateCoverageFloor {
		slack = append(slack, fmt.Sprintf("gateCoverageFloor: %d -> %d", gateCoverageFloor, compared))
	}
	sort.Strings(slack)
	if len(slack) > 0 {
		t.Errorf("COVERAGE IMPROVED — TIGHTEN THE RATCHET (this is a good failure):\n  %v\n"+
			"  Update the constants in this file to the measured values. Leaving them\n"+
			"  loose means the next regression has that much room to hide before it reds.",
			slack)
	}
}

// TestGateSpellingSetsAreConsistent_7484 pins the invariant the helper above
// defends against: every spelling a comparison set names must actually be
// produced by spellingVerdicts, which builds its map by ranging
// gateSpellingsMulti. If someone edits one list and not the other, the
// differential silently starts scoring phantom verdicts instead of failing.
func TestGateSpellingSetsAreConsistent_7484(t *testing.T) {
	produced := map[string]bool{}
	for _, n := range gateSpellingsMulti {
		produced[n] = true
	}
	for _, n := range gateSpellingsScalar {
		if !produced[n] {
			t.Errorf("gateSpellingsScalar names %q, which spellingVerdicts never populates "+
				"(it ranges gateSpellingsMulti). Every leaf comparing over that set would "+
				"score a PHANTOM verdict for it: state[%q] is \"\", which is neither "+
				"err/unstable/inert nor a real keep/drop.", n, n)
		}
	}
	// The differential must have something to compare, in both sets.
	if len(gateSpellingsScalar) < 2 || len(gateSpellingsMulti) < 2 {
		t.Errorf("a differential needs at least two spellings per set; got scalar=%d multi=%d",
			len(gateSpellingsScalar), len(gateSpellingsMulti))
	}
}

// TestZeroArgLeavesCanStillBeValueBearing_7484 pins the measurement that decided
// the classifier's shape, so it cannot quietly stop being true.
//
// The tempting shortcut for raising coverage is to exclude leaves the schema
// declares value-less (`args == 0`) from the enumeration. This test exists to
// make that shortcut fail loudly: some `args == 0` leaves produce real spelling
// verdicts TODAY, which means they carry values the schema simply does not
// declare — `firewall ... from source-prefix-list`,
// `interfaces <*> fabric-options member-interfaces`,
// `routing-options rib-groups <*> import-rib` and friends. Excluding by `args`
// would retire those live cells, which is the one thing #7484 says not to do.
//
// Asserted as "at least one witness" rather than an exact count: the property is
// `args == 0` does not imply value-less, and one witness settles it. Pinning the
// count would red on every unrelated schema addition and get deleted.
func TestZeroArgLeavesCanStillBeValueBearing_7484(t *testing.T) {
	var zeroArgs int
	var witnesses []string
	for _, g := range enumerateGateLeaves() {
		if g.args != 0 {
			continue
		}
		zeroArgs++
		if gateLeafCompared(g) && len(witnesses) < 6 {
			witnesses = append(witnesses, g.siteKey())
		}
	}
	t.Logf("args==0 leaves enumerated: %d; witnesses that ARE compared: %v", zeroArgs, witnesses)
	if len(witnesses) == 0 {
		t.Errorf("no `args == 0` leaf produced a spelling verdict.\n"+
			"  Either the schema now declares every value-bearing leaf correctly — in which\n"+
			"  case say so and this test can go — or the enumeration/classifier stopped\n"+
			"  reaching them. Do NOT respond by excluding args==0 leaves from coverage:\n"+
			"  that is what this test exists to prevent (%d such leaves are enumerated).",
			zeroArgs)
	}
}

// TestGateParentPrereqRefusesToAuthorTheLeafUnderTest_7492 binds the guard in
// gateLeafPrereq, which no table row currently exercises — the one shipped row
// names `neighbor`, a container, and containers are never enumerated as leaves.
// An unexercised guard is a claim, and a claim owes a test: without this, the
// refusal could be deleted and nothing would notice until a future row happened
// to collide, at which point the prerequisite would author the very value it
// exists to make observable and the leaf would compare against itself.
func TestGateParentPrereqRefusesToAuthorTheLeafUnderTest_7492(t *testing.T) {
	const key = "zzq-7492-synthetic-parent"
	gateParentPrereq[key] = "collide 10.211.199.1; other 7;"
	defer delete(gateParentPrereq, key)

	// A leaf whose name collides with the prerequisite's first statement.
	collide := gateLeaf{path: []string{key}, leaf: "collide"}
	if body, sets := gateLeafPrereq(collide); body != "" || sets != nil {
		t.Errorf("prerequisite was applied to the leaf it names: body=%q sets=%v.\n"+
			"  The row would author `collide`, so the zero/one/two configs would all\n"+
			"  already contain a value for the leaf under test and the differential\n"+
			"  would be comparing the leaf against itself.", body, sets)
	}
	// A non-colliding leaf under the same parent still gets it.
	fine := gateLeaf{path: []string{key}, leaf: "somethingelse"}
	body, sets := gateLeafPrereq(fine)
	if body == "" || len(sets) != 2 {
		t.Errorf("a non-colliding leaf must still receive the prerequisite; got body=%q sets=%v", body, sets)
	}
	for _, cmd := range sets {
		if !strings.HasPrefix(cmd, "set "+key+" ") {
			t.Errorf("set-spelling prerequisite must be rooted at the PARENT path, got %q", cmd)
		}
	}
}
