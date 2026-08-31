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
const gateCoverageFloor = 692

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
	gateBlindUnreachable: 144,
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
	gateBlindFlag:       177,
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
