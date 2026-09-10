package config

import (
	"encoding/json"
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
	// #8830: the leaf IS read and its value is DELIBERATELY ignored, with an
	// advisory saying so -- `system dataplane cores` compiles to "retired
	// DPDK-era knob (#1525), accepted for config compatibility but ignored".
	// That is the LOUD form of dropping a value and it is #8785's documented
	// remedy shape ("read it AND say it does nothing"), so it must not sit in
	// `unreachable`, which asserts the leaf changed NOTHING.
	gateBlindAdvisory gateBlindClass = "advisory (read, value ignored, warning says so)"
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
	// #8830: everything above compared through gateMarshal, which NULLS
	// cfg.Warnings. That normalisation is correct for the DIFFERENTIAL -- an
	// advisory about a rejected value would make it look installed when
	// comparing two spellings -- but this classifier asks a different question,
	// "did the leaf reach the compiler at all", and for THAT an advisory is
	// evidence that it did. The same channel is signal for one question and
	// noise for the other, so the helper's normalisation encodes the
	// differential's question and inheriting it here answered the wrong one.
	//
	// Re-scored with warnings included, 7 of the 141 leaves this branch used to
	// return DO change output. They are read and deliberately ignored.
	if gateLeafChangesWarnings(g, pre, epath) {
		return gateBlindAdvisory
	}
	return gateBlindUnreachable
}

// gateLeafChangesWarnings repeats the classifier's probe with cfg.Warnings
// KEPT, and reports whether naming the leaf (bare or with a value) changes the
// advisory output. It is deliberately separate from gateMarshal rather than a
// flag on it: the differential must keep nulling warnings, and a shared helper
// that sometimes does and sometimes does not is how this mismatch happened.
func gateLeafChangesWarnings(g gateLeaf, pre string, epath []string) bool {
	compile := func(stmt string) (string, bool) {
		if pre != "" && stmt != "" {
			stmt = pre + " " + stmt
		} else if pre != "" {
			stmt = pre
		}
		tree, errs := NewParser(gateBraceConfig(epath, stmt)).Parse()
		if len(errs) > 0 {
			return "", false
		}
		cfg, err := CompileConfigLenient(tree)
		if err != nil {
			return "", false
		}
		j, merr := json.Marshal(cfg.Warnings)
		if merr != nil {
			return "", false
		}
		return string(j), true
	}
	base, ok := compile("")
	if !ok {
		return false
	}
	if w, ok := compile(g.leaf + ";"); ok && w != base {
		return true
	}
	for _, vp := range gateValuePairs {
		if w, ok := compile(g.leaf + " " + vp.v1 + ";"); ok && w != base {
			return true
		}
	}
	return false
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
// 702 -> 703 for the destination-pool half of #8800. Declaring `address`
// under the destination NAT pool made that spelling COMPARE as well; blind
// held at 364, so the leaf is genuinely gate-covered rather than having
// moved into a blind class. Re-MEASURED at this head, not derived by adding
// one to the source-pool number.
//
// 703 -> 705 for #8825: declaring `application` and `application-set` under
// `applications application-set` made those two spellings COMPARE. Blind is
// unchanged BY THIS CHANGE at 393 -- the earlier 364 -> 393 rise was the
// `flag` ceiling going 179 -> 209 for the #8807 `then` fix, not this one, and
// all three buckets sit exactly at their ceilings (141 + 209 + 43 = 393).
// Re-measured at this head rather than derived by adding two.
//
// 705 -> 706 for #8844. Declaring `keys` under `perfect-forward-secrecy`
// made that spelling COMPARE, and the parent left the enumeration in the
// same move: it was a childless leaf and now has a child, so `unreachable`
// drops 141 -> 140 (see the ceiling below). Both deltas are from this one
// change -- ATTRIBUTED, not assumed: the only schema edit on this branch is
// the #8844 declaration, and enumerated is unchanged at 1098.
// issue 8939 moves it 706 -> 692, a NET LOSS of 14 compared sites, and drops
// the flag ceiling 209 -> 201. TRACKED AT ISSUE 8971 -- the drop is owed, not
// justified: a floor that falls with a paragraph attached is absorbed, one that
// falls with an open issue naming the sites is not.
//
// The sequence, because the middle step is counter-intuitive: `packedStatements`
// on the two filter-term `then` nodes moved eight leaves OUT of the
// value-less-flag blind bucket and made them comparable for the first time;
// once comparable, 22 sites reported a #2419 shape-dependent drop; registering
// them in notAValueList -- which this gate's own text prescribes for a leaf
// that is not a list in any spelling -- removed them from enumeration.
//
// MEASURED, because the first reading was wrong: the divergence is PRE-EXISTING,
// not introduced. `then { count c1 c2; }` and `then count c1 c2;` compile
// IDENTICALLY, before and after the opt-in. The change exposed a divergence
// among other spellings; it did not cause one.
// ATTRIBUTED, not assumed: `packedStatements` on the two filter-term `then`
// nodes means a run written on one line now SPLITS, so eight actions that were
// previously unreachable to this gate -- they sat unsplit on the node's Keys
// and read as value-less flags -- are now compared. `enumerated` is unchanged
// at 1098, which is what says the movement is spelling coverage rather than a
// change in the population.
// #9323 raises it 715 -> 716. Declaring `interface-routes` directly under the
// routing-instance wildcard made ONE more spelling comparable: the #2226
// rib-group contract writes `set routing-instances <ri> interface-routes
// rib-group inet <g>` and the compiler has always read it, but with no schema
// declaration the walker found nothing under the container that could change
// output. Declaring it changed no compiler behaviour — it made an already-read
// leaf VISIBLE to the enumeration, the same movement #9151 recorded.
// #9351 raises it 716 -> 742. `routing-instances <n> protocols` stopped being a
// second, drifted DECLARATION of the `protocols` grammar and became the GLOBAL
// node, shared by pointer. That made 101 previously-undeclared per-instance
// schema paths reachable, and 26 of the leaves under them now COMPARE.
//
// ATTRIBUTED, not assumed: `origin/master` at this branch point runs this cell
// GREEN, and the only schema edit on this branch is the shared-node swap.
// The movement is spelling coverage, not new compiler behaviour — the
// routing-instance compiler has always called the same compileProtocols; the
// leaves were simply unreachable to a flat-set walk that had nothing to descend
// into, so their tokens packed onto the container key. Same movement as #9323
// and #9151: an already-read leaf becoming VISIBLE to the enumeration.
// #9416 raises it 742 -> 743. Declaring `snmp community <c> routing-instance
// <ri>` — the per-routing-instance spelling of the SNMP source restriction —
// made its `clients` leaf COMPARABLE, and it lands in the compared bucket, not
// a blind one. The two other leaves this change declares (`snmp client-list`
// and `client-list-name`) are registered in notAValueList and are therefore
// excluded from the enumeration rather than added to it, which is why the floor
// moves by ONE and not by three.
//
// This IS new compiler behaviour, unlike #9323/#9351 which only made
// already-read leaves visible: before #9416 that restriction compiled to
// nothing and the community was answerable from every source. The floor moving
// is a side effect of fixing it, not the point of the change.
// #9235 LOWERS it 743 -> 740, and a lowering needs a stronger argument than a
// raise, so here it is.
//
// The three `security flow aging` thresholds (early-ageout, high-watermark,
// low-watermark) are registered in notAValueList by #9235 and are therefore
// EXCLUDED from the enumeration rather than added to it — the same mechanism the
// #9416 paragraph above records for `snmp client-list` and `client-list-name`,
// which is why that change moved the floor by one and not by three.
//
// THE COVERAGE LOST IS NOT A HIDING PLACE, which is the part that distinguishes
// this from the regression this floor exists to catch. That regression is a leaf
// that STOPPED COMPILING: it could still exhibit the #2419 class and now carries
// no verdict, so the class has more room to hide. These three cannot exhibit it
// at all. The class is "a two-element LIST authored in one spelling compiles
// differently from the same list in another", and each of these leaves is
// `args: 1` with a `smallint` value pair — there is no list. Measured rather than
// argued from the arity, as notAValueList's contract requires:
//
//	aging { early-ageout 10 20; }      early=10   20 DISCARDED
//	aging { early-ageout [ 10 20 ]; }  early=10   20 DISCARDED
//	aging { early-ageout { 10; 20; } } early=0    block form not read at all
//
// and the typed schema walk REJECTS every one of those spellings, so no operator
// can author a two-element list here in the first place.
//
// They became comparable at all only because #9235 taught compileFlow to expand
// `aging`'s flat run — before it, the run sat unsplit on the container's Keys and
// the enumeration could not reach the individual leaves. So the floor is
// returning to a population that never included them, rather than shrinking past
// one that did. Identical in shape to the #8939 registration recorded in
// notAValueList, which cost 14 sites (1098/706 -> 1076/692) for the same reason.
const gateCoverageFloor = 740

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
	// Both #8844 and #8830 moved this bucket, in DIFFERENT ways, and the value
	// below is RE-MEASURED at the merge rather than reconciled from the two.
	//
	//   #8844 (already on master) 141 -> 140. A real SHRINK, not a
	//   reclassification: `perfect-forward-secrecy` was a CHILDLESS leaf
	//   whose value genuinely landed nowhere, because the compiler reads a
	//   `keys` CHILD. Declaring that child moved the parent out of the leaf
	//   enumeration and put `keys` in as COMPARED. The tree got less blind.
	//
	//   #8830 (this branch) moves SEVEN leaves to `advisory` -- they DO
	//   change output, via a warning the classifier could not see while it
	//   compared through gateMarshal. A pure reclassification: nothing about
	//   those leaves changed, the measurement did.
	//
	// PREDICTED BEFORE MEASURING, so the number is falsifiable rather than
	// confirmatory: `perfect-forward-secrecy` is NOT one of the seven, so
	// the two changes are disjoint and 140 - 7 = 133 was expected.
	//
	//   #9151 moves ONE leaf out of `unreachable`, 133 -> 132. The schema
	//   now declares `protocols rip group { neighbor, export }`, which
	//   compiler_protocols.go was already reading. Before the declaration
	//   the container had NO declared children, so the spelling walker
	//   found nothing under it that could change output and the site
	//   counted as unreachable. Declaring the children did not change any
	//   compiler behaviour -- it made an already-read leaf VISIBLE to the
	//   enumeration. A leaf leaving `unreachable` for `compared` is the
	//   good direction, and it is why gateCoverageFloor rises 692 -> 694
	//   in the same change: two new spellings became comparable.
	//   #9323 raises it 132 -> 137, DELIBERATELY, and the five are named
	//   because a ceiling raised without them is just slack. Four are the
	//   routing-instance keywords the compiler admits and compiles to no
	//   field — `vrf-target`, `vrf-table-label`, `route-distinguisher` and
	//   (for the spelling differential's purposes) `description`; they are
	//   declared so the #9323 gate's permitted set, which is read from the
	//   schema, does not reject configuration the compiler accepts. An
	//   accepted-and-inert leaf CANNOT change output by construction, so the
	//   differential can never move it out of `unreachable` — that is a
	//   property of the leaf, not a gap in the instrument. The fifth is the
	//   `interface-routes` container itself, whose comparable child moved the
	//   floor above.
	// #9351: 137 -> 153, a NET +16 that is +17 and -1. MEASURED by diffing this
	// cell's own classification against origin/master rather than inferred from
	// the totals: all 17 arrivals are `routing-instances <*> protocols bgp
	// group <*> <leaf>` — the GROUP level, not the neighbour level, whose 14
	// leaves went straight to COMPARED. A group-level leaf probed ALONE changes
	// no output because a group with no neighbour materialises nothing, which
	// is the same "stanza needs a sibling" shape this ceiling already records
	// for `security log stream <*> source-interface`.
	//
	// The one DEPARTURE is `routing-instances <*> protocols bgp group` itself:
	// it was a childless leaf and now has children, so it left the enumeration
	// exactly as `perfect-forward-secrecy` did in the #8844 note above.
	//
	// ATTRIBUTED: origin/master runs this cell green at the branch point and
	// the only schema edit on this branch is the shared-node swap.
	// #9414: 153 -> 138, a pure RECLASSIFICATION of fifteen leaves into
	// `advisory` (named at that ceiling), not a shrink: nothing about the leaves
	// changed, the measurement did -- they now change output through the #9414
	// advisory, the #8830 shape. ATTRIBUTED: origin/master ran this cell green
	// at the branch point, and #9414 is the only change on the branch touching
	// pkg/config. The `structured-data brief` leaves stay here: the advisory
	// names `structured-data` whether or not `brief` is present, so `brief`
	// still changes nothing.
	gateBlindUnreachable: 138,
	// #8830: read, value deliberately ignored, advisory says so. Measured at
	// this head: vrrp-group track-interface priority-cost (inet and inet6),
	// security log stream transport tls-profile, system dataplane
	// cores/memory/socket-mem, system services ssh rate-limit. This is a
	// CEILING like the others -- it may shrink freely, and it shrinks when a
	// knob stops being ignored, which is a real implementation landing.
	// #9414 raises this 7 -> 22, DELIBERATELY, and names the fifteen because a
	// raise without them is slack: `system syslog file <*>` allow-duplicates,
	// explicit-priority, match, match-strings; `system syslog host <*>`
	// exclude-hostname, explicit-priority, facility-override, log-prefix, match,
	// match-strings, routing-instance; `system syslog user <*>`
	// allow-duplicates, explicit-priority, match, match-strings. Each is read and
	// deliberately not applied, and its advisory says so: the same definition as
	// the seven above. The blind TOTAL did not move (427); these left
	// `unreachable`, where they were silent. They leave THIS class only when a
	// modifier is actually implemented.
	gateBlindAdvisory: 22,
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
	// RAISED 179 -> 209 for the #8807-followup completion fix, DELIBERATELY and
	// with the reason, which is what this cell asks for rather than a silent
	// bump. The 30 new members are the `reject` message types (14 per address
	// family) and the two policy-statement default actions, declared as children
	// so `then reject <TAB>` and `policy-statement <p> then <TAB>` offer what the
	// compiler already accepts.
	//
	// They are enum VALUES modelled as child keywords, not configuration leaves
	// of their own. This class means "read, but value-less", and for these the
	// value-lessness is the whole nature of the thing: `tcp-reset` IS the value.
	// There is no second spelling of it for a differential to compare, so they
	// can never leave this class however the gate improves — unlike the other
	// 179, where "make them compare" is a real option.
	//
	// The alternative was declaring `reject` as args:1 with an enum validator,
	// which adds no leaves. Measured: it preserves every compiled spelling but
	// completion still offers only <[Enter]>, so it does not fix the defect. The
	// children form was chosen on that measurement rather than on which number
	// it moves.
	// #9351: 217 -> 224. MEASURED, not inferred — the seven arrivals are
	// `routing-instances <*> protocols bgp` {log-updown, multipath ibgp,
	// multipath multiple-as} and `... group <*> neighbour <*>`
	// {default-originate, passive, remove-private, route-reflector-client}.
	// Every one is a value-less flag under the newly shared subtree, which is
	// what this class is for; none of them is a leaf whose value could be lost.
	gateBlindFlag: 224, // 209 -> 201, issue 8939; coverage cost tracked at issue 8971
	gateBlindErr:  43,
	// TIGHTENED 1 -> 0. The single member of this class was
	// `policy-options policy-statement <*> then`, and it is gone because the
	// schema now declares that node's children instead of calling it a bare
	// leaf. Its value always moved the output — compiler_routing.go iterates
	// those children for the policy-level default action — while fewer than two
	// spellings were comparable, which is exactly what this class is for.
	//
	// A ZERO CEILING HERE IS A CLAIM, not an absence: it says no leaf remains
	// whose value demonstrably reaches the compiler while the gate cannot
	// compare its spellings. If a new one appears this reds, which is the point.
	gateBlindValueMoves: 0,
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

	// gateBlindAdvisory must be in this list. A class that is classified but not
	// ENUMERATED vanishes from the blind total and from the per-class report,
	// which is strictly worse than sitting in the wrong bucket: seven leaves
	// simply stopped being counted, and the test still passed because every
	// remaining bucket was at its ceiling.
	classes := []gateBlindClass{gateBlindUnreachable, gateBlindAdvisory, gateBlindFlag, gateBlindErr, gateBlindValueMoves}
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
