package config

import (
	"sort"
	"strings"
	"testing"
)

// A COUNTED RATCHET over pairs that are admitted to the brace-elision scope but
// whose container CANNOT SPLIT a multi-statement packed run.
//
// ON THE NUMBER IN THIS FILE'S NAME: 8880 was picked before issue #8880 existed
// and it turned out to name one MEMBER of this population, not the population.
// That was luck, so the attributions are spelled out rather than left implied:
//
//	#8880   policies from-zone -- the TRUNCATION member below
//	#8883   system name-server -- the INJECTION member below
//	(none)  this ratchet itself has no issue; it is the class those two
//	        instantiate, and the count is what makes the class visible
//
// Both members are asserted here directly, so if either issue is fixed this
// cell reds and says which one and in which direction.
//
// THERE ARE TWO FAILURE MODES AND THEY SPLIT ON THIS PREDICATE'S OWN
// DISJUNCTION, which is why `multi || args >= N` is not one population wearing
// two hats:
//
//	multi leaves      INJECTION -- the repeated statement's KEYWORD is absorbed
//	                  as a list value, so the packed arm has MORE members than
//	                  the braced one, one of them a phantom named after the
//	                  keyword.
//	args >= 2 keys    TRUNCATION -- later instances are simply lost, so the
//	                  packed arm has FEWER.
//
// A CELL THAT COMPARES LENGTHS SCORES INJECTION AS INCREASED COVERAGE. "3 vs 2"
// reads as a gain until you print the members and see that one of the three is
// a phantom. Every comparison here is on rendered CONTENTS for that reason.
//
// SEVERITY IS NOT A PROPERTY OF THE MODE. Injection is SILENT in a NAT pool and
// in the resolver list, REJECTED for a WireGuard peer, and WARNED for an
// address-set. Whether the operator hears about it depends entirely on whether
// some unrelated downstream validator happens to trip over the phantom, so the
// gate verdict has to be measured per pair and cannot be inferred from the mode.
//
// A `STRICT-REJECTS` VERDICT ONLY MEANS "HANDLED" IF THE BRACED ARM WAS
// ACCEPTED. A fixture whose braced arm also fails makes the packed rejection
// evidence of nothing -- the liveness rule pointed at reject verdicts rather
// than at equality ones. Each member below asserts its braced reference first.
//
// THE DEFECT CLASS, with a live member measured at this base:
//
//	system { name-server 1.1.1.1 name-server 8.8.8.8; }
//	  packed  1.1.1.1 | name-server | 8.8.8.8
//	  braced  1.1.1.1 | 8.8.8.8
//
// The second statement is not merely lost. The multi leaf absorbs the following
// statement's KEYWORD as one of its own values, so the box ends up with a
// resolver literally named `name-server`. A dropped entry breaks whatever
// referenced it and somebody notices; a garbage entry sits in the list.
//
// WHY A RATCHET RATHER THAN 462 ADJUDICATIONS. Landing the count is what makes
// the population's GROWTH visible on the commit that causes it. The #8850
// address-book fix was partial for hours precisely because nothing counted this
// class: the scope entry was added, the container could not split, and the only
// signal was a two-entry fixture nobody had written yet.
//
// THIS IS NOT #8876, AND CONFLATING THEM MAKES BOTH UNFALSIFIABLE.
//
//	#8876   the container's PARENT EDGE is missing, so the container is never
//	        created at all (163 missing edges, 32 load-bearing)
//	here    the container IS reachable and IS admitted, and folds a
//	        multi-statement run into ONE
//
// A row that drifts between them is evidence for neither.
//
// THE NUMBER IS AN OVER-APPROXIMATION AND THE CEILING IS NOT MEASURED IN EITHER
// DIRECTION. A pair is only actually broken if a multi-statement packed run
// REACHES that container in a config someone writes, which this census does not
// model; some leaf-lists are also correct not to split. And the threshold below
// is itself a judgement -- see the two counts.
//
// STATE THE INSTRUMENT, NOT JUST THE BASE. Both 95 and 462 are true at the same
// commit; what separates them is the predicate and the traversal. A bare "N at
// master <sha>" does not identify which number you measured, and the walk here
// descends into `wildcard` nodes -- an earlier version did not, and silently
// missed ("peer","allowed-ips"), a WireGuard peer's CIDR list reachable only
// through an instance slot.
// The bool value is whether the leaf is `multi`, recorded AT THE NODE THAT
// QUALIFIED. Looking it up afterwards by (keyword, leaf) is ambiguous -- the
// same pair is reachable by several schema paths, and a first-match walk
// attributed the wrong node, giving 87 where the in-walk count gives 89.
func unsplittablePairs8880(minArgs int) (map[string]bool, map[string]bool) {
	uniq := map[string]bool{}
	conflict := map[string]bool{}
	seen := map[string]bool{}
	var walk func(path, kw string, n *schemaNode)
	walk = func(path, kw string, n *schemaNode) {
		if n == nil || seen[path] {
			return
		}
		seen[path] = true
		for name, c := range n.children {
			if c == nil {
				continue
			}
			// Admitted to the brace-elision scope, container cannot split a
			// packed run, leaf carries a value that a second statement would
			// collide with.
			if kw != "" && compactNormalizeInScope(kw, name) &&
				!n.packedStatements && (c.multi || c.args >= minArgs) {
				key := kw + " " + name
				if was, seenBefore := uniq[key]; seenBefore && was != c.multi {
					// LAST-WRITE-WINS HERE IS NON-DETERMINISTIC: Go randomises map
					// iteration, so which path writes last varies per run. The
					// pair COUNT is unaffected (the key is the same either way),
					// but any per-pair property read off it drifts -- measured, a
					// multi/non-multi split reported 87 then 93 on one unchanged
					// tree. Conflicting pairs are excluded from the split rather
					// than resolved arbitrarily.
					conflict[key] = true
				}
				uniq[key] = c.multi
			}
			walk(path+"/"+name, name, c)
		}
		// An instance slot keeps the PARENT's keyword: a wildcard is a name, not
		// a container keyword.
		if n.wildcard != nil {
			walk(path+"/*", kw, n.wildcard)
		}
	}
	for k, c := range setSchema.children {
		walk(k, k, c)
	}
	return uniq, conflict
}

func TestUnsplittablePairRatchet8880(t *testing.T) {
	// Measured at master 2a4796a72, twice, with the counts asserted equal.
	//
	// TWO THRESHOLDS, BOTH ASSERTED, because picking one silently would hide the
	// judgement. `args >= 2` was the original predicate. `args >= 1` is the one
	// the analogous #8768 population had to be widened to after an
	// `args == 1 && !multi` leaf (`address-set`) was found losing its second
	// instance live -- the argument that a fixed-arity leaf's "boundary is not
	// in question" answered a narrower question than the comparison asks.
	//
	// Both move together under an ordinary scope widening; they diverge when
	// something changes the arity model.
	// #8925 args2 95 -> 96 and args1 460 -> 461 (both move together, as this
	// cell predicts for an ordinary widening -- `as-path` is args: 2 so it
	// enters both populations). The GROWTH is deliberate, attributed and
	// strictly an improvement -- read the measurement before treating it as a
	// regression signal.
	//
	// `policy-options as-path` was admitted to the elision scope in the same
	// change. Measured, for a config carrying TWO as-path entries:
	//
	//	braced                             before 2   after 2
	//	elided, two separate statements    before 0   after 2   <- fixed
	//	elided, both in ONE packed run     before 0   after 1   <- partial
	//
	// So the pair joins this population because it is now REACHABLE at all.
	// Before the admission the whole stanza was dropped and the run yielded
	// nothing; it now yields the first of two. That is a smaller loss than the
	// one it replaced, not a new one.
	//
	// THE BETTER REMEDY WAS TRIED AND REJECTED ON EVIDENCE. Adding
	// `packedStatements: true` to schemaPolicyOptions DOES fix the one-run case
	// completely (1 -> 2) and shrank this population to 457 -- but
	// TestPackedOptInHoldsForEveryLeafPair8768 then failed for every leaf pair
	// involving `community` or `policy-statement`, because both declare
	// children and the split cannot find their boundary. Opting the container
	// in would have fixed `as-path` by breaking two other leaves. The opt-in
	// was withdrawn; #8768 is the guard that caught it, and it caught a claim
	// I had already convinced myself was safe on the strength of one leaf.
	//
	// That also NARROWS a claim in this cell's own failure message, which
	// generalises from `system name-server` that a `multi` leaf makes
	// packedStatements insufficient. `as-path` is `args: 2, multi: true` and
	// packedStatements fixes it completely -- being `multi` is not by itself
	// what makes the opt-in insufficient. Recorded rather than rewritten: the
	// message's 89/373 split is lane-8388's measurement, not mine to re-derive.
	// issue 8922 moves it again, on top of #8925. Exactly two more pairs
	// entered: `ssh ciphers` and `ssh macs`, admitted so the brace-elided
	// spelling stops silently dropping the SSH algorithm allowlists while their
	// schema-identical `key-exchange` sibling was already applied.
	//
	// STRICT IMPROVEMENT, measured on both sides rather than argued:
	//
	//	                            before        after
	//	ssh ciphers X;              []            [aes256-ctr]        FIXED
	//	ssh ciphers [ a b ];        []            [a b]               FIXED
	//	ssh ciphers X; macs Y;      [] and []     [] and []           UNCHANGED
	//
	// The multi-statement run was ALREADY fully lost before the admission --
	// #8850's decline branch refuses to fold an ambiguous run, so nothing folds
	// and everything is dropped. The admission does not create that case and
	// does not worsen it; it fixes the single-statement and bracketed-list
	// spellings, which are the ones an operator writes.
	//
	// I FIRST JUSTIFIED THIS BY SAYING ciphers/macs ARE `multi`, SO THE
	// packedStatements OPT-IN IS KNOWN INSUFFICIENT FOR THEM. #8925's
	// measurement above REFUTES THAT INFERENCE: `as-path` is args:2 AND multi,
	// and packedStatements fixes it completely. Being `multi` is not by itself
	// what makes the opt-in insufficient, so the claim is withdrawn.
	//
	// WHAT IS ACTUALLY TRUE HERE IS NARROWER AND UNTESTED: the opt-in has not
	// been tried on `ssh`. It may or may not resolve the packed run. The
	// residual is open and its remedy is UNMEASURED rather than known-absent --
	// which is a weaker statement than the one this comment carried when it was
	// written, and the honest one.
	//
	// The count below is RE-DERIVED at the merged base, not obtained by adding
	// the two deltas: a shared ratchet's movement is the sum of everyone's
	// work, and arithmetic on two separately-measured numbers is not a
	// measurement.
	//
	// #8933 MOVED IT AGAIN, AND THE INTERACTION IS THE POINT. #8930 measured
	// 98/463 on its own branch and #8933 measured 100/471 on its own; both were
	// correct about their own tree and BOTH WOULD HAVE BEEN WRONG had either
	// been carried across the other's merge. Re-derived once more at the base
	// that has both (master 2338ae3b0): 100 / 471. This is the third
	// re-derivation on this constant in a day and every one of them agreed with
	// a measurement and disagreed with an addition.
	//
	// The +8 is the eight `policy-options ... term <t> then <action>` pairs
	// admitted by #8933. They enter this population because `then` cannot split
	// a multi-statement packed run -- but a two-statement `then` has no elided
	// spelling to reach it with, so the over-approximation this comment already
	// warns about is where they sit.
	// issue 8904 SHRINKS it: 463 -> 455 at args>=1, while args>=2 HOLDS at 98.
	// `interfaces/*/tunnel`, `interfaces/*/unit/tunnel` and
	// `firewall/policer/if-exceeding` were opted into packedStatements so their
	// packed runs SPLIT instead of keeping only the first statement, which
	// removes their pairs from this population entirely -- this is the SHRANK
	// branch, and the constant is tightened rather than left loose.
	//
	// THE TWO THRESHOLDS DIVERGE HERE, AND THAT IS EXPECTED RATHER THAN A
	// SIGNAL. This cell's own note says they move together under an ordinary
	// scope widening and diverge when something changes the arity model. This
	// change is not a widening: every leaf opted in is `args: 1` and non-multi
	// (tunnel source/destination/mode/key/ttl/keepalive-retry, if-exceeding
	// bandwidth-limit/burst-size-limit), so none of them was ever in the
	// args>=2 population and only args>=1 can move. A change that moved args>=2
	// too would mean something else had also happened.
	//
	// Re-derived at this base and run twice with the numbers asserted equal --
	// the third re-derivation of this constant today, and every one has agreed
	// with a measurement and disagreed with an addition.
	// RE-DERIVED AT THIS REBASED BASE, NOT COMPUTED. The obvious move here is
	// 471 - 8, and it is wrong on principle even when it happens to be right:
	// subtracting assumes this opt-in removes precisely the pairs #8933's
	// admission added and that nothing else interacts. THE INTERACTION IS WHY
	// THIS CONSTANT EXISTS. Four separate re-derivations today, each forced by
	// a merge conflict on this literal, and every one agreed with a measurement
	// rather than with arithmetic.
	//
	// FOR HONESTY: this time the arithmetic WOULD have agreed -- 471 - 8 = 463,
	// and args>=2 held at 100 exactly as predicted, because every leaf opted in
	// is args:1 non-multi and #8933's eight `then <action>` heads are args:1
	// too, so neither change could touch that population. The measurement is
	// not vindicated by having differed. It is the practice that is worth
	// keeping, and a run where it agrees is the cheapest possible confirmation
	// that nothing unmodelled happened.
	// READ THIS BEFORE REACHING FOR A REMEDY -- twice now someone has reached
	// for the wrong one, including me.
	//
	// THIS POPULATION'S MEMBERSHIP CRITERION IS BROADER THAN ITS REMEDY
	// ADVICE, and the gap is where both corrections landed. Membership is
	// "the container cannot split a multi-statement run". The advice assumes
	// the cause is a packed run failing to split, for which packedStatements
	// is a candidate. Those are DIFFERENT CLAIMS, so a member can be here for
	// a cause the advice does not fit:
	//
	//	policy-options as-path   packedStatements DOES fix it, contradicting
	//	                         the advice's own "a multi leaf makes it
	//	                         insufficient" generalisation.
	//	syslog host/file/user    packedStatements does NOT fix it; the
	//	                         residual is a FOLDED-SIBLING MERGE, not a
	//	                         split failure at all.
	//
	// MEASURE the member's actual residual before choosing a remedy; do not
	// infer the cause from the population it landed in.
	//
	// #8943 args1 463 -> 466: the three `syslog` destinations were admitted.
	// GROWTH, deliberate, attributed, and a strict improvement -- measured for
	// a config carrying TWO syslog hosts:
	//
	//	braced                            before 2   after 2
	//	elided, two separate statements   before 0   after 1   <- improved, TRUNCATES
	//	elided, both in ONE packed run    before 0   after 0   <- unchanged
	//
	// The pair joins this population because it is now reachable at all; the
	// loss it leaves is smaller than the one it replaced.
	//
	// AND THE RESIDUAL IS NOT THIS CELL'S MECHANISM, which is worth recording
	// because the population name says otherwise. `packedStatements` on
	// `syslog` does NOT fix it (still 1 and 0) and #8768 objects to the opt-in
	// besides. The two-separate-statements case loses its second host to a
	// FOLDED-SIBLING MERGE -- two `syslog host X { ... }` statements each fold
	// to a `syslog` node and the merge keeps one -- not to a packed run failing
	// to split. So a pair can sit in this population for a reason the
	// population does not model, and the opt-in is not a candidate remedy for
	// it. Same shape as the as-path correction recorded above: the cell's
	// remedy advice is narrower than its membership.
	// issue 8939 SHRINKS it 466 -> 460 at args>=1; args>=2 HOLDS at 100.
	// `packedStatements` on the two filter-term `then` nodes means their packed
	// runs SPLIT, so those pairs leave this population -- the SHRANK branch, and
	// the constant is tightened rather than left loose.
	//
	// args>=2 holding is the expected divergence: every `then` action is args:0
	// or args:1, so none was ever in that population. A change moving both
	// would mean something else had happened.
	//
	// Re-derived at this base, twice, not computed as 466 - 6.
	// issue 8932 SHRINKS it 460 -> 452 at args>=1; args>=2 HOLDS at 100.
	// `packedStatements` on the `security log stream` node means its packed run
	// SPLITS, so its eight pairs leave this population -- the SHRANK branch,
	// and the constant is tightened rather than left loose.
	//
	// args>=2 holding is the expected divergence: every stream leaf is args:1,
	// so none was ever in that population.
	//
	// AND THIS MEMBER IS A THIRD CAUSE THE ADVICE ABOVE DOES NOT FIT -- the
	// note this cell now carries about membership being broader than the
	// remedy. `stream <s>` is ARG-NAMED, so a pair-keyed admission is
	// structurally unreachable: production calls the predicate with ("s1",
	// "category"), never ("stream", "category"). Every pair up its chain was
	// already admitted and every one inert. The remedy had to be a NODE opt-in;
	// no admission could have worked.
	//
	// Re-derived at this base, twice, not computed as 460 - 8.
	const (
		wantArgs2 = 101
		// #8928 admitted `ip-monitoring policy`, so exactly one more pair is
		// in scope and therefore one more is unsplittable. Re-derived by
		// running the cell at this base, not by adding one to the old value.
		// #9689 SHRINKS it 452 -> 451: `profile` opted into packedStatements, so
		// `profile feed-name` is splittable (and the new `profile fail-mode` never
		// enters the population).
		// #9620 H11 SHRINKS it 451 -> 449. The splitter now walks a container
		// HEAD's own elided body instead of refusing the run outright, so a pair
		// whose head declares the following token is splittable. The two that
		// left are the address-book `address+address-set` pairs, at the global
		// book and the zone-local one. The same two were registered in the #8768
		// opt-in guard as diverging by nested elision, and those registrations
		// went stale in the same run and are deleted there -- two independent
		// ratchets naming the same pair movement.
		wantArgs1 = 449
	)
	pairs2, _ := unsplittablePairs8880(2)
	pairs1, conflict1 := unsplittablePairs8880(1)
	got2, got1 := len(pairs2), len(pairs1)

	// STABILITY. A census that is not run twice is a number, not a measurement;
	// this package has produced 79/112/121 on one unchanged tree before, from
	// node-keyed dedup plus Go's randomised map order.
	p2b, _ := unsplittablePairs8880(2)
	p1b, _ := unsplittablePairs8880(1)
	if a, b := len(p2b), len(p1b); a != got2 || b != got1 {
		t.Fatalf("census is NOT STABLE across two runs in one process: "+
			"args>=2 %d then %d, args>=1 %d then %d. Fix the instrument before "+
			"reading any number off it (#8880)", got2, a, got1, b)
	}
	// STABILITY OF EVERY NUMBER REPORTED, not just the headline counts. The
	// first version of this check compared only the two lengths, and passed
	// while the multi/non-multi split drifted 87 -> 93 on an unchanged tree. A
	// stability assertion is only as wide as the values it reads.
	countMulti := func(pairs, conf map[string]bool) int {
		n := 0
		for k, isMulti := range pairs {
			if !conf[k] && isMulti {
				n++
			}
		}
		return n
	}
	_, conf1b := unsplittablePairs8880(1)
	if x, y := countMulti(pairs1, conflict1), countMulti(p1b, conf1b); x != y {
		t.Fatalf("the multi/non-multi split is NOT STABLE across two runs: "+
			"%d then %d. A pair whose multi-ness depends on which schema path "+
			"wrote last is being resolved by Go's map order (#8880)", x, y)
	}

	for _, c := range []struct {
		label     string
		got, want int
	}{{"args>=2", got2, wantArgs2}, {"args>=1", got1, wantArgs1}} {
		if c.got == c.want {
			continue
		}
		dir := "GREW"
		if c.got < c.want {
			dir = "SHRANK"
		}
		t.Errorf("unsplittable-pair population %s %s: got %d, want %d (#8880)\n"+
			"MEMBERSHIP IS BROADER THAN THE REMEDY ADVICE: measure this "+
			"member's actual residual before choosing a remedy, and do not "+
			"infer the cause from the population -- two members so far had "+
			"causes the advice did not fit. "+
			"GREW means a pair was admitted to the brace-elision scope whose "+
			"container cannot split a multi-statement run -- the #8850 "+
			"address-book shape, where the scope entry alone folds two "+
			"statements into one and keeps only the first.\n"+
			"THE REMEDY DEPENDS ON THE LEAF AND `packedStatements` IS NOT ALWAYS "+
			"ONE. Measured: giving `system` packedStatements does NOT fix "+
			"`name-server`, because a multi leaf absorbs the rest of the run in "+
			"consumeNodeKeys, so the split still yields one statement and the "+
			"tail is returned whole. Of this population 89 are multi and 373 are "+
			"not; the opt-in is a candidate remedy for the 373 and is known "+
			"insufficient for the 89.\n"+
			"SHRANK means something was fixed: TIGHTEN THIS CONSTANT. Leaving it "+
			"loose gives the next regression that much room to hide.\n"+
			"THE NUMBER IS AN OVER-APPROXIMATION: a pair is only broken if a "+
			"multi-statement packed run actually reaches that container, which "+
			"this census does not model. Ceiling unmeasured in both directions.\n"+
			"NOT #8876: that is a missing parent EDGE so the container is never "+
			"created; this is a container that IS reachable and admitted.",
			c.label, dir, c.got, c.want)
	}

	// ADEQUACY, not just liveness. An empty or all-inclusive population would
	// satisfy the equality above at the wrong constant, so the predicate is
	// checked to actually DISCRIMINATE: a container that HAS opted in must be
	// absent, or the `!n.packedStatements` clause has stopped doing anything.
	set2 := pairs2
	if len(set2) == 0 {
		t.Error("population is EMPTY, so the equality above asserts nothing (#8880)")
	}
	// THESE ANCHORS MUST EXIST AT THIS BASE. The first pair written here was
	// ("address-book","address"), which is admitted only on the still-open #8866
	// -- so at master it is absent from the population for a reason that has
	// nothing to do with the clause under test, and the check could never fire.
	// A control that cannot fail is not a control. Both below are admitted AND
	// their container declares packedStatements at 2a4796a72; there are 32 such
	// pairs, so this is a sample of a real set rather than a lucky pick.
	for _, optedIn := range []string{"gateway local-identity", "dead-peer-detection interval"} {
		if set2[optedIn] {
			t.Errorf("%q is in the population, but its container declares "+
				"packedStatements -- the clause that makes this census mean "+
				"anything has stopped filtering (#8880)", optedIn)
		}
	}

	// LIVE MEMBERS. A counted ratchet with no demonstrated member is a number.
	// These two are adjudicated: the packed spelling does not merely lose the
	// second statement, it absorbs that statement's KEYWORD as a value.
	// TRUNCATION MODE, kept beside the injection ones so a reader does not
	// generalise from a single mode. This is issue #8880.
	//
	// ZERO IS THE DELIBERATE POST-FIX OUTCOME -- DO NOT "FIX" IT BACK TO ONE.
	// Before #8884 the packed spelling compiled ONE of the two zone pairs; the
	// fold consumed the first block and stranded the rest of the run. #8884
	// makes the fold DECLINE instead, so the packed spelling now compiles NONE:
	//
	//	braced          [a->b c->d]
	//	before #8884    [a->b]        one of two -- a silently WRONG policy set
	//	after  #8884    []            none -- fail-closed, default-deny applies
	//
	// That is a deliberate judgement and the right one: half a policy set reads
	// as correct and permits the wrong traffic, where an empty one denies and is
	// noticed. A future change that makes this return ONE again would look like
	// progress on this cell's numbers and would be a regression.
	//
	// It is still a MEMBER of this population, and still silent at commit: zero
	// warnings, no strict rejection. Declining is a better failure, not the
	// absence of one.
	//
	// AND IT IS THE ONLY ONE. Measured: the `args >= 2 && !multi` clause -- the
	// truncation clause -- has exactly ONE member in the narrow population,
	// `policies from-zone` (args=3), and it is this one. A ratchet landing on
	// `args >= 2` alone would therefore carry a mode with a single, already
	// handled member, which is most of the argument for asserting the wide
	// threshold beside it.
	t.Run("member/policies from-zone (truncation)", func(t *testing.T) {
		const rule = "policy p1 { match { source-address any; destination-address " +
			"any; application any; } then { permit; } }"
		const zones = "security-zone a { } security-zone b { } security-zone c { } " +
			"security-zone d { }"
		const blocks = "from-zone a to-zone b { " + rule + " } from-zone c to-zone d { " + rule + " }"
		pairs := func(txt string) []string {
			tree, errs := NewParser(txt).Parse()
			if len(errs) > 0 {
				t.Fatalf("parse: %v", errs)
			}
			cfg, err := CompileConfigLenient(tree)
			if err != nil {
				t.Fatalf("compile: %v", err)
			}
			var out []string
			for _, p := range cfg.Security.Policies {
				out = append(out, p.FromZone+"->"+p.ToZone)
			}
			sort.Strings(out)
			return out
		}
		// BOTH ARMS CARRY THE SAME TWO BLOCKS. An earlier version of this
		// fixture gave the braced arm two rule bodies and the packed arm one,
		// so "1 vs 2" would have been the fixture rather than the fold -- right
		// by accident, which is worse than wrong.
		braced := pairs("security { zones { " + zones + " } policies { " + blocks + " } }")
		packed := pairs("security { zones { " + zones + " } policies " + blocks + " }")
		if len(braced) != 2 {
			t.Fatalf("the BRACED reference produced %v, not two zone pairs, so "+
				"this member demonstrates nothing", braced)
		}
		if strings.Join(packed, "|") == strings.Join(braced, "|") {
			t.Errorf("policies/from-zone no longer truncates (packed %v == braced "+
				"%v), so it is FIXED and must leave this cell -- and the counts "+
				"above re-derived (#8880)", packed, braced)
		}
		if len(packed) >= len(braced) {
			t.Errorf("policies/from-zone still differs but no longer LOSES a "+
				"block (packed %v, braced %v). This member is the TRUNCATION "+
				"mode; if it has become injection the mode split above is wrong "+
				"and must be re-derived, not edited (#8880)", packed, braced)
		}
		// Guard the DIRECTION of any future change here. Going from none back to
		// one is the shape #8884 deliberately moved away from, and it would read
		// as an improvement against a count.
		if len(packed) == 1 {
			t.Errorf("policies/from-zone compiles ONE of %d zone pairs again "+
				"(%v). #8884 moved this from one to NONE on purpose: a partial "+
				"policy set reads as correct and permits the wrong traffic, "+
				"where an empty one denies and is noticed. This is a regression "+
				"wearing the shape of progress (#8880)", len(braced), packed)
		}
	})

	for _, c := range []struct {
		pair, packed, braced string
		read                 func(*Config) []string
	}{
		// #8883 FIXED both `system name-server` and `system domain-search` and
		// this cell RED when they stopped diverging, exactly as designed — a
		// member that becomes adjudicated must leave the list or the list
		// outlives its reason.
		//
		// They are replaced rather than merely removed: an empty loop would
		// measure nothing while still passing. The replacements are members of
		// the SAME class that #8883's fix does NOT reach, which is the point
		// worth keeping — the remedy is PER-READER, not per-class.
		// `firewallMatchValues` serves name-server, domain-search, ssh
		// key-exchange and bgp export; `ntp server` and `nat source pool
		// address` have their own value loops and still absorb the keyword.
		{"ntp server",
			"system { ntp { server 1.1.1.1 server 2.2.2.2; } }",
			"system { ntp { server 1.1.1.1; server 2.2.2.2; } }",
			func(c *Config) []string { return c.System.NTPServers }},
		{"pool address",
			"security { nat { source { pool P { address 10.0.0.1/32 address 10.0.0.2/32; } } } }",
			"security { nat { source { pool P { address 10.0.0.1/32; address 10.0.0.2/32; } } } }",
			func(c *Config) []string {
				for _, p := range c.Security.NAT.SourcePools {
					return p.Addresses
				}
				return nil
			}},
	} {
		t.Run("member/"+c.pair, func(t *testing.T) {
			compile := func(txt string) []string {
				tree, errs := NewParser(txt).Parse()
				if len(errs) > 0 {
					t.Fatalf("parse %q: %v", txt, errs)
				}
				cfg, err := CompileConfigLenient(tree)
				if err != nil {
					t.Fatalf("compile %q: %v", txt, err)
				}
				return c.read(cfg)
			}
			braced, packed := compile(c.braced), compile(c.packed)
			// LIVENESS: both arms empty would satisfy any comparison.
			if len(braced) != 2 {
				t.Fatalf("the BRACED reference produced %v, not two entries, so "+
					"this member demonstrates nothing", braced)
			}
			if strings.Join(packed, "|") == strings.Join(braced, "|") {
				t.Errorf("%s no longer diverges (packed %v == braced %v), so it "+
					"is FIXED and must be removed from this cell -- and the "+
					"counts above re-derived (#8880)", c.pair, packed, braced)
			}
			// The specific harm: the next statement's KEYWORD became a value.
			kw := strings.SplitN(c.pair, " ", 2)[1]
			var found bool
			for _, v := range packed {
				if v == kw {
					found = true
				}
			}
			if !found {
				t.Errorf("%s still diverges but no longer absorbs %q as a VALUE "+
					"(packed %v). The failure mode changed; re-adjudicate this "+
					"member rather than leaving a stale description (#8880)",
					c.pair, kw, packed)
			}
		})
	}

	var sample []string
	for k := range set2 {
		sample = append(sample, k)
	}
	sort.Strings(sample)
	if len(sample) > 6 {
		sample = sample[:6]
	}
	multi, resolved := 0, 0
	for k, isMulti := range pairs1 {
		if conflict1[k] {
			continue // multi-ness differs by path; excluded, see below
		}
		resolved++
		if isMulti {
			multi++
		}
	}
	// A pair whose multi-ness DIFFERS between the schema paths that reach it has
	// no single remedy, so it is counted separately rather than averaged into
	// one bucket. Reported, not asserted: the count is a property of the schema,
	// not a regression, and folding it into the ratchet constant would make an
	// unrelated schema edit look like a population change.
	if len(conflict1) > 0 {
		var c []string
		for k := range conflict1 {
			c = append(c, k)
		}
		sort.Strings(c)
		t.Logf("#8880: %d pair(s) qualify with DIFFERENT multi-ness on "+
			"different schema paths, so the remedy split does not resolve for "+
			"them: %v", len(conflict1), c)
	}
	t.Logf("#8880: %d pairs at args>=2, %d at args>=1 (of %d whose remedy "+
		"resolves: %d multi, %d not), wildcard-traversing, master 2a4796a72; "+
		"e.g. %v", got2, got1, resolved, multi, resolved-multi, sample)
}
