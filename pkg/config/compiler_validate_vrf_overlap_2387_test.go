package config

import (
	"strings"
	"testing"
)

// #2387 (Track A.1): the userspace-dp session/flow identity is the bare 5-tuple
// with no routing-instance/VRF discriminator (userspace-dp/src/session/key.rs),
// so two flows in different routing-instances that share a 5-tuple collide in
// the conntrack map. The collision is LIVE under PBR `then routing-instance`.
// validateVRFOverlap emits a commit WARNING (never a reject) when two DISTINCT
// routing-instances carry overlapping L3 address space.
//
// These tests pin: (1) two RIs with overlapping addresses on their member
// interface units WARN, naming both RIs + the prefix; (2) non-overlapping RIs
// do NOT warn (no false positive); (3) a single RI / no RI does NOT warn;
// (4) the PBR-term source (`then routing-instance`) also feeds the overlap set;
// (5) the warning ENDS with the exact status sentence, verbatim, so nothing can
// be appended after it that does not ITSELF re-terminate with the tail, the tail
// cannot be reworded, and the status sentence itself cannot be dropped; and
// (6) losing the promise did not cost the diagnostic any of its substance,
// polarity included.
//
// (5) is deliberately NOT "no forecast in either direction". Measured: the
// suffix pin catches APPEND-after-tail and REWORD-inside-tail in both
// directions, with one contrived exception — an append that duplicates the whole
// 84-character tail at its end satisfies `HasSuffix` again, so
// "…limitation. A fix is guaranteed. Meanwhile, <tail verbatim>" passes, and
// "guaranteed" is on neither list. That is defeating the guard, not stumbling
// past it, and every SIMPLE append is caught; it is recorded so nobody reasons
// from "appends are impossible" when deciding a spelling is not worth listing.
// The pin is BLIND to a forecast SPLICED before the tail or
// PREPENDED at the front — there, the token lists are the only defence, and a
// blocklist is incomplete by construction. Nine distinct foreclosing sentences
// and nine distinct promising sentences, none using a listed spelling, were
// each spliced before the tail and left the whole package suite GREEN. So what
// is enforced is purely LEXICAL: "none of the listed spellings appears anywhere,
// plus no tampering with the tail at all" — not "no forecast", and not even "no
// forecast in a listed spelling". The check cannot see meaning in either
// direction. It misses a forecast phrased in a spelling nobody listed, and it
// rejects accurate neutral prose that happens to contain one — eight such
// sentences were measured tripping the lists. Do not grow the lists toward
// completeness; see the doctrine note at the blocklist itself.
//
// "Either direction" is load-bearing in (5). The contract on validateVRFOverlap
// is that the text must not promise a fix "nor rule one out", and until now only
// the promise half was guarded: appending ". #2387 is closed wontfix; this is by
// design and permanent" passed the whole suite while foreclosing an outcome that
// is still the maintainer's to decide. See vrfOverlapForeclosingTokens.
//
// fail-on-revert: removing the validateVRFOverlap call (or its detection body)
// drops the warning, so TestVRFOverlapWarnsOnOverlappingRIs goes RED.
//
// The mutation that ISOLATES the promise dimension is a TAIL-ONLY substitution:
// replace "…may cross-forward. See #2387 for the status of this limitation"
// with "…may cross-forward until the session identity is VRF-aware", KEEPING
// the "flows PBR steers in from default-instance ingress share routing domain 0 in the session identity, so"
// clause. That reds TestVRFOverlapWarningStatesStatusNotPromise twice over — the
// message no longer ends with vrfOverlapStatusTail, and "until" is on the
// blocklist — while TestVRFOverlapWarningKeepsDiagnosticSubstance stays GREEN,
// which is what distinguishes "the promise is gone" from "the diagnostic is
// gone". The converse isolation is stripping the "…carries no routing-instance
// discriminator, so " clause and keeping the tail: substance RED, promise GREEN.
//
// A LITERAL revert to the pre-PR string reds BOTH, and that is correct, not a
// failure of the pair: the old string ALSO lacked the discriminator clause, so
// reverting changes two things at once — it re-adds the promise AND removes the
// diagnosis. Do not read a both-red result as "the tests do not separate"; run
// the tail-only mutation above to see them separate. (That the old text trips
// the substance test at all is the useful part: the replacement is strictly
// more informative than what it replaced, and this test is what pins that.)

// vrf2387Warnings returns the compile warnings carrying the cross-VRF overlap
// diagnosis. It selects on the diagnosis phrase, NOT on "#2387" — see the
// comment on the filter below for why the issue reference cannot be the
// selector.
// vrf2387WarningsLenient is vrf2387Warnings on the TOLERANT path.
//
// #7924 promoted the overlap+PBR combination to a strict commit REJECTION, so a
// caller whose subject is the WARNING for that combination can no longer reach
// it through CompileConfig. The lenient path still emits the identical warning
// (the rejection is a downgrade of it, not a replacement), so a test about
// warning CONTENT keeps testing content rather than being rewritten into a test
// about disposition — which #7924 covers separately and on purpose.
func vrf2387WarningsLenient(t *testing.T, cmds []string) []string {
	t.Helper()
	return vrf2387WarningsWith(t, cmds, CompileConfigLenient)
}

func vrf2387Warnings(t *testing.T, cmds []string) []string {
	t.Helper()
	return vrf2387WarningsWith(t, cmds, CompileConfig)
}

func vrf2387WarningsWith(t *testing.T, cmds []string, compile func(*ConfigTree) (*Config, error)) []string {
	t.Helper()
	tree := buildTree(t, cmds)
	cfg, err := compile(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	var out []string
	for _, w := range cfg.Warnings {
		// Filter on the DIAGNOSIS, not on "#2387". Filtering on the issue
		// reference made the status-sentence assertion below unreachable: every
		// warning reaching it had already been selected for containing the very
		// substring the sentence ends with. Dropping #2387 from a format string
		// failed the fixture's count assertion instead, with a message about the
		// wrong thing. This phrase is carried by both overlap format strings and
		// by neither the truncation notice nor any other warning, so the
		// selection stays arm-neutral, and it appears nowhere inside
		// vrfOverlapStatusTail, so it cannot pre-satisfy that assertion either.
		if strings.Contains(w, "overlapping L3 across routing-instances") {
			out = append(out, w)
		}
	}
	return out
}

func TestVRFOverlapWarnsOnOverlappingRIs(t *testing.T) {
	warns := vrf2387Warnings(t, []string{
		"set interfaces ge-0/0/1 unit 0 family inet address 10.0.0.1/24",
		"set interfaces ge-0/0/2 unit 0 family inet address 10.0.0.2/24",
		"set routing-instances RI-A instance-type virtual-router",
		"set routing-instances RI-A interface ge-0/0/1.0",
		"set routing-instances RI-B instance-type virtual-router",
		"set routing-instances RI-B interface ge-0/0/2.0",
	})
	if len(warns) != 1 {
		t.Fatalf("expected exactly one #2387 overlap warning, got %d: %v", len(warns), warns)
	}
	w := warns[0]
	for _, want := range []string{`"RI-A"`, `"RI-B"`, "10.0.0.0/24", "NOT session-isolated"} {
		if !strings.Contains(w, want) {
			t.Errorf("warning missing %q: %s", want, w)
		}
	}
}

func TestVRFOverlapNoWarnNonOverlapping(t *testing.T) {
	// Distinct address space per VRF — the common multi-VRF deployment. No warn.
	warns := vrf2387Warnings(t, []string{
		"set interfaces ge-0/0/1 unit 0 family inet address 10.0.0.1/24",
		"set interfaces ge-0/0/2 unit 0 family inet address 10.0.1.1/24",
		"set routing-instances RI-A instance-type virtual-router",
		"set routing-instances RI-A interface ge-0/0/1.0",
		"set routing-instances RI-B instance-type virtual-router",
		"set routing-instances RI-B interface ge-0/0/2.0",
	})
	if len(warns) != 0 {
		t.Fatalf("non-overlapping RIs should not warn, got: %v", warns)
	}
}

func TestVRFOverlapNoWarnSingleRI(t *testing.T) {
	// A single RI cannot overlap another RI. No warn even with two interfaces
	// carrying the same subnet inside the SAME instance.
	warns := vrf2387Warnings(t, []string{
		"set interfaces ge-0/0/1 unit 0 family inet address 10.0.0.1/24",
		"set interfaces ge-0/0/2 unit 0 family inet address 10.0.0.2/24",
		"set routing-instances RI-A instance-type virtual-router",
		"set routing-instances RI-A interface ge-0/0/1.0",
		"set routing-instances RI-A interface ge-0/0/2.0",
	})
	if len(warns) != 0 {
		t.Fatalf("single RI should not warn, got: %v", warns)
	}
}

func TestVRFOverlapNoWarnNoRI(t *testing.T) {
	// No routing-instances at all — plain master-table config. No warn.
	warns := vrf2387Warnings(t, []string{
		"set interfaces ge-0/0/1 unit 0 family inet address 10.0.0.1/24",
		"set interfaces ge-0/0/2 unit 0 family inet address 10.0.0.2/24",
	})
	if len(warns) != 0 {
		t.Fatalf("no-RI config should not warn, got: %v", warns)
	}
}

func TestVRFOverlapWarnsViaPBRTerms(t *testing.T) {
	// The same destination prefix steered into two different routing-instances
	// by two PBR `then routing-instance` terms is the exact reachable-via-PBR
	// trigger — overlap detected from the filter-term source.
	//
	// #7924: this exact shape is now a strict commit REJECTION, so the warning is
	// reached through the tolerant path. The subject of this test is unchanged and
	// deliberately so — it binds that PBR TERMS FEED the overlap detector, which
	// is the input #7924's rejection depends on. Rewriting it into a
	// disposition assertion would have deleted the only coverage of that feed and
	// left #7924 resting on a source nothing pins.
	warns := vrf2387WarningsLenient(t, []string{
		"set routing-instances RI-A instance-type virtual-router",
		"set routing-instances RI-B instance-type virtual-router",
		"set firewall family inet filter fbf term to-a from destination-address 172.16.9.0/24",
		"set firewall family inet filter fbf term to-a then routing-instance RI-A",
		"set firewall family inet filter fbf term to-b from destination-address 172.16.9.0/24",
		"set firewall family inet filter fbf term to-b then routing-instance RI-B",
	})
	if len(warns) != 1 {
		t.Fatalf("expected one #2387 overlap warning from PBR terms, got %d: %v", len(warns), warns)
	}
	for _, want := range []string{`"RI-A"`, `"RI-B"`, "172.16.9.0/24"} {
		if !strings.Contains(warns[0], want) {
			t.Errorf("PBR warning missing %q: %s", want, warns[0])
		}
	}
}

func TestVRFOverlapV6NoCrossFamilyFalsePositive(t *testing.T) {
	// A v4 subnet in one RI and a v6 subnet in another never overlap. No warn.
	warns := vrf2387Warnings(t, []string{
		"set interfaces ge-0/0/1 unit 0 family inet address 10.0.0.1/24",
		"set interfaces ge-0/0/2 unit 0 family inet6 address 2001:db8::1/64",
		"set routing-instances RI-A instance-type virtual-router",
		"set routing-instances RI-A interface ge-0/0/1.0",
		"set routing-instances RI-B instance-type virtual-router",
		"set routing-instances RI-B interface ge-0/0/2.0",
	})
	if len(warns) != 0 {
		t.Fatalf("cross-family (v4 vs v6) must not warn, got: %v", warns)
	}
}

// vrfOverlapStatusTail is the exact wording BOTH overlap format strings must
// END with. It is this PR's actual deliverable: the sentence that replaced the
// old "until the session identity is VRF-aware" promise with a pointer to the
// still-open decision.
//
// Asserted as an exact TERMINAL substring, not as tokens, because every weaker
// form measured GREEN while the deliverable was gone. A bare `Contains("#2387")`
// passed with this whole sentence deleted, since the diagnosis clause earlier in
// the message carries a second "#2387". And no token list can forbid text being
// APPENDED after the sentence: "…status of this limitation. A fix is
// guaranteed." reintroduces an explicit promise while matching every token
// check. One suffix comparison forbids truncating and rewording the tail
// outright, and forbids appending anything that does not re-terminate with the
// tail verbatim — and it needs no maintenance as new promise spellings are
// invented. Re-terminating is the one hole: repeating the whole tail after an
// appended promise satisfies `HasSuffix` again. It takes deliberate effort, so
// treat it as a limit on what the pin PROVES rather than a gap to plug.
//
// It deliberately starts AFTER the "…session identity, so " clause. That makes the
// two tests SEPARABLE — not orthogonal, and the difference is measured. Deleting
// the diagnosis reds TestVRFOverlapWarningKeepsDiagnosticSubstance and only that
// test, so the substance check is not a second spelling of this one. The converse
// does NOT hold: the tail carries the substantive polarity word ("may"), so
// flipping it to "cannot" reds BOTH — this test on the suffix compare, the
// substance test on its own phrase list. So read a red here as "the tail changed",
// not as "someone made a promise"; a polarity edit lands in both columns at once.
const vrfOverlapStatusTail = "colliding 5-tuples may cross-forward. " +
	"See #2387 for the status of this limitation"

// vrfOverlapForwardLookingTokens are SPELLINGS that commonly appear when an
// advisory stops stating the CURRENT limitation and starts promising a future
// one. They are not themselves promises, and the check that uses them cannot
// tell the difference — see the both-directions note below. #2387
// is held on a maintainer risk-appetite call: neither candidate end-state (the
// hard-reject posture, or the VRF-aware session key) is decided, so the warning
// must not assert that either one arrives. The original text said colliding
// 5-tuples may cross-forward "until the session identity is VRF-aware", and the
// #2387 plan then cited that sentence back as evidence the widening was already
// settled — a promise the open decision may never keep.
//
// This list is the SECONDARY layer, and it is a BLOCKLIST: incomplete by
// construction. vrfOverlapStatusTail above is the primary binding and pins the
// message from "colliding 5-tuples" to its last character exactly, so the only
// region where these tokens are the sole defence is the span BEFORE the tail — a
// promise spliced between "NOT session-isolated (#2387) —" and the diagnosis
// clause. Do not read a green result as "the warning contains no promise"; read
// it as "the tail is exactly right and the head contains none of these
// spellings". Do not grow this list toward completeness — that is the trap it
// documents. The entries below the first group were each added after a review
// demonstrated it passing the test while reintroducing a promise, so treat any
// addition the same way: prove it green first, then add it.
//
// It is WRONG IN BOTH DIRECTIONS, and the second direction is easy to miss.
// These are substring matches, so a hit proves a spelling APPEARS — never that
// the sentence containing it forecasts anything. Eight accurate, deliberately
// non-forecasting sentences were measured tripping this list: "#2387 leaves
// both future end-states open" (via "future"), "the #2387 roadmap records no
// selected end-state" (via "roadmap"), "operators must never infer either
// end-state from this warning" (via "never"), and five more. Every one of them
// is exactly the neutrality the contract asks for, and every one is rejected.
//
// That direction is fail-SAFE — it blocks correct text rather than admitting
// wrong text — but it is not free: the pressure it puts on an author is toward
// vaguer operator wording, which costs the diagnostic the substance
// TestVRFOverlapWarningKeepsDiagnosticSubstance exists to protect. If you hit a
// false red, reword around the spelling. Do not carve an exception into the
// list, and do not water down the message to get past it.
//
// Adding a whole DIRECTION is a different act from growing this list, and
// vrfOverlapForeclosingTokens below is that: not one more spelling of a covered
// axis, but the first coverage of an axis that had none.
var vrfOverlapForwardLookingTokens = []string{
	"until",
	"will be",
	"planned",
	"future",
	"deferred",
	"upcoming",
	"roadmap",
	"once the session",
	"when the session",
	// Measured escapes — each was inserted into the warning and observed to
	// leave the test GREEN before it was listed here.
	//
	// "temporarily" earns its own entry: it does NOT contain "temporary" as a
	// substring, so the shorter token does not cover it.
	//
	// A cautionary one, kept as a worked example rather than removed: an
	// earlier round added "work is under way", which fires only on that exact
	// four-word spelling and does NOT match "work is underway" or "work is in
	// progress" — the phrasing actually measured. Reaching for a phrase you
	// imagined instead of the one you observed buys nothing. "in progress"
	// below is the token that does the work.
	"not yet",
	"pending",
	"temporary",
	"temporarily",
	"in a later release",
	"for now",
	"interim",
	"to be addressed",
	"work is under way",
	"underway",
	"in progress",
	"soon",
	"shortly",
	"eventually",
	"plan to",
	"will gain",
	"is expected to",
	"shall",
	"going to",
	"next release",
	"targeted for",
	"tracked for",
}

// vrfOverlapForeclosingTokens are the mirror image: spellings that commonly
// appear when a text rules a fix OUT. The same both-directions caveat applies —
// a hit proves the spelling is present, not that an outcome was foreclosed;
// "operators must never infer either end-state from this warning" trips "never"
// while foreclosing nothing. The contract on validateVRFOverlap is symmetric — the text "must not
// promise a fix, nor rule one out" — because #2387 is held on a maintainer
// risk-appetite call whose two candidate end-states are BOTH still open. A
// warning saying the collision is permanent and by design is exactly as wrong as
// one saying a fix is coming, and it is the more dangerous error of the two: an
// operator who reads "by design" stops treating an overlapping-VRF topology as a
// hazard to revisit.
//
// This axis had NO guard until now. Every one of the 31 entries above is
// forward-looking, so appending ". #2387 is closed wontfix; this is by design
// and permanent" passed the whole suite while foreclosing the outcome the
// comment forbids foreclosing. vrfOverlapStatusTail now reds that append — and
// any other that does not itself re-terminate with the tail — in either
// direction; these tokens cover the same span the forward list does, the message
// BEFORE the tail, and inherit the same disclosed incompleteness.
//
// The entries are checked against the shipped text: none is a substring of the
// current warning, so this list starts from a real green.
var vrfOverlapForeclosingTokens = []string{
	"wontfix",
	"won't fix",
	"will not",
	"never",
	"by design",
	"as designed",
	"working as intended",
	"permanent",
	"closed as",
	"not going to",
	"no fix",
}

// vrfOverlapBothFormStrings returns one warning from EACH of the two format
// strings in validateVRFOverlap: the equal-prefix form (both RIs carry the
// identical prefix) and the unequal-overlap form (the prefixes overlap without
// being equal). A fixture that hits only one arm leaves the other's wording
// unbound, so every wording assertion below runs against both.
func vrfOverlapBothFormStrings(t *testing.T) (equal, unequal string) {
	t.Helper()

	eq := vrf2387Warnings(t, []string{
		"set interfaces ge-0/0/1 unit 0 family inet address 10.0.0.1/24",
		"set interfaces ge-0/0/2 unit 0 family inet address 10.0.0.2/24",
		"set routing-instances RI-A instance-type virtual-router",
		"set routing-instances RI-A interface ge-0/0/1.0",
		"set routing-instances RI-B instance-type virtual-router",
		"set routing-instances RI-B interface ge-0/0/2.0",
	})
	if len(eq) != 1 {
		t.Fatalf("equal-prefix fixture: want 1 warning, got %d: %v", len(eq), eq)
	}
	// 10.0.0.0/24 vs 10.0.0.0/25 overlap but are not equal, so this reaches the
	// second format string. Assert the arm separation actually held rather than
	// trusting the fixture: if both fixtures produced the same form, every
	// "both format strings" claim below would be vacuous.
	un := vrf2387Warnings(t, []string{
		"set interfaces ge-0/0/1 unit 0 family inet address 10.0.0.1/24",
		"set interfaces ge-0/0/2 unit 0 family inet address 10.0.0.2/25",
		"set routing-instances RI-A instance-type virtual-router",
		"set routing-instances RI-A interface ge-0/0/1.0",
		"set routing-instances RI-B instance-type virtual-router",
		"set routing-instances RI-B interface ge-0/0/2.0",
	})
	if len(un) != 1 {
		t.Fatalf("unequal-overlap fixture: want 1 warning, got %d: %v", len(un), un)
	}
	if !strings.Contains(eq[0], "both carry") {
		t.Fatalf("equal-prefix fixture did not reach the equal-prefix format string: %s", eq[0])
	}
	if !strings.Contains(un[0], "carry overlapping L3") {
		t.Fatalf("unequal fixture did not reach the unequal-overlap format string: %s", un[0])
	}
	return eq[0], un[0]
}

// TestVRFOverlapWarningStatesStatusNotPromise pins two LEXICAL properties of
// BOTH format strings: the message ENDS with vrfOverlapStatusTail verbatim, and
// the message contains none of the listed spellings — from either list —
// anywhere. It compares text. It does not and cannot evaluate meaning.
//
// The NAME is aspirational, not a description of what runs. "NotPromise" is
// shorthand for the CONTRACT on validateVRFOverlap, which is symmetric —
// "neither promises nor forecloses". The test approximates that contract with
// two substring checks, and the gap between the contract and the approximation
// is the subject of the next paragraph. Do not read the name as the guarantee.
//
// What that does NOT amount to is "the text cannot forecast either outcome". The
// suffix compare is absolute but reaches only the tail; everything before it is
// governed by two token BLOCKLISTS, which are incomplete by construction. Nine
// foreclosing and nine promising sentences, each spliced before the tail in a
// spelling nobody listed, left the whole package suite GREEN. Treat a green as
// "the tail is intact and no listed spelling appears" — not as a proof of
// neutrality. Do not respond by growing the lists; see the doctrine note at the
// blocklist itself.
//
// Restoring the old "…may cross-forward until the session identity is VRF-aware"
// wording reds this twice over: the suffix no longer matches, and "until" is on
// the forward list. Appending ". #2387 is closed wontfix; this is by design and
// permanent" reds it on the suffix; splicing the same text BEFORE the tail reds
// it on the foreclosing list, which is the span the suffix cannot reach.
func TestVRFOverlapWarningStatesStatusNotPromise(t *testing.T) {
	equal, unequal := vrfOverlapBothFormStrings(t)
	for _, tc := range []struct {
		form string
		warn string
	}{
		{"equal-prefix", equal},
		{"unequal-overlap", unequal},
	} {
		lower := strings.ToLower(tc.warn)
		for _, grp := range []struct {
			verb   string
			tokens []string
		}{
			{"forward-looking", vrfOverlapForwardLookingTokens},
			{"foreclosing", vrfOverlapForeclosingTokens},
		} {
			for _, tok := range grp.tokens {
				if strings.Contains(lower, tok) {
					// Report the SPELLING, not a verdict about meaning. This is a
					// substring test: a hit proves %q appears, NOT that the sentence
					// containing it forecasts anything. Accurate neutral prose can
					// trip it — "#2387 leaves both future end-states open" is caught
					// by "future" while forecasting nothing. Saying "this promises a
					// fix" would be a claim the check cannot support.
					t.Errorf("%s form contains the %s spelling %q. #2387 is an open decision, so the "+
						"warning must state the limitation and point at the issue without forecasting "+
						"either outcome. If this text IS neutral, reword to avoid the spelling — do not "+
						"add an exception to the list: %s",
						tc.form, grp.verb, tok, tc.warn)
				}
			}
		}
		if !strings.HasSuffix(tc.warn, vrfOverlapStatusTail) {
			t.Errorf("%s form does not END with the status sentence %q — the advisory must close "+
				"by stating the consequence and pointing at the open decision, with nothing "+
				"appended after it (an append that re-terminates with the tail verbatim would "+
				"satisfy this check; do not do that): %s",
				tc.form, vrfOverlapStatusTail, tc.warn)
		}
	}
}

// TestVRFOverlapWarningKeepsDiagnosticSubstance is the negative control for
// TestVRFOverlapWarningStatesStatusNotPromise. Dropping the promise must not
// cost the operator the diagnosis: the warning still has to say WHAT is wrong
// (steered flows share routing domain 0 in the session identity) and WHAT follows
// from it (colliding 5-tuples MAY cross-forward).
//
// What this control actually defends against is GUTTING the warning down to a
// bare issue reference — text that still passes the helper's selector, still
// carries both arm markers, and still ends with the exact status tail, but has
// lost the cause, the consequence, or the pairing that says which instance sits
// on which source and prefix. Measured on such a gut:
// TestVRFOverlapWarningStatesStatusNotPromise stays GREEN and this test reds. Be
// precise about how much that proves — TestVRFOverlapWarnsOnOverlappingRIs also
// reds there, because that particular gut drops "NOT session-isolated", which it
// asserts too. The cell where this control is the ONLY red in the file is
// stripping the "…share routing domain 0 in the session identity, so " clause while
// leaving the tail intact: promise GREEN, six pre-existing GREEN, this one RED.
// That is the measurement that makes it load-bearing rather than duplicative.
//
// An earlier revision of this comment said the promise test "is satisfied just as
// well by deleting the warning text wholesale". The word doing the damage is
// "wholesale": a WHOLESALE delete does red the promise test, at
// vrfOverlapBothFormStrings' one-warning-per-fixture Fatalf, because the
// diagnosis selector no longer matches anything. It is the skeleton-preserving
// gut, not the wholesale delete, that this control alone catches.
func TestVRFOverlapWarningKeepsDiagnosticSubstance(t *testing.T) {
	equal, unequal := vrfOverlapBothFormStrings(t)
	for _, tc := range []struct {
		form string
		warn string
		// ident is the WHICH of the diagnosis: which routing-instances, reached
		// through which config source, over which prefix.
		//
		// These are ORDERED PAIRINGS held as one contiguous substring, not a
		// list of tokens to find somewhere in the message. Presence and
		// association are different properties, and only the second is useful:
		// a token list is satisfied while every identifier is attached to the
		// WRONG object. Both format strings interleave the two instances'
		// identifiers — the equal-prefix arm substitutes FIVE arguments (two
		// name/origin pairs plus the single prefix they share), the unequal arm
		// SIX (a full (name, origin, prefix) triple each) — which is exactly
		// where an argument transposition happens, and `go vet` cannot see it,
		// because every argument is a string or Stringer feeding %q/%s, so the
		// printf checker reports nothing.
		//
		// Measured on the token-list version: swapping the two origins, or the
		// two RI names, or the two prefixes, left `go test ./pkg/config/
		// -count=1` fully green and `go vet ./pkg/config/` silent, while the
		// operator was sent to the wrong interface or told the wrong prefix
		// sits on the wrong instance. Fixture truth is
		// RI-A <- ge-0/0/1.0 @ 10.0.0.0/24 and RI-B <- ge-0/0/2.0 @ 10.0.0.0/25.
		//
		// The pairing form is a strict replacement, not an addition: a strip
		// breaks the contiguous substring too, so it still catches everything
		// the token list caught.
		ident []string
	}{
		{
			form: "equal-prefix",
			warn: equal,
			ident: []string{
				`"RI-A" (interface "ge-0/0/1.0") and "RI-B" (interface "ge-0/0/2.0") both carry 10.0.0.0/24`,
			},
		},
		{
			form: "unequal-overlap",
			warn: unequal,
			// One pairing per instance: this arm's whole reason to exist is
			// that the two prefixes DIFFER, so each must stay bound to its own
			// instance and origin.
			ident: []string{
				`"RI-A" (interface "ge-0/0/1.0", 10.0.0.0/24)`,
				`"RI-B" (interface "ge-0/0/2.0", 10.0.0.0/25)`,
			},
		},
	} {
		// The explanation: what is wrong and what follows from it. Each entry
		// carries its own POLARITY, because a bare noun does not. "cross-forward"
		// alone was satisfied by "colliding 5-tuples CANNOT cross-forward", which
		// tells the operator the exact opposite of the truth — the hazard reads as
		// a reassurance and the topology looks safe. Assert the claim, not the
		// vocabulary: subject + modality + verb as one contiguous span, and the
		// cause with the "no" that makes it a cause.
		for _, want := range []string{
			"NOT session-isolated",
			"flows PBR steers in from default-instance ingress share routing domain 0 in the session identity",
			"colliding 5-tuples may cross-forward",
		} {
			if !strings.Contains(tc.warn, want) {
				t.Errorf("%s form lost diagnostic substance %q: %s", tc.form, want, tc.warn)
			}
		}
		// The identification: which objects the explanation is about.
		for _, want := range tc.ident {
			if !strings.Contains(tc.warn, want) {
				t.Errorf("%s form no longer states the pairing %q — the warning explains the hazard "+
					"but not which routing-instance sits on which source and prefix: %s",
					tc.form, want, tc.warn)
			}
		}
	}
}
