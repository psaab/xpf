package config

import (
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// #8690: the normalizer's SCOPE is a safety claim, and this re-derives it from
// measurement on every run rather than trusting the list in
// compactNormalizeInScope.
//
// The rule #8689 established: a site may be normalized only once its elided
// spelling compiles identically to the EMPTY stanza — a positive measurement
// that no reader consumes the packed tail today, so moving it into a child
// cannot break one. Some containers DO read their tail (`redundancy-group 0
// node 0 priority 200` is the shipped HA spelling), which is why membership is
// by measurement and not by family name.
//
// THE RULE IS SUFFICIENT, NOT NECESSARY, and building this cell is what showed
// that. "Elided compiles to empty" proves the tail reaches no reader, so moving
// it cannot lose anything — but a reader that handles BOTH shapes is equally
// safe and is not empty-equivalent. `chassis cluster authentication-key` is
// exactly that: #8689 admitted it, `compileChassis` reads the packed tail AND
// the child, and both spellings compile the PSK correctly. An "must be
// empty-equivalent" assertion would have demanded its removal from a working
// increment.
//
// So what this asserts is the property the rule is a proxy FOR: for every site
// the gate admits, normalizing must not change the compiled result — the
// elided spelling with the pass applied must equal the braced spelling. A
// widening that admits a tail whose reader only understands the packed form
// reds here, with the site named, which is the `redundancy-group 0 node 0
// priority 200` failure. Empty-equivalence is reported alongside, because it is
// still the cheapest evidence when it holds.
func TestCompactNormalizeScopePreservesCompiledResult8690(t *testing.T) {
	var admitted, violating, disarmed, fixtureLimited, introducedRejection []string
	emptyEquivalent := 0
	seamObserved := 0
	// SKIP ACCOUNTING. Making admission behavioural gave this loop a failure
	// mode the earlier version could not have: it drives real parses and
	// compiles, so it can now SKIP a site — and a site it skipped is not a site
	// it found safe. Reported per reason, and the in-scope bucket is an error,
	// because that one is a site production DOES normalize and this cell did
	// not examine. (Credit: lane-8015 found this shape in the partial-site
	// guard when making it behavioural; it applies identically here.)
	var unsynthesizable, unparsable []string
	var inScopeUnexaminable []string
	for _, s := range collectCompactSites() {
		if len(s.container) == 0 || strings.HasPrefix(s.container[0], "groups") {
			continue
		}
		parent := s.container[:len(s.container)-1]
		stanza := s.container[len(s.container)-1]
		siteKeyEarly := strings.Join(s.container, " ") + " " + s.leaf
		v1, v2, ok := synthPair(s.node)
		if !ok {
			// No distinguishing pair of values, so scope cannot even be
			// determined for this site — it is UNKNOWN, not safe.
			unsynthesizable = append(unsynthesizable, siteKeyEarly)
			continue
		}
		ctx := contextFor(parent)
		siteKey := strings.Join(s.container, " ") + " " + s.leaf
		elidedText := nest(parent, ctx+stanza+" "+s.leaf+" "+v1+";")

		// ADMISSION COMES FROM THE PASS, NOT FROM A RE-DERIVED MODEL OF IT.
		//
		// The obvious spelling here is `compactNormalizeInScope(stanza,
		// s.leaf)`, and it is WRONG in a way that hides sites. Production calls
		// the predicate with `node.Keys[0]` — the stanza KEYWORD — while this
		// walk's container path carries the schema ARG PLACEHOLDER in that
		// position for any stanza that takes a name. So for `system login user
		// u1 { class ...; }` production asks about ("user", "class") and the
		// re-derived version asks about ("xpfarg", "class"), which no case
		// matches. The guard would then skip the very site being widened and
		// report a clean scope.
		//
		// That is the dangerous direction of error: under-admitting means
		// production normalizes something this cell never examined. So admit by
		// running the actual pass and asking whether it TOUCHED the tree. No
		// model, no drift.
		probe, perrs := NewParser(elidedText).Parse()
		if len(perrs) > 0 || probe == nil {
			unparsable = append(unparsable, siteKey)
			continue
		}
		if normalizeCompactStanzas(probe) == 0 {
			continue // production leaves this site alone; not in scope
		}
		cb1 := compileText(t, nest(parent, ctx+stanza+" { "+s.leaf+" "+v1+"; }"))
		cb2 := compileText(t, nest(parent, ctx+stanza+" { "+s.leaf+" "+v2+"; }"))
		ce := compileText(t, nest(parent, ctx+stanza+" { }"))
		if cb1 == nil || cb2 == nil || ce == nil {
			// The pass DOES normalize this site (checked above), but a
			// reference spelling would not compile, so the safety property
			// could not be evaluated. That is the dangerous bucket.
			inScopeUnexaminable = append(inScopeUnexaminable, siteKey)
			continue
		}
		if cfgEqual(cb1, cb2) {
			continue // the value is not observable here; nothing to protect
		}
		admitted = append(admitted, siteKey)

		// THE SAFETY PROPERTY: with the pass applied, the elided spelling must
		// compile to what the braced spelling compiles to. If it does not, the
		// normalization moved a tail its reader only understood in place.
		cc := compileText(t, elidedText)
		if cc == nil || !cfgEqual(cb1, cc) {
			violating = append(violating, siteKey)
			continue
		}
		// SECOND ARM — the one the "preserves the compiled result" check above
		// is STRUCTURALLY BLIND TO. That check asks whether elided-with-pass
		// equals braced, which is what the pass is FOR: it reports success
		// exactly when the pass did its job. It therefore cannot tell
		// "made a harmless spelling compile correctly" apart from
		// "converted a deliberate commit-time REJECTION into a silent
		// acceptance" — in both cases elided ends up equal to braced.
		//
		// That second case is a real defect and it happened during this
		// increment: admitting `user`/`class` made `system login user u1
		// class super-user;` compile clean where the #6662 gate had rejected
		// it. The normalizer runs at compiler.go:210 and that gate at :349,
		// so a rewritten tree reaches the gate with nothing left to reject.
		//
		// So: compile the elided spelling through the STRICT commit path with
		// the pass disabled. If it was rejected there and is accepted with the
		// pass on, the pass is not normalizing a spelling — it is disarming a
		// gate, and that has to be a deliberate registered decision.
		// THREE STATES, not two. The harmful case is a rejection becoming an
		// ACCEPTANCE. But a site can also fail with the pass enabled for an
		// unrelated reason — the census fixture supplies one synthesized value
		// per leaf, and it is not always type-valid for that leaf's validator
		// (`dhcpv6 ... fixed-address` gets an IPv4 literal, so it trades "has
		// no fixed-address" for "is not an IPv6 address").
		//
		// A two-state test folds that third case into "safe", because the
		// pass-enabled compile did not succeed. That is the fixture answering,
		// not the site: under a type-valid value the same site might well
		// compile clean and be a real disarm. So it is counted and named
		// separately rather than silently passing.
		// WHAT THIS ARM CANNOT SEE AT ALL, and why a green arm 2 does NOT mean a
		// widening is safe. It compiles ONE well-formed elided spelling and
		// compares acceptance against rejection. Any gate whose predicate needs
		// something that single spelling cannot express is invisible to it BY
		// CONSTRUCTION, not by oversight. Three kinds are known, all found by
		// ordinary cells in the full suite after arm 2 passed:
		//
		//   - a gate that fires on a DUPLICATE. `chassis ... ip-monitoring
		//     global-weight` rejects "specified 2 times with different values";
		//     one spelling cannot be two occurrences.
		//   - a gate that fires on a TRAILING TOKEN. `security ike gateway <g>
		//     dynamic hostname <fqdn> <extra>` rejects the extra token; the
		//     synthesized fixture supplies a well-formed value and no extra.
		//   - CONTENT SURVIVAL across a multi-statement packed body. A
		//     `redundancy-group` body loses `preempt` when its tail is moved,
		//     which is a wrong compiled result rather than a wrong verdict, so
		//     an acceptance comparison never looks at it.
		//
		// SO: RUN THE FULL pkg/config SUITE AFTER A WIDENING. It is not
		// redundant with this cell; it is the only thing that catches the three
		// above, and each was caught that way rather than here.
		//
		// The duplicate case is also circular in a way worth keeping: those
		// chassis sites are ABSENT FROM THE CENSUS precisely because the gate
		// rejects their packed spelling — so an over-reach analysis based on
		// the inventory cannot see them either. Absence caused by the very gate
		// the widening would disarm.
		//
		// LIMITATION, stated because this arm's failure condition is coarser
		// than the harm it is named for. A rejection becoming an acceptance is
		// harmful only when the gate was refusing the packed SPELLING on
		// purpose. There is a second, benign kind: a gate that rejects because
		// the elided spelling DROPPED something, where the pass repairs the
		// drop and the acceptance is the correct outcome. Measured example —
		// `nat source rule-set <r> rule <r> match source-address 10.0.0.0/8;`
		// is refused by the #8430 empty-match gate without the pass ("the
		// dataplane reads an EMPTY match set as UNCONSTRAINED ... would
		// translate EVERY packet") and compiles clean with it, because the
		// criterion survives. That is the pass working.
		//
		// Both shapes trip the condition below, so a widening that legitimately
		// resolves a drop-caused gate will red here and needs a human decision
		// rather than a mechanical fix. The #6662 login case is the harmful
		// kind: the braced form was always accepted, nothing was dropped, and
		// the gate existed to refuse that spelling across an HA version skew.
		// Distinguishing them automatically would need the gates themselves to
		// declare which kind they are; until then this arm reports and a person
		// classifies.
		off := compileStrict8690(t, elidedText, true)
		on := compileStrict8690(t, elidedText, false)
		switch {
		case off != nil && on == nil:
			disarmed = append(disarmed, siteKey)
		case off != nil && on != nil && on.Error() != off.Error():
			fixtureLimited = append(fixtureLimited, siteKey)
		case off == nil && on != nil:
			// THE OTHER DIRECTION, which this arm did not look at until a hand
			// measurement turned one up. The pass can also turn an ACCEPTANCE
			// into a REJECTION, and that is usually the gate working rather
			// than breaking: elided `from-zone <a> to-zone <b> policy p1;` is
			// accepted without the pass because the tail is dropped and no
			// policy is created for anything to object to, and is refused with
			// it by the #3044 missing-criterion gate because the policy now
			// exists. A silent loss became a loud rejection.
			//
			// Reported rather than failed, for that reason — but reported,
			// because the same signature would appear if the pass MANGLED a
			// stanza into something invalid, and nothing else in this cell
			// would notice. It is also a commit-compatibility fact: a config
			// that committed clean stops committing. (The tolerant load path
			// is what governs whether that strands a node, and for the known
			// instance it accepts both spellings.)
			introducedRejection = append(introducedRejection, siteKey)
		}
		// SEAM LIVENESS. The check above reads "rejected without the pass,
		// accepted with it". If skipCompactNormalize stopped being honoured,
		// both sides would run the pass, nothing would ever be rejected, and
		// the arm would report a clean scope for the same reason a correct one
		// does — vacuous, and indistinguishable from healthy. So record that
		// the flag actually changed an outcome somewhere: for an
		// empty-equivalent site the un-normalized compile drops the tail and
		// the normalized one keeps it, which must be observable.
		if a, b := compileSeam8690(t, elidedText, true), compileSeam8690(t, elidedText, false); a != nil && b != nil && !cfgEqual(a, b) {
			seamObserved++
		}

		// Informational: was this site also empty-equivalent before the pass
		// existed? That is #8689's stated rule and the cheapest evidence, but a
		// reader handling both shapes is safe without it.
		if compactElidedCompilesEmpty(t, parent, ctx, stanza, s.leaf, v1, ce) {
			emptyEquivalent++
		}
	}
	sort.Strings(admitted)
	sort.Strings(violating)
	sort.Strings(disarmed)
	sort.Strings(fixtureLimited)
	sort.Strings(introducedRejection)

	// DEGENERACY GUARD: a walk that admitted nothing would report a clean scope
	// for the same reason a correct one does.
	if len(admitted) == 0 {
		t.Fatal("the scope walk admitted NO site — either collectCompactSites " +
			"stopped producing them or compactNormalizeInScope stopped admitting " +
			"any, and either way this cell is measuring nothing (#8690)")
	}
	if seamObserved == 0 {
		t.Fatal("the skipCompactNormalize seam changed NO outcome across every " +
			"admitted site. The rejection-vs-acceptance arm above depends on " +
			"that flag actually disabling the pass; if it is being ignored, the " +
			"arm silently reports a clean scope no matter what is admitted. " +
			"Fix the seam before trusting this cell (#8690)")
	}
	t.Logf("#8690 normalizer scope: %d admitted sites, %d of them empty-equivalent "+
		"(the rest are read correctly in BOTH shapes, which is equally safe)",
		len(admitted), emptyEquivalent)

	if len(violating) > 0 {
		t.Errorf("%d site(s) are in the normalizer's scope where normalizing "+
			"CHANGES the compiled result: %v.\n"+
			"The elided spelling no longer compiles to what the braced spelling "+
			"does, which means the tail was moved away from a reader that only "+
			"understood it in place — the `redundancy-group 0 node 0 priority "+
			"200` failure. Remove them from compactNormalizeInScope (#8690).",
			len(violating), violating)
	}

	sort.Strings(inScopeUnexaminable)
	if n := len(unsynthesizable) + len(unparsable); n > 0 {
		t.Logf("#8690 scope walk skipped %d site(s) before scope could be "+
			"determined (%d unsynthesizable, %d unparsable). Those are UNKNOWN "+
			"to this cell, not safe — the same gap a behavioural guard acquires "+
			"in exchange for not modelling the predicate.",
			n, len(unsynthesizable), len(unparsable))
	}
	// The in-scope-but-unexaminable set is asserted for EQUALITY against a
	// checked-in list, the same shape as the #2419 inventory itself: a new
	// member reds because the pass started rewriting something this cell cannot
	// see, and a member that becomes examinable ALSO reds, so the list cannot
	// quietly outlive its reason. A bare threshold would permit both.
	if diff := diffSiteSets8690(inScopeUnexaminable, knownUnexaminable8690); diff != "" {
		t.Errorf("the set of sites the pass normalizes but this cell cannot "+
			"EXAMINE has changed:\n%s\n"+
			"Production rewrites these and the cell says nothing about them, so "+
			"they are counted as neither safe nor unsafe — silence that reads "+
			"as a clean scope. A NEW entry means a widening admitted a site "+
			"whose reference spelling will not compile in isolation; give it a "+
			"compilable fixture (a required sibling is usually missing) rather "+
			"than adding it here. A REMOVED entry means one became examinable "+
			"and the list should shrink (#8690).", diff)
	}
	// The bucket is asserted for EQUALITY, not merely reported. lane-8526's
	// point, one axis over from where it was raised: a site cannot silently
	// become HARMFUL here, because the classification is recomputed from a live
	// switch every run and a site whose fixture becomes type-valid falls into
	// the disarm branch and reds. But the bucket could silently GROW — a
	// widening admitting fifty sites whose gate status cannot be determined
	// logged a bigger number and passed. A category that only accumulates stops
	// being a measurement and becomes a registration.
	if diff := diffSiteSets8690(fixtureLimited, sortedKeys8690(knownFixtureLimited8690)); diff != "" {
		t.Errorf("the set of admitted sites whose GATE STATUS cannot be "+
			"measured has changed:\n%s\n"+
			"A NEW entry means a widening admitted a site where the census "+
			"fixture's value fails a different validator with the pass enabled, "+
			"so nothing was learned about whether a gate was disarmed — that is "+
			"unmeasured, not safe, and it needs a deliberate decision rather "+
			"than a bigger number in a log line. A REMOVED entry means one "+
			"became measurable (usually improved value synthesis) and the list "+
			"should shrink.\n"+
			"MEASURE A NEW ENTRY BY HAND before adding it — write the site out "+
			"with a type-VALID value and compare strict compiles with the pass "+
			"disabled and enabled. This bucket is where a disarm hides: "+
			"`security dynamic-address feed-server <n> url` sat here reported "+
			"as merely unmeasured, and hand-measurement with a real URL showed "+
			"it rejected without the pass and accepted with it. Visibility is "+
			"not a verdict (#8690).", diff)
	}
	if n := len(introducedRejection); n > 0 {
		// COUNT, not the list. Measured at 64 sites, and spot-checking showed
		// they are the pass DOING ITS JOB rather than a hazard: the elided
		// spelling drops its tail, so without the pass nothing is created and
		// no validator has anything to object to; with the pass the stanza
		// exists and its own validator says what is missing.
		//
		//	chassis device-map interface ge-0-0-0;
		//	  pass OFF -> accepted (no device-map entry exists)
		//	  pass ON  -> "interface ge-0-0-0 has neither a pci nor a mac
		//	              identity key" -- correct, and previously silent
		//
		// The complete spelling (`interface ge-0-0-0 { pci ...; }`) is accepted
		// both ways, so this is not a regression on real configs. Printing all
		// 64 every run would read as a warning list and be ignored, which is
		// worse than a number with its meaning attached.
		//
		// It is still counted, because the SAME signature would appear if the
		// pass mangled a stanza into something invalid. A jump here after a
		// widening is worth a look; a steady number is the pass converting
		// silent losses into diagnostics. And before assuming any instance is
		// harmless, check the TOLERANT path -- a persisted config that stops
		// loading strands a node (#1960); for the instance measured by hand,
		// load/peer-sync accepts both spellings.
		t.Logf("#8690: %d admitted site(s) are accepted WITHOUT the pass and "+
			"rejected WITH it -- the pass making a dropped tail visible to the "+
			"stanza's own validator. Not a defect list; see the note above "+
			"before treating a change in this number as one.", n)
	}
	// EVERY BUCKET ENTRY MUST CARRY A HAND-MEASURED VERDICT. This is a hard
	// failure, and it is enforceable only because the backlog was driven to
	// zero first -- with entries outstanding it would have had to grandfather
	// them and would have been born weak.
	//
	// The reason it is not a reported count: a count starts at zero and grows
	// one entry at a time, each addition individually defensible, and the whole
	// history of this bucket is that visible-but-unmeasured reads as clean. A
	// category that only accumulates stops being a measurement and becomes a
	// registration. lane-8015 measured three entries here by hand and one was a
	// would-be gate disarm that no other guard in the tree would have caught.
	//
	// The escape hatch is not a threshold, it is a person: write the site out
	// with a type-valid value and the siblings its validator needs, and record
	// what you found. That is the same shape as `benign` -- adding an entry is
	// recording a verdict, never a number going up.
	var unmeasured []string
	for site, verdict := range knownFixtureLimited8690 {
		if verdict == notHandMeasured8690 {
			unmeasured = append(unmeasured, site)
		}
	}
	sort.Strings(unmeasured)
	if len(unmeasured) > 0 {
		t.Errorf("%d of %d entries in the gate-status-unknown bucket have NO "+
			"hand-measured verdict: %v.\n"+
			"An entry here is a QUESTION, not a finding: the census fixture could "+
			"not decide whether the pass disarms a gate at that site, and arm 2 "+
			"passing is the absence of evidence rather than evidence. Write the "+
			"site out with a type-valid value and the siblings its validator "+
			"needs, compare strict compiles with the pass disabled and enabled, "+
			"and record what you found. If it is still undecidable, say so and "+
			"say why -- but check the FIXTURE first, because one that is wrong in "+
			"a new way reports the same word as a site that genuinely cannot be "+
			"decided (#8690).", len(unmeasured), len(knownFixtureLimited8690), unmeasured)
	}
	if len(fixtureLimited) > 0 {
		t.Logf("#8690: %d admitted site(s) could not have their gate status "+
			"measured, because the census fixture's value fails a different "+
			"validator with the pass enabled: %v.\n"+
			"These are NOT known-safe — a type-valid value might compile clean "+
			"and make them real disarms. They are reported rather than folded "+
			"into the clean count so the distinction stays visible.",
			len(fixtureLimited), fixtureLimited)
	}
	// STEP 3 of the rule, given somewhere to live. The arm above cannot
	// distinguish a gate refusing the packed SPELLING (harmful to disarm) from
	// one refusing the CONSEQUENCE OF THE DROP, where the pass repairs the drop
	// and the acceptance is the correct outcome. That distinction needs a
	// person, and a person's verdict needs a home — otherwise a benign disarm
	// blocks its family forever and the only way forward is to drop a real fix.
	//
	// An entry here is a CLASSIFICATION with its evidence, not a suppression,
	// and it is held to the same standard as #8704's deepDupUnreportable: the
	// cell below fails for a listed site that is NOT currently disarming, so a
	// stale entry — one whose gate was retired, or whose site left the scope —
	// reds instead of quietly excusing the next real disarm that lands on the
	// same key.
	benign := map[string]string{
		"security ipsec policy xpfarg proposal-set": "the gate refuses the CONSEQUENCE of the " +
			"drop, and says so in its own message. Measured: with the pass disabled the elided " +
			"`policy p1 proposal-set standard;` loses the proposal-set and the gate rejects with " +
			"\"has no resolvable ipsec proposal ... the configured perfect-forward-secrecy group " +
			"would be SILENTLY DROPPED\"; with the pass enabled the proposal-set survives and the " +
			"same gate accepts. The braced spelling — the reference behaviour — is accepted " +
			"either way, so the config is legitimate and only the elided form was losing it. " +
			"This gate was written to catch exactly this drop class, so the pass repairing the " +
			"drop and the gate then passing is the intended interaction, not a disarm.",
		// The three sites admitted with the #8690 `open` residue. All three were
		// re-measured HERE with the pair ADMITTED, which is the only state in
		// which the measurement means anything: for an EXCLUDED pair the pass
		// touches 0 nodes, so `passDisabled` true and false are the same run and
		// a "the pass is not load-bearing here" result is a restatement of the
		// exclusion rather than a finding about the site. lane-8015 established
		// that on `policy scheduler-name`. Here the axis genuinely moves — the
		// elided spelling flips REJECTED -> accepted — which is what makes these
		// gradeable at all.
		//
		// Measured, with type-VALID values, all three identical in shape:
		//
		//	BRACED passDisabled=true   <nil>      <- the config is legitimate
		//	BRACED passDisabled=false  <nil>
		//	ELIDED passDisabled=true   REJECTED   <- the gate catches the drop
		//	ELIDED passDisabled=false  <nil>      <- the pass repairs it
		//
		// The braced leg is the one that decides benign-vs-genuine, and each
		// gate's own message names the MISSING VALUE rather than the spelling.
		"protocols bgp group xpfarg neighbor xpfarg peer-as": "the gate refuses the CONSEQUENCE of the drop. " +
			"Measured with the pass disabled, elided `neighbor 10.0.0.2 peer-as 65001;` " +
			"loses the peer-as and BGP rejects with \"missing/invalid peer-as — a BGP " +
			"neighbor requires a peer-as\"; with the pass enabled the value survives and " +
			"the same gate accepts. Braced is accepted either way. The gate names the " +
			"absent value, so it is objecting to the drop and the pass repairs it.",
		"security dynamic-address feed-server xpfarg hostname": "the gate refuses the CONSEQUENCE of the drop. " +
			"Measured with the pass disabled, elided `feed-server f1 hostname " +
			"\"feeds.example.com\";` loses the hostname and the compiler rejects with " +
			"\"feed-server \\\"f1\\\" resolves to an empty endpoint (no url or hostname, or a " +
			"slash-only url)\"; with the pass enabled it survives and the same gate " +
			"accepts. Braced is accepted either way.",
		"system services dhcp-local-server group xpfarg pool xpfarg static-binding xpfarg fixed-address": "the gate refuses the CONSEQUENCE of the " +
			"drop. Measured with the pass disabled, elided `static-binding b1 " +
			"fixed-address 10.0.1.50;` loses the address and the compiler rejects with " +
			"\"static-binding \\\"b1\\\" has no fixed-address — a reservation cannot be " +
			"empty\"; with the pass enabled it survives and the same gate accepts. " +
			"Braced is accepted either way. ONE key covers the dhcp and dhcpv6 twins " +
			"because they share dhcpStaticBindingSchema(); the v4 twin is what this arm " +
			"grades, and the v6 twin is hand-measured in knownFixtureLimited8690 " +
			"because the census fixture cannot give it a type-valid address.",
		"snmp trap-group xpfarg targets": "the gate refuses the CONSEQUENCE of the drop, not " +
			"the spelling. Measured: with the pass disabled the elided " +
			"`trap-group tg1 targets 10.0.0.1;` loses its targets and snmp rejects with " +
			"\"no targets configured (a trap group with zero targets sends no " +
			"notifications)\"; with the pass enabled the target survives and the same gate " +
			"accepts. The gate is doing its job in both cases — it is the DROP it objects " +
			"to, and the pass repairs the drop. Normalizing here makes the operator's " +
			"config mean what they wrote, which is the acceptance being correct rather " +
			"than the gate being disarmed. Same shape as the #8430 empty-match example " +
			"in the LIMITATION note above.",
	}
	var unclassified []string
	for _, site := range disarmed {
		if _, ok := benign[site]; !ok {
			unclassified = append(unclassified, site)
		}
	}
	for site := range benign {
		found := false
		for _, d := range disarmed {
			if d == site {
				found = true
			}
		}
		if !found {
			t.Errorf("site %q is classified benign in this cell but is NOT currently disarming "+
				"any gate. The classification is stale — its gate may have been retired or the "+
				"site may have left the scope — and a stale entry silently excuses the next "+
				"real disarm that lands on the same key. Delete it (#8690)", site)
		}
	}
	disarmed = unclassified
	if len(disarmed) > 0 {
		t.Errorf("%d site(s) in the normalizer's scope are REJECTED at strict "+
			"commit with the pass disabled and ACCEPTED with it enabled: %v.\n"+
			"That is not a spelling normalization — the pass runs before the "+
			"commit gates, so it is deleting the shape a gate was written to "+
			"refuse and turning a loud rejection into a silent acceptance "+
			"(the #6662 packed-login-body case). If the rejection is genuinely "+
			"obsolete, retire the GATE deliberately; do not disarm it as a side "+
			"effect of widening this scope (#8690).", len(disarmed), disarmed)
	}
}

// compactElidedCompilesEmpty compiles the elided spelling with the normalizer
// SUPPRESSED, so the question asked is the pre-normalization one: does the
// packed tail reach any reader?
func compactElidedCompilesEmpty(t *testing.T, parent []string, ctx, stanza, leaf, v string, empty *Config) bool {
	t.Helper()
	text := nest(parent, ctx+stanza+" "+leaf+" "+v+";")
	tree, perrs := NewParser(text).Parse()
	if len(perrs) > 0 || tree == nil {
		return true // unparseable here is the census's problem, not this cell's
	}
	// The same lenient opts compileText uses, plus the suppression — so the
	// only difference from the census's own measurement is the normalizer.
	opts := lenientCompileOpts()
	opts.skipCompactNormalize = true
	got, err := compileConfigWithOpts(tree, opts)
	if err != nil || got == nil {
		return true
	}
	got.Warnings = nil
	return cfgEqual(got, empty)
}

// #8690: the normalizer must not DISARM a commit gate, and this is the cell
// that caught it doing exactly that during development.
//
// The pass runs at compiler.go:210; the #6662 packed-login-body gate runs at
// :349. So a tree the normalizer has rewritten reaches that gate ALREADY
// un-packed, and the gate sees nothing to reject. Admitting `user`/`class` to
// scope turned this:
//
//	system login user u1 class super-user;   -> REJECTED at commit, with the
//	    error naming the consequence ("the account resolves to the fail-closed
//	    `unauthorized` class ... on a binary before #6701 it instead reached the
//	    legacy no-RBAC allow-everything mode")
//
// into a clean compile. That is not a spelling change: it converts a loud
// commit-time refusal into a silent acceptance, and makes an RBAC class compile
// on this binary that a peer on an older one still drops — the same HA-skew
// hazard #6662 was decided on.
//
// `filedByDesign` lists the four `system login user <u> authentication` leaves
// and NOT `class`, so the registry alone would not have stopped this. The gate
// governs the whole packed login body; only running it before and after shows
// that. Hence the exclusion in compactNormalizeInScope is by CONTAINER.
func TestCompactNormalizeDoesNotDisarmTheLoginPackedGate8690(t *testing.T) {
	tree, perrs := NewParser("system { login { user u1 class super-user; } }").Parse()
	if len(perrs) > 0 {
		t.Fatalf("parse: %v", perrs)
	}
	if _, err := CompileConfig(tree); err == nil {
		t.Error("a packed `system login user <u> class ...` body COMPILED CLEAN. " +
			"The #6662 gate must still reject it: normalizing that body before " +
			"the gate runs converts a commit-time refusal into a silent " +
			"acceptance and changes RBAC across an HA sync between binaries " +
			"that disagree (#8690)")
	}

	// ANTI-OVER-REJECT: the braced spelling is the one #6662 tells the operator
	// to write, so it must still compile. A gate that rejected both would
	// satisfy the assertion above while making the documented remedy fail.
	braced, perrs := NewParser("system { login { user u1 { class super-user; } } }").Parse()
	if len(perrs) > 0 {
		t.Fatalf("parse braced: %v", perrs)
	}
	if _, err := CompileConfig(braced); err != nil {
		t.Errorf("the BRACED login body must still compile — it is the rewrite "+
			"#6662's own error message instructs the operator to make: %v", err)
	}
}

// compileStrict8690 compiles through the STRICT commit path — the one that runs
// the commit gates — optionally with the brace-elided normalizer disabled via
// the compileOpts seam. It returns the compile error so a caller can compare
// ACCEPTANCE against REJECTION, which is the distinction the compiled-result
// comparison cannot make.
func compileStrict8690(t *testing.T, text string, skipNormalize bool) error {
	t.Helper()
	tree, perrs := NewParser(text).Parse()
	if len(perrs) > 0 {
		return fmt.Errorf("parse: %v", perrs)
	}
	_, err := compileConfigWithOpts(tree, compileOpts{skipCompactNormalize: skipNormalize})
	return err
}

// compileSeam8690 is compileStrict8690 returning the compiled Config, used to
// prove the seam is LIVE — see the seamObserved guard.
func compileSeam8690(t *testing.T, text string, skipNormalize bool) *Config {
	t.Helper()
	tree, perrs := NewParser(text).Parse()
	if len(perrs) > 0 {
		return nil
	}
	cfg, err := compileConfigWithOpts(tree, compileOpts{skipCompactNormalize: skipNormalize})
	if err != nil || cfg == nil {
		return nil
	}
	cfg.Warnings = nil
	return cfg
}

// #8690 requirement: the pass must run at BOTH compile entry points.
//
// It is wired at both (compiler.go, compileConfigWithOpts and the node-aware
// sibling behind CompileConfigForNode), and until this cell existed that
// wiring was untested: deleting the call from the node-aware path reds NOTHING
// in the whole pkg/config suite. That path is the cluster one — Store.SyncApply
// and peer-interface display compile a peer's config through it — so losing the
// pass there does not fail, it makes a peer compile the SAME config
// DIFFERENTLY from the node that authored it. The authoring node folds the
// packed credential into a child and the peer leaves it packed; the two nodes
// then disagree about a pre-shared key or an authentication algorithm while
// both report a clean commit. That is the #8597 K51 asymmetry class, and it is
// exactly what the comment at that call site warns about.
//
// So this asserts the AGREEMENT between the two entry points rather than a
// literal compiled value: a future change to what the pass produces stays
// green here as long as both paths produce it, and any divergence reds.
func TestCompactNormalizeRunsAtBothCompileEntryPoints8690(t *testing.T) {
	const elided = `security { ike { policy p1 { pre-shared-key ascii-text "s3cret"; } } }`
	const packed = `security { ike { policy p1 pre-shared-key ascii-text "s3cret"; } }`

	// POSITIVE CONTROL: the pass must actually touch this input, or the
	// agreement below would hold for the trivial reason that there is nothing
	// to do — the same green a correctly-wired pair produces.
	probe, perrs := NewParser(packed).Parse()
	if len(perrs) > 0 {
		t.Fatalf("parse: %v", perrs)
	}
	if n := normalizeCompactStanzas(probe); n == 0 {
		t.Fatalf("the fixture is not in the normalizer's scope, so this cell " +
			"cannot observe whether either entry point runs it. Pick a packed " +
			"stanza compactNormalizeInScope admits (#8690)")
	}

	braced := compileText(t, elided)
	if braced == nil {
		t.Fatal("the braced spelling must compile — it is the reference result")
	}
	viaPlain := compileText(t, packed)
	if viaPlain == nil || !cfgEqual(braced, viaPlain) {
		t.Error("the PLAIN entry point did not normalize the packed spelling to " +
			"the braced result (#8690)")
	}

	tree, perrs := NewParser(packed).Parse()
	if len(perrs) > 0 {
		t.Fatalf("parse: %v", perrs)
	}
	viaNode, err := CompileConfigForNodeLenient(tree, 0)
	if err != nil || viaNode == nil {
		t.Fatalf("node-aware compile of the packed spelling failed: %v", err)
	}
	viaNode.Warnings = nil
	if !cfgEqual(viaPlain, viaNode) {
		t.Error("the two compile entry points DISAGREE on the packed spelling. " +
			"The node-aware path (Store.SyncApply, peer display) is not running " +
			"the brace-elided normalizer, so a cluster peer compiles this " +
			"credential differently from the node that authored it while both " +
			"report a clean commit — the #8597 K51 asymmetry class (#8690)")
	}
}

// The consequential member of family 3, asserted on the compiled config.
//
// `system services ssh root-login deny;` decides whether root may log in at
// all. Brace-elided, the value used to be dropped and the field compiled to
// "", which is not "deny" — the operator wrote a lockout and got the daemon's
// default, on a commit that reported success. That is the same shape as
// #8689's IS-IS authentication key and family 2's zone screen binding: a
// security control silently absent rather than loudly wrong.
//
// The seam supplies the positive half. Without it this cell would assert only
// that two spellings agree, which they would also do if the pass were removed
// and BOTH dropped the value — the vacuous green that "assert the agreement"
// is otherwise vulnerable to.
func TestElidedSSHRootLoginReachesTheDaemon8690(t *testing.T) {
	const braced = `system { services { ssh { root-login deny; } } }`
	const elided = `system { services { ssh root-login deny; } }`

	b, e := compileText(t, braced), compileText(t, elided)
	if b == nil || e == nil {
		t.Fatalf("both spellings must compile (braced=%v elided=%v)", b != nil, e != nil)
	}
	if b.System.Services.SSH.RootLogin != "deny" {
		t.Fatalf("fixture is wrong: the braced spelling must set root-login, got %q",
			b.System.Services.SSH.RootLogin)
	}
	if e.System.Services.SSH.RootLogin != "deny" {
		t.Errorf("brace-elided `ssh root-login deny` compiled to RootLogin=%q, not \"deny\". "+
			"The operator wrote a root lockout and the daemon received the default, "+
			"on a commit that reported success (#8690)", e.System.Services.SSH.RootLogin)
	}

	// POSITIVE CONTROL: with the pass disabled the elided spelling must NOT
	// carry the value. If it does, this cell is not observing the pass and
	// would stay green if the pass were deleted.
	tree, perrs := NewParser(elided).Parse()
	if len(perrs) > 0 {
		t.Fatalf("parse: %v", perrs)
	}
	off, err := compileConfigWithOpts(tree, compileOpts{skipCompactNormalize: true})
	if err != nil || off == nil {
		t.Fatalf("un-normalized compile failed: %v", err)
	}
	if off.System.Services.SSH.RootLogin == "deny" {
		t.Error("with the normalizer DISABLED the elided spelling still carried " +
			"root-login, so this cell is not observing the pass and would stay " +
			"green if the pass were removed (#8690)")
	}
}

// knownUnexaminable8690 are sites the pass normalizes but whose reference
// spelling does not compile in isolation, so the safety property cannot be
// evaluated for them. They are NOT known-safe; they are known-unmeasured.
//
// Every entry needs a required sibling INSIDE the stanza that the synthesized
// fixture does not supply — a three-color-policer with no rate block, an
// ip-monitoring policy with no probe. That is the #8436 duplicate-block
// dependency lane-8526 measured: the compact spelling cannot carry the sibling
// and re-opening the instance does not merge, so these are unmeasurable by this
// method until #8436 lands, not merely unfixtured.
var knownUnexaminable8690 = []string{
	// #8690: this one is the INVERSE of every other entry, and the difference
	// is worth stating because the failure message tells the next person to
	// supply a missing sibling — which cannot work here.
	//
	// The cell evaluates three configs: `stanza { leaf v1; }`, `{ leaf v2; }`
	// and the EMPTY skeleton `stanza { }`. For every other entry the empty
	// skeleton fails because some OTHER required leaf is absent, so a richer
	// fixture fixes it. Here the empty skeleton fails because `test T1 { }` is
	// rejected with "target is required" — THE LEAF UNDER TEST IS ITSELF THE
	// REQUIRED SIBLING. Any fixture that makes the control compile has to
	// supply `target`, which is the value the control exists to omit.
	//
	// So this is not a fixture gap; it is a limit of the three-config method
	// for a leaf whose own presence is the stanza's validity condition. It is
	// listed rather than fixed, and the verdict comes from a HAND measurement
	// taken with the pair admitted and the pass both ways:
	//
	//	BLOCK   test T { target address 1.2.3.4; }   passOFF clean   passON clean
	//	COMPACT test T target address 1.2.3.4;       passOFF REJECT  passON clean, test registers
	//
	// which is the benign pattern — the gate refuses the consequence of the
	// drop and the pass repairs it. Its nine sibling leaves are NOT benign and
	// do not share this verdict; they are `sibling-blocked` in the register.
	"services rpm probe xpfarg test xpfarg target",

	"class-of-service fairness rss-expectation interface xpfarg queue",
	"class-of-service fairness rss-expectation interface xpfarg queue xpfarg active-workers",
	"class-of-service fairness rss-expectation interface xpfarg queue xpfarg at-least-active-workers",
	"class-of-service fairness rss-expectation interface xpfarg queue xpfarg cstruct",
	"class-of-service fairness rss-expectation interface xpfarg queue xpfarg cstruct-max",
	"class-of-service fairness rss-expectation interface xpfarg queue xpfarg max-worker-flow-share",
	"firewall three-color-policer",
	"firewall three-color-policer xpfarg single-rate committed-burst-size",
	"firewall three-color-policer xpfarg single-rate committed-information-rate",
	"firewall three-color-policer xpfarg single-rate excess-burst-size",
	"firewall three-color-policer xpfarg then loss-priority",
	"firewall three-color-policer xpfarg two-rate committed-burst-size",
	"firewall three-color-policer xpfarg two-rate committed-information-rate",
	"firewall three-color-policer xpfarg two-rate peak-burst-size",
	"firewall three-color-policer xpfarg two-rate peak-information-rate",
	"services ip-monitoring policy xpfarg match rpm-probe",
	"services ip-monitoring policy xpfarg then preferred-route route xpfarg next-hop",
	"services ip-monitoring policy xpfarg then preferred-route routing-instance xpfarg route xpfarg next-hop",
}

// diffSiteSets8690 returns a human-readable difference between a measured set and an
// expected one, or "" when they match.
func diffSiteSets8690(got, want []string) string {
	// Wording is deliberately NEUTRAL about why a site is in the set: this
	// helper serves two buckets with different meanings (unexaminable, and
	// gate-status-unmeasurable), and the caller's Errorf supplies the meaning.
	// It previously described only the first, so a diff in the second was
	// reported with a sentence that did not apply to it.
	w := map[string]bool{}
	for _, x := range want {
		w[x] = true
	}
	g := map[string]bool{}
	for _, x := range got {
		g[x] = true
	}
	var b strings.Builder
	for _, x := range got {
		if !w[x] {
			b.WriteString("  NEW (measured now, not in the checked-in set): " + x + "\n")
		}
	}
	for _, x := range want {
		if !g[x] {
			b.WriteString("  GONE (in the checked-in set, no longer measured): " + x + "\n")
		}
	}
	return b.String()
}

// #8690: every rule in compactNormalizeInScope must be scoped by (container,
// head) PAIR — never by a head alone, never by a container alone.
//
// This is not style. A head-only rule is safe only while no container acquires
// that head with a tail somebody reads; a container-only rule is safe only
// while no head appears under that container that somebody reads. Both make
// the predicate's correctness contingent on the CURRENT INVENTORY rather than
// on the rule, and this sweep moves the inventory. Such a rule therefore fails
// at the moment a family lands — inside someone else's merge conflict.
//
// Both directions really existed here. `head == "authentication-key"` was
// head-only, and `containerKeyword == "match"` was container-only and admitted
// `services ip-monitoring policy <p> match rpm-probe` — a different feature in
// a different subtree, reached only because it spells its criteria block
// `match`.
//
// The probe is a sentinel that cannot occur in any config: if the predicate
// still says yes when the container is replaced by a token no schema contains,
// it was not reading the container.
func TestNormalizerScopeIsPairScopedNotTokenScoped8690(t *testing.T) {
	const noSuchContainer = "xpf-no-such-container-8690"
	const noSuchHead = "xpf-no-such-head-8690"

	var headOnly, containerOnly []string
	checked := 0
	var walk func(n *schemaNode, kw string, depth int)
	walk = func(n *schemaNode, kw string, depth int) {
		if n == nil || depth > 9 {
			return
		}
		for name, ch := range n.children {
			if kw != "" && compactNormalizeInScope(kw, name) {
				checked++
				if compactNormalizeInScope(noSuchContainer, name) {
					headOnly = append(headOnly, kw+" "+name)
				}
				if compactNormalizeInScope(kw, noSuchHead) {
					containerOnly = append(containerOnly, kw+" "+name)
				}
			}
			walk(ch, name, depth+1)
		}
		if n.wildcard != nil {
			walk(n.wildcard, kw, depth+1)
		}
	}
	walk(setSchema, "", 0)

	// DEGENERACY CONTROL: if the walk admitted nothing, both checks above are
	// vacuous and this cell reports a clean scope for the same reason a correct
	// one does.
	if checked == 0 {
		t.Fatal("the schema walk found NO admitted pair, so the pair-scoping " +
			"assertions ran against nothing. Either the walk broke or the " +
			"predicate stopped admitting anything (#8690)")
	}
	sort.Strings(headOnly)
	sort.Strings(containerOnly)

	if len(headOnly) > 0 {
		t.Errorf("%d rule(s) admit on the HEAD ALONE — the predicate still says "+
			"yes with the container replaced by a token no schema contains: %v.\n"+
			"That rule is safe only until some other container acquires the same "+
			"head with a tail a reader consumes, and it will fail when a family "+
			"lands rather than when it is written. Scope it to the containers "+
			"that measured safe (#8690).", len(headOnly), dedupe8690(headOnly))
	}
	if len(containerOnly) > 0 {
		t.Errorf("%d rule(s) admit on the CONTAINER ALONE — the predicate still "+
			"says yes with the head replaced by a token no schema contains: %v.\n"+
			"That rule is safe only until some head appears under that container "+
			"that a reader consumes. `containerKeyword == \"match\"` was exactly "+
			"this and reached services ip-monitoring (#8690).",
			len(containerOnly), dedupe8690(containerOnly))
	}
	t.Logf("#8690: %d admitted (container, head) pair(s), none head-only or container-only", checked)
}

func dedupe8690(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, x := range in {
		if !seen[x] {
			seen[x] = true
			out = append(out, x)
		}
	}
	return out
}

// knownFixtureLimited8690 are admitted sites whose gate status could not be
// determined: with the pass enabled they fail a DIFFERENT validator than they
// fail with it disabled, because the census supplies one synthesized value per
// leaf and it is not always type-valid for that leaf (`dhcpv6 ...
// fixed-address` receives an IPv4 literal).
//
// They are NOT known-safe. Under a type-valid value any of them could compile
// clean and prove to be a real disarm. Listed rather than counted so that
// admitting a new one is a decision someone makes rather than a number that
// moves.
var knownFixtureLimited8690 = map[string]string{

	// HAND-MEASURED IN BULK. Each was written out with a type-VALID value and
	// the siblings its validator needs -- a NAT rule-set with a from/to zone
	// and a then-block, a global address-book for the `-name` leaves, a policy
	// with a then-block. That is what the census fixture cannot supply and why
	// these read as undecidable to the arm.
	"security nat destination rule-set xpfarg rule xpfarg match application":              natMatchBenign8690,
	"security nat destination rule-set xpfarg rule xpfarg match destination-address":      natMatchBenign8690,
	"security nat destination rule-set xpfarg rule xpfarg match destination-address-name": natMatchBenign8690,
	"security nat destination rule-set xpfarg rule xpfarg match destination-port":         natMatchBenign8690,
	"security nat destination rule-set xpfarg rule xpfarg match protocol":                 natMatchBenign8690,
	"security nat destination rule-set xpfarg rule xpfarg match source-address":           natMatchBenign8690,
	"security nat destination rule-set xpfarg rule xpfarg match source-address-name":      natMatchBenign8690,
	"security nat source rule-set xpfarg rule xpfarg match application":                   natMatchBenign8690,
	"security nat source rule-set xpfarg rule xpfarg match destination-address":           natMatchBenign8690,
	"security nat source rule-set xpfarg rule xpfarg match destination-address-name":      natMatchBenign8690,
	"security nat source rule-set xpfarg rule xpfarg match destination-port":              natMatchBenign8690,
	"security nat source rule-set xpfarg rule xpfarg match source-address":                natMatchBenign8690,
	"security nat source rule-set xpfarg rule xpfarg match source-address-name":           natMatchBenign8690,

	"security policies from-zone xpfarg xpfarg xpfarg policy xpfarg match application":         policyMatchNoDisarm8690,
	"security policies from-zone xpfarg xpfarg xpfarg policy xpfarg match destination-address": policyMatchNoDisarm8690,
	"security policies from-zone xpfarg xpfarg xpfarg policy xpfarg match source-address":      policyMatchNoDisarm8690,
	"security policies global policy xpfarg match application":                                 policyMatchNoDisarm8690,
	"security policies global policy xpfarg match destination-address":                         policyMatchNoDisarm8690,
	"security policies global policy xpfarg match source-address":                              policyMatchNoDisarm8690,

	"protocols bgp group xpfarg neighbor xpfarg export": "HAND-MEASURED: SAFE. With a policy-statement defined and the group given a type and peer-as, BOTH spellings compile cleanly -- there is no gate here at all, and the arm read it as undecidable only because its minimal fixture lacked the referenced policy.",
	"protocols bgp group xpfarg neighbor xpfarg import": "HAND-MEASURED: SAFE. With a policy-statement defined and the group given a type and peer-as, BOTH spellings compile cleanly -- there is no gate here at all, and the arm read it as undecidable only because its minimal fixture lacked the referenced policy.",

	"security nat static rule-set xpfarg rule xpfarg match source-address": "HAND-MEASURED: NO DISARM POSSIBLE. With a complete static rule-set both spellings are REJECTED IDENTICALLY, so the pass changes no verdict here.",
	// HAND-MEASURED. lane-8015 showed this bucket hides live disarms — it
	// hand-measured the three its scope added and `security dynamic-address
	// feed-server <n> url` proved to be a real one. So an entry carries the
	// verdict a person reached with a type-VALID value and the siblings the
	// validator needs, not merely the fact that the census fixture could not
	// decide. A visible unmeasured bucket is still unmeasured.
	// The two halves of the #8690 `open` residue whose census value is not
	// type-valid. Each is the TWIN of a site this arm DOES grade, in the same
	// container one leaf over, and neither inherits its twin's verdict — that
	// inference is what the v4/v6 static-binding pair disproved. Both were
	// measured by hand, with the pair ADMITTED and a type-valid value.
	"security dynamic-address feed-server xpfarg url": "HAND-MEASURED: BENIGN, and " +
		"the twin of `feed-server <f> hostname` which this arm grades directly. With " +
		"a real URL, elided `feed-server f1 url \"https://feeds.example.com/list\";` is " +
		"refused without the pass (\"resolves to an empty endpoint (no url or " +
		"hostname, or a slash-only url)\") and compiles with it; BRACED is accepted " +
		"both ways, so the config is legitimate and only the elided form lost the " +
		"value. Same gate and same message as the hostname twin, which is expected: " +
		"one validator covers both leaves. NOTE ON PROVENANCE — this site was " +
		"previously reported as a LIVE disarm; it was not, because the pair was not " +
		"admitted at that time. It is live NOW, in this commit, because this change " +
		"admits it.",

	"system services dhcpv6-local-server group xpfarg pool xpfarg static-binding xpfarg fixed-address": "HAND-MEASURED: " +
		"BENIGN, and the twin of the dhcp-local-server site this arm grades " +
		"directly. With a real IPv6 address, elided `static-binding b1 fixed-address " +
		"2001:db8::50;` is refused without the pass (\"has no fixed-address — a " +
		"reservation cannot be empty\") and compiles with it; BRACED is accepted both " +
		"ways. Measured SEPARATELY from its v4 twin rather than inheriting it: that " +
		"pair is the one that established the rule, since arm 2 caught the v4 side " +
		"and was structurally blind to this one.",

	"security ipsec policy xpfarg proposals": "HAND-MEASURED: BENIGN. Elided " +
		"`ipsec policy pol1 proposals pr1;` is refused without the pass (\"has no " +
		"resolvable ipsec proposal ... the configured perfect-forward-secrecy group " +
		"would be silently dropped\") and compiles with it. The gate objects to the " +
		"DROP, not the spelling: with the pass the compiled config is IDENTICAL to " +
		"the braced spelling's, which is the decisive test. Same class as the #8430 " +
		"empty-match gate and `snmp trap-group targets`.",

	"security policies from-zone xpfarg xpfarg xpfarg policy": "HAND-MEASURED: " +
		"NOT A DISARM — it runs the OTHER WAY, which this arm does not check at " +
		"all. With zones defined, elided `from-zone trust to-zone untrust policy " +
		"p1;` is ACCEPTED without the pass (the tail is dropped, so no policy is " +
		"created and nothing objects) and REJECTED with it by the #3044 " +
		"missing-criterion gate (the policy now exists and has no match " +
		"dimensions). The pass converts a SILENT LOSS into a LOUD REJECTION, which " +
		"is the gate working. No upgrade hazard: the tolerant load/peer-sync path " +
		"accepts both spellings, so a persisted config still loads and only a fresh " +
		"commit is refused.",

	// NOT YET HAND-MEASURED. Listed with an explicit marker rather than left
	// bare, so the difference between "a person checked and it is fine" and
	// "nobody has looked" is visible in the file. Every one is a candidate for
	// the treatment above.
}

// notHandMeasured8690 marks a bucket entry nobody has measured by hand yet.
// A NEW entry starts here and is expected to leave: write the site out with a
// type-valid value and the siblings its validator needs, then replace this with
// what you found. The count of entries still holding it is reported each run.
// It is not a verdict; it is the absence of one.
const notHandMeasured8690 = "NOT YET HAND-MEASURED: the census fixture could not decide, and no one has written this site out with a type-valid value to find out"

// #8690: a DEMONSTRATION that arm 2's reach is narrower than its name suggests,
// kept executable so the limitation note above cannot quietly stop being true.
//
// Arm 2 compiles one WELL-FORMED elided spelling and compares acceptance
// against rejection. A gate whose predicate needs something that spelling
// cannot express is invisible to it by construction. This pins the
// trailing-token kind, which is the one measurable in isolation:
//
//	security ike gateway <g> dynamic hostname <fqdn>          -> accepted
//	security ike gateway <g> dynamic hostname <fqdn> <extra>  -> REJECTED
//
// Arm 2 only ever builds the first, so it reports "no gate here" for a site
// governed by a gate that fires on the second. If someone later teaches the
// arm to vary token count, this cell reds — and the limitation note above
// should shrink with it rather than outliving its reason.
//
// Two sibling blind spots are NOT asserted here because I could not isolate
// them in a fixture, and asserting a shape I have not measured would be the
// defect this file exists to catch. Both were found by lane-8015 with ordinary
// cells in the full suite after arm 2 passed: a gate firing on a DUPLICATE
// (`chassis ... ip-monitoring global-weight`, "specified 2 times with
// different values") and CONTENT SURVIVAL across a multi-statement packed body
// (a `redundancy-group` losing `preempt`). The duplicate case is also circular
// — those sites are absent from the census precisely because the gate rejects
// their packed spelling, so an inventory-based over-reach analysis cannot see
// them either.
func TestArm2CannotSeeATrailingTokenGate8690(t *testing.T) {
	const wellFormed = `security { ike { gateway g1 { dynamic hostname host.example.com; } } }`
	const withExtra = `security { ike { gateway g1 { dynamic hostname host.example.com extra; } } }`

	compile := func(txt string) error {
		tree, perrs := NewParser(txt).Parse()
		if len(perrs) > 0 {
			return nil // a parse failure is not the gate we are probing
		}
		_, err := compileConfigWithOpts(tree, compileOpts{})
		return err
	}

	if err := compile(wellFormed); err != nil {
		t.Fatalf("the well-formed spelling must compile — it is what arm 2 builds, "+
			"and if it stopped compiling this demonstration would be measuring "+
			"something else: %v", err)
	}
	if compile(withExtra) == nil {
		t.Error("the trailing-token spelling now COMPILES, so the gate this cell " +
			"demonstrates is gone. Arm 2's stated blind spot for token-count " +
			"predicates no longer has this example behind it — find another or " +
			"shrink the limitation note above, rather than leaving a claim with " +
			"no evidence under it (#8690)")
	}
}

// sortedKeys8690 returns a map's keys, so an equality assertion can be made
// against a map that carries per-entry evidence.
func sortedKeys8690(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// natMatchBenign8690 is the shared verdict for the thirteen `security nat
// {source,destination} rule-set <r> rule <r> match <leaf>` sites. They are one
// finding, not thirteen: every one trips the SAME gate for the SAME reason, and
// writing the measurement out thirteen times would imply thirteen independent
// confirmations of something established once.
const natMatchBenign8690 = "HAND-MEASURED: BENIGN. Without the pass the elided " +
	"spelling drops the criterion and #8430 refuses the result -- \"the match " +
	"block constrains nothing, and the dataplane reads an EMPTY match set as " +
	"UNCONSTRAINED -- this rule would translate EVERY packet reaching it, not " +
	"none\". With the pass the criterion survives and it compiles. The decisive " +
	"test is not the acceptance flip but that elided-with-pass compiles to a " +
	"config IDENTICAL to the braced spelling's, verified directly: the gate " +
	"objects to the DROP, not to the spelling."

// policyMatchNoDisarm8690 covers the six `security policies ... match <leaf>`
// sites, where the measurement is unusually direct: the ERROR TEXT ITSELF shows
// the tail surviving.
const policyMatchNoDisarm8690 = "HAND-MEASURED: NOT A DISARM, and it cannot " +
	"become one. #3044 requires all three of source-address, destination-address " +
	"and application, and the elided spelling can carry only ONE criterion, so " +
	"BOTH spellings are rejected however good the fixture is. The pass is " +
	"nonetheless demonstrably working, visible in the error shrinking: without " +
	"it the gate reports three missing criteria, with it two. The surviving " +
	"criterion is the one that was folded."

// #8690: the normalizer preserves the folded tail, witnessed by a gate that was
// not built to witness anything.
//
// Most evidence for this pass is an equality: elided-with-pass compiles to what
// braced compiles to. That is sound, but both sides are produced by the same
// compiler and an equality can hold because two things are equally wrong.
//
// The #3044 policy gate gives an independent reading. It requires all three of
// source-address, destination-address and application, and NAMES THE ONES IT
// CANNOT FIND. The compact spelling can carry exactly one criterion, so the
// policy is refused either way — but the refusal COUNTS:
//
//	`policies global policy p1 match source-address any;`
//	  pass DISABLED -> missing "source-address", "destination-address", "application"
//	  pass ENABLED  -> missing "destination-address", "application"
//
// The criterion that stops being missing is the one that was folded. That is a
// direct observation of the tail surviving, from an instrument with no stake in
// the question and no knowledge that it is being used as one — which is a
// different kind of evidence from an assertion this lane wrote about its own
// pass.
//
// It also holds on sites that can NEVER be disarms, since neither spelling is
// ever accepted, so the reading is not entangled with the acceptance flip.
func TestTheGateCountsTheSurvivingCriterion8690(t *testing.T) {
	const elided = `security {
  zones { security-zone trust { host-inbound-traffic { system-services ping; } } }
  policies { global { policy p1 { match source-address any; then { permit; } } } }
}`
	compile := func(skipPass bool) string {
		tree, perrs := NewParser(elided).Parse()
		if len(perrs) > 0 {
			t.Fatalf("parse: %v", perrs)
		}
		_, err := compileConfigWithOpts(tree, compileOpts{skipCompactNormalize: skipPass})
		if err == nil {
			return ""
		}
		return err.Error()
	}
	without, with := compile(true), compile(false)
	if without == "" || with == "" {
		t.Fatalf("both spellings must be REJECTED for this reading to mean "+
			"anything — the evidence is which criteria the gate names, not "+
			"whether it fires (without=%q with=%q)", without, with)
	}

	// The folded criterion must be named as missing WITHOUT the pass and not
	// named WITH it. Asserted as a difference between the two readings rather
	// than against literal error text, so a reworded #3044 message does not
	// red this for the wrong reason.
	const folded = `"source-address"`
	if !strings.Contains(without, folded) {
		t.Errorf("with the pass DISABLED the gate does not report %s as missing, "+
			"so the fixture is not exercising the drop this cell is built on. "+
			"Either the elided spelling stopped dropping the criterion or #3044 "+
			"stopped naming it: %s", folded, without)
	}
	if strings.Contains(with, folded) {
		t.Errorf("with the pass ENABLED the gate STILL reports %s as missing, so "+
			"the folded criterion did not survive normalization. The pass is not "+
			"preserving the tail at this site (#8690): %s", folded, with)
	}
	if without == with {
		t.Error("the gate reports the SAME missing criteria with and without the " +
			"pass, so this cell is observing nothing. It reads the DIFFERENCE " +
			"between the two, and an identical pair means either the seam stopped " +
			"working or the site left the normalizer's scope (#8690)")
	}
}

// #8690: no (container, head) pair may be admitted by more than one family
// switch, and this is a SAFETY property rather than tidiness.
//
// compactNormalizeInScope is a series of per-family `switch containerKeyword +
// " " + head` blocks. Nothing stops two families listing the same pair, and 52
// currently do.
//
// THE COMPILER ALREADY COVERS THE EASY HALF, which is why this cell is scoped
// the way it is: a duplicate case WITHIN one switch is a build error ("duplicate
// case ... in expression switch"). Only the cross-switch case is invisible, and
// that is exactly the case that arises here, because each family was added as
// its own switch by a different lane. So this cell is not re-checking something
// the toolchain does; it covers the half the toolchain cannot see. Each duplicate is harmless while the answer is "admit" — but
// the moment somebody needs to REMOVE a pair, because a measurement showed it
// disarms a gate or truncates a read tail, they delete it from the family they
// are working in and the OTHER switch still returns true. The exclusion looks
// applied, the diff looks right, and the site is still normalized.
//
// That is not hypothetical: a mutation that deleted `"match source-address"`
// from one switch left the pass admitting it from the other, and the mutation
// read as a clean escape rather than as an incomplete edit.
//
// The existing 52 are PINNED rather than red, because they were introduced
// across several lanes' landed families and redding them would block work for a
// hazard this assertion exists to stop growing. A new duplicate reds; a
// resolved one also reds, so the list shrinks as families are tidied and cannot
// outlive its reason.
func TestNoPairIsAdmittedByTwoFamilySwitches8690(t *testing.T) {
	src, err := os.ReadFile("compact_normalize_8662.go")
	if err != nil {
		t.Fatalf("read predicate source: %v", err)
	}
	caseLine := regexp.MustCompile(`(?m)^\t\t"([a-z][^"]*)",?$`)
	counts := map[string]int{}
	for _, m := range caseLine.FindAllStringSubmatch(string(src), -1) {
		counts[m[1]]++
	}
	if len(counts) == 0 {
		t.Fatal("no case strings found in compact_normalize_8662.go — this cell " +
			"scans source text, so a formatting change can make it silently " +
			"measure nothing (#8690)")
	}
	var dup []string
	for pair, n := range counts {
		if n > 1 {
			dup = append(dup, pair)
		}
	}
	sort.Strings(dup)
	if diff := diffSiteSets8690(dup, knownDuplicatePairs8690); diff != "" {
		t.Errorf("the set of (container, head) pairs listed by MORE THAN ONE "+
			"family switch has changed:\n%s\n"+
			"A NEW entry means two families now admit the same pair, and removing "+
			"it from one will not remove it from the scope — an exclusion that "+
			"silently does not exclude. A REMOVED entry means one was tidied and "+
			"this list should shrink with it. Prefer resolving the duplicate to "+
			"adding it here (#8690).", diff)
	}
	t.Logf("#8690: %d distinct pairs across the family switches, %d of them listed twice",
		len(counts), len(dup))
}

// knownDuplicatePairs8690 are the pairs currently listed by two family
// switches. Each is a latent silent-non-exclusion; see the cell above. They are
// pinned, not endorsed.
var knownDuplicatePairs8690 = []string{
	"address-set address",
	"address-set address-set",
	"daily start-time",
	"daily stop-time",
	"friday start-time",
	"friday stop-time",
	"group authentication-key",
	"group interface",
	"host-inbound-traffic protocols",
	"host-inbound-traffic system-services",
	"interface authentication-key",
	"interface authentication-type",
	"isis authentication-key",
	"isis authentication-type",
	"manual authentication-algorithm",
	"match application",
	"match destination-address",
	"match destination-address-name",
	"match destination-port",
	"match from-zone",
	"match protocol",
	"match source-address",
	"match source-address-name",
	"match to-zone",
	"monday start-time",
	"monday stop-time",
	"neighbor authentication-key",
	"policies default-policy-log",
	"policy description",
	"proposal authentication-algorithm",
	"proposal authentication-method",
	"rip authentication-key",
	"rip authentication-type",
	"saturday start-time",
	"saturday stop-time",
	"schedulers scheduler",
	"scheduler start-time",
	"scheduler stop-time",
	"security-zone description",
	"security-zone interfaces",
	"security-zone screen",
	"sunday start-time",
	"sunday stop-time",
	"system domain-name",
	"then log",
	"thursday start-time",
	"thursday stop-time",
	"tuesday start-time",
	"tuesday stop-time",
	"vpn pre-shared-key",
	"wednesday start-time",
	"wednesday stop-time",
}
