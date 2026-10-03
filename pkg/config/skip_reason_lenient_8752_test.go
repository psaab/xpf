package config

import (
	"strings"
	"testing"
)

// #8752: a conservation exemption justified by "REFUSED at commit" is a
// STRICT-path fact, and dupConservationSkipped8436 governs BOTH compile paths.
//
// `Store.Load` and `Store.SyncApply` compile leniently — that is the whole point
// of them, since they read configurations the operator did not just author — and
// the lenient path does not refuse. So an entry skipped on a rejection is
// unexamined on the path where a conservation defect actually bites, and a skip
// with a stated reason reads as settled: nobody re-derives it.
//
// This pins the LENIENT-path behaviour of the three entries in that group, so
// the annotation is a measurement rather than prose. The two policy duplicates
// merge to one. The RSS fixture remains refused on strict compile but is now
// tolerated on lenient load with a warning and no expectation rows (#11796).
// If any answer changes, this reds — and a new entry added to that group owes
// the same measurement before its reason can say "refused".
//
// #8752 UPDATE — the two policy duplicates used to keep BOTH objects silently,
// and that was the defect. They now fold to ONE, because the #8752 merge runs
// on exactly the path this cell is about. The RSS case exercises the separate
// tolerant-load contract: strict compilation still refuses its unrecognized
// `expectation` children, while lenient compilation warns and omits the rows.
// Its census skip remains because the fixture builder cannot provide a valid
// integer queue name for that site.
func TestSkippedOnRefusalStillNeedsTheLenientAnswer8752(t *testing.T) {
	cases := []struct {
		name           string
		text           string
		lenientAccept  bool
		wantObjects    int
		wantRSSRows    int
		wantRSSWarning bool
	}{
		{
			name: "security policies from-zone <a> <b> <c> policy",
			text: `security { zones { security-zone trust; security-zone untrust; }
				policies { from-zone trust to-zone untrust {
					policy p1 { match { source-address any; destination-address any; application any; } then { permit; } }
					policy p1 { then { deny; } }
				} } }`,
			lenientAccept: true, wantObjects: 1,
		},
		{
			name: "security policies global policy",
			text: `security { policies { global {
					policy g1 { match { source-address any; destination-address any; application any; } then { permit; } }
					policy g1 { then { deny; } }
				} } }`,
			lenientAccept: true, wantObjects: 1,
		},
		{
			// The unknown `expectation` children still fail strict validation.
			// The tolerant path must warn and omit both malformed queue rows.
			name: "class-of-service fairness rss-expectation interface <i> queue",
			text: `class-of-service { fairness { rss-expectation { interface ge-0/0/0 {
					queue 0 { expectation balanced; }
					queue 0 { expectation any; }
				} } } }`,
			lenientAccept: true, wantRSSRows: 0, wantRSSWarning: true,
		},
	}

	for _, c := range cases {
		tree, perrs := NewParser(c.text).Parse()
		if len(perrs) > 0 {
			t.Fatalf("%s: fixture must parse: %v", c.name, perrs)
		}
		// The strict path must refuse every malformed fixture; the lenient
		// path's acceptance and omission behaviour is measured below.
		if _, err := compileConfigWithOpts(tree, compileOpts{}); err == nil {
			t.Errorf("%s: the STRICT path accepted the malformed input, so the skip entry's stated "+
				"reason (\"REFUSED at commit\") is no longer true and the entry needs "+
				"re-deriving on both paths", c.name)
		}

		cfg, err := compileConfigWithOpts(tree, lenientCompileOpts())
		gotAccept := err == nil && cfg != nil
		if gotAccept != c.lenientAccept {
			t.Errorf("%s: LENIENT accept = %v, want %v. That is the path Store.Load and "+
				"Store.SyncApply use, so a change here changes whether a config already on "+
				"disk loads with a silent duplicate", c.name, gotAccept, c.lenientAccept)
			continue
		}
		if !gotAccept {
			continue
		}
		if c.wantObjects > 0 {
			policyRows := 0
			for _, zone := range cfg.Security.Policies {
				policyRows += len(zone.Policies)
			}
			policyRows += len(cfg.Security.GlobalPolicies)
			if policyRows != c.wantObjects {
				t.Errorf("%s: lenient compile produced %d security policy rows, want %d", c.name, policyRows, c.wantObjects)
			}
		}

		rssRows := 0
		if cfg.ClassOfService != nil {
			rssRows = len(cfg.ClassOfService.FairnessExpectations)
		}
		if rssRows != c.wantRSSRows {
			t.Errorf("%s: lenient compile produced %d RSS rows, want %d", c.name, rssRows, c.wantRSSRows)
		}
		if c.wantRSSWarning && !strings.Contains(strings.Join(cfg.Warnings, "\n"), "rss-expectation") {
			t.Errorf("%s: lenient compile accepted malformed RSS rows without a warning: %v", c.name, cfg.Warnings)
		}
	}
}

// TestTheDuplicatePolicyPoisonsTheSnapshot8752 pins the CONSEQUENCE of the
// duplicate that the cell above pins the EXISTENCE of.
//
// lane-8015's cell establishes that the lenient path accepts the duplicate and
// produces two objects. That is the finding. This one records what those two
// objects DO, because the census annotation originally said "the duplicate
// WINS", and a reader acting on that would make the FIRST occurrence
// authoritative -- which leaves the real harm in place.
//
// The spurious policy sits second and never wins a first-match evaluation. What
// matters is that compiling it sets LenientContentDropped, because
// policies_lower.go poisons such a rule with the __unsupported__ sentinel so
// the Rust integrity preflight rejects the WHOLE snapshot (previous-good
// retained; fresh-boot default-deny). The operator's entire configuration fails
// to load -- a strictly worse and differently-shaped outcome than a policy set
// that merely evaluates wrong.
//
// THE OTHER HALF OF THAT CHAIN IS ALREADY PINNED, AND THIS CELL DELIBERATELY
// DOES NOT RE-ASSERT IT. The claim spans two packages, so it needs two cells:
//
//	this cell (pkg/config)                        duplicate  -> LenientContentDropped
//	TestLenientWidenedPolicyLowersToSentinel5575  flag       -> __unsupported__ sentinel
//	 (pkg/dataplane/userspace/lenient_permit_widening_5575_test.go)
//
// Cited as a CELL rather than as a line in policies_lower.go, because a line
// number is prose the moment the file moves and a cell is runnable. That is the
// same rule the register applies to its own `wrong-remedy` class -- a claim
// without a runnable cite is prose -- turned on this comment. The original
// draft of this note cited policies_lower.go:194 and would have rotted at the
// next edit to that file.
//
// If this cell is ever the ONLY one left of the two, the consequence paragraph
// in the census annotation has become unfalsifiable again: half a cross-package
// chain asserts nothing about the chain.
//
// This cell is therefore the acceptance criterion for the #8752 fold: folding
// the occurrences into one policy carrying the operator's criteria must clear
// LenientContentDropped. An implementation that removes the duplicate OBJECT
// but leaves the flag set has not fixed the thing operators feel.
//
// #8752 HAS NOW LANDED, AND THIS CELL WAS RE-POINTED RATHER THAN DELETED — as
// its own failure message instructed. It asserts the same chain, at the link
// the fix changed:
//
//	before   duplicate -> second object -> LenientContentDropped -> sentinel -> whole snapshot rejected
//	after    duplicate -> MERGED into the first occurrence -> flag CLEAR -> snapshot loads
//
// The second half of the chain is untouched and still pinned by
// TestLenientWidenedPolicyLowersToSentinel5575: a policy that DOES carry the
// flag still lowers to __unsupported__ and still fails the preflight. That is
// the correct outcome — the flag is not wrong, the duplicate was. Breaking the
// chain at its FIRST link is precisely what "fix the cause, not the symptom"
// means here, and it is why the fold had to merge the occurrences rather than
// suppress the flag on them.
//
// The measured equivalence that justifies the fold's SHAPE, recorded here
// because it is the reason merging is not an invention: this fixture compiled
// through the flat `set` spelling — the one operators actually type — produces
// the SAME single policy, with the same terminal action and the same criteria,
// and the same "2 conflicting terminal actions" warning. The two spellings
// differ afterwards by exactly one warning: the hierarchical one additionally
// reports the duplicate it merged, which the flat spelling never had.
func TestTheDuplicatePolicyPoisonsTheSnapshot8752(t *testing.T) {
	const text = `security {
  policies {
    from-zone trust to-zone untrust {
      policy p1 { match { source-address 10.0.0.0/8; destination-address any; application any; } then { permit; } }
      policy p1 { then { deny; } }
    }
  }
  zones { security-zone trust { } security-zone untrust { } }
}`
	tree, perrs := NewParser(text).Parse()
	if len(perrs) > 0 {
		t.Fatalf("fixture must parse: %v", perrs)
	}
	cfg, err := CompileConfigLenient(tree)
	if err != nil || cfg == nil {
		t.Fatalf("the TOLERANT path must accept this (it is the path Store.Load uses): %v", err)
	}
	var pols []*Policy
	for _, pr := range cfg.Security.Policies {
		pols = append(pols, pr.Policies...)
	}
	if len(pols) != 1 {
		t.Fatalf("want the duplicate FOLDED into 1 policy, got %d. If this is 2 again the "+
			"#8752 fold has regressed: the second occurrence is back, it carries "+
			"LenientContentDropped, and policies_lower.go will poison the snapshot so the "+
			"operator's WHOLE configuration fails to load", len(pols))
	}
	got := pols[0]

	// The operator's criteria survive the fold. A fix that produced one policy
	// by discarding the occurrence that carried the match would be worse than
	// the duplicate it replaced.
	if src := got.Match.SourceAddresses; len(src) != 1 || src[0] != "10.0.0.0/8" {
		t.Errorf("the folded policy lost the operator's source criteria: %v — the fold must "+
			"MERGE into the first occurrence, not replace it", src)
	}
	if len(got.Match.DestinationAddresses) == 0 || len(got.Match.Applications) == 0 {
		t.Errorf("the folded policy lost destination/application criteria: dst=%d app=%d",
			len(got.Match.DestinationAddresses), len(got.Match.Applications))
	}

	// THE CLAIM THAT MATTERS, inverted by the fix. This is the property #8752
	// exists to deliver: no object carries the poison flag, so nothing lowers
	// to __unsupported__ and the snapshot loads.
	if got.LenientContentDropped {
		t.Errorf("the folded policy carries LenientContentDropped. The fold removed the " +
			"duplicate OBJECT but not the harm: policies_lower.go poisons such a rule with " +
			"the __unsupported__ sentinel, the Rust integrity preflight rejects the WHOLE " +
			"snapshot, and the operator's configuration does not load (previous-good " +
			"retained; fresh-boot default-deny). That is the thing operators feel, and " +
			"clearing it is the acceptance criterion this cell was written to hold (#8752)")
	}

	// Merging must not be SILENT. The strict path rejects this configuration,
	// so a tolerant load that accepts it owes the operator a diagnostic —
	// otherwise the fix converts a loud refusal into an invisible rewrite.
	var warned bool
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "duplicate policy name") {
			warned = true
		}
	}
	if !warned {
		t.Errorf("the fold merged without warning; warnings=%v. A configuration a strict "+
			"commit REJECTS must not load silently just because the tolerant path can "+
			"repair it", cfg.Warnings)
	}

	// The conflicting terminal action is still reported by the existing gate,
	// and the fold resolves it the same way the flat `set` spelling does.
	// Asserting it here keeps the fold from quietly becoming the thing that
	// decides a policy's action.
	var actionWarned bool
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "conflicting terminal actions") {
			actionWarned = true
		}
	}
	if !actionWarned {
		t.Errorf("merging the two occurrences put `permit` and `deny` on one policy and no "+
			"conflicting-terminal-action warning was raised; warnings=%v. The fold must not "+
			"swallow that diagnosis — it is now the only thing telling the operator the two "+
			"statements disagreed", cfg.Warnings)
	}
}
