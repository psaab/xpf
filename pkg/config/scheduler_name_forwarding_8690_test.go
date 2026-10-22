package config

import "testing"

// #8690/#8752: `security policies … policy <p> scheduler-name`.
//
// SUPERSEDED BY #8752, AND RE-POINTED RATHER THAN DELETED. This cell used to
// pin the site as `wrong-remedy`: normalizing it would move the packed tail
// into a SPURIOUS DUPLICATE policy, restoring the schedule onto the wrong
// object. #8752 folds a repeated `policy <p>` into the first occurrence on the
// tolerant path, so there is no longer a wrong object to land on, and the
// premise of that classification is gone.
//
// What the fold changed, measured on the LENIENT path:
//
//	before   pol#1 sched=""  src=[any] PERMIT   +  pol#2 sched="S" src=[] DENY
//	after    pol#1 sched="S" src=[any] PERMIT       (one policy; the duplicate folded in)
//
// So the HARM this cell documented — a policy written TIME-LIMITED running
// PERMANENTLY ACTIVE — is fixed, and fixed WITHOUT the normalizer: the fold
// carries the packed tail onto the surviving policy itself.
//
// A NARROWER DIVERGENCE REMAINS, and it is the reason the site is now classed
// `open` rather than removed. At the census's own shape — a LONE
// `policy p1 scheduler-name S;` with no sibling to fold into — the schedule is
// still dropped where the block spelling carries it. Both halves are asserted
// below, because "the harm is fixed" and "there is nothing left here" are
// different claims and only the first one is true.
//
// The historical narrative is kept verbatim below. This entry has been wrong
// three times (`owed-own-change` → `no-drop-measured` → `wrong-remedy`), each
// time because a fixture chose a different spelling than the question was
// about, and the record of which spelling answers which question is the most
// reusable thing this file contains.
//
// ---- history, as written when the site was classed `wrong-remedy` ----
//
// The normalizer was the WRONG REMEDY for this site, and three measurements
// were needed to establish that because each earlier one used a different
// spelling.
//
// WHERE THE DUPLICATE SHAPE COMES FROM, stated precisely because an earlier
// version of this comment got it wrong. It is NOT what a CLI session produces:
// flat `set … policy p1 match …` followed by `set … policy p1 scheduler-name S`
// MERGES into one policy carrying both, measured in both orderings and on both
// compile paths. Attributing the duplicate to a pair of `set` lines was hand-
// written hierarchical text standing in for the flat-set spelling — the trap
// CLAUDE.md names ("ALWAYS use ParseSetCommand() + tree.SetPath(), NEVER
// NewParser()"), and the third instance of it on this one file in a day.
//
// It arrives as a config FILE with the two statements as siblings: hand-edited,
// written by an older build, or pushed by an un-upgraded primary. That is
// narrower than "an operator typed two set lines" — and it is exactly the
// population Store.Load and Store.SyncApply exist to accept, which is why the
// lenient path is still the right place to point at.
//
// THE HARM IS REAL. On the LENIENT path — which is what production uses on Load and
// SyncApply (configstore/store.go: boot config load and HA config sync) — that
// compiles to TWO policies named p1:
//
//	pol#1  sched=""   src=[any]  PERMIT    <- the operator's policy, schedule LOST
//	pol#2  sched=""   src=[]     DENY      <- a spurious match-less duplicate
//
// So a policy written as TIME-LIMITED runs PERMANENTLY ACTIVE. That much of the
// original forwarding concern was right.
//
// BUT NORMALIZING DOES NOT FIX IT. With ("policy","scheduler-name") ADMITTED —
// and that admission is load-bearing: at master, with the pair excluded, pol#2
// carries sched="" under BOTH skipNorm settings, because the pass touches 0
// nodes and the two runs are the same — the pass moves the packed tail into the
// DUPLICATE's body:
//
//	pol#1  sched=""   src=[any]  PERMIT    <- STILL scheduleless
//	pol#2  sched="S"  src=[]     DENY      <- the schedule lands here
//
// The schedule is restored onto the wrong policy. The defect is that the second
// `policy p1 …` statement DUPLICATES rather than merging — a policy-level
// defect (#3473 duplicate policy name; lane-8526's #8436 duplicate-block work),
// not a brace-elision one. Normalizing this pair changes only the inert
// census spelling, where the policy has no body and does nothing either way.
//
// THAT IS WHY IT MUST NOT BE SWEPT: admitting it removes two lines from the
// #2419 inventory and looks like progress, while the reachable harm is
// untouched. A remedy that clears the evidence without fixing the defect is
// worse than none.
//
// Why the earlier measurements disagreed, recorded so the next reader does not
// repeat them: the STRICT path REJECTS the elided spelling, so cfg is nil and
// there is nothing to inspect — a gate firing is the absence of a compiled
// result, not evidence about one. And any skipNorm comparison taken while the
// pair is EXCLUDED is vacuous, because the pass touches 0 nodes and both sides
// are the same run.
func TestSchedulerNameFoldRestoresTheScheduleOntoTheOperatorsPolicy8690(t *testing.T) {
	const sched = `schedulers { scheduler S { daily { start-time 09:00; stop-time 17:00; } } }`
	const head = `security { zones { security-zone trust; security-zone untrust; } `
	const body = `match { source-address any; destination-address any; application any; } then { permit; }`

	// The reachable spelling: a real policy, plus the brace-elided statement a
	// second `set` line produces.
	reachable := sched + head + `policies { from-zone trust to-zone untrust { policy p1 { ` + body + ` } policy p1 scheduler-name S; } } }`
	// The reference: the schedule written inside the policy.
	reference := sched + head + `policies { from-zone trust to-zone untrust { policy p1 { ` + body + ` scheduler-name S; } } } }`

	policies := func(t *testing.T, text string) []*Policy {
		t.Helper()
		tree, perrs := NewParser(text).Parse()
		if len(perrs) > 0 {
			t.Fatalf("fixture must parse: %v", perrs)
		}
		cfg, err := compileTree(tree, lenientCompileOpts(), nil)
		if err != nil || cfg == nil {
			t.Fatalf("the LENIENT path must accept this — that is the whole point of it: %v", err)
		}
		var out []*Policy
		for _, z := range cfg.Security.Policies {
			out = append(out, z.Policies...)
		}
		return out
	}

	// POSITIVE HALF: written inside the policy, the schedule is carried. Without
	// this the comparison below is between two empties.
	ref := policies(t, reference)
	if len(ref) != 1 || ref[0].SchedulerName != "S" {
		t.Fatalf("the reference spelling must produce ONE policy carrying the schedule; got %d, sched=%q",
			len(ref), func() string {
				if len(ref) > 0 {
					return ref[0].SchedulerName
				}
				return ""
			}())
	}

	// THE CURE. The reachable spelling now folds to ONE policy: the operator's,
	// carrying the schedule the elided statement supplied.
	got := policies(t, reachable)
	if len(got) != 1 {
		t.Fatalf("the reachable spelling must now produce ONE policy — #8752 folds the "+
			"duplicate `policy p1 …` statement into the first occurrence on the tolerant "+
			"path; got %d. If this is 2 again the fold has regressed and the operator's "+
			"time-limited policy is once more running permanently active behind a "+
			"match-less deny", len(got))
	}
	if got[0].SchedulerName != "S" {
		t.Fatalf("the folded policy has scheduler-name %q, want %q — the fold must carry the "+
			"packed tail ONTO the surviving policy. Dropping it would leave exactly the "+
			"harm this site was filed for: a policy written TIME-LIMITED running "+
			"PERMANENTLY ACTIVE", got[0].SchedulerName, "S")
	}
	if len(got[0].Match.SourceAddresses) == 0 {
		t.Errorf("the folded policy lost its match criteria — the fold REPLACED the " +
			"operator's occurrence instead of merging into it")
	}
	if got[0].Action != PolicyPermit {
		t.Errorf("the folded policy's action = %v, want PolicyPermit — the operator's "+
			"`then permit` must survive; a policy with no terminal action defaults to deny",
			got[0].Action)
	}
	// The folded result must equal what writing the schedule inside the policy
	// produces. Without this the assertions above could all hold on a policy
	// that differs from the reference in some other way.
	if got[0].SchedulerName != ref[0].SchedulerName || got[0].Action != ref[0].Action ||
		len(got[0].Match.SourceAddresses) != len(ref[0].Match.SourceAddresses) {
		t.Errorf("folded policy does not match the braced reference: folded{sched=%q "+
			"action=%v src=%d} vs reference{sched=%q action=%v src=%d}",
			got[0].SchedulerName, got[0].Action, len(got[0].Match.SourceAddresses),
			ref[0].SchedulerName, ref[0].Action, len(ref[0].Match.SourceAddresses))
	}

	// WHAT REMAINS, and why the site is `open` rather than gone. With no
	// sibling to fold into, the elided spelling still drops the schedule that
	// the block spelling carries. This is the divergence the census records,
	// and normalizing is now a correct remedy for it — there is no other policy
	// for the tail to land on.
	lone := policies(t, sched+head+`policies { from-zone trust to-zone untrust { policy p1 scheduler-name S; } } }`)
	loneBlock := policies(t, sched+head+`policies { from-zone trust to-zone untrust { policy p1 { scheduler-name S; } } } }`)
	if len(lone) != 1 || len(loneBlock) != 1 {
		t.Fatalf("the lone fixtures must each produce one policy; got %d and %d",
			len(lone), len(loneBlock))
	}
	if loneBlock[0].SchedulerName != "S" {
		t.Fatalf("positive control: the lone BLOCK spelling must carry the schedule, got %q. "+
			"Without it the comparison below is between two empties",
			loneBlock[0].SchedulerName)
	}
	if lone[0].SchedulerName != "" {
		t.Fatalf("the lone ELIDED spelling now carries scheduler-name %q. The remaining "+
			"divergence is gone, which means the site should leave the #8690 inventory "+
			"entirely — re-derive the `open` entry in "+
			"testdata/compact_block_permanent_exclusions_8690.txt rather than leaving it "+
			"pointing at a site that no longer diverges", lone[0].SchedulerName)
	}

	// The pair is still NOT admitted to the normalizer. That is a statement
	// about work not done, not about work forbidden: admitting it now owes the
	// #8690 two-arm procedure, which has not been re-run since the fold removed
	// the objection. If somebody admits it, this reds and points them at the
	// register entry to re-derive.
	if compactNormalizeInScope("policy", "scheduler-name") {
		t.Fatal("(\"policy\", \"scheduler-name\") has been ADMITTED to the normalizer's " +
			"scope. Since #8752 that is no longer the WRONG remedy — the schedule would " +
			"land on the operator's policy, because the duplicate it used to land on is " +
			"folded away. But admitting it still owes the #8690 two-arm measurement (arm 1: " +
			"no reader consumes the tail; arm 2: the strict-path acceptance comparison), " +
			"and the register entry is still classed `open` on the basis that neither arm " +
			"was re-run. Run them and re-derive the entry in " +
			"testdata/compact_block_permanent_exclusions_8690.txt.")
	}
}
