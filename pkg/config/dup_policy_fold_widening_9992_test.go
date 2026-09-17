package config

import (
	"strings"
	"testing"
)

// #9992 — an actionless policy has effective DENY semantics on the tolerant
// path (#3043), even though compilePolicy reports no explicit terminal action.
// A duplicate fold that ends in PERMIT therefore widens a defaulted deny and
// must poison the merged policy just like an explicit deny/reject (#9571).
//
// RED-on-revert: restoring statementRestricts9571's old `ok && a != Permit`
// predicate makes every defaulted-deny case below compile as an unpoisoned
// permit. The strict assertions pin that #3473/#3043 admission is unchanged.
func TestFoldDefaultedDenyWideningIsPoisoned9992(t *testing.T) {
	for _, tc := range []struct {
		name, strictDiagnostic string
		text                   string
	}{
		{"zone-pair actionless then permit", "no terminal action", zonePairText9571(
			`policy p1 { ` + anyMatch9571 + ` } policy p1 { ` + anyMatch9571 + ` then { permit; } }`)},
		{"global actionless then permit", "no terminal action", globalText9571(
			`policy g1 { ` + anyMatch9571 + ` } policy g1 { ` + anyMatch9571 + ` then { permit; } }`)},
		{"zone-pair actionless then permit fragment", "missing required criterion", zonePairText9571(
			`policy p1 { ` + anyMatch9571 + ` } policy p1 { then { permit; } }`)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := CompileConfig(parse9571(t, tc.text)); err == nil {
				t.Fatal("strict commit accepted a duplicate/actionless policy; #3473/#3043 must remain strict rejects")
			} else if !strings.Contains(err.Error(), tc.strictDiagnostic) {
				t.Fatalf("strict diagnostic = %q, want %q (#3043/#3044 pin)", err, tc.strictDiagnostic)
			}
			for _, entry := range lenientEntries9571 {
				cfg, err := entry.compile(parse9571(t, tc.text))
				if err != nil {
					t.Fatalf("%s must accept the persisted duplicate on the tolerant path (#1960): %v", entry.label, err)
				}
				pols := policies9571(cfg)
				if len(pols) != 1 {
					t.Fatalf("%s: want duplicate folded into one policy, got %d", entry.label, len(pols))
				}
				if pols[0].Action != PolicyPermit {
					t.Fatalf("%s: fixture premise broken: merged action = %v, want permit", entry.label, pols[0].Action)
				}
				if !pols[0].LenientContentDropped {
					t.Errorf("%s: #9992 regression: effective defaulted deny folded into an unpoisoned permit", entry.label)
				}
				if LenientDroppedPolicyLocator(cfg) == "" {
					t.Errorf("%s: poisoned policy is not visible to the #6707 preflight", entry.label)
				}
				if !hasWarning9571(cfg, "duplicate policy name", "#9571") {
					t.Errorf("%s: missing #9571 widening warning: %v", entry.label, cfg.Warnings)
				}
			}
		})
	}
}

// An all-actionless fold remains an effective DENY, not a widening into
// PERMIT. Keeping statementPermits9571 explicit-only prevents over-poisoning.
func TestFoldTwoDefaultedDeniesAreNotWidened9992(t *testing.T) {
	for _, tc := range []struct {
		name string
		text string
	}{
		{"zone-pair actionless duplicates", zonePairText9571(
			`policy p1 { ` + anyMatch9571 + ` } policy p1 { ` + anyMatch9571 + ` }`)},
		{"global actionless duplicates", globalText9571(
			`policy g1 { ` + anyMatch9571 + ` } policy g1 { ` + anyMatch9571 + ` }`)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, entry := range lenientEntries9571 {
				cfg, err := entry.compile(parse9571(t, tc.text))
				if err != nil {
					t.Fatalf("%s must accept the persisted duplicate on the tolerant path (#1960): %v", entry.label, err)
				}
				pols := policies9571(cfg)
				if len(pols) != 1 {
					t.Fatalf("%s: want duplicate folded into one policy, got %d", entry.label, len(pols))
				}
				if pols[0].Action != PolicyDeny {
					t.Fatalf("%s: effective all-actionless action = %v, want deny (#3043)", entry.label, pols[0].Action)
				}
				if pols[0].LenientContentDropped {
					t.Errorf("%s: all-actionless effective deny was over-poisoned as a widening", entry.label)
				}
				if hasWarning9571(cfg, "#9571") {
					t.Errorf("%s: unexpected #9571 widening warning: %v", entry.label, cfg.Warnings)
				}
			}
		})
	}
}
