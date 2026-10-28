package config

import "testing"

// #17026 fold: CarvedComposedExtraSequencesForStatements16869 is the single
// termination walk behind CarvedComposedExtraSequences16869, so the strict
// gate (po.PolicyStatements) and the pkg/frr render belt (filtered statement
// map) cannot diverge. These cells pin the statement-map variant directly:
// duplicate names, the empty chain, missing members, and the terminating /
// next-policy boundary shapes.
func TestCarvedComposedReserveForStatements17026(t *testing.T) {
	terminating := &PolicyStatement{DefaultAction: "reject"}
	terminatingNext := &PolicyStatement{
		DefaultAction: "accept",
		Terms:         []*PolicyTerm{{Name: "t", NextPolicy: true}},
	}
	plain := &PolicyStatement{Terms: []*PolicyTerm{{Name: "t", Action: "accept"}}}
	pss := map[string]*PolicyStatement{
		"A": terminating,
		"B": plain,
		"C": terminatingNext,
	}

	cases := []struct {
		name     string
		pss      map[string]*PolicyStatement
		chain    []string
		carved   bool
		fallback string
		want     uint64
	}{
		{"empty chain reserves carved pair", pss, nil, true, "permit", 1},
		{"non-carved reserves nothing", pss, []string{"B"}, false, "permit", 0},
		{"deny fallback reserves nothing", pss, []string{"B"}, true, "deny", 0},
		{"non-terminating member", pss, []string{"B"}, true, "permit", 1},
		{"terminating member first", pss, []string{"A", "B"}, true, "permit", 0},
		{"terminating member after plain", pss, []string{"B", "A"}, true, "permit", 0},
		{"duplicate terminating name", pss, []string{"A", "A"}, true, "permit", 0},
		{"duplicate plain name", pss, []string{"B", "B"}, true, "permit", 1},
		{"missing member skipped", pss, []string{"X", "B"}, true, "permit", 1},
		{"missing then terminating", pss, []string{"X", "A"}, true, "permit", 0},
		{"nil statement skipped", map[string]*PolicyStatement{"A": nil, "B": plain}, []string{"A", "B"}, true, "permit", 1},
		{"next-policy default does not terminate", pss, []string{"C"}, true, "permit", 1},
		{"next-policy then terminating", pss, []string{"C", "A"}, true, "permit", 0},
		{"nil map empty chain", nil, nil, true, "permit", 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := CarvedComposedExtraSequencesForStatements16869(tc.pss, tc.chain, tc.carved, tc.fallback); got != tc.want {
				t.Fatalf("CarvedComposedExtraSequencesForStatements16869 = %d, want %d", got, tc.want)
			}
		})
	}

	// The po-based helper must agree with the statement-map variant over
	// po.PolicyStatements for every shape above (single walk, no mirror).
	po := &PolicyOptionsConfig{PolicyStatements: pss}
	for _, chain := range [][]string{nil, {"B"}, {"A", "B"}, {"B", "A"}, {"A", "A"}, {"X", "A"}, {"C"}, {"C", "A"}} {
		want := CarvedComposedExtraSequencesForStatements16869(pss, chain, true, "permit")
		if got := CarvedComposedExtraSequences16869(po, chain, true, "permit"); got != want {
			t.Fatalf("po helper disagrees with statement-map variant for chain %v: got %d, want %d", chain, got, want)
		}
	}
	if got := CarvedComposedExtraSequences16869(nil, []string{"B"}, true, "permit"); got != 0 {
		t.Fatalf("nil po must reserve 0, got %d", got)
	}
}
