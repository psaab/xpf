package configstore

import (
	"strings"
	"testing"
)

// #16872: routing-policy `then next term` is a documented Junos
// flow-control action. Through CheckText (the strict commit-check /
// day-0 pipeline, including the schema walk) it must commit, keep its
// modifiers, and fall through — identical to the term without the
// marker. Pre-fix the schema enum (policy-only) rejected it with
// `invalid value "term" ... (expected one of: policy)`.
//
// FAIL-ON-REVERT: restoring the policy-only enum makes the CheckText
// cells below fail; the positive controls (next policy, no-marker)
// pass either way.
func TestCheckTextRoutingNextTerm16872(t *testing.T) {
	withMarker := `policy-options { policy-statement P { term a { then { local-preference 200; next term; } } term b { then accept; } } }`
	cfg, err := CheckText(withMarker, -1)
	if err != nil {
		t.Fatalf("CheckText rejected `then next term`: %v", err)
	}
	term := cfg.PolicyOptions.PolicyStatements["P"].Terms[0]
	if !term.NextTerm || term.NextPolicy || term.Action != "" {
		t.Fatalf("next-term compiled wrong: NextTerm=%v NextPolicy=%v Action=%q", term.NextTerm, term.NextPolicy, term.Action)
	}
	if !term.HasLocalPreference || term.LocalPreference != 200 {
		t.Fatalf("next term lost local-preference 200: %+v", term)
	}

	// Flat-set spelling through the same operator pipeline.
	flat := "set policy-options policy-statement P term a then local-preference 200\nset policy-options policy-statement P term a then next term\nset policy-options policy-statement P term b then accept\n"
	cfg, err = CheckText(flat, -1)
	if err != nil {
		t.Fatalf("CheckText rejected flat `then next term`: %v", err)
	}
	if term := cfg.PolicyOptions.PolicyStatements["P"].Terms[0]; !term.NextTerm || term.Action != "" {
		t.Fatalf("flat next-term compiled wrong: %+v", term)
	}

	// Positive controls: `next policy` still commits as a jump, and the
	// same policy without any marker still commits as fall-through.
	if _, err := CheckText(`policy-options { policy-statement P { term a { then next policy; } } }`, -1); err != nil {
		t.Fatalf("control: `then next policy` rejected: %v", err)
	}
	if _, err := CheckText(`policy-options { policy-statement P { term a { then { local-preference 200; } } term b { then accept; } } }`, -1); err != nil {
		t.Fatalf("control: modifier-only term rejected: %v", err)
	}

	// Still malformed: an unknown continuation stays refused, naming it.
	if _, err := CheckText(`policy-options { policy-statement P { term a { then next polic; } } }`, -1); err == nil || !strings.Contains(err.Error(), "polic") {
		t.Fatalf("control: `then next polic` must stay rejected naming polic, got %v", err)
	}
}
