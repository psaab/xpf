package natshow

import (
	"context"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// nat_actionless_dnat_annotation_6823_test.go — #6823.
//
// #6823 decided the contract for a leniently-admitted ACTIONLESS NAT rule: it
// is NON-TERMINAL, so matching traffic falls THROUGH to whatever rule follows.
// The decision is only as good as what the operator is told, and #7640's
// annotation told the two kinds different things.
//
// The source arm named the consequence ("does NOT stop rule evaluation, so
// matching traffic falls through to any later broader rule"). The destination
// arm named only the mechanism — "the rule is not published to the dataplane
// at all" — which is TRUE and reads as INERT. That is the precise framing the
// #5717 / #6820 line of work exists to retire: the rule being absent is exactly
// WHY evaluation continues, so an operator who wrote a DNAT rule believing it
// exempts a host is told the reassuring half of a sentence whose other half is
// that the host is translated by the next broader rule.
//
// TestLenientlyAdmittedSourceRuleIsAnnotated7640 cannot see this: it renders
// the SOURCE detail only, so the destination arm of the same switch was
// unbound.

func actionlessDestCfg6823() *config.Config {
	cfg := &config.Config{}
	cfg.Security.NAT.Destination = &config.DestinationNATConfig{
		RuleSets: []*config.NATRuleSet{{
			Name:     "rd1",
			FromZone: "untrust",
			Rules:    []*config.NATRule{{Name: "actionless"}}, // no terminal action
		}},
	}
	cfg.LenientNATTerminalActionRules = []config.LenientNATTerminalActionRule{
		{Reason: config.LenientNATTerminalActionReasonActionless, Kind: "destination", RuleSet: "rd1", Rule: "actionless", Actions: 0},
	}
	return cfg
}

// TestActionlessDestRuleAnnotationNamesTheFallThrough6823 binds the
// destination arm to the same standard as the source arm.
//
// The "ADMITTED BY TOLERANT LOAD" half is asserted first as a PRECONDITION: it
// proves the annotation fired for this rule at all, so a missing "falls
// through" is a wording gap and not a renderer that annotated nothing.
func TestActionlessDestRuleAnnotationNamesTheFallThrough6823(t *testing.T) {
	var b strings.Builder
	RenderDestRuleDetail(context.Background(), &b, actionlessDestCfg6823(), nil, nil)
	got := b.String()

	if !strings.Contains(got, "ADMITTED BY TOLERANT LOAD") {
		t.Fatalf("precondition: the leniently-admitted DESTINATION rule is not "+
			"annotated at all, so the wording assertion below would be vacuous "+
			"(#7640/#6823):\n%s", got)
	}
	if !strings.Contains(got, "falls through") {
		t.Fatalf("the destination annotation does not name the CONSEQUENCE. "+
			"#6823 decided an actionless rule is NON-TERMINAL, so matching "+
			"traffic is translated by the next broader rule; telling the "+
			"operator only that the rule is 'not published to the dataplane' "+
			"reads as INERT — the framing #5717/#6820 retired:\n%s", got)
	}
	if !strings.Contains(got, "does NOT stop rule evaluation") {
		t.Fatalf("the destination annotation does not say the rule is "+
			"NON-TERMINAL. That is the #6823 contract in one clause, and it is "+
			"what distinguishes 'your exemption silently does nothing' from "+
			"'your exemption works':\n%s", got)
	}
}

// TestActionlessDestRuleIsNotBlamedOnAPool6823 pins the destination twin of
// the `Action: interface` defect #7640 fixed on the source side.
//
// An ACTIONLESS rule names no pool, and the #6534 NOT INSTALLED line reported
// it as `references undefined or address-less pool ""` — asserting a reference
// the rule does not carry, on exactly the rule shape an operator is hunting.
// It is worse than cosmetic because it mis-attributes the CAUSE: the reader
// goes off to define a pool, when the rule carries no translation action for a
// pool to belong to.
//
// The NOT-INSTALLED half is asserted as a PRECONDITION so this cannot pass by
// the line disappearing altogether — which would be a different regression
// (#6534: the renderer must say the dataplane installed nothing) wearing the
// same green.
func TestActionlessDestRuleIsNotBlamedOnAPool6823(t *testing.T) {
	var b strings.Builder
	RenderDestRuleDetail(context.Background(), &b, actionlessDestCfg6823(), nil, nil)
	got := b.String()

	if !strings.Contains(got, "NOT INSTALLED") {
		t.Fatalf("precondition: the actionless rule no longer reports NOT "+
			"INSTALLED at all, so the wording assertions below are vacuous "+
			"(#6534 requires the renderer to say the dataplane installed "+
			"nothing):\n%s", got)
	}
	if strings.Contains(got, "address-less pool") {
		t.Fatalf("an ACTIONLESS destination rule is blamed on a pool it does "+
			"not reference (#6823). The rule names no translation action; "+
			"reporting an undefined pool sends the operator to define one:\n%s",
			got)
	}
	if !strings.Contains(got, "names no translation action") {
		t.Fatalf("the NOT INSTALLED reason does not name the actual cause — "+
			"that the rule carries no translation action:\n%s", got)
	}
}

// TestDestRuleWithADanglingPoolStillNamesThePool6823 is the paired control for
// the cell above, and the reason the fix is a message split rather than a
// message replacement. A rule that genuinely DOES reference a missing pool must
// still be told so: collapsing both cases to "names no translation action"
// would trade one misattribution for another, and this cell is what makes the
// two distinguishable rather than merely different from the old text.
func TestDestRuleWithADanglingPoolStillNamesThePool6823(t *testing.T) {
	cfg := &config.Config{}
	cfg.Security.NAT.Destination = &config.DestinationNATConfig{
		RuleSets: []*config.NATRuleSet{{
			Name:     "rd1",
			FromZone: "untrust",
			Rules: []*config.NATRule{{
				Name: "dangling",
				Then: config.NATThen{Type: config.NATDestination, PoolName: "nope"},
			}},
		}},
	}
	var b strings.Builder
	RenderDestRuleDetail(context.Background(), &b, cfg, nil, nil)
	got := b.String()

	if !strings.Contains(got, `address-less pool "nope"`) {
		t.Fatalf("a rule that DOES reference a missing pool must still name it "+
			"— the #6823 split must not swallow the #6534 dangling-pool "+
			"reason:\n%s", got)
	}
	if strings.Contains(got, "names no translation action") {
		t.Fatalf("a rule naming pool \"nope\" was reported as carrying no "+
			"translation action; it carries one, pointing at a pool that does "+
			"not exist:\n%s", got)
	}
}

// TestHealthyDestRuleIsNotAnnotated6823 is the PAIRED control. Without it,
// "the annotation names the fall-through" is satisfied by a renderer that
// prints the sentence on every destination rule — which is the same noise as
// annotating everything, and trains an operator to skip the line.
func TestHealthyDestRuleIsNotAnnotated6823(t *testing.T) {
	cfg := &config.Config{}
	cfg.Security.NAT.Destination = &config.DestinationNATConfig{
		Pools: map[string]*config.NATPool{"dp1": {Name: "dp1", Address: "10.0.0.5"}},
		RuleSets: []*config.NATRuleSet{{
			Name:     "rd1",
			FromZone: "untrust",
			Rules: []*config.NATRule{{
				Name: "ok",
				Then: config.NATThen{Type: config.NATDestination, PoolName: "dp1"},
			}},
		}},
	}
	var b strings.Builder
	RenderDestRuleDetail(context.Background(), &b, cfg, nil, nil)
	got := b.String()

	if strings.Contains(got, "ADMITTED BY TOLERANT LOAD") {
		t.Fatalf("a well-formed destination rule was annotated:\n%s", got)
	}
	if strings.Contains(got, "falls through") {
		t.Fatalf("a well-formed destination rule was told its traffic falls "+
			"through:\n%s", got)
	}
}
