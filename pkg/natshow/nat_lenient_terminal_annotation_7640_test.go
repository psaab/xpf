package natshow

import (
	"context"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// nat_lenient_terminal_annotation_7640_test.go — #7640.
//
// The operator looking at the offending rule was the one person guaranteed not
// to be told about it: the compile-time warning goes to the commit response,
// which a tolerant LOAD does not have. These cells bind the annotation, and the
// action-rendering defect it sits next to.

func actionlessSourceCfg7640() *config.Config {
	cfg := &config.Config{}
	cfg.Security.NAT.Source = []*config.NATRuleSet{{
		Name:     "rs1",
		FromZone: "trust",
		ToZone:   "untrust",
		Rules:    []*config.NATRule{{Name: "actionless"}}, // no terminal action
	}}
	cfg.LenientNATTerminalActionRules = []config.LenientNATTerminalActionRule{
		{Reason: config.LenientNATTerminalActionReasonActionless, Kind: "source", RuleSet: "rs1", Rule: "actionless", Actions: 0},
	}
	return cfg
}

// TestActionlessSourceRuleIsNotRenderedAsInterface7640 pins a display defect
// the annotation work uncovered, and it is the worse half of the two.
//
// The action string defaulted to "interface" whenever neither a pool nor `off`
// was set — so an ACTIONLESS rule displayed `Action: interface`, an action it
// does not carry and will not perform. For the one rule shape an operator most
// needs to find, the view actively asserted the wrong thing.
//
// FAIL-ON-REVERT: restore the `action := "interface"` default and the "none"
// assertion reds.
func TestActionlessSourceRuleIsNotRenderedAsInterface7640(t *testing.T) {
	var b strings.Builder
	RenderSourceRuleDetail(context.Background(), &b, actionlessSourceCfg7640(), nil, nil)
	got := b.String()

	if strings.Contains(got, "Action:                  interface") {
		t.Fatalf("an ACTIONLESS rule rendered as `Action: interface` — the view "+
			"claims an action the rule does not carry, on exactly the rule shape "+
			"an operator is trying to find (#7640):\n%s", got)
	}
	if !strings.Contains(got, "Action:                  none") {
		t.Fatalf("expected `Action: none` for a rule with no terminal action:\n%s", got)
	}
}

// TestLenientlyAdmittedSourceRuleIsAnnotated7640 is the surface the issue is
// about: the rule the tolerant path admitted says so, where the operator is
// already looking.
//
// FAIL-ON-REVERT: drop the noteLenientTerminalAction call and the annotation
// disappears while every other line still renders — the pre-#7640 silence.
func TestLenientlyAdmittedSourceRuleIsAnnotated7640(t *testing.T) {
	var b strings.Builder
	RenderSourceRuleDetail(context.Background(), &b, actionlessSourceCfg7640(), nil, nil)
	got := b.String()

	if !strings.Contains(got, "ADMITTED BY TOLERANT LOAD") {
		t.Fatalf("the rule the tolerant path admitted is not annotated — an "+
			"operator inspecting it cannot tell a commit would refuse it "+
			"(#7640):\n%s", got)
	}
	// The consequence, not just the fact: for source NAT the fall-through is
	// what the operator has to reason about.
	if !strings.Contains(got, "falls through") {
		t.Fatalf("the annotation does not name the CONSEQUENCE (fall-through to a "+
			"later broader rule), which is the part that decides whether this "+
			"matters:\n%s", got)
	}
}

// TestHealthyRuleIsNotAnnotated7640 is the PAIRED control. Without it, "the
// annotation appears" is satisfied by a renderer that annotates every rule,
// which would train an operator to ignore it.
func TestHealthyRuleIsNotAnnotated7640(t *testing.T) {
	cfg := &config.Config{}
	cfg.Security.NAT.Source = []*config.NATRuleSet{{
		Name:  "rs1",
		Rules: []*config.NATRule{{Name: "ok", Then: config.NATThen{Interface: true}}},
	}}
	var b strings.Builder
	RenderSourceRuleDetail(context.Background(), &b, cfg, nil, nil)
	got := b.String()

	if strings.Contains(got, "ADMITTED BY TOLERANT LOAD") {
		t.Fatalf("a well-formed rule was annotated:\n%s", got)
	}
	if !strings.Contains(got, "Action:                  interface") {
		t.Fatalf("a genuine interface rule must still render as `interface`:\n%s", got)
	}
}

// TestAnnotationIsScopedToTheNamedRule7640 pins that the record is matched on
// identity rather than smeared across the rule-set. A tolerantly-loaded config
// usually carries SOME good rules too, and annotating those would be the same
// noise as annotating everything.
func TestAnnotationIsScopedToTheNamedRule7640(t *testing.T) {
	cfg := actionlessSourceCfg7640()
	cfg.Security.NAT.Source[0].Rules = append(cfg.Security.NAT.Source[0].Rules,
		&config.NATRule{Name: "healthy", Then: config.NATThen{Interface: true}})

	var b strings.Builder
	RenderSourceRuleDetail(context.Background(), &b, cfg, nil, nil)
	got := b.String()

	if n := strings.Count(got, "ADMITTED BY TOLERANT LOAD"); n != 1 {
		t.Fatalf("annotation appeared %d times for one recorded rule in a "+
			"two-rule rule-set; it must be scoped to the named rule:\n%s", n, got)
	}
	// And it is attached to the right one: the annotation must follow the
	// actionless rule's header, not the healthy one's.
	iActionless := strings.Index(got, "source NAT rule: actionless")
	iHealthy := strings.Index(got, "source NAT rule: healthy")
	iNote := strings.Index(got, "ADMITTED BY TOLERANT LOAD")
	if !(iActionless < iNote && iNote < iHealthy) {
		t.Fatalf("the annotation is not attached to the actionless rule "+
			"(actionless@%d note@%d healthy@%d):\n%s", iActionless, iNote, iHealthy, got)
	}
}

func TestDuplicatePoolRuleIsAnnotated17253(t *testing.T) {
	cfg := &config.Config{}
	cfg.Security.NAT.Source = []*config.NATRuleSet{{
		Name:     "rs1",
		FromZone: "trust",
		ToZone:   "untrust",
		Rules:    []*config.NATRule{{Name: "duplicate-pools", Then: config.NATThen{PoolName: "P"}}},
	}}
	cfg.LenientNATTerminalActionRules = []config.LenientNATTerminalActionRule{
		{
			Reason: config.LenientNATTerminalActionReasonDuplicatePools,
			Kind:   "source", RuleSet: "rs1", Rule: "duplicate-pools", Actions: 2,
		},
	}

	var b strings.Builder
	RenderSourceRuleDetail(context.Background(), &b, cfg, nil, nil)
	got := b.String()
	if !strings.Contains(got, "ADMITTED BY TOLERANT LOAD") ||
		!strings.Contains(got, "2 different pools") ||
		!strings.Contains(got, "silently discarded") {
		t.Fatalf("duplicate-pool finding lacks its specific consequence:\n%s", got)
	}
	if strings.Contains(got, "mutually-exclusive actions") {
		t.Fatalf("duplicate-pool finding was rendered as an action contradiction:\n%s", got)
	}
}
