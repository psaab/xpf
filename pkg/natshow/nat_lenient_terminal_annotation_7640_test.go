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
		!strings.Contains(got, "collapse during lowering") ||
		!strings.Contains(got, "compiled `then` shape") {
		t.Fatalf("duplicate-pool finding lacks its shape-dependent consequence:\n%s", got)
	}
	if strings.Contains(got, "mutually-exclusive actions") ||
		strings.Contains(strings.ToLower(got), "first pool") {
		t.Fatalf("duplicate-pool finding was misclassified or claimed a guaranteed first pool:\n%s", got)
	}
}

func TestUnknownReasonDoesNotFallBackToActionless17253(t *testing.T) {
	for _, tc := range []struct {
		name   string
		reason config.LenientNATTerminalActionReason
	}{
		{name: "empty", reason: ""},
		{name: "unknown", reason: "future-reason"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := actionlessSourceCfg7640()
			cfg.LenientNATTerminalActionRules[0].Reason = tc.reason

			var b strings.Builder
			RenderSourceRuleDetail(context.Background(), &b, cfg, nil, nil)
			got := b.String()
			if strings.Contains(got, "ADMITTED BY TOLERANT LOAD") ||
				strings.Contains(got, "falls through") {
				t.Fatalf("reason %q was rendered with the actionless consequence:\n%s",
					tc.reason, got)
			}
		})
	}
}
func TestCompiledDuplicatePoolResolutionMatches17253(t *testing.T) {
	fixtures := []struct {
		name     string
		then     string
		wantPool string
		wantOff  bool
	}{
		{
			name:     "sibling-destination-nat-nodes",
			then:     "then { destination-nat { pool PD; } destination-nat { pool PD2; } }",
			wantPool: "PD2",
		},
		{
			name:     "duplicate-pools-with-off",
			then:     "then { destination-nat { pool PD; pool PD2; off; } }",
			wantPool: "PD",
			wantOff:  true,
		},
	}
	for _, fixture := range fixtures {
		t.Run(fixture.name, func(t *testing.T) {
			text := `security {
  zones { security-zone untrust; }
  nat { destination {
    pool PD { address 10.0.0.5; }
    pool PD2 { address 10.0.0.6; }
    rule-set RD { from zone untrust;
      rule R1 {
        match { destination-address 203.0.113.10/32; }
        ` + fixture.then + `
      }
    }
  } }
}`
			tree, parseErr := config.NewParser(text).Parse()
			if len(parseErr) != 0 {
				t.Fatalf("fixture did not parse: %v", parseErr)
			}
			cfg, err := config.CompileConfigLenient(tree)
			if err != nil {
				t.Fatalf("lenient compile failed: %v", err)
			}
			if len(cfg.LenientNATTerminalActionRules) != 1 {
				t.Fatalf("findings = %+v, want one duplicate-pool finding", cfg.LenientNATTerminalActionRules)
			}
			finding := cfg.LenientNATTerminalActionRules[0]
			if finding.Reason != config.LenientNATTerminalActionReasonDuplicatePools || finding.Actions != 2 {
				t.Fatalf("finding = %+v, want duplicate pools (2)", finding)
			}
			rule := cfg.Security.NAT.Destination.RuleSets[0].Rules[0]
			if rule.Then.PoolName != fixture.wantPool || rule.Then.Off != fixture.wantOff {
				t.Fatalf("resolved Then = %+v, want pool=%q off=%v",
					rule.Then, fixture.wantPool, fixture.wantOff)
			}
			var rendered strings.Builder
			RenderDestRuleDetail(context.Background(), &rendered, cfg, nil, nil)
			got := rendered.String()
			for _, want := range []string{
				"ADMITTED BY TOLERANT LOAD",
				"2 different pools",
				"collapse during lowering",
				"compiled `then` shape",
			} {
				if !strings.Contains(got, want) {
					t.Errorf("duplicate-pool annotation missing %q:\n%s", want, got)
				}
			}
			if strings.Contains(strings.ToLower(got), "first pool") ||
				strings.Contains(got, "all but the first") {
				t.Fatalf("annotation claims a guaranteed first pool:\n%s", got)
			}
		})
	}
}

func TestPackedContradictionUsesAuthoredOrderAnnotation17253(t *testing.T) {
	fixtures := []struct {
		name     string
		modes    string
		wantPool string
		wantOff  bool
	}{
		{name: "off-first", modes: "off pool P", wantOff: true},
		{name: "pool-first", modes: "pool P off", wantPool: "P"},
	}
	for _, fixture := range fixtures {
		t.Run(fixture.name, func(t *testing.T) {
			text := `security { zones { security-zone trust; security-zone untrust; } nat { source {
  pool P { address 203.0.113.5; }
  rule-set RS { from zone trust; to zone untrust;
    rule R1 { match { source-address 10.0.0.0/24; }
      then { source-nat ` + fixture.modes + `; }
    }
  } } } }`
			tree, parseErr := config.NewParser(text).Parse()
			if len(parseErr) != 0 {
				t.Fatalf("fixture did not parse: %v", parseErr)
			}
			cfg, err := config.CompileConfigLenient(tree)
			if err != nil {
				t.Fatalf("lenient compile failed: %v", err)
			}
			if len(cfg.LenientNATTerminalActionRules) != 1 {
				t.Fatalf("findings = %+v, want one packed-contradiction finding",
					cfg.LenientNATTerminalActionRules)
			}
			finding := cfg.LenientNATTerminalActionRules[0]
			if finding.Reason != config.LenientNATTerminalActionReasonPackedContradiction ||
				finding.Actions != 2 {
				t.Fatalf("finding = %+v, want packed contradiction with 2 authored modes", finding)
			}
			resolved := cfg.Security.NAT.Source[0].Rules[0].Then
			if resolved.PoolName != fixture.wantPool || resolved.Off != fixture.wantOff {
				t.Fatalf("resolved Then = %+v, want pool=%q off=%v",
					resolved, fixture.wantPool, fixture.wantOff)
			}
			var rendered strings.Builder
			RenderSourceRuleDetail(context.Background(), &rendered, cfg, nil, nil)
			got := rendered.String()
			if !strings.Contains(got, "first authored mode takes effect") ||
				!strings.Contains(got, "order determines the applied action") {
				t.Fatalf("packed contradiction annotation does not explain authored-order resolution:\n%s", got)
			}
			if strings.Contains(got, "fixed precedence") {
				t.Fatalf("packed contradiction was rendered with multi-action precedence:\n%s", got)
			}
		})
	}
}
