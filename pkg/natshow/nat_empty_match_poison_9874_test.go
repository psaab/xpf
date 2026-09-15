package natshow

import (
	"context"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #9874 show surfaces: a rule whose authored match constrains nothing must not
// render as an armed rule. Source installs as claim-and-drop (ADMITTED-style
// note naming the drop); destination publishes nothing (NOT INSTALLED via the
// shared predicate).

func poisonedSourceCfg9874() *config.Config {
	cfg := &config.Config{}
	cfg.Security.NAT.SourcePools = map[string]*config.NATPool{
		"p1": {Name: "p1", Addresses: []string{"172.16.0.5/32"}},
	}
	cfg.Security.NAT.Source = []*config.NATRuleSet{{
		Name:     "rs1",
		FromZone: "trust",
		ToZone:   "untrust",
		Rules: []*config.NATRule{{
			Name:                "poisoned",
			Then:                config.NATThen{Type: config.NATSource, PoolName: "p1"},
			LenientMatchDropped: true,
		}},
	}}
	return cfg
}

func poisonedDestCfg9874() *config.Config {
	cfg := &config.Config{}
	dnat := &config.DestinationNATConfig{
		Pools: map[string]*config.NATPool{
			"p1": {Name: "p1", Address: "192.168.1.10"},
		},
	}
	dnat.RuleSets = []*config.NATRuleSet{{
		Name:     "rs1",
		FromZone: "untrust",
		Rules: []*config.NATRule{{
			Name:                "poisoned",
			Then:                config.NATThen{Type: config.NATDestination, PoolName: "p1"},
			LenientMatchDropped: true,
		}},
	}}
	cfg.Security.NAT.Destination = dnat
	return cfg
}

func TestPoisonedSourceRuleIsAnnotatedDrop_9874(t *testing.T) {
	var b strings.Builder
	RenderSourceRuleDetail(context.Background(), &b, poisonedSourceCfg9874(), nil, nil)
	got := b.String()
	if !strings.Contains(got, "ADMITTED BY TOLERANT LOAD") {
		t.Fatalf("poisoned source rule not annotated as tolerant-admitted:\n%s", got)
	}
	if !strings.Contains(got, "dropped") {
		t.Fatalf("annotation does not name the CONSEQUENCE (drop):\n%s", got)
	}
	if strings.Contains(got, "NOT INSTALLED") {
		t.Fatalf("poisoned source rule claims NOT INSTALLED — it installs as a drop, and the label would promise fall-through:\n%s", got)
	}
}

func TestPoisonedDestRuleIsAnnotatedNotInstalled_9874(t *testing.T) {
	var b strings.Builder
	RenderDestRuleDetail(context.Background(), &b, poisonedDestCfg9874(), nil, nil)
	got := b.String()
	if !strings.Contains(got, "NOT INSTALLED") {
		t.Fatalf("poisoned destination rule not annotated NOT INSTALLED (it publishes no entry):\n%s", got)
	}
	if !strings.Contains(got, "constrains nothing") {
		t.Fatalf("annotation does not name the cause:\n%s", got)
	}
}

// Operative-cause precedence: a marked rule that ALSO trips the terminal-action
// gate must not print the fall-through consequence — the drop stops evaluation.
func TestPoisonedSourceRuleSubsumesTerminalActionNote_9874(t *testing.T) {
	cfg := poisonedSourceCfg9874()
	cfg.LenientNATTerminalActionRules = []config.LenientNATTerminalActionRule{
		{Kind: "source", RuleSet: "rs1", Rule: "poisoned", Actions: 0},
	}
	var b strings.Builder
	RenderSourceRuleDetail(context.Background(), &b, cfg, nil, nil)
	got := b.String()
	if !strings.Contains(got, "ADMITTED BY TOLERANT LOAD") {
		t.Fatalf("poison note missing:\n%s", got)
	}
	if strings.Contains(got, "falls through") {
		t.Fatalf("terminal-action fall-through text printed beside the drop note — contradiction:\n%s", got)
	}
}

// Healthy rules render byte-identical: no new annotation lines.
func TestHealthyNATRulesRenderUnannotated_9874(t *testing.T) {
	cfg := poisonedSourceCfg9874()
	cfg.Security.NAT.Source[0].Rules[0].LenientMatchDropped = false
	cfg.Security.NAT.Source[0].Rules[0].Match.SourceAddresses = []string{"10.0.0.0/24"}
	var b strings.Builder
	RenderSourceRuleDetail(context.Background(), &b, cfg, nil, nil)
	if got := b.String(); strings.Contains(got, "ADMITTED BY TOLERANT LOAD") || strings.Contains(got, "9874") {
		t.Fatalf("healthy source rule gained an annotation:\n%s", got)
	}
	dcfg := poisonedDestCfg9874()
	dcfg.Security.NAT.Destination.RuleSets[0].Rules[0].LenientMatchDropped = false
	dcfg.Security.NAT.Destination.RuleSets[0].Rules[0].Match.DestinationAddresses = []string{"203.0.113.10/32"}
	var db strings.Builder
	RenderDestRuleDetail(context.Background(), &db, dcfg, nil, nil)
	if got := db.String(); strings.Contains(got, "NOT INSTALLED") || strings.Contains(got, "9874") {
		t.Fatalf("healthy destination rule gained an annotation:\n%s", got)
	}
}
