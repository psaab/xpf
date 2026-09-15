package natshow

import (
	"context"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #9879 show surface: a broad `off` exemption a narrower later translate rule
// re-enters must not render as a fully-armed exemption. The rule IS installed
// (it still exempts the non-overlapping remainder), so the annotation leads
// with PARTIALLY SHADOWED — never NOT INSTALLED, which would promise
// fall-through that does not happen.

func shadowedOffCfg9879() *config.Config {
	cfg := &config.Config{}
	dnat := &config.DestinationNATConfig{
		Pools: map[string]*config.NATPool{
			"p1": {Name: "p1", Address: "192.168.1.10"},
		},
	}
	dnat.RuleSets = []*config.NATRuleSet{{
		Name:     "rs1",
		FromZone: "untrust",
		Rules: []*config.NATRule{
			{
				Name: "r-exempt",
				Match: config.NATMatch{
					DestinationAddress: "192.0.2.10/32",
				},
				Then: config.NATThen{Type: config.NATDestination, Off: true},
			},
			{
				Name: "r-dnat",
				Match: config.NATMatch{
					DestinationAddress: "192.0.2.10/32",
					DestinationPorts:   []int{80},
				},
				Then: config.NATThen{Type: config.NATDestination, PoolName: "p1"},
			},
		},
	}}
	cfg.Security.NAT.Destination = dnat
	return cfg
}

func TestShadowedOffRuleIsAnnotatedPartiallyShadowed_9879(t *testing.T) {
	var b strings.Builder
	RenderDestRuleDetail(context.Background(), &b, shadowedOffCfg9879(), nil, nil)
	got := b.String()
	if !strings.Contains(got, "PARTIALLY SHADOWED") {
		t.Fatalf("shadowed off rule not annotated PARTIALLY SHADOWED:\n%s", got)
	}
	if !strings.Contains(got, `"r-dnat"`) {
		t.Fatalf("annotation does not name the re-entering translate rule:\n%s", got)
	}
	if strings.Contains(got, "NOT INSTALLED") {
		t.Fatalf("shadowed off rule claims NOT INSTALLED — it IS installed (partial shadow, not exclusion):\n%s", got)
	}
}

func TestHealthyOffRuleHasNoShadowWarning_9879(t *testing.T) {
	cfg := shadowedOffCfg9879()
	// Narrow the off to the same tier as the translate: same exact port, so
	// config order wins and the off holds — no shadow, no warning.
	cfg.Security.NAT.Destination.RuleSets[0].Rules[0].Match.DestinationPorts = []int{80}
	var b strings.Builder
	RenderDestRuleDetail(context.Background(), &b, cfg, nil, nil)
	got := b.String()
	if strings.Contains(got, "PARTIALLY SHADOWED") {
		t.Fatalf("healthy off rule gained a shadow warning:\n%s", got)
	}
	if !strings.Contains(got, "Action:                  off") {
		t.Fatalf("off rule no longer renders as an exemption:\n%s", got)
	}
}
