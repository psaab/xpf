package routing

import (
	"fmt"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// pbr16802Dsts returns n distinct destination prefixes for one steering term.
func pbr16802Dsts(n int) []string {
	out := make([]string, 0, n)
	for i := range n {
		out = append(out, fmt.Sprintf("198.51.%d.0/24", i))
	}
	return out
}

// pbr16802Config builds a config attaching each named filter as the inet
// input filter on successive interfaces ge-0/0/0, ge-0/0/1, ... in order.
func pbr16802Config(filters []*config.FirewallFilter, attached []string) *config.Config {
	cfg := &config.Config{RoutingInstances: []*config.RoutingInstanceConfig{{Name: "ATT", TableID: 101}}}
	cfg.Firewall.FiltersInet = make(map[string]*config.FirewallFilter, len(filters))
	for _, f := range filters {
		cfg.Firewall.FiltersInet[f.Name] = f
	}
	cfg.Interfaces.Interfaces = make(map[string]*config.InterfaceConfig, len(attached))
	for i, name := range attached {
		ifName := fmt.Sprintf("ge-0/0/%d", i)
		cfg.Interfaces.Interfaces[ifName] = &config.InterfaceConfig{
			Name:  ifName,
			Units: map[int]*config.InterfaceUnit{0: {Number: 0, FilterInputV4: name}},
		}
	}
	return cfg
}

func pbr16802Filter(name string) *config.FirewallFilter {
	return &config.FirewallFilter{
		Name: name,
		Terms: []*config.FirewallFilterTerm{
			{Name: "steer", DestAddresses: pbr16802Dsts(250), RoutingInstance: "ATT"},
		},
	}
}

// TestBuildPBRRulesWindowExhaustedMultiAttach16802 is the #16802 acceptance
// probe: one filter with a 250-dst term attached on three interfaces fills
// the 500-rule window exactly with the first two attachments, so only the
// third attachment loses its steer — degraded must be 1, exactly as the
// twin control of three distinctly named filters reports.
//
// FAIL-ON-REVERT: pre-fix accountPBRWindowExhausted resumed at the first
// attachment of the triggering filter NAME, re-accounting the installed
// second attachment and the trigger itself — degraded=3 with three
// identical error lines.
func TestBuildPBRRulesWindowExhaustedMultiAttach16802(t *testing.T) {
	shared := pbr16802Filter("sharedF")
	multi := pbr16802Config([]*config.FirewallFilter{shared},
		[]string{"sharedF", "sharedF", "sharedF"})

	rules, degraded := PBRBuildRulesAndStats(multi)
	if len(rules) != maxPBRSteeringRules {
		t.Fatalf("multi-attach rules = %d, want exactly the %d cap", len(rules), maxPBRSteeringRules)
	}
	if degraded != 1 {
		t.Errorf("multi-attach degraded = %d, want 1 (only ge-0/0/2 lost its steer)", degraded)
	}

	// Twin control: three distinctly named filters with identical terms.
	distinct := pbr16802Config(
		[]*config.FirewallFilter{pbr16802Filter("ctrlA"), pbr16802Filter("ctrlB"), pbr16802Filter("ctrlC")},
		[]string{"ctrlA", "ctrlB", "ctrlC"})
	rules, degraded = PBRBuildRulesAndStats(distinct)
	if len(rules) != maxPBRSteeringRules {
		t.Fatalf("control rules = %d, want exactly the %d cap", len(rules), maxPBRSteeringRules)
	}
	if degraded != 1 {
		t.Errorf("control degraded = %d, want 1 (only the third filter lost its steer)", degraded)
	}
}

// TestBuildPBRRulesWindowExhaustedMultiAttachLaterStillCounted16802 pins
// that accounting resumes strictly AFTER the triggering attachment, not
// after every attachment of the same name: with the same 250-dst filter on
// four interfaces, the third attachment triggers exhaustion and the fourth
// is also lost — degraded must be 2.
//
// FAIL-ON-REVERT: pre-fix degraded=4 (trigger plus re-accounted installed
// and triggering attachments and the genuinely lost fourth); a fix that
// skipped the whole filter name would report 1.
func TestBuildPBRRulesWindowExhaustedMultiAttachLaterStillCounted16802(t *testing.T) {
	shared := pbr16802Filter("sharedF")
	cfg := pbr16802Config([]*config.FirewallFilter{shared},
		[]string{"sharedF", "sharedF", "sharedF", "sharedF"})

	rules, degraded := PBRBuildRulesAndStats(cfg)
	if len(rules) != maxPBRSteeringRules {
		t.Fatalf("rules = %d, want exactly the %d cap", len(rules), maxPBRSteeringRules)
	}
	if degraded != 2 {
		t.Errorf("degraded = %d, want 2 (third attachment triggered, fourth also lost)", degraded)
	}
}
