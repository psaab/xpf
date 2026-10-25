package routing

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// compileFBF16623 builds the issue's strict-compiled shape: an input filter
// on ge-0/0/2 with a carve term followed by an overlapping steer term, plus
// the ISP2 forwarding instance the steer targets.
func compileFBF16623(t *testing.T, carveThen ...string) *config.Config {
	t.Helper()
	lines := []string{
		"set routing-instances ISP2 instance-type forwarding",
		"set firewall family inet filter fbf term carve from source-address 10.0.0.0/8",
	}
	for _, then := range carveThen {
		lines = append(lines, "set firewall family inet filter fbf term carve then "+then)
	}
	lines = append(lines,
		"set firewall family inet filter fbf term steer from source-address 10.1.0.0/16",
		"set firewall family inet filter fbf term steer then routing-instance ISP2",
		"set interfaces ge-0/0/2 unit 0 family inet filter input fbf",
	)
	tree := &config.ConfigTree{}
	for _, command := range lines {
		path, err := config.ParseSetCommand(command)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", command, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", command, err)
		}
	}
	cfg, err := config.CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	return cfg
}

// #16623: a modifier-only carve term (`then count mgmt`) terminates as
// implicit accept since #14632, so the kernel PBR mirror must NOT install an
// ip rule steering its 10.1.0.0/16 subset into ISP2. The steer is dropped
// with the shadow degraded error instead.
//
// FAIL-ON-REVERT: restoring the old `Action != Unset || RoutingInstance != ""`
// recording predicate makes the count-only cell emit 1 rule with no error.
func TestCompiledModifierOnlyCarveShadowsLaterSteer16623(t *testing.T) {
	cfg := compileFBF16623(t, "count mgmt")

	carve := cfg.Firewall.FiltersInet["fbf"].Terms[0]
	if carve.Action != config.FilterActionUnset || carve.NextTerm || carve.Count != "mgmt" {
		t.Fatalf("carve compiled wrong: Action=%q NextTerm=%v Count=%q", carve.Action, carve.NextTerm, carve.Count)
	}

	rules, err := BuildPBRRules(cfg)
	if len(rules) != 0 {
		t.Fatalf("modifier-only carve-out must shadow the steer: got %d rules %+v, want 0", len(rules), rules)
	}
	if err == nil || !strings.Contains(err.Error(), "term steer is shadowed by a preceding terminating term") {
		t.Fatalf("want shadow degraded error for term steer, got %v", err)
	}
	if _, degraded := PBRBuildRulesAndStats(cfg); degraded < 1 {
		t.Fatalf("shadowed steer must count as degraded, got %d", degraded)
	}
}

// Control: the same carve with an explicit `accept` behaves identically —
// the modifier-only cell above must match this, not the fall-through cell.
func TestCompiledExplicitAcceptCarveShadowsLaterSteer16623(t *testing.T) {
	cfg := compileFBF16623(t, "count mgmt", "accept")

	rules, err := BuildPBRRules(cfg)
	if len(rules) != 0 {
		t.Fatalf("explicit accept carve-out must shadow the steer: got %d rules %+v, want 0", len(rules), rules)
	}
	if err == nil || !strings.Contains(err.Error(), "term steer is shadowed by a preceding terminating term") {
		t.Fatalf("want shadow degraded error for term steer, got %v", err)
	}
}

// Twin: the same carve authored as fall-through (`then count mgmt` +
// `then next term`) must NOT shadow — the steer rule is built for ISP2
// scoped to the attached interface.
func TestCompiledNextTermCarveDoesNotShadowLaterSteer16623(t *testing.T) {
	cfg := compileFBF16623(t, "count mgmt", "next term")

	carve := cfg.Firewall.FiltersInet["fbf"].Terms[0]
	if !carve.NextTerm || carve.Action != config.FilterActionUnset || carve.Count != "mgmt" {
		t.Fatalf("fall-through carve compiled wrong: Action=%q NextTerm=%v Count=%q", carve.Action, carve.NextTerm, carve.Count)
	}

	rules, err := BuildPBRRules(cfg)
	if err != nil {
		t.Fatalf("authored fall-through must not degrade the steer: %v", err)
	}
	if len(rules) != 1 {
		t.Fatalf("authored fall-through must keep the steer: got %d rules %+v, want 1", len(rules), rules)
	}
	if rules[0].Src != "10.1.0.0/16" || rules[0].Instance != "ISP2" || rules[0].IifName != "ge-0-0-2" {
		t.Fatalf("steer rule = %+v, want Src=10.1.0.0/16 Instance=ISP2 IifName=ge-0-0-2", rules[0])
	}
}
