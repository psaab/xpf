package daemon

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #14632 (Y26-02): a modifier-only term (`then count bgp;`, no authored
// `next term`) terminates as an implicit Accept in Junos — nonterminating
// actions "carry with them an implicit accept action". The kernel lo0 mirror
// must therefore emit a TERMINATING accept (with the honored log/count
// modifiers riding it), not a non-terminating modifier rule that lets a later
// discard blackhole the counted traffic. Only an authored `then next term`
// falls through.
//
// FAIL-ON-REVERT: restoring `term.Action == "" && term.RoutingInstance == ""`
// as the fall-through guard makes the modifier-only cells below go RED (the
// rule loses its `accept` verdict and falls through to the later drop).

func TestNftModifierOnlyTerminatesAsAccept14632(t *testing.T) {
	prefixLists := map[string]*config.PrefixList{}

	// Modifier-only with honored modifiers: terminating accept, modifiers ride.
	term := &config.FirewallFilterTerm{
		Name: "count-bgp", Protocols: []string{"tcp"}, Count: "bgp", Log: true,
	}
	rules := nftRulesFromTerm(term, "ip", prefixLists)
	if len(rules) != 1 {
		t.Fatalf("modifier-only: got %d rules, want 1: %v", len(rules), rules)
	}
	if !strings.HasSuffix(rules[0], " accept") {
		t.Errorf("modifier-only must terminate as implicit accept, got %q", rules[0])
	}
	if !strings.Contains(rules[0], `counter name "xpflo0_bgp"`) {
		t.Errorf("modifier-only accept lost its count modifier: %q", rules[0])
	}

	// Modifier-only with NO honored modifier (forwarding-class only): still a
	// terminating bare accept — it must shadow a later discard exactly as the
	// Rust evaluator's implicit accept does.
	fcTerm := &config.FirewallFilterTerm{
		Name: "fc-only", Protocols: []string{"tcp"}, ForwardingClass: "expedited-forwarding",
	}
	if got := nftRule(t, fcTerm, "ip", prefixLists); got != "meta l4proto 6 accept" {
		t.Errorf("unhonored-modifier-only: got %q, want terminating %q", got, "meta l4proto 6 accept")
	}

	// Control: authored `next term` (with the same honored modifiers) still
	// falls through — a NON-TERMINATING rule with no verdict.
	nextTerm := &config.FirewallFilterTerm{
		Name: "count-next", Protocols: []string{"tcp"}, Count: "bgp", Log: true, NextTerm: true,
	}
	nextRules := nftRulesFromTerm(nextTerm, "ip", prefixLists)
	if len(nextRules) != 1 {
		t.Fatalf("explicit next-term: got %d rules, want 1: %v", len(nextRules), nextRules)
	}
	for _, verdict := range []string{"accept", "drop", "reject"} {
		if strings.Contains(nextRules[0], verdict) {
			t.Errorf("explicit next-term emitted a terminating %q: %q", verdict, nextRules[0])
		}
	}
}

func TestLo0PayloadModifierOnlyShadowsLaterDiscard14632(t *testing.T) {
	// End-to-end acceptance shape: `then count bgp;` (tcp/179) ahead of a
	// final discard must ACCEPT at the modifier-only term in the kernel
	// payload, so the discard never sees BGP traffic.
	cfg := &config.Config{}
	cfg.Firewall.FiltersInet = map[string]*config.FirewallFilter{
		"lo0-in": {
			Name: "lo0-in",
			Terms: []*config.FirewallFilterTerm{
				{Name: "count-bgp", Protocols: []string{"tcp"}, DestinationPorts: []string{"179"}, Count: "bgp"},
				{Name: "deny-rest", Protocols: []string{"tcp"}, Action: "discard"},
			},
		},
	}
	payload := buildLo0FilterPayload(cfg, "lo0-in", "")
	acceptIdx := strings.Index(payload, "accept")
	dropIdx := strings.Index(payload, "drop")
	if acceptIdx < 0 {
		t.Fatalf("modifier-only term emitted no terminating accept in lo0 payload (#14632):\n%s", payload)
	}
	if dropIdx < 0 {
		t.Fatalf("discard term missing from lo0 payload:\n%s", payload)
	}
	if acceptIdx > dropIdx {
		t.Fatalf("term order inverted in lo0 payload:\n%s", payload)
	}

	// Control: the same filter with authored `next term` on the count term.
	cfg2 := &config.Config{}
	cfg2.Firewall.FiltersInet = map[string]*config.FirewallFilter{
		"lo0-in": {
			Name: "lo0-in",
			Terms: []*config.FirewallFilterTerm{
				{Name: "count-bgp", Protocols: []string{"tcp"}, DestinationPorts: []string{"179"}, Count: "bgp", NextTerm: true},
				{Name: "deny-rest", Protocols: []string{"tcp"}, Action: "discard"},
			},
		},
	}

	payload2 := buildLo0FilterPayload(cfg2, "lo0-in", "")
	// The chain header carries `policy accept;` — scope the verdict checks to
	// the count term's rule line (dport 179), which must carry NO verdict.
	for _, line := range strings.Split(payload2, "\n") {
		if strings.Contains(line, "dport 179") && strings.Contains(line, "accept") {
			t.Errorf("explicit next-term count rule must not terminate as accept:\n%s", payload2)
		}
	}
	if !strings.Contains(payload2, "drop") {
		t.Errorf("explicit next-term payload lost the reachable discard:\n%s", payload2)
	}
}
