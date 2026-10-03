package frr

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

func TestConflictingNextPolicyTerminalActionFailsClosed11780(t *testing.T) {
	for _, action := range []string{"accept", "reject"} {
		t.Run(action, func(t *testing.T) {
			ps := &config.PolicyStatement{
				Name:          "ONLY",
				DefaultAction: "reject",
				Terms:         []*config.PolicyTerm{{Name: "bad", Action: action, NextPolicy: true}},
			}
			po := &config.PolicyOptionsConfig{PolicyStatements: map[string]*config.PolicyStatement{"ONLY": ps}}
			body, next := New().renderPolicyTermSequences(po, "ONLY", "ONLY", ps, 10)
			if !strings.Contains(body, "route-map ONLY deny 10\n") {
				t.Fatalf("conflicting action must render as deny, got:\n%s", body)
			}
			if strings.Contains(body, "on-match goto") || strings.Contains(body, "on-match next") || strings.Contains(body, nextPolicySequenceMarker) {
				t.Fatalf("conflicting action must not continue or jump, got:\n%s", body)
			}
			if next != 20 {
				t.Fatalf("term sequence end = %d, want 20", next)
			}
			if policyHasNextPolicyTerm(ps) {
				t.Fatal("conflicting action must not be treated as a valid next-policy jump")
			}
			if got := config.RouteMapSequenceCount(po, ps); got != 1 {
				t.Fatalf("sequence count = %d, want one term sequence without a bypassable default", got)
			}
		})
	}
}

func TestNarrowedSurvivorTreatsConflictingNextPolicyAsDeny11780(t *testing.T) {
	po := &config.PolicyOptionsConfig{PolicyStatements: map[string]*config.PolicyStatement{
		"BAD": {Name: "BAD", Terms: []*config.PolicyTerm{{Name: "bad", Action: "accept", NextPolicy: true}}},
	}}
	if got := narrowedSurvivorShape10129([]string{"BAD"}, po); got != "match-all" {
		t.Fatalf("unconditional conflicting action is rendered as deny and terminates: shape=%q", got)
	}
}
