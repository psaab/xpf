package api

import (
	"strings"
	"testing"
)

// metrics_nat_lenient_terminal_7640_test.go — #7640.
//
// A NAT rule admitted by the tolerant load / peer-sync / rollback path despite
// the strict terminal-action gate had no live signal at all. The compile-time
// warning reaches an operator through the commit RESPONSE and an apply-time log
// line — and a tolerant LOAD has neither, which is precisely the path on which
// such a rule survives. The node then runs indefinitely carrying a rule a
// commit would refuse.
//
// This binds the WIRING: the record can be correct on the config and the
// operator still sees nothing if the accessor never reaches a Desc.

// TestNATLenientTerminalActionGauge7640 is PAIRED across three points.
//
// The healthy leg is load-bearing: the gauge must publish an explicit 0, not go
// absent, on a clean node. An alert written `xpf_nat_rules_lenient_terminal_action > 0`
// cannot distinguish "none admitted" from "this series stopped being reported",
// so a gauge that vanishes when healthy is the same blindness the metric exists
// to remove.
//
// The two-rule leg rejects a gauge hardwired to 1, which would look right
// against a single-rule fixture and under-report every real config — one
// tolerantly-loaded config commonly carries several such rules, since whatever
// produced one (a pre-gate release, an older peer) produced them all.
func TestNATLenientTerminalActionGauge7640(t *testing.T) {
	for _, tc := range []struct {
		name  string
		rules []string
		want  float64
	}{
		{"healthy", nil, 0},
		{"one-rule", []string{"source rule-set rs1 rule r (0 actions)"}, 1},
		{"several-rules", []string{
			"source rule-set rs1 rule r (0 actions)",
			"destination rule-set drs rule d (2 actions)",
		}, 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := &Server{ // dp intentionally nil — config-only boot must still report
				natLenientTerminalActionRulesFn: func() []string { return tc.rules },
			}
			got, ok := gatherSingleSample6802(t, s, "xpf_nat_rules_lenient_terminal_action")
			if !ok {
				t.Fatal("xpf_nat_rules_lenient_terminal_action was not emitted — a " +
					"node running a NAT rule a commit would refuse looks identical " +
					"to a clean one (#7640)")
			}
			if got != tc.want {
				t.Errorf("gauge = %v, want %v — it does not track the wired fn, so "+
					"it reports the same value whether or not the node is running "+
					"rules the strict gate rejects", got, tc.want)
			}
		})
	}
}

// TestNATLenientTerminalActionGaugeAbsentWhenUnwired7640 pins the other half of
// the optional-hook contract. With no hook wired the series must not be
// published at all rather than published as a constant 0: a hardcoded 0 from a
// process that never consulted the active config asserts "no rule was admitted"
// on something that has no idea, and an operator alerting on this series would
// read that as an all-clear.
func TestNATLenientTerminalActionGaugeAbsentWhenUnwired7640(t *testing.T) {
	s := &Server{} // natLenientTerminalActionRulesFn deliberately nil
	if _, ok := gatherSingleSample6802(t, s, "xpf_nat_rules_lenient_terminal_action"); ok {
		t.Fatal("xpf_nat_rules_lenient_terminal_action was published with no hook " +
			"wired — that reports a confident 'nothing admitted' from a process " +
			"that never read the active config")
	}
}

func TestNATLenientTerminalActionHelpNamesDuplicatePools17253(t *testing.T) {
	c := newCollector(&Server{})
	got := c.natRulesLenientTerminalAction.String()
	for _, want := range []string{"DUPLICATE-POOL", "distinct pools", "all but the first"} {
		if !strings.Contains(got, want) {
			t.Errorf("xpf_nat_rules_lenient_terminal_action help is missing %q: %s", want, got)
		}
	}
}
