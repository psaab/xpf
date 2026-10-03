package format

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #6848 (#4228 Gap 7 residual): `show class-of-service rewrite-rule`.
//
// The load-bearing property is NOT that the rules render — it is that the
// output distinguishes an ENFORCED rewrite rule from an inert one. Three of the
// four rewrite-rule families (ieee-802.1, inet-precedence, exp) commit clean and
// have no runtime effect; only dscp is applied on egress. Rendering them
// identically would reproduce, inside the command built to expose the problem,
// exactly the silence that made the problem worth fixing.

// testCoSRewriteRuleConfig builds all four rewrite-rule families. The two
// inert families are rendered as names only; although the compiler validates
// their entries into Go-only definitions, those values have no wire/runtime
// consumer and are intentionally not exposed by this show command.
func testCoSRewriteRuleConfig() *config.Config {
	cfg := testCoSConfig()
	cfg.ClassOfService.DSCPRewriteRules = map[string]*config.CoSDSCPRewriteRule{
		"rw-dscp": {
			Name: "rw-dscp",
			Entries: []*config.CoSDSCPRewriteRuleEntry{
				// Expedited-forwarding: DSCP 46 = 101110b.
				{ForwardingClass: "bandwidth-10mb", LossPriority: "low", DSCPValue: 46},
				// No explicit loss-priority -> renders the Junos "low" default.
				{ForwardingClass: "best-effort", DSCPValue: 0},
			},
		},
	}
	cfg.ClassOfService.IEEE8021RewriteRules = map[string]*config.CoSIEEE8021RewriteRule{
		"rw-pcp": {
			Name: "rw-pcp",
			Entries: []*config.CoSIEEE8021RewriteRuleEntry{
				{ForwardingClass: "bandwidth-10mb", LossPriority: "high", PCPValue: 5},
			},
		},
	}
	cfg.ClassOfService.INetPrecedenceRewriteRules = []string{"rw-prec"}
	cfg.ClassOfService.EXPRewriteRules = []string{"rw-exp"}
	// #6858 fold: BIND rw-dscp to the fixture's unit. Without this the rule is
	// configured-but-unbound and must NOT report as enforced -- the original
	// fixture omitted the binding and still asserted "Enforced: yes", so the
	// test pinned the defect rather than the contract. `Enforced: yes` has to
	// be earned by a real binding.
	cfg.ClassOfService.Interfaces["reth0"].Units[80].DSCPRewriteRule = "rw-dscp"
	return cfg
}

// testCoSRewriteRuleConfigUnbound is testCoSRewriteRuleConfig with the dscp
// binding removed: the rule is configured but no unit references it.
func testCoSRewriteRuleConfigUnbound() *config.Config {
	cfg := testCoSRewriteRuleConfig()
	cfg.ClassOfService.Interfaces["reth0"].Units[80].DSCPRewriteRule = ""
	return cfg
}

// TestFormatCoSRewriteRulesRendersAllFourFamilies pins that no family is
// silently dropped — including the two rendered as names only, with no visible
// code-point rows, which would be the easy ones to omit.
func TestFormatCoSRewriteRulesRendersAllFourFamilies(t *testing.T) {
	out := FormatCoSRewriteRules(testCoSRewriteRuleConfig(), "", "")
	for _, want := range []string{
		"Rewrite rule: rw-dscp, Code point type: dscp",
		"Rewrite rule: rw-pcp, Code point type: ieee-802.1",
		"Rewrite rule: rw-prec, Code point type: inet-precedence",
		"Rewrite rule: rw-exp, Code point type: exp",
		// dscp code points, rendered as binary like the classifier view.
		"101110",
		"000000",
		// The 3-bit PCP code point.
		"101",
		// Loss-priority default fills in for the unset entry.
		"best-effort",
		"low",
		"high",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in output:\n%s", want, out)
		}
	}
}

// TestFormatCoSRewriteRulesMarksInertTypes is the #6848 point of the command.
//
// FAIL-ON-REVERT: cosRewriteRuleEnforcement returns the rendered STRING, not a
// bool. Make it return "yes" unconditionally (or drop the Enforced column) and
// the three inert assertions go RED. Make it return an inert reason for dscp
// and the enforced assertion goes RED — so the test binds the mapping in BOTH
// directions rather than just "some marker is present".
func TestFormatCoSRewriteRulesMarksInertTypes(t *testing.T) {
	out := FormatCoSRewriteRules(testCoSRewriteRuleConfig(), "", "")

	// dscp IS applied on egress: it must NOT be marked inert.
	dscpLine := ruleHeaderLine(t, out, "rw-dscp")
	if !strings.Contains(dscpLine, "Enforced: yes") {
		t.Errorf("dscp rewrite rule must be reported as enforced; got header:\n%s", dscpLine)
	}

	// The other three commit clean and do nothing. Each must say so on its own
	// header line — an operator reading one rule must not have to notice the
	// absence of a marker on another.
	for _, name := range []string{"rw-pcp", "rw-prec", "rw-exp"} {
		line := ruleHeaderLine(t, out, name)
		if !strings.Contains(line, "Enforced: no") {
			t.Errorf("rule %q is accepted-but-inert and must be marked NOT enforced; got header:\n%s",
				name, line)
		}
		if !strings.Contains(line, "dataplane rewrites dscp only") {
			t.Errorf("rule %q inert marker must say WHAT the operator loses, not just "+
				"that a flag is off; got header:\n%s", name, line)
		}
	}
}

// TestFormatCoSRewriteRulesUnboundDSCPIsNotEnforced is the #6858 gate MAJOR pin.
//
// Runtime DSCP rewriting happens only for the rule an egress interface
// REFERENCES: the rewrite table is built from
// `tables.dscp_rewrite_rules.get(&iface.cos_dscp_rewrite_rule)`
// (forwarding_build/cos.rs), so a dscp rule no unit binds rewrites nothing.
//
// As first shipped, `Enforced` was computed from the code-point TYPE alone, so
// an unbound dscp rule printed "Enforced: yes". That is the accepted-but-inert
// failure class one level in — inside the command written to expose that very
// class — and worse than having no command at all, because it turns an
// unanswered question into a confidently wrong answer.
//
// FAIL-ON-REVERT: compute enforcement from cpType alone and the unbound rule
// reports "Enforced: yes", failing here.
func TestFormatCoSRewriteRulesUnboundDSCPIsNotEnforced(t *testing.T) {
	out := FormatCoSRewriteRules(testCoSRewriteRuleConfigUnbound(), "rw-dscp", "")
	line := ruleHeaderLine(t, out, "rw-dscp")
	if strings.Contains(line, "Enforced: yes") {
		t.Errorf("an UNBOUND dscp rewrite rule reported as enforced; no unit "+
			"references it, so it rewrites nothing. header:\n%s", line)
	}
	if !strings.Contains(line, "not bound") {
		t.Errorf("an unbound dscp rule must say WHY it will not act (no unit "+
			"binds it), not merely that it is unenforced. header:\n%s", line)
	}
	// It must NOT borrow the unsupported-type wording: the type IS supported,
	// the binding is missing. Conflating the two would send the operator to
	// fix the wrong thing.
	if strings.Contains(line, "rewrites dscp only") {
		t.Errorf("unbound dscp rule reported with the unsupported-TYPE reason; "+
			"the type is supported and the binding is what is missing:\n%s", line)
	}
}

// TestFormatCoSRewriteRulesBoundDSCPIsEnforced is the positive control for the
// test above: with a binding present the same rule DOES report enforced. Without
// this, "never says yes" would satisfy the unbound assertion.
func TestFormatCoSRewriteRulesBoundDSCPIsEnforced(t *testing.T) {
	line := ruleHeaderLine(t, FormatCoSRewriteRules(testCoSRewriteRuleConfig(), "rw-dscp", ""), "rw-dscp")
	if !strings.Contains(line, "Enforced: yes") {
		t.Errorf("a BOUND dscp rewrite rule must report as enforced:\n%s", line)
	}
}

// ruleHeaderLine returns the single "Rewrite rule: <name>, ..." line for name.
// Asserting against the whole output would let a marker on ANY rule satisfy a
// per-rule claim.
func ruleHeaderLine(t *testing.T, out, name string) string {
	t.Helper()
	prefix := "Rewrite rule: " + name + ","
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(line, prefix) {
			return line
		}
	}
	t.Fatalf("no header line for rewrite rule %q in output:\n%s", name, out)
	return ""
}

// TestFormatCoSRewriteRulesNameOnlyFamiliesRenderNoTable pins that a family
// with no modeled code points renders an explicit explanation rather than an
// empty column header — an empty table reads as "configured with nothing in
// it", which is a different and wrong claim.
func TestFormatCoSRewriteRulesNameOnlyFamiliesRenderNoTable(t *testing.T) {
	out := FormatCoSRewriteRules(testCoSRewriteRuleConfig(), "rw-prec", "")
	if !strings.Contains(out, "Code points not modeled") {
		t.Errorf("name-only family must explain that no code points are modeled:\n%s", out)
	}
	if strings.Contains(out, "Forwarding class") {
		t.Errorf("name-only family must not render an empty code-point table:\n%s", out)
	}
}

func TestFormatCoSRewriteRulesFilters(t *testing.T) {
	cfg := testCoSRewriteRuleConfig()

	// Every type filter selects its own family and excludes the others.
	for _, tc := range []struct {
		typeFilter string
		want       string
		exclude    []string
	}{
		{"dscp", "rw-dscp", []string{"rw-pcp", "rw-prec", "rw-exp"}},
		{"ieee-802.1", "rw-pcp", []string{"rw-dscp", "rw-prec", "rw-exp"}},
		{"inet-precedence", "rw-prec", []string{"rw-dscp", "rw-pcp", "rw-exp"}},
		{"exp", "rw-exp", []string{"rw-dscp", "rw-pcp", "rw-prec"}},
	} {
		out := FormatCoSRewriteRules(cfg, "", tc.typeFilter)
		if !strings.Contains(out, tc.want) {
			t.Errorf("type=%s did not select %s:\n%s", tc.typeFilter, tc.want, out)
		}
		for _, ex := range tc.exclude {
			if strings.Contains(out, ex) {
				t.Errorf("type=%s leaked %s:\n%s", tc.typeFilter, ex, out)
			}
		}
	}

	// Name filter selects one rule.
	out := FormatCoSRewriteRules(cfg, "rw-pcp", "")
	if !strings.Contains(out, "rw-pcp") || strings.Contains(out, "rw-dscp") {
		t.Errorf("name=rw-pcp filter wrong:\n%s", out)
	}

	// No match reports the filter message rather than the "none configured"
	// message — the two states are different and must not be conflated.
	out = FormatCoSRewriteRules(cfg, "nope", "")
	if !strings.Contains(out, "No class-of-service rewrite-rule matches") {
		t.Errorf("expected no-match message, got:\n%s", out)
	}
}

func TestFormatCoSRewriteRulesEmptyConfig(t *testing.T) {
	if out := FormatCoSRewriteRules(nil, "", ""); !strings.Contains(out, "No class-of-service rewrite-rules configured") {
		t.Errorf("nil config: %q", out)
	}
	cfg := testCoSConfig() // has ClassOfService but no rewrite rules
	if out := FormatCoSRewriteRules(cfg, "", ""); !strings.Contains(out, "No class-of-service rewrite-rules configured") {
		t.Errorf("no rules configured: %q", out)
	}
}
