package nftables

import "testing"

// netlink_lo0_zero_render_6529_test.go proves the door #6529's rendered-rule-count
// gate exists for: a lo0 spec that HAS terms but lowers to ZERO kernel rules, so
// the installed xpf_lo0 table is an empty `policy accept` shell even though the
// filter is not "empty" by any term-counting measure. A gate keyed on
// len(spec.V4Terms)+len(spec.V6Terms) would record enforcement here.
//
// Revert InstallLo0 to returning only an error (dropping len(p.rules)) and the
// daemon can no longer distinguish this case at all.
func TestLo0SpecWithTermsCanRenderZeroRules6529(t *testing.T) {
	// A positive source scope constrained to no prefix of this family is the
	// Junos match-nothing term (lo0AddrScope's empty-positive arm): the rule is
	// skipped entirely. On the lenient / peer-sync path an unresolved
	// `from source-prefix-list` resolves exactly this way — constrained, empty.
	spec := Lo0FilterSpec{NoIPv6RejectZeroHopLimit: true, V4Terms: []Lo0FilterTerm{
		{Name: "unresolved-scope", Action: "discard", SrcConstrained: true},
	}}
	if len(spec.V4Terms) == 0 {
		t.Fatal("precondition: the spec must carry a term")
	}

	p := newBuildPlan(t, "xpf_lo0", lo0FilterPriority)
	buildLo0FilterNetlink(p, spec)
	if p.err != nil {
		t.Fatalf("a match-nothing term is valid, not a build error: %v", p.err)
	}
	if len(p.rules) != 0 {
		t.Fatalf("a match-nothing term must render NO rules; got %d:\n%s", len(p.rules), canonRules(p))
	}
}

// TestLo0SpecRuleCountIsReported6529 pins that the count InstallLo0 reports is
// the RENDERED one. It exercises the same builder InstallLo0 runs, against a
// spec that does render, so the two cases above and below are distinguishable.
func TestLo0SpecRuleCountIsReported6529(t *testing.T) {
	p := newBuildPlan(t, "xpf_lo0", lo0FilterPriority)
	buildLo0FilterNetlink(p, Lo0FilterSpec{NoIPv6RejectZeroHopLimit: true, V4Terms: []Lo0FilterTerm{
		{Name: "deny-rest", Action: "discard"},
	}})
	if p.err != nil {
		t.Fatalf("build: %v", p.err)
	}
	if len(p.rules) != 1 {
		t.Fatalf("a terminating discard term renders exactly 1 rule; got %d:\n%s",
			len(p.rules), canonRules(p))
	}
}
