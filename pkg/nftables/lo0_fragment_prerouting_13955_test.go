package nftables

import (
	"strings"
	"testing"
)

// #13955: IPv4 lo0 `is-fragment` cannot be enforced at input: kernel
// IPv4 defragmentation runs at NF_INET_PRE_ROUTING priority -400, before
// any input-hook chain. A fragment match at input therefore never sees
// the original fragment header. Until a semantics-preserving pre-defrag
// renderer exists, the kernel mirror must refuse this candidate rather
// than install a silently ineffective filter. IPv6 remains representable.
func TestLo0V4FragmentFailsClosedBeforeDefrag13955(t *testing.T) {
	p := newBuildPlan(t, "xpf_lo0", lo0FilterPriority)
	buildLo0FilterNetlink(p, Lo0FilterSpec{V4Terms: []Lo0FilterTerm{
		{Name: "drop-frags", IsFragment: true, Action: "discard"},
	}})
	if p.err == nil || !strings.Contains(p.err.Error(), "IPv4 is-fragment") {
		t.Fatalf("IPv4 lo0 fragment filter must fail closed before installation, got err=%v rules:\n%s", p.err, canonRules(p))
	}
	if len(p.rules) != 0 {
		t.Fatalf("refused fragment filter emitted partial rules:\n%s", canonRules(p))
	}
}

// Sibling parity: IPv6 is-fragment is not affected by IPv4 defrag and
// continues to be evaluated at the established lo0 input hook.
func TestLo0V6FragmentStaysOnInput13955(t *testing.T) {
	p := newBuildPlan(t, "xpf_lo0", lo0FilterPriority)
	buildLo0FilterNetlink(p, Lo0FilterSpec{V6Terms: []Lo0FilterTerm{
		{Name: "drop-frags6", IsFragment: true, Action: "discard"},
	}})
	if p.err != nil {
		t.Fatalf("IPv6 fragment filter should remain representable: %v", p.err)
	}
	found := false
	for i, exprs := range p.rules {
		if strings.Contains(canonRule(p, exprs), "exthdr(type=44") {
			found = true
			if p.ruleChains[i] != "input" {
				t.Errorf("v6 fragment rule on %q, want input", p.ruleChains[i])
			}
		}
	}
	if !found {
		t.Fatalf("no v6 fragment rule; rules:\n%s", canonRules(p))
	}
}

func TestLo0NoFragmentRemainsUnchanged13955(t *testing.T) {
	p := newBuildPlan(t, "xpf_lo0", lo0FilterPriority)
	buildLo0FilterNetlink(p, Lo0FilterSpec{V4Terms: []Lo0FilterTerm{
		{Name: "ssh", Protocols: []string{"tcp"}, DestinationPorts: []string{"22"}, Action: "accept"},
	}})
	if p.err != nil {
		t.Fatalf("ordinary lo0 filter: %v", p.err)
	}
	if len(p.rules) != 1 {
		t.Fatalf("ordinary term emitted %d rules, want the existing single rule: %s", len(p.rules), canonRules(p))
	}
	if len(p.ruleChains) != len(p.rules) {
		t.Fatalf("rule-chain mapping mismatch: rules=%d chains=%d", len(p.rules), len(p.ruleChains))
	}
	for i, chain := range p.ruleChains {
		if chain != "input" {
			t.Errorf("ordinary rule %d on %q, want input", i, chain)
		}
	}
}
