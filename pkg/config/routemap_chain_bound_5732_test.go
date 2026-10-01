package config

import (
	"fmt"
	"strings"
	"testing"
)

// TestComposedChainSequenceCount_5732 pins the composed-chain accounting:
// the SUM of per-member RouteMapSequenceCount, truncated at the first member
// with an explicit terminating policy default.
func TestComposedChainSequenceCount_5732(t *testing.T) {
	pss := map[string]*PolicyStatement{
		// 3 sequences, non-terminating (no policy default).
		"A": {Name: "A", Terms: []*PolicyTerm{{Name: "t", PrefixList: []string{"a", "b", "c"}}}},
		// 2 sequences, non-terminating.
		"B": {Name: "B", Terms: []*PolicyTerm{{Name: "t", PrefixList: []string{"x", "y"}}}},
		// 5 sequences but TERMINATES the chain (policy `then accept`).
		"TERM": {Name: "TERM", DefaultAction: "accept",
			Terms: []*PolicyTerm{{Name: "t", PrefixList: []string{"p", "q", "r", "s", "u"}}}},
	}
	cases := []struct {
		name  string
		chain []string
		want  uint64
	}{
		{"A+B", []string{"A", "B"}, 5},
		{"single-A", []string{"A"}, 3},
		{"undefined-skipped", []string{"A", "nope", "B"}, 5},
		// TERM terminates the chain: members AFTER it (B) are not rendered.
		{"terminating-truncates", []string{"A", "TERM", "B"}, 3 + 5},
		{"empty", nil, 0},
	}
	for _, c := range cases {
		if got := ComposedChainSequenceCount(nil, pss, c.chain); got != c.want {
			t.Errorf("%s: ComposedChainSequenceCount = %d, want %d", c.name, got, c.want)
		}
	}
}

// TestComposedChainSequenceBound_CompileReject_5732 is the fail-on-revert wiring
// test — the concrete #5732 repro. Two BGP export policies A and B each expand
// to ~3600 route-map sequences (60 from-prefix-list x 60 from-as-path), so each
// individually PASSES the per-policy #5701 gate (3600 <= 6552). A neighbor
// `export [ A B ]` composes them into ONE route-map summing 7200 sequences,
// which exceeds the 6552 ceiling → highest FRR seq 10*7201 = 72010 > 65535 →
// the reload would be poisoned. The composed gate must REJECT it at commit.
//
// FAIL-ON-REVERT: removing validateBGPComposedChainSequenceBoundStrict (or the
// chain-sum count) makes CompileConfig accept the chain (each member passes the
// per-policy gate), so the reject assertion fires RED.
func TestComposedChainSequenceBound_CompileReject_5732(t *testing.T) {
	const per = 60 // 60 x 60 = 3600 sequences per policy (<= 6552, passes #5701)
	var sets []string
	for _, pol := range []string{"A", "B"} {
		for i := 0; i < per; i++ {
			sets = append(sets, fmt.Sprintf("set policy-options policy-statement %s term t1 from prefix-list %s_pl%d", pol, pol, i))
		}
		for i := 0; i < per; i++ {
			// #7471: define each as-path. `from as-path` is definedness-gated
			// now and that gate runs first, so a dangling ref would reject
			// before the CHAIN BOUND under test could fire.
			sets = append(sets, fmt.Sprintf(`set policy-options as-path %s_asp%d "^%d "`, pol, i, 65000+i))
			sets = append(sets, fmt.Sprintf("set policy-options policy-statement %s term t1 from as-path %s_asp%d", pol, pol, i))
		}
	}
	// Compose A and B on a neighbor export chain.
	sets = append(sets,
		"set protocols bgp group g1 neighbor 10.0.0.1 peer-as 65001",
		"set protocols bgp group g1 neighbor 10.0.0.1 export [ A B ]",
	)

	// Each member individually passes the per-policy #5701 gate.
	lenient, err := CompileConfigLenient(treeFromSets(t, sets))
	if err != nil {
		t.Fatalf("lenient compile must not hard-fail: %v", err)
	}
	if got := RouteMapSequenceCount(&lenient.PolicyOptions, lenient.PolicyOptions.PolicyStatements["A"]); got > MaxRouteMapSequences {
		t.Fatalf("test setup: member A (%d) must be UNDER the per-policy ceiling %d", got, MaxRouteMapSequences)
	}
	// The composed chain exceeds the ceiling.
	if got := ComposedChainSequenceCount(&lenient.PolicyOptions, lenient.PolicyOptions.PolicyStatements, []string{"A", "B"}); got <= MaxRouteMapSequences {
		t.Fatalf("test setup: composed A+B (%d) must EXCEED the ceiling %d", got, MaxRouteMapSequences)
	}

	// Strict commit path REJECTS the composed chain.
	if _, err := CompileConfig(treeFromSets(t, sets)); err == nil {
		t.Fatal("CompileConfig must reject a composed BGP chain that overflows the FRR route-map sequence ceiling")
	} else if !strings.Contains(err.Error(), "composed policy chain") || !strings.Contains(err.Error(), "A B") {
		t.Fatalf("reject error must name the composed chain, got %q", err.Error())
	}

	// Tolerant load DOWNGRADES to a warning (no hard fail, #1960 no-brick).
	found := false
	for _, w := range lenient.Warnings {
		if strings.Contains(w, "composed route-map chain") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("tolerant load must record a composed-chain downgrade warning, got %v", lenient.Warnings)
	}
}

// TestComposedChainSequenceBound_ShortChainPasses_5732 proves a normal short
// chain (both members tiny) compiles clean — no false rejection.
func TestComposedChainSequenceBound_ShortChainPasses_5732(t *testing.T) {
	cfg, err := compileSet(t, []string{
		"set routing-options autonomous-system 65000",
		"set protocols bgp group g1 neighbor 10.0.0.1 peer-as 65001",
		"set protocols bgp group g1 neighbor 10.0.0.1 export [ A B ]",
		"set policy-options policy-statement A term t from protocol bgp",
		"set policy-options policy-statement B term t then accept",
	})
	if err != nil {
		t.Fatalf("a normal short composed chain must compile, got %v", err)
	}
	// Sanity: the chain resolved to A,B on the neighbor.
	n := bgpNeighbor(t, cfg, "10.0.0.1")
	if got, want := n.Export, []string{"A", "B"}; !equalStrs5732(got, want) {
		t.Fatalf("neighbor.Export = %v, want %v", got, want)
	}
}

// treeFromSets builds a ConfigTree from flat `set` commands via
// ParseSetCommand + SetPath (never NewParser, per CLAUDE.md).
func treeFromSets(t *testing.T, sets []string) *ConfigTree {
	t.Helper()
	tree := &ConfigTree{}
	for _, s := range sets {
		path, err := ParseSetCommand(s)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", s, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", s, err)
		}
	}
	return tree
}

func equalStrs5732(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
