package nftables

import (
	"strings"
	"testing"
)

// netlink_lo0_from_unrepresentable_9875_test.go is the no-kernel parent-RED for
// #9875: the lo0 kernel mirror must never install a rule whose `from` block
// carried a match leaf the dataplane does not enforce (recorded on
// config.FirewallFilterTerm.UnknownFrom, #3307) or a value-bearing leaf
// written with NO operand (config.FirewallFilterTerm.ValuelessFrom, #8480).
//
// The marker reaches the builder by the same channel #6806 opened for
// ICMPTypeUnrepresentable / ICMPCodeUnrepresentable: the surviving predicates
// in this DTO are byte-identical to a term authored without the leaf, so only
// the FromUnrepresentable marker can carry the refusal evidence. Revert the
// marker check and the cases below go RED: p.err becomes nil and the build
// emits a widened rule the operator did not write.

// buildLo0Term9875 builds a single-term v4 lo0 plan and returns it.
func buildLo0Term9875(t *testing.T, term Lo0FilterTerm) *nlPlan {
	t.Helper()
	p := newBuildPlan(t, "xpf_lo0", lo0FilterPriority)
	buildLo0FilterNetlink(p, Lo0FilterSpec{V4Terms: []Lo0FilterTerm{term}})
	return p
}

// TestLo0FromUnrepresentableFailsClosed9875 pins the marker channel. Every
// term carries a SURVIVING predicate alongside the marker, so without the
// check the builder lowers a widened rule instead of erroring.
func TestLo0FromUnrepresentableFailsClosed9875(t *testing.T) {
	cases := []struct {
		name string
		term Lo0FilterTerm
	}{
		{
			name: "marked_accept_with_surviving_protocol",
			term: Lo0FilterTerm{
				Name: "widened-accept", Action: "accept",
				Protocols:           []string{"tcp"},
				FromUnrepresentable: true,
			},
		},
		{
			name: "marked_discard_with_surviving_ports",
			term: Lo0FilterTerm{
				Name: "widened-discard", Action: "discard",
				Protocols:           []string{"tcp"},
				DestinationPorts:    []string{"22"},
				FromUnrepresentable: true,
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := buildLo0Term9875(t, tc.term)
			if p.err == nil {
				t.Fatalf("build MUST fail closed on a from-unrepresentable term; "+
					"rules:\n%s", canonRules(p))
			}
			if !strings.Contains(p.err.Error(), "unrepresentable from") {
				t.Errorf("the diagnostic must name the unrepresentable from leaf, got %v", p.err)
			}
			if !strings.Contains(p.err.Error(), tc.term.Name) {
				t.Errorf("the diagnostic must name the term %q, got %v", tc.term.Name, p.err)
			}
			if len(p.rules) != 0 {
				t.Errorf("a failed-closed term must emit NO rule, got %d:\n%s",
					len(p.rules), canonRules(p))
			}
		})
	}
}

// TestLo0FromUnrepresentableRefusesWholePlan9875 pins the GPT-2 ordering:
// the marker preflight runs ahead of address elimination, so a marked term
// refuses the whole plan even when it is also match-nothing for the
// family — and a marked match-nothing term alongside a healthy term still
// fails the install (the Rust side rejects the same snapshot; installing
// the remainder would split the dataplanes).
func TestLo0FromUnrepresentableRefusesWholePlan9875(t *testing.T) {
	nothing := Lo0FilterTerm{
		Name: "marked-nothing", Action: "accept",
		// Constrained to a v6-only scope: match-nothing for the v4 pass.
		SrcConstrained: true, SrcAddrs: []string{"2001:db8::1/128"},
		FromUnrepresentable: true,
	}
	healthy := Lo0FilterTerm{
		Name: "ok", Action: "accept",
		Protocols: []string{"tcp"}, DestinationPorts: []string{"22"},
	}
	for _, tc := range []struct {
		name  string
		terms []Lo0FilterTerm
	}{
		{"marked match-nothing alone refuses", []Lo0FilterTerm{nothing}},
		{"marked match-nothing poisons a healthy plan", []Lo0FilterTerm{healthy, nothing}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := newBuildPlan(t, "xpf_lo0", lo0FilterPriority)
			buildLo0FilterNetlink(p, Lo0FilterSpec{V4Terms: tc.terms})
			if p.err == nil {
				t.Fatalf("a marked match-nothing term must refuse the whole plan; rules:\n%s",
					canonRules(p))
			}
			if !strings.Contains(p.err.Error(), "unrepresentable from") {
				t.Fatalf("the refusal must come from the marker preflight, got %v", p.err)
			}
		})
	}
}

// TestLo0UnmarkedTermStillLowers9875 is the anti-over-fix half. The gate keys
// on the marker, never on the mere presence of from predicates.
func TestLo0UnmarkedTermStillLowers9875(t *testing.T) {
	p := buildLo0Term9875(t, Lo0FilterTerm{
		Name: "ok", Action: "accept",
		Protocols: []string{"tcp"}, DestinationPorts: []string{"22"},
	})
	if p.err != nil {
		t.Fatalf("an unmarked term must lower, got %v", p.err)
	}
	if len(p.rules) != 1 {
		t.Fatalf("want exactly 1 rule, got %d:\n%s", len(p.rules), canonRules(p))
	}
}
