package nftables

import (
	"strings"
	"testing"
)

// netlink_lo0_proto_icmp_6806_test.go is the no-kernel parent-RED for #6806:
// the lo0 kernel mirror must never install a rule whose `from protocol` or
// `from icmp-type` / `icmp-code` narrowing was silently dropped because a token
// would not resolve.
//
// The two dimensions reach the builder by DIFFERENT channels, and the tests are
// built to fail for the right reason on each:
//
//   - protocol arrives as a RAW string, so the builder detects the bad token
//     itself (lo0Protocols), exactly like filterFamilyAddrs for addresses;
//   - icmp-type/code arrive already RESOLVED to bytes, so an unresolvable token
//     leaves no trace and only the ICMPTypeUnrepresentable /
//     ICMPCodeUnrepresentable markers can carry it.
//
// Revert lo0Protocols to the pre-fix per-token drop, or drop either marker
// check, and the matching sub-case below goes RED: p.err becomes nil and the
// build emits a rule the operator did not write.

// buildLo0Term6806 builds a single-term v4 lo0 plan and returns it.
func buildLo0Term6806(t *testing.T, term Lo0FilterTerm) *nlPlan {
	t.Helper()
	p := newBuildPlan(t, "xpf_lo0", lo0FilterPriority)
	buildLo0FilterNetlink(p, Lo0FilterSpec{NoIPv6RejectZeroHopLimit: true, V4Terms: []Lo0FilterTerm{term}})
	return p
}

// TestLo0UnresolvableProtocolFailsClosed6806 covers both directions a
// per-token drop resolves wrongly. The ALL-unresolvable shape is the fail-open
// the issue names; the PARTIAL shape is its mirror image and is the reason
// "skip the bad token" can never be the fix.
func TestLo0UnresolvableProtocolFailsClosed6806(t *testing.T) {
	cases := []struct {
		name string
		why  string
		term Lo0FilterTerm
	}{
		{
			name: "all_unresolvable_widens_an_accept_to_every_protocol",
			why: "the resolved slice empties, the `len(protos) > 0` guard emits NO " +
				"l4proto predicate, and a term written to admit ONE protocol admits " +
				"every protocol in its scope (fail-OPEN on the primary host-inbound path)",
			term: Lo0FilterTerm{
				Name: "widened-accept", Action: "accept",
				Protocols: []string{"not-a-protocol"},
			},
		},
		{
			name: "partial_narrows_a_discard",
			why: "the surviving subset installs a discard for tcp only; traffic on the " +
				"protocol that would not resolve is no longer denied and falls through " +
				"to the implicit accept",
			term: Lo0FilterTerm{
				Name: "narrowed-discard", Action: "discard",
				Protocols: []string{"tcp", "not-a-protocol"},
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := buildLo0Term6806(t, tc.term)
			if p.err == nil {
				t.Fatalf("build MUST fail closed on an unresolvable protocol token: %s\nrules:\n%s",
					tc.why, canonRules(p))
			}
			if !strings.Contains(p.err.Error(), "unresolvable protocol") {
				t.Errorf("the diagnostic must name the unresolvable protocol, got %v", p.err)
			}
			if !strings.Contains(p.err.Error(), tc.term.Name) {
				t.Errorf("the diagnostic must name the term %q, got %v", tc.term.Name, p.err)
			}
		})
	}
}

// TestLo0UnrepresentableICMPFailsClosed6806 pins the marker channel. The term
// carries NO resolved bytes — which is exactly the all-unresolvable shape — so
// without the marker the builder sees an unconstrained term and emits a rule
// matching every ICMP type/code in its scope.
func TestLo0UnrepresentableICMPFailsClosed6806(t *testing.T) {
	cases := []struct {
		name string
		term Lo0FilterTerm
	}{
		{
			name: "type_marker_alone",
			term: Lo0FilterTerm{
				Name: "icmp-type-unrep", Action: "accept",
				ICMPTypeUnrepresentable: true,
			},
		},
		{
			name: "code_marker_alone",
			term: Lo0FilterTerm{
				Name: "icmp-code-unrep", Action: "accept",
				ICMPCodeUnrepresentable: true,
			},
		},
		{
			// The mixed shape: some types resolved, some not. Emitting only the
			// resolved bytes would install a NARROWED predicate, which flips the
			// direction for a discard term.
			name: "partially_resolved_types",
			term: Lo0FilterTerm{
				Name: "icmp-partial", Action: "discard",
				ICMPTypes:               []int{8},
				ICMPTypeUnrepresentable: true,
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := buildLo0Term6806(t, tc.term)
			if p.err == nil {
				t.Fatalf("build MUST fail closed on an unrepresentable icmp-type/code; "+
					"rules:\n%s", canonRules(p))
			}
			if !strings.Contains(p.err.Error(), "icmp") {
				t.Errorf("the diagnostic must name the icmp dimension, got %v", p.err)
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

// TestLo0ResolvableProtocolAndICMPStillLower6806 is the anti-over-fix half. A
// gate that fired on well-formed input would reject valid configs — and every
// one of these shapes is reachable from an ordinary commit, unlike the
// fail-closed shapes above.
func TestLo0ResolvableProtocolAndICMPStillLower6806(t *testing.T) {
	t.Run("named_and_numeric_protocols_lower", func(t *testing.T) {
		p := buildLo0Term6806(t, Lo0FilterTerm{
			Name: "ok-protos", Action: "accept",
			Protocols: []string{"tcp", "udp", "17"},
		})
		if p.err != nil {
			t.Fatalf("a resolvable protocol list must lower, got %v", p.err)
		}
		if len(p.rules) != 1 {
			t.Fatalf("want exactly 1 rule, got %d:\n%s", len(p.rules), canonRules(p))
		}
	})

	t.Run("resolved_icmp_without_markers_lowers", func(t *testing.T) {
		p := buildLo0Term6806(t, Lo0FilterTerm{
			Name: "ok-icmp", Action: "accept",
			ICMPTypes: []int{8}, ICMPCodes: []int{0},
		})
		if p.err != nil {
			t.Fatalf("a fully resolved icmp term must lower, got %v", p.err)
		}
		if len(p.rules) != 1 {
			t.Fatalf("want exactly 1 rule, got %d:\n%s", len(p.rules), canonRules(p))
		}
	})

	t.Run("no_protocol_and_no_icmp_is_unconstrained_not_failed", func(t *testing.T) {
		// A term that simply does not constrain protocol or ICMP must keep
		// lowering. The gate keys on an unresolvable TOKEN, never on absence.
		p := buildLo0Term6806(t, Lo0FilterTerm{Name: "bare", Action: "accept"})
		if p.err != nil {
			t.Fatalf("an unconstrained term must lower, got %v", p.err)
		}
		if len(p.rules) != 1 {
			t.Fatalf("want exactly 1 rule, got %d:\n%s", len(p.rules), canonRules(p))
		}
	})
}
