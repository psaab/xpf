package nftables

import (
	"strings"
	"testing"
)

// netlink_lo0_addrs_6512_test.go is the no-kernel parent-RED for #6512: the lo0
// kernel mirror must never install a rule built from a NARROWED (or, on an
// except list, WIDENED) subset of the address list the operator authored. A
// malformed token fails the plan CLOSED, the same posture parsePortTokens /
// lo0DSCPs already take for an unrepresentable port / DSCP token (#6405).
//
// Revert filterFamilyAddrs to the pre-fix per-token drop (no error return, bad
// token skipped) and every fail-closed sub-case below goes RED — p.err becomes
// nil and the build emits a rule the operator did not write.

// buildLo0Term6512 builds a single-term v4 lo0 plan and returns it.
func buildLo0Term6512(t *testing.T, term Lo0FilterTerm) *nlPlan {
	t.Helper()
	p := newBuildPlan(t, "xpf_lo0", lo0FilterPriority)
	buildLo0FilterNetlink(p, Lo0FilterSpec{NoIPv6RejectZeroHopLimit: true, V4Terms: []Lo0FilterTerm{term}})
	return p
}

// TestLo0MalformedAddressFailsClosed6512 covers the three shapes a per-token
// drop resolves WRONGLY, in three different directions.
func TestLo0MalformedAddressFailsClosed6512(t *testing.T) {
	failClosed := []struct {
		name string
		why  string
		term Lo0FilterTerm
	}{
		{
			name: "partial_positive_source_narrows_a_discard",
			why: "the surviving subset installs a discard for 10.0.0.0/8 only; a host in " +
				"the dropped range falls through to the implicit accept (fail-OPEN)",
			term: Lo0FilterTerm{
				Name: "narrowed-discard", Action: "discard",
				SrcAddrs: []string{"10.0.0.0/8", "10.0.0.0/99"}, SrcConstrained: true,
			},
		},
		{
			name: "partial_positive_destination_narrows",
			why:  "same shape on the destination direction",
			term: Lo0FilterTerm{
				Name: "narrowed-dst", Action: "discard",
				DstAddrs: []string{"192.0.2.1", "not-an-address"}, DstConstrained: true,
			},
		},
		{
			name: "all_malformed_except_widens_to_match_all",
			why: "the except list empties, lo0AddrScope's empty-except arm drops the " +
				"predicate, and the accept becomes UNCONSTRAINED — this is why " +
				"'skip the bad entry' can never be the fix: empty means match everything",
			term: Lo0FilterTerm{
				Name: "widened-accept", Action: "accept",
				SrcAddrs: []string{"10.0.0.0/99"}, SrcExcept: true, SrcConstrained: true,
			},
		},
		{
			name: "partial_except_widens",
			why:  "one surviving prefix is excepted; the malformed one is no longer excepted",
			term: Lo0FilterTerm{
				Name: "widened-partial", Action: "accept",
				SrcAddrs: []string{"10.0.0.0/8", "10.0.0.0/99"}, SrcExcept: true, SrcConstrained: true,
			},
		},
	}
	for _, tc := range failClosed {
		t.Run(tc.name, func(t *testing.T) {
			p := buildLo0Term6512(t, tc.term)
			if p.err == nil {
				t.Fatalf("build MUST fail closed on a malformed address token: %s\nrules:\n%s",
					tc.why, canonRules(p))
			}
			if !strings.Contains(p.err.Error(), "malformed address") {
				t.Errorf("the diagnostic must name the malformed address, got %v", p.err)
			}
			if !strings.Contains(p.err.Error(), tc.term.Name) {
				t.Errorf("the diagnostic must name the term %q, got %v", tc.term.Name, p.err)
			}
		})
	}
}

// TestLo0WellFormedAddressesStillLower6512 is the anti-over-fix half: the
// fail-closed gate must fire on MALFORMED tokens only. A wrong-family literal is
// legitimately dropped (the inet chain never consults the v6 vector, and the
// userspace matcher agrees), "any"/"" stay no-constraint placeholders, and a
// clean list still lowers to a real predicate. A "fix" that failed closed on any
// of these would reject valid configs.
func TestLo0WellFormedAddressesStillLower6512(t *testing.T) {
	t.Run("clean_list_lowers", func(t *testing.T) {
		p := buildLo0Term6512(t, Lo0FilterTerm{
			Name: "ok", Action: "discard",
			SrcAddrs: []string{"10.0.0.0/8", "192.168.1.1"}, SrcConstrained: true,
		})
		if p.err != nil {
			t.Fatalf("a well-formed address list must lower, got %v", p.err)
		}
		if len(p.rules) != 1 {
			t.Fatalf("want exactly 1 rule, got %d:\n%s", len(p.rules), canonRules(p))
		}
	})

	t.Run("wrong_family_literal_is_dropped_not_failed", func(t *testing.T) {
		// A v6 literal in the v4 chain: the family filter drops it, leaving an
		// empty POSITIVE set -> match nothing -> the rule is skipped. That is the
		// #3433 H02 contract and must NOT become a build error.
		p := buildLo0Term6512(t, Lo0FilterTerm{
			Name: "v6-in-v4", Action: "accept",
			SrcAddrs: []string{"2001:db8::1"}, SrcConstrained: true,
		})
		if p.err != nil {
			t.Fatalf("a wrong-family literal must be dropped, not fail the build: %v", p.err)
		}
		if len(p.rules) != 0 {
			t.Fatalf("an empty positive set matches nothing; want 0 rules, got %d:\n%s",
				len(p.rules), canonRules(p))
		}
	})

	t.Run("any_and_empty_are_placeholders", func(t *testing.T) {
		p := buildLo0Term6512(t, Lo0FilterTerm{
			Name: "any-src", Action: "accept",
			SrcAddrs: []string{"any", "", "10.0.0.0/8"}, SrcConstrained: true,
		})
		if p.err != nil {
			t.Fatalf("`any` / empty are no-constraint placeholders, not malformed: %v", p.err)
		}
		if len(p.rules) != 1 {
			t.Fatalf("want exactly 1 rule, got %d:\n%s", len(p.rules), canonRules(p))
		}
	})
}
