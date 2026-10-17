package nftables

import (
	"testing"

	"github.com/google/nftables/expr"
)

// Regression for #14394 (DR8-H3): a lo0 flexible-match-range with
// `match-start layer-4` must load from the TRANSPORT header (@th /
// PayloadBaseTransportHeader), not the network header. The compiler has
// accepted layer-4 since #3232 and the userspace matcher honours it, but
// the kernel lo0 mirror dropped MatchStart at the DTO boundary and
// rendered every flex-match at the L3 base — so a `then discard` term
// essentially never matched (fail-open on host-bound traffic) and a
// `then accept` term wrongly fell through.
//
// A term with an unrepresentable match-start must render NO rule
// (matches nothing), never a widened rule at the wrong base.

func flexPayloadBase(t *testing.T, fm Lo0FlexMatch) (expr.PayloadBase, bool) {
	t.Helper()
	for _, e := range flexMatchExprs(fm) {
		if p, ok := e.(*expr.Payload); ok {
			return p.Base, true
		}
	}
	return 0, false
}

func TestFlexMatchLayer4UsesTransportBase14394(t *testing.T) {
	base, ok := flexPayloadBase(t, Lo0FlexMatch{MatchStart: "layer-4", ByteOffset: 0, BitLength: 8, Value: 0x11, Mask: 0xff})
	if !ok {
		t.Fatal("layer-4 flex-match rendered no payload load, want a transport-header load")
	}
	if base != expr.PayloadBaseTransportHeader {
		t.Fatalf("layer-4 flex-match payload base = %v, want PayloadBaseTransportHeader (@th) — rendering at the L3 base is the #14394 fail-open", base)
	}
}

func TestFlexMatchLayer3AndEmptyUseNetworkBase14394(t *testing.T) {
	for _, start := range []string{"", "layer-3"} {
		base, ok := flexPayloadBase(t, Lo0FlexMatch{MatchStart: start, ByteOffset: 6, BitLength: 8, Value: 0x11, Mask: 0xff})
		if !ok {
			t.Fatalf("match-start %q rendered no payload load", start)
		}
		if base != expr.PayloadBaseNetworkHeader {
			t.Fatalf("match-start %q payload base = %v, want PayloadBaseNetworkHeader (@nh) — layer-3 must stay byte-identical", start, base)
		}
		if !flexMatchRepresentable(Lo0FlexMatch{MatchStart: start, ByteOffset: 6, BitLength: 8, Value: 0x11, Mask: 0xff}) {
			t.Fatalf("match-start %q must be representable", start)
		}
	}
}

func TestFlexMatchUnrepresentableStartMatchesNothing14394(t *testing.T) {
	for _, start := range []string{"payload", "bogus", "layer-5", "Layer-4"} {
		fm := Lo0FlexMatch{MatchStart: start, ByteOffset: 0, BitLength: 8, Value: 0x11, Mask: 0xff}
		if flexMatchRepresentable(fm) {
			t.Errorf("match-start %q must be unrepresentable", start)
		}
		if exprs := flexMatchExprs(fm); len(exprs) != 0 {
			t.Errorf("match-start %q rendered %d exprs, want none (no accept/widening rule at the wrong base)", start, len(exprs))
		}
		// The lo0 plan must emit no rule for the term at all.
		p := newBuildPlan(t, "xpf_lo0", lo0FilterPriority)
		buildLo0FilterNetlink(p, Lo0FilterSpec{V4Terms: []Lo0FilterTerm{
			{Name: "bad-start", Protocols: []string{"tcp"}, FlexMatch: &fm, Action: "accept"},
			{Name: "deny-rest", Action: "discard"},
		}})
		if p.err != nil {
			t.Fatalf("match-start %q: build must match-nothing per term, not fail the plan: %v", start, p.err)
		}
		// Only deny-rest's rule may survive.
		if len(p.rules) != 1 {
			t.Fatalf("match-start %q: want exactly 1 rule (deny-rest), got %d:\n%s", start, len(p.rules), canonRules(p))
		}
	}
}
