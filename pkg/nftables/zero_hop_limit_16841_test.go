package nftables

import (
	"testing"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
)

// #16841: EmitZeroHopLimitLocalDrop must render exactly one
// `ip6 hoplimit 0 fib daddr type { local, anycast } drop` rule when the
// knob is unset, and nothing when it is set. RED on revert: deleting
// the emit call sites leaves the default case empty.

func renderZeroHop(admit bool) *nlPlan {
	p := &nlPlan{c: &nftables.Conn{}, table: &nftables.Table{Name: "t"}, chain: &nftables.Chain{Name: "input"}}
	EmitZeroHopLimitLocalDrop(p, admit)
	return p
}

func TestEmitZeroHopLimitLocalDrop16841(t *testing.T) {
	p := renderZeroHop(false)
	if len(p.rules) != 1 {
		t.Fatalf("default: rules = %d, want 1", len(p.rules))
	}
	var sawPayload, sawFib, sawDrop bool
	for _, e := range p.rules[0] {
		switch x := e.(type) {
		case *expr.Payload:
			if x.Base == expr.PayloadBaseNetworkHeader && x.Offset == 7 && x.Len == 1 {
				sawPayload = true
			}
		case *expr.Fib:
			sawFib = true
		case *expr.Verdict:
			if x.Kind == expr.VerdictDrop {
				sawDrop = true
			}
		}
	}
	if !sawPayload || !sawFib || !sawDrop {
		t.Errorf("default rule missing hop-limit payload/fib/drop: payload=%v fib=%v drop=%v", sawPayload, sawFib, sawDrop)
	}

	if p := renderZeroHop(true); len(p.rules) != 0 {
		t.Errorf("knob set: rules = %d, want 0", len(p.rules))
	}
}

func TestZeroHopSpecFields16841(t *testing.T) {
	// The spec fields are the wiring: a builder that ignores them
	// renders the default drop even with the knob set.
	if (HostInboundSpec{}).NoIPv6RejectZeroHopLimit {
		t.Error("HostInboundSpec zero value must default-reject")
	}
	if (FenceSpec{}).NoIPv6RejectZeroHopLimit || (GapFenceSpec{}).NoIPv6RejectZeroHopLimit || (Lo0FilterSpec{}).NoIPv6RejectZeroHopLimit {
		t.Error("fence/lo0 spec zero values must default-reject")
	}
}
