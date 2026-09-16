package frr

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #9947 item (2): settles the #8369 "UNREACHABLE" rationale from source.
//
// TestEmptySurvivorMakesASynthesizedDenyUNREACHABLE8369 renders [EMPTY] and
// [EMPTY,GHOST] — neither containing a synthesized deny — and infers that a
// trailing deny would sit behind the survivor's match-all permit-10. But the
// synthesis shape under discussion is a chain MEMBER with a terminating
// default (SYNTH-DENY, DefaultAction reject): EMPTY contributes zero term
// sequences and no default, so the member's deny lands at sequence 10 as
// the FIRST and ONLY sequence. This cell renders that shape and asserts
// reachability directly, either way it falls.
func TestEmptySurvivorSynthesizedDenyIsReachable9947(t *testing.T) {
	po := &config.PolicyOptionsConfig{
		PolicyStatements: map[string]*config.PolicyStatement{
			"EMPTY":      {Name: "EMPTY"},
			"SYNTH-DENY": {Name: "SYNTH-DENY", DefaultAction: "reject"},
		},
	}
	m := New()

	// Control: [EMPTY] alone is the lone match-all permit the 8369 test
	// pins (permit-all today).
	alone := m.renderComposedRouteMap(po, "E-xpf-chain", []string{"EMPTY"})
	if strings.Count(alone, "route-map E-xpf-chain ") != 1 || !strings.Contains(alone, "route-map E-xpf-chain permit 10") {
		t.Fatalf("CONTROL FAILED: [EMPTY] must render lone permit-10, got:\n%s", alone)
	}

	// Measurement: synthesize the deny as a chain member.
	got := m.renderComposedRouteMap(po, "ES-xpf-chain", []string{"EMPTY", "SYNTH-DENY"})
	if n := strings.Count(got, "route-map ES-xpf-chain "); n != 1 {
		t.Fatalf("synthesized [EMPTY,SYNTH-DENY] rendered %d sequences, want exactly 1:\n%s", n, got)
	}
	if !strings.Contains(got, "route-map ES-xpf-chain deny 10") {
		t.Fatalf("synthesized deny is not the reachable first sequence, got:\n%s", got)
	}
	if strings.Contains(got, "permit") {
		t.Fatalf("synthesized render still permits; the deny-all direction is what this cell settles:\n%s", got)
	}
	// Settled: the deny IS reachable by every route (first and only
	// sequence) — the empty-survivor shape flips permit-all to deny-all,
	// the maximum behavior change, not an inert trailing deny. Excluding
	// it from a deny-safe denominator would hide an outage case, not
	// correct an over-count.
}
