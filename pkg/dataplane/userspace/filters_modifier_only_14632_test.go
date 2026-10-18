package userspace

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #14632 (Y26-02): a modifier-only term (`then count bgp;` with NO authored
// `next term`) carries Junos nonterminating actions, which "carry with them an
// implicit accept action" — the term applies its modifiers and TERMINATES as
// Accept. Only an authored `then next term` falls through. Before the fix the
// snapshot builder synthesized NextTerm for every empty-action term, the Rust
// compiler fell through on the empty action alone, and the renderer/nft mirrors
// claimed the same fall-through — so `then count bgp;` ahead of a final discard
// blackholed the counted traffic (e.g. BGP on lo0).
//
// FAIL-ON-REVERT: restoring `term.NextTerm || (term.Action == "" && ...)` in
// buildFilterTermSnapshots (or the `Action == ""` renderer predicate) makes
// the modifier-only cells below go RED.

func TestFilterSnapshotModifierOnlyDoesNotFallThrough14632(t *testing.T) {
	// Authored `then count bgp;` — no `next term`, no terminating action.
	cfg := nextTermCfg([]*config.FirewallFilterTerm{
		{Name: "count-bgp", Protocols: []string{"tcp"}, DestinationPorts: []string{"179"}, Count: "bgp"},
		{Name: "drop-rest", Protocols: []string{"tcp"}, Action: "discard"},
	})
	snaps := buildFirewallFilterSnapshots(cfg)
	if len(snaps) != 1 || len(snaps[0].Terms) != 2 {
		t.Fatalf("expected 1 filter with 2 terms, got %#v", snaps)
	}
	if snaps[0].Terms[0].NextTerm {
		t.Error("modifier-only term without authored `next term` must NOT be marked fall-through (#14632 implicit accept)")
	}
	if snaps[0].Terms[1].NextTerm {
		t.Error("terminating discard must NOT be marked fall-through")
	}
}

func TestFilterSnapshotExplicitNextTermStillFallsThrough14632(t *testing.T) {
	// Authored `then { count c; next term; }` — the explicit continuation.
	cfg := nextTermCfg([]*config.FirewallFilterTerm{
		{Name: "count-next", Protocols: []string{"tcp"}, Count: "hits", NextTerm: true},
		{Name: "drop", Protocols: []string{"tcp"}, Action: "discard"},
	})
	snaps := buildFirewallFilterSnapshots(cfg)
	if !snaps[0].Terms[0].NextTerm {
		t.Error("authored `then next term` must still be marked fall-through")
	}
}

func TestFilterSnapshotRoutingInstanceAuthoredBitPreserved14632(t *testing.T) {
	// Tolerant RI + next-term: the authored bit is preserved verbatim for
	// disclosure (#10514) even though the term terminates as accept.
	cfg := nextTermCfg([]*config.FirewallFilterTerm{
		{Name: "steer", Protocols: []string{"tcp"}, RoutingInstance: "mgmt-vrf", NextTerm: true},
	})
	snaps := buildFirewallFilterSnapshots(cfg)
	if !snaps[0].Terms[0].NextTerm {
		t.Error("authored NextTerm on a routing-instance term must be preserved for disclosure")
	}
	// Routing-instance without the authored bit must NOT gain one.
	cfg2 := nextTermCfg([]*config.FirewallFilterTerm{
		{Name: "steer", Protocols: []string{"tcp"}, RoutingInstance: "mgmt-vrf"},
	})
	snaps2 := buildFirewallFilterSnapshots(cfg2)
	if snaps2[0].Terms[0].NextTerm {
		t.Error("routing-instance term without authored `next term` must NOT be marked fall-through")
	}
}

func TestSnapshotRenderModifierOnlyIsImplicitAccept14632(t *testing.T) {
	// The effective renderer must mirror the Rust predicate
	// `continue_term = next_term && action.is_empty() && routing_instance.is_empty()`:
	// a modifier-only term (empty action, no next_term bit) renders its
	// modifiers plus the terminating implicit `then accept`, never the
	// fall-through line.
	snap := FirewallTermSnapshot{Name: "count-bgp", Protocols: []string{"tcp"}, Count: "bgp"}
	out := RenderFirewallFilterSnapshot(&FirewallFilterSnapshot{
		Name: "edge", Family: "inet", Terms: []FirewallTermSnapshot{snap},
	})
	if strings.Contains(out, "then next term (fall-through)") {
		t.Errorf("modifier-only term rendered as fall-through; runtime now terminates as implicit accept (#14632).\n%s", out)
	}
	if !strings.Contains(out, "then count bgp") {
		t.Errorf("modifier-only render lost its count modifier.\n%s", out)
	}
	if !strings.Contains(out, "then accept") {
		t.Errorf("modifier-only render must show the terminating implicit accept.\n%s", out)
	}

	// Control: authored next-term still renders fall-through.
	snapNext := FirewallTermSnapshot{Name: "count-next", Protocols: []string{"tcp"}, Count: "hits", NextTerm: true}
	outNext := RenderFirewallFilterSnapshot(&FirewallFilterSnapshot{
		Name: "edge", Family: "inet", Terms: []FirewallTermSnapshot{snapNext},
	})
	if !strings.Contains(outNext, "then next term (fall-through)") {
		t.Errorf("authored next-term must still render fall-through.\n%s", outNext)
	}
}
