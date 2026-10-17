package nftables

import (
	"strings"
	"testing"
)

// #14632 (Y26-02): the netlink lo0 mirror must terminate a modifier-only term
// (empty action, no authored `next term`) as an implicit Accept — verdict(1) —
// exactly as the Rust evaluator does after the fix. Only an authored
// `next term` falls through (no verdict). FAIL-ON-REVERT: restoring
// `t.Action == "" && t.RoutingInstance == ""` as the fall-through guard makes
// the modifier-only cell emit no terminating verdict.

func TestNetlinkModifierOnlyTerminatesAsAccept14632(t *testing.T) {
	// Modifier-only with an honored count modifier: terminating accept.
	got := netlinkActionNextTermRules10253(t, Lo0FilterTerm{
		Name: "count-bgp", Protocols: []string{"tcp"}, Count: "bgp",
	})
	if !strings.Contains(got, "verdict(1)") {
		t.Errorf("modifier-only lost its terminating accept (verdict(1)):\n%s", got)
	}

	// Modifier-only with no honored modifier: still a terminating accept.
	gotBare := netlinkActionNextTermRules10253(t, Lo0FilterTerm{
		Name: "bare-modifier", Protocols: []string{"tcp"},
	})
	if !strings.Contains(gotBare, "verdict(1)") {
		t.Errorf("unhonored modifier-only lost its terminating accept (verdict(1)):\n%s", gotBare)
	}

	// Control: authored next-term still falls through (no rule without a
	// honored modifier; a non-terminating rule with one).
	if gotNext := netlinkActionNextTermRules10253(t, Lo0FilterTerm{
		Name: "next", NextTerm: true,
	}); gotNext != "" {
		t.Errorf("actionless authored next-term emitted a rule, want fall-through:\n%s", gotNext)
	}
	gotNextMod := netlinkActionNextTermRules10253(t, Lo0FilterTerm{
		Name: "count-next", Protocols: []string{"tcp"}, Count: "bgp", NextTerm: true,
	})
	if strings.Contains(gotNextMod, "verdict(") {
		t.Errorf("authored next-term emitted a terminating verdict, want fall-through:\n%s", gotNextMod)
	}
}
