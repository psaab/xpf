package nftables

import (
	"strings"
	"testing"
)

// #10253: the netlink lo0 mirror must resolve a contradictory real action plus
// `then next term` in favour of the action, matching Rust
// `continue_term = action.is_empty() && routing_instance.is_empty()`
// (userspace-dp/src/filter/compiler.rs, #5142). Before the fix the
// `(t.NextTerm || t.Action == "") && t.RoutingInstance == ""` branch at
// netlink_lo0.go:262 returned before the terminating verdict, so the kernel
// mirror fell through while Rust terminated.
//
// FAIL-ON-REVERT: restoring the NextTerm-inclusive branch makes the action and
// reject cells below emit no verdict rules; actionless and routing-instance
// controls remain unchanged.
func netlinkActionNextTermRules10253(t *testing.T, term Lo0FilterTerm) string {
	t.Helper()
	p := newBuildPlan(t, "xpf_10253", lo0FilterPriority)
	buildLo0TermNetlink(p, term, famV4)
	if p.err != nil {
		t.Fatalf("build term %q: %v", term.Name, p.err)
	}
	return canonRules(p)
}

func TestNetlinkActionNextTermTerminatesMirroringRust10253(t *testing.T) {
	for _, tc := range []struct {
		name       string
		action     string
		wantVerdict string
	}{
		{"accept", "accept", "verdict(1)"},
		{"discard", "discard", "verdict(0)"},
		// Mixed-version/tolerant snapshots can carry an unknown non-empty
		// action; the Rust compiler fails it closed to discard, so the
		// netlink mirror must not let NextTerm suppress the drop.
		{"unknown-fails-closed", "frobnicate", "verdict(0)"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := netlinkActionNextTermRules10253(t, Lo0FilterTerm{
				Name: tc.name, Action: tc.action, NextTerm: true,
			})
			if !strings.Contains(got, tc.wantVerdict) {
				t.Errorf("action %q + next-term: got rules without terminating %s:\n%s",
					tc.action, tc.wantVerdict, got)
			}
		})
	}

	got := netlinkActionNextTermRules10253(t, Lo0FilterTerm{
		Name: "reject", Action: "reject", NextTerm: true,
	})
	if !strings.Contains(got, "reject(type=1,code=0)") ||
		!strings.Contains(got, "reject(type=2,code=3)") {
		t.Errorf("reject + next-term must retain both terminating reply rules:\n%s", got)
	}
}

func TestNetlinkActionlessAndRoutingInstanceControls10253(t *testing.T) {
	// Empty action plus NextTerm is the actual fall-through shape: it emits no
	// rule when it has no honored modifier.
	if got := netlinkActionNextTermRules10253(t, Lo0FilterTerm{
		Name: "next", NextTerm: true,
	}); got != "" {
		t.Errorf("actionless next-term emitted a rule, want fall-through:\n%s", got)
	}

	// A routing-instance term is terminal even with NextTerm set, and the
	// empty-action placeholder maps to accept in both mirrors (#9140).
	got := netlinkActionNextTermRules10253(t, Lo0FilterTerm{
		Name: "steer", RoutingInstance: "mgmt-vrf", NextTerm: true,
	})
	if !strings.Contains(got, "verdict(1)") {
		t.Errorf("routing-instance + next-term lost its terminating accept:\n%s", got)
	}
}
