// External test package so it can import the shared grammarvectors tables
// (which themselves import clusterfailover) without an import cycle.
package clusterfailover_test

import (
	"testing"

	"github.com/psaab/xpf/pkg/clusterfailover"
	"github.com/psaab/xpf/pkg/clusterfailover/grammarvectors"
)

// TestParseCommandAccepts pins that every well-formed command form parses to
// the expected typed op AND round-trips to the expected wire action string
// (Op.Action is the inverse of the wire parser).
func TestParseCommandAccepts(t *testing.T) {
	for _, tc := range grammarvectors.CommandAccepts {
		t.Run(tc.Name, func(t *testing.T) {
			op, err := clusterfailover.ParseCommand(tc.Args)
			if err != nil {
				t.Fatalf("ParseCommand(%v) unexpected error: %v", tc.Args, err)
			}
			if op != tc.Op {
				t.Fatalf("ParseCommand(%v) = %+v, want %+v", tc.Args, op, tc.Op)
			}
			if got := op.Action(); got != tc.Action {
				t.Fatalf("Op.Action() = %q, want %q", got, tc.Action)
			}
			// The formatted action must itself parse back to the same op.
			round, err := clusterfailover.ParseAction(tc.Action)
			if err != nil {
				t.Fatalf("ParseAction(%q) unexpected error: %v", tc.Action, err)
			}
			if round != tc.Op {
				t.Fatalf("ParseAction(%q) = %+v, want %+v", tc.Action, round, tc.Op)
			}
		})
	}
}

// TestParseCommandRejects pins that every malformed command form is rejected
// with an error and yields the zero Op — proving the grammar is closed before
// any caller can reach a cluster side effect.
func TestParseCommandRejects(t *testing.T) {
	for _, tc := range grammarvectors.CommandRejects {
		t.Run(tc.Name, func(t *testing.T) {
			op, err := clusterfailover.ParseCommand(tc.Args)
			if err == nil {
				t.Fatalf("ParseCommand(%v) = %+v, want rejection", tc.Args, op)
			}
			if op != (clusterfailover.Op{}) {
				t.Fatalf("ParseCommand(%v) returned non-zero op %+v on error", tc.Args, op)
			}
		})
	}
}

// TestParseActionAccepts pins the well-formed wire action forms.
func TestParseActionAccepts(t *testing.T) {
	for _, tc := range grammarvectors.ActionAccepts {
		t.Run(tc.Name, func(t *testing.T) {
			op, err := clusterfailover.ParseAction(tc.Action)
			if err != nil {
				t.Fatalf("ParseAction(%q) unexpected error: %v", tc.Action, err)
			}
			if op != tc.Op {
				t.Fatalf("ParseAction(%q) = %+v, want %+v", tc.Action, op, tc.Op)
			}
			if got := op.Action(); got != tc.Action {
				t.Fatalf("Op.Action() = %q, want %q (not a round-trip)", got, tc.Action)
			}
		})
	}
}

// TestParseActionRejects pins that every malformed wire action fails-closed.
func TestParseActionRejects(t *testing.T) {
	for _, action := range grammarvectors.ActionRejects {
		t.Run(action, func(t *testing.T) {
			op, err := clusterfailover.ParseAction(action)
			if err == nil {
				t.Fatalf("ParseAction(%q) = %+v, want rejection", action, op)
			}
			if op != (clusterfailover.Op{}) {
				t.Fatalf("ParseAction(%q) returned non-zero op %+v on error", action, op)
			}
		})
	}
}

// TestTargeted pins which forms carry an explicit node target (the fabric-
// proxyable subset).
func TestTargeted(t *testing.T) {
	cases := []struct {
		op   clusterfailover.Op
		want bool
	}{
		{clusterfailover.RGFailover(1), false},
		{clusterfailover.TargetedRGFailover(1, 0), true},
		{clusterfailover.DataFailover(1), true},
		{clusterfailover.ResetFailover(1), false},
		{clusterfailover.ForcePrimary(1), false},
	}
	for _, tc := range cases {
		if got := tc.op.Targeted(); got != tc.want {
			t.Errorf("Op%+v.Targeted() = %v, want %v", tc.op, got, tc.want)
		}
	}
}

// TestSupportedNode pins the grammar's node range.
func TestSupportedNode(t *testing.T) {
	for n, want := range map[int]bool{-1: false, 0: true, 1: true, 2: false, 99: false} {
		if got := clusterfailover.SupportedNode(n); got != want {
			t.Errorf("SupportedNode(%d) = %v, want %v", n, got, want)
		}
	}
}

// TestIsFailoverAction pins the family gate the gRPC handler uses to route an
// action to ParseAction versus the unrelated system-action handlers.
func TestIsFailoverAction(t *testing.T) {
	yes := []string{
		"cluster-failover:1", "cluster-failover:1:node0",
		"cluster-failover-data:node0", "cluster-failover-reset:1",
		"cluster-failover-force-primary:1",
		// Malformed members are still in the family (routed to ParseAction,
		// which rejects them) — not misrouted to "unknown action".
		"cluster-failover:1:node", "cluster-failover-data:bogus",
		"cluster-failover-force-primary:bogus",
	}
	for _, a := range yes {
		if !clusterfailover.IsFailoverAction(a) {
			t.Errorf("IsFailoverAction(%q) = false, want true", a)
		}
	}
	no := []string{"", "reboot", "zeroize", "userspace-inject:0:x", "cluster-failover", "cluster-failoverX"}
	for _, a := range no {
		if clusterfailover.IsFailoverAction(a) {
			t.Errorf("IsFailoverAction(%q) = true, want false", a)
		}
	}
}
