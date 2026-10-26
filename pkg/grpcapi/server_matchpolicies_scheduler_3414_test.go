package grpcapi

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/psaab/xpf/pkg/configstore"
	"github.com/psaab/xpf/pkg/dataplane"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
)

// schedOnlyMatchStore commits a config whose ONLY trust->untrust rule is a
// scheduled PERMIT bound to "after-hours", with default-policy deny and NO
// unscheduled fallback policy — so the verdict turns entirely on whether the
// scheduled rule is treated active. The dataplane snapshot builder drops the
// rule whenever per-scheduler active-state is unavailable (policyRuleInactive:
// nil map => Inactive), so the gRPC MatchPolicies simulator must report
// default-deny on that path (#3414).
func schedOnlyMatchStore(t *testing.T) *configstore.Store {
	t.Helper()
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure() error = %v", err)
	}
	if err := store.LoadOverride(`
schedulers {
    scheduler after-hours {
        daily;
    }
}
security {
    zones {
        security-zone trust;
        security-zone untrust;
    }
    policies {
        default-policy deny-all;
        from-zone trust to-zone untrust {
            policy night-allow {
                match { source-address any; destination-address any; application any; }
                then { permit; }
                scheduler-name after-hours;
            }
        }
    }
}
`); err != nil {
		t.Fatalf("LoadOverride() error = %v", err)
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit() error = %v", err)
	}
	return store
}

// schedMatchServer builds a gRPC Server over schedOnlyMatchStore. When
// withProvider is false the dp is a bare *dataplane.Manager, which satisfies
// grpcRuntime but NOT policySchedulerStateProvider — exactly the
// state-unavailable path (s.policySchedulerActiveState returns ok=false).
func schedMatchServer(t *testing.T, active map[string]bool, withProvider bool) *Server {
	t.Helper()
	s := &Server{store: schedOnlyMatchStore(t)}
	if withProvider {
		s.dp = &schedulerStateDP{Manager: dataplane.New(), active: active}
	} else {
		s.dp = dataplane.New()
	}
	return s
}

// TestGRPCMatchPoliciesScheduledPolicyFailsClosedWhenStateUnavailable pins
// #3414 on the gRPC MatchPolicies simulator. With NO scheduler-state provider
// (early boot / NoDataplane) the simulator must treat the scheduler-bound
// permit as INACTIVE — exactly as the dataplane snapshot builder does — and
// fall through to the default-policy. Before #3414 s.policyInactiveFn()
// returned nil on this path, so the scheduled permit was simulated
// as-if-active and gRPC certified a PERMIT the dataplane is actually skipping.
//
// RED-on-revert: reverting server_show_policies_text.go:policyInactiveFn to
//
//	state, ok := s.policySchedulerActiveState(); if !ok { return nil }
//
// makes the no-provider case below return a matched PERMIT, so the Matched/
// Action/DefaultUsed assertions fail. Positive controls C/D (provider present)
// are unaffected by that revert, so they stay green and confirm the available-
// state path is not over-fail-closed.
func TestGRPCMatchPoliciesScheduledPolicyFailsClosedWhenStateUnavailable(t *testing.T) {
	req := &pb.MatchPoliciesRequest{
		FromZone:        "trust",
		ToZone:          "untrust",
		Protocol:        "tcp",
		DestinationPort: 80,
	}

	// Case A: no provider -> state unavailable -> fail closed (default deny).
	t.Run("no provider -> fail closed default deny", func(t *testing.T) {
		s := schedMatchServer(t, nil, false)
		resp, err := s.MatchPolicies(context.Background(), req)
		if err != nil {
			t.Fatalf("MatchPolicies error = %v", err)
		}
		if resp.Matched {
			t.Fatalf("Matched = true, want false (scheduled permit must be skipped when state unavailable); got %+v", resp)
		}
		if resp.Action != "deny (default)" {
			t.Errorf("Action = %q, want %q", resp.Action, "deny (default)")
		}
		if !resp.DefaultUsed {
			t.Errorf("DefaultUsed = false, want true (fell through to default-policy)")
		}
	})

	// Case C (positive control): provider present, scheduler ACTIVE -> permit.
	t.Run("scheduler active -> permit", func(t *testing.T) {
		s := schedMatchServer(t, map[string]bool{"after-hours": true}, true)
		resp, err := s.MatchPolicies(context.Background(), req)
		if err != nil {
			t.Fatalf("MatchPolicies error = %v", err)
		}
		if !resp.Matched {
			t.Fatalf("Matched = false, want true (scheduler active); got %+v", resp)
		}
		if resp.Action != "permit" {
			t.Errorf("Action = %q, want %q", resp.Action, "permit")
		}
		if resp.DefaultUsed {
			t.Errorf("DefaultUsed = true, want false (scheduled permit matched)")
		}
	})

	// Case D (regression anchor): provider present, scheduler INACTIVE ->
	// default deny (the #3104 behavior, unchanged by #3414).
	t.Run("scheduler inactive -> default deny", func(t *testing.T) {
		s := schedMatchServer(t, map[string]bool{"after-hours": false}, true)
		resp, err := s.MatchPolicies(context.Background(), req)
		if err != nil {
			t.Fatalf("MatchPolicies error = %v", err)
		}
		if resp.Matched {
			t.Fatalf("Matched = true, want false (scheduler inactive); got %+v", resp)
		}
		if resp.Action != "deny (default)" {
			t.Errorf("Action = %q, want %q", resp.Action, "deny (default)")
		}
		if !resp.DefaultUsed {
			t.Errorf("DefaultUsed = false, want true")
		}
	})
}

type schedulerAppliedPairDP17837 struct {
	*schedulerStateDP
	appliedState map[string]bool
	appliedLatch bool
	desiredState map[string]bool
	desiredLatch bool
}

func (d *schedulerAppliedPairDP17837) PolicySchedulerAppliedStateAndFailClosed() (map[string]bool, bool) {
	return d.appliedState, d.appliedLatch
}

func (d *schedulerAppliedPairDP17837) PolicySchedulerDesiredStateAndFailClosed() (map[string]bool, bool) {
	return d.desiredState, d.desiredLatch
}

// TestGRPCMatchPoliciesUsesAppliedSchedulerState17837 verifies MatchPolicies
// does not make a staged desired transition visible before helper acceptance.
func TestGRPCMatchPoliciesUsesAppliedSchedulerState17837(t *testing.T) {
	s := &Server{
		store: schedOnlyMatchStore(t),
		dp: &schedulerAppliedPairDP17837{
			schedulerStateDP: &schedulerStateDP{Manager: dataplane.New(), active: map[string]bool{"after-hours": false}},
			appliedState:     map[string]bool{"after-hours": true},
			desiredState:     map[string]bool{"after-hours": false},
			desiredLatch:     true,
		},
	}
	resp, err := s.MatchPolicies(context.Background(), &pb.MatchPoliciesRequest{
		FromZone:        "trust",
		ToZone:          "untrust",
		Protocol:        "tcp",
		DestinationPort: 80,
	})
	if err != nil {
		t.Fatalf("MatchPolicies() error = %v", err)
	}
	if !resp.Matched || resp.Action != "permit" || resp.DefaultUsed {
		t.Fatalf("MatchPolicies() = %+v, want applied scheduled permit", resp)
	}
}
