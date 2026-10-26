package cli

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/dataplane"
)

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

// PolicySchedulerDesiredStateAndFailClosed simulates a staged transition for
// the fail-on-revert guard; simulator output must use the applied pair above.
func (d *schedulerAppliedPairDP17837) PolicySchedulerDesiredStateAndFailClosed() (map[string]bool, bool) {
	return d.desiredState, d.desiredLatch
}

// TestShowMatchPoliciesUsesAppliedSchedulerState17837 catches the desired-vs-
// applied divergence: a failed close leaves the helper's scheduled permit live,
// so simulation must continue to report that previously applied permit.
func TestShowMatchPoliciesUsesAppliedSchedulerState17837(t *testing.T) {
	c := &CLI{
		store: schedOnlyMatchStore(t),
		dp: &schedulerAppliedPairDP17837{
			schedulerStateDP: &schedulerStateDP{Manager: dataplane.New(), active: map[string]bool{"after-hours": false}},
			appliedState:     map[string]bool{"after-hours": true},
			desiredState:     map[string]bool{"after-hours": false},
			desiredLatch:     true,
		},
	}
	args := []string{"from-zone", "trust", "to-zone", "untrust", "protocol", "tcp", "destination-port", "80"}
	out := captureStdout(t, func() {
		if err := c.showMatchPolicies(c.store.ActiveConfig(), args); err != nil {
			t.Fatalf("showMatchPolicies() error = %v", err)
		}
	})
	if !strings.Contains(out, "Policy: night-allow") {
		t.Fatalf("show match did not report the applied scheduled permit:\n%s", out)
	}
	if strings.Contains(out, "No matching policy found") {
		t.Fatalf("show match fell through using staged desired state:\n%s", out)
	}
}
