package daemon

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)

// #17082 — the scheduler's optional-interface ladder kept non-latch
// SetPolicySchedulerActiveState / UpdatePolicyScheduleState arms that only
// the retired eBPF *dataplane.Manager satisfied, and the latch fallback
// dropped failClosed on that arm. Both published types implement the latch
// methods, so the fix deletes the non-latch interfaces/arms and binds the
// latch + heartbeat interfaces at compile time
// (policy_scheduler_published_type_17082.go).
//
// RED proof: harness-stash the production fix (restore master's
// daemon_scheduler.go and delete the guard file, keep this test and the
// latch-only fakes in policy_scheduler_apply_test.go). The latch-only fakes
// then reach no updater at all — updatePolicyScheduleStateLocked returns
// nil without calling them — so the latchCalls assertions below fail;
// restoring the fix makes them pass. Separately, removing
// UpdatePolicyScheduleStateWithLatch from LegacyDataPlaneAdapter fails
// `go build ./pkg/daemon/` via the guard file (acceptance in #17082).

// TestPublishedUserspaceDataplaneSatisfiesSchedulerLatch17082 mirrors the
// #9482 published-type cell: it asks about the DYNAMIC type Boot() returns,
// so a third published type that lacks the latch surface reds here even
// though the compile-time guard names only the two known types.
func TestPublishedUserspaceDataplaneSatisfiesSchedulerLatch17082(t *testing.T) {
	var published dataplane.RuntimeDataPlane = dpuserspace.Boot()
	if published == nil {
		t.Fatal("FIXTURE FAILED: dpuserspace.Boot() returned nil")
	}
	if _, ok := published.(policyScheduleFailClosedUpdater); !ok {
		t.Fatalf("#17082: published dataplane %T does not satisfy policyScheduleFailClosedUpdater; the scheduler republish would silently no-op", published)
	}
	if _, ok := published.(policySchedulerActiveStateLatchSetter); !ok {
		t.Fatalf("#17082: published dataplane %T does not satisfy policySchedulerActiveStateLatchSetter; the scheduler seed would silently no-op", published)
	}
	if _, ok := published.(policyScheduleHeartbeatUpdater); !ok {
		t.Fatalf("#17082: published dataplane %T does not satisfy policyScheduleHeartbeatUpdater; the scheduler heartbeat would silently no-op", published)
	}
}

// TestSchedulerLatchCarriesFailClosed17082 is the behavioural defect cell:
// failClosed=true must reach the latch updater intact, and the
// apply-transaction (non-latch-semantics) entry must forward
// failClosed=false through the same latch method — never a non-latch arm.
func TestSchedulerLatchCarriesFailClosed17082(t *testing.T) {
	dp := &runtimeOnlyPolicyUpdaterTestDP{}
	d := &Daemon{}
	d.setDataplane(dp)

	if err := d.updatePolicyScheduleStateWithLatchLocked(&config.Config{}, map[string]bool{"workhours": false}, true); err != nil {
		t.Fatalf("latch update: %v", err)
	}
	if dp.latchCalls != 1 || !dp.failClosedSeen {
		t.Fatalf("latchCalls=%d failClosedSeen=%v, want 1/true (failClosed dropped on a non-latch arm is the #17082 fail-open)", dp.latchCalls, dp.failClosedSeen)
	}
	if got, ok := dp.stateSeen["workhours"]; !ok || got {
		t.Fatalf("stateSeen[workhours] = %t, present=%t; want false", got, ok)
	}

	if err := d.updatePolicyScheduleStateLocked(&config.Config{}, map[string]bool{"workhours": true}); err != nil {
		t.Fatalf("apply-transaction update: %v", err)
	}
	if dp.latchCalls != 2 || dp.failClosedSeen {
		t.Fatalf("after non-latch entry: latchCalls=%d failClosedSeen=%v, want 2/false", dp.latchCalls, dp.failClosedSeen)
	}
}

// TestSchedulerSeedUsesLatchSetter17082 pins the seed arm: the userspace
// fake implements only the latch setter, so a seed that fell back to the
// deleted non-latch setter would never be observed.
func TestSchedulerSeedUsesLatchSetter17082(t *testing.T) {
	dp := &userspacePolicySchedulerApplyTestDP{}
	d := &Daemon{}
	d.setDataplane(dp)

	d.seedPolicySchedulerActiveStateLocked(map[string]bool{"workhours": true}, true)
	if dp.seedCalls != 1 || !dp.seedFailClosedSeen {
		t.Fatalf("seedCalls=%d seedFailClosedSeen=%v, want 1/true", dp.seedCalls, dp.seedFailClosedSeen)
	}
	if got, ok := dp.seedStateSeen["workhours"]; !ok || !got {
		t.Fatalf("seedStateSeen[workhours] = %t, present=%t; want true", got, ok)
	}
}

// CONTROL: a dataplane that satisfies none of the latch interfaces (the
// runtime-only fake without the updater) must still be tolerated as a
// no-op — deleting the fallback arms must not turn an incapable backend
// into an error or a panic on the apply/scheduler paths.
func TestSchedulerLatchIncapableDataplaneStillNoOps17082(t *testing.T) {
	dp := &runtimeOnlyApplyTestDP{}
	d := &Daemon{}
	d.setDataplane(dp)

	if err := d.updatePolicyScheduleStateWithLatchLocked(&config.Config{}, map[string]bool{"workhours": true}, true); err != nil {
		t.Fatalf("incapable dataplane latch update err = %v, want nil no-op", err)
	}
	if err := d.updatePolicyScheduleStateLocked(&config.Config{}, map[string]bool{"workhours": true}); err != nil {
		t.Fatalf("incapable dataplane apply update err = %v, want nil no-op", err)
	}
	// Seed and heartbeat must likewise stay silent no-ops.
	d.seedPolicySchedulerActiveStateLocked(map[string]bool{"workhours": true}, true)
}
