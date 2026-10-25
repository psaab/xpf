package userspace

import (
	"context"
	"os"
	"os/exec"
	"sync/atomic"
	"testing"
	"time"
)

// #16653: the status poll releases m.mu for its RPC and, pre-fix, fenced the
// reply only on helper process identity and the link-cycle lease. A status
// applied by a concurrent mutator while the poll was off-lock (a durable
// DISARMED apply, as disarmSnapshotProtocolFailureLocked /
// disarmBeforeUnsupportedPublishLocked perform) was then overwritten by the
// older poll reply: userspace_ctrl.Enabled=1, ready binding rows and
// lastStatus.ForwardingArmed=true returned for up to one tick. Because the
// stale cache says ForwardingArmed == desired (standalone, supported), the
// same tick's syncDesiredForwardingStateLocked sees no delta and does not
// correct it.
//
// The fix snapshots m.lastStatusSeq before dropping m.mu and discards the
// reply if any other status was applied in between, in the same shape as the
// link-cycle discard. The pager sibling (R3-B16-02) was already closed by
// #16518 (SuppressStatus), so no pager change is needed here.
//
// Arms:
//   - overlap: first poll blocks, a DISARMED status is applied under m.mu,
//     then the older ARMED reply is released. Asserted at the moment the
//     second poll enters its RPC (i.e. the first tick has fully run):
//     ctrl must still be 0 and the cache still disarmed.
//   - twin: same disarm, no poll in flight — ctrl 0 either way.
//   - control: no intervening apply — a fresh poll reply IS applied, so the
//     fence cannot be satisfied by wedging the poll.
//
// The statuses carry ForwardingSupported=true throughout: that keeps
// desiredForwardingArmedLocked() true, so the reconcile cannot mask the
// defect by re-disarming within the same tick (the durable-disarm shape in
// the issue, where syncDesiredForwardingStateLocked sees no delta).

func armedStatus16653() *ProcessStatus {
	st := readyHelperStatus()
	st.ForwardingArmed = true
	st.Capabilities.ForwardingSupported = true
	return st
}

func disarmedStatus16653() *ProcessStatus {
	st := readyHelperStatus()
	st.Enabled = false
	st.ForwardingArmed = false
	st.Capabilities.ForwardingSupported = true
	return st
}

func stalePollManager16653(t *testing.T) (*Manager, *fakeCtrlMap) {
	t.Helper()
	m, ctrl := seamedManager(t)
	proc, err := os.FindProcess(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	m.proc = &exec.Cmd{Process: proc}
	m.lastStatus.Capabilities.ForwardingSupported = true
	return m, ctrl
}

func TestStalePollDoesNotOverwriteNewerDisarm16653(t *testing.T) {
	old := statusLoopInterval
	statusLoopInterval = 5 * time.Millisecond
	t.Cleanup(func() { statusLoopInterval = old })

	t.Run("overlap_discards_stale_armed_reply", func(t *testing.T) {
		m, ctrl := stalePollManager16653(t)
		entered := make(chan struct{}, 1)
		firstRelease := make(chan struct{})
		gate := make(chan struct{})
		var calls atomic.Int32
		m.controlRequestHook = func(req ControlRequest, status *ProcessStatus) error {
			if req.Type != "status" {
				if status != nil {
					*status = *disarmedStatus16653()
				}
				return nil
			}
			if calls.Add(1) == 1 {
				select {
				case entered <- struct{}{}:
				default:
				}
				<-firstRelease
				if status != nil {
					*status = *armedStatus16653()
				}
				return nil
			}
			// Later polls park here so the end of tick 1 is observable
			// without a fresh (disarmed) reply correcting it first.
			<-gate
			if status != nil {
				*status = *disarmedStatus16653()
			}
			return nil
		}

		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan struct{})
		go func() {
			defer close(done)
			m.statusLoop(ctx)
		}()
		var gateOnce atomic.Bool
		t.Cleanup(func() {
			cancel()
			if gateOnce.CompareAndSwap(false, true) {
				close(gate)
			}
			<-done
		})

		select {
		case <-entered:
		case <-time.After(2 * time.Second):
			t.Fatal("status loop did not enter the blocked poll")
		}

		// Concurrent mutator: durable DISARMED status under m.mu while
		// the poll RPC is off-lock. This bumps lastStatusSeq.
		m.mu.Lock()
		seqBefore := m.lastStatusSeq
		if err := m.applyHelperStatusLocked(disarmedStatus16653()); err != nil {
			m.mu.Unlock()
			t.Fatalf("disarm applyHelperStatusLocked: %v", err)
		}
		seqAfter := m.lastStatusSeq
		m.mu.Unlock()
		if seqAfter == seqBefore {
			t.Fatal("premise: disarm did not bump lastStatusSeq, so the fence cannot observe it")
		}
		if !ctrl.haveStored || ctrl.stored.Enabled != 0 {
			t.Fatalf("premise: ctrl = %+v haveStored=%v after disarm, want Enabled=0 written",
				ctrl.stored, ctrl.haveStored)
		}

		close(firstRelease)

		// Tick 1 has fully run once tick 2 enters its (parked) RPC.
		deadline := time.Now().Add(2 * time.Second)
		for calls.Load() < 2 && time.Now().Before(deadline) {
			time.Sleep(time.Millisecond)
		}
		if calls.Load() < 2 {
			t.Fatal("second poll never started: first tick did not complete")
		}

		m.mu.Lock()
		cached := m.lastStatus
		m.mu.Unlock()
		if cached.ForwardingArmed || cached.Enabled {
			t.Fatalf("cached status = Enabled=%v ForwardingArmed=%v after stale poll reply, "+
				"want the newer disarm retained (#16653)", cached.Enabled, cached.ForwardingArmed)
		}
		if ctrl.stored.Enabled != 0 {
			t.Fatalf("ctrl.Enabled = %d after stale poll reply, want 0: the poll "+
				"re-enabled ctrl over a durable disarm (#16653)", ctrl.stored.Enabled)
		}
	})

	t.Run("twin_no_overlap_disarm_holds", func(t *testing.T) {
		m, ctrl := stalePollManager16653(t)
		m.mu.Lock()
		if err := m.applyHelperStatusLocked(disarmedStatus16653()); err != nil {
			m.mu.Unlock()
			t.Fatalf("disarm applyHelperStatusLocked: %v", err)
		}
		m.mu.Unlock()
		if !ctrl.haveStored || ctrl.stored.Enabled != 0 {
			t.Fatalf("ctrl = %+v haveStored=%v after disarm with no poll in flight, want Enabled=0",
				ctrl.stored, ctrl.haveStored)
		}
		m.mu.Lock()
		defer m.mu.Unlock()
		if m.lastStatus.ForwardingArmed || m.lastStatus.Enabled {
			t.Fatalf("cached status armed after disarm: Enabled=%v ForwardingArmed=%v",
				m.lastStatus.Enabled, m.lastStatus.ForwardingArmed)
		}
	})

	t.Run("control_fresh_poll_still_applies", func(t *testing.T) {
		m, _ := stalePollManager16653(t)
		entered := make(chan struct{}, 1)
		gate := make(chan struct{})
		var calls atomic.Int32
		m.controlRequestHook = func(req ControlRequest, status *ProcessStatus) error {
			if req.Type != "status" {
				if status != nil {
					*status = *disarmedStatus16653()
				}
				return nil
			}
			if calls.Add(1) == 1 {
				select {
				case entered <- struct{}{}:
				default:
				}
				if status != nil {
					st := disarmedStatus16653()
					st.RingEntries = 4242
					*status = *st
				}
				return nil
			}
			<-gate
			if status != nil {
				*status = *disarmedStatus16653()
			}
			return nil
		}
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan struct{})
		go func() {
			defer close(done)
			m.statusLoop(ctx)
		}()
		var gateOnce atomic.Bool
		t.Cleanup(func() {
			cancel()
			if gateOnce.CompareAndSwap(false, true) {
				close(gate)
			}
			<-done
		})
		select {
		case <-entered:
		case <-time.After(2 * time.Second):
			t.Fatal("status loop did not enter the poll (control)")
		}
		deadline := time.Now().Add(2 * time.Second)
		for time.Now().Before(deadline) {
			m.mu.Lock()
			gen := m.lastStatusSeq
			m.mu.Unlock()
			if gen >= 1 {
				return
			}
			time.Sleep(time.Millisecond)
		}
		t.Fatal("fresh poll reply was never applied: the #16653 fence wedged the poll")
	})
}
