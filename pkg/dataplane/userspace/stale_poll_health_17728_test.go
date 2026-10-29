package userspace

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// #17728: the #16653 stale-sequence fence discarded the whole tick, including
// the #9651 poll-health accounting that ran only after it. A same-process,
// same-cycle poll whose reply is stale because a concurrent mutator published
// a newer status still contributes its result to helper liveness. Status
// publication remains fenced, so the stale armed reply must not overwrite the
// newer disarm.
func TestStaleSeqFencePreservesPollHealthAccounting17728(t *testing.T) {
	oldInterval := statusLoopInterval
	statusLoopInterval = 5 * time.Millisecond
	t.Cleanup(func() { statusLoopInterval = oldInterval })

	for _, tc := range []struct {
		name             string
		pollErr          error
		initialFailures  int
		wantFailures     int
		wantFirstFailure bool
	}{
		{
			name:             "answered_poll_resets_wedge_count",
			initialFailures:  helperWedgeFailedPolls - 1,
			wantFailures:     0,
			wantFirstFailure: false,
		},
		{
			name:             "transport_error_still_counts",
			pollErr:          errors.New("transport: connection refused"),
			initialFailures:  1,
			wantFailures:     2,
			wantFirstFailure: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m, ctrl := stalePollManager16653(t)
			firstFailure := time.Now().Add(-time.Second)
			m.mu.Lock()
			m.liveness.failures = tc.initialFailures
			if tc.initialFailures != 0 {
				m.liveness.firstFailure = firstFailure
			}
			seqBefore := m.lastStatusSeq
			m.mu.Unlock()

			entered := make(chan struct{}, 1)
			firstRelease := make(chan struct{})
			secondPollGate := make(chan struct{})
			var firstOnce, secondOnce sync.Once
			releaseFirst := func() { firstOnce.Do(func() { close(firstRelease) }) }
			releaseSecond := func() { secondOnce.Do(func() { close(secondPollGate) }) }
			var calls atomic.Int32
			m.controlRequestHook = func(req ControlRequest, status *ProcessStatus) error {
				if req.Type != "status" {
					if status != nil {
						*status = *disarmedStatus16653()
					}
					return nil
				}
				switch calls.Add(1) {
				case 1:
					select {
					case entered <- struct{}{}:
					default:
					}
					<-firstRelease
					if tc.pollErr != nil {
						return tc.pollErr
					}
					if status != nil {
						*status = *armedStatus16653()
					}
					return nil
				default:
					<-secondPollGate
					if status != nil {
						*status = *disarmedStatus16653()
					}
					return nil
				}
			}

			ctx, cancel := context.WithCancel(context.Background())
			done := make(chan struct{})
			go func() {
				defer close(done)
				m.statusLoop(ctx)
			}()
			defer func() {
				cancel()
				releaseFirst()
				releaseSecond()
				<-done
			}()

			select {
			case <-entered:
			case <-time.After(2 * time.Second):
				t.Fatal("status loop did not enter the blocked poll")
			}

			m.mu.Lock()
			if m.lastStatusSeq != seqBefore {
				m.mu.Unlock()
				t.Fatalf("lastStatusSeq changed before concurrent mutation: got %d want %d", m.lastStatusSeq, seqBefore)
			}
			if err := m.applyHelperStatusLocked(disarmedStatus16653()); err != nil {
				m.mu.Unlock()
				t.Fatalf("disarm applyHelperStatusLocked: %v", err)
			}
			seqAfter := m.lastStatusSeq
			m.mu.Unlock()
			if seqAfter == seqBefore {
				t.Fatal("premise: disarm did not bump lastStatusSeq")
			}

			releaseFirst()
			deadline := time.Now().Add(2 * time.Second)
			for calls.Load() < 2 && time.Now().Before(deadline) {
				time.Sleep(time.Millisecond)
			}
			if calls.Load() < 2 {
				t.Fatal("second poll never started: first tick did not complete")
			}

			m.mu.Lock()
			failures := m.liveness.failures
			firstFailureZero := m.liveness.firstFailure.IsZero()
			gotFirstFailure := m.liveness.firstFailure
			cached := m.lastStatus
			gotSeq := m.lastStatusSeq
			m.mu.Unlock()

			if failures != tc.wantFailures || firstFailureZero == tc.wantFirstFailure {
				t.Fatalf("liveness after stale poll = failures:%d firstFailureZero:%v, want failures:%d firstFailureZero:%v (#17728/#9651)",
					failures, firstFailureZero, tc.wantFailures, !tc.wantFirstFailure)
			}
			if tc.wantFirstFailure && !gotFirstFailure.Equal(firstFailure) {
				t.Fatalf("firstFailure changed after stale transport error: got %v want %v", gotFirstFailure, firstFailure)
			}
			if gotSeq != seqAfter {
				t.Fatalf("lastStatusSeq = %d after stale reply, want %d (#16653)", gotSeq, seqAfter)
			}
			if cached.ForwardingArmed || cached.Enabled {
				t.Fatalf("cached status = Enabled=%v ForwardingArmed=%v after stale reply, want newer disarm (#16653)", cached.Enabled, cached.ForwardingArmed)
			}
			if ctrl.stored.Enabled != 0 {
				t.Fatalf("ctrl.Enabled = %d after stale reply, want 0 (#16653)", ctrl.stored.Enabled)
			}
		})
	}
}
