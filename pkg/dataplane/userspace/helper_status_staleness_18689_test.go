package userspace

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

func TestHelperStatusStalenessUsesStatusAnswersAndBound18689(t *testing.T) {
	m := New()
	now := time.Now()
	m.liveTrack.reset(1, now, false)
	if age, stale := m.HelperStatusAgeAndStale(); age >= 0 || stale {
		t.Fatalf("before a status answer age/stale = %s/%v, want undefined/false", age, stale)
	}
	m.liveTrack.noteAnsweredStatus(1, now.Add(-helperWedgeMinSpan+time.Second))
	m.liveTrack.noteAnswered(1, now) // an unrelated control answer must not refresh status age
	if age, stale := m.HelperStatusAgeAndStale(); stale || age < helperWedgeMinSpan-time.Second {
		t.Fatalf("other control answer refreshed status age: %s stale=%v", age, stale)
	}
	if helperStatusStale(helperWedgeMinSpan - time.Nanosecond) {
		t.Fatal("status age just below helperWedgeMinSpan is stale")
	}
	if !helperStatusStale(helperWedgeMinSpan) {
		t.Fatal("status age at helperWedgeMinSpan is not stale")
	}
	m.liveTrack.noteAnsweredStatus(1, time.Now())
	if age, stale := m.HelperStatusAgeAndStale(); age < 0 || stale {
		t.Fatalf("one answered status did not clear stale: age=%s stale=%v", age, stale)
	}
	m.liveTrack.retire()
	if age, stale := m.HelperStatusAgeAndStale(); age >= 0 || stale {
		t.Fatalf("retired generation retained status age: age=%s stale=%v", age, stale)
	}
}

func TestStatusPollAnswersClearStalenessBeforePublicationFence18689(t *testing.T) {
	oldInterval := statusLoopInterval
	statusLoopInterval = 5 * time.Millisecond
	t.Cleanup(func() { statusLoopInterval = oldInterval })

	for _, tc := range []struct {
		name string
		err  error
	}{
		{name: "success"},
		{name: "answered_decode_error", err: &statusDecodeError{cause: errors.New("bad status")}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m, _ := stalePollManager16653(t)
			m.liveTrack.reset(m.procGen, time.Now(), false)
			m.liveTrack.noteAnsweredStatus(m.procGen, time.Now().Add(-helperWedgeMinSpan-time.Second))
			m.mu.Lock()
			m.setLastStatusLocked(ProcessStatus{PID: 4242})
			m.mu.Unlock()
			if status, err := m.Status(); err != nil || !status.HelperStatusStale {
				t.Fatalf("before poll status stale=%v err=%v, want stale", status.HelperStatusStale, err)
			}

			entered := make(chan struct{})
			release := make(chan struct{})
			var calls atomic.Int32
			m.controlRequestHook = func(req ControlRequest, status *ProcessStatus) error {
				if req.Type != "status" {
					return nil
				}
				if calls.Add(1) != 1 {
					return errors.New("later poll is silent")
				}
				close(entered)
				<-release
				if tc.err != nil {
					return tc.err
				}
				*status = *readyHelperStatus()
				status.PID = 5151
				return nil
			}

			ctx, cancel := context.WithCancel(context.Background())
			done := make(chan struct{})
			go func() {
				defer close(done)
				m.statusLoop(ctx, false)
			}()
			t.Cleanup(func() {
				cancel()
				select {
				case <-release:
				default:
					close(release)
				}
				<-done
			})
			select {
			case <-entered:
			case <-time.After(2 * time.Second):
				t.Fatal("status poll did not enter hook")
			}

			// Simulate a concurrent status publication while the poll is off-lock.
			// The reply below is fenced from cache publication but must still update
			// the answered-status clock before that fence.
			m.mu.Lock()
			m.setLastStatusLocked(ProcessStatus{PID: 4242})
			m.mu.Unlock()
			close(release)

			deadline := time.Now().Add(2 * time.Second)
			for time.Now().Before(deadline) {
				if age, stale := m.HelperStatusAgeAndStale(); age >= 0 && !stale {
					status, err := m.Status()
					if err != nil {
						t.Fatal(err)
					}
					if status.PID != 4242 {
						t.Fatalf("fenced poll replaced cached status PID with %d", status.PID)
					}
					if status.HelperStatusStale || !status.HelperStatusAgeKnown {
						t.Fatalf("fresh status view has age-known=%v stale=%v", status.HelperStatusAgeKnown, status.HelperStatusStale)
					}
					return
				}
				time.Sleep(time.Millisecond)
			}
			t.Fatal("answered status poll did not clear staleness before the publication fence")
		})
	}
}

func TestFailedStatusPollDoesNotClearStaleness18689(t *testing.T) {
	oldInterval := statusLoopInterval
	statusLoopInterval = 5 * time.Millisecond
	t.Cleanup(func() { statusLoopInterval = oldInterval })

	m, _ := stalePollManager16653(t)
	m.liveTrack.reset(m.procGen, time.Now(), false)
	m.liveTrack.noteAnsweredStatus(m.procGen, time.Now().Add(-helperWedgeMinSpan-time.Second))
	m.mu.Lock()
	m.setLastStatusLocked(ProcessStatus{PID: 4242})
	m.mu.Unlock()
	entered := make(chan struct{}, 1)
	var calls atomic.Int32
	m.controlRequestHook = func(req ControlRequest, _ *ProcessStatus) error {
		if req.Type == "status" && calls.Add(1) == 1 {
			close(entered)
		}
		return errors.New("status transport failed")
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		m.statusLoop(ctx, false)
	}()
	t.Cleanup(func() {
		cancel()
		<-done
	})
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("status poll did not enter hook")
	}
	time.Sleep(15 * time.Millisecond)
	if age, stale := m.HelperStatusAgeAndStale(); age < helperWedgeMinSpan || !stale {
		t.Fatalf("failed poll refreshed status age: age=%s stale=%v", age, stale)
	}
	if status, err := m.Status(); err != nil || !status.HelperStatusStale {
		t.Fatalf("status summary view stale=%v err=%v, want stale after failed poll", status.HelperStatusStale, err)
	}
}
