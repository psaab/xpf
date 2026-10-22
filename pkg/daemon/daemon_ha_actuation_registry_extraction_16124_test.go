package daemon

import (
	"errors"
	"sync"
	"testing"
	"time"
)

// Daemon-less registry cells: the registry must be constructible and fully
// drivable with no Daemon, which is the point of the extraction. Each cell
// names the pre-extraction Daemon behaviour it preserves.

func TestFailoverActuationRegistryDaemonLess16124(t *testing.T) {
	newReg := func(timeout time.Duration) *failoverActuationRegistry {
		r := newFailoverActuationRegistry()
		r.timeout = timeout
		return r
	}

	t.Run("two outstanding requests both resolve on RG resolve", func(t *testing.T) {
		r := newReg(2 * time.Second)
		r.arm(1, 11)
		r.arm(1, 12)
		r.arm(2, 11)
		r.resolveRG(1, nil)
		if err := r.wait(1, 11); err != nil {
			t.Fatalf("wait(1,11) = %v, want nil", err)
		}
		if err := r.wait(1, 12); err != nil {
			t.Fatalf("wait(1,12) = %v, want nil", err)
		}
		if n := r.armedCount(); n != 1 {
			t.Fatalf("armed after RG1 resolve = %d, want 1 (RG2 untouched)", n)
		}
	})

	t.Run("resolution failure fans out and consumed differs from never armed", func(t *testing.T) {
		r := newReg(2 * time.Second)
		cause := errors.New("rg_active clear rejected")
		r.arm(1, 21)
		r.resolveRG(1, cause)
		if err := r.wait(1, 21); !errors.Is(err, cause) {
			t.Fatalf("wait = %v, want %v", err, cause)
		}
		if err := r.wait(1, 21); !errors.Is(err, ErrFailoverVerdictConsumed) {
			t.Fatalf("second wait = %v, want ErrFailoverVerdictConsumed", err)
		}
		if err := r.wait(1, 99); !errors.Is(err, ErrFailoverNeverArmed) {
			t.Fatalf("never-armed wait = %v, want ErrFailoverNeverArmed", err)
		}
	})

	t.Run("fail is per-request not per-RG", func(t *testing.T) {
		r := newReg(150 * time.Millisecond)
		b1 := r.arm(1, 31)
		r.arm(1, 32)
		cause := errors.New("superseded")
		r.fail(1, 31, b1, cause)
		if err := r.wait(1, 31); !errors.Is(err, cause) {
			t.Fatalf("failed request wait = %v, want %v", err, cause)
		}
		// Sibling must still be armed: its wait must time out, not consume
		// the other request's failure.
		if err := r.wait(1, 32); err == nil || errors.Is(err, cause) {
			t.Fatalf("sibling wait = %v, want a timeout (still armed), not the sibling verdict", err)
		}
	})

	t.Run("timeout drops barrier and late resolve is no-op", func(t *testing.T) {
		r := newReg(40 * time.Millisecond)
		r.arm(1, 41)
		if err := r.wait(1, 41); err == nil {
			t.Fatal("wait with no resolve must time out with non-nil error")
		}
		if n := r.armedCount(); n != 0 {
			t.Fatalf("armed after timeout = %d, want 0", n)
		}
		r.resolveRG(1, nil) // late resolve: no panic, no resurrection
		if err := r.wait(1, 41); !errors.Is(err, ErrFailoverNeverArmed) {
			t.Fatalf("wait after timeout+late resolve = %v, want ErrFailoverNeverArmed", err)
		}
	})

	t.Run("concurrent resolves close exactly once", func(t *testing.T) {
		r := newReg(2 * time.Second)
		r.arm(4, 51)
		var wg sync.WaitGroup
		for i := range 8 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if i%2 == 0 {
					r.resolveRG(4, nil)
					return
				}
				r.resolveRG(4, errFenceRejected)
			}()
		}
		wg.Wait()
		if err := r.wait(4, 51); err != nil && !errors.Is(err, errFenceRejected) {
			t.Fatalf("wait = %v, want nil or the rejection", err)
		}
	})
}

// forEachRGState must visit a snapshot: a callback that creates a new RG
// state (getOrCreateRGState takes the write lock) must not deadlock, and
// states created during the visit are not visited in that pass.
func TestForEachRGStateSnapshot16124(t *testing.T) {
	d := &Daemon{rgStates: make(map[int]*rgStateMachine)}
	d.getOrCreateRGState(1)
	d.getOrCreateRGState(2)

	visited := map[int]bool{}
	done := make(chan struct{})
	go func() {
		defer close(done)
		d.forEachRGState(func(id int, s *rgStateMachine) {
			visited[id] = true
			// Creating another state mid-visit takes rgStatesMu.Lock;
			// holding the lock across the callback would deadlock here.
			d.getOrCreateRGState(99)
		})
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("forEachRGState deadlocked: snapshot semantics broken (lock held across callback?)")
	}
	if len(visited) != 2 || !visited[1] || !visited[2] {
		t.Fatalf("visited = %v, want exactly {1,2} (snapshot taken before visit)", visited)
	}
	if d.getOrCreateRGState(99) == nil {
		t.Fatal("state created during visit must exist afterwards")
	}
}
