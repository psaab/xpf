package snmp

import (
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

// TestTrapSendFailure_10016_CountsFailedSends is the #10016 RED-on-revert
// guard. The worker's send-failure arm must count the failed job in
// trapsDropped: otherwise a runtime send failure is neither delivered nor
// counted, breaking the accepted == delivered + trapsDropped exactness the
// README claims. RED on revert: drop the Add(1) from the send-failure arm in
// trapWorker and trapsDropped stays 0 while the assertion below FAILS.
func TestTrapSendFailure_10016_CountsFailedSends(t *testing.T) {
	const total = 5
	var calls atomic.Int64
	sender := func(target string, pkt []byte) error {
		calls.Add(1)
		return errors.New("simulated send failure")
	}

	a := &Agent{startTime: time.Now(), trapSender: sender}
	for i := 0; i < total; i++ {
		a.enqueueTrap(trapJob{target: "192.0.2.9:162", pkt: []byte{1}})
	}

	// Wait until the worker has attempted every send (all fail), so Stop
	// finds an empty queue and the abandoned-backlog drain counts nothing.
	deadline := time.Now().Add(2 * time.Second)
	for calls.Load() != total {
		if time.Now().After(deadline) {
			t.Fatalf("worker attempted %d sends, want %d — the queue did not drain", calls.Load(), total)
		}
		time.Sleep(time.Millisecond)
	}
	a.Stop()

	if got := a.trapsDropped.Load(); got != total {
		t.Fatalf("trapsDropped = %d, want %d — failed sends were not counted (#10016)", got, total)
	}
}

// TestTrapSendFailure_10016_MixedAccountingExact pins the invariant across a
// mix of successful and failed sends: every accepted job resolves to exactly
// one of delivered or trapsDropped, so delivered + trapsDropped == total with
// no residual and no double-count. RED on revert for the same missing Add(1).
func TestTrapSendFailure_10016_MixedAccountingExact(t *testing.T) {
	const total = 6
	var calls, delivered atomic.Int64
	sender := func(target string, pkt []byte) error {
		if calls.Add(1)%2 == 0 {
			delivered.Add(1)
			return nil
		}
		return errors.New("simulated send failure")
	}

	a := &Agent{startTime: time.Now(), trapSender: sender}
	for i := 0; i < total; i++ {
		a.enqueueTrap(trapJob{target: "192.0.2.9:162", pkt: []byte{1}})
	}

	deadline := time.Now().Add(2 * time.Second)
	for calls.Load() != total {
		if time.Now().After(deadline) {
			t.Fatalf("worker attempted %d sends, want %d — the queue did not drain", calls.Load(), total)
		}
		time.Sleep(time.Millisecond)
	}
	a.Stop()

	const wantDelivered, wantDropped = int64(total / 2), uint64(total / 2)
	if got := delivered.Load(); got != wantDelivered {
		t.Fatalf("delivered = %d, want %d", got, wantDelivered)
	}
	if got := a.trapsDropped.Load(); got != wantDropped {
		t.Fatalf("trapsDropped = %d, want %d — failed sends were not counted exactly once (#10016)", got, wantDropped)
	}
	if got := delivered.Load() + int64(a.trapsDropped.Load()); got != total {
		t.Fatalf("delivered(%d) + trapsDropped(%d) = %d, want %d — accounting not exact",
			delivered.Load(), a.trapsDropped.Load(), got, total)
	}
}
