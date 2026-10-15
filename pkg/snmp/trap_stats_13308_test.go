package snmp

import (
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

// TestSNMPTrapStatsExported_13308 is the #13308 (D6-09) RED-on-revert guard.
// trapsDropped was maintained exactly inside package snmp but had no exported
// accessor, and successful sends were never counted, so consumers and
// operators had zero visibility into trap delivery.
//
// RED on pristine master: Agent.TrapStats / trapsSent do not exist (build
// failure). RED on revert of the trapsSent increment alone: sent stays 0
// and enqueued != sent+dropped fires.
func TestSNMPTrapStatsExported_13308(t *testing.T) {
	const total = 6
	var calls atomic.Int64
	sender := func(target string, pkt []byte) error {
		if calls.Add(1)%2 == 0 {
			return nil
		}
		return errors.New("simulated send failure")
	}
	a := &Agent{startTime: time.Now(), trapSender: sender}
	enq, sent, dropped := a.TrapStats()
	if enq != 0 || sent != 0 || dropped != 0 {
		t.Fatalf("fresh agent TrapStats = (%d,%d,%d), want (0,0,0)", enq, sent, dropped)
	}
	for range total {
		a.enqueueTrap(trapJob{target: "192.0.2.9:162", pkt: []byte{1}})
	}
	deadline := time.Now().Add(2 * time.Second)
	for calls.Load() != total {
		if time.Now().After(deadline) {
			t.Fatalf("worker attempted %d sends, want %d", calls.Load(), total)
		}
		time.Sleep(time.Millisecond)
	}
	// Wait for accounting to settle after the sender's final return.
	deadline = time.Now().Add(2 * time.Second)
	for {
		enq, sent, dropped = a.TrapStats()
		if enq == total && sent+dropped == total {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("TrapStats = enqueued=%d sent=%d dropped=%d, want enqueued=%d and sent+dropped=%d",
				enq, sent, dropped, total, total)
		}
		time.Sleep(time.Millisecond)
	}
	a.Stop()
	enq, sent, dropped = a.TrapStats()
	if enq != total || sent != total/2 || dropped != total/2 {
		t.Fatalf("TrapStats = enqueued=%d sent=%d dropped=%d, want (%d,%d,%d)",
			enq, sent, dropped, total, total/2, total/2)
	}
	if enq != sent+dropped {
		t.Fatalf("invariant broken: enqueued=%d != sent(%d)+dropped(%d)", enq, sent, dropped)
	}
}
