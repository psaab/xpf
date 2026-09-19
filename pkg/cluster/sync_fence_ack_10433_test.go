package cluster

import (
	"net"
	"strings"
	"testing"
	"time"
)

func fenceAckTimeoutSession10433(seq uint64, waiter chan FenceAck) *SessionSync {
	ss := NewSessionSync(":0", "10.0.0.2:4785", nil)
	ss.fenceAckWaiters = map[uint64]fenceAckWaiter{
		seq: {ch: waiter},
	}
	return ss
}
func TestFenceAckTimeoutArmConsumesDeliveredAck10433(t *testing.T) {
	const seq = 17
	waiter := make(chan FenceAck, 1)
	want := FenceAck{Seq: seq, Status: FenceAckOK, RGsFenced: 2, RGsTotal: 2}
	waiter <- want
	timer := time.NewTimer(time.Nanosecond)
	defer timer.Stop()

	// Both the ACK and real timer.C are ready together. Consume only the
	// deadline here to force the timeout-arm continuation; the continuation
	// itself must still take the buffered ACK without select randomness.
	select {
	case <-timer.C:
	case <-time.After(time.Second):
		t.Fatal("FIXTURE: real timer did not fire")
	}
	got := fenceAckTimeoutSession10433(seq, waiter).fenceAckAtTimeout(seq, waiter)
	if got.timedOut {
		t.Fatal("timeout arm reported a timeout despite a delivered ack")
	}
	if !got.ok {
		t.Fatal("timeout arm treated a delivered ack as a disconnect")
	}
	if got.ack != want {
		t.Fatalf("timeout arm ack = %+v, want %+v", got.ack, want)
	}
}

func TestFenceAckTimeoutArmReportsGenuineTimeout10433(t *testing.T) {
	const seq = 18
	waiter := make(chan FenceAck, 1)

	got := fenceAckTimeoutSession10433(seq, waiter).fenceAckAtTimeout(seq, waiter)
	if !got.timedOut {
		t.Fatalf("empty waiter result = %+v, want timeout", got)
	}
	if got.ok {
		t.Fatal("genuine timeout reported as an acknowledgement")
	}
}

func TestFenceAckTimeoutArmReportsDisconnect10433(t *testing.T) {
	const seq = 19
	waiter := make(chan FenceAck)
	close(waiter)

	got := fenceAckTimeoutSession10433(seq, waiter).fenceAckAtTimeout(seq, waiter)
	if got.timedOut {
		t.Fatal("closed waiter reported as a timeout")
	}
	if got.ok {
		t.Fatal("closed waiter reported as an acknowledgement")
	}
}

func TestSendFenceAwaitReportsGenuineTimeout10433(t *testing.T) {
	ss := NewSessionSync(":0", "10.0.0.2:4785", nil)
	local, peer := net.Pipe()
	defer local.Close()
	defer peer.Close()
	ss.installConn(0, local)
	ss.peerCapabilityFlags.Store(uint32(capFlagFenceAck))

	errCh := make(chan error, 1)
	go func() {
		_, err := ss.SendFenceAwait(25 * time.Millisecond)
		errCh <- err
	}()
	waitForFenceFrame9915(t, peer)

	select {
	case err := <-errCh:
		if err == nil {
			t.Fatal("fence wait returned success without an acknowledgement")
		}
		if !strings.Contains(err.Error(), "timed out") {
			t.Fatalf("fence wait error = %q, want timeout", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("fence wait did not report the genuine timeout")
	}
	if got := ss.stats.FenceAcksTimedOut.Load(); got != 1 {
		t.Fatalf("FenceAcksTimedOut = %d, want 1", got)
	}
}
