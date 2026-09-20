package nfqueue

import (
	"errors"
	"testing"

	"golang.org/x/sys/unix"
)

// TestVerdictBatchPrevalidatesDuplicate9506 protects the reservation boundary:
// a duplicate pointer must fail before any packet is marked terminal or sent.
// Reverting the prevalidation would strand the first reservation and make a
// supervisor unable to reconcile the batch.
func TestVerdictBatchPrevalidatesDuplicate9506(t *testing.T) {
	q := &Queue{id: 61, fd: -1}
	pkt := &Packet{q: q, id: 1}
	if err := q.VerdictBatch(VerdictAccept, []*Packet{pkt, pkt}); !errors.Is(err, ErrAlreadyVerdicted) {
		t.Fatalf("duplicate batch error=%v, want ErrAlreadyVerdicted", err)
	}
	if pkt.done.Load() {
		t.Fatal("duplicate batch marked packet terminal before validation")
	}
	stats := q.Stats()
	if stats.VerdictAttempted != 0 || stats.VerdictUncertain != 0 || stats.VerdictSuccessful != 0 {
		t.Fatalf("duplicate batch transport stats=%+v, want no attempted transport", stats)
	}
}

// TestVerdictUncertainIsTerminal9506 protects the fail-closed transport
// contract: an unacknowledged send error is counted uncertain and cannot be
// retried as though the kernel definitely rejected it.
func TestVerdictUncertainIsTerminal9506(t *testing.T) {
	q := &Queue{id: 61, fd: -1}
	pkt := &Packet{q: q, id: 2}
	if err := pkt.Verdict(VerdictAccept); err == nil {
		t.Fatal("invalid descriptor verdict unexpectedly succeeded")
	}
	if !pkt.done.Load() {
		t.Fatal("send error left packet retryable")
	}
	if err := pkt.Verdict(VerdictDrop); !errors.Is(err, ErrAlreadyVerdicted) {
		t.Fatalf("retry error=%v, want ErrAlreadyVerdicted", err)
	}
	stats := q.Stats()
	if stats.VerdictAttempted != 1 || stats.VerdictSuccessful != 0 || stats.VerdictUncertain != 1 {
		t.Fatalf("uncertain transport stats=%+v, want attempted=1 successful=0 uncertain=1", stats)
	}
}

func TestVerdictAfterCloseReturnsErrClosed9506(t *testing.T) {
	q := &Queue{id: 61, fd: -1, closed: true}
	pkt := &Packet{q: q, id: 3}
	if err := pkt.Verdict(VerdictAccept); !errors.Is(err, ErrClosed) {
		t.Fatalf("closed queue verdict=%v, want ErrClosed", err)
	}
}

func TestVerdictEAGAINLeavesPacketRetryable9506(t *testing.T) {
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_DGRAM|unix.SOCK_NONBLOCK, 0)
	if err != nil {
		t.Fatalf("socketpair: %v", err)
	}
	defer unix.Close(fds[0])
	defer unix.Close(fds[1])
	fill := make([]byte, 4096)
	for {
		if err := unix.Send(fds[0], fill, unix.MSG_DONTWAIT); err != nil {
			if err != unix.EAGAIN && err != unix.EWOULDBLOCK {
				t.Fatalf("fill socket: %v", err)
			}
			break
		}
	}
	q := &Queue{id: 61, fd: fds[0]}
	pkt := &Packet{q: q, id: 4}
	if err := pkt.Verdict(VerdictAccept); !errors.Is(err, ErrVerdictTimeout) {
		t.Fatalf("EAGAIN verdict error=%v, want ErrVerdictTimeout", err)
	}
	if pkt.done.Load() {
		t.Fatal("EAGAIN verdict consumed terminal reservation")
	}
}
