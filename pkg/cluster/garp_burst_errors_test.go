package cluster

import (
	"errors"
	"sync"
	"testing"

	"golang.org/x/sys/unix"
)

// withBurstSend swaps the burstSend seam for the duration of fn and restores
// it, also resetting the burstSendErrors counter so each test sees a clean
// baseline. It returns the counter delta observed during fn.
func withBurstSend(t *testing.T, sender func(fd int, pkt []byte, addr unix.Sockaddr) error, fn func()) uint64 {
	t.Helper()
	orig := burstSend
	before := burstSendErrors.Load()
	burstSend = sender
	defer func() { burstSend = orig }()
	fn()
	return burstSendErrors.Load() - before
}

// failAfterN returns a sender that succeeds for the first n calls then fails
// for every subsequent call, recording how many frames it was asked to send.
func failAfterN(n int, frames *int) func(int, []byte, unix.Sockaddr) error {
	var mu sync.Mutex
	calls := 0
	return func(_ int, _ []byte, _ unix.Sockaddr) error {
		mu.Lock()
		defer mu.Unlock()
		calls++
		*frames = calls
		if calls <= n {
			return nil
		}
		return errors.New("injected send failure")
	}
}

// TestARPBurstFollowupsCountFailures proves the GARP burst follow-up loop
// counts per-frame send failures into burstSendErrors instead of dropping
// them. With count=4 the loop sends (count-1)*2 = 6 follow-up frames; the
// injected sender succeeds once then fails, so 5 frames fail.
//
// FAIL-ON-REVERT: if the //nolint:errcheck "ignore the error" behaviour is
// restored (drop the burstSend result, never touch burstSendErrors), the
// counter stays at 0 and this assertion goes RED.
func TestARPBurstFollowupsCountFailures(t *testing.T) {
	const count = 4
	var frames int
	delta := withBurstSend(t, failAfterN(1, &frames), func() {
		// fd=-1: the helper's defer unix.Close(-1) returns EBADF, ignored.
		runARPBurstFollowups(-1, "ge-0-0-2", "10.0.61.1", []byte{0x01}, []byte{0x02}, unix.SockaddrLinklayer{}, count, func() bool { return true })
	})

	wantFrames := (count - 1) * 2 // 6 follow-up frames attempted
	if frames != wantFrames {
		t.Fatalf("follow-up frames attempted = %d, want %d (loop must not abort on error)", frames, wantFrames)
	}
	wantFailed := uint64(wantFrames - 1) // first succeeds, rest fail
	if delta != wantFailed {
		t.Fatalf("burstSendErrors delta = %d, want %d (errors must be counted, not dropped)", delta, wantFailed)
	}
}

// TestNABurstFollowupsCountFailures is the IPv6 unsolicited-NA equivalent.
// count=4 -> (count-1) = 3 follow-up NAs; first succeeds, 2 fail.
func TestNABurstFollowupsCountFailures(t *testing.T) {
	const count = 4
	var frames int
	delta := withBurstSend(t, failAfterN(1, &frames), func() {
		runNABurstFollowups(-1, "ge-0-0-2", "2001:559:8585:80::200", []byte{0x01}, unix.SockaddrLinklayer{}, count, func() bool { return true })
	})

	wantFrames := count - 1 // 3 follow-up NAs attempted
	if frames != wantFrames {
		t.Fatalf("follow-up NAs attempted = %d, want %d (loop must not abort on error)", frames, wantFrames)
	}
	wantFailed := uint64(wantFrames - 1) // first succeeds, rest fail
	if delta != wantFailed {
		t.Fatalf("burstSendErrors delta = %d, want %d (errors must be counted, not dropped)", delta, wantFailed)
	}
}

// TestBurstFollowupsAllSucceedNoCount confirms the happy path leaves the
// counter untouched — a clean failover must not report phantom send errors.
func TestBurstFollowupsAllSucceedNoCount(t *testing.T) {
	var frames int
	delta := withBurstSend(t, failAfterN(1<<30, &frames), func() {
		runARPBurstFollowups(-1, "ge-0-0-2", "10.0.61.1", []byte{0x01}, []byte{0x02}, unix.SockaddrLinklayer{}, 3, func() bool { return true })
	})
	if delta != 0 {
		t.Fatalf("burstSendErrors delta = %d on all-success path, want 0", delta)
	}
}

// TestBurstSendErrorsAccessor confirms the exported observability accessor
// reflects the underlying atomic counter.
func TestBurstSendErrorsAccessor(t *testing.T) {
	if got, want := BurstSendErrors(), burstSendErrors.Load(); got != want {
		t.Fatalf("BurstSendErrors() = %d, want %d", got, want)
	}
}
