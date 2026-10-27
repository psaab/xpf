package cluster

import (
	"sync"
	"sync/atomic"
	"testing"

	"golang.org/x/sys/unix"
)

// recordingBurstSend installs a burstSend seam that records every follow-up
// frame and never errors. It returns a count accessor and a restore func.
// fd is never touched (the loops defer unix.Close(fd); -1 yields a harmless
// EBADF that the loop ignores).
func recordingBurstSend(t *testing.T) (count func() int, restore func()) {
	t.Helper()
	var n atomic.Int64
	prev := burstSend
	burstSend = func(fd int, pkt []byte, addr unix.Sockaddr) error {
		n.Add(1)
		return nil
	}
	return func() int { return int(n.Load()) }, func() { burstSend = prev }
}

// TestARPBurstFollowups_AbortsOnAbdication is the #2867 fail-on-revert guard.
//
// It starts the GARP burst follow-up loop as "master", then abdicates (the
// stillValid predicate flips to false) after the FIRST recorded follow-up
// frame. With the abdication gate present the loop must stop, so far fewer
// than the full (count-1)*2 follow-up frames are sent. If the gate is removed
// (the `if stillValid != nil && !stillValid()` break deleted), the loop runs
// to completion and sends all follow-up frames — and this test goes RED.
func TestARPBurstFollowups_AbortsOnAbdication(t *testing.T) {
	count, restore := recordingBurstSend(t)
	defer restore()

	const burst = 10 // 9 follow-up pairs = 18 follow-up frames if ungated
	var abdicated atomic.Bool
	stillValid := func() bool { return !abdicated.Load() }

	// Flip to abdicated as soon as the loop performs its first follow-up
	// frame, by wrapping the recorder.
	prev := burstSend
	var once sync.Once
	burstSend = func(fd int, pkt []byte, addr unix.Sockaddr) error {
		once.Do(func() { abdicated.Store(true) })
		return prev(fd, pkt, addr)
	}

	runARPBurstFollowups(-1, "eth0", "10.0.0.1", []byte{1}, []byte{2},
		unix.SockaddrLinklayer{}, burst, stillValid)

	// First iteration sends the request+reply pair (2 frames) before the
	// gate is re-checked at the top of iteration 2, where abdication (set
	// during the first frame) stops the loop. So at most 2 follow-up frames.
	if got := count(); got > 2 {
		t.Fatalf("abdication gate failed: sent %d follow-up frames, want <= 2 "+
			"(loop kept poisoning ARP caches after abdication — #2867 regression)", got)
	}
	if got := count(); got == 0 {
		t.Fatalf("sent 0 follow-up frames; the loop never ran (test seam broken)")
	}
}

// TestARPBurstFollowups_RunsToCompletionWhileMaster proves the gate does not
// regress the legitimate burst: while still master (stillValid stays true)
// every follow-up frame is sent.
func TestARPBurstFollowups_RunsToCompletionWhileMaster(t *testing.T) {
	count, restore := recordingBurstSend(t)
	defer restore()

	const burst = 4 // 3 follow-up pairs = 6 follow-up frames
	stillValid := func() bool { return true }

	runARPBurstFollowups(-1, "eth0", "10.0.0.1", []byte{1}, []byte{2},
		unix.SockaddrLinklayer{}, burst, stillValid)

	if got, want := count(), (burst-1)*2; got != want {
		t.Fatalf("master burst truncated: sent %d follow-up frames, want %d", got, want)
	}
}

// TestARPBurstFollowups_NilPredicateRefused17158 proves #17158: a nil
// predicate is refused and sends nothing, at both the follow-up helper
// and the exported burst entry points. Reverting the nil check (restoring
// the ungated twin behaviour) makes the helper send (burst-1)*2 frames
// and the exported calls return nil/interface errors instead — RED.
func TestARPBurstFollowups_NilPredicateRefused17158(t *testing.T) {
	count, restore := recordingBurstSend(t)
	defer restore()

	const burst = 4
	runARPBurstFollowups(-1, "eth0", "10.0.0.1", []byte{1}, []byte{2},
		unix.SockaddrLinklayer{}, burst, nil)
	if got := count(); got != 0 {
		t.Fatalf("nil-predicate ARP follow-ups sent %d frames, want 0 (#17158)", got)
	}
	runNABurstFollowups(-1, "eth0", "fd00::1", []byte{1},
		unix.SockaddrLinklayer{}, burst, nil)
	if got := count(); got != 0 {
		t.Fatalf("nil-predicate NA follow-ups sent %d frames, want 0 (#17158)", got)
	}
	// Exported entry points refuse before any socket/interface work: the
	// predicate check precedes address/interface validation, so a bogus
	// interface still yields the predicate error, not a lookup error.
	if err := SendGratuitousARPBurstGated("no-such-iface-17158", nil, 3, nil); err == nil {
		t.Fatal("SendGratuitousARPBurstGated with nil predicate was accepted (#17158)")
	}
	if err := SendGratuitousIPv6BurstGated("no-such-iface-17158", nil, 3, nil); err == nil {
		t.Fatal("SendGratuitousIPv6BurstGated with nil predicate was accepted (#17158)")
	}
	if err := SendProxyGratuitousIPv6BurstGated("no-such-iface-17158", nil, 3, nil); err == nil {
		t.Fatal("SendProxyGratuitousIPv6BurstGated with nil predicate was accepted (#17158)")
	}
}

// TestNABurstFollowups_AbortsOnAbdication is the IPv6 sibling fail-on-revert
// guard for runNABurstFollowups.
func TestNABurstFollowups_AbortsOnAbdication(t *testing.T) {
	count, restore := recordingBurstSend(t)
	defer restore()

	const burst = 10 // 9 follow-up NAs if ungated
	var abdicated atomic.Bool
	stillValid := func() bool { return !abdicated.Load() }

	prev := burstSend
	var once sync.Once
	burstSend = func(fd int, pkt []byte, addr unix.Sockaddr) error {
		once.Do(func() { abdicated.Store(true) })
		return prev(fd, pkt, addr)
	}

	runNABurstFollowups(-1, "eth0", "fd00::1", []byte{1},
		unix.SockaddrLinklayer{}, burst, stillValid)

	// One NA per iteration: iter 1 sends (and sets abdicated), iter 2's
	// pre-send gate stops the loop. At most 1 follow-up frame.
	if got := count(); got > 1 {
		t.Fatalf("NA abdication gate failed: sent %d follow-up frames, want <= 1 "+
			"(loop kept poisoning neighbor caches after abdication — #2867 regression)", got)
	}
	if got := count(); got == 0 {
		t.Fatalf("sent 0 follow-up NAs; the loop never ran (test seam broken)")
	}
}

// TestNABurstFollowups_RunsToCompletionWhileMaster proves the IPv6 burst is
// not regressed while still master.
func TestNABurstFollowups_RunsToCompletionWhileMaster(t *testing.T) {
	count, restore := recordingBurstSend(t)
	defer restore()

	const burst = 4 // 3 follow-up NAs
	runNABurstFollowups(-1, "eth0", "fd00::1", []byte{1},
		unix.SockaddrLinklayer{}, burst, func() bool { return true })

	if got, want := count(), burst-1; got != want {
		t.Fatalf("master NA burst truncated: sent %d follow-up frames, want %d", got, want)
	}
}
