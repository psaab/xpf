// #5380, single-shot form: ClearAllSessions issues exactly ONE helper
// round trip (mirror_clear_chunk), so a hung helper costs exactly one
// round-trip deadline by construction — there is no chunk loop left to
// guard. (The old form of this test bound a per-chunk dial loop with a
// helperDown() skip guard; both are gone with the Go paging branches.)
//
// This binds the structural single-dial shape. A mirror seeded with one
// v4 and one v6 session clears against a HUNG helper (accepts but never
// replies): the clear dials once, pays ~one shrunk deadline, surfaces
// the transport failure with (0,0), and leaves the mirror intact
// (fail-closed atomic — Go sweeps nothing).
//
// FAIL-ON-REVERT: reintroduce any retry/continuation loop around the
// clear RPC and this test goes RED — the hung helper accepts 2+
// connections (not 1) and the elapsed doubles past the bound. A clean
// structural + elapsed assertion, not a compile break.
package userspace

import (
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/cilium/ebpf/rlimit"
)

// countingHungSessionSocket binds the dedicated session socket, ACCEPTS every
// connection, and parks it without reading or replying — a helper whose
// session thread is wedged. It records how many connections were accepted so a
// test can prove which chunks actually dialed the helper (a skipped chunk
// never dials).
type countingHungSessionSocket struct {
	ln      net.Listener
	mu      sync.Mutex
	accepts int
	held    []net.Conn
}

func startCountingHungSessionSocket(t *testing.T, sockPath string) *countingHungSessionSocket {
	t.Helper()
	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("listen hung session socket: %v", err)
	}
	c := &countingHungSessionSocket{ln: ln}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			c.mu.Lock()
			c.accepts++
			c.held = append(c.held, conn)
			c.mu.Unlock()
		}
	}()
	t.Cleanup(func() {
		_ = ln.Close()
		c.mu.Lock()
		for _, h := range c.held {
			_ = h.Close()
		}
		c.mu.Unlock()
	})
	return c
}

func (c *countingHungSessionSocket) acceptCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.accepts
}

func TestClearAllSingleShotFastFailsOnHungHelper5380(t *testing.T) {
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Skipf("RemoveMemlock: %v", err)
	}

	// One v4 + one v6 mirror session; newClearManager5881 sets m.proc,
	// injects real session maps, and seeds the pair; the short-prefix
	// mkdtemp keeps the AF_UNIX path under the 108-byte sun_path limit
	// (run with TMPDIR=/tmp).
	m, adapter, sessionSock := newClearManager5881(t)
	sock := startCountingHungSessionSocket(t, sessionSock)

	// Shrink the per-request bounds so the timing is fast to measure. The
	// dial succeeds (the socket accepts), so the round-trip deadline is
	// what the hung clear pays.
	origDial, origRT := sessionSyncDialTimeout, sessionSyncRoundtripDeadline
	sessionSyncDialTimeout = 400 * time.Millisecond
	sessionSyncRoundtripDeadline = 400 * time.Millisecond
	t.Cleanup(func() {
		sessionSyncDialTimeout = origDial
		sessionSyncRoundtripDeadline = origRT
	})

	type result struct {
		v4, v6  int
		err     error
		elapsed time.Duration
	}
	resCh := make(chan result, 1)
	go func() {
		start := time.Now()
		v4, v6, err := adapter.ClearAllSessions()
		resCh <- result{v4: v4, v6: v6, err: err, elapsed: time.Since(start)}
	}()

	// Bound sits between one and two shrunk deadlines: the single-shot
	// clear pays ~one deadline; a reintroduced loop would pay ~two. The
	// 5s watchdog guarantees the suite never hangs on the pathological
	// regression.
	const bound = 650 * time.Millisecond
	select {
	case res := <-resCh:
		if res.elapsed > bound {
			t.Fatalf("ClearAllSessions took %v against a hung helper; want <%v. "+
				"More than one dial happened — a paging/retry loop was reintroduced (#5380)",
				res.elapsed, bound)
		}
		// Structural, jitter-free RED signal: exactly ONE dial.
		if got := sock.acceptCount(); got != 1 {
			t.Fatalf("hung helper accepted %d connections; want 1 (single-shot). "+
				"Extra dials mean a loop was reintroduced (#5380)", got)
		}
		// #5881 contract intact: the transport failure is still surfaced
		// (the wrapped sentinel) with (0,0) — nothing confirmed.
		if !errors.Is(res.err, errSessionHelperUnreachable) {
			t.Fatalf("expected the clear-all error to carry errSessionHelperUnreachable "+
				"(the authoritative revocation is unconfirmed), got %v", res.err)
		}
		if res.v4 != 0 || res.v6 != 0 {
			t.Errorf("counts = (%d, %d), want (0, 0) (nothing confirmed)", res.v4, res.v6)
		}
		if mv4, mv6 := m.bpfShim.SessionCount(); mv4 != 1 || mv6 != 1 {
			t.Errorf("mirror count = (%d, %d), want (1, 1) intact — Go sweeps nothing", mv4, mv6)
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("ClearAllSessions did not return within 5s against a hung helper; " +
			"the single clear RPC is not timing out (#5380)")
	}
}
