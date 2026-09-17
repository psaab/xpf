package userspace

import (
	"net"
	"time"
)

// #8526: bound how long m.mu can be held across a control-socket round trip
// once something has asked the daemon to stop.
//
// THE HAZARD. This is a CLASS, not a site. Every *Manager method that takes
// m.mu and then performs a control round trip under it holds the lock for the
// whole round trip — twenty-one of them at the time of writing, including
// UpdatePolicyScheduleState (the site the issue was filed against),
// UpdateRGActive, PublishRouteOverlaySnapshot, ensureProcessLocked, and the
// 1 Hz statusLoop. The count is deliberately not pinned here: an earlier hand
// census said sixteen and was already stale. TestEveryControlCallerHolds-
// TheManagerMutex8526 recomputes the list on every run and logs it.
//
// Every one of them funnels through requestDetailedLocked, whose reachable
// round-trip bound is
//
//	controlBaseDeadline + 64 * controlDeadlinePerMiB = 67s
//
// at the MaxControlRequestBytes ceiling (pinned by
// TestControlDeadlineCapIsUnreachableOnAdmissibleRequests7675), against the
// shipped unit's TimeoutStopSec=20 — a 3.35x overrun.
//
// WHAT ACTUALLY BREAKS. Two stop paths wait on exactly this:
//
//   - Manager.Close / Manager.Teardown take m.mu before stopLocked, so a
//     slow helper blocks the dataplane teardown itself; and
//   - runShutdownSequence calls d.stopPolicySchedulerLoop() early, which
//     ends in an UNBOUNDED d.schedulerWg.Wait(). The goroutine it joins is
//     the policy scheduler, and the scheduler's updateFn is
//     UpdatePolicyScheduleState — the site this issue was filed against. A
//     scheduler tick sitting in a 67s round trip stalls the whole shutdown
//     sequence before FRR stop, RA withdraw, VRRP stop and dp teardown have
//     run at all.
//
// A SIGKILLed xpfd never reaches disableCtrlBeforeTeardownLocked, so the XDP
// shim is left ctrl-enabled redirecting transit to the XSK fds of a helper
// systemd is about to kill with it — transit blackholed until the next start.
//
// WHY THIS IS NOT A LOCK NARROWING, AND MUST NOT BE. The obvious fix —
// release m.mu around the round trip in UpdatePolicyScheduleState — is wrong
// three times over. (1) It fixes one door out of twenty-one; a waiter still
// blocks behind the rest, one of which runs every second. (2) The
// long hold is not incidental: UpdatePolicyScheduleState builds the snapshot
// from manager state, publishes it, and commits m.generation /
// m.lastSnapshot / m.publishedSnapshot and the applied scheduler-state view
// from the SAME critical section.
// Dropping the lock across the publish opens a window where
// m.policySchedulerActive (the applied/show cache) and the helper's live
// snapshot disagree, which is the #3780 stale-permit failure the error return
// exists to prevent. (3) It would make that one site the only unserialized
// control caller.
//
// So nothing here narrows a critical section. m.mu keeps exactly the scope it
// has; what changes is that the I/O performed under it becomes SHORT once a
// stop is in progress. That fixes the whole class at once, because every
// member of it reaches the socket through the same function —
// TestControlDeadlineHasExactlyOneSite8526 asserts there is no other.
//
// LOCK ORDER. ctrlIOMu is a LEAF. Code holding it never acquires m.mu (and
// never blocks: SetDeadline on a net.Conn does not wait for the peer). The
// only legal order is m.mu -> ctrlIOMu, taken by armControlIO /
// releaseControlIO under requestDetailedLocked's caller-held m.mu.
// BeginControlShutdown takes ctrlIOMu ALONE, which is what lets it run while
// a 67s round trip holds m.mu — the whole point.
// TestBeginControlShutdownDoesNotAcquireManagerMutex8526 asserts that.
const (
	// controlShutdownCutover is how long a round trip that is ALREADY IN
	// FLIGHT when the stop begins may still take. It is short because the
	// only thing waiting on it is a teardown: the helper is about to be told
	// to shut down (or killed with us), so a reply that has not arrived by
	// now has no consumer worth the stop budget. It is not zero so a
	// round trip that is a few milliseconds from completing still completes
	// rather than being reported as a spurious failure.
	controlShutdownCutover = 500 * time.Millisecond

	// controlShutdownCeiling caps a round trip STARTED after the stop began.
	// It is deliberately equal to controlBaseDeadline, so it is a NO-OP for
	// every request the teardown itself issues — disable_ctrl, stop_workers,
	// status, shutdown are all far below 1 MiB and already get exactly this
	// deadline. It binds only on a large apply_snapshot that slipped past the
	// daemon's apply fence, which is the residual that would otherwise
	// reintroduce a 67s hold after the cutover above had already run.
	controlShutdownCeiling = controlBaseDeadline
)

// BeginControlShutdown declares that the PROCESS is stopping and bounds the
// control socket accordingly: every round trip in flight right now has its
// deadline pulled in to controlShutdownCutover, and every round trip started
// afterwards is capped at controlShutdownCeiling.
//
// It is idempotent and safe to call from any goroutine, including one that is
// itself about to block on m.mu — it takes only the leaf ctrlIOMu.
//
// THE LATCH IS SCOPED TO A TERMINAL STOP, and that scoping is load-bearing.
// The only caller is runShutdownSequence, at the very top of the daemon
// teardown, ahead of the applySem drain and the schedulerWg join this exists
// to unblock; the process does not come back from there. Manager.Close and
// Manager.Teardown deliberately call cutInFlightControlIO instead, because
// Teardown is NOT terminal: the bootstrap rollback (enterBootstrapMode,
// pkg/daemon/bootstrap.go) tears the dataplane down and KEEPS the object so a
// later confirmed commit re-arms it. A latch set there would cap every
// subsequent apply at controlShutdownCeiling for the life of the daemon,
// re-opening the #4036 false-timeout on the first feed-heavy commit after a
// bootstrap rollback — a fix that is correct on the path it was written for
// and wrong on the one path that reuses the object.
func (m *Manager) BeginControlShutdown() {
	if m == nil {
		return
	}
	m.ctrlIOMu.Lock()
	defer m.ctrlIOMu.Unlock()
	m.ctrlShutdown = true
	m.cutInFlightControlIOLocked()
}

// cutInFlightControlIO pulls in the deadline of every round trip in flight
// WITHOUT latching the ceiling for future ones.
//
// This is what a teardown of the dataplane needs and all it needs: the caller
// is about to block on m.mu, so the round trip holding it has to end, but the
// Manager may still be reused (see the bootstrap-rollback note above) and must
// not be left with a permanently narrowed deadline.
func (m *Manager) cutInFlightControlIO() {
	if m == nil {
		return
	}
	m.ctrlIOMu.Lock()
	defer m.ctrlIOMu.Unlock()
	m.cutInFlightControlIOLocked()
}

// cutInFlightControlIOLocked requires ctrlIOMu.
func (m *Manager) cutInFlightControlIOLocked() {
	cut := time.Now().Add(controlShutdownCutover)
	for conn := range m.ctrlIOConns {
		// Best effort: a conn whose owner has already returned is removed from
		// the set before it is closed (releaseControlIO is deferred AFTER
		// conn.Close, so it runs first), so this cannot race a Close.
		_ = conn.SetDeadline(cut)
	}
}

// armControlIO registers conn for the duration of ONE control round trip and
// sets its deadline, both under ctrlIOMu.
//
// Doing both under the same lock is load-bearing, not tidiness. If the
// deadline were computed here and applied by the caller after the unlock, a
// BeginControlShutdown landing in that window would cut a conn whose owner
// then immediately overwrote the cut with the full scaled deadline — the one
// interleaving where the bound silently does not apply.
func (m *Manager) armControlIO(conn net.Conn, scaled time.Duration) {
	m.ctrlIOMu.Lock()
	defer m.ctrlIOMu.Unlock()
	if m.ctrlIOConns == nil {
		m.ctrlIOConns = make(map[net.Conn]struct{}, 1)
	}
	m.ctrlIOConns[conn] = struct{}{}
	d := scaled
	if m.ctrlShutdown && d > controlShutdownCeiling {
		d = controlShutdownCeiling
	}
	// #9344: record what was actually ARMED. A mutation that severed the
	// call site in requestDetailedLocked — swapping controlWorkDeadline back
	// for controlRoundtripDeadline — survived the whole suite, because the
	// cell that checks the floor calls the sizing FUNCTION and nothing
	// observed what the socket got. This is the seam that makes the wiring
	// checkable without a timing-dependent test.
	m.lastArmedControlDeadline = d
	_ = conn.SetDeadline(time.Now().Add(d))
}

// releaseControlIO unregisters conn when its round trip ends. A conn left in
// the set would be a dangling reference SetDeadline is called on after Close;
// that is harmless (it returns ErrClosed) but the set would grow without
// bound over the daemon's lifetime.
func (m *Manager) releaseControlIO(conn net.Conn) {
	m.ctrlIOMu.Lock()
	delete(m.ctrlIOConns, conn)
	m.ctrlIOMu.Unlock()
}
