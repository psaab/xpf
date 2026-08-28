package userspace

import (
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cilium/ebpf"
)

// ctrlMapUpdater is the subset of *ebpf.Map the manager uses on the
// userspace_ctrl and userspace_bindings maps. *ebpf.Map satisfies it directly;
// tests substitute a fake to inject Lookup/Update/readback faults without a
// privileged BPF map (#5486).
//
// #6994 widened its ROLE, not its method set: `Lookup` + `Update` is already
// everything applyHelperStatusLocked and its five helpers call on either map
// (measured: 4 ctrlMap.Lookup, 7 ctrlMap.Update, 2 bindingsMap.Lookup,
// 6 bindingsMap.Update across the non-test tree), so routing that chain through
// this interface needed no new method and no behavioural change.
type ctrlMapUpdater interface {
	Lookup(key, valueOut interface{}) error
	Update(key, value interface{}, flags ebpf.MapUpdateFlags) error
}

// ctrlMapForDisableLocked returns the ctrl-map accessor used to disable ctrl.
// Production returns the real bpfShim userspace_ctrl map; a test hook can
// override it. Returns nil (a true nil interface, never a typed nil) when the
// shim map is not loaded.
func (m *Manager) ctrlMapForDisableLocked() ctrlMapUpdater {
	if m.disableCtrlMapHook != nil {
		return m.disableCtrlMapHook
	}
	if cm := m.bpfShim.Map(mapNameUserspaceCtrl); cm != nil {
		return cm
	}
	return nil
}

// disableUserspaceCtrlLocked sets ctrl.enabled=0 in the BPF map so the XDP
// shim stops redirecting packets to XSK. This MUST be called before the
// helper exits (or workers/UMEM are torn down) to prevent packets being sent
// to dead socket fds.
//
// It returns an error instead of silently swallowing failures (#5486): a
// stale enabled=1 row with READY bindings keeps the shim redirecting to
// soon-dead XSK fds until heartbeat expiry, so a caller preparing teardown
// MUST learn the gate was not established and fail closed (clear bindings).
func (m *Manager) disableUserspaceCtrlLocked() error {
	ctrlMap := m.ctrlMapForDisableLocked()
	if ctrlMap == nil {
		return fmt.Errorf("userspace: cannot disable ctrl: %s map not loaded", mapNameUserspaceCtrl)
	}
	return disableUserspaceCtrl(ctrlMap)
}

// disableUserspaceCtrl writes ctrl.enabled=0 and verifies the gate took.
//
// On a Lookup failure it does NOT bail out leaving enabled=1: it writes a
// zeroed (Enabled=0) fail-closed row anyway, then returns the read error. The
// Update result is checked (not discarded) and the row is read back to confirm
// Enabled==0 — a silent no-op here would strand transit redirecting to
// soon-dead XSK fds after worker/UMEM teardown.
func disableUserspaceCtrl(ctrlMap ctrlMapUpdater) error {
	zero := uint32(0)
	var ctrl userspaceCtrlValue
	lookupErr := ctrlMap.Lookup(zero, &ctrl)
	if lookupErr != nil {
		// Prior ctrl unreadable — still establish the fail-closed gate with
		// a zeroed ctrl row rather than leaving a stale enabled=1.
		ctrl = userspaceCtrlValue{}
	}
	ctrl.Enabled = 0
	if err := ctrlMap.Update(zero, ctrl, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("userspace: disable ctrl update failed: %w", err)
	}
	// Read back to confirm the disable actually took. A silent write no-op
	// would leave enabled=1 and keep transit redirecting after teardown.
	var verify userspaceCtrlValue
	if err := ctrlMap.Lookup(zero, &verify); err != nil {
		return fmt.Errorf("userspace: disable ctrl readback failed: %w", err)
	}
	if verify.Enabled != 0 {
		return fmt.Errorf("userspace: disable ctrl readback shows enabled=%d, want 0", verify.Enabled)
	}
	if lookupErr != nil {
		slog.Warn("userspace: disabled ctrl via fail-closed fallback (prior ctrl unreadable)", "err", lookupErr)
		return fmt.Errorf("userspace: disable ctrl lookup failed (fail-closed fallback written): %w", lookupErr)
	}
	slog.Info("userspace: disabled ctrl (helper stopping)")
	return nil
}

// disableCtrlBeforeTeardownLocked disables ctrl ahead of stopping workers or
// cycling the link. Teardown cannot abort — the helper is stopping — so if the
// disable cannot be verified, the fail-closed gate is not trustworthy: this
// forcibly clears ALL binding rows (nothing READY for the shim to redirect)
// before the caller proceeds to worker/UMEM teardown, logs the failure, and
// returns the error for callers that surface it (#5486).
func (m *Manager) disableCtrlBeforeTeardownLocked() error {
	if err := m.disableUserspaceCtrlLocked(); err != nil {
		slog.Error("userspace: ctrl disable before teardown failed; clearing all bindings fail-closed", "err", err)
		m.clearAllBindingRowsLocked()
		return err
	}
	return nil
}

// reEnableUserspaceCtrlLocked sets ctrl.enabled=1 in the BPF map.
// Used to rollback a ctrl disable when the subsequent operation fails.
func (m *Manager) reEnableUserspaceCtrlLocked() {
	ctrlMap := m.bpfShim.Map(mapNameUserspaceCtrl)
	if ctrlMap == nil {
		return
	}
	zero := uint32(0)
	var ctrl userspaceCtrlValue
	if err := ctrlMap.Lookup(zero, &ctrl); err != nil {
		return
	}
	ctrl.Enabled = 1
	_ = ctrlMap.Update(zero, ctrl, ebpf.UpdateAny)
	slog.Info("userspace: re-enabled ctrl (rollback)")
}

// DisableAndStopHelper disables ctrl. This prevents the XDP shim from
// redirecting new packets to XSK. Must be called BEFORE any operation that
// invalidates UMEM (e.g. link DOWN on mlx5 zero-copy). Worker threads keep
// running but see no new packets since ctrl=0 stops XSK redirects.
//
// Deprecated: use PrepareLinkCycle which also stops the Rust workers.
func (m *Manager) DisableAndStopHelper() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.proc == nil || m.proc.Process == nil {
		return
	}
	// Teardown path: the wrapper logs and clears bindings fail-closed if the
	// disable cannot be verified; there is no error channel to surface it on.
	_ = m.disableCtrlBeforeTeardownLocked()
}

// linkCycleLeaseTTL bounds the gap between two consecutive TOUCHES of a
// link-cycle lease. Since #6871 round 8 that gap is a CONSTANT — the heartbeat
// period below — so this is an actual bound rather than an estimate.
//
// WHY IT USED TO BE AN ESTIMATE, AND WHY THAT WAS NOT SURVIVABLE. Rounds 6 and 7
// made the daemon renew at three points in step 2.6 (all via
// Daemon.renewLinkCycleLease, pkg/daemon/daemon_apply_dataplane.go):
//
//	programRethMemberMAC        after this member's MAC set
//	finishRethMemberLinkTail    after this member's ethtool + child-netdev loop
//	reconcileAfterRethLinkCycle after the VIP/link-local reconcile, i.e. just
//	                            before NotifyLinkCycle releases the lease
//
// leaving the TTL to cover the gaps between them. Exactly one of those gaps has
// a hard ceiling — the `ethtool -K <if> rxvlan off`, 20s (externalCommandTimeout
// 15s + runCommandStdinTimeout's 5s WaitDelay, pkg/daemon/exec_timeout.go) — and
// round 7 narrowed the claim honestly to "60s is 3x the only bounded term".
//
// That narrowing was honest and still insufficient, because the OTHER terms in
// the same gap scale with operator-controlled cardinality:
//
//   - finishRethMemberLinkTail walks every child netdev of the member
//     (netlink.LinkList filtered by ParentIndex) and per child does a
//     addr_gen_mode sysctl write, a conditional LinkSetHardwareAddr, and
//     rethSubIfaceLinkLocalRepair's address list/add. A member can carry one
//     VLAN sub-interface per VLAN id, so that loop is reachable at ~4094
//     iterations on ONE member — inside the same interval as the 20s ethtool.
//     At 10ms per child it alone is 40s; the interval is over 60s before the
//     second member is reached.
//   - reconcileAfterRethLinkCycle loops over every redundancy group, netlink
//     per group.
//   - the whole loop is over cfg.RethToPhysical(), i.e. up to the schema's
//     reth-count ceiling of 128 (pkg/config/schema_chassis.go).
//   - and netlink has no elapsed-time bound at all: ONE syscall can block
//     indefinitely, which no amount of call-site renewal covers.
//
// A bigger constant is the same defect with a bigger number, so round 8 stopped
// picking one. A live lease now renews ITSELF every linkCycleLeaseHeartbeat from
// a goroutine the lease owns (startLinkCycleHeartbeat), which makes the interval
// the TTL must cover independent of member count, child-netdev count, redundancy
// group count and netlink latency — including the single-blocking-syscall case,
// which the daemon's call-site renewals structurally cannot reach. The TTL is
// now 4x that period.
//
// The three daemon call sites stay. They are no longer load-bearing, and they
// are cheap (RenewLinkCycle refuses to create a lease, so an apply that cycled
// nothing is a no-op); keeping them means a heartbeat that failed to start still
// degrades to round 7's behaviour rather than to no renewal at all.
//
// THE OTHER HALF: A HEARTBEAT KEEPS A LEASE ALIVE, so on its own it would turn a
// leaked lease from a 60s suppression into a permanent one — worse than the race
// it closes. That is why the daemon wraps the whole cycle in a guaranteed
// release: applyDataplaneAndHACore defers AbandonLinkCycle, which runs on every
// exit from the apply including a panic and any early return added later. The
// two are a package and neither is correct alone. What remains is a caller
// BLOCKED forever inside the cycle — and there, holding is the right answer: the
// workers really are joined and reconciling really would be wrong.
//
// WHAT THE TTL DOES NOT COVER, stated first because an earlier revision of this
// paragraph had it exactly backwards (#6871 round 13). It said the TTL "covers
// exactly one residual: a lease acquired outside that deferred extent". It
// covers that residual not at all. acquireLinkCycleLease starts the heartbeat
// unconditionally, wherever it is called from, and the heartbeat re-arms the
// deadline every 15s for as long as the word is non-zero — so a lease taken
// outside the daemon's deferred abandon is precisely the lease the TTL can never
// reach. It renews itself until the process exits.
//
// That is not a footnote. It means the two guards below are not a supplement to
// a TTL backstop, they are the ONLY thing standing between a second acquisition
// site and a permanently suppressed reconcile loop, and a reader who believes
// the TTL will eventually clean up after a leaked acquisition will under-weight
// exactly the check that matters. In link_cycle_acquisition_site_6871_test.go:
//
//	TestLinkCycleLeaseHasExactlyOneAcquisitionSite_6871  tree-wide: every
//	    production CALL of PrepareLinkCycle must be on an allowlist, because
//	    LinkController lives in pkg/dataplane and any package can hold one
//	TestLinkCycleLeaseIsAcquiredOnlyByPrepare_6871       in-package:
//	    acquireLinkCycleLease is unexported, so anything in package userspace
//	    could take a lease WITHOUT going through PrepareLinkCycle and inherit
//	    none of the daemon's deferred release
//
// Both also reject a reference that is not a CALL — a method value can be stored
// and invoked from anywhere later, so no enclosing declaration bounds it, and
// keying one by its neighbours was itself a measured escape (#6871 round 13).
//
// #6871 round 9 (F2): this paragraph previously named the first of those as
// existing enforcement, and it did not exist — the only match for the name in
// the tree was this comment. The factual claim was true and the guard was
// absent, which is the worse of the two failures: it is the reason the next
// reader does not add the check.
//
// WHAT THE TTL DOES COVER is a heartbeat that is alive but STARVED: four missed
// beats — a GC pause, a saturated box, a goroutine that does not get scheduled —
// which is the margin the 4x above is chosen for. That case stays bounded and
// loud rather than silent: linkCycleInFlight logs a Warn under the CAS when it
// retires an expired lease, and the state it degrades to is master's — the
// pre-#6871 behaviour where the tick was never suppressed at all. An overrun
// loses the added protection for the tail of that cycle; it does not introduce a
// new failure mode.
const linkCycleLeaseTTL = 60 * time.Second

// linkCycleLeaseHeartbeat is the period at which a live lease renews itself, and
// it is the quantity linkCycleLeaseTTL is 4x of. It is a constant BECAUSE that
// is the whole point: every candidate for "how long can one step of step 2.6
// take" is operator-controlled (see the cardinality list above), so the lease
// stops asking and re-arms on a timer instead.
//
// 4x leaves room for three consecutive missed beats — a fully saturated box, a
// GC pause, a descheduled goroutine — before the backstop fires.
const linkCycleLeaseHeartbeat = linkCycleLeaseTTL / 4

// linkCycleHeartbeatTicker produces the beat channel and its stop. Indirected so
// a test can drive beats synchronously instead of waiting out 15s of wall clock.
// Production never reassigns it. Mirrors linkCycleLeaseElapsed above.
var linkCycleHeartbeatTicker = func() (<-chan time.Time, func()) {
	t := time.NewTicker(linkCycleLeaseHeartbeat)
	return t.C, t.Stop
}

// linkCycleHeartbeat is the per-Manager state of the lease's self-renewal
// goroutine. Zero value = not beating.
type linkCycleHeartbeat struct {
	mu   sync.Mutex
	stop chan struct{}
	done chan struct{}
}

// startLinkCycleHeartbeat begins renewing a lease that has just been taken.
//
// Idempotent: a second acquire with a beat already running re-arms the DEADLINE
// (the caller stored it) without stacking a second goroutine. The running
// heartbeat renews whichever lease is live, so one goroutine serves every
// acquisition between a start and its release.
//
// #6871 (round 9, F1): the loop has EXACTLY ONE exit, and that is load-bearing
// rather than tidiness. Round 8 added a second — a self-reap when the lease word
// read 0 — which returned without clearing linkCycleHB.stop/done. The early
// return above tests that FIELD, not goroutine liveness, so one reap left the
// field non-nil with nothing running and every later acquireLinkCycleLease in the
// same apply silently started no heartbeat: every RETH member cycled after that
// point ran on round-7 protection, which the TTL block above argues is not
// survivable at operator-controlled cardinality.
//
// The trigger was the case this whole round is built around. The word reaches 0
// two ways: releaseLinkCycleLease, which stops the heartbeat first so no reap can
// follow it, and linkCycleInFlight's backstop CAS after four missed beats —
// exactly the starvation the 4x TTL margin exists to absorb.
//
// Clearing the fields inside the reap was the other candidate fix and is
// rejected: the goroutine would be clearing state it no longer owns. A release
// plus a fresh acquire can install a NEW stop/done between the reap's decision
// and its lock, and the dying goroutine would then clear its successor's fields,
// orphaning a live heartbeat and letting a third acquire stack a second one.
// Making that safe needs an identity check; having one exit needs nothing.
//
// The cost of no reap is one atomic load per beat on a retired lease, until the
// release that is guaranteed by the daemon's deferred AbandonLinkCycle. That is
// the entire price, and it buys an invariant a reader can check by looking:
// while linkCycleHB.stop is non-nil, a goroutine is receiving.
func (m *Manager) startLinkCycleHeartbeat() {
	m.linkCycleHB.mu.Lock()
	defer m.linkCycleHB.mu.Unlock()
	if m.linkCycleHB.stop != nil {
		return
	}
	stop := make(chan struct{})
	done := make(chan struct{})
	m.linkCycleHB.stop, m.linkCycleHB.done = stop, done
	beats, cancel := linkCycleHeartbeatTicker()
	go func() {
		defer close(done)
		defer cancel()
		for {
			select {
			case <-stop:
				return
			case <-beats:
				// A beat with no lease held is a no-op by construction:
				// RenewLinkCycle never CASes from the 0 sentinel.
				m.RenewLinkCycle()
			}
		}
	}()
}

// stopLinkCycleHeartbeat ends the renewal goroutine and WAITS for it, so a
// released lease can never be extended by a beat still in flight.
//
// The wait cannot deadlock against m.mu: the goroutine's only call is
// RenewLinkCycle, which touches nothing but the atomic lease word. That is why
// the heartbeat has its own mutex rather than reusing m.mu — the release site
// (NotifyLinkCycle) holds m.mu across this call.
func (m *Manager) stopLinkCycleHeartbeat() {
	m.linkCycleHB.mu.Lock()
	stop, done := m.linkCycleHB.stop, m.linkCycleHB.done
	m.linkCycleHB.stop, m.linkCycleHB.done = nil, nil
	m.linkCycleHB.mu.Unlock()
	if stop == nil {
		return
	}
	close(stop)
	<-done
}

// linkCycleLeaseEpoch is the process-lifetime reference the lease deadline is
// measured from. It is captured once and never reassigned, so
// time.Since(linkCycleLeaseEpoch) reads Go's MONOTONIC clock (a time.Time
// carrying a monotonic reading subtracts monotonically) and is immune to
// wall-clock steps.
//
// #6871 (round 6): the deadline was previously stored as
// time.Now().Add(TTL).UnixNano() and compared against another UnixNano — both of
// which STRIP the monotonic reading and leave a pure wall-clock comparison. A
// step is not hypothetical on this appliance: it runs chrony, and a first sync
// after boot can move the wall clock by minutes. A forward correction larger
// than the TTL expires a one-second-old lease and re-opens the worker-restart
// race the lease exists to close; a backward one strands the lease until the
// clock catches up.
var linkCycleLeaseEpoch = time.Now()

// linkCycleLeaseElapsedOverride is the test seam behind linkCycleLeaseElapsed
// below: a test installs a fake clock here so it can prove the TTL backstop
// really does expire a stranded lease, without sleeping one out. Production
// never installs one. Mirrors linkCycleRebindSleep below.
//
// #6871 round 11: this comment opened "linkCycleLeaseElapsed reports monotonic
// time since linkCycleLeaseEpoch" — the doc of the func VAR of that name, which
// round 10 split into this variable plus the function below. The prose stayed
// attached to the variable and kept the old subject, so `go doc -u` printed the
// function's description under the seam and showed the function itself
// undocumented. Third instance of the same insertion-and-refactor-steals-the-doc
// class as round 10's F3 (prose) and this round's N3 (a comment paragraph in the
// wrong branch), and the first of the three found by looking rather than by
// review.
//
// #6871 round 10 (F1): ATOMIC, because a plain func var is data-raced by a
// leaked heartbeat.
//
// A test that takes a real lease and does not release it leaves a heartbeat
// goroutine running on the production 15s ticker. Once a package run exceeds
// 15s — this one takes 38-56s — that orphan beats, calls RenewLinkCycle, and
// READS this seam from its own goroutine, while a later test WRITES it. `go
// test -race` reported exactly that, from three different leak sites.
//
// The seam is made race-free rather than the leaks chased one by one. This
// package's tests hold 42 non-comment acquireLinkCycleLease() / PrepareLinkCycle(
// call lines (`grep -nE 'acquireLinkCycleLease\(\)|PrepareLinkCycle\(' *_test.go`
// minus the six whose line is a comment), and the next one added would reopen the
// hole in the VARIABLE, and an atomic override cannot be raced there by any of
// them. Releasing is still the right hygiene —
// newLinkCycleProcessOnlyManager does it centrally.
//
// #6871 round 12: that count read "twenty", which no rule over these files
// yields; it is 42 by the grep above. The number is load-bearing here — it is
// the argument for fixing the seam instead of the sites — so it is stated with
// the command that reproduces it rather than from memory.
//
// #6871 round 11: that is the whole of the guarantee, and both the round-10
// commit message ("a leaked heartbeat now renews its own dead Manager and races
// nothing") and an earlier revision of this comment ("cannot be raced by any of
// them", unqualified) claimed more. THE ATOMIC PROTECTS THE POINTER, NOT WHAT
// IT POINTS AT. A leaked beat does not merely renew a dead Manager: reaching
// linkCycleLeaseElapsed at all means it CALLS the override installed at that
// instant, from its own goroutine. Every closure a test installs is therefore
// shared state, and anything it captures mutably must be atomic in its own
// right. fakeLinkCycleClock's counter already was; injectAtLeaseExpiryCheck's
// one-shot flag was a plain bool, and `go test -race` reported a genuine data
// race on it — read through this function, previous write through this function
// from startLinkCycleHeartbeat.func1. Fixed there, in
// link_cycle_lease_race_6871_test.go, which also records what the fix does and
// does not buy.
//
// So: install-and-read of the override never races, which is what this variable
// owes. Closure captures are the caller's obligation, which is what the round-10
// claim silently annexed.
//
// #6871 round 12: there is a SECOND caller obligation, and it is not about
// races. A leaked beat calling an installed closure can also perform work the
// closure meant for its installer — injectAtLeaseExpiryCheck's one-shot was
// consumable by any goroutine, and a stolen injection made its cells pass
// VACUOUSLY (measured: ~24% of accelerated iterations with the B1 fix reverted,
// i.e. with the cell obliged to fail). A closure whose effect depends on WHERE
// in a reader it runs must gate on the calling goroutine; the atomic makes that
// gate safe, it does not supply it.
//
// A red -race run in this package is not automatically this. It also contains
// load-sensitive DEADLINE tests — TestLargeApplySnapshotDoesNotFalseTimeout and
// TestEventStreamRawDataplaneEventsFeedSyslogFanout — which fail under load
// because a wall-clock budget was missed, and are not races. Round 10 was right
// to retract the round-9 claim that the observed races WERE that class; it does
// not follow that the class is empty. Read the report: a race names two
// goroutines and two accesses, a blown deadline names neither.
//
// Production never installs an override, so the hot path is one atomic load
// returning nil plus the same time.Since it always did.
var linkCycleLeaseElapsedOverride atomic.Pointer[func() time.Duration]

// linkCycleLeaseElapsed reports monotonic time since linkCycleLeaseEpoch — or
// whatever a test has installed in linkCycleLeaseElapsedOverride above, which
// is where the seam's contract is stated.
func linkCycleLeaseElapsed() time.Duration {
	if fn := linkCycleLeaseElapsedOverride.Load(); fn != nil {
		return (*fn)()
	}
	return time.Since(linkCycleLeaseEpoch)
}

// linkCycleLeaseDeadline is the value stored in linkCycleLeaseUntil for a lease
// taken or renewed now. It is monotonic nanoseconds since linkCycleLeaseEpoch,
// and is never 0 (elapsed is non-negative and the TTL is positive), so the 0
// sentinel that means "no lease" stays unambiguous.
func linkCycleLeaseDeadline() int64 {
	return int64(linkCycleLeaseElapsed() + linkCycleLeaseTTL)
}

// acquireLinkCycleLease opens the #6871 lease. Callers hold m.mu, but the lease
// deliberately does not depend on it — it is read by the status loop from
// outside m.mu's protection of the window it covers.
//
// It also starts the round-8 heartbeat, so the deadline is re-armed on a fixed
// period for as long as the cycle runs. Store FIRST, then start: the heartbeat
// refuses to renew from the 0 sentinel, so a beat that somehow ran before the
// store would be a no-op and the lease would never open.
func (m *Manager) acquireLinkCycleLease() {
	m.linkCycleLeaseUntil.Store(linkCycleLeaseDeadline())
	m.startLinkCycleHeartbeat()
}

// RenewLinkCycle pushes a lease that is ALREADY held out by another full TTL. It
// is what makes the TTL a per-member bound instead of a whole-cycle guess: the
// daemon calls it once per member of step 2.6's rethToPhys loop (from
// programRethMemberMAC), so the deadline tracks the sequence's actual progress
// rather than a wall-clock estimate of its total length (#6871 round 6).
//
// It never creates a lease FROM THE 0 SENTINEL, and it never resurrects one that
// has already been retired to 0. That is the property that matters: a renewal
// that could open a lease would let any caller suppress the 1 Hz reconcile with
// no cycle in flight and nothing obliged to release it — the daemon's loop runs
// on every RETH apply, the vast majority of which never cycle a link at all. The
// load/CAS pair is what keeps it true against a concurrent release:
// linkCycleInFlight below is checked first (which also self-heals an
// already-expired deadline by CASing it to 0), and the CAS then re-reads and
// fails rather than resurrecting a lease NotifyLinkCycle released in between.
//
// #6871 (round 7): "NEVER renews an expired lease" is stronger than the code and
// an earlier revision claimed it. A renewal can pass the linkCycleInFlight check
// while the lease is live, be descheduled past the deadline, and then CAS a
// still-nonzero — and by then expired — deadline forward, because no reader
// happened to observe the expiry and retire it to 0 in the interim. What is true
// is narrower and still sufficient: the call BEGAN while a cycle genuinely owned
// the dataplane, so it extends a real cycle rather than conjuring a phantom one,
// and the overshoot is bounded by the deschedule window rather than unbounded.
//
// Renewing an unexpired lease that is already further out than the new deadline
// is a no-op, so the ordering of renew against a fresh acquire does not matter.
func (m *Manager) RenewLinkCycle() {
	if !m.linkCycleInFlight() {
		return
	}
	want := linkCycleLeaseDeadline()
	for {
		until := m.linkCycleLeaseUntil.Load()
		if until == 0 || until >= want {
			return
		}
		if m.linkCycleLeaseUntil.CompareAndSwap(until, want) {
			return
		}
	}
}

// releaseLinkCycleLease ends the lease. Idempotent in EFFECT — the release site
// runs unconditionally at the top of NotifyLinkCycle's critical section, so a
// second call, or a call with no lease held, leaves the same state behind.
//
// Not a no-op, though, and an earlier revision said it was (#6871 round 13). The
// two halves of a lease are retired by different writers and can be out of step:
// linkCycleInFlight's backstop CAS clears the WORD while deliberately leaving the
// heartbeat goroutine running (see startLinkCycleHeartbeat on why the reap was
// removed). A release arriving in that state finds Load()==0 and still does real
// work — it stops and JOINS the heartbeat. That is the point: "no lease" and
// "nothing is still beating for it" are not the same condition, and this is the
// only thing that makes them one.
//
// Heartbeat FIRST, then the word. Ordering is not load-bearing either way —
// RenewLinkCycle refuses to renew from the 0 sentinel, so a beat racing the
// clear cannot resurrect anything — but stopping first means the goroutine is
// already joined when the word goes to 0, which keeps "released" and "nothing is
// still touching this lease" the same instant.
func (m *Manager) releaseLinkCycleLease() {
	m.stopLinkCycleHeartbeat()
	m.linkCycleLeaseUntil.Store(0)
}

// AbandonLinkCycle drops a lease that is still held when the apply that took it
// is leaving, and reports whether there was one. It is the OTHER half of the
// round-8 heartbeat, and neither half is correct alone.
//
// The heartbeat renews a live lease forever, which is exactly right while the
// cycle runs and exactly wrong once its owner is gone: without a guaranteed
// release, a leaked lease would suppress the 1 Hz reconcile permanently rather
// than for one TTL — strictly worse than what the lease exists to prevent. The
// daemon therefore defers this over the whole extent that can take a lease
// (applyDataplaneAndHACore), so it runs on every exit including a panic and any
// early return a later change introduces.
//
// It does NOT rebind. The rebind has two owners already — step 2.6b2 for a
// completed cycle and programRethMACWithWorkerJoin for an aborted one — and
// firing a third would be the double rebind that gets EBUSY on mlx5 zero-copy
// queues. Dropping the lease hands the helper back to the 1 Hz reconcile, which
// is master's behaviour: the leak degrades to the status quo ante rather than to
// a frozen dataplane.
//
// HOW LONG THAT TAKES, stated because an earlier revision implied one tick
// (#6871 round 9, F6). What resumes within a tick is the RECONCILE — the gate at
// the top of the status loop stops suppressing it, so ctrl re-enable via
// applyHelperStatusLocked is available on the next pass, ~1s. Restoring
// FORWARDING is slower and depends on which producer fires. The busy-binding
// auto-rebind is the one that recreates workers, and
// shouldAutoRebindBusyBindingsLocked (maps_sync.go) gates it three ways: the
// wedge must have been observed for >= 5s, rebinds are rate-limited to one per
// 15s, and hasBusyBindingsWedgeLocked additionally requires
// lastStatus.ForwardingArmed. So the honest figure is SECONDS, not one tick, and
// on an unlucky ordering more than five of them.
//
// That is acceptable for what this is — a path taken only when a code path
// leaked a lease, i.e. a bug — but it is not a fast recovery and must not be
// described as one. The timing is not bound by a test: it is a multi-producer
// property of the status loop against a live helper, and the map-free fixtures
// this suite is built on cannot reach it. What IS bound is the half that
// matters here, that the abandon un-suppresses the reconcile at all.
//
// A true return means a code path took a lease and did not release it, which is
// a bug in that path rather than an expected outcome — the caller logs it.
func (m *Manager) AbandonLinkCycle() bool {
	held := m.linkCycleLeaseUntil.Load() != 0
	m.releaseLinkCycleLease()
	return held
}

// linkCycleInFlight reports whether a RETH MAC link cycle currently owns the
// dataplane. It self-heals a stranded lease past linkCycleLeaseTTL: the CAS
// clears the deadline so the wedge cannot recur every tick, and the tick that
// observes the expiry resumes reconciling immediately.
//
// #6871 (round 8): the expiry branch RE-READS on a lost CAS instead of reporting
// the expiry it failed to commit, and that is a correctness fix, not tidying.
//
// FOUR writers touch this word: this expiry CAS, RenewLinkCycle's CAS,
// acquireLinkCycleLease's Store, and releaseLinkCycleLease's Store(0) — which an
// earlier revision omitted while listing its outcome in the table below, so the
// count and the table contradicted each other (#6871 round 13). Any of the other
// three can land between the Load above and the CAS below, and when one does,
// the CAS FAILS — the word no longer holds the value that was read. The previous
// form returned false anyway:
//
//	if m.linkCycleLeaseUntil.CompareAndSwap(until, 0) { warn }
//	return false                     // CAS result discarded
//
// A failed CAS means the word MOVED, and the value it moved to is the one that
// decides the answer:
//
//	moved to 0            a concurrent release retired it   -> no cycle (false)
//	moved further out     a renewal extended a live cycle   -> IN FLIGHT (true)
//	moved to a new lease  a fresh PrepareLinkCycle          -> IN FLIGHT (true)
//
// Two of those three read the opposite way from the discarded expiry, so the old
// form unlatched the guard for the remainder of a cycle that was live — the 1 Hz
// tick then respawns AF_XDP workers, re-enables ctrl, or republishes bindings
// into a NIC whose queues that cycle is about to destroy. The renewal case is
// the sharp one: a renewal landing on the expiry instant is precisely what
// renewal is FOR, so the mechanism added to strengthen the lease was the one
// most likely to defeat it.
//
// The loop terminates for the standard lock-free reason: an iteration either
// returns or its CAS lost, and a lost CAS means another writer committed a
// change. Same shape as RenewLinkCycle's loop directly above.
func (m *Manager) linkCycleInFlight() bool {
	for {
		until := m.linkCycleLeaseUntil.Load()
		if until == 0 {
			return false
		}
		if int64(linkCycleLeaseElapsed()) < until {
			return true
		}
		// Expired as read. Report "no cycle" only if THIS goroutine is the one
		// that retired it; otherwise re-read and judge the new value.
		if m.linkCycleLeaseUntil.CompareAndSwap(until, 0) {
			slog.Warn("userspace: link-cycle lease expired without a rebind; resuming reconcile",
				"ttl", linkCycleLeaseTTL)
			return false
		}
	}
}

// PrepareLinkCycle must be called BEFORE any link DOWN/UP cycle (e.g. RETH
// MAC programming). It:
//  1. Disables ctrl so the XDP shim stops redirecting to XSK
//  2. Leaves the userspace shim attached with transit fail-closed
//  3. Sends "stop_workers" to the Rust helper, which joins all worker
//     threads — so no thread touches UMEM after a SUCCESSFUL return. That
//     qualifier is the contract (#6871 round 13): if the request fails this
//     function returns an error with the workers possibly still running, which
//     is exactly why the error is returned rather than logged, and why the
//     caller must not cycle the link on it
//  4. Takes the #6871 link-cycle lease, which holds that join across the
//     window where m.mu is NOT held (see below). The daemon renews it once per
//     RETH member (RenewLinkCycle), so the lease tracks the loop's progress
//     rather than a wall-clock guess at its total length.
//
// The caller then performs the link DOWN/UP. Afterwards, NotifyLinkCycle
// sends "rebind" to recreate workers with fresh AF_XDP sockets.
//
// #6871: the join alone is a MOMENT, not a barrier. This function releases m.mu
// on return, and the daemon does not reach setDown until several netlink calls
// later — so every other holder of m.mu runs in between. The 1 Hz status tick
// alone restarts the workers four different ways in that window:
//
//   - syncSnapshotLocked's plan-key branch stopLocked()s and respawns the whole
//     HELPER PROCESS (process_status.go);
//   - retryDeferredWorkerArmLocked republishes with DeferWorkers=false to settle
//     a #5134 debt (manager_worker_arm_5134.go);
//   - maybeAutoRebindBusyBindingsLocked sends "rebind" directly — the exact
//     inverse of the stop_workers just issued (maps_sync.go);
//   - applyHelperStatusLocked re-enables ctrl, pointing the shim at XSK sockets
//     whose queues the cycle is about to destroy (maps_sync.go).
//
// stop_workers keeps registered bindings and forwarding_armed, so the helper's
// same-plan predicate sees runnable-but-not-live bindings and restarts workers
// on any of those. The lease makes the tick skip its whole body while a cycle
// owns the dataplane, and gates the ctrl re-enable at its source so the
// non-tick callers of applyHelperStatusLocked (UpdateRGActive, driven by VRRP
// events and by reconcileRGStateLoop's 2s pass, which is NOT serialized on the
// daemon's applySem) cannot re-enable it either.
//
// The operator worker-affecting verbs are the sixth producer and are gated at
// their own entry points rather than here — see errLinkCycleInFlight in
// manager_status.go for why the gate cannot live in requestLocked.
//
// The SEVENTH is the daemon's own 500ms HA watchdog heartbeat, and it is the one
// that shows why enumerating callers is not enough: UpdateHAWatchdog runs on its
// own goroutine with no applySem, and its first/change/backstop branch ends in
// syncDesiredForwardingStateLocked, which sends the same worker-respawning
// set_forwarding_state the operator verbs do. That gate lives at the emitter
// (manager_ha.go) rather than at UpdateHAWatchdog, so it also covers the tick's
// and the compile path's calls — see the comment there for why the watchdog's
// update_ha_state half is deliberately NOT suppressed (#6871 round 6).
func (m *Manager) PrepareLinkCycle() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.proc == nil || m.proc.Process == nil {
		// No helper running: there are no workers to join, so a link cycle
		// cannot race one. This is a genuine success, not a swallowed
		// failure. No lease either — there is nothing for it to protect, and
		// taking one would suppress the reconcile for no reason.
		return nil
	}
	// Take the lease BEFORE the first mutation of dataplane state. The window
	// that needs covering opens at the ctrl disable, not at the successful
	// join: disableCtrlBeforeTeardownLocked can clear every binding row
	// fail-closed and then stop_workers can still fail, and a tick landing in
	// THAT state would repopulate the rows it just cleared.
	m.acquireLinkCycleLease()
	// Disable ctrl BEFORE stopping workers. If the disable cannot be
	// verified the wrapper clears all bindings fail-closed so the shim has
	// no READY slot to redirect to while the workers are being joined.
	//
	// #5103: the ctrl-disable error is CAPTURED rather than acted on here (see
	// the scope note at the return — it is deliberately NOT folded into this
	// function's error). Above all it must NOT short-circuit the worker join
	// below — the join is the half that makes UMEM safe to unmap, and skipping
	// it on a ctrl-disable failure would leave workers running through the very
	// link cycle this function exists to protect. The wrapper has already
	// cleared all binding rows fail-closed, so the shim has nothing READY to
	// redirect into while the join proceeds.
	ctrlErr := m.disableCtrlBeforeTeardownLocked()
	// Tell the Rust helper to stop all workers. This joins worker
	// threads so they stop touching UMEM before the NIC unmaps pages
	// during link DOWN.
	var status ProcessStatus
	if err := m.requestLocked(ControlRequest{Type: "stop_workers"}, &status); err != nil {
		// #5103: previously a Warn + bare return, which the void signature
		// made invisible. A failed join means worker threads may still be
		// touching UMEM, so the link MUST NOT be cycled.
		slog.Error("userspace: stop_workers before link cycle failed; link cycle must not proceed",
			"err", err)
		return fmt.Errorf("userspace: stop_workers before link cycle: %w", err)
	}
	slog.Info("userspace: workers stopped before link cycle",
		"bindings", len(status.Bindings))
	// SCOPE of the error contract, deliberately narrow: it reports whether the
	// WORKER JOIN succeeded, and nothing else. ctrlErr is logged (loudly, by
	// disableCtrlBeforeTeardownLocked) and its own failure path has already
	// cleared every binding row fail-closed, so the shim has nothing READY to
	// redirect into — but it is NOT folded into the return.
	//
	// Propagating it was tried and is wrong: "userspace_ctrl map not loaded" is
	// a legitimate state (no shim attached), and in that state there is no
	// redirect path for the gate to protect. Failing there would block RETH MAC
	// programming on a healthy deployment — an over-rejection in place of the
	// under-rejection this change exists to fix. The caller's decision hinges
	// on whether threads can still touch UMEM, which is exactly the join.
	_ = ctrlErr
	return nil
}

var linkCycleRebindSleep = time.Sleep

// NotifyLinkCycle tells the userspace helper to rebind all AF_XDP sockets.
// In mlx5 (and other drivers), a link DOWN/UP cycle destroys the kernel-side
// XSK receive queue.  The sockets remain open but no longer receive packets.
// This is called after programRethMAC which takes RETH interfaces DOWN/UP.
//
// PrepareLinkCycle should have been called BEFORE the link cycle to stop
// workers (so they don't access UMEM during link DOWN). This method
// waits 1s for NIC reinitialization then sends "rebind" to recreate
// workers with fresh AF_XDP sockets.
//
// The 1s delay lets the mlx5 NIC fully reinitialize its UMR (User
// Memory Region) subsystem after link reactivation. Without this, the
// NIC's UMR WQE queue overflows when all XSK sockets are recreated
// simultaneously (rx_xsk_congst_umr), causing UMEM pages to not be mapped
// and packets to be silently dropped despite successful XDP_REDIRECT.
//
// #6871: it returns an error, for the same reason PrepareLinkCycle does, and
// with the same deliberately narrow scope — it reports whether the REBIND
// landed, and nothing else (see the scope note at the status apply). This is the
// designated inverse of "stop_workers" and the daemon uses it BOTH to complete a
// cycle and to unwind an aborted one, but a failed rebind used to be a slog.Warn
// and a bare return on a void function, so a clean cycle whose rebind failed left
// every worker stopped WHILE THE COMMIT REPORTED SUCCESS: a silent total
// dataplane outage on that node. The error return is what makes the daemon's
// "this path owns its own rollback" claim true rather than attempted;
// programRethMACWithWorkerJoin folds it into the same errRethPrepareLinkCycle
// class as a failed join, and step 2.6b2 folds it into the commit error.
//
// It also ends the link-cycle lease, unconditionally, at the top of its critical
// section — see the release site for why that is both the earliest and the
// latest correct point.
func (m *Manager) NotifyLinkCycle() error {
	return m.notifyLinkCycle(true)
}

// NotifyLinkCycleKeepingLease is NotifyLinkCycle's repair WITHOUT the release
// (#7007).
//
// The two acts were fused, and on a multi-member RETH apply that fusion is a
// bug: acquire is per MEMBER (each member's PrepareLinkCycle, inside the loop)
// while release was per REPAIR, so an aborted member's in-loop rollback ended a
// lease a DIFFERENT, already-cycled member still depended on. Everything after
// it — the remaining members' tails and all three renewal sites — ran against a
// zeroed word, because RenewLinkCycle refuses the 0 sentinel.
//
// The aborted member still has to rebind: its own workers are joined and its
// ctrl is off, and nothing else will undo that. What it must not do is end the
// APPLY's lease to do it. This is the call that separates the two, and the
// apply-wide site (step 2.6b2, outside the loop) is what releases.
//
// NOT a refcount, deliberately — see docs/reth-mac.md. Acquires and releases do
// not pair: two members both cycling is two acquires and ONE release, so a
// refcount would sit at 1 on the most ordinary multi-member commit, strand the
// lease to the deferred abandon, and make that backstop's ERROR routine noise.
func (m *Manager) NotifyLinkCycleKeepingLease() error {
	return m.notifyLinkCycle(false)
}

func (m *Manager) notifyLinkCycle(release bool) error {
	// Let the NIC fully tear down XSK zero-copy contexts before recreating
	// sockets. mlx5 releases zero-copy queue resources asynchronously after
	// socket close — binding a new socket to the same queue before teardown
	// completes returns EBUSY. 1s gives the driver ample time.
	//
	// The lease is still held across this sleep. That is the point: m.mu is NOT
	// held here, so without it the tick would have a full second of open season
	// on a helper whose workers are joined and whose sockets are dead.
	linkCycleRebindSleep(1 * time.Second)

	m.mu.Lock()
	defer m.mu.Unlock()
	// End the lease here, FIRST, and unconditionally.
	//
	// Earliest correct point: from this line on we hold m.mu for the rest of the
	// function, so no other producer can interleave anyway — the lease exists
	// only to cover the window where m.mu is NOT held, and that window just
	// closed. Releasing here (rather than at the end) also keeps the ctrl gate in
	// applyHelperStatusLocked out of the way of our own post-rebind status apply,
	// so a completed cycle re-enables ctrl on this call instead of costing an
	// extra tick of fail-closed transit.
	//
	// Latest correct point: it precedes every `return` below, including the
	// no-helper early return and the rebind failure. A release placed after any
	// of those would strand the lease on exactly the paths where forwarding is
	// already down, adding a frozen reconcile loop on top of an outage that is
	// already in progress.
	//
	// For HOW LONG is not "until the TTL backstop fires", and an earlier revision
	// said it was (#6871 round 13). Two things are wrong with that. The daemon
	// defers abandonLinkCycleLease over the whole apply, so a lease stranded on
	// one of these returns is dropped when applyDataplaneAndHACore returns — much
	// sooner than 60s. And the TTL could not have fired first anyway: the
	// heartbeat re-arms the deadline every 15s for as long as the word is
	// non-zero, so inside that extent expiry is not the mechanism that ends
	// anything. The backstop is for a STARVED heartbeat, not for a missed
	// release.
	if release {
		m.releaseLinkCycleLease()
	} else {
		// #7007: the lease deliberately survives this repair. Renew it, so the
		// rebind's own duration cannot be what expires it — a repair that took
		// longer than the TTL would otherwise hand the reconcile loop a window
		// mid-apply, which is the thing the lease exists to prevent.
		m.RenewLinkCycle()
	}
	if m.proc == nil || m.proc.Process == nil {
		return nil
	}
	// Ensure ctrl is disabled (PrepareLinkCycle should have done this,
	// but guard against callers that skip it). The subsequent rebind
	// re-establishes ctrl; a fail-closed binding clear here is safe because
	// applyHelperStatusLocked below repopulates the binding rows.
	_ = m.disableCtrlBeforeTeardownLocked()
	// Reset the ctrl enable gate so the fill-ring bootstrap delay
	// restarts from scratch after rebind.  Without this, ctrl stays
	// enabled while the new bindings aren't ready — packets redirected
	// to dead XSK sockets are silently dropped (cold-start blackout).
	//
	// Preserve ctrlEnableAt across rebinds: the hard timeout should
	// count from the FIRST prewarm, not restart on every link cycle.
	// Otherwise repeated rebinds (e.g. RETH MAC programming) keep
	// pushing the hard timeout forward and ctrl never enables.
	m.neighborsPrewarmed = false
	// Reset liveness state so the XSK probe runs fresh after rebind.
	// The old probe result is stale — the link cycle destroyed the
	// previous XSK sockets and the new ones need re-validation.
	m.xskLivenessProven = false
	m.xskLivenessFailed = false
	m.xskProbeStart = time.Time{}
	m.lastXSKRX = 0

	var status ProcessStatus
	if err := m.requestLocked(ControlRequest{Type: "rebind"}, &status); err != nil {
		// #6871: was a Warn and a bare return. The workers are joined and ctrl
		// is off at this point, so a rebind that does not land leaves this node
		// forwarding nothing — and the void signature made that indistinguishable
		// from a successful rebind to the one caller that reports the commit.
		slog.Error("userspace: rebind after link cycle failed; workers stay stopped",
			"err", err)
		return fmt.Errorf("userspace: rebind after link cycle: %w", err)
	}
	// SCOPE of the error contract, deliberately narrow and mirroring
	// PrepareLinkCycle's: this function reports whether the REBIND landed, and
	// nothing else. The status apply is logged but NOT folded in.
	//
	// Folding it was tried and is wrong for the same reason PrepareLinkCycle
	// does not fold its ctrl-disable error: applyHelperStatusLocked fails with
	// "userspace_ctrl map not loaded" whenever no shim is attached, which is a
	// legitimate state, and in that state there is no redirect path for the
	// binding rows to matter to. Returning there would fail a commit on a
	// healthy deployment — an over-rejection in place of the under-rejection
	// this change exists to fix. The caller's decision hinges on one thing:
	// whether the workers stop_workers joined are running again, which is
	// exactly the rebind.
	if err := m.applyHelperStatusLocked(&status); err != nil {
		slog.Warn("userspace: helper status apply after link-cycle rebind failed", "err", err)
	}
	// #2079 r11: the deferred apply (DeferWorkers) skipped the appliedSnapshot
	// capture because the helper had not reconciled its forwarding state. The
	// rebind above reconciles the bindings (and swaps the coordinator
	// forwarding state to the applied generation), so NOW record the applied
	// snapshot — its config + generation are coherent with the NAT pool
	// counters the helper will report. m.deferWorkers is cleared by the daemon
	// before NotifyLinkCycle, so markAppliedSnapshotLocked's defer-skip does
	// not suppress this capture.
	m.markAppliedSnapshotLocked()
	ready := 0
	for _, b := range status.Bindings {
		if b.Ready {
			ready++
		}
	}
	slog.Info("userspace: AF_XDP rebind initiated after link cycle",
		"forwarding_armed", status.ForwardingArmed,
		"bindings", len(status.Bindings),
		"ready", ready)
	// Re-bootstrap NAPI queues after rebind. The link DOWN/UP cycle
	// destroyed the XSK channels; the rebind created new sockets but
	// the fill ring WQEs haven't been posted to the NIC yet. Broadcast
	// pings generate hardware RX events that trigger NAPI, which posts
	// fill ring WQEs so zero-copy XSK can receive packets.
	m.bootstrapNAPIQueuesAsyncLocked("link-cycle")
	return nil
}
