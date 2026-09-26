// Package ra implements an embedded Router Advertisement sender using
// mdlayher/ndp. It replaces the external radvd binary with per-interface
// sender goroutines that build and send RA packets directly.
//
// Shutdown contract (#2033): each interface has at most ONE live NDP
// connection at any time. A sender being withdrawn/stopped moves to a DRAINING
// TOMBSTONE (m.draining) under m.mu while it joins OUTSIDE the lock, so a
// concurrent Apply/WithdrawOnce never starts a second sender on the same
// interface (which would race the goodbye or collide on ndp.Listen). All RA
// emission — including the lifetime-0 goodbye — is performed by the per-sender
// owner goroutine (see sender.run / finishShutdown), so a normal RA can never
// follow the goodbye on the wire.
package ra

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"sort"
	"sync"
	"time"

	"github.com/psaab/xpf/pkg/config"
)

// claimWaitPoll is how often a deferred Apply re-checks whether a draining
// tombstone (or WithdrawOnce claim) for an interface has cleared.
const claimWaitPoll = 5 * time.Millisecond

// claimWaitTimeout bounds how long a deferred Apply waits for a draining
// tombstone to clear, and how long releaseDrain waits to join a sender before
// giving up (the standalone goodbye / graceful join is ~100 ms, so this is
// generous). A package var so the timeout-arm test can shorten it.
var claimWaitTimeout = 5 * time.Second

// drainEntry is the single atomic claim-and-hold for a draining interface
// (#2033, structural fix for the three standalone-goodbye races). Its presence
// in m.draining is a tombstone: while it exists the interface is NOT absent, so
// a concurrent Apply/WithdrawOnce/Withdraw treats it as a claim and defers
// instead of opening a second NDP conn. ALL fields are read/written ONLY under
// m.mu. The entry is owned (created and eventually removed) by exactly ONE
// goroutine — the one that joins its sender (or the WithdrawOnce/standalone
// claimant). That single owner is the SOLE emitter of any standalone goodbye,
// and it HOLDS the entry across the whole emit, so:
//   - the owner is the only one that can take the goodbye (no double-send),
//   - the entry blocks any concurrent Apply for the entire emit (no clobber of
//     a re-claimed live sender, ≤1 live conn preserved),
//   - the goodbye decision reads sender.goodbyeEmitted only AFTER <-stopped
//     (happens-before), never on the timeout path.
type drainEntry struct {
	sender         *sender                   // draining sender; nil for a standalone-only claim
	cfg            *config.RAInterfaceConfig // config for a standalone goodbye, if owed
	goodbyeWanted  bool                      // a graceful Withdraw targeted this interface
	goodbyeClaimed bool                      // the owner has taken responsibility to emit it
	// startIfaceEpoch is the per-interface epoch (m.ifaceEpoch[name]) captured
	// when a CHANGED-config restart installed this entry (#4961). releaseDrain
	// starts the replacement only if this interface's epoch is UNCHANGED — i.e.
	// no interface-scoped withdraw (WithdrawInterfaces/WithdrawOnce naming THIS
	// interface) superseded the restart. It is 0 (and unused) for removal /
	// Clear / WithdrawOnce entries, which pass onProvenClose=nil.
	startIfaceEpoch uint64

	// joinTimedOut records that releaseDrain gave up joining this entry's owner
	// within claimWaitTimeout and handed the tombstone to the detached reclaimer
	// (#5094). It is set true when the reclaimer is armed and surfaced in
	// Manager.Status so an operator sees a wedged-owner interface as "join timed
	// out; reclaiming" rather than a plain draining that silently converges. The
	// reclaimer, not this flag, still owns the eventual goodbye/replacement.
	joinTimedOut bool
}

// Manager manages per-interface RA sender goroutines.
type Manager struct {
	mu      sync.Mutex
	senders map[string]*sender // active senders, keyed by Linux interface name

	// draining holds the per-interface claim-and-hold tombstones (see
	// drainEntry). While an entry is present the interface is claimed; a
	// concurrent Apply/WithdrawOnce/Withdraw must defer rather than start a new
	// sender (#2033 I16). The owner removes it (under m.mu) only AFTER any
	// standalone goodbye it claimed has fully completed.
	draining map[string]*drainEntry

	// epoch is the WHOLE-MANAGER fence, bumped by the whole-manager mutators
	// (Apply, Withdraw, Clear). A deferred Apply / changed-config restart
	// captures it before releasing m.mu and ABORTS if it changed — a newer
	// whole-manager call (e.g. a BACKUP transition's Withdraw/Clear, or a fresh
	// full Apply) superseded it (#2033 I16b). This prevents a stale Apply from
	// starting RA on a demoted node.
	//
	// #4961: the INTERFACE-SCOPED withdraws (WithdrawInterfaces / WithdrawOnce)
	// no longer bump this global fence — bumping it made an unrelated
	// WithdrawInterfaces([B]) cancel a DIFFERENT interface A's in-flight
	// changed-config restart (epoch mismatch → A's replacement suppressed AND
	// its tombstone deleted → A loses its RA sender → IPv6 loss on A's hosts).
	// They now bump only the per-interface epoch below, so supersession is
	// scoped to the interfaces they actually name.
	epoch uint64

	// ifaceEpoch is the per-interface supersession revision (#4961), bumped by
	// the interface-scoped withdraws (WithdrawInterfaces / WithdrawOnce) for
	// each interface they name. A changed-config restart records the target
	// interface's epoch on its drainEntry (startIfaceEpoch) and a deferred Apply
	// captures it per interface; releaseDrain / applyDeferred start the
	// (re)placement only if THIS interface's epoch is still unchanged. A withdraw
	// of interface B thus cannot cancel interface A's restart.
	ifaceEpoch map[string]uint64

	// goodbyeOwed is the graceful-withdrawal RETRY DEBT (#6777). A graceful
	// withdrawal's FINAL lifetime-0 goodbye is the last chance hosts get to drop
	// this router before Router Lifetime (default 1800s) expiry; before #6777 a
	// failure of that final emit was logged and then ERASED — finishDrainDecision
	// set goodbyeClaimed, deleted the tombstone, dropped the sender, and returned
	// only the replacement-start error, so Withdraw()/Apply() reported success.
	// The daemon's own retry driver (reconcileClusterRAServices) advances
	// lastRAReconcileHash ONLY on a successful apply, so a swallowed failure was
	// latched as converged and the every-2s pass never retried it: the stale IPv6
	// default-router identity lived on hosts for up to 30 minutes while operators
	// saw a clean withdrawal. This is the graceful-path twin of the one-shot
	// WithdrawOnce debt #5093 fixed.
	//
	// An entry here means "a lifetime-0 RA is still OWED on this interface and no
	// sender/tombstone remains to carry it". Apply re-attempts every owed goodbye
	// whose interface is not in the desired set and returns a non-nil error while
	// any debt survives, which keeps the reconcile digest un-advanced so the
	// periodic pass re-drives it. Debt is bounded (maxGoodbyeRetries) so a
	// permanently unsendable interface cannot spin the 2s reconcile forever, and
	// is dropped outright when a sender is (re)started on the interface — the
	// router is BACK, so there is nothing left to withdraw.
	goodbyeOwed map[string]*goodbyeDebt

	// goodbyeSuppressed records interfaces whose last stop intentionally did
	// not emit a goodbye. It prevents a concurrent failed graceful drain from
	// recreating retry debt after ClearInterfacesWithoutGoodbye suppresses it.
	// A later Apply that desires the interface clears this marker.
	goodbyeSuppressed map[string]bool
}

// goodbyeDebt is one interface's outstanding final-goodbye retry debt (#6777).
type goodbyeDebt struct {
	cfg      *config.RAInterfaceConfig
	attempts int
	// recordedEpoch is the whole-manager epoch this debt was (re-)recorded at.
	// retryOwedGoodbyes runs at the END of Apply, and Apply bumps the epoch at
	// its start, so a debt recorded by THIS Apply's own withdrawal carries the
	// current epoch. Retrying it in the same pass would burn one of the bounded
	// attempts microseconds after the standalone backstop already failed on a
	// fresh conn — the budget exists to span the daemon's 2s reconcile passes,
	// not to be spent three times on one tick. Same-epoch debts are therefore
	// held over (and still reported outstanding, which is what keeps the
	// reconcile digest un-advanced so a next pass happens at all).
	recordedEpoch uint64
}

// maxGoodbyeRetries bounds the #6777 retry debt. The debt exists to survive a
// TRANSIENT emit failure (a link-local that has not come back yet, a momentary
// write error) across the daemon's 2s reconcile pass. It must NOT become an
// unbounded error source: Apply returns non-nil while any debt is outstanding,
// which suppresses the reconcile digest, so an interface that can never accept
// the goodbye (its link-local is permanently gone) would otherwise re-apply and
// log every 2s forever. After this many further attempts the debt is dropped
// with a single Warn — we tried, we said so, we stop.
const maxGoodbyeRetries = 3

// HasDeadSenders reports whether any live sender's ASYNCHRONOUS conn open
// failed, so it will never emit an RA (#2865's dead-sender state, #6793).
//
// It exists because a dead sender has no retry owner of its own. `openConn`
// runs in the owner goroutine with a bounded bind retry (~2s, for a link-local
// that has not settled yet); when that retry is exhausted the owner exits and
// the sender stays in `m.senders` marked dead. `Apply`'s changed-config branch
// knows how to rebuild it — the #2865 "rebuilding dead sender (initial conn
// open failed)" path — but only when something calls `Apply` again, and nothing
// does:
//
//   - STANDALONE: RA is applied from `applyServicesReconcile`, which runs only
//     on a config apply. `reconcileRGStateLoop` is cluster-only. So a boot-time
//     bind failure leaves the interface with NO router advertisements until an
//     operator happens to commit — hosts on that segment get no default route,
//     silently, on a node that reports a successful commit.
//   - CLUSTER: `reconcileClusterRAServices` runs every 2s but is DIGEST-GATED,
//     and a dead sender does not move the desired-set digest. So its "a
//     transient boot-time bind failure recovers on the next reconcile with NO
//     config change" promise did not hold either.
//
// Cheap by construction: it is a map walk over live senders and `dead()` is a
// non-blocking channel probe, so the always-on caller costs nothing on the
// common path where every sender opened.
func (m *Manager) HasDeadSenders() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, s := range m.senders {
		if s.dead() {
			return true
		}
	}
	return false
}

// DeadSenderInterfaces returns the interfaces whose sender is dead, sorted, for
// logging. Separate from HasDeadSenders so the hot always-on probe allocates
// nothing.
func (m *Manager) DeadSenderInterfaces() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	var names []string
	for name, s := range m.senders {
		if s.dead() {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	return names
}

// New creates a new RA manager.
func New() *Manager {
	return &Manager{
		senders:           make(map[string]*sender),
		draining:          make(map[string]*drainEntry),
		ifaceEpoch:        make(map[string]uint64),
		goodbyeOwed:       make(map[string]*goodbyeDebt),
		goodbyeSuppressed: make(map[string]bool),
	}
}

// bumpEpoch increments the whole-manager fence epoch. Callers must hold m.mu.
func (m *Manager) bumpEpoch() { m.epoch++ }

// bumpIfaceEpoch increments the per-interface supersession revision for name
// (#4961). Callers must hold m.mu.
func (m *Manager) bumpIfaceEpoch(name string) { m.ifaceEpoch[name]++ }

// recordGoodbyeDebtLocked retains the #6777 retry debt for a FAILED final
// lifetime-0 goodbye on name, so a later Apply can re-attempt it. Callers hold
// m.mu.
//
// A "interface not found" failure records NOTHING: the netdev is gone, so there
// is no link to emit on and no host behind it left to hear a goodbye. Retrying
// that would be a permanent error source for a legitimately-removed interface.
// A bind or write failure IS retained — those are the transient shapes the debt
// exists for (a link-local that has not come back yet on a demoting RETH member
// mid-MAC-cycle, a momentary write error).
//
// The attempt counter is preserved across re-records so a repeatedly failing
// interface converges on maxGoodbyeRetries rather than restarting its budget
// every pass.
func (m *Manager) recordGoodbyeDebtLocked(name string, cfg *config.RAInterfaceConfig, err error) {
	if m.goodbyeSuppressed[name] {
		delete(m.goodbyeOwed, name)
		return
	}
	if cfg == nil {
		return
	}
	if !errors.Is(err, errGoodbyeWrite) && !isGoodbyeBindFailure(err) {
		slog.Debug("ra: final goodbye failed on a vanished interface; no retry debt",
			"interface", name, "err", err)
		return
	}
	d := m.goodbyeOwed[name]
	if d == nil {
		d = &goodbyeDebt{}
		m.goodbyeOwed[name] = d
	}
	d.cfg = cfg
	d.recordedEpoch = m.epoch
	slog.Info("ra: retaining final-goodbye retry debt", "interface", name,
		"attempts", d.attempts)
}

// isGoodbyeBindFailure reports whether err is a goodbye failure that happened
// BEFORE the lifetime-0 write — i.e. sendOneGoodbye's ndp.Listen leg failed.
// sendOneGoodbye wraps the two pre-write failures distinctly: a missing netdev
// is wrapped with the "goodbye interface" prefix (permanent — no debt), while a
// bind failure propagates ndp.Listen's error unwrapped. Anything that is
// neither a write failure nor a missing netdev is therefore a bind failure.
func isGoodbyeBindFailure(err error) bool {
	return err != nil && !errors.Is(err, errGoodbyeIfaceMissing)
}

// retryOwedGoodbyes re-attempts every #6777 retry debt whose interface is NOT
// in desired, and reports whether any debt is still outstanding afterwards.
//
// It runs on the Apply path deliberately: Apply is what the daemon's periodic
// reconcile drives, and reconcileClusterRAServices advances its convergence
// digest only when Apply returns nil. Returning a non-nil error while debt
// survives is therefore the whole retry mechanism — it keeps the digest
// un-advanced so the every-2s pass calls Apply again instead of latching the
// failed withdrawal as converged.
//
// An interface that reappeared in desired has its debt DROPPED, not retried:
// the router is coming back on that link, so withdrawing it would be wrong.
// The emit goes through WithdrawOnce, which takes the same claim-and-hold
// tombstone every other goodbye path takes, so a retry can never open a second
// conn on an interface that already has a live sender (#2033 MAJOR 1). A
// Skipped result (the interface was busy) leaves the debt in place WITHOUT
// spending an attempt — nothing was tried.
func (m *Manager) retryOwedGoodbyes(desired map[string]*config.RAInterfaceConfig) error {
	m.mu.Lock()
	var todo []*config.RAInterfaceConfig
	var held []string
	for name, d := range m.goodbyeOwed {
		if m.goodbyeSuppressed[name] {
			delete(m.goodbyeOwed, name)
			continue
		}
		if _, back := desired[name]; back {
			slog.Info("ra: dropping final-goodbye retry debt; interface is advertised again",
				"interface", name)
			delete(m.goodbyeOwed, name)
			continue
		}
		if d == nil || d.cfg == nil {
			delete(m.goodbyeOwed, name)
			continue
		}
		if d.recordedEpoch == m.epoch {
			// Recorded by THIS Apply's own withdrawal — hold it over to the next
			// pass, but still report it outstanding.
			held = append(held, name)
			continue
		}
		if d.attempts >= maxGoodbyeRetries {
			slog.Warn("ra: giving up on the final lifetime-0 goodbye; hosts may "+
				"hold this router until Router Lifetime expiry",
				"interface", name, "attempts", d.attempts)
			delete(m.goodbyeOwed, name)
			continue
		}
		d.attempts++
		todo = append(todo, d.cfg)
	}
	m.mu.Unlock()

	var errs []error
	for _, name := range held {
		errs = append(errs, fmt.Errorf("ra: final goodbye owed on %s (retry deferred to the next pass)", name))
	}
	if len(todo) == 0 {
		return errors.Join(errs...)
	}

	for _, r := range m.WithdrawOnce(todo) {
		switch {
		case r.Sent:
			m.mu.Lock()
			delete(m.goodbyeOwed, r.Interface)
			m.mu.Unlock()
			slog.Info("ra: retried final goodbye succeeded; debt cleared",
				"interface", r.Interface)
		case r.Skipped:
			// Busy: another owner holds the interface and will emit. Refund the
			// attempt — a skip is not a try.
			m.mu.Lock()
			if d := m.goodbyeOwed[r.Interface]; d != nil && d.attempts > 0 {
				d.attempts--
			}
			m.mu.Unlock()
			errs = append(errs, fmt.Errorf("ra: final goodbye still owed on %s (interface busy)", r.Interface))
		default:
			errs = append(errs, r.Err)
		}
	}
	return errors.Join(errs...)
}

// interfaceBusy reports whether the named interface currently has an active
// sender or a draining tombstone. Callers must hold m.mu.
func (m *Manager) interfaceBusy(name string) bool {
	if _, ok := m.senders[name]; ok {
		return true
	}
	_, ok := m.draining[name]
	return ok
}

// releaseDrain is the SINGLE exit path for a draining sender, used by Withdraw,
// Clear, Apply removal AND Apply's changed-config restart (#2033 structural fix;
// round-4 unification). The caller is the sole owner of name's drainEntry and
// has just signalled the sender to stop. releaseDrain owns the whole
// "stop the old sender (join-or-timeout) → optionally emit exactly-once →
// optionally start a replacement on PROVEN-close → release tombstone" sequence,
// so no divergent inline copy of these rules can drift (closes round-4 MAJOR
// 1 + 2). Must be called WITHOUT m.mu held.
//
//   - onProvenClose, if non-nil, is the changed-config replacement starter. It
//     runs ONLY on the proven-closed (<-stopped) arm, while the tombstone is
//     still HELD (a concurrent Apply defers), and ONLY if no graceful withdraw
//     superseded the replace (epoch unchanged AND no goodbye wanted), evaluated
//     UNDER the lock that performs the start with FRESH state (no boolean cached
//     across an unlock — round-5). It opens the replacement conn — guaranteed
//     AFTER the old conn is proven closed (≤1 live conn). It runs under m.mu and
//     returns any start error.
//   - startEpoch is the manager epoch captured by the caller when it claimed the
//     interface; a changed epoch means a newer Withdraw/Clear/Apply superseded
//     this op, so the replacement is aborted.
//
// Timeout discipline (closes race 2 AND round-4 MAJOR 1/2): goodbyeEmitted is
// read ONLY after a successful <-stopped. On a join TIMEOUT (owner wedged
// despite bounded SetWriteDeadline) releaseDrain does NOT read goodbyeEmitted,
// does NOT emit a standalone, and does NOT start the replacement — the old conn
// may still be live, so opening a replacement would break ≤1-conn and an emit
// would be unordered. It LEAVES the tombstone in place (so any future
// Apply/reconcile defers — never 2 conns) and starts a detached reclaimer that
// removes the tombstone once the wedged owner finally exits. The degraded
// state is "old sender lingers, no replacement, tombstone held" — never 2
// conns, never an unordered emit, never a dropped-into-double goodbye.
//
// Round-5 atomicity: the goodbye-vs-replace decision is re-evaluated against the
// LIVE tombstone under the lock at the ACT point — never trusting a boolean
// computed before the emit unlock. goodbyeWanted is monotonic (false→true only)
// and epoch is monotonic increasing, so a "replace" decision observed under the
// act-lock (epoch==startEpoch AND !goodbyeWanted AND same entry) cannot be
// invalidated while the lock is held; conversely if a racing Withdraw flipped
// goodbyeWanted in the emit gap, the act-lock re-check sees it, suppresses the
// replace, AND emits the now-owed goodbye (the withdraw wins).
func (m *Manager) releaseDrain(name string, s *sender, startEpoch uint64, onProvenClose func() error) error {
	if s != nil {
		// #4830: time.After inside a select leaks its Timer in the runtime's
		// timer heap until it fires (up to claimWaitTimeout) whenever the
		// OTHER case (s.stopped) wins the select first — the common path,
		// since most releases join promptly. time.NewTimer + a deferred
		// Stop reclaims it immediately instead.
		t := time.NewTimer(claimWaitTimeout)
		defer t.Stop()
		select {
		case <-s.stopped:
			// proven closed — fall through to the ordered decision below.
		case <-t.C:
			slog.Warn("ra: timed out joining draining sender; deferring the "+
				"goodbye/replacement to the reclaimer (owner may still hold a "+
				"live conn); leaving tombstone held", "interface", name)
			// #5094: the timeout defers, it must NOT erase this generation's
			// owed action. Hand the SAME startEpoch + onProvenClose (nil for a
			// removal/withdraw) to the detached reclaimer, which re-evaluates
			// them against fresh state once the wedged owner finally proves
			// closed — instead of dropping the replacement/goodbye and leaving
			// the interface senderless until an unrelated later Apply re-drives
			// it.
			m.reclaimTombstoneWhenStopped(name, s, startEpoch, onProvenClose)
			return nil
		}
	}

	// Proven closed (or s==nil): run the ordered post-close decision, then
	// make-before-break — wait UNLOCKED for any started replacement's conn to
	// come live so Apply returns only once the replacement RA conn is up, with
	// no observable 0-live-conn window across a config replace (#2834). The old
	// conn was PROVEN closed before the replacement started (≤1 live conn), and
	// waitConnReady returns promptly if the open gives up or is pre-empted.
	repl, goodbyeErr, startErr := m.finishDrainDecision(name, s, startEpoch, onProvenClose)
	if repl != nil && !repl.waitConnReady(claimWaitTimeout) {
		slog.Warn("ra: replacement sender conn did not come up after a "+
			"config replace", "interface", name)
	}
	// #6777: a failed FINAL goodbye is a caller-visible failure, not a log line.
	// Joining it with the start error is what makes Apply's firstErr and
	// Withdraw's aggregate non-nil, which in turn keeps the daemon's reconcile
	// digest un-advanced so the owed goodbye is actually retried.
	return errors.Join(goodbyeErr, startErr)
}

// finishDrainDecision runs the ordered post-close decision for a draining
// interface whose sender has PROVEN closed (the caller observed <-s.stopped, or
// s==nil): emit an owed standalone goodbye (claim-once, held across the emit)
// and/or start the still-current replacement, each re-evaluated against FRESH
// state under m.mu, then remove the tombstone. It is the single body shared by
// releaseDrain's proven-close arm AND the join-timeout reclaimer (#5094), so
// both apply identical goodbye-vs-replace-vs-supersession rules.
//
// The goodbye claim and the replacement decision are made against FRESH state
// at the act point. Because goodbyeWanted only goes false→true and epoch only
// increases, at most one emit pass is needed (claim → unlock → blocking emit →
// re-lock); a late Withdraw that flips goodbyeWanted during that emit gap is
// caught on the re-lock, which re-runs the same claim-and-decide logic before
// acting on the replacement.
//
// It returns the started replacement sender (nil if none started) so the caller
// can wait UNLOCKED for its conn to come live (the #2834 make-before-break) —
// finishDrainDecision itself must not block on that while holding m.mu. The
// replacement is looked up from m.senders under the SAME lock that started it,
// so the returned pointer is never a shared mutable local (no cross-goroutine
// data race between a synchronous caller and the detached reclaimer).
//
// Identity guard (matters for the reclaimer, a no-op for releaseDrain): when
// s != nil the whole decision is gated on the live tombstone still being OURS
// (e.sender == s). The reclaimer runs long after the timeout, so a newer
// Apply/Withdraw may have replaced the tombstone with its own entry; if so we
// do nothing and leave it to its new owner. releaseDrain's synchronous caller
// installs the entry immediately before this runs, and a racing Withdraw only
// flips fields on that SAME entry (never replaces it), so the guard always
// holds there — the behavior is unchanged.
func (m *Manager) finishDrainDecision(name string, s *sender, startEpoch uint64, onProvenClose func() error) (*sender, error, error) {
	// goodbyeErr survives the re-loop: the emit runs with m.mu dropped and the
	// loop re-acquires to decide the replacement, so a failure recorded on the
	// emit pass must still be returned after the (goodbye-free) second pass
	// falls through to the tombstone delete. Returning it is only half of
	// #6777 — recordGoodbyeDebtLocked below retains the state a retry needs.
	var goodbyeErr error
	for {
		m.mu.Lock()
		e := m.draining[name]
		if e == nil || (s != nil && e.sender != s) {
			// Gone, or a newer call re-claimed the interface with its own entry;
			// that newer owner manages its own goodbye/replacement/release.
			m.mu.Unlock()
			return nil, goodbyeErr, nil
		}

		// Decide goodbye claim-once with FRESH goodbyeWanted/goodbyeClaimed.
		if e.goodbyeWanted && !e.goodbyeClaimed && s != nil && !s.goodbyeEmitted.Load() {
			e.goodbyeClaimed = true
			cfg := e.cfg
			m.mu.Unlock()
			slog.Info("ra: emitting standalone goodbye (owner exited without "+
				"one; claim held across emit)", "interface", name)
			if cfg != nil {
				// Surface a failed backstop goodbye (#5093): this is the last
				// retry the graceful-withdraw path has, so a swallowed write
				// error here would silently leave the stale router live on hosts.
				// #6777: "surface" means RETURN it and RETAIN the debt — the
				// pre-#6777 code logged it here and then fell through to the
				// tombstone delete with goodbyeClaimed set, erasing every trace
				// a retry could act on while reporting success to the caller.
				if err := m.sendOneGoodbye(cfg); err != nil {
					slog.Warn("ra: standalone goodbye failed",
						"interface", name, "err", err)
					goodbyeErr = err
					m.mu.Lock()
					m.recordGoodbyeDebtLocked(name, cfg, err)
					m.mu.Unlock()
				} else {
					// A late success clears any debt an earlier attempt left.
					m.mu.Lock()
					delete(m.goodbyeOwed, name)
					m.mu.Unlock()
				}
			}
			// Re-loop: re-acquire the lock and re-evaluate against fresh state
			// before deciding the replacement (the emit ran outside the lock).
			continue
		}

		// No (further) goodbye owed. Decide the replacement under THIS lock with
		// FRESH epoch + goodbyeWanted (round-5: no cached boolean). Start ONLY
		// if the whole-manager fence is still ours (no Clear/Withdraw/full-Apply
		// superseded), THIS interface's per-interface epoch is unchanged (#4961:
		// no interface-scoped withdraw naming this interface superseded), AND no
		// goodbye was wanted (a withdraw overrides a replace). None can change
		// while we hold the lock.
		var (
			startErr error
			repl     *sender
		)
		if onProvenClose != nil && m.epoch == startEpoch &&
			m.ifaceEpoch[name] == e.startIfaceEpoch && !e.goodbyeWanted {
			// Old conn PROVEN closed + tombstone still held → ≤1 live conn.
			if startErr = onProvenClose(); startErr == nil {
				repl = m.senders[name]
			}
		}
		delete(m.draining, name)
		m.mu.Unlock()
		return repl, goodbyeErr, startErr
	}
}

// reclaimTombstoneWhenStopped detaches a goroutine that waits for a wedged
// owner to finally exit, then completes the SAME ordered post-close decision
// releaseDrain would have run inline had the join not timed out (#5094): emit an
// owed standalone goodbye and/or start the still-current replacement, then
// remove the tombstone. This self-heals the degraded "join timed out" state
// WITHOUT ever opening a second conn while the old one may be live — the
// replacement is opened only after <-s.stopped proves the old conn closed, and
// only while the tombstone is still held (≤1 live conn).
//
// startEpoch and onProvenClose are the caller's captured generation intent
// (onProvenClose is nil for a removal/withdraw, which want no replacement).
// finishDrainDecision re-evaluates them against fresh state under m.mu and its
// identity guard leaves a newer owner's re-claimed entry untouched. It is the
// exact same decision body the synchronous proven-close arm runs, so a
// timeout defers the action rather than erasing it.
func (m *Manager) reclaimTombstoneWhenStopped(name string, s *sender, startEpoch uint64, onProvenClose func() error) {
	// Mark the still-held tombstone so Status surfaces the wedged-owner interface
	// as "join timed out; reclaiming" rather than a plain draining (#5094).
	m.mu.Lock()
	if e := m.draining[name]; e != nil && e.sender == s {
		e.joinTimedOut = true
	}
	m.mu.Unlock()

	go func() {
		<-s.stopped
		// The wedged owner has finally exited; its conn is now PROVEN closed.
		repl, goodbyeErr, startErr := m.finishDrainDecision(name, s, startEpoch, onProvenClose)
		// #6777: the reclaimer has no caller to return to, so the retry debt
		// recordGoodbyeDebtLocked left behind IS the surface here — the next
		// Apply picks it up. Log the two failures distinctly; conflating them
		// under the replacement-start message hid which one actually happened.
		if goodbyeErr != nil {
			slog.Warn("ra: reclaimer final goodbye failed after wedged owner "+
				"exited; retry debt retained", "interface", name, "err", goodbyeErr)
		}
		if startErr != nil {
			slog.Warn("ra: reclaimer replacement start failed after wedged owner "+
				"exited", "interface", name, "err", startErr)
			return
		}
		// Best-effort make-before-break for the healed replacement (bounded).
		// This path is already degraded (the old owner wedged past the join
		// timeout, so there was an unavoidable RA gap); the wait only bounds how
		// long the detached reclaimer lingers before logging completion.
		if repl != nil {
			repl.waitConnReady(claimWaitTimeout)
		}
		slog.Info("ra: reclaimed tombstone after wedged owner finally exited",
			"interface", name)
	}()
}

// Apply diffs the current senders against the desired set and starts/stops/
// updates as needed. Unchanged configs are left running without RA gap.
//
// INVARIANT (#2033 MAJOR 1): at no point are two live NDP conns present for one
// interface. Every transition that replaces or removes a sender installs a
// draining tombstone for that interface BEFORE releasing m.mu and stops the old
// sender (closing its conn) BEFORE any replacement conn is opened. The
// tombstone covers the whole stop→start window, so a concurrent
// Apply/Withdraw/WithdrawOnce that sees it defers instead of opening a second
// conn. A CHANGED config is a hard replace (no goodbye — the router is not
// going away); a REMOVED config (this interface, or all of them when configs is
// empty) is a GRACEFUL withdraw that emits a final lifetime-0 goodbye (#5092),
// so hosts drop the router immediately rather than holding a stale default
// route until Router Lifetime expires.
//
// Interfaces that are ALREADY draining when this Apply runs (a prior
// withdraw/stop or a WithdrawOnce claim still tearing down) are NOT started in
// this pass — that would race a second conn against the one tearing down.
// Instead they are deferred: Apply releases m.mu, waits (bounded) for the
// tombstone to clear, then re-acquires m.mu and starts them — but ONLY if the
// manager epoch has not changed in the meantime (a newer Withdraw/Clear would
// have superseded this Apply; starting here would re-arm RA on a demoted node).
func (m *Manager) Apply(configs []*config.RAInterfaceConfig) error {
	m.mu.Lock()

	m.bumpEpoch()

	if len(configs) == 0 {
		// Config-driven removal of ALL RA (#5092): retire every sender with a
		// final lifetime-0 goodbye (RFC 4861 §6.2.5) rather than a silent hard
		// stop, so hosts drop this router immediately instead of holding the
		// stale default route until Router Lifetime (default 1800s) expires.
		// Same graceful path as Withdraw(); Clear() remains the explicit
		// no-goodbye primitive for a forced/unsafe stop.
		owned, epoch := m.collectGracefulWithdrawLocked()
		m.mu.Unlock()
		var errs []error
		for _, o := range owned {
			// nil onProvenClose: a removal never starts a replacement.
			// #6777: a failed final goodbye here is returned, not dropped —
			// this branch IS the cluster "no active owner" withdrawal, and its
			// caller (reconcileClusterRAServices) latches convergence on a nil
			// return.
			if err := m.releaseDrain(o.name, o.s, epoch, nil); err != nil {
				errs = append(errs, err)
			}
		}
		// Nothing is desired, so every outstanding debt is still owed.
		if err := m.retryOwedGoodbyes(nil); err != nil {
			errs = append(errs, err)
		}
		return errors.Join(errs...)
	}

	// Build desired map.
	desired := make(map[string]*config.RAInterfaceConfig, len(configs))
	for _, cfg := range configs {
		desired[cfg.Interface] = cfg
		delete(m.goodbyeSuppressed, cfg.Interface)
	}

	// A pending stop. tomb=true means a tombstone was installed for the
	// interface and must be cleared after the join (removal) or after the
	// replacement starts (restart).
	type stopReq struct {
		name string
		s    *sender
	}
	var toStop []stopReq

	// Remove senders not in the desired set. A TRUE removal (the operator
	// deleted this interface's RA config and nothing re-advertises the router)
	// is a GRACEFUL withdraw (#5092): install a goodbyeWanted drainEntry and
	// signalStop(modeGraceful) so the owner emits the RFC 4861 §6.2.5
	// lifetime-0 goodbye as its final RA — hosts drop this router at once
	// instead of holding the stale default route until Router Lifetime
	// (default 1800s) expires. This mirrors claimGracefulLocked's active-sender
	// branch; releaseDrain's standalone backstop covers a lost upgrade race.
	// The changed-config RESTART path below stays a hard replace (no goodbye —
	// the router is not going away; the replacement re-advertises immediately).
	// The tombstone also lets a concurrent WithdrawOnce/Apply defer and a racing
	// graceful Withdraw flip goodbyeWanted (idempotent — already true here).
	for name, s := range m.senders {
		if _, ok := desired[name]; !ok {
			slog.Info("ra: withdrawing removed sender (graceful goodbye)", "interface", name)
			delete(m.senders, name)
			m.draining[name] = &drainEntry{sender: s, cfg: s.cfg, goodbyeWanted: true}
			s.signalStop(modeGraceful)
			toStop = append(toStop, stopReq{name, s})
		}
	}

	// Classify desired interfaces: unchanged (left running), changed (hard
	// replace — tombstone + stop old, defer the start), or already-draining /
	// new (deferred or started directly).
	var firstErr error
	var deferred []*config.RAInterfaceConfig  // already-draining when we held the lock
	var toRestart []*config.RAInterfaceConfig // changed config: old stopped, start after join
	for name, cfg := range desired {
		existing, ok := m.senders[name]
		if ok && !existing.dead() && configEqual(existing.cfg, cfg) {
			continue // No change — keep running, no RA gap.
		}

		// Changed config OR a DEAD sender (its openConn failed at boot, so it
		// will never emit an RA — #2865): hard-replace. Install a tombstone,
		// stop the old sender, and DEFER the start until the old conn is closed
		// (the tombstone covers the whole window). Never open the new conn while
		// the old one is live (#2033 MAJOR 1). For a dead sender the old conn is
		// already closed (run() exited via finishShutdown), so the join in
		// releaseDrain returns immediately and the rebuild proceeds — a transient
		// boot-time bind failure recovers on the next reconcile with NO config
		// change, instead of leaving the interface permanently without RAs.
		if ok {
			if existing.dead() && configEqual(existing.cfg, cfg) {
				slog.Info("ra: rebuilding dead sender (initial conn open failed)",
					"interface", name)
			} else {
				slog.Info("ra: restarting sender", "interface", name)
			}
			delete(m.senders, name)
			// #4961: record THIS interface's per-interface epoch on the restart
			// tombstone. releaseDrain starts the replacement only if the epoch is
			// still this value — an interface-scoped withdraw naming this
			// interface bumps it and suppresses the (now-superseded) restart,
			// while a withdraw of a DIFFERENT interface leaves it untouched.
			m.draining[name] = &drainEntry{
				sender:          existing,
				cfg:             existing.cfg,
				startIfaceEpoch: m.ifaceEpoch[name],
			}
			existing.signalStop(modeHard)
			toStop = append(toStop, stopReq{name, existing})
			toRestart = append(toRestart, cfg)
			continue
		}

		// New interface. If a tombstone is already present (a prior withdraw/
		// stop or a WithdrawOnce claim is still tearing down), defer — do not
		// start a second conn.
		if _, draining := m.draining[name]; draining {
			deferred = append(deferred, cfg)
			continue
		}

		if err := m.startLocked(cfg); err != nil && firstErr == nil {
			firstErr = err
		}
	}

	epoch := m.epoch
	// #4961: capture each deferred interface's per-interface epoch as the
	// baseline applyDeferred re-checks, so an interface-scoped withdraw naming
	// that interface (but NOT one naming a different interface) aborts its
	// deferred start.
	deferredIfaceEpoch := make(map[string]uint64, len(deferred))
	for _, cfg := range deferred {
		deferredIfaceEpoch[cfg.Interface] = m.ifaceEpoch[cfg.Interface]
	}
	m.mu.Unlock()

	restartSet := make(map[string]*config.RAInterfaceConfig, len(toRestart))
	for _, cfg := range toRestart {
		restartSet[cfg.Interface] = cfg
	}

	// All stopped (removal AND changed-config restart) senders go through the
	// SAME releaseDrain discipline (round-4 unification): join-or-timeout →
	// exactly-once goodbye if owed → for a restart, start the replacement ONLY
	// on the proven-closed arm while the tombstone is held (≤1 live conn) and
	// only if a graceful withdraw did not supersede the replace. A removal
	// passes onProvenClose=nil (no replacement).
	//
	// onProvenClose is a bare startLocked closure that touches NO Apply-local
	// state: on the join-TIMEOUT path releaseDrain hands this same closure to the
	// detached reclaimer, which runs it in another goroutine after the wedged
	// owner finally exits (#5094). A closure that wrote back into an Apply local
	// (e.g. the started replacement) would data-race that late reclaimer run.
	// releaseDrain owns the #2834 make-before-break wait internally now, so Apply
	// no longer needs the replacement handle here.
	for _, req := range toStop {
		name := req.name
		var onProvenClose func() error
		if cfg, isRestart := restartSet[name]; isRestart {
			cfg := cfg // capture
			// Runs under m.mu, tombstone held, old conn proven closed.
			onProvenClose = func() error { return m.startLocked(cfg) }
		}
		if err := m.releaseDrain(name, req.s, epoch, onProvenClose); err != nil && firstErr == nil {
			firstErr = err
		}
	}

	// Second pass for interfaces that were ALREADY draining when we held the
	// lock (not our own restart tombstones — those are handled above).
	if len(deferred) > 0 {
		if err := m.applyDeferred(deferred, epoch, deferredIfaceEpoch); err != nil && firstErr == nil {
			firstErr = err
		}
	}

	// #6777: re-attempt any final goodbye a PREVIOUS graceful withdrawal failed
	// to emit. This runs LAST so the removals above have already released their
	// tombstones — a retry claims the interface through WithdrawOnce and would
	// otherwise self-skip on a tombstone this very Apply still holds. While any
	// debt survives this returns non-nil, which keeps the daemon's RA reconcile
	// digest un-advanced so the periodic pass re-drives Apply.
	if err := m.retryOwedGoodbyes(desired); err != nil && firstErr == nil {
		firstErr = err
	}

	return firstErr
}

// applyDeferred waits (bounded) for each deferred interface's tombstone to
// clear, then re-acquires m.mu and starts it — but only if neither the
// whole-manager fence (startEpoch) nor THIS interface's per-interface epoch
// (startIfaceEpoch[iface], #4961) changed. A whole-manager Withdraw/Clear/Apply
// bumps the former; an interface-scoped withdraw naming this interface bumps the
// latter. A withdraw of a DIFFERENT interface changes neither, so this start
// still proceeds. It must be called WITHOUT m.mu held.
func (m *Manager) applyDeferred(configs []*config.RAInterfaceConfig, startEpoch uint64, startIfaceEpoch map[string]uint64) error {
	var firstErr error
	for _, cfg := range configs {
		if !m.waitTombstoneClear(cfg.Interface) {
			slog.Warn("ra: deferred Apply timed out waiting for drain",
				"interface", cfg.Interface)
			continue
		}

		m.mu.Lock()
		if m.epoch != startEpoch || m.ifaceEpoch[cfg.Interface] != startIfaceEpoch[cfg.Interface] {
			// A newer whole-manager call (epoch) or an interface-scoped withdraw
			// naming this interface (ifaceEpoch) superseded this start; abort.
			slog.Debug("ra: deferred Apply superseded by newer epoch, skipping",
				"interface", cfg.Interface)
			m.mu.Unlock()
			continue
		}
		if m.interfaceBusy(cfg.Interface) {
			// Something else (re)claimed it; do not double-start.
			m.mu.Unlock()
			continue
		}
		err := m.startLocked(cfg)
		m.mu.Unlock()
		if err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// waitTombstoneClear polls until the interface has no draining tombstone, up to
// claimWaitTimeout. Returns true if it cleared, false on timeout.
func (m *Manager) waitTombstoneClear(name string) bool {
	deadline := time.Now().Add(claimWaitTimeout)
	for {
		m.mu.Lock()
		_, draining := m.draining[name]
		m.mu.Unlock()
		if !draining {
			return true
		}
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(claimWaitPoll)
	}
}

// startLocked starts a sender for cfg and records it in m.senders. Callers must
// hold m.mu.
func (m *Manager) startLocked(cfg *config.RAInterfaceConfig) error {
	iface, err := net.InterfaceByName(cfg.Interface)
	if err != nil {
		slog.Warn("ra: interface not found, skipping",
			"interface", cfg.Interface, "err", err)
		return fmt.Errorf("interface %s: %w", cfg.Interface, err)
	}

	s := newSender(cfg, iface)
	if err := s.start(); err != nil {
		slog.Warn("ra: failed to start sender",
			"interface", cfg.Interface, "err", err)
		return fmt.Errorf("start %s: %w", cfg.Interface, err)
	}

	m.senders[cfg.Interface] = s
	slog.Info("ra: sender started", "interface", cfg.Interface,
		"prefixes", len(cfg.Prefixes))
	return nil
}

// ownedDrain is an interface whose draining sender THIS graceful Withdraw owns
// the join+release for (the active-sender case). The single owner runs
// releaseDrain, which is the sole emitter of any standalone goodbye and holds
// the entry across the emit.
type ownedDrain struct {
	name string
	s    *sender
}

// Withdraw sends goodbye RAs (lifetime=0) on all interfaces, then stops all
// senders. This tells hosts to immediately remove this router as a default
// gateway. The goodbye is the LAST RA each sender emits (owner-emitted on
// exit), so a normal RA can never follow it.
func (m *Manager) Withdraw() error {
	m.mu.Lock()
	m.bumpEpoch()
	owned, epoch := m.collectGracefulWithdrawLocked()
	m.mu.Unlock()
	// #6777: aggregate the per-interface outcomes instead of returning a
	// hard-coded nil. Every caller already had an `if err := d.ra.Withdraw();
	// err != nil` branch — those branches were unreachable, so a final goodbye
	// that never went out was reported to operators as a clean withdrawal.
	var errs []error
	for _, o := range owned {
		// nil onProvenClose: a withdraw never starts a replacement.
		if err := m.releaseDrain(o.name, o.s, epoch, nil); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// collectGracefulWithdrawLocked flips graceful-withdrawal intent on every active
// sender AND every already-draining interface, returning the drains THIS caller
// owns the join+release for plus the current fenced epoch. Callers hold m.mu
// (and have already bumped the whole-manager epoch); they must Unlock and drive
// releaseDrain(o.name, o.s, epoch, nil) for each returned drain. Shared by
// Withdraw() and Apply()'s empty-config branch (config-driven removal of ALL RA,
// #5092) so both retire senders with a final lifetime-0 goodbye — the graceful
// terminal withdrawal RFC 4861 §6.2.5 recommends — rather than a silent hard
// stop that strands a stale default route on hosts.
//
// Already-draining interfaces are included (e.g. a Clear acquired m.mu first and
// hard-stopped them, or a changed-config restart is mid stop->start):
// claimGracefulLocked flips goodbyeWanted on those entries so their existing
// owner's release path emits the standalone if one is owed.
func (m *Manager) collectGracefulWithdrawLocked() ([]ownedDrain, uint64) {
	var names []string
	for name := range m.senders {
		names = append(names, name)
	}
	for name := range m.draining {
		names = append(names, name)
	}
	return m.claimGracefulLocked(names), m.epoch
}

// WithdrawInterfaces sends goodbye RAs and stops senders only for the named
// interfaces. Other senders are left running.
func (m *Manager) WithdrawInterfaces(names []string) {
	m.mu.Lock()
	// #4961: bump ONLY the per-interface epochs for the named interfaces, NOT
	// the whole-manager fence. Bumping the global fence made this cancel an
	// UNRELATED interface's in-flight changed-config restart (IPv6 loss on that
	// interface). Interface-scoped supersession is now scoped to `names`.
	for _, name := range names {
		m.bumpIfaceEpoch(name)
	}
	owned := m.claimGracefulLocked(names)
	epoch := m.epoch
	m.mu.Unlock()
	for _, o := range owned {
		// #6777: no error return to thread this through (this entry point has
		// no production caller today), but a failed final goodbye still leaves
		// retry debt that the next Apply picks up. Log which interface it was.
		if err := m.releaseDrain(o.name, o.s, epoch, nil); err != nil {
			slog.Warn("ra: interface-scoped withdraw failed",
				"interface", o.name, "err", err)
		}
	}
}

// ClearInterfacesWithoutGoodbye stops only the named senders without emitting
// lifetime-0 RAs. It cancels pending replacements and discards current or late
// retry debt; a goodbye already requested by another operation cannot be
// recalled. HA ownership moves use it when the identity remains present on the
// peer; other interfaces and their senders are untouched.
func (m *Manager) ClearInterfacesWithoutGoodbye(names []string) error {
	if len(names) == 0 {
		return nil
	}

	m.mu.Lock()
	seen := make(map[string]struct{}, len(names))
	var owned []ownedDrain
	for _, name := range names {
		if _, dup := seen[name]; dup {
			continue
		}
		seen[name] = struct{}{}
		m.bumpIfaceEpoch(name)
		m.goodbyeSuppressed[name] = true
		delete(m.goodbyeOwed, name)
		if s, ok := m.senders[name]; ok {
			delete(m.senders, name)
			m.draining[name] = &drainEntry{sender: s, cfg: s.cfg}
			s.signalStop(modeHard)
			owned = append(owned, ownedDrain{name: name, s: s})
			continue
		}
		if e := m.draining[name]; e != nil {
			// Preserve the draining operation's monotonic goodbye decision.
			if e.sender != nil {
				e.sender.signalStop(modeHard)
			}
		}
	}
	epoch := m.epoch
	m.mu.Unlock()

	var errs []error
	for _, o := range owned {
		if err := m.releaseDrain(o.name, o.s, epoch, nil); err != nil {
			errs = append(errs, err)
		}
		m.mu.Lock()
		if _, draining := m.draining[o.name]; !draining {
			delete(m.goodbyeOwed, o.name)
		}
		m.mu.Unlock()
	}
	return errors.Join(errs...)
}


// claimGracefulLocked records the graceful withdrawal intent for each named
// interface UNDER m.mu, and returns only the interfaces THIS Withdraw owns the
// join+release for. Per interface (atomic under m.mu — #2033 MAJOR 2):
//   - active sender: move it to a NEW drainEntry{goodbyeWanted:true},
//     signalStop(graceful), and OWN the release (returned in ownedDrain). The
//     owner emits the goodbye on exit; releaseDrain's standalone backstop
//     covers the lost-upgrade case.
//   - already draining (Clear/restart/WithdrawOnce owns it): just flip
//     goodbyeWanted=true on the existing entry and upgrade the live sender (if
//     any) via signalStop(graceful). We do NOT own its release; the existing
//     owner's release path (releaseDrain / Apply restart) emits the standalone
//     if owed — claim-once via goodbyeClaimed guarantees no double-send even if
//     several Withdraws flip the same entry.
//
// Callers must hold m.mu.
func (m *Manager) claimGracefulLocked(names []string) []ownedDrain {
	var owned []ownedDrain
	seen := make(map[string]struct{}, len(names))
	for _, name := range names {
		if _, dup := seen[name]; dup {
			continue // dedup within this call
		}
		seen[name] = struct{}{}
		if s, ok := m.senders[name]; ok {
			slog.Info("ra: sending goodbye RA", "interface", name)
			delete(m.senders, name)
			m.draining[name] = &drainEntry{sender: s, cfg: s.cfg, goodbyeWanted: true}
			s.signalStop(modeGraceful)
			owned = append(owned, ownedDrain{name: name, s: s})
			continue
		}
		if e := m.draining[name]; e != nil {
			// Another caller (Clear / changed-config restart / WithdrawOnce)
			// owns this entry's release. Flip goodbyeWanted so that owner emits
			// the standalone if owed, and upgrade the still-running sender (if
			// any) so it may emit the goodbye itself. We do NOT take the release.
			e.goodbyeWanted = true
			if e.cfg == nil {
				e.cfg = m.cfgForName(name)
			}
			if e.sender != nil {
				slog.Info("ra: upgrading draining sender to graceful goodbye",
					"interface", name)
				e.sender.signalStop(modeGraceful)
			}
			continue
		}
		// No sender and no tombstone: nothing to withdraw (already fully gone).
	}
	return owned
}

// cfgForName returns a config to build a standalone goodbye from for name, when
// an existing drainEntry was a nil-cfg claim (e.g. a WithdrawOnce entry). Best
// effort: a WithdrawOnce entry carries no cfg, so a graceful Withdraw that
// races it cannot synthesize one — return nil and rely on the WithdrawOnce's
// own goodbye (it emits exactly one). Callers hold m.mu.
func (m *Manager) cfgForName(string) *config.RAInterfaceConfig { return nil }

// ResendBurst tells all running senders to re-send their startup burst. Used
// after RETH MAC link cycles that kill the NDP socket — the sender restarts but
// the original startup burst was lost during the link DOWN. The re-burst is
// routed through the owner goroutine (non-blocking) so it serializes with the
// owner's other writes (#2033 S2/I8) instead of racing a second writer.
func (m *Manager) ResendBurst() {
	m.mu.Lock()
	defer m.mu.Unlock()
	for name, s := range m.senders {
		slog.Info("ra: re-sending startup burst after link cycle", "interface", name)
		s.requestBurst()
	}
}

// WithdrawOnce sends a one-shot goodbye RA (router lifetime=0) on the given
// interfaces. Used on startup when a node boots as secondary to withdraw stale
// RA routes from a previous primary run. Unlike Withdraw(), this does NOT
// require a running sender — it opens a temporary NDP connection, sends the
// goodbye, and closes it WITHOUT launching a sender goroutine or a startup
// burst (so it never re-advertises the router it is withdrawing — #2033 S1).
//
// It claims the interface via a draining tombstone under m.mu so a concurrent
// Apply does NOT start a real sender mid-goodbye (#2033 I4); the Apply defers
// and starts after the claim clears (it must WAIT, not skip — dropping a MASTER
// Apply would leave the interface with no sender). Interfaces with a live
// sender (VRRP MASTER already won) or an existing tombstone are skipped — a
// goodbye must not clobber a live primary.
func (m *Manager) WithdrawOnce(configs []*config.RAInterfaceConfig) []GoodbyeResult {
	// The busy-check and the tombstone install MUST be atomic under m.mu —
	// claimWithdrawOnceLocked does both while holding the lock. Splitting them
	// (check, drop the lock, then install) reopens the #2272 check-and-act race:
	// between the check and the install, an Apply() or a concurrent WithdrawOnce
	// could start a real sender on the same interface, producing two owners on
	// one link or a sender that races the goodbye (the #2033 blackhole class).
	toGoodbye := m.claimWithdrawOnceLocked(configs)

	// The tombstone for each claimed interface is HELD across sendOneGoodbye
	// (which runs without m.mu so the emit's blocking writes do not stall other
	// callers). While it is held, interfaceBusy reports the interface as busy, so
	// a concurrent Apply defers instead of opening a second NDP conn (#2033 I4),
	// and a concurrent WithdrawOnce skips it. sendOneGoodbye never launches a
	// run() loop, so it emits only the lifetime-0 goodbye and never a normal RA
	// after it — preserving the single-owner-emit invariant. The tombstone is
	// removed only AFTER the goodbye fully completes.
	//
	// Per-interface outcomes are returned so the cold-boot caller can retain
	// retry debt: a claimed interface reports Sent only when a lifetime-0 RA
	// actually went out, Err when the bind/write failed. An interface that was
	// busy (a live sender won, or another withdraw owns it) is reported Skipped —
	// its goodbye is another owner's responsibility, not retry debt here (#5093).
	claimed := make(map[string]error, len(toGoodbye))
	for _, cfg := range toGoodbye {
		err := m.sendOneGoodbye(cfg)
		claimed[cfg.Interface] = err
		m.mu.Lock()
		delete(m.draining, cfg.Interface)
		m.mu.Unlock()
	}

	results := make([]GoodbyeResult, 0, len(configs))
	seen := make(map[string]struct{}, len(configs))
	for _, cfg := range configs {
		if _, dup := seen[cfg.Interface]; dup {
			continue
		}
		seen[cfg.Interface] = struct{}{}
		if err, ok := claimed[cfg.Interface]; ok {
			results = append(results, GoodbyeResult{
				Interface: cfg.Interface,
				Sent:      err == nil,
				Err:       err,
			})
			continue
		}
		results = append(results, GoodbyeResult{Interface: cfg.Interface, Skipped: true})
	}
	return results
}

// claimWithdrawOnceLocked performs the WithdrawOnce check-and-claim for each
// config ATOMICALLY under a single m.mu hold (#2272). For every interface that
// is not already busy (no live sender, no draining tombstone) it installs a
// claim-and-hold tombstone and returns it for the caller to emit a goodbye on.
// Holding m.mu across BOTH the interfaceBusy check AND the tombstone install is
// the whole point: it closes the window in which an Apply()/WithdrawOnce could
// otherwise start a competing sender between the check and the claim. The
// returned slice is the set this call OWNS the goodbye + tombstone-release for.
//
// The tombstone pre-marks goodbyeClaimed=true: WithdrawOnce emits exactly one
// goodbye itself, so a racing graceful Withdraw that flips goodbyeWanted on this
// entry must NOT also emit a standalone (claim-once, #2033). sender is nil — a
// WithdrawOnce claim has no run() loop to join.
func (m *Manager) claimWithdrawOnceLocked(configs []*config.RAInterfaceConfig) []*config.RAInterfaceConfig {
	m.mu.Lock()
	defer m.mu.Unlock()
	// #4961: interface-scoped op — bump only the named interfaces' per-interface
	// epochs, not the whole-manager fence, so a WithdrawOnce of interface B
	// cannot cancel interface A's in-flight restart / deferred start.
	//
	// #8597 (muse-004 K19): the bump belongs INSIDE the claim, not in a
	// preceding loop over every named interface.
	//
	// The invariant this package runs on is that a supersession bump
	// accompanies real superseding RESPONSIBILITY. Withdraw flips the global
	// fence and owns every drain. WithdrawInterfaces bumps and then flips
	// goodbyeWanted on the entry it supersedes, so even its already-draining
	// path takes over the goodbye. The skip path below does NEITHER — it emits
	// nothing, claims nothing, and reports Skipped — so bumping there
	// superseded work this call took no responsibility for.
	//
	// What that cost: finishDrainDecision starts a changed-config replacement
	// only while `m.ifaceEpoch[name] == e.startIfaceEpoch`, and applyDeferred
	// aborts a deferred start on the same comparison. A stray bump made the
	// replacement silently not happen, the tombstone get released anyway, and
	// BOTH error returns stay nil — the interface ends with no RA sender while
	// every caller is told it succeeded, and its hosts keep the router until
	// Router Lifetime (1800s default) expires. Reproduced before the fix.
	//
	// The trigger is routine: the daemon runs runStartupGoodbye in its own
	// goroutine (pkg/daemon/daemon_ha.go), so a cold-boot WithdrawOnce runs
	// concurrently with Apply's changed-config restart.
	//
	// On the CLAIMED path the bump is still load-bearing and stays: this call
	// takes the interface over and emits the goodbye, so a deferred Apply start
	// that captured the epoch in deferredIfaceEpoch must be superseded.
	// Deleting the bump rather than moving it would let a deferred start bring
	// the sender back after the operator withdrew it.
	var toGoodbye []*config.RAInterfaceConfig
	for _, cfg := range configs {
		if m.interfaceBusy(cfg.Interface) {
			slog.Debug("ra: WithdrawOnce: interface busy, skipping",
				"interface", cfg.Interface)
			continue
		}
		m.bumpIfaceEpoch(cfg.Interface)
		m.draining[cfg.Interface] = &drainEntry{cfg: cfg, goodbyeClaimed: true}
		toGoodbye = append(toGoodbye, cfg)
	}
	return toGoodbye
}

// GoodbyeResult reports the per-interface outcome of a one-shot goodbye
// (WithdrawOnce). Exactly one of Sent / Skipped is true, or Err is non-nil:
//   - Sent:    at least one lifetime-0 RA was written without error.
//   - Skipped: the interface was busy (a live sender won, or another withdraw
//     already owns the goodbye) so this call did not attempt it.
//   - Err:     the bind or the lifetime-0 write failed; the caller should retain
//     retry debt (mark the one-shot done only after Sent — #5093).
type GoodbyeResult struct {
	Interface string
	Sent      bool
	Skipped   bool
	Err       error
}

// sendOneGoodbye opens a temporary sender for cfg, emits the standalone goodbye
// (no burst, no link toggle — #2033 I12), and closes. m.mu must NOT be held. It
// returns nil only when the goodbye actually went out; a missing interface, a
// bind failure, or a lifetime-0 write failure returns a non-nil error so the
// caller can surface it and retain retry debt (#5093).
func (m *Manager) sendOneGoodbye(cfg *config.RAInterfaceConfig) error {
	iface, err := net.InterfaceByName(cfg.Interface)
	if err != nil {
		slog.Debug("ra: WithdrawOnce: interface not found",
			"interface", cfg.Interface, "err", err)
		return fmt.Errorf("%w %s: %w", errGoodbyeIfaceMissing, cfg.Interface, err)
	}
	s := newSender(cfg, iface)
	if err := s.sendGoodbyeStandalone(); err != nil {
		slog.Debug("ra: WithdrawOnce: failed to send goodbye",
			"interface", cfg.Interface, "err", err)
		return err
	}
	return nil
}

// Clear stops all senders without sending goodbye RAs.
func (m *Manager) Clear() error {
	m.mu.Lock()
	m.bumpEpoch()
	err := m.clearLocked()
	m.mu.Unlock()
	return err
}

// clearLocked hard-stops all active senders without a goodbye. Callers must
// hold m.mu; it moves senders to drainEntry tombstones, releases the lock to
// join+release each, then re-acquires — so it returns with m.mu held (matching
// its callers). No goodbye is emitted for a pure Clear (modeHard); but if a
// racing graceful Withdraw flipped goodbyeWanted on an entry, clearLocked's
// release path emits the standalone goodbye (claim-once, held across the emit).
func (m *Manager) clearLocked() error {
	if len(m.senders) == 0 {
		return nil
	}
	type pending struct {
		name string
		s    *sender
	}
	var ps []pending
	for name, s := range m.senders {
		delete(m.senders, name)
		// drainEntry with the sender so a racing graceful Withdraw can flip
		// goodbyeWanted + upgrade the live sender (#2033 MAJOR 2).
		m.draining[name] = &drainEntry{sender: s, cfg: s.cfg}
		s.signalStop(modeHard)
		ps = append(ps, pending{name, s})
	}
	epoch := m.epoch

	// Join + release each OUTSIDE the lock so Clear of many interfaces does not
	// stall other callers; re-acquire before returning (caller expects m.mu
	// held). releaseDrain handles the claim-once + held-across-emit standalone
	// goodbye if a racing Withdraw wanted one. nil onProvenClose: Clear never
	// starts a replacement.
	m.mu.Unlock()
	for _, p := range ps {
		// Clear is the explicit NO-goodbye primitive, so a goodbye is owed here
		// only when a racing graceful Withdraw flipped goodbyeWanted on one of
		// these entries. That Withdraw does not own the release and cannot
		// observe the outcome, so this log (plus the #6777 retry debt) is the
		// only surface for it.
		if err := m.releaseDrain(p.name, p.s, epoch, nil); err != nil {
			slog.Warn("ra: clear: a goodbye claimed by a racing withdraw failed",
				"interface", p.name, "err", err)
		}
	}
	m.mu.Lock()
	return nil
}

// SenderInfo holds per-interface RA sender status for display.
type SenderInfo struct {
	Interface   string
	SrcAddr     string
	Prefixes    []string
	DNSServers  []string
	NAT64Prefix string
	Preference  string
	Lifetime    int // router lifetime in seconds
	MaxInterval int
	MinInterval int
	LinkMTU     int
	Managed     bool
	Other       bool
	LastRA      string // time since last RA
	// State is "active" for a running sender or "draining" for an interface
	// whose sender is tearing down / emitting its goodbye (#2033). A draining
	// interface is deliberately reported as distinct from active so operators
	// do not read a withdrawing router as still advertising.
	State string
	// JoinTimedOut is set on a draining entry whose owner wedged past
	// claimWaitTimeout, so releaseDrain handed the owed goodbye/replacement to
	// the detached reclaimer (#5094). It lets the display distinguish a normal
	// brief drain from a stuck one that is being self-healed by the reclaimer.
	JoinTimedOut bool
}

// Status returns information about all RA senders, including interfaces that
// are currently draining (their State is "draining").
func (m *Manager) Status() []SenderInfo {
	m.mu.Lock()
	defer m.mu.Unlock()

	var result []SenderInfo
	for _, s := range m.senders {
		// #4119: report the effective Router Lifetime. An explicit 0
		// (DefaultLifetimeSet, "not a default router") is reported as 0, not
		// coerced to 1800; only an unset default-lifetime shows the 1800
		// default.
		lifetime := defaultRouterLifetime
		if s.cfg.DefaultLifetimeSet {
			lifetime = s.cfg.DefaultLifetime
		}
		info := SenderInfo{
			Interface:   s.cfg.Interface,
			SrcAddr:     s.getSrcAddr().String(),
			Lifetime:    lifetime,
			MaxInterval: s.cfg.MaxAdvInterval,
			MinInterval: s.cfg.MinAdvInterval,
			LinkMTU:     s.cfg.LinkMTU,
			Managed:     s.cfg.ManagedConfig,
			Other:       s.cfg.OtherStateful,
			Preference:  s.cfg.Preference,
			NAT64Prefix: s.cfg.NAT64Prefix,
			State:       "active",
		}
		if info.MaxInterval <= 0 {
			info.MaxInterval = defaultMaxAdvInterval
		}
		if info.MinInterval <= 0 {
			info.MinInterval = info.MaxInterval / 3
		}
		if info.Preference == "" {
			info.Preference = "medium"
		}
		for _, pfx := range s.cfg.Prefixes {
			info.Prefixes = append(info.Prefixes, pfx.Prefix)
		}
		info.DNSServers = s.cfg.DNSServers
		if last := s.getLastRA(); !last.IsZero() {
			info.LastRA = fmt.Sprintf("%.0fs ago", time.Since(last).Seconds())
		} else {
			info.LastRA = "never"
		}
		result = append(result, info)
	}

	// Surface draining interfaces so a withdrawing router is not silently
	// invisible (it is no longer "active" but not yet gone).
	for name, e := range m.draining {
		result = append(result, SenderInfo{
			Interface:    name,
			State:        "draining",
			LastRA:       "n/a",
			JoinTimedOut: e.joinTimedOut,
		})
	}
	return result
}

// configEqual compares two RA configs for equality.
func configEqual(a, b *config.RAInterfaceConfig) bool {
	if a.Interface != b.Interface ||
		a.ManagedConfig != b.ManagedConfig ||
		a.OtherStateful != b.OtherStateful ||
		a.Preference != b.Preference ||
		a.DefaultLifetime != b.DefaultLifetime ||
		// #4119: unset (→1800) and explicit-0 both have DefaultLifetime==0 but
		// marshal a DIFFERENT Router Lifetime, so the set-flag is part of the
		// identity — otherwise an unset→"default-lifetime 0" edit would not
		// restart the sender and the wire would keep advertising 1800.
		a.DefaultLifetimeSet != b.DefaultLifetimeSet ||
		a.MaxAdvInterval != b.MaxAdvInterval ||
		a.MinAdvInterval != b.MinAdvInterval ||
		a.LinkMTU != b.LinkMTU ||
		// #4590 (A5-03): compare CIDR fields by parsed value, not raw text.
		// buildRA re-parses NAT64Prefix via netip.ParsePrefix (sender.go), so
		// an operator re-typing an equivalent-but-non-canonical form
		// ("64:ff9b::/96" -> "0064:ff9b::/96") produces identical wire yet a
		// raw-string compare here reported a diff and forced a spurious RA
		// sender restart (sub-second RA gap). Normalizing suppresses that.
		!prefixEqual(a.NAT64Prefix, b.NAT64Prefix) ||
		a.NAT64PrefixLife != b.NAT64PrefixLife ||
		a.SourceLinkLocal != b.SourceLinkLocal ||
		// #4570: reachable-time / retransmit-timer are stamped onto the wire
		// by buildRA (#4307, sender.go) but were omitted from this
		// change-detector, so a day-2 commit changing ONLY those two RA-header
		// timers left configEqual==true → Apply's `continue` skipped the
		// sender restart → the wire kept advertising the OLD values until an
		// unrelated RA edit or daemon restart. Unlike DefaultLifetime (#4119),
		// 0 = "unspecified" maps DIRECTLY to a zero wire field with no
		// unset/default coercion, so a plain int compare is exact — no "Set"
		// companion is needed to distinguish absent from explicit-0.
		a.ReachableTime != b.ReachableTime ||
		a.RetransTimer != b.RetransTimer {
		return false
	}

	if len(a.Prefixes) != len(b.Prefixes) {
		return false
	}
	for i := range a.Prefixes {
		if !prefixEqual(a.Prefixes[i].Prefix, b.Prefixes[i].Prefix) ||
			a.Prefixes[i].OnLink != b.Prefixes[i].OnLink ||
			a.Prefixes[i].Autonomous != b.Prefixes[i].Autonomous ||
			a.Prefixes[i].ValidLifetime != b.Prefixes[i].ValidLifetime ||
			a.Prefixes[i].PreferredLife != b.Prefixes[i].PreferredLife ||
			// #6587: Delegated gates whether the PIO is emitted at all
			// (buildRA drops a delegated /0), so it is WIRE-AFFECTING and
			// belongs in this change detector. The #4307 comment above
			// records what omitting a wire-affecting field from this list
			// cost last time: a stale advertisement.
			a.Prefixes[i].Delegated != b.Prefixes[i].Delegated {
			return false
		}
	}

	if len(a.DNSServers) != len(b.DNSServers) {
		return false
	}
	for i := range a.DNSServers {
		if a.DNSServers[i] != b.DNSServers[i] {
			return false
		}
	}

	return true
}

// prefixEqual reports whether two CIDR strings denote the same prefix,
// tolerating equivalent-but-non-canonical textual forms. configEqual is a
// change-detector that gates the RA sender restart; the wire is always built
// by re-parsing the CIDR via netip.ParsePrefix (buildRA, sender.go), so two
// strings that parse to the same netip.Prefix produce byte-identical RA
// output. Comparing the raw strings therefore restarted the sender on a
// purely cosmetic re-type (#4590 A5-03). If either side fails to parse (""
// = unset, or a value that slipped past validation), fall back to an exact
// string compare so a genuine change is never masked — an unnecessary
// restart is harmless, a missed one is not.
func prefixEqual(a, b string) bool {
	if a == b {
		return true
	}
	pa, errA := netip.ParsePrefix(a)
	pb, errB := netip.ParsePrefix(b)
	if errA != nil || errB != nil {
		return false
	}
	return pa == pb
}
