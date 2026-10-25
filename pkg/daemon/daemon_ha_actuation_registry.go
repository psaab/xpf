package daemon

import (
	"errors"
	"fmt"
	"sync"
	"time"
)

// failoverActuation is the fence-completion barrier armed before a
// remote-requested transfer-out. done is closed exactly once, when the local
// demotion has been RESOLVED; err is the verdict (nil = the demotion actually
// actuated, non-nil = it did not) and is written under the registry lock before
// done is closed, so every observer of the close also observes the verdict.
type failoverActuation struct {
	done     chan struct{}
	resolved bool
	err      error
}

// failoverActuationKey identifies ONE transfer-out request: the redundancy
// group plus the request id the peer minted for it (SessionSync.failoverSeq).
// Keying the barrier map on the REQUEST rather than on the RG alone is what
// makes a stale cycle harmless — an older request's disarm, or the disarm its
// expired wait performs, can only ever remove its own entry and never the
// barrier a newer request for the same RG is about to block on (#6177).
// A peer that sends no request id supplies 0, which degrades to exactly the
// pre-#6177 one-slot-per-RG behaviour rather than failing.
type failoverActuationKey struct {
	rgID  int
	reqID uint64
}

// #9259: the two remaining routes into #9036's collapse.
//
// #9036's chain was: the barrier is gone -> the wait returns nil -> nil means
// applied. PR #9247 removed ONE way for the barrier to be gone (supersede, now
// resolved with ErrFailoverSuperseded). The FINAL link — **absence of a barrier
// is read as proof of fencing** — was untouched, and two more ways reach it:
//
//  1. NEVER ARMED: a (rgID, reqID) for which no barrier was ever registered
//     here — a duplicate or stale failover request, or a retry across a fabric
//     blip.
//  2. VERDICT ALREADY CONSUMED: the first waiter deletes the entry after
//     reading it, deliberately, so a later wait cannot re-read a stale verdict
//     (#6177). A second wait for the same request then found an empty slot.
//
// Both returned nil, and sync_failover.go sends failoverAckApplied EXACTLY when
// this returns nil. So the peer promoted on no evidence that this node fenced.
//
// Both are now errors, so the ack downgrades to `failed`; the sync layer
// restores this owner and the requester records the aborted request so its
// election holds instead of promoting on the secondary-hold heartbeat
// (#16592 — a failed ack alone never held the requester). The trade is
// deliberate and asymmetric: holding costs a failover attempt, while the
// previous default cost the one-owner-per-RG property (#5640).
//
// SAFE FOR THE NORMAL PATH, checked rather than assumed. handleRemoteFailover
// calls WaitFailoverApplied only after OnRemoteFailover returned nil, and that
// handler arms the barrier BEFORE ManualFailover and disarms it only on the
// error path — where it returns the error and no wait ever runs. On every path
// that reaches the wait for a live request, a barrier is armed. The supersede
// path deliberately leaves a FAILED barrier rather than none, so it is
// unaffected.
var (
	// ErrFailoverNeverArmed: no barrier was ever registered for this request.
	ErrFailoverNeverArmed = errors.New(
		"no fence barrier was ever armed for this failover request; nothing here " +
			"demoted anything, so this node cannot confirm it fenced")
	// ErrFailoverVerdictConsumed: an earlier waiter already took the verdict.
	ErrFailoverVerdictConsumed = errors.New(
		"the fence verdict for this failover request was already consumed by an " +
			"earlier waiter; a second wait has no evidence of its own")
)

// failoverConsumedCap bounds the consumed-request ledger.
//
// The ledger exists ONLY to tell ErrFailoverVerdictConsumed from
// ErrFailoverNeverArmed. Both are errors and both downgrade the ack
// identically, so an eviction degrades the DIAGNOSTIC and never the safety
// property — a key that has fallen out is reported as never-armed, which is
// the more conservative of the two readings. Stated because a bounded ledger
// silently changing an operator-facing reason is the kind of thing that gets
// discovered during an outage.
const failoverConsumedCap = 1024

const defaultFailoverActuateTimeout = 3 * time.Second

// failoverActuationRegistry owns the failover fence barriers (#16124).
//
// It is the shrunk extraction of the actuation state that used to live as
// four loose Daemon fields (mutex, wait map, consumed ledger, timeout).
// One mutex guards all of it — deliberately NOT split — so the
// arm/resolve/wait interleavings the #6177/#6371/#9036/#9259 fixes rely on
// keep a single lock order. The zero value is usable: maps allocate lazily
// on first arm/consume, matching the minimal-Daemon constructions tests
// build as literals. Daemon holds one registry value and delegates; the
// registry itself needs no Daemon, which is what makes it unit-testable
// in isolation.
type failoverActuationRegistry struct {
	mu            sync.Mutex
	waiters       map[failoverActuationKey]*failoverActuation
	consumed      map[failoverActuationKey]struct{}
	consumedOrder []failoverActuationKey
	timeout       time.Duration
}

func newFailoverActuationRegistry() *failoverActuationRegistry {
	return &failoverActuationRegistry{
		waiters: make(map[failoverActuationKey]*failoverActuation),
		timeout: defaultFailoverActuateTimeout,
	}
}

// arm registers a fence-completion barrier for (rgID, reqID) before a
// remote-requested transfer-out enqueues its async demotion event. It MUST
// be called before cluster.ManualFailover so the demotion actuation
// (watchClusterEvents -> resolveRG) cannot close-and-forget the barrier
// before wait observes it. It returns the barrier so the caller can hand
// the same instance back to disarm: the map slot is the request's, but the
// identity check is what keeps a superseded handle from evicting a live
// one (#6177).
func (r *failoverActuationRegistry) arm(rgID int, reqID uint64) *failoverActuation {
	b := &failoverActuation{done: make(chan struct{})}
	r.mu.Lock()
	if r.waiters == nil {
		r.waiters = make(map[failoverActuationKey]*failoverActuation)
	}
	r.waiters[failoverActuationKey{rgID: rgID, reqID: reqID}] = b
	r.mu.Unlock()
	return b
}

// disarm drops a barrier that will never be actuated — used when
// ManualFailover fails to enqueue the demotion (no event will ever fire),
// and by wait when its bounded wait expires. It does NOT close the channel:
// on the ManualFailover-error path no waiter can be blocked on it because
// the applied-ack path is not reached, and on the timeout path the waiter
// has already given up.
//
// b is the barrier the caller armed. The entry is removed only when it is
// still THAT barrier: a handle that has already been superseded by a re-arm
// must not evict the live one, which would leave the newer request's wait
// reading an empty slot and reporting the fence as actuated when it was not
// (#6177). A nil handle disarms nothing.
func (r *failoverActuationRegistry) disarm(rgID int, reqID uint64, b *failoverActuation) {
	if b == nil {
		return
	}
	key := failoverActuationKey{rgID: rgID, reqID: reqID}
	r.mu.Lock()
	if r.waiters[key] == b {
		delete(r.waiters, key)
	}
	r.mu.Unlock()
}

// resolveRG completes every armed barrier for rgID exactly once with
// verdict cause (nil = actuated). The demotion event carries no request
// id, and the fact it reports — this node finished demoting rgID — answers
// the question every in-flight request for that RG is asking, so the
// verdict fans out across the RG's entries. It is idempotent: the resolved
// flag is set under the lock, so a second demotion event for the same RG
// is a no-op and never double-closes. The verdict is written BEFORE the
// close, so any goroutine that observes the close also observes the
// verdict.
//
// A resolved barrier is left in the map rather than deleted — wait
// consumes it. Deleting here would make a resolution that lands before the
// waiter arrives read as "never armed", i.e. success, which would throw
// away exactly the failure verdict this path exists to deliver (#6371).
func (r *failoverActuationRegistry) resolveRG(rgID int, cause error) {
	r.mu.Lock()
	var resolved []*failoverActuation
	for key, b := range r.waiters {
		if key.rgID != rgID || b == nil || b.resolved {
			continue
		}
		b.resolved = true
		b.err = cause
		resolved = append(resolved, b)
	}
	r.mu.Unlock()
	for _, b := range resolved {
		close(b.done)
	}
}

// fail resolves ONE request's barrier with a failure verdict and LEAVES IT
// IN THE MAP for wait to consume (#9036).
//
// It is the supersede path's replacement for disarm. Both stop the
// misleading fence timeout #8000 was fixing; only this one keeps the
// distinction between "fenced" and "never happened" on the wire, because
// disarming makes wait take its `b == nil` arm and return nil, which the
// ack path cannot tell from a real fence.
//
// Per-REQUEST, not per-RG, and that is the difference from resolveRG. A
// demotion EVENT answers a question every in-flight request for the RG is
// asking, so its verdict fans out. A supersede is a fact about ONE
// request's generation check; failing a sibling request's barrier with it
// would discard the identity discipline #6177 exists to enforce.
//
// cause must be non-nil — a nil cause is indistinguishable from success,
// which is the defect this function exists to prevent.
func (r *failoverActuationRegistry) fail(rgID int, reqID uint64, b *failoverActuation, cause error) {
	if b == nil || cause == nil {
		return
	}
	key := failoverActuationKey{rgID: rgID, reqID: reqID}
	r.mu.Lock()
	fire := r.waiters[key] == b && !b.resolved
	if fire {
		b.resolved = true
		b.err = cause
	}
	r.mu.Unlock()
	if fire {
		close(b.done)
	}
}

// noteVerdictConsumedLocked records that this request's verdict was taken.
// The caller holds r.mu.
func (r *failoverActuationRegistry) noteVerdictConsumedLocked(key failoverActuationKey) {
	if r.consumed == nil {
		r.consumed = make(map[failoverActuationKey]struct{})
	}
	if _, dup := r.consumed[key]; dup {
		return
	}
	if len(r.consumedOrder) >= failoverConsumedCap {
		oldest := r.consumedOrder[0]
		r.consumedOrder = r.consumedOrder[1:]
		delete(r.consumed, oldest)
	}
	r.consumed[key] = struct{}{}
	r.consumedOrder = append(r.consumedOrder, key)
}

// wait blocks until the local demotion for the (rgID, reqID) transfer-out
// has been resolved (barrier closed by resolveRG, directly or via the
// Daemon signal wrappers) or the bounded timeout elapses. A nil barrier
// means the request was never armed (or an earlier waiter already consumed
// the verdict) — return immediately. It returns nil only when the demotion
// actually actuated: a failed actuation surfaces its cause (#6371) and a
// barrier that never resolves surfaces a timeout. This gates the
// remote-failover applied-ack so the peer never promotes into a two-owner
// window (#5640).
func (r *failoverActuationRegistry) wait(rgID int, reqID uint64) error {
	key := failoverActuationKey{rgID: rgID, reqID: reqID}
	r.mu.Lock()
	b := r.waiters[key]
	r.mu.Unlock()
	if b == nil {
		// #9259: absence of a barrier is NOT proof of fencing. Distinguish
		// the two ways to get here so the operator-facing reason is the
		// true one; both downgrade the ack identically.
		r.mu.Lock()
		_, consumed := r.consumed[key]
		r.mu.Unlock()
		if consumed {
			return fmt.Errorf("redundancy group %d request %d: %w", rgID, reqID,
				ErrFailoverVerdictConsumed)
		}
		return fmt.Errorf("redundancy group %d request %d: %w", rgID, reqID,
			ErrFailoverNeverArmed)
	}
	timeout := r.timeout
	if timeout <= 0 {
		timeout = defaultFailoverActuateTimeout
	}
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case <-b.done:
		// Consume the resolved barrier: this waiter owns the verdict, and
		// leaving it behind would let a later wait re-read a stale one.
		r.mu.Lock()
		err := b.err
		if r.waiters[key] == b {
			delete(r.waiters, key)
			// #9259: remember that this request's verdict was taken, so a
			// second wait reports "already consumed" rather than the
			// indistinguishable "never armed" — and, before this change,
			// rather than nil.
			r.noteVerdictConsumedLocked(key)
		}
		r.mu.Unlock()
		return err
	case <-timer.C:
		// Drop the stranded barrier so a later actuation event does not
		// close an orphaned channel that no one reads. Identity-checked,
		// so this expiry cannot disturb another request's live barrier
		// (#6177).
		r.disarm(rgID, reqID, b)
		return fmt.Errorf("timed out waiting for local fence actuation of redundancy group %d", rgID)
	}
}

// waitBatch blocks until every RG in the batch transfer-out reqID has been
// fenced, or returns the first RG's failure verdict (#5640).
func (r *failoverActuationRegistry) waitBatch(rgIDs []int, reqID uint64) error {
	for i, rgID := range rgIDs {
		if err := r.wait(rgID, reqID); err != nil {
			// A failure makes the batch unacknowledgeable. Do not wait
			// for siblings after that point, but release their barriers
			// so a partially failed batch cannot strand entries in the
			// map (#13221).
			for _, siblingRGID := range rgIDs[i+1:] {
				key := failoverActuationKey{rgID: siblingRGID, reqID: reqID}
				r.mu.Lock()
				b := r.waiters[key]
				r.mu.Unlock()
				r.disarm(siblingRGID, reqID, b)
			}
			return err
		}
	}
	return nil
}

// armedCount reports how many barriers are still held (test support).
func (r *failoverActuationRegistry) armedCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.waiters)
}

// lookup returns the barrier armed for (rgID, reqID), or nil (test support
// for the batch sibling-release path and leak assertions).
func (r *failoverActuationRegistry) lookup(rgID int, reqID uint64) *failoverActuation {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.waiters[failoverActuationKey{rgID: rgID, reqID: reqID}]
}
