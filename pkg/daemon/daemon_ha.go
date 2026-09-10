package daemon

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"sort"
	"strings"
	"time"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"github.com/psaab/xpf/pkg/cluster"
	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
	"github.com/psaab/xpf/pkg/vrrp"
)

// getOrCreateRGState returns the rgStateMachine for the given RG, creating
// one if it doesn't exist yet.
func (d *Daemon) getOrCreateRGState(rgID int) *rgStateMachine {
	d.rgStatesMu.RLock()
	s, ok := d.rgStates[rgID]
	d.rgStatesMu.RUnlock()
	if ok {
		return s
	}
	d.rgStatesMu.Lock()
	defer d.rgStatesMu.Unlock()
	// Double-check after upgrading to write lock.
	if s, ok = d.rgStates[rgID]; ok {
		return s
	}
	// New() always makes this map, but the fence path (#6530) now reaches
	// here from a Daemon that minimal constructions build as a literal, and
	// a nil-map write panics. Lazily allocating costs nothing on the hot
	// read path (which never gets here) and removes the footgun.
	if d.rgStates == nil {
		d.rgStates = make(map[int]*rgStateMachine)
	}
	s = newRGStateMachine()
	d.rgStates[rgID] = s
	return s
}

func (d *Daemon) syncRGStrictVIPOwnershipMode(cc *config.ClusterConfig) {
	if cc == nil {
		return
	}
	var cfg *config.Config
	if d.store != nil {
		cfg = d.store.ActiveConfig()
	}
	strictByDefault := strictVIPOwnershipByDefault(cc, cfg)
	for _, rg := range cc.RedundancyGroups {
		s := d.getOrCreateRGState(rg.ID)
		s.SetStrictVIPOwnership(strictByDefault)
	}
}

func strictVIPOwnershipByDefault(cc *config.ClusterConfig, cfg *config.Config) bool {
	if cc == nil {
		return false
	}
	if cc.NoRethVRRP || cc.PrivateRGElection {
		return false
	}
	// In the userspace dataplane, hot standby depends on the future owner
	// already being forwarding-ready before VIP/MAC ownership moves. Waiting
	// for the VRRP MASTER event to derive rg_active leaves a cutover window
	// where reply packets can hit the promoted node before userspace is active.
	if cfg == nil {
		return false
	}
	return dataplane.EffectiveType(cfg.System.DataplaneType) != dataplane.TypeUserspace
}

func (d *Daemon) setLocalFailoverCommitReady(rgID int, ready bool) {
	d.localFailoverCommitMu.Lock()
	defer d.localFailoverCommitMu.Unlock()
	if d.localFailoverCommitReady == nil {
		d.localFailoverCommitReady = make(map[int]bool)
	}
	d.localFailoverCommitReady[rgID] = ready
}

func (d *Daemon) localFailoverCommitIsReady(rgID int) bool {
	d.localFailoverCommitMu.Lock()
	defer d.localFailoverCommitMu.Unlock()
	if d.localFailoverCommitReady == nil {
		return false
	}
	return d.localFailoverCommitReady[rgID]
}

// recordRGActiveAppliedIfCurrentOrStable records a completed rg_active write
// against the transition that produced it. #6799: it is now a thin wrapper over
// rgStateMachine.RecordApplied so EVERY apply path — the four cluster/VRRP event
// handlers and the two reconcile-loop arms — reaches ONE decision made under a
// single lock hold. It used to take three separate holds and had no way to see
// that another writer had re-armed the retry debt mid-apply.
func recordRGActiveAppliedIfCurrentOrStable(s *rgStateMachine, tr rgTransition, active bool) bool {
	return s.RecordApplied(tr, active)
}

// #5250 (A7-b1 F4): every wait here is ABORTABLE on daemon stop. It used to
// bare-`time.Sleep` up to localFailoverCommitTimeout (1s) plus the dwell delay
// with no cancellation, so a `systemctl stop xpfd` landing mid-transfer held
// shutdown for the rest of that window. The signal is d.applyCancelCtx(), the
// DAEMON-STOP context (#2926) the archive timer also waits on — NOT d.daemonCtx,
// which is context.Background in production and never cancelled. Taking it here
// rather than threading a ctx through SetLocalTransferCommitReadyHook leaves
// pkg/cluster untouched. A cancelled wait returns an ERROR, the fail-closed
// direction: cluster.requestPeerFailover responds to non-nil by calling
// abortRequestedPeerFailover and sending no commit, so the peer stays
// un-promoted rather than committing a transfer this node can no longer verify.
func (d *Daemon) waitLocalFailoverCommitReady(rgIDs []int) error {
	if len(rgIDs) == 0 {
		return nil
	}
	timeout := d.localFailoverCommitTimeout
	if timeout <= 0 {
		timeout = time.Second
	}
	delay := d.localFailoverCommitDelay
	stop := d.applyCancelCtx().Done()
	// One timer, reset per wait, so a full 1 s of 10 ms polls does not allocate
	// a hundred of them on the failover path.
	timer := time.NewTimer(time.Hour)
	if !timer.Stop() {
		<-timer.C
	}
	defer timer.Stop()
	wait := func(dur time.Duration) error {
		timer.Reset(dur)
		select {
		case <-stop:
			if !timer.Stop() {
				<-timer.C
			}
			return fmt.Errorf("daemon stopping while waiting for local failover activation settle for redundancy groups %v", rgIDs)
		case <-timer.C:
			return nil
		}
	}
	deadline := time.Now().Add(timeout)
	dwelled := false
	for {
		ready := true
		for _, rgID := range rgIDs {
			if d.cluster != nil && !d.cluster.IsLocalPrimary(rgID) {
				return fmt.Errorf("local redundancy group %d lost primary before peer demotion commit", rgID)
			}
			if !d.localFailoverCommitIsReady(rgID) {
				ready = false
				break
			}
		}
		if ready {
			if !dwelled && delay > 0 {
				dwelled = true
				if err := wait(delay); err != nil {
					return err
				}
				continue
			}
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("timed out waiting for local failover activation settle for redundancy groups %v", rgIDs)
		}
		if err := wait(10 * time.Millisecond); err != nil {
			return err
		}
	}
}

// failoverActuation is the fence-completion barrier armed before a
// remote-requested transfer-out. done is closed exactly once, when the local
// demotion has been RESOLVED; err is the verdict (nil = the demotion actually
// actuated, non-nil = it did not) and is written under failoverActuateMu before
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

// armFailoverActuation registers a fence-completion barrier for (rgID, reqID)
// before a remote-requested transfer-out enqueues its async demotion event. It
// MUST be called before cluster.ManualFailover so the demotion actuation
// (watchClusterEvents -> signalFailoverActuated) cannot close-and-forget the
// barrier before waitFailoverActuated observes it. It returns the barrier so
// the caller can hand the same instance back to disarmFailoverActuation: the
// map slot is the request's, but the identity check is what keeps a superseded
// handle from evicting a live one (#6177).
func (d *Daemon) armFailoverActuation(rgID int, reqID uint64) *failoverActuation {
	b := &failoverActuation{done: make(chan struct{})}
	d.failoverActuateMu.Lock()
	if d.failoverActuateWait == nil {
		d.failoverActuateWait = make(map[failoverActuationKey]*failoverActuation)
	}
	d.failoverActuateWait[failoverActuationKey{rgID: rgID, reqID: reqID}] = b
	d.failoverActuateMu.Unlock()
	return b
}

// disarmFailoverActuation drops a barrier that will never be actuated — used
// when ManualFailover fails to enqueue the demotion (no event will ever fire),
// and by waitFailoverActuated when its bounded wait expires. It does NOT close
// the channel: on the ManualFailover-error path no waiter can be blocked on it
// because the applied-ack path is not reached, and on the timeout path the
// waiter has already given up.
//
// b is the barrier the caller armed. The entry is removed only when it is
// still THAT barrier: a handle that has already been superseded by a re-arm
// must not evict the live one, which would leave the newer request's wait
// reading an empty slot and reporting the fence as actuated when it was not
// (#6177). A nil handle disarms nothing.
func (d *Daemon) disarmFailoverActuation(rgID int, reqID uint64, b *failoverActuation) {
	if b == nil {
		return
	}
	key := failoverActuationKey{rgID: rgID, reqID: reqID}
	d.failoverActuateMu.Lock()
	if d.failoverActuateWait[key] == b {
		delete(d.failoverActuateWait, key)
	}
	d.failoverActuateMu.Unlock()
}

// signalFailoverActuated marks rgID's demotion as actuated (VRRP resigned /
// rg_active cleared) and releases any waiter with a success verdict. Safe to
// call for every non-primary cluster event — an unarmed RG simply has no
// barrier to resolve.
func (d *Daemon) signalFailoverActuated(rgID int) {
	d.resolveFailoverActuation(rgID, nil)
}

// signalFailoverActuationFailed releases rgID's barrier with a FAILURE verdict:
// the demotion side effects did not land (e.g. the dataplane rejected the
// rg_active clear), so this node may still be forwarding for the RG. The waiter
// surfaces cause, the sync layer downgrades the applied-ack to failed, and the
// peer holds instead of promoting into a two-owner window (#6371). cause must
// be non-nil; a nil cause would be indistinguishable from success.
func (d *Daemon) signalFailoverActuationFailed(rgID int, cause error) {
	if cause == nil {
		cause = fmt.Errorf("redundancy group %d demotion not actuated", rgID)
	}
	d.resolveFailoverActuation(rgID, cause)
}

// resolveFailoverActuation completes every armed barrier for rgID exactly once
// with verdict cause (nil = actuated). The demotion event carries no request
// id, and the fact it reports — this node finished demoting rgID — answers the
// question every in-flight request for that RG is asking, so the verdict fans
// out across the RG's entries. It is idempotent: the resolved flag is set under
// the lock, so a second demotion event for the same RG is a no-op and never
// double-closes. The verdict is written BEFORE the close, so any goroutine that
// observes the close also observes the verdict.
//
// A resolved barrier is left in the map rather than deleted — waitFailoverActuated
// consumes it. Deleting here would make a resolution that lands before the
// waiter arrives read as "never armed", i.e. success, which would throw away
// exactly the failure verdict this path exists to deliver (#6371).
func (d *Daemon) resolveFailoverActuation(rgID int, cause error) {
	d.failoverActuateMu.Lock()
	var resolved []*failoverActuation
	for key, b := range d.failoverActuateWait {
		if key.rgID != rgID || b == nil || b.resolved {
			continue
		}
		b.resolved = true
		b.err = cause
		resolved = append(resolved, b)
	}
	d.failoverActuateMu.Unlock()
	for _, b := range resolved {
		close(b.done)
	}
}

// failFailoverActuation resolves ONE request's barrier with a failure verdict
// and LEAVES IT IN THE MAP for waitFailoverActuated to consume (#9036).
//
// It is the supersede path's replacement for disarmFailoverActuation. Both
// stop the misleading fence timeout #8000 was fixing; only this one keeps the
// distinction between "fenced" and "never happened" on the wire, because
// disarming makes waitFailoverActuated take its `b == nil` arm and return nil,
// which the ack path cannot tell from a real fence.
//
// Per-REQUEST, not per-RG, and that is the difference from
// resolveFailoverActuation. A demotion EVENT answers a question every in-flight
// request for the RG is asking, so its verdict fans out. A supersede is a fact
// about ONE request's generation check; failing a sibling request's barrier
// with it would discard the identity discipline #6177 exists to enforce.
//
// cause must be non-nil — a nil cause is indistinguishable from success, which
// is the defect this function exists to prevent.
func (d *Daemon) failFailoverActuation(rgID int, reqID uint64, b *failoverActuation, cause error) {
	if b == nil || cause == nil {
		return
	}
	key := failoverActuationKey{rgID: rgID, reqID: reqID}
	d.failoverActuateMu.Lock()
	fire := d.failoverActuateWait[key] == b && !b.resolved
	if fire {
		b.resolved = true
		b.err = cause
	}
	d.failoverActuateMu.Unlock()
	if fire {
		close(b.done)
	}
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
// Both are now errors, so the ack downgrades to `failed` and the peer HOLDS.
// The trade is deliberate and asymmetric: holding costs a failover attempt,
// while the previous default cost the one-owner-per-RG property (#5640).
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

// noteFailoverVerdictConsumed records that this request's verdict was taken.
// The caller holds failoverActuateMu.
func (d *Daemon) noteFailoverVerdictConsumedLocked(key failoverActuationKey) {
	if d.failoverActuateConsumed == nil {
		d.failoverActuateConsumed = make(map[failoverActuationKey]struct{})
	}
	if _, dup := d.failoverActuateConsumed[key]; dup {
		return
	}
	if len(d.failoverActuateConsumedOrder) >= failoverConsumedCap {
		oldest := d.failoverActuateConsumedOrder[0]
		d.failoverActuateConsumedOrder = d.failoverActuateConsumedOrder[1:]
		delete(d.failoverActuateConsumed, oldest)
	}
	d.failoverActuateConsumed[key] = struct{}{}
	d.failoverActuateConsumedOrder = append(d.failoverActuateConsumedOrder, key)
}

// waitFailoverActuated blocks until the local demotion for the (rgID, reqID)
// transfer-out has been resolved (barrier closed by signalFailoverActuated /
// -Failed) or the bounded timeout elapses. A nil barrier means the request was
// never armed (or an earlier waiter already consumed the verdict) — return
// immediately. It returns nil only when the demotion actually actuated: a
// failed actuation surfaces its cause (#6371) and a barrier that never resolves
// surfaces a timeout. This gates the remote-failover applied-ack so the peer
// never promotes into a two-owner window (#5640).
func (d *Daemon) waitFailoverActuated(rgID int, reqID uint64) error {
	key := failoverActuationKey{rgID: rgID, reqID: reqID}
	d.failoverActuateMu.Lock()
	b := d.failoverActuateWait[key]
	d.failoverActuateMu.Unlock()
	if b == nil {
		// #9259: absence of a barrier is NOT proof of fencing. Distinguish the
		// two ways to get here so the operator-facing reason is the true one;
		// both downgrade the ack identically.
		d.failoverActuateMu.Lock()
		_, consumed := d.failoverActuateConsumed[key]
		d.failoverActuateMu.Unlock()
		if consumed {
			return fmt.Errorf("redundancy group %d request %d: %w", rgID, reqID,
				ErrFailoverVerdictConsumed)
		}
		return fmt.Errorf("redundancy group %d request %d: %w", rgID, reqID,
			ErrFailoverNeverArmed)
	}
	timeout := d.failoverActuateTimeout
	if timeout <= 0 {
		timeout = 3 * time.Second
	}
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case <-b.done:
		// Consume the resolved barrier: this waiter owns the verdict, and
		// leaving it behind would let a later wait re-read a stale one.
		d.failoverActuateMu.Lock()
		err := b.err
		if d.failoverActuateWait[key] == b {
			delete(d.failoverActuateWait, key)
			// #9259: remember that this request's verdict was taken, so a
			// second wait reports "already consumed" rather than the
			// indistinguishable "never armed" — and, before this change,
			// rather than nil.
			d.noteFailoverVerdictConsumedLocked(key)
		}
		d.failoverActuateMu.Unlock()
		return err
	case <-timer.C:
		// Drop the stranded barrier so a later actuation event does not
		// close an orphaned channel that no one reads. Identity-checked, so
		// this expiry cannot disturb another request's live barrier (#6177).
		d.disarmFailoverActuation(rgID, reqID, b)
		return fmt.Errorf("timed out waiting for local fence actuation of redundancy group %d", rgID)
	}
}

// vipReleaseBarrier is the completion surface awaitRethVIPRelease waits on:
// *vrrp.ResignBarrier in production. Taking the interface rather than the
// concrete type is what lets the deferred-verdict wiring be driven in a unit
// test without real VRRP instances and live netlink.
type vipReleaseBarrier interface {
	// Done closes once every targeted VRRP instance has released its VIPs.
	Done() <-chan struct{}
	// Err is the release verdict, valid once Done has closed.
	Err() error
}

// resignRethRG drives the RETH VRRP resignation for rgID and returns the
// barrier that completes when the virtual addresses are actually off the
// interface (#6177 item 1). A nil return means there is nothing to wait for and
// the caller resolves its fence immediately — the pre-#6177 behaviour, which is
// correct only when no RETH VIP tenure exists to release.
//
// resignRethRGFn is the unit-test seam; production leaves it nil.
func (d *Daemon) resignRethRG(rgID int) vipReleaseBarrier {
	if d.resignRethRGFn != nil {
		return d.resignRethRGFn(rgID)
	}
	if d.vrrpMgr == nil {
		return nil
	}
	return d.vrrpMgr.ResignRG(rgID)
}

// rethVIPReleaseTimeout bounds awaitRethVIPRelease. VIP removal is a handful of
// netlink deletes on the VRRP instance goroutine — sub-millisecond in practice,
// and the whole RETH failover budget is ~60ms — so anything approaching this
// bound means the run loop is not making progress (wedged, or retired between
// the arm and the release). It is deliberately far BELOW failoverActuateTimeout
// (3s) so the peer-facing verdict names the VIP release as the thing that did
// not happen instead of surfacing as a generic barrier timeout, and far below
// the initiator's 20s ack timeout so the ack is a decision, not a hang.
const rethVIPReleaseTimeout = 500 * time.Millisecond

// awaitRethVIPRelease resolves rgID's fence barrier on the ACTUAL removal of the
// RETH virtual addresses (#6177 item 1).
//
// #5640 withheld the remote-failover applied-ack until the local demotion was
// actuated, but on the RETH-VRRP path "actuated" meant ResignRG had returned:
// priority-0 written (synchronously — so the resigning node cannot win a
// re-election) and a non-blocking resignCh send performed. The advert burst and
// the becomeBackup VIP removal still ran afterwards on the instance goroutine,
// so the peer could promote — add VIPs, GARP — while this node's addresses were
// still on the interface. A sub-millisecond two-owner residual, but a real one,
// and the reason this issue carries the security label. Direct-VIP mode
// (no-reth-vrrp) never had the gap: reconcileDirectVIPOwnership removes the
// addresses inline on this goroutine.
//
// A failed release, and an expiry, both resolve the barrier with a FAILURE
// verdict: the sync layer downgrades the applied-ack to failed and the peer
// HOLDS rather than promoting into a window where both nodes answer for the
// VIP. That is the safe direction — a held failover is recoverable, a
// duplicate-address window is not — and it is not the common case: a VRRP
// instance that is already BACKUP consumes the resign token on its next loop
// hop and reports a clean release, and an RG with no RETH instances at all
// yields a barrier that is born complete.
func (d *Daemon) awaitRethVIPRelease(rgID int, barrier vipReleaseBarrier) {
	timeout := d.rethVIPReleaseTimeout
	if timeout <= 0 {
		timeout = rethVIPReleaseTimeout
	}
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case <-barrier.Done():
		if err := barrier.Err(); err != nil {
			d.signalFailoverActuationFailed(rgID, fmt.Errorf(
				"redundancy group %d RETH virtual addresses not released on demotion: %w", rgID, err))
			return
		}
		d.signalFailoverActuated(rgID)
	case <-timer.C:
		d.signalFailoverActuationFailed(rgID, fmt.Errorf(
			"timed out after %s waiting for redundancy group %d RETH virtual addresses to be released",
			timeout, rgID))
	}
}

// waitFailoverActuatedBatch blocks until every RG in the batch transfer-out
// reqID has been fenced, or returns the first RG's failure verdict (#5640).
func (d *Daemon) waitFailoverActuatedBatch(rgIDs []int, reqID uint64) error {
	for _, rgID := range rgIDs {
		if err := d.waitFailoverActuated(rgID, reqID); err != nil {
			return err
		}
	}
	return nil
}

// isRethMasterState returns true when ALL VRRP instances for rgID are MASTER.
// Returns false if no instances exist for the RG.
func (d *Daemon) isRethMasterState(rgID int) bool {
	return d.getOrCreateRGState(rgID).AllVRRPMaster()
}

// isAnyRethInstanceMaster returns true if ANY VRRP instance for rgID is
// MASTER. Used by the cluster event handler to defer rg_active deactivation
// until all VRRP instances have transitioned to BACKUP.
func (d *Daemon) isAnyRethInstanceMaster(rgID int) bool {
	return d.getOrCreateRGState(rgID).AnyVRRPMaster()
}

// snapshotRethMasterState returns per-RG master state derived from all
// per-instance entries. An RG is MASTER only when ALL its instances are MASTER.
func (d *Daemon) snapshotRethMasterState() map[int]bool {
	d.rgStatesMu.RLock()
	defer d.rgStatesMu.RUnlock()
	out := make(map[int]bool, len(d.rgStates))
	for rgID, s := range d.rgStates {
		out[rgID] = s.IsActive()
	}
	return out
}

func (d *Daemon) watchClusterEvents(ctx context.Context) {
	// Debounce VRRP updates: coalesce rapid cluster events into a single
	// UpdateInstances call. Without this, every heartbeat-driven state change
	// triggers a separate update before priorities settle.
	var vrrpTimer *time.Timer
	defer func() {
		if vrrpTimer != nil {
			vrrpTimer.Stop()
		}
	}()

	for {
		select {
		case <-ctx.Done():
			return
		case ev := <-d.cluster.Events():
			vrrpTimer = d.handleClusterEvent(ctx, ev, vrrpTimer)
		}
	}
}

// handleClusterEvent applies one cluster state-change event: it drives
// rg_active through the unified rgStateMachine, orders the VRRP and blackhole
// side effects around that write, and releases the #5640 fence barrier on a
// demotion.
//
// vrrpTimer is the caller's in-flight VRRP-priority debounce timer (nil when
// none is armed); the possibly re-armed timer is returned so watchClusterEvents
// keeps exactly one pending update and can stop it on exit. Split out of the
// select loop so the handling is reachable from a test without an injectable
// cluster event channel (cluster.Manager only exposes a receive-only Events()).
func (d *Daemon) handleClusterEvent(ctx context.Context, ev cluster.ClusterEvent, vrrpTimer *time.Timer) *time.Timer {
	noRethVRRP := d.isNoRethVRRP()

	// Dual-active winner reaffirm: no state change but send
	// GARPs to refresh upstream ARP/NDP caches after split-brain.
	if ev.DualActiveWin && noRethVRRP {
		d.scheduleDirectAnnounce(ev.GroupID, "dual-active-win")
		return vrrpTimer
	}

	// Update rg_active through unified state machine.
	//
	// Both cluster and VRRP events funnel through rgStateMachine
	// which determines rg_active = clusterPri || anyVrrpMaster.
	// This prevents the dual-inactive window (both nodes
	// rg_active=false during failover) and eliminates the race
	// between the two independent goroutine writers.
	//
	// Transition ordering safety:
	// - Activation: set rg_active FIRST, then remove blackholes,
	//   then trigger VRRP MASTER (#485). Neighbor readiness is
	//   maintained continuously in the background.
	// - Deactivation: run preflight FIRST, then resign VRRP,
	//   add blackholes, then clear rg_active (#485)
	isPrimary := ev.NewState == cluster.StatePrimary
	clusterDemotionEdge := ev.OldState == cluster.StatePrimary && !isPrimary
	d.setLocalFailoverCommitReady(ev.GroupID, false)
	s := d.getOrCreateRGState(ev.GroupID)
	tr := s.SetCluster(isPrimary)
	if isPrimary {
		// Activation: enable forwarding first.
		// Re-read desired state to guard against a
		// concurrent VRRP goroutine that may have
		// already superseded this transition.
		if rt := d.dataplane(); tr.Changed && rt != nil {
			cur, _ := s.CurrentDesired()
			if err := rt.HA().SetRGActive(ctx, ev.GroupID, cur); err != nil {
				slog.Warn("failed to update rg_active from cluster event",
					"rg", ev.GroupID, "active", cur, "err", err)
			} else {
				recordRGActiveAppliedIfCurrentOrStable(s, tr, cur)
			}
		}
		// Only remove blackholes once this node's desired state is
		// actually active. In strict VIP ownership mode, a cluster
		// primary event alone does not activate the RG until VRRP
		// ownership has moved as well.
		if shouldRemoveBlackholesOnClusterPrimary(s) {
			d.removeBlackholeRoutes(ev.GroupID)
		}

		// VRRP priority + ForceRGMaster AFTER rg_active and
		// blackhole removal (#485).
		if !noRethVRRP {
			d.vrrpMgr.UpdateRGPriority(ev.GroupID, 200)
			// With preempt=false, VRRP won't self-elect even at
			// higher priority. Force MASTER since cluster state
			// is authoritative (e.g. after failover reset).
			// Only do this for intentional promotions (Secondary →
			// Primary), NOT on initial boot (SecondaryHold → Primary)
			// where VRRP should follow its own election timer.
			if ev.OldState == cluster.StateSecondary {
				d.vrrpMgr.ForceRGMaster(ev.GroupID)
			}
		}

		// no-reth-vrrp direct mode: reconcile VIP ownership from
		// actual cluster local/peer state, not just this rg_active
		// edge. This prevents stale VIPs from surviving a demotion
		// when the rg_state machine has already drifted inactive.
		if noRethVRRP {
			d.reconcileDirectVIPOwnership(ev.GroupID, "cluster-primary")
			go d.RefreshFabricFwd()
		}
		if noRethVRRP && d.cluster != nil && d.cluster.IsLocalPrimary(ev.GroupID) && (d.dataplane() == nil || !s.NeedsApply()) {
			d.setLocalFailoverCommitReady(ev.GroupID, true)
		}
	} else {
		// Demotion: run preflight and resign VRRP BEFORE
		// clearing rg_active (#485). The preflight shifts
		// userspace flow cache entries to FabricRedirect so
		// the demoting node forwards via fabric during the
		// transition window. ResignRG must follow preflight
		// so traffic is already on the fabric path before
		// the VRRP BACKUP transition removes VIPs.
		if clusterDemotionEdge && d.dataplane() != nil {
			d.tryPrepareUserspaceRGDemotion(ev.GroupID)
		}
		// #6177 item 1: capture the RETH resign barrier so the fence verdict
		// below can be released on the VIPs actually leaving the interface,
		// not merely on the resignation having been signalled.
		var rethResign vipReleaseBarrier
		if !noRethVRRP {
			if ev.OldState == cluster.StatePrimary &&
				(ev.NewState == cluster.StateSecondary || ev.NewState == cluster.StateSecondaryHold) {
				rethResign = d.resignRethRG(ev.GroupID)
			}
		}
		// Deactivation: blackhole routes first (if transitioning
		// to inactive), then clear rg_active.
		if tr.Changed && !tr.Active {
			d.injectBlackholeRoutes(ev.GroupID)
		}
		// #6371: track whether the dataplane accepted the demotion write.
		// A failed rg_active update means this node may still be forwarding
		// for the RG, so the fence below must NOT report actuation.
		var actuateErr error
		if rt := d.dataplane(); tr.Changed && rt != nil {
			cur, _ := s.CurrentDesired()
			if !cur && !clusterDemotionEdge {
				d.tryPrepareUserspaceRGDemotion(ev.GroupID)
			}
			if err := rt.HA().SetRGActive(ctx, ev.GroupID, cur); err != nil {
				slog.Warn("failed to update rg_active from cluster event",
					"rg", ev.GroupID, "active", cur, "err", err)
				actuateErr = fmt.Errorf("redundancy group %d rg_active=%v not applied on demotion: %w",
					ev.GroupID, cur, err)
			} else {
				recordRGActiveAppliedIfCurrentOrStable(s, tr, cur)
			}
		}

		// no-reth-vrrp direct mode: always reconcile actual VIP
		// ownership on non-primary transitions. Removal must not
		// depend on a fresh rg_active edge because stale VIPs can
		// survive a failback if the state machine already drifted.
		if noRethVRRP {
			d.reconcileDirectVIPOwnership(ev.GroupID, "cluster-secondary")
		}

		// #5640: the local demotion is now actuated — VRRP has
		// resigned to priority-0 (or direct VIP ownership was
		// reconciled away) and rg_active is cleared. Release any
		// remote-failover applied-ack that is holding for this fence
		// so the peer only promotes AFTER this node stopped owning
		// the RG. Fires for every non-primary edge; unarmed RGs no-op.
		//
		// #6371: when the rg_active write above FAILED, the fence did not
		// complete — resolve the barrier with that error instead, so the
		// applied-ack downgrades to failed and the peer holds rather than
		// promoting into a two-owner window. Reporting the failure (rather
		// than staying silent) keeps the waiter from burning its full
		// timeout on a fence that is already known not to have landed.
		//
		// #6177 item 1: on the RETH-VRRP path the VIP removal runs on the VRRP
		// instance goroutine, so at this point the resignation is only
		// SIGNALLED (priority-0 is set synchronously, the addresses are not yet
		// off the wire). Hand the verdict to awaitRethVIPRelease, which resolves
		// the barrier from the release itself. It runs on its own goroutine
		// because handleClusterEvent serialises every cluster event — blocking
		// here would stall unrelated RGs' state changes behind one VIP removal.
		switch {
		case actuateErr != nil:
			d.signalFailoverActuationFailed(ev.GroupID, actuateErr)
		case rethResign != nil:
			go d.awaitRethVIPRelease(ev.GroupID, rethResign)
		default:
			d.signalFailoverActuated(ev.GroupID)
		}
	}

	// Strict VIP ownership: suppress GARP on secondary, allow on primary.
	// Not applicable with no-reth-vrrp (no VRRP instances).
	if !noRethVRRP && s.IsStrictVIPOwnership() {
		d.vrrpMgr.SetGARPSuppression(ev.GroupID, !isPrimary)
	}

	// Debounced VRRP priority update — 500ms coalesce window.
	// Skipped in no-reth-vrrp mode (no RETH VRRP instances to update).
	if !noRethVRRP {
		if vrrpTimer != nil {
			vrrpTimer.Stop()
		}
		// #5250 (A7-b1 F4): the debounce closure CAPTURES the managers it uses
		// and checks the stop signal before touching them. It used to read
		// d.store / d.cluster / d.vrrpMgr through the receiver at FIRE time,
		// 500ms after arming, and the only thing stopping it is
		// watchClusterEvents' deferred vrrpTimer.Stop() — which for an AfterFunc
		// timer does not wait for a body that has already begun. So the
		// last-armed update could run during or after the shutdown that stopped
		// it, re-reading fields the teardown was tearing down.
		//
		// The stop signal is d.applyCancelCtx(), NOT this function's ctx: the
		// watcher runs as watchClusterEvents(d.daemonCtx) and daemonCtx is
		// context.Background() in production (see its field comment), so gating
		// on ctx would be a branch that can never be taken. The channel is read
		// on the watcher goroutine at ARM time so the field read cannot race
		// the timer.
		stopCh := d.applyCancelCtx().Done()
		clusterRef, storeRef, vrrpRef := d.cluster, d.store, d.vrrpMgr
		vrrpTimer = time.AfterFunc(500*time.Millisecond, func() {
			select {
			case <-stopCh:
				return
			default:
			}
			if clusterRef == nil || storeRef == nil || vrrpRef == nil {
				return
			}
			if cfg := storeRef.ActiveConfig(); cfg != nil {
				localPri := clusterRef.LocalPriorities()
				var all []*vrrp.Instance
				all = append(all, vrrp.CollectInstances(cfg)...)
				all = append(all, vrrp.CollectRethInstances(cfg, localPri)...)
				if err := vrrpRef.UpdateInstances(all); err != nil {
					slog.Warn("cluster: failed to update VRRP instances", "err", err)
				}
			}
		})
	}

	// RG0-specific: config ownership, plus the RG0 half of IPsec SA
	// re-initiation. #9139: the DATA-RG half lives in applyRethServicesForRG,
	// and each leg is scoped by ownsIPsecConn to the connections whose external
	// interface belongs to an RG this node owns — so the two do not overlap and
	// neither initiates the other's tunnels.
	if ev.GroupID == 0 {
		d.applyRG0OwnershipTransition(ev.NewState)
	}
	return vrrpTimer
}

// reconcileRG0ConfigOwnership re-derives the config-store read-only gate from
// RG0's authoritative state, correcting a divergence a dropped event left
// behind (#6889).
//
// THE PROBLEM IT SOLVES. SetClusterReadOnly is the authority boundary for who
// may write config in a cluster, and its only production driver was the RG0
// TRANSITION handler, reached from the event consumer. Manager.sendEvent is
// non-blocking and drops on a full channel, so the boundary's state could
// diverge from the state that decides it:
//
//   - drop a PROMOTION and the node reports RG0 primary (IsLocalPrimary(0)
//     passes, gRPC admits the operator) while the store still refuses writes
//     with ErrClusterReadOnly. The operator sees a node that claims to own
//     config and will not be configured, and the only trace is a slog.Warn
//     about a full channel that never mentions config ownership;
//   - drop a DEMOTION and it diverges the other way, which fails OPEN.
//
// Neither self-heals: nothing re-drove the gate until the NEXT RG0 transition,
// so a single burst of events could strand a node indefinitely. The
// dropped-event fallback (triggerReconcile -> reconcileRGState) did generic RG
// work and never touched this gate.
//
// WHY IT RE-DRIVES THE TRANSITION HANDLER instead of calling SetClusterReadOnly
// directly. The gate is not the handler's only consequence: promotion also
// reconciles config-sync to the peer, re-initiates synced IPsec SAs and nudges
// DHCP lease-sync, and demotion CONFIRMS a pending commit-confirmed before
// going read-only (#4378) so its rollback timer cannot fire on the demoted
// standby and diverge from the peer. A dropped event skipped all of those, not
// just the gate. Setting the bit alone would paper over the symptom this issue
// names while leaving the rest of the transition unapplied — so the correction
// runs the SAME code path the event would have, and there is exactly one
// implementation of what an RG0 ownership change means.
//
// IT IS SILENT WHEREVER THE EVENT HANDLER IS SILENT. Only StatePrimary,
// StateSecondary and StateSecondaryHold drive the gate, because those are the
// only cases applyRG0OwnershipTransition acts on. StateLost and StateDisabled
// are left exactly as they are: inventing a gate decision for a state the
// transition path never decided would be new behaviour arriving through a
// recovery mechanism, which is the wrong place to introduce it.
//
// A no-op when the gate already agrees, so the 2s loop costs one comparison.
func (d *Daemon) reconcileRG0ConfigOwnership() {
	if d.cluster == nil || d.store == nil {
		return
	}
	rg0 := d.cluster.GroupState(0)
	if rg0 == nil {
		// No RG0 in this config — nothing owns the gate, so nothing to
		// reconcile. Not the same as "RG0 exists and is secondary".
		return
	}

	var wantReadOnly bool
	switch rg0.State {
	case cluster.StatePrimary:
		wantReadOnly = false
	case cluster.StateSecondary, cluster.StateSecondaryHold:
		wantReadOnly = true
	default:
		return
	}
	if d.store.ClusterReadOnly() == wantReadOnly {
		return
	}

	slog.Warn("cluster: config read-only gate disagreed with RG0 state — correcting. "+
		"An RG0 transition event was almost certainly dropped (see the "+
		"\"event channel full\" warning); the node would otherwise have stayed in "+
		"this split state until the next transition.",
		"rg0_state", rg0.State.String(), "store_read_only_was", !wantReadOnly,
		"issue", "#6889")
	d.applyRG0OwnershipTransition(rg0.State)
}

// applyRG0OwnershipTransition reacts to a RG0 ownership change: it toggles the
// store's cluster read-only gate (whose INTENT is that only the RG0 primary
// writes config -- this function is the only thing that arms it, so a node that
// never transitions is not gated at all; see pkg/cluster/README.md "Recovery"
// and #6890) and, on promotion, re-initiates synced IPsec SAs and nudges DHCP
// lease-sync.
//
// #4378: on DEMOTION it also confirms any in-flight `commit confirmed` window
// BEFORE going read-only. The committing node had already pushed the committed
// config to the peer (now RG0 primary) via config-sync
// (commitConfirmedAndApply -> applyAndSyncCommitted -> pushCommittedConfigToPeer),
// so the primary is running that config. Confirming keeps both nodes on it.
// Without this, the armed rollback timer would still fire on the demoted
// standby (PromoteRollback carries no read-only guard), reverting its
// store+dataplane to the pre-confirm tree while the primary keeps the commit —
// config divergence that surfaces at the next failover.
func (d *Daemon) applyRG0OwnershipTransition(newState cluster.NodeState) {
	switch newState {
	case cluster.StatePrimary:
		slog.Info("cluster: became primary for RG0, enabling config writes")
		d.store.SetClusterReadOnly(false)

		// #5863: becoming the RG0 config authority is a desired-state change.
		// A peer that connected while this node was secondary had its config
		// push skipped by the connect edge; now that this node owns config,
		// reconcile so the connected peer receives the authoritative config
		// once (level-triggered, RG0-gated, deduped per epoch/generation) —
		// instead of waiting for an unrelated commit/reconnect.
		d.reconcileConfigSyncToPeer("rg0-promotion")

		// On failover to primary: re-initiate synced IPsec SAs.
		if cc := d.clusterConfig(); cc != nil && cc.IPsecSASync && d.ipsec != nil && d.getSessionSync() != nil {
			go d.reinitiateIPsecSAs()
		}

		// #2239: on failover to primary, nudge the lease-sync push loop so
		// this node begins replicating its (now owned) lease set. The actual
		// Kea pre-seed + post-start lease-add seed are tied to the per-RG Kea
		// start in applyRethServicesForRG (where Kea is restarted on the VRRP
		// MASTER transition).
		if cc := d.clusterConfig(); cc != nil && cc.DHCPLeaseSync && d.dhcpServer != nil && d.getSessionSync() != nil {
			d.nudgeDHCPLeaseSync()
		}

	case cluster.StateSecondary, cluster.StateSecondaryHold:
		slog.Info("cluster: became secondary for RG0, disabling config writes")
		// #4378: confirm any pending commit-confirmed before going read-only
		// so its rollback timer does not fire on the demoted standby and
		// diverge from the peer that holds the synced committed config.
		if d.store.ConfirmPendingOnDemotion() {
			slog.Info("cluster: confirmed pending commit-confirmed on RG0 demotion")
		}
		d.store.SetClusterReadOnly(true)
	}
}

// rethVRIDBase is the VRRP GroupID offset for RETH instances.
// RETH instances use GroupID = rethVRIDBase + rgID (set in pkg/vrrp/vrrp.go).
// Standalone VRRP may use any valid VRID, including this numeric range, so
// event classification must also require the empty-family RETH marker.
const rethVRIDBase = 100

// isRethVRID reports whether a VRID is in the numeric RETH convention range;
// it is not sufficient to classify an event without the Family marker.
func isRethVRID(vrid int) bool {
	return vrid >= rethVRIDBase
}

// rgIDFromVRID extracts the redundancy group ID from a VRRP group ID.
// VRID = rethVRIDBase + RG ID (set in pkg/vrrp/vrrp.go).
func rgIDFromVRID(vrid int) int {
	return vrid - rethVRIDBase
}

// isRethVRRPEvent identifies events from the implicit cluster/RETH collector.
// Generic standalone instances always carry inet/inet6; RETH instances leave
// Family empty. The family guard prevents a valid standalone VRID in the
// numeric 100+RG range from driving cluster ownership state (#5083).
func isRethVRRPEvent(ev vrrp.VRRPEvent) bool {
	return ev.Family == "" && isRethVRID(ev.GroupID)
}

// watchVRRPEvents monitors VRRP state changes and logs transitions.
// On MASTER transition, updates rg_active, removes blackhole routes, and
// refreshes fabric forwarding. Neighbor readiness is maintained in the
// background by runPeriodicNeighborResolution / maintainClusterNeighborReadiness.
// Also starts/stops RA senders and Kea DHCP server per-RG — in
// active/active mode, a BACKUP event for RG1 must not clear services
// started for RG0.
func (d *Daemon) watchVRRPEvents(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case ev, ok := <-d.vrrpMgr.Events():
			if !ok {
				return
			}
			// Generic standalone instances carry an explicit address family;
			// implicit RETH instances deliberately leave Family empty. Family is
			// authoritative here because a valid standalone VRID may numerically
			// equal rethVRIDBase+RG and must not be commandeered by cluster
			// rg_active/blackhole control (#5083).
			if !isRethVRRPEvent(ev) {
				slog.Info("vrrp: standalone state change (non-RETH)",
					"interface", ev.Interface,
					"family", ev.Family,
					"group", ev.GroupID,
					"state", ev.State.String())
				continue
			}
			rgID := rgIDFromVRID(ev.GroupID)
			slog.Info("vrrp: state change",
				"interface", ev.Interface,
				"group", ev.GroupID,
				"rg", rgID,
				"state", ev.State.String())
			if ev.State == vrrp.StateMaster {
				s := d.getOrCreateRGState(rgID)
				tr := s.SetVRRP(ev.Interface, true)
				if rt := d.dataplane(); tr.Changed && tr.Active && rt != nil {
					// Activation order: set rg_active FIRST, then
					// remove blackhole routes. Re-read desired state
					// to guard against interleaved cluster goroutine.
					// Only activate when ALL VRRP instances in the RG
					// are MASTER — prevents partial ownership (#132).
					cur, _ := s.CurrentDesired()
					if err := rt.HA().SetRGActive(ctx, rgID, cur); err != nil {
						slog.Warn("failed to update rg_active", "rg", rgID, "err", err)
					} else {
						recordRGActiveAppliedIfCurrentOrStable(s, tr, cur)
					}
					go d.RefreshFabricFwd()
				}
				// Only remove blackholes and apply services when ALL
				// VRRP instances in the RG are MASTER (#132).
				if tr.Changed && tr.Active {
					d.removeBlackholeRoutes(rgID)
					d.addStableRethLinkLocal(rgID)
					d.applyRethServicesForRG(rgID)
				}
				if d.cluster != nil && d.cluster.IsLocalPrimary(rgID) && s.AllVRRPMaster() {
					d.setLocalFailoverCommitReady(rgID, true)
				}
			}
			if ev.State == vrrp.StateBackup {
				s := d.getOrCreateRGState(rgID)
				tr := s.SetVRRP(ev.Interface, false)
				if !s.AllVRRPMaster() {
					d.setLocalFailoverCommitReady(rgID, false)
				}
				if tr.Changed && !tr.Active {
					// Deactivation order: inject blackhole routes FIRST,
					// then clear rg_active. Re-read desired state to
					// guard against interleaved cluster goroutine.
					d.injectBlackholeRoutes(rgID)
					if rt := d.dataplane(); rt != nil {
						cur, _ := s.CurrentDesired()
						if !cur {
							d.tryPrepareUserspaceRGDemotion(rgID)
						}
						if err := rt.HA().SetRGActive(ctx, rgID, cur); err != nil {
							slog.Warn("failed to update rg_active", "rg", rgID, "err", err)
						} else {
							recordRGActiveAppliedIfCurrentOrStable(s, tr, cur)
						}
						go d.RefreshFabricFwd()
					}
					d.removeStableRethLinkLocal(rgID)
					d.clearRethServicesForRG(rgID)
				}
			}
		}
	}
}

// reconcileRGStateLoop periodically reads the authoritative cluster and VRRP
// states and reconciles rgStateMachine / rg_active BPF map / blackhole routes /
// VRRP posture / RA+DHCP services.
// This is the safety net for dropped events (non-blocking channel sends).
// Runs every 2s; also wakes immediately on event-drop notifications via
// reconcileNowCh. Skips if cluster or dataplane is nil.
func (d *Daemon) reconcileRGStateLoop(ctx context.Context) {
	// Run immediately on startup to correct stale rg_active from prior run.
	d.reconcileRGStatePass()

	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			d.reconcileRGStatePass()
		case <-d.reconcileNowCh:
			d.reconcileRGStatePass()
		}
	}
}

// reconcileRGStatePass runs one reconcile pass. In production it calls
// reconcileRGState; a non-nil reconcileTickHook (test-only, #5681) substitutes
// for it so the shutdown-ordering regression test can hold a pass in-flight and
// prove the loop is joined before HA ownership cleanup.
func (d *Daemon) reconcileRGStatePass() {
	if d.reconcileTickHook != nil {
		d.reconcileTickHook()
		return
	}
	d.reconcileRGState()
}

// triggerReconcile requests an immediate RG state reconciliation pass.
// Non-blocking: if a reconcile is already pending, the request is coalesced.
func (d *Daemon) triggerReconcile() {
	select {
	case d.reconcileNowCh <- struct{}{}:
	default:
	}
}

// reconcileVRRPInstances recomputes the desired VRRP instance set from the
// active config and re-drives vrrp.UpdateInstances (#2156, B1). It is the
// bounded self-recovery hook for the build-before-teardown ordering: a
// VIP-change restart that was deferred because a member interface was
// transiently down is retried here on the next reconcile tick once the
// interface returns. It mirrors the desired-set computation in applyConfig
// (collect standalone VRRP, then RETH VRRP when clustered) so the reconcile
// path and the commit path agree on the canonical instance set. Cheap no-op
// on a steady config. Nil-guards d.vrrpMgr / d.store so it is safe to call
// from reconcileRGState in minimal (test) daemon constructions.
func (d *Daemon) reconcileVRRPInstances() {
	if d.vrrpMgr == nil || d.store == nil {
		return
	}
	cfg := d.store.ActiveConfig()
	if cfg == nil {
		return
	}
	instances := vrrp.CollectInstances(cfg)
	if d.cluster != nil {
		localPri := d.cluster.LocalPriorities()
		instances = append(instances, vrrp.CollectRethInstances(cfg, localPri)...)
	}
	if err := d.vrrpMgr.UpdateInstances(instances); err != nil {
		slog.Warn("reconcile: failed to re-drive VRRP instances", "err", err)
	}
}

func shouldRemoveBlackholesOnClusterPrimary(s *rgStateMachine) bool {
	active, _ := s.CurrentDesired()
	return active
}

// expectedRethVRRPCounts returns the number of RETH VRRP instances the active
// config expects per redundancy group. It mirrors the desired-set computation
// in reconcileVRRPInstances / applyConfig (vrrp.CollectRethInstances) so the
// posture check and the instance builder agree on the canonical set. The
// posture check (CheckVRRPPosture, #5843) uses this to detect an
// expected-but-missing VRRP instance that the instantiated-only inventory
// (rgVRRP) cannot see — one MASTER instance plus one that failed to
// instantiate must not read as complete primary posture.
//
// Returns an empty map (all lookups yield 0 → posture falls back to the
// instantiated count) when config or cluster state is unavailable, or when
// no-reth-vrrp / private-rg-election disables RETH VRRP entirely (in which
// case CollectRethInstances returns nil and the posture check is skipped by
// the noRethVRRP guard in reconcileRGState anyway).
func (d *Daemon) expectedRethVRRPCounts() map[int]int {
	counts := make(map[int]int)
	if d.store == nil || d.cluster == nil {
		return counts
	}
	cfg := d.store.ActiveConfig()
	if cfg == nil {
		return counts
	}
	localPri := d.cluster.LocalPriorities()
	for _, inst := range vrrp.CollectRethInstances(cfg, localPri) {
		counts[rgIDFromVRID(inst.GroupID)]++
	}
	return counts
}

func (d *Daemon) reconcileRGState() {
	if d.cluster == nil || d.vrrpMgr == nil {
		return
	}

	// #6889: re-derive the config read-only gate from RG0's authoritative
	// state. Placed FIRST so no later early return in this function can skip
	// it — the gate is an authority boundary, not per-RG actuation.
	d.reconcileRG0ConfigOwnership()

	// #2114: ONE dataplane snapshot per reconcile pass (plan §5.3 rule 1),
	// shared across the per-RG actuation loop below — a mid-pass cell clear
	// must not let one RG actuate through the old backend while a later RG
	// observes nil and skips its deactivation (which could leave
	// rg_active=true set as the peer takes ownership). The userspace-active
	// mode check and the per-RG readiness/blackhole helpers are fed the
	// SAME snapshot (Codex PR #6743 r2-1 — no transitive per-RG reloads).
	reconcileDP := d.dataplane()
	reconcileDPUserspaceActive := d.userspaceDataplaneActiveFor(reconcileDP)

	// #2156 (B1): re-drive the VRRP instance set from the active config on
	// every reconcile pass. Combined with the build-before-teardown
	// ordering in vrrp.UpdateInstances, this gives bounded (~2s)
	// self-recovery: if a VIP-change restart was deferred because a member
	// interface was transiently down (carrier flap, mid-rename), the old
	// instance kept running and this pass re-attempts the swap once the
	// interface returns — no operator re-commit needed. On a steady config
	// this is a cheap no-op (UpdateInstances' no-change paths continue;
	// priority-only deltas hit the in-place updateConfig path, never a
	// restart, so it cannot cause a restart storm).
	d.reconcileVRRPInstances()

	// Read authoritative VRRP instance states.
	vrrpStates := d.vrrpMgr.InstanceStates()

	// Build per-RG VRRP state map: rgID → { iface → isMaster }. Generic
	// standalone instances carry Family and are excluded even when their VRID
	// falls in the numeric 100+RG range (#5083).
	rgVRRP := make(map[int]map[string]bool)
	for _, ev := range vrrpStates {
		if !isRethVRRPEvent(ev) {
			continue
		}
		rgID := rgIDFromVRID(ev.GroupID)
		if rgVRRP[rgID] == nil {
			rgVRRP[rgID] = make(map[string]bool)
		}
		rgVRRP[rgID][ev.Interface] = (ev.State == vrrp.StateMaster)
	}

	// Expected RETH VRRP instance count per RG, derived from the active
	// config (#5843). rgVRRP above only sees instances that actually
	// instantiated, so an instance that failed to come up is invisible and
	// the posture check would read "all present are MASTER" as complete
	// primary posture. Passing the expected count to CheckVRRPPosture lets
	// it detect an expected-but-missing instance (partial ownership).
	expectedVRRP := d.expectedRethVRRPCounts()

	// Collect all known RG IDs from three sources:
	// 1) existing rgStates (event-driven)
	// 2) cluster-configured groups (may exist before VRRP fires)
	// 3) RETH VRRP instances (may exist before cluster events)
	seen := make(map[int]bool)
	d.rgStatesMu.RLock()
	for rgID := range d.rgStates {
		seen[rgID] = true
	}
	d.rgStatesMu.RUnlock()
	for _, gs := range d.cluster.GroupStates() {
		seen[gs.GroupID] = true
	}
	for rgID := range rgVRRP {
		seen[rgID] = true
	}
	rgIDs := make([]int, 0, len(seen))
	for rgID := range seen {
		rgIDs = append(rgIDs, rgID)
	}

	// Evaluate per-RG readiness for the takeover gate.
	noRethVRRP := d.isNoRethVRRP()

	// Check fabric readiness — only relevant when peer is alive.
	fabricReady := true
	if d.cluster.PeerAlive() {
		d.fabricMu.RLock()
		fp := d.fabricPopulated
		d.fabricMu.RUnlock()
		if !fp {
			d.triggerFabricRefresh()
			fabricReady = false
		}
	}

	if mon := d.cluster.Monitor(); mon != nil {
		for _, rgID := range rgIDs {
			ifReady, ifReasons := mon.RGInterfaceReady(rgID)
			ready, reasons := d.takeoverReadinessForRG(reconcileDP, rgID, ifReady, ifReasons, fabricReady, noRethVRRP)
			d.cluster.SetRGReady(rgID, ready, reasons)
		}
	}

	// anyRGChanged collects per-RG transitions so the #1827
	// ip-monitoring HA gating (primary-only probes + overlay
	// publication) re-evaluates exactly once per reconcile pass.
	anyRGChanged := false

	for _, rgID := range rgIDs {
		clusterPri := d.cluster.IsLocalPrimary(rgID)
		vrrp := rgVRRP[rgID] // may be nil if no VRRP instances for this RG
		if vrrp == nil {
			vrrp = make(map[string]bool)
		}

		s := d.getOrCreateRGState(rgID)
		tr := s.Reconcile(clusterPri, vrrp)

		// Desired-vs-applied retry: even if the state machine didn't
		// change this pass, a prior UpdateRGActive failure may have
		// left applied != desired. Retry unconditionally.
		needsApply := tr.Changed || s.NeedsApply()
		if needsApply && reconcileDP != nil {
			if tr.Changed {
				slog.Info("reconcile: correcting rg_active drift",
					"rg", rgID, "active", tr.Active, "epoch", tr.Epoch)
			} else if s.ShouldLogRetry() {
				// #757: only log retry once per apply streak; subsequent
				// ticks stay silent until MarkApplied() clears the gate.
				slog.Info("reconcile: retrying rg_active apply",
					"rg", rgID, "active", tr.Active)
			}
			if tr.Active {
				// Activation ordering: set rg_active FIRST, then
				// remove blackholes.
				if err := reconcileDP.HA().SetRGActive(context.Background(), rgID, true); err != nil {
					if s.ShouldLogApplyError(err.Error()) {
						slog.Warn("reconcile: failed to update rg_active",
							"rg", rgID, "active", true, "err", err)
					}
				} else if recordRGActiveAppliedIfCurrentOrStable(s, tr, true) {
					// #6799: the record is CONDITIONAL. This arm used to call
					// MarkApplied unconditionally on a value captured before the
					// lock dropped, so a fence that re-armed the retry debt while
					// SetRGActive was in flight had its debt erased and the RG
					// never re-drove. The readiness flag below is inside the
					// accepted branch for the same reason: it gates a PEER
					// FAILOVER COMMIT (waitLocalFailoverCommitReady), so it must
					// never be raised off a convergence the machine refused.
					if noRethVRRP && clusterPri && !s.NeedsApply() {
						d.setLocalFailoverCommitReady(rgID, true)
					}
				} else {
					slog.Warn("reconcile: rg_active write completed but the state machine REFUSED "+
						"to record it (another writer re-armed the retry, or the desired state "+
						"moved); leaving the retry armed so the next pass re-drives",
						"rg", rgID, "active", true)
				}
			} else {
				// Deactivation ordering: blackholes FIRST, then
				// clear rg_active.
				d.injectBlackholeRoutesFor(reconcileDPUserspaceActive, rgID)
				d.tryPrepareUserspaceRGDemotion(rgID)
				if err := reconcileDP.HA().SetRGActive(context.Background(), rgID, false); err != nil {
					if s.ShouldLogApplyError(err.Error()) {
						slog.Warn("reconcile: failed to update rg_active",
							"rg", rgID, "active", false, "err", err)
					}
				} else {
					// The deactivation readiness flag is cleared unconditionally:
					// lowering readiness is always safe, and must not depend on
					// whether the convergence record was accepted (#6799).
					d.setLocalFailoverCommitReady(rgID, false)
					if !recordRGActiveAppliedIfCurrentOrStable(s, tr, false) {
						slog.Warn("reconcile: rg_active write completed but the state machine "+
							"REFUSED to record it (another writer re-armed the retry, or the "+
							"desired state moved); leaving the retry armed so the next pass "+
							"re-drives",
							"rg", rgID, "active", false)
					}
				}
			}
		}

		// Declarative blackhole route reconciliation: assert the route
		// set that should exist regardless of prior transition results.
		// Active RGs should NOT have blackholes; inactive RGs SHOULD.
		if tr.Active {
			d.removeBlackholeRoutesFor(reconcileDPUserspaceActive, rgID)
		} else {
			d.injectBlackholeRoutesFor(reconcileDPUserspaceActive, rgID)
		}

		// VRRP posture reconciliation (#86): detect sustained mismatch
		// between cluster state and VRRP state. Only act after 10s+
		// continuous mismatch to avoid fighting transient states (VRRP
		// sync-hold, election timers, hitless restart). Skip entirely
		// during sync-hold when VRRP is intentionally suppressing preempt.
		// Also skip when no-reth-vrrp is active (no RETH VRRP instances).
		//
		// NeedsMaster: only re-send priority update — do NOT call
		// ForceRGMaster here. ForceRGMaster overrides preempt=false,
		// which should only happen from explicit cluster operations
		// (Secondary→Primary in watchClusterEvents). After a reboot
		// the transition is SecondaryHold→Primary, which intentionally
		// skips ForceRGMaster so VRRP respects non-preempt config.
		// The priority update fixes the dropped-event case (#86) while
		// letting VRRP's preempt logic decide whether to transition.
		if d.vrrpMgr != nil && !d.vrrpMgr.InSyncHold() && !noRethVRRP {
			switch s.CheckVRRPPosture(time.Now(), expectedVRRP[rgID]) {
			case vrrpPostureNeedsMaster:
				slog.Warn("reconcile: VRRP posture mismatch — cluster=primary but VRRP!=MASTER, re-sending priority",
					"rg", rgID)
				d.vrrpMgr.UpdateRGPriority(rgID, 200)
			case vrrpPostureNeedsResign:
				slog.Warn("reconcile: VRRP posture mismatch — cluster=secondary but VRRP=MASTER, resigning",
					"rg", rgID)
				d.vrrpMgr.ResignRG(rgID)
			}
		}

		// Direct-mode VIP safety net: reconcile desired ownership on every
		// pass from actual cluster state so stale VIPs are removed even if
		// the rg_state machine already thinks the RG is inactive.
		if noRethVRRP {
			d.reconcileDirectVIPOwnership(rgID, "reconcile")
		}

		// RA/DHCP service reconciliation (#93): safety net for dropped
		// VRRP events that should have started or stopped per-RG services.
		// Services (RA/DHCP) only start/stop on actual state change to
		// avoid thrashing restarts every reconcile tick.
		if tr.Changed {
			if tr.Active {
				d.applyRethServicesForRG(rgID)
			} else {
				d.clearRethServicesForRG(rgID)
			}
			anyRGChanged = true
		}
		// Stable link-local: ensure correct on EVERY reconcile tick.
		// The kernel preserves NODAD addresses across daemon restarts,
		// so stale addresses can exist without a state transition.
		// Direct mode owns this inside reconcileDirectVIPOwnership();
		// VRRP mode keeps the legacy per-tick add/remove behavior here.
		if !noRethVRRP {
			if tr.Active {
				d.addStableRethLinkLocal(rgID)
			} else {
				d.removeStableRethLinkLocal(rgID)
			}
		}

		// Startup goodbye RA: when an RG is inactive on the first
		// reconcile pass (node booted as secondary), send a one-shot
		// goodbye RA (lifetime=0) to clear stale routes from a
		// previous primary run. Each RETH node has a per-node virtual
		// MAC producing a distinct link-local, so hosts see each node
		// as a separate IPv6 router. Without this, hosts ECMP-split
		// traffic to BOTH nodes even though only one is active.
		if !tr.Active && d.ra != nil && d.startupGoodbyeNeeded(rgID) {
			cfg := d.store.ActiveConfig()
			if cfg != nil {
				rgIfaces := rethInterfacesForRG(cfg, rgID)
				rgIfaceSet := make(map[string]bool, len(rgIfaces))
				for _, n := range rgIfaces {
					rgIfaceSet[n] = true
				}
				allRA := d.buildRAConfigs(cfg)
				var rgRA []*config.RAInterfaceConfig
				for _, ra := range allRA {
					if rgIfaceSet[ra.Interface] {
						rgRA = append(rgRA, ra)
					}
				}
				if len(rgRA) > 0 && d.startupGoodbyeBegin(rgID) {
					// Emit off the reconcile goroutine (bind retry can take ~2s);
					// the sticky bit is set only after the goodbye lands so a
					// failure is retried on the next reconcile tick (#5093).
					go d.runStartupGoodbye(rgID, rgRA)
				}
			}
		}
	}

	// #1827 §4.4: on any RG transition, re-evaluate ip-monitoring HA
	// gating — gated probes run (and the overlay publishes) only on
	// the data-RG primary; the standby reverts to the config baseline.
	if anyRGChanged {
		d.reconcileIPMonGating()
	}

	// #5861: dropped-event safety net. A VRRP event that started/stopped RA
	// could be lost (event queue overflow, restart mid-transition), or a day-2
	// RA edit on a stable-active RG could have landed while this node was
	// already MASTER. Reconcile the cluster RA senders to the current active
	// owners every pass — hash-gated, so it is a no-op when the effective RA
	// set did not move, and re-applies (via ra.Apply's safe diff) when it did.
	d.reconcileClusterRAServices("reconcile")
	// #6535: the same dropped-work safety net for the OTHER per-RG service.
	// Unlike RA, Kea had no converger at all — a failed apply was simply
	// lost until the next RG transition or operator commit.
	d.reconcileClusterDHCPServices("reconcile")
}

// startupGoodbyeNeeded reports whether the cold-boot one-shot goodbye still
// needs to run for rgID: not already confirmed sent AND not currently in
// flight. Guarded by startupGoodbyeMu because the in-flight/done state is now
// written from the async goodbye goroutine (#5093).
func (d *Daemon) startupGoodbyeNeeded(rgID int) bool {
	d.startupGoodbyeMu.Lock()
	defer d.startupGoodbyeMu.Unlock()
	return !d.startupGoodbyeRA[rgID] && !d.startupGoodbyeInflight[rgID]
}

// startupGoodbyeBegin atomically claims the in-flight slot for rgID. It returns
// false if the goodbye was completed or claimed by another goroutine between the
// startupGoodbyeNeeded check and here, so at most one goodbye goroutine runs per
// RG at a time (a duplicate would self-skip on the held WithdrawOnce tombstone
// and falsely record success — #5093).
func (d *Daemon) startupGoodbyeBegin(rgID int) bool {
	d.startupGoodbyeMu.Lock()
	defer d.startupGoodbyeMu.Unlock()
	if d.startupGoodbyeRA[rgID] || d.startupGoodbyeInflight[rgID] {
		return false
	}
	if d.startupGoodbyeInflight == nil {
		d.startupGoodbyeInflight = make(map[int]bool)
	}
	d.startupGoodbyeInflight[rgID] = true
	return true
}

// runStartupGoodbye emits the cold-boot one-shot goodbye for an inactive RG and
// marks the RG done ONLY when every interface's lifetime-0 RA was written (or
// intentionally skipped because another owner already holds it). On any
// per-interface write/bind failure it leaves the sticky bit unset so the next
// reconcile pass (2s ticker) retries — the old code set the bit before launching
// the async withdraw, so a bind/write failure was never retried and the stale
// IPv6 default-router identity lingered on hosts until Router Lifetime expiry
// (#5093). Runs in its own goroutine; the in-flight slot serializes retries.
func (d *Daemon) runStartupGoodbye(rgID int, rgRA []*config.RAInterfaceConfig) {
	withdraw := d.startupGoodbyeWithdrawFn
	if withdraw == nil {
		withdraw = d.ra.WithdrawOnce
	}
	results := withdraw(rgRA)
	done := true
	for _, r := range results {
		if r.Err != nil {
			done = false
			slog.Warn("ra: startup goodbye failed; will retry on next reconcile",
				"rg", rgID, "interface", r.Interface, "err", r.Err)
		}
	}

	d.startupGoodbyeMu.Lock()
	delete(d.startupGoodbyeInflight, rgID)
	if done {
		if d.startupGoodbyeRA == nil {
			d.startupGoodbyeRA = make(map[int]bool)
		}
		d.startupGoodbyeRA[rgID] = true
	}
	d.startupGoodbyeMu.Unlock()

	if done {
		slog.Info("ra: startup goodbye complete", "rg", rgID)
	}
}

// rethInterfacesForRG returns the Linux interface names of RETH interfaces
// belonging to the given redundancy group.
func rethInterfacesForRG(cfg *config.Config, rgID int) []string {
	return rethInterfacesMatchingRG(cfg, func(id int) bool { return id == rgID })
}

// rethInterfacesMatchingRG returns the Linux interface names of every RETH
// interface whose redundancy group satisfies want.
//
// It is the SINGLE source for both RG-derived interface sets the cluster DHCP
// filter needs — "which interfaces does THIS node currently master" and "which
// interfaces are redundancy-group-scoped AT ALL" (#6520). Deriving the two from
// one walker is not a style preference: a divergence between them is ALWAYS a
// bug, because the filter's keep rule is exactly "RG-scoped implies mastered".
// If one set resolved a RETH member differently from the other, a node-local
// interface would be misread as an unmastered RG member (service dropped) or an
// RG member as node-local (both nodes serve DHCP on one redundant segment).
func rethInterfacesMatchingRG(cfg *config.Config, want func(rgID int) bool) []string {
	var names []string
	rgOwners := cfg.RethRGOwners() // #6781
	for name, ifc := range cfg.Interfaces.Interfaces {
		if ifc == nil {
			continue
		}
		// #6781: RG ownership from the shared predicate, not a name test. The
		// #6520 rationale in this function's doc comment — "a divergence
		// between them is ALWAYS a bug" — is exactly why it must not carry a
		// private reading of its own.
		if owns, ok := rgOwners[name]; ok && want(owns) {
			// Resolve RETH to physical member for Linux-level operations.
			resolved := config.LinuxIfName(cfg.ResolveReth(name))
			for _, unit := range ifc.Units {
				if unit == nil { // #6780
					continue
				}
				if unit.VlanID > 0 {
					names = append(names, resolved+"."+fmt.Sprintf("%d", unit.VlanID))
				} else {
					names = append(names, resolved)
				}
			}
		}
	}
	return names
}

// injectBlackholeRoutes adds blackhole routes for RETH subnets of the given
// RG. Called on VRRP BACKUP transition — prevents bpf_fib_lookup from routing
// return traffic via the default route (which would escape via WAN). Instead,
// FIB returns BLACKHOLE and the BPF failure handler triggers fabric redirect.
func (d *Daemon) injectBlackholeRoutes(rgID int) {
	d.injectBlackholeRoutesFor(d.userspaceDataplaneActive(), rgID)
}

// injectBlackholeRoutesFor is injectBlackholeRoutes with the
// userspace-active mode decision supplied by the caller, so a reconcile
// pass evaluates all RGs against ONE dataplane snapshot (#2114, Codex PR
// #6743 r2-1). Event-path callers keep the per-invocation load via the
// zero-arg wrapper.
func (d *Daemon) injectBlackholeRoutesFor(userspaceActive bool, rgID int) {
	if userspaceActive {
		return
	}
	d.blackholeMu.Lock()
	defer d.blackholeMu.Unlock()

	cfg := d.store.ActiveConfig()
	if cfg == nil {
		return
	}

	var routes []netlink.Route
	rgOwners := cfg.RethRGOwners() // #6781
	for name, ifc := range cfg.Interfaces.Interfaces {
		if ifc == nil {
			continue
		}
		if owns, ok := rgOwners[name]; !ok || owns != rgID { // #6781
			continue
		}
		for _, unit := range ifc.Units {
			if unit == nil { // #6780
				continue
			}
			for _, addr := range unit.Addresses {
				_, ipNet, err := net.ParseCIDR(addr)
				if err != nil {
					slog.Warn("blackhole: failed to parse RETH address",
						"rg", rgID, "iface", name, "addr", addr, "err", err)
					continue
				}
				rt := netlink.Route{
					Dst:      ipNet,
					Type:     unix.RTN_BLACKHOLE,
					Priority: 4242,
				}
				if err := netlink.RouteAdd(&rt); err != nil {
					if errors.Is(err, unix.EEXIST) {
						// Idempotent transition: route already present
						// from a prior BACKUP event. Track it so MASTER
						// cleanup removes it deterministically.
						routes = append(routes, rt)
						slog.Debug("blackhole: route already exists",
							"rg", rgID, "dst", ipNet)
						continue
					}
					slog.Warn("blackhole: failed to add route",
						"rg", rgID, "dst", ipNet, "err", err)
					continue
				}
				routes = append(routes, rt)
				slog.Info("blackhole: injected route for inactive RG",
					"rg", rgID, "dst", ipNet)
			}
		}
	}
	d.blackholeRoutes[rgID] = routes
}

// removeBlackholeRoutes removes blackhole routes previously injected for the
// given RG. Called on VRRP MASTER transition — the connected route returns
// naturally when the VIP is added back.
func (d *Daemon) removeBlackholeRoutes(rgID int) {
	d.removeBlackholeRoutesFor(d.userspaceDataplaneActive(), rgID)
}

// removeBlackholeRoutesFor is removeBlackholeRoutes with the
// userspace-active mode decision supplied by the caller (#2114, Codex PR
// #6743 r2-1 — see injectBlackholeRoutesFor).
func (d *Daemon) removeBlackholeRoutesFor(userspaceActive bool, rgID int) {
	if userspaceActive {
		return
	}
	d.blackholeMu.Lock()
	defer d.blackholeMu.Unlock()

	for _, rt := range d.blackholeRoutes[rgID] {
		if err := netlink.RouteDel(&rt); err != nil {
			if errors.Is(err, unix.ESRCH) {
				// Idempotent transition: route already gone.
				slog.Debug("blackhole: route already removed",
					"rg", rgID, "dst", rt.Dst)
				continue
			}
			slog.Warn("blackhole: failed to remove route",
				"rg", rgID, "dst", rt.Dst, "err", err)
		} else {
			slog.Info("blackhole: removed route for active RG",
				"rg", rgID, "dst", rt.Dst)
		}
	}
	delete(d.blackholeRoutes, rgID)
}

// reconcileBlackholeRoutes removes stale blackhole routes left by a previous
// daemon run. The in-memory blackholeRoutes map is lost on restart, so any
// RTN_BLACKHOLE routes with priority 4242 (our sentinel) survive in the kernel.
// Called once at startup before cluster comms start.
func (d *Daemon) reconcileBlackholeRoutes() {
	d.blackholeMu.Lock()
	defer d.blackholeMu.Unlock()

	families := []int{netlink.FAMILY_V4, netlink.FAMILY_V6}
	for _, family := range families {
		routes, err := netlink.RouteListFiltered(family, &netlink.Route{
			Type: unix.RTN_BLACKHOLE,
		}, netlink.RT_FILTER_TYPE)
		if err != nil {
			slog.Warn("blackhole: failed to list routes for reconciliation",
				"family", family, "err", err)
			continue
		}
		for _, rt := range routes {
			if rt.Priority != 4242 {
				continue
			}
			if err := netlink.RouteDel(&rt); err != nil && !errors.Is(err, unix.ESRCH) {
				slog.Warn("blackhole: failed to remove stale route",
					"dst", rt.Dst, "err", err)
			} else {
				slog.Info("blackhole: removed stale route from previous run",
					"dst", rt.Dst)
			}
		}
	}
}

// applyRethServicesForRG starts RA senders and Kea DHCP server only for
// RETH interfaces belonging to the given RG. Called on VRRP MASTER
// transition — these services must only run on the primary to avoid
// dual-router / dual-DHCP issues.
func (d *Daemon) applyRethServicesForRG(rgID int) {
	if d.store == nil {
		return
	}
	cfg := d.store.ActiveConfig()
	if cfg == nil {
		return
	}
	// RA senders (#5861): converge to the union of RA configs for every RG
	// this node is currently the active owner for. reconcileClusterRAServices
	// snapshots ownership + applies under raReconcileMu so this MASTER apply
	// cannot race a concurrent commit/demotion; the state machine already
	// marked rgID active before this call, so the snapshot includes it.
	d.reconcileClusterRAServices(fmt.Sprintf("vrrp-master-rg%d", rgID))
	if d.dhcpServer != nil {
		// Same desired state as the commit path and the #6535 converger.
		// The MASTER edge deliberately does NOT apply a nil desired state —
		// clearing is the BACKUP edge's job — so the nil guard stays.
		dhcpCfg := d.desiredClusterDHCPConfig(cfg)
		if dhcpCfg != nil {
			// #2239 Q3: pre-seed the held peer leases into the Kea
			// memfile BEFORE the (re)start so Kea loads the in-use
			// bindings at boot and can never hand an in-use address to
			// a different client even before the post-start lease-add
			// seed runs (fully closes the duplicate-allocation window).
			// Best-effort + fail-open; the post-start seed is the
			// backstop.
			d.preSeedDHCPLeaseMemfile()
			// ApplyAsync (#1835 F2): Kea reconcile shells out to
			// systemctl with a 15s bound; running it inline would
			// block this VRRP event loop. Latest-wins coalescing in
			// the manager keeps final state correct; failures are
			// logged by the worker with this reason.
			d.dhcpServer.ApplyAsync(dhcpCfg, fmt.Sprintf("vrrp MASTER rg%d", rgID))
			slog.Info("vrrp: DHCP server apply enqueued (MASTER)", "rg", rgID)
			// #2239: after the async Kea start, seed the held peer
			// leases via lease{4,6}-add (the reinitiateIPsecSAs
			// precedent). Async so it never blocks this VRRP event
			// loop; it waits a bounded time for the control socket and
			// re-anchors lifetimes to the local clock. Idempotent with
			// the memfile pre-seed (lease-add → lease-update on
			// collision). Nudge the push loop so this node replicates
			// its now-owned set.
			if cc := d.clusterConfig(); cc != nil && cc.DHCPLeaseSync && d.getSessionSync() != nil {
				go d.seedDHCPLeasesFromPeer(context.Background())
				d.nudgeDHCPLeaseSync()
			}
		}
	}
	// #1387 inc-2: nudge the DDNS reconcile loop on MASTER takeover so
	// records are re-published/refreshed within one loop iteration. The
	// gate (ddnsWriterGateOpen) now reports MASTER for this RG, so the
	// nudged pass publishes. Async-takeover ordering is benign: the Kea
	// ApplyAsync above may lag this nudge, so a too-early pass sees fewer
	// leases and only adds on the next cycle — it never deletes on the
	// strength of a not-yet-written lease (daemon_ddns.go nudge note).
	d.nudgeDDNSReconcile()
	// #2691 P2: a MASTER takeover changes which RG scopes this node may
	// publish for Surface A too — nudge it to (re)publish its RG records.
	d.nudgeSurfaceADDNSReconcile()

	// #9087: this node now owns rgID, so it must ANSWER proxy-ARP for the pool
	// addresses on that RG's interfaces. Nothing drove that before: the
	// apply-path reconcile runs on a commit and a failover is not a commit, so
	// the new owner stayed silent until the 30s re-assert ticker happened to
	// fire. Measured immediately after a crash-failover plus manual failback:
	// `fw0=0 fw1=1` — the only answerer was the node that no longer owns the
	// address, which mis-steers pool-mode NAT return traffic for the window.
	d.nudgeProxyARPReassert()

	// #9139: re-initiate the peer's IPsec SAs that belong to THIS RG.
	//
	// This leg did not exist. reinitiateIPsecSAs was wired ONLY to
	// applyRG0OwnershipTransition(StatePrimary), so on a DATA-RG failover it
	// never ran — and in the asymmetric case (this node already RG0 primary,
	// taking RG1 from a dead peer) there is no RG0 transition at all, so
	// nothing re-initiated the tunnels anchored on the reth whose VIP just
	// moved here. With the default `establish-tunnels` setting charon emits no
	// start_action, so the tunnel then waits for the REMOTE peer.
	//
	// ownsIPsecConn scopes the set to this RG, so this is not a second
	// unconditional initiate-everything: RG0's own transition still handles
	// RG0-anchored connections, and neither leg touches the other's.
	//
	// ASYNC for the reason the DHCP lease seed above is async: this runs on the
	// VRRP event loop, and InitiateConnection shells out to swanctl per
	// connection. Blocking here delays every subsequent VRRP event on the node.
	if cc := d.clusterConfig(); cc != nil && cc.IPsecSASync && d.getSessionSync() != nil {
		go d.reinitiateIPsecSAs()
	}
}

// clearRethServicesForRG withdraws RA senders and stops DHCP server only
// for RETH interfaces belonging to the given RG. Called on VRRP BACKUP
// transition. If other RGs are still MASTER, their services remain active.
func (d *Daemon) clearRethServicesForRG(rgID int) {
	// #9087: nudged FIRST, and before the early returns, because the demote
	// side of the window is the one that leaves a wrong answerer on the wire.
	// This node no longer owns rgID, so the #8297 gate will now suppress its
	// proxy-ARP entries and the reconcile must SWEEP them; until it runs, the
	// demoted node keeps answering for the pool address. The early returns
	// below are about RA/Kea state and say nothing about whether a sweep is
	// owed, so gating the nudge behind them would drop it on exactly the
	// config-less paths where the stale entry still sits in the kernel.
	d.nudgeProxyARPReassert()
	if d.store == nil {
		return
	}
	cfg := d.store.ActiveConfig()
	if cfg == nil {
		return
	}

	// Check if any other RG is still master — if so, reapply services for
	// those RGs only; otherwise clear everything.
	anyOtherMaster := false
	for otherRG, isMaster := range d.snapshotRethMasterState() {
		if otherRG != rgID && isMaster {
			anyOtherMaster = true
			break
		}
	}

	// RA senders (#5861): converge to the union of RA configs for the RGs this
	// node still owns. The state machine already marked rgID inactive before
	// this call, so reconcileClusterRAServices drops rgID's interfaces from the
	// desired set — ra.Apply emits the lifetime-0 goodbye for them and leaves
	// any still-owned RG's senders running (subsuming the prior
	// WithdrawInterfaces / Withdraw split). Owner-gated + serialized so a
	// concurrent commit cannot re-arm the demoted RG's senders.
	d.reconcileClusterRAServices(fmt.Sprintf("vrrp-backup-rg%d", rgID))
	if d.dhcpServer != nil {
		// ApplyAsync on both branches (#1835 F2): keeps this VRRP
		// event loop off the 15s-bounded systemctl path AND funnels
		// every Kea desired state through the same latest-wins
		// mailbox, preserving ordering with the MASTER-side applies.
		// ApplyAsync(nil) is the authoritative clear (Apply(nil)).
		if anyOtherMaster {
			// Reapply DHCP with only the remaining master RGs'
			// interfaces (nil when none match → clear).
			d.dhcpServer.ApplyAsync(d.desiredClusterDHCPConfig(cfg),
				fmt.Sprintf("vrrp BACKUP rg%d (other RG still MASTER)", rgID))
		} else {
			d.dhcpServer.ApplyAsync(nil, fmt.Sprintf("vrrp BACKUP rg%d", rgID))
			slog.Info("vrrp: DHCP server stop enqueued (BACKUP)", "rg", rgID)
		}
	}
	// #2691 P1b / #2664: nudge the DDNS reconcile loop after a (partial)
	// demotion. This closes the documented "no DDNS nudge on partial demotion"
	// gap: when this node loses RG `rgID` but stays MASTER for another RG, the
	// per-RG writer gate now CLOSES for rgID's scopes — but only a reconcile
	// pass acts on it, so without this nudge the demoted RG's records would keep
	// being re-asserted until the next 30s tick. The nudged pass STOPS
	// publishing rgID's leases (the gate is closed for that RG) and does NOT
	// withdraw them (stop-writing, never withdraw — the peer that became MASTER
	// for rgID refreshes them; a withdraw race would blackhole, plan §5.6). The
	// nudge is benign if it races the async Kea re-apply: a too-early pass sees
	// the unchanged store and only the gate state matters for the demoted RG.
	d.nudgeDDNSReconcile()
	// #2691 P2: a partial demotion changes the per-RG Surface A gate too —
	// nudge so the demoted RG's scopes stop publishing (never withdraw).
	d.nudgeSurfaceADDNSReconcile()
}

// stripUntaggedUnitSuffix normalizes a resolved Linux interface name by
// removing a trailing ".0" unit suffix. An untagged reth unit (e.g. `reth1.0`)
// resolves via ResolveReth to "ge-0-0-1.0", but the real kernel interface Kea
// binds to — and the name rethInterfacesForRG emits for a VlanID==0 unit — is
// the bare member "ge-0-0-1" (there is NO ".0" VLAN device for an untagged
// unit). A tagged unit (".100") is left intact so it only matches its tagged
// member.
//
// #4647: the master-RG DHCP filter compared the resolved group interface
// ("ge-0-0-1.0") against the bare master-RG member ("ge-0-0-1") with an exact
// string compare, so the canonical `interface reth1.0` config never matched,
// the group was dropped, and clearFamilyLocked wiped the Kea config even though
// the RG was MASTER — DHCP-server-in-cluster was non-functional. Normalizing the
// untagged ".0" on both sides restores the match while keeping tagged units
// bound to their VLAN member.
func stripUntaggedUnitSuffix(iface string) string {
	return strings.TrimSuffix(iface, ".0")
}

// desiredClusterDHCPConfig is the single source of truth for the Kea desired
// state in cluster mode: the master-RG-filtered DHCP config, or nil when this
// node should serve nothing. Every driver — the commit path
// (daemon_apply_routing.go), the RG-transition edge (applyRethServicesForRG /
// clearRethServicesForRG), and the #6535 reconcile converger — derives its
// desired state from here.
//
// It is single-sourced rather than duplicated because a divergence between the
// converger and the edge is ALWAYS a bug: the converger runs every 2s and
// would fight the edge forever, restarting Kea on every tick. Binding two
// copies with a test would not be enough — there is no legitimate reason for
// them to differ.
func (d *Daemon) desiredClusterDHCPConfig(cfg *config.Config) *config.DHCPServerConfig {
	if cfg == nil {
		return nil
	}
	if cfg.System.DHCPServer.DHCPLocalServer == nil && cfg.System.DHCPServer.DHCPv6LocalServer == nil {
		return nil
	}
	// filterDHCPConfigForMasterRGs resolves RETH interface names into a COPY
	// (resolveDHCPRethInterfaces returns one; the shared active config is never
	// written) and filters the groups into freshly-allocated ones. It returns
	// nil when no group's interfaces belong to a currently-MASTER RG.
	//
	// #9141: this comment previously claimed the function "copies the config",
	// which is what made the in-place rewrite invisible — the copy was a shallow
	// struct copy over pointer/map/slice fields, so the resolve wrote straight
	// through to cfg. The claim is now true.
	return d.filterDHCPConfigForMasterRGs(cfg)
}

// reconcileClusterDHCPServices is the periodic converger for the Kea applier
// (#6535). Every other trigger is an EDGE: applyRethServicesForRG /
// clearRethServicesForRG run only under `if tr.Changed`, and the commit path
// runs only when an operator commits. So a Kea apply that FAILED had nowhere
// to be retried from, and the failure survives: the node that should be
// serving stays dark, or the node that should have stopped keeps serving —
// persistent dual-DHCP (or no-DHCP) after a failover, not a transient blip.
//
// This mirrors reconcileClusterRAServices, the converger the RA half of the
// same two services already has, including its central rule — the applied
// marker advances only on a verified success, so a transient error is retried
// on a later pass rather than latched as converged.
//
// It re-drives ONLY when the manager reports the last completed attempt
// failed, and the manager spaces retries (applyRetryInterval). A converged Kea
// costs one atomic-guarded bool read per pass.
func (d *Daemon) reconcileClusterDHCPServices(reason string) {
	if d.dhcpServer == nil || d.store == nil {
		return
	}
	if !d.dhcpServer.ClaimApplyRetry(time.Now()) {
		return
	}
	cfg := d.store.ActiveConfig()
	if cfg == nil {
		return
	}
	desired := d.desiredClusterDHCPConfig(cfg)
	slog.Info("reconcile: retrying failed DHCP server apply", "reason", reason)
	d.dhcpServer.ApplyAsync(desired, "reconcile: "+reason)
}

// filterDHCPConfigForMasterRGs returns the DHCP config this node should serve
// in cluster mode: every group member that is either NODE-LOCAL or belongs to a
// redundancy group this node currently masters. Returns nil if nothing
// survives.
//
// #6520 (a) — mastership scoping applies ONLY to RG-scoped members. Before this
// fix the keep-set was built exclusively from `rethInterfacesForRG` over the
// MASTER RGs, so it could only ever contain RETH members: every interface that
// is not part of a redundancy group — the `fxp0.0` management lifeline, and any
// plain node-local data interface — was removed from every group on BOTH nodes,
// and a group made only of such members disappeared entirely. That silently
// killed DHCP service the operator configured on a node-local segment the
// moment the box was clustered. Redundancy-group mastership says which node
// answers for a REDUNDANT interface; it says nothing about an interface that
// has no redundant peer, and Junos clusters likewise run `fxp0` services per
// node. So an interface that belongs to NO redundancy group is kept
// unconditionally, and only an RG-scoped member is gated on this node holding
// that RG.
//
// The two sets are derived from ONE walker (rethInterfacesMatchingRG) so
// "RG-scoped" and "mastered" cannot resolve a RETH member differently.
func (d *Daemon) filterDHCPConfigForMasterRGs(cfg *config.Config) *config.DHCPServerConfig {
	// Collect all interfaces belonging to master RGs. Normalize the untagged
	// ".0" suffix (#4647) so the set is keyed by the bare member name that the
	// resolved group interface also normalizes to below.
	masterIfaces := make(map[string]bool)
	for rgID, isMaster := range d.snapshotRethMasterState() {
		if !isMaster {
			continue
		}
		for _, n := range rethInterfacesForRG(cfg, rgID) {
			masterIfaces[stripUntaggedUnitSuffix(n)] = true
		}
	}
	// Every interface that IS redundancy-group-scoped, regardless of which node
	// currently masters it. An interface absent from this set has no redundant
	// peer and is therefore node-local (#6520).
	rgScoped := make(map[string]bool)
	for _, n := range rethInterfacesMatchingRG(cfg, func(int) bool { return true }) {
		rgScoped[stripUntaggedUnitSuffix(n)] = true
	}

	dhcpCfg := resolveDHCPRethInterfaces(cfg.System.DHCPServer, cfg)

	filterGroups := func(groups map[string]*config.DHCPServerGroup) map[string]*config.DHCPServerGroup {
		if groups == nil {
			return nil
		}
		result := make(map[string]*config.DHCPServerGroup)
		for name, group := range groups {
			var kept []string
			for _, iface := range group.Interfaces {
				// #4647: normalize the untagged ".0" so a `reth1.0`
				// group (resolved to "ge-0-0-1.0") matches its master RG
				// member ("ge-0-0-1"). Keep the NORMALIZED name — the
				// bare member is the real kernel interface Kea binds to;
				// "ge-0-0-1.0" is not a device. Tagged units keep their
				// ".<vlan>" and match only the tagged member.
				norm := stripUntaggedUnitSuffix(iface)
				// #6520: node-local members (no redundancy group) are not
				// mastership-scoped and are always kept; RG-scoped members are
				// kept only while this node masters their RG.
				if masterIfaces[norm] || !rgScoped[norm] {
					kept = append(kept, norm)
				}
			}
			if len(kept) > 0 {
				cp := *group
				cp.Interfaces = kept
				// #6520 (b): DHCPServerGroup carries independent Interfaces and
				// Pools arrays with no semantic edge, so a group whose member
				// list SHRANK here no longer describes which pool belongs to
				// which member. Record that so the Kea renderer suppresses its
				// per-subnet interface selector instead of cross-binding a
				// removed member's pool onto a survivor (dhcpserver.subnetInterface).
				cp.MembersFiltered = len(kept) != len(group.Interfaces)
				result[name] = &cp
			}
		}
		return result
	}

	// #9348: COPY the source and swap only what this function narrows, rather
	// than reconstructing the result field by field.
	//
	// The old shape was `var result config.DHCPServerConfig` plus
	// `&config.DHCPLocalServerConfig{Groups: filtered}`, which names exactly the
	// fields the author knew about and silently drops the rest. Six were being
	// dropped, measured:
	//
	//	v4 SocketType    src="udp" filtered=""
	//	v4 ExpiredLeases src=true  filtered=false
	//	v6 SocketType    src="udp" filtered=""
	//	v6 ExpiredLeases src=true  filtered=false
	//	DynamicDNS       src=true  filtered=false
	//	DynamicDNSv6     src=true  filtered=false
	//
	// The two that MATTER are the family-level Kea scalars: a clustered node
	// rendered Kea WITHOUT the operator's `expired-leases-processing` (#1387,
	// so Kea fell back to its built-in reclamation defaults) and WITHOUT
	// `dhcp-socket-type` (#7318, so Kea fell back to `raw`) — while a
	// standalone node rendered both. #7318 exists precisely because `raw` does
	// not work on some substrates, so on a cluster that leaf read as applied and
	// was not.
	//
	// The DDNS pair is harmless and was checked rather than assumed: this
	// result goes only to dhcpserver.Manager (the Kea render), and the DDNS
	// policy is read straight off the ACTIVE config by
	// ddns.Manager.ReconcileScoped(ctx, &cfg.System.DHCPServer, opts) — pkg/
	// dhcpserver never reads DynamicDNS at all. They ride along here anyway,
	// because the point of the shape is that nobody has to make that judgement
	// per field.
	//
	// The copy is the guard: a field added to either struct is carried by
	// construction instead of needing someone to remember this site. Same shape
	// as #9141's resolveDHCPRethInterfaces — copy the struct, freshly allocate
	// only what is written.
	result := dhcpCfg
	result.DHCPLocalServer = nil
	result.DHCPv6LocalServer = nil
	if src := dhcpCfg.DHCPLocalServer; src != nil {
		if filtered := filterGroups(src.Groups); len(filtered) > 0 {
			cp := *src
			cp.Groups = filtered
			result.DHCPLocalServer = &cp
		}
	}
	if src := dhcpCfg.DHCPv6LocalServer; src != nil {
		if filtered := filterGroups(src.Groups); len(filtered) > 0 {
			cp := *src
			cp.Groups = filtered
			result.DHCPv6LocalServer = &cp
		}
	}
	if result.DHCPLocalServer == nil && result.DHCPv6LocalServer == nil {
		return nil
	}
	return &result
}

// applyRethServices starts RA senders and Kea DHCP server. Called on VRRP
// MASTER transition — these services bind to RETH member interfaces
// and must only run on the primary node to avoid dual-RA / dual-DHCP.
// Deprecated: use applyRethServicesForRG for per-RG management.
func (d *Daemon) applyRethServices() {
	cfg := d.store.ActiveConfig()
	if cfg == nil {
		return
	}
	if d.ra != nil {
		raConfigs := d.buildRAConfigs(cfg)
		if len(raConfigs) > 0 {
			if err := d.ra.Apply(raConfigs); err != nil {
				slog.Warn("vrrp: failed to apply RA on MASTER", "err", err)
			} else {
				slog.Info("vrrp: RA senders started (MASTER)")
			}
		}
	}
	if d.dhcpServer != nil && (cfg.System.DHCPServer.DHCPLocalServer != nil || cfg.System.DHCPServer.DHCPv6LocalServer != nil) {
		dhcpCfg := resolveDHCPRethInterfaces(cfg.System.DHCPServer, cfg)
		// ApplyAsync (#1835 F2): see applyRethServicesForRG.
		d.dhcpServer.ApplyAsync(&dhcpCfg, "vrrp MASTER (legacy all-RG)")
		slog.Info("vrrp: DHCP server apply enqueued (MASTER)")
	}
}

// clearRethServices sends goodbye RAs (lifetime=0) and stops Kea DHCP
// server. Called on VRRP BACKUP transition to prevent the secondary from
// advertising RAs or serving DHCP leases. The goodbye RA tells hosts to
// immediately remove this router as a default gateway.
// Deprecated: use clearRethServicesForRG for per-RG management.
func (d *Daemon) clearRethServices() {
	if d.ra != nil {
		if err := d.ra.Withdraw(); err != nil {
			slog.Warn("vrrp: failed to withdraw RA on BACKUP", "err", err)
		} else {
			slog.Info("vrrp: RA withdrawn (BACKUP, goodbye RA sent)")
		}
	}
	if d.dhcpServer != nil {
		// ApplyAsync(nil) == authoritative clear (#1835 F2): see
		// clearRethServicesForRG.
		d.dhcpServer.ApplyAsync(nil, "vrrp BACKUP (legacy all-RG)")
		slog.Info("vrrp: DHCP server stop enqueued (BACKUP)")
	}
}

// neighborWarmProbeTimeout bounds each warmup send. A UDP send to an
// unconnected socket normally returns immediately (the ARP/ND solicit is
// queued asynchronously), so this deadline effectively never fires; it is a
// defensive per-probe bound matching the pre-#5451 per-dial DialTimeout.
const neighborWarmProbeTimeout = 50 * time.Millisecond

// neighborWarmMaxSockets caps how many datagram sockets warmNeighborCache
// opens, regardless of session-table size: one reusable unconnected socket per
// address family (IPv4 + IPv6). Before #5451 the warmup opened one CONNECTED
// socket per unique session IP — at CGNAT scale (tens of thousands of unique
// destinations) that burst of DialTimeout calls exhausted ephemeral ports / file
// descriptors and stalled failover convergence, the worst possible time for a
// local resource storm. Reusing one unconnected socket per family and sending an
// unconnected datagram per destination triggers the same kernel neighbor
// resolution (route lookup → neigh_resolve_output → arp_solicit/ndisc_solicit)
// while bounding the FD/port high-water mark by this constant.
const neighborWarmMaxSockets = 2

// neighborWarmDialer opens datagram sockets used by warmNeighborCache to
// trigger kernel neighbor (ARP/ND) resolution. It is a seam so tests can count
// sockets opened and capture probed destinations without touching the network
// (#5451).
type neighborWarmDialer interface {
	// open returns one datagram socket for the given network ("udp4"/"udp6").
	open(network string) (neighborWarmConn, error)
}

// neighborWarmConn is a single unconnected datagram socket that can probe many
// destinations. probe sends a byte to dst, which triggers neighbor resolution
// for that destination's next-hop.
type neighborWarmConn interface {
	probe(dst netip.AddrPort) error
	Close() error
}

// udpNeighborWarmDialer is the production neighborWarmDialer: it opens a real
// unconnected UDP socket via net.ListenUDP.
type udpNeighborWarmDialer struct{}

func (udpNeighborWarmDialer) open(network string) (neighborWarmConn, error) {
	conn, err := net.ListenUDP(network, nil)
	if err != nil {
		return nil, err
	}
	return &udpNeighborWarmConn{conn: conn}, nil
}

type udpNeighborWarmConn struct{ conn *net.UDPConn }

func (c *udpNeighborWarmConn) probe(dst netip.AddrPort) error {
	// A send is what actually drives ARP/ND: connect() alone only does the
	// route lookup. One byte to (dst, port 1) on the unconnected socket makes
	// the kernel call neigh_resolve_output() for the next-hop.
	_ = c.conn.SetWriteDeadline(time.Now().Add(neighborWarmProbeTimeout))
	_, err := c.conn.WriteToUDPAddrPort([]byte{0}, dst)
	return err
}

func (c *udpNeighborWarmConn) Close() error { return c.conn.Close() }

func (d *Daemon) warmDialer() neighborWarmDialer {
	if d.neighborWarmDialer != nil {
		return d.neighborWarmDialer
	}
	return udpNeighborWarmDialer{}
}

// warmNeighborCache iterates synced sessions and sends ARP requests /
// ICMPv6 Neighbor Solicitations for unique destination IPs. This
// pre-populates the kernel neighbor cache so that bpf_fib_lookup
// returns SUCCESS (not NO_NEIGH) for the first packet after failover.
//
// It reuses ONE unconnected datagram socket per address family (see
// neighborWarmMaxSockets) rather than opening a connected socket per unique IP,
// so the failover-time FD/ephemeral-port high-water mark is bounded by a
// constant instead of by session-table size (#5451). Every unique IP is still
// warmed; warming stays best-effort (a per-probe error does not abort the
// rest).
func (d *Daemon) warmNeighborCache() {
	// #2114: snapshot-per-operation (plan §5.3 rule 5) — one load feeds
	// both the v4 and the v6 iteration below.
	rt := d.dataplane()
	if rt == nil {
		return
	}

	seen := make(map[[4]byte]bool)
	seenV6 := make(map[[16]byte]bool)

	// Iterate IPv4 sessions: collect unique dst IPs (forward entries
	// need ARP for the next-hop toward the destination) and unique src IPs
	// (return entries need ARP for the on-link client).
	_ = rt.Sessions().ForEachV4(func(key dataplane.SessionKey, val dataplane.SessionValue) bool {
		if val.IsReverse != 0 {
			return true
		}
		if !seen[key.DstIP] {
			seen[key.DstIP] = true
		}
		if !seen[key.SrcIP] {
			seen[key.SrcIP] = true
		}
		return true
	})

	// Iterate IPv6 sessions.
	_ = rt.Sessions().ForEachV6(func(key dataplane.SessionKeyV6, val dataplane.SessionValueV6) bool {
		if val.IsReverse != 0 {
			return true
		}
		if !seenV6[key.DstIP] {
			seenV6[key.DstIP] = true
		}
		if !seenV6[key.SrcIP] {
			seenV6[key.SrcIP] = true
		}
		return true
	})

	dialer := d.warmDialer()

	// Resolve IPv4 neighbors by sending a UDP datagram per destination to
	// trigger kernel ARP. One reusable unconnected socket serves every
	// destination, so FD/port cost is O(1), not O(unique IPs).
	count := 0
	if len(seen) > 0 {
		if conn, err := dialer.open("udp4"); err == nil {
			for ip4 := range seen {
				addr := netip.AddrFrom4(ip4)
				if !addr.IsGlobalUnicast() || addr.IsPrivate() && addr.IsLoopback() {
					continue
				}
				if conn.probe(netip.AddrPortFrom(addr, 1)) == nil {
					count++
				}
			}
			conn.Close()
		}
	}

	// Resolve IPv6 neighbors (one reusable unconnected socket).
	countV6 := 0
	if len(seenV6) > 0 {
		if conn, err := dialer.open("udp6"); err == nil {
			for ip6 := range seenV6 {
				addr := netip.AddrFrom16(ip6)
				if !addr.IsGlobalUnicast() {
					continue
				}
				if conn.probe(netip.AddrPortFrom(addr, 1)) == nil {
					countV6++
				}
			}
			conn.Close()
		}
	}

	if count > 0 || countV6 > 0 {
		slog.Info("cluster: neighbor cache warmup complete",
			"ipv4_hosts", count, "ipv6_hosts", countV6)
		// Brief pause to allow ARP/NDP responses before traffic arrives.
		time.Sleep(200 * time.Millisecond)
	}
}

// clusterConfig returns the current cluster config or nil.
func (d *Daemon) clusterConfig() *config.ClusterConfig {
	if d.store == nil {
		return nil
	}
	cfg := d.store.ActiveConfig()
	if cfg == nil || cfg.Chassis.Cluster == nil {
		return nil
	}
	return cfg.Chassis.Cluster
}

// ipsecSAFingerprint returns a stable, order-independent fingerprint of an
// active IPsec connection-name set. The empty set maps to the empty string so
// a never-up node and a torn-down node share the same sentinel (see
// ipsecSASyncAdvertise).
func ipsecSAFingerprint(names []string) string {
	if len(names) == 0 {
		return ""
	}
	sorted := append([]string(nil), names...)
	sort.Strings(sorted)
	return strings.Join(sorted, "\n")
}

// ipsecSASyncAdvertise decides whether the primary should advertise the current
// active IPsec connection-name set to the standby, given the fingerprint of the
// set it last advertised (lastFP; the empty string means the last advertised
// set was empty or nothing has been advertised yet). It returns whether to push
// and the fingerprint to remember for the next tick.
//
// #4385: a NON-EMPTY set is advertised every tick — a heartbeat re-push so a
// freshly reconnected/restarted standby relearns the full set within one
// interval (this is the ONLY mechanism that seeds a new standby's peer set, so
// it preserves the pre-#4385 reconnect-safety behavior). An EMPTY set is
// advertised exactly ONCE, on the transition down from a previously non-empty
// set — a tunnel was administratively downed or all its SAs were torn down — so
// the standby CLEARS its stale peer set instead of resurrecting the tunnel on
// takeover (reinitiateIPsecSAs). A steady empty set, INCLUDING a node that
// never brought an SA up, is never advertised: no 30s empty-heartbeat churn,
// and the standby's default peer set is already empty so there is nothing to
// clear.
//
// force=true (a peer (re)connected) advertises the CURRENT set regardless —
// empty or not — so a standby that missed the one-shot empty during a
// disconnect gap, or that retained a stale peer set across a same-process blip,
// converges to our actual state immediately (empty -> it clears; non-empty ->
// it re-seeds). This mirrors the DHCP peer-connect nudge (force=true re-push).
func ipsecSASyncAdvertise(names []string, lastFP string, force bool) (push bool, newFP string) {
	fp := ipsecSAFingerprint(names)
	if force {
		return true, fp
	}
	if len(names) > 0 {
		return true, fp
	}
	// Empty set: advertise once to clear the standby ONLY if we previously
	// advertised a non-empty set (downed-but-was-up, not never-up).
	if lastFP != "" {
		return true, ""
	}
	return false, ""
}

// ipsecSANextFP returns the fingerprint to remember after one advertise attempt.
// The last-sent fingerprint advances ONLY when a push was due AND the send was
// confirmed to an active conn (#4385). A push that no-ops on a nil/dropped conn
// leaves lastFP unchanged, so the (empty or changed) advertisement RETRIES on
// the next tick rather than being silently marked as sent — the fix for the
// window where a drop-to-zero empty push lands during a reconnect gap, the
// fingerprint advances anyway, and the standby is left holding a stale set that
// resurrects the tunnel on takeover.
func ipsecSANextFP(push, sendConfirmed bool, fp, lastFP string) string {
	if push && sendConfirmed {
		return fp
	}
	return lastFP
}

// advertiseIPsecSAOnce runs one IPsec SA advertise pass on the primary and
// returns the fingerprint to carry into the next pass. force=true (a peer
// (re)connect nudge) re-advertises the current set regardless of change. It is
// a no-op (returns lastFP unchanged) on a non-primary node, when the feature is
// disabled, when the active-SA read fails, or when the send does not reach an
// active conn.
// ipsecSAAdvertiseEligible reports whether this node should be advertising its
// active IPsec SA set to the peer at all.
//
// #9139: IsLocalPrimaryAny(), not IsLocalPrimary(0). Active/active is a
// supported configuration, and gating on RG0 meant the node that actually HOLDS
// the SAs — the RG1 primary, when IPsec is anchored on an RG1 reth —
// short-circuited and never advertised, while the RG0 primary advertised its own
// empty set (which ipsecSASyncAdvertise then suppresses). The standby therefore
// learned nothing and re-initiated nothing on failover. This mirrors #3764,
// which replaced a lowest-data-RG gate with IsLocalPrimaryAny() in
// daemon_ipmon.go for the identical reason.
//
// Extracted from advertiseIPsecSAOnce so the GATE can be driven without a live
// swanctl: the rest of that function shells out, and a gate nothing can exercise
// is how this one was wrong for so long.
func (d *Daemon) ipsecSAAdvertiseEligible() bool {
	if d.cluster == nil {
		return false
	}
	return d.cluster.IsLocalPrimaryAny()
}

func (d *Daemon) advertiseIPsecSAOnce(lastFP string, force bool) string {
	// The set advertised is this node's WHOLE active set. Attribution to a
	// specific RG happens at INITIATE time (ownsIPsecConn, #9139), because what
	// matters there is whether the RECEIVER owns the interface the connection
	// binds to — a local question the sender cannot answer.
	if !d.ipsecSAAdvertiseEligible() {
		return lastFP
	}
	cc := d.clusterConfig()
	if cc == nil || !cc.IPsecSASync {
		return lastFP
	}
	names, err := d.ipsecActiveNames()
	if err != nil {
		slog.Debug("cluster: failed to get IPsec SA names", "err", err)
		return lastFP
	}
	push, fp := ipsecSASyncAdvertise(names, lastFP, force)
	sendConfirmed := false
	if ss := d.getSessionSync(); push && ss != nil {
		sendConfirmed = ss.QueueIPsecSA(names)
	}
	return ipsecSANextFP(push, sendConfirmed, fp, lastFP)
}

// nudgeIPsecSASync requests an immediate IPsec SA re-advertise (fired when a
// peer sync connection is established). Non-blocking depth-1 send that coalesces
// a burst; safe before the loop starts.
func (d *Daemon) nudgeIPsecSASync() {
	if d.ipsecSANudgeCh == nil {
		return
	}
	select {
	case d.ipsecSANudgeCh <- struct{}{}:
	default:
	}
}

// syncIPsecSAPeriodic runs on the primary node, periodically syncing active IPsec
// connection names to the secondary via the session sync channel. It advertises
// the current active set every tick when non-empty (heartbeat re-push) and, per
// #4385, advertises the empty set once when the active set drops to zero so the
// standby does not resurrect an administratively-downed tunnel on takeover. A
// peer-connect nudge forces a re-advertise of the current set (empty or not) so
// a reconnected standby converges even if it missed the one-shot empty.
func (d *Daemon) syncIPsecSAPeriodic(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	// lastFP tracks the fingerprint of the last set advertised to the standby
	// (empty string = last advertised set was empty / nothing advertised yet).
	// This goroutine is single-instance per comms lifetime (started once in
	// daemon_ha_sync.go and re-created with a fresh commsCtx only on a
	// transport-field change), so the local is safe without a lock.
	var lastFP string
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			lastFP = d.advertiseIPsecSAOnce(lastFP, false)
		case <-d.ipsecSANudgeCh:
			// A peer sync connection was (re)established: force a re-advertise
			// of the CURRENT set so a standby that missed the one-shot empty
			// during the gap (or retained a stale set across a blip) converges.
			lastFP = d.advertiseIPsecSAOnce(lastFP, true)
		}
	}
}

// reinitiateIPsecSAs re-initiates the IPsec connections synced from the peer
// that belong to a redundancy group THIS node now owns.
//
// Called from BOTH takeover edges (#9139): applyRG0OwnershipTransition for RG0
// and applyRethServicesForRG for a data RG. It used to be wired to the RG0 edge
// alone, which never fires on an asymmetric per-RG failover — the node taking
// RG1 was already RG0 primary, so there was no RG0 transition and no tunnel came
// back. Both legs call this same function; ownsIPsecConn is what keeps them from
// initiating each other's connections.
func (d *Daemon) reinitiateIPsecSAs() {
	ss := d.getSessionSync()
	if ss == nil {
		return
	}
	names := ss.PeerIPsecSAs()
	if len(names) == 0 {
		return
	}
	owned := d.ipsecSAsToReinitiate(names)
	if len(owned) == 0 {
		return
	}
	slog.Info("cluster: re-initiating IPsec SAs after failover", "count", len(owned))
	initiate := d.ipsecInitiate
	for _, name := range owned {
		if err := initiate(name); err != nil {
			slog.Warn("cluster: failed to initiate IPsec SA", "name", name, "err", err)
		} else {
			slog.Info("cluster: IPsec SA initiated", "name", name)
		}
	}
}

// ipsecSAsToReinitiate filters the peer's advertised set to the connections
// whose external interface belongs to a redundancy group THIS node owns.
//
// #9139: the peer advertises its whole active set, and on a per-RG failover the
// peer may still be ALIVE and still own another RG — initiating its whole set
// would raise a second IKE SA to the same remote from a different local address.
// Trading a missed re-initiation for a duplicate one is not a fix. This also
// tightens the pre-#9139 RG0 path, which initiated everything the peer
// advertised regardless of what this node holds.
//
// Split from the effect so the DECISION can be driven without swanctl.
func (d *Daemon) ipsecSAsToReinitiate(names []string) []string {
	// #9511: attribute against the generation strongSwan has LOADED, not the
	// promoted config; they differ after a failed IPsec render or reload.
	cfg := d.ipsecAttributionConfig()
	// #9511: one index per active config, not per name or per pass; building it
	// renders every VPN.
	idx := d.cachedIPsecSANameIndex(cfg)
	owned := make([]string, 0, len(names))
	var skipped []string
	for _, name := range names {
		if d.ownsIPsecConn(cfg, idx, name) {
			owned = append(owned, name)
		} else {
			skipped = append(skipped, name)
		}
	}
	if len(skipped) > 0 {
		// Not a warning: on an asymmetric cluster this is the CORRECT outcome
		// and it fires on every partial failover. It is logged because a tunnel
		// that did not come back is the first thing an operator looks for, and
		// "we deliberately did not initiate it, the peer still owns its RG" is
		// the answer they need.
		slog.Info("cluster: skipping peer IPsec SAs whose redundancy group this "+
			"node does not own", "skipped", skipped)
	}
	return owned
}

// ipsecInitiate is the swanctl call, behind a test seam.
//
// #9139 added it because BOTH halves of that fix are wiring — an advertise gate
// and a per-RG re-initiate CALL SITE — and neither was drivable: d.ipsec is a
// concrete *ipsec.Manager whose InitiateConnection shells out. Measured, the
// three mutations that matter (revert the gate, delete the per-RG leg, drop the
// scoping) all SURVIVED a suite that tested only the filter function. A seam
// that makes the call site observable is the difference between guarding the
// fix and guarding a helper the fix happens to call.
// ipsecActiveNames is the swanctl active-SA read, behind a test seam.
//
// #9139: it is the FIRST thing advertiseIPsecSAOnce touches after the gate, so
// observing whether it was called is how a cell can tell that the gate actually
// ran. Measured: severing the gate's CALL SITE — leaving the gate function
// itself perfectly correct and fully unit-tested — SURVIVED the suite. Binding
// a helper is not binding the wiring that calls it, and this seam is what makes
// the difference falsifiable.
func (d *Daemon) ipsecActiveNames() ([]string, error) {
	if fn := d.ipsecActiveNamesFn; fn != nil {
		return fn()
	}
	return d.ipsec.ActiveConnectionNames()
}

func (d *Daemon) ipsecInitiate(name string) error {
	if fn := d.ipsecInitiateFn; fn != nil {
		return fn(name)
	}
	return d.ipsec.InitiateConnection(name)
}

// desiredStandaloneDHCPConfig returns the DHCP server config the STANDALONE
// (non-cluster) Kea applier should install: the committed stanza with RETH
// logical interface names resolved to their physical member Linux names, in a
// COPY. It is the sibling of desiredClusterDHCPConfig, which does the same for
// the clustered path and additionally filters the groups to the RGs this node
// masters.
//
// It exists as a named function for the reason #9141 exists: the standalone
// site used to inline `resolveDHCPRethInterfaces(&cfg.System.DHCPServer, cfg)`,
// which handed the resolver the shared active config by pointer. Naming the
// derivation gives it a seam a cell can drive, and makes the standalone and
// cluster paths symmetric — both now RETURN a desired config rather than
// editing one in place.
func desiredStandaloneDHCPConfig(cfg *config.Config) config.DHCPServerConfig {
	if cfg == nil {
		return config.DHCPServerConfig{}
	}
	return resolveDHCPRethInterfaces(cfg.System.DHCPServer, cfg)
}

// resolveDHCPRethInterfaces RETURNS a copy of dhcpCfg whose DHCP server group
// interfaces are translated from Junos logical names to the kernel devices Kea
// must bind. It never writes through cfg.
//
// #9407: the translation used to be LinuxIfName(ResolveReth(ref)) — the slash
// rewrite and the RETH member map, and nothing else. That is TWO arms short of
// the canonical resolver, and both gaps produced a name Kea cannot bind:
//
//	reth1.0             -> "ge-0-0-1.0"    a dangling unit suffix; not a device
//	reth1.80 (vlan 180) -> "ge-0-0-1.80"   the UNIT number, not the VLAN device
//
// Only the CLUSTER path papered over the first, with stripUntaggedUnitSuffix
// (#4647), so the STANDALONE builder named a phantom device on identical
// config — different behaviour by topology. Nothing covered the second on
// either topology; it is the #5107 class RA already fixed.
//
// The vlan-id gap did more than misname a device: it silently defeated the
// master-RG filter. filterDHCPConfigForMasterRGs compares the group's resolved
// interface against rethInterfacesMatchingRG, which ALREADY derives
// `<member>.<vlan-id>` — so a tagged group resolved to `<member>.<unit>`
// matched neither masterIfaces nor rgScoped, and the filter's "not RG-scoped
// implies node-local, always keep" arm kept it on a node that masters nothing.
// Measured before this change, with no RG mastered:
//
//	group reth1.80 -> kept as "ge-0-0-1.80"   (should have been dropped)
//
// Config.ResolveKernelIfName is that canonical resolver, and it is the same one
// rethInterfacesMatchingRG's arms reproduce — so the two sides of the filter
// comparison now derive their names the same way instead of being asserted to
// agree (#8994's doctrine).
//
// #9141: it used to take a *config.DHCPServerConfig and rewrite
// `group.Interfaces[i]` IN PLACE. Every caller looked safe — two of them did
// `dhcpCfg := cfg.System.DHCPServer` first — but that is a SHALLOW struct copy:
// DHCPLocalServer is a pointer, Groups is a map of pointers, and Interfaces is a
// slice, so all three are shared with the daemon's live active config and the
// rewrite landed on it. (The third caller, applyRoutingAndServices in
// daemon_apply_routing.go, passed &cfg.System.DHCPServer with no copy at all.)
//
// Measured harm — the shared config is mutated and an ATTRIBUTION one subsystem
// over flips:
//
//	BEFORE: Groups[g1].Interfaces = [reth1.0]   rgForInterfaces = 1
//	AFTER : Groups[g1].Interfaces = [ge-0-0-1.0] rgForInterfaces = 0
//
// rgForInterfaces (daemon_ddns.go) looks the group's member up in
// cfg.Interfaces.Interfaces, which is keyed by JUNOS names (`reth1`). After the
// rewrite the base name is `ge-0-0-1`, which misses, so the pool is scored RG 0
// = "not HA-owned". buildLeaseSubnetRGMap then reports no RG-owned pool at all,
// ddnsReconcileOptions sees anyRGOwnedPool false, and the unattributable-lease
// branch flips from FAIL-CLOSED to admit — the #2664 per-lease double-write /
// stale-memfile guard is disarmed. It is ORDER-DEPENDENT: the guard behaves
// differently before and after the first apply in a process lifetime, and is
// repaired only by a daemon restart (which recompiles the config from text).
//
// The peer is NOT affected: config sync ships TEXT (ShowActive -> the ConfigTree
// AST), not the compiled struct, so each node recompiles from its own copy.
//
// The copy is deliberately SHALLOW past the fields that are written: the
// family-level scalars ride along on the struct copy, the group's Pools slice is
// shared because nothing here writes it, and only the Interfaces slices — the
// only thing this function rewrites — are freshly allocated.
func resolveDHCPRethInterfaces(dhcpCfg config.DHCPServerConfig, cfg *config.Config) config.DHCPServerConfig {
	resolve := func(src *config.DHCPLocalServerConfig) *config.DHCPLocalServerConfig {
		if src == nil {
			return nil
		}
		out := *src
		if src.Groups == nil {
			return &out
		}
		groups := make(map[string]*config.DHCPServerGroup, len(src.Groups))
		for name, group := range src.Groups {
			if group == nil {
				groups[name] = nil
				continue
			}
			cp := *group
			if group.Interfaces != nil {
				ifaces := make([]string, len(group.Interfaces))
				for i, iface := range group.Interfaces {
					ifaces[i] = cfg.ResolveKernelIfName(iface)
				}
				cp.Interfaces = ifaces
			}
			groups[name] = &cp
		}
		out.Groups = groups
		return &out
	}
	out := dhcpCfg
	out.DHCPLocalServer = resolve(dhcpCfg.DHCPLocalServer)
	out.DHCPv6LocalServer = resolve(dhcpCfg.DHCPv6LocalServer)
	return out
}
