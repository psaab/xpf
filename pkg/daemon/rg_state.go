package daemon

import (
	"sync"
	"time"
)

// rgStateMachine tracks the combined cluster + VRRP state for a single
// redundancy group. Both watchClusterEvents and watchVRRPEvents funnel
// transitions through this struct, which determines the desired rg_active
// value from the combined inputs.
//
// Activation rule (default): rg_active = clusterPri || allVrrpMaster
//   - Cluster Primary alone activates (avoids dual-inactive window while
//     VRRP catches up)
//   - ALL VRRP instances MASTER activates (prevents partial ownership
//     when one interface reaches MASTER before others — #132)
//   - Both false → deactivate
//
// Activation rule (strict-vip-ownership): rg_active = allVrrpMaster
//   - VRRP master state is the sole authority for activation
//   - ALL instances must be MASTER (prevents partial ownership — #132)
//   - Prevents brief dual-active window during failover in same-L2 deployments
//
// Desired-vs-applied tracking: the state machine tracks both what the
// desired rg_active value should be and whether it was successfully applied
// to the BPF map. The reconciliation loop retries when they diverge.
//
// The epoch counter is monotonically incremented on every state change,
// enabling stale-update detection in the reconciliation loop.
type rgStateMachine struct {
	mu            sync.Mutex
	clusterPri    bool            // cluster says Primary for this RG
	vrrpInstances map[string]bool // per-interface VRRP master state
	active        bool            // desired rg_active value
	applied       bool            // last successfully applied rg_active value
	applyPending  bool            // true when desired != applied
	// invalidateSeq counts InvalidateApplied calls (#6799). It is the key that
	// makes "did anything re-arm the debt while my apply was in flight?"
	// answerable. Guarded by mu, like every field above.
	invalidateSeq uint64
	epoch         uint64 // monotonic counter

	// VRRP posture mismatch tracking (#86): detect when VRRP state
	// doesn't match cluster expectations and only take corrective action
	// after a sustained mismatch (vrrpPostureDelay). This prevents the
	// reconcile loop from fighting transient states (sync-hold, election,
	// hitless restart).
	vrrpMismatchSince time.Time // when mismatch was first detected (zero = no mismatch)

	startedAt time.Time // when this state machine was created (for posture delay selection)

	// kernelUpgradeHold (#14404): while set, desired is forced false
	// regardless of clusterPri / VRRP MASTER. The daemon mirrors the
	// cluster hold onto every rgStateMachine (syncRGKernelUpgradeHold);
	// without this term a VRRP MASTER event alone (cluster secondary)
	// activates rg_active, removes blackholes, and starts RETH services
	// on an unverified candidate kernel.
	kernelUpgradeHold bool

	// Strict VIP ownership (#104): when enabled, rg_active is derived
	// solely from VRRP master state, NOT clusterPri || anyVrrpMaster.
	// This prevents the brief dual-active window during failover.
	strictVIPOwnership bool

	// Log-once state for the reconcile loop (#757). reconcileRGStateLoop
	// (daemon_ha.go) retries UpdateRGActive on its 2s ticker when applied
	// != desired, and additionally whenever a dropped event wakes it via
	// reconcileNowCh — so the real rate is at least one pass per RG every
	// 2s and bursts higher under event loss. Without these gates the
	// "retrying" INFO and "failed" WARN fire on every one of those passes
	// for as long as the helper is down, which buries real diagnostics.
	//
	// Reset contract: both fields are cleared by MarkApplied() AND by
	// RecordApplied() on success. A successful apply starts a fresh
	// streak so the next failure surfaces one WARN and the next retry
	// streak surfaces one INFO.
	lastRetryLogged bool   // "retrying" INFO already emitted for the current failure streak
	lastApplyErrMsg string // text of last error WARN'd in the current failure streak (empty = not warned)
}

// rgTransition is returned by state machine updates to inform the caller
// whether rg_active changed and what the new value is.
type rgTransition struct {
	Changed bool   // rg_active value changed
	Active  bool   // new rg_active value
	Epoch   uint64 // current epoch after this transition
	// InvalidateSeq is the invalidation counter observed when this transition
	// was produced (#6799). An apply carries it across its off-lock dataplane
	// write so RecordApplied can tell whether a SECOND writer re-armed the
	// retry debt while that write was in flight. The epoch cannot answer that:
	// InvalidateApplied deliberately does not bump it, and even if it did, the
	// desired-value fallback would let the record through anyway.
	InvalidateSeq uint64
}

func newRGStateMachine() *rgStateMachine {
	return &rgStateMachine{
		vrrpInstances: make(map[string]bool),
		startedAt:     time.Now(),
	}
}

// SetStrictVIPOwnership enables or disables strict VIP ownership mode.
// When enabled, rg_active is derived from VRRP master state only.
func (s *rgStateMachine) SetStrictVIPOwnership(strict bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.strictVIPOwnership = strict
}

// IsStrictVIPOwnership returns whether strict VIP ownership mode is enabled.
func (s *rgStateMachine) IsStrictVIPOwnership() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.strictVIPOwnership
}

// SetCluster updates the cluster Primary/Secondary state and returns
// the resulting rg_active transition.
func (s *rgStateMachine) SetCluster(isPrimary bool) rgTransition {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.clusterPri = isPrimary
	return s.reconcileLocked()
}

// SetVRRP updates the VRRP state for a specific interface and returns
// the resulting rg_active transition.
func (s *rgStateMachine) SetVRRP(iface string, isMaster bool) rgTransition {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.vrrpInstances[iface] = isMaster
	return s.reconcileLocked()
}

// IsActive returns the DESIRED rg_active value — what the state machine wants
// the dataplane to be, not what it is.
//
// #8326: the name does not say "desired" and that ambiguity was load-bearing.
// A comment in rg_forwarding_status_7367.go asserted "IsActive is the APPLIED
// value, not DesiredActive", which was false, and the render built on it
// reported a redundancy group as forwarding whenever the state machine merely
// WANTED it to be — including when the apply failed, which is the exact case
// that render exists to surface. Use AppliedActive for what was actually
// written to the dataplane.
func (s *rgStateMachine) IsActive() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.active
}

// AppliedActive returns the rg_active value the daemon last SUCCESSFULLY
// applied to the dataplane, which is what the node is actually forwarding on.
//
// Distinct from IsActive by construction, not by convention: they read
// different fields, and they diverge for the whole window between a desired
// change and its successful apply — which includes forever, when the apply
// keeps failing. That window is the one an operator consults
// `show chassis cluster` to detect, so a status surface must read this.
func (s *rgStateMachine) AppliedActive() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.applied
}

// Epoch returns the current epoch counter.
func (s *rgStateMachine) Epoch() uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.epoch
}

// AnyVRRPMaster returns true if any VRRP instance is MASTER.
func (s *rgStateMachine) AnyVRRPMaster() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.anyMasterLocked()
}

// AllVRRPMaster returns true if ALL VRRP instances are MASTER.
// Returns false if no instances exist.
func (s *rgStateMachine) AllVRRPMaster() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.allMasterLocked()
}

// VRRPInstanceCount returns how many VRRP instances are currently known
// for this RG (#15165). Zero is ambiguous on its own: it means either no
// instance is expected (RG0 in legacy mode, which never gets one) or an
// expected instance has not instantiated yet. Callers must combine it
// with the config-derived expected count before treating zero as
// "no VRRP gate applies".
func (s *rgStateMachine) VRRPInstanceCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.vrrpInstances)
}

// Reconcile overwrites the internal state with the authoritative cluster
// and VRRP state, then recomputes rg_active. Called by the periodic
// reconciliation loop to correct any drift from dropped events.
// vrrpStates maps interface name → isMaster.
func (s *rgStateMachine) Reconcile(clusterPri bool, vrrpStates map[string]bool) rgTransition {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.clusterPri = clusterPri
	// Replace all VRRP instance states.
	s.vrrpInstances = make(map[string]bool, len(vrrpStates))
	for iface, isMaster := range vrrpStates {
		s.vrrpInstances[iface] = isMaster
	}
	return s.reconcileLocked()
}

// MarkApplied records that the desired rg_active value was successfully
// written to the BPF map. Clears any sticky log-once state so the next
// failure/retry cycle produces a fresh WARN and INFO (#757).
func (s *rgStateMachine) MarkApplied(active bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.markAppliedLocked(active)
}

// markAppliedLocked is the ONE body every convergence record shares (#6799).
// MarkApplied and RecordApplied both call it, so the #757 log-once gate reset
// cannot drift between them — that drift was a real reviewer finding once
// (an apply path that reset the gates and one that did not), and it is now
// structurally impossible rather than pinned by a duplicate test.
// Caller MUST hold s.mu.
func (s *rgStateMachine) markAppliedLocked(active bool) {
	s.applied = active
	if s.applied == s.active {
		s.applyPending = false
	}
	s.lastRetryLogged = false
	s.lastApplyErrMsg = ""
}

// InvalidateApplied re-arms the desired-vs-applied retry after a writer OTHER
// than the state machine's own apply path has written rg_active in the
// dataplane.
//
// #6530: applied/applyPending are advanced only by MarkApplied and
// RecordApplied, and neither has a path that SETS applyPending — both only
// CLEAR it, when applied == active. So any second writer to rg_active leaves
// the state machine believing it has already converged: reconcileRGState's
// retry predicate (tr.Changed || s.NeedsApply()) sees desired == applied and
// does nothing, and nothing else re-arms it. Forwarding then stays wherever
// that second writer left it, permanently — a blackhole with no retry, not a
// glitch the next tick repairs. fenceAllRedundancyGroups (daemon_ha_sync.go)
// is the instance that motivated this entry point; it exists so a future
// third writer is one call away from correct rather than one review away from
// a blackhole. (daemon_run_shutdown.go's SetRGActive(false) is a third writer
// today and deliberately does NOT call this: the daemon is exiting, there is
// no later reconcile pass to arm.)
//
// It arms the retry UNCONDITIONALLY rather than recording whatever value the
// second writer wrote. A write that returned an error may still have partially
// landed, so the only claim the state machine can honestly make afterwards is
// "not known to have converged"; forcing a re-drive is the fail-closed reading
// and costs at most one idempotent re-apply on the next reconcile tick.
// Callers must invoke it AFTER their write so the reconcile pass that observes
// the re-armed retry runs against settled dataplane state.
//
// applied is set to the negation of active rather than left alone, to preserve
// the struct invariant reconcileLocked relies on (applyPending is true exactly
// when applied != active); a later successful MarkApplied clears both together.
//
// It deliberately does not bump the epoch. An epoch-guarded record already fails
// routinely — reconcileLocked bumps the epoch on every 2s pass — and
// RecordApplied falls back to accepting whenever the desired value still
// matches what that caller wrote, so an epoch bump would not stop a concurrent
// in-flight apply from stamping over this — which is exactly why #6799 added
// the invalidation counter below instead of bumping the epoch here.
// Ordering between two unsynchronised rg_active writers is not something this
// struct can resolve; what it can guarantee is that it never silently believes
// a convergence it did not observe.
func (s *rgStateMachine) InvalidateApplied() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.applied = !s.active
	s.applyPending = true
	// #6799: stamp the invalidation so an apply that was ALREADY IN FLIGHT
	// when this ran cannot stamp over the debt it just armed. The paragraph
	// above correctly observed that an epoch bump would not achieve this;
	// this counter is what does, because RecordApplied compares the value the
	// in-flight transition captured before it started.
	s.invalidateSeq++
}

// ShouldLogRetry reports whether the "reconcile: retrying rg_active apply"
// INFO should be emitted this tick. Returns true the first time the
// retry loop fires after a transition; subsequent ticks in the same
// retry streak stay silent until MarkApplied() clears the flag (#757).
func (s *rgStateMachine) ShouldLogRetry() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.lastRetryLogged {
		return false
	}
	s.lastRetryLogged = true
	return true
}

// ShouldLogApplyError reports whether the given error should be WARN'd
// this tick. Returns true only when the message text differs from the
// last WARN'd text for this RG, so a steady-state retry loop stays
// silent while a changing fault still surfaces (#757).
func (s *rgStateMachine) ShouldLogApplyError(errMsg string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.lastApplyErrMsg == errMsg {
		return false
	}
	s.lastApplyErrMsg = errMsg
	return true
}

// NeedsApply returns true if the desired rg_active differs from the last
// successfully applied value.
func (s *rgStateMachine) NeedsApply() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.applyPending
}

// #8326: DesiredActive was REMOVED. It returned s.active — byte-identical to
// IsActive — and had no non-test caller. Two names for one field is what made
// "IsActive is the APPLIED value, not DesiredActive" read as a considered
// distinction rather than a mistake: the sentence is only plausible if the two
// accessors differ, and nothing in the code said they did not. The pair that
// exists now, IsActive and AppliedActive, reads different fields.

// RecordApplied records that `active` was written to the dataplane for the
// transition tr, and reports whether that record was ACCEPTED (#6799).
//
// It is the single decision point for "may this apply claim convergence?", and
// it makes that decision and acts on it under ONE lock hold. The predecessor —
// recordRGActiveAppliedIfCurrentOrStable — took THREE separate holds
// (ApplyIfCurrent, then CurrentDesired, then MarkApplied), so the state it
// decided on could move between the decision and the act. That is the same
// no-cached-boolean discipline pkg/ra's finishDrainDecision settled on: re-read
// under the lock hold that performs the act, never carry a verdict across an
// unlock.
//
// Two independent reasons to REFUSE, and they answer different questions:
//
//   - The invalidation counter moved. Some OTHER writer touched rg_active while
//     this apply was in flight and armed the retry debt (the cluster fence does
//     exactly this, #6530). Recording convergence now would erase that debt, and
//     the erasure is not temporary: reconcileLocked only SETS applyPending when
//     applied != active, so once this clears it with the two in agreement,
//     nothing re-arms it and reconcileRGState's `tr.Changed || s.NeedsApply()`
//     retry never fires again. Forwarding then stays wherever the other writer
//     left it — precisely the "fenced-then-recovered primary stays dark forever"
//     failure #6530 was written to prevent.
//   - The epoch moved AND the desired value no longer matches what was written.
//     A moved epoch alone is routine (reconcileLocked bumps it every 2s pass),
//     so refusing on it alone would reject nearly every apply; what matters is
//     whether the value this caller wrote is still the value the machine wants.
//
// On acceptance it mirrors MarkApplied exactly, including the #757 log-once
// gate reset, so the two paths cannot drift.
func (s *rgStateMachine) RecordApplied(tr rgTransition, active bool) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.invalidateSeq != tr.InvalidateSeq {
		return false
	}
	if s.epoch != tr.Epoch && s.active != active {
		return false
	}
	s.markAppliedLocked(active)
	return true
}

// CurrentDesired returns the current desired active state and epoch
// atomically. Use this to re-read the authoritative state before
// applying side effects in race-prone paths.
func (s *rgStateMachine) CurrentDesired() (active bool, epoch uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.active, s.epoch
}

// SetKernelUpgradeHold mirrors the cluster kernel-upgrade hold onto this
// RG (#14404). While held, reconcileLocked forces desired=false; clearing
// re-derives desired from the retained cluster/VRRP inputs so a VRRP
// MASTER that arrived (and was suppressed) while held activates on clear
// without needing a new event. Returns the resulting transition.
func (s *rgStateMachine) SetKernelUpgradeHold(held bool) rgTransition {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.kernelUpgradeHold = held
	return s.reconcileLocked()
}

// KernelUpgradeHeld reports the #14404 hold mirrored on this RG.
func (s *rgStateMachine) KernelUpgradeHeld() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.kernelUpgradeHold
}

func (s *rgStateMachine) reconcileLocked() rgTransition {
	s.epoch++
	var desired bool
	if s.kernelUpgradeHold {
		desired = false // #14404: hold is authority until the marker clears it
	} else if s.strictVIPOwnership {
		desired = s.allMasterLocked() // VRRP-only: ALL instances must be MASTER (#132)
	} else {
		desired = s.clusterPri || s.allMasterLocked() // ALL VRRP instances required (#132)
	}
	changed := desired != s.active
	s.active = desired
	if s.active != s.applied {
		s.applyPending = true
	}
	return rgTransition{
		Changed:       changed,
		Active:        desired,
		Epoch:         s.epoch,
		InvalidateSeq: s.invalidateSeq,
	}
}

func (s *rgStateMachine) anyMasterLocked() bool {
	for _, m := range s.vrrpInstances {
		if m {
			return true
		}
	}
	return false
}

func (s *rgStateMachine) allMasterLocked() bool {
	if len(s.vrrpInstances) == 0 {
		return false
	}
	for _, m := range s.vrrpInstances {
		if !m {
			return false
		}
	}
	return true
}

// vrrpPostureDelayStartup is the posture mismatch delay used during the
// first 30 seconds after daemon startup. The longer delay avoids fighting
// transient states like sync-hold, VRRP election, and hitless restart.
const vrrpPostureDelayStartup = 10 * time.Second

// vrrpPostureDelaySteadyState is the posture mismatch delay used after
// the startup window. In normal operation, 2 seconds is enough to ride
// out brief VRRP election jitter while still recovering quickly from a
// stuck mismatch (#101).
const vrrpPostureDelaySteadyState = 2 * time.Second

// vrrpPostureStartupWindow is how long after state machine creation the
// startup (conservative) delay is used before switching to steady-state.
const vrrpPostureStartupWindow = 30 * time.Second

// vrrpPostureMismatch describes the type of posture correction needed.
type vrrpPostureMismatch int

const (
	vrrpPostureOK          vrrpPostureMismatch = iota // no correction needed
	vrrpPostureNeedsMaster                            // cluster=primary but VRRP != MASTER
	vrrpPostureNeedsResign                            // cluster=secondary but VRRP == MASTER
)

// CheckVRRPPosture checks whether VRRP state matches cluster expectations
// and returns a correction action if the mismatch has persisted long enough.
// Uses a conservative 10s delay during the startup window (first 30s) and
// a faster 2s delay in steady state. Resets the mismatch timer when state
// matches.
//
// expectedInstances is the number of RETH VRRP instances the active config
// says SHOULD exist for this RG (derived by the caller from
// vrrp.CollectRethInstances). It closes the instantiated-only inventory gap:
// the instantiated set (s.vrrpInstances) only contains instances that
// actually came up, so an instance that failed to instantiate is invisible
// and "all present are MASTER" would wrongly read as complete primary
// posture. A value <= 0 means the caller has no config-derived expectation,
// in which case the instantiated count is used as the floor (no missing
// instance is inferred).
//
// Complete primary posture (#5843) requires EVERY expected VRRP instance to
// be MASTER — not merely ANY. The prior anyMaster classification masked
// partial RETH ownership: with two RETH VRRP instances in one RG, one MASTER
// + one BACKUP (or one MASTER + one failed-to-instantiate) read as OK, the
// mismatch timer was cleared, and UpdateRGPriority was never re-driven, so
// the non-MASTER interface's VIP stayed peer-owned / blackholed and was
// never repaired.
//
// The caller is responsible for skipping this check during sync-hold.
func (s *rgStateMachine) CheckVRRPPosture(now time.Time, expectedInstances int) vrrpPostureMismatch {
	s.mu.Lock()
	defer s.mu.Unlock()

	// If no VRRP instances exist for this RG (e.g. member interface
	// missing after reboot), posture correction is impossible — there is
	// nothing to drive UpdateRGPriority against — so skip. This bounds the
	// inventory-gap fix to the PARTIAL case (>=1 instantiated): a fully
	// absent RG is left to reconcileVRRPInstances' re-instantiation.
	// #14404: while the kernel-upgrade hold is armed the hold — not the
	// posture timer — is the authority. Reporting NeedsResign here would
	// ResignRG (priority 0), then the 2s reconcile re-drives priority from
	// config and the instance re-promotes: MASTER-flapping, not held-down.
	// The VRRP hold gate (becomeMaster refusal) keeps it BACKUP; posture
	// stays silent until the hold clears.
	if s.kernelUpgradeHold {
		s.vrrpMismatchSince = time.Time{}
		return vrrpPostureOK
	}
	if len(s.vrrpInstances) == 0 {
		s.vrrpMismatchSince = time.Time{}
		return vrrpPostureOK
	}

	instantiated := len(s.vrrpInstances)
	expected := expectedInstances
	if expected < instantiated {
		// No config expectation (<=0) or a stale under-count: never treat
		// the instantiated instances themselves as "missing".
		expected = instantiated
	}

	// Complete primary posture: every instantiated instance is MASTER AND
	// no expected instance is missing. allMasterLocked covers the first
	// clause; instantiated >= expected covers the inventory gap (an RG
	// expecting 2 with only 1 instantiated is NOT complete even if that
	// one is MASTER).
	allExpectedMaster := s.allMasterLocked() && instantiated >= expected
	// Resignation still keys off ANY master: when cluster=secondary, even
	// a single lingering MASTER instance must resign.
	anyMaster := s.anyMasterLocked()

	var mismatch vrrpPostureMismatch
	switch {
	case s.clusterPri && !allExpectedMaster:
		// Cluster says we're primary but not every expected VRRP instance
		// is MASTER (some BACKUP/stuck, or an expected instance missing).
		mismatch = vrrpPostureNeedsMaster
	case !s.clusterPri && anyMaster:
		// Cluster says secondary but VRRP is still MASTER.
		mismatch = vrrpPostureNeedsResign
	default:
		// State matches — clear mismatch timer.
		s.vrrpMismatchSince = time.Time{}
		return vrrpPostureOK
	}

	// Start or continue mismatch tracking.
	if s.vrrpMismatchSince.IsZero() {
		s.vrrpMismatchSince = now
		return vrrpPostureOK // first detection, don't act yet
	}

	// Use conservative delay near startup (sync-hold, election), fast
	// correction in steady state (#101).
	delay := vrrpPostureDelaySteadyState
	if now.Sub(s.startedAt) < vrrpPostureStartupWindow {
		delay = vrrpPostureDelayStartup
	}

	if now.Sub(s.vrrpMismatchSince) < delay {
		return vrrpPostureOK // mismatch hasn't persisted long enough
	}

	// Sustained mismatch — reset timer and signal correction.
	s.vrrpMismatchSince = time.Time{}
	return mismatch
}
