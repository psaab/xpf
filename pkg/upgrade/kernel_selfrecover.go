package upgrade

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/unix"
)

// Kernel-channel HA bounded local self-recovery (#1930 INC-2).
//
// The LANE-1 HA kernel roll is driven by an EXTERNAL orchestrator
// (scripts/deploy/xpf-deploy.py): it drains a node (ForceSecondary), reboots it
// into the candidate, and on success ResetFailover()s it back. The hazard
// (r2 AGY): if the orchestrator CRASHES while a node is drained+rebooting, the
// node comes back up still drained (all RGs ManualFailover=true, weight 0) with
// nothing to ResetFailover it — it sits passive forever, halving cluster
// capacity and leaving no automatic recovery.
//
// This is the bounded LOCAL self-recovery: at daemon startup (and periodically),
// a node that finds itself DRAINED, with NO active kernel-roll lease naming it,
// and a HEALTHY PRIMARY peer, auto-ResetFailover()s after a grace period. The
// lease is the coordination point: while a roll is legitimately in progress the
// orchestrator holds a lease naming the node, which SUPPRESSES self-recovery
// (so we never fight a real in-flight roll); once the orchestrator finishes (or
// crashes, letting the lease EXPIRE), self-recovery is free to act.
//
// Conservative by construction: it only ResetFailovers (rejoins as ELIGIBLE —
// VRRP preempt rules then decide who is primary); it never forces primary. If
// the peer is not a healthy primary, it does nothing (a real dual-down needs
// operator/orchestrator attention, not an automatic rejoin race).

// KernelRollLease is the coordination record the external orchestrator writes
// to each node it is actively rolling. Its presence + unexpired TTL SUPPRESSES
// that node's self-recovery. A crashed orchestrator's lease expires, re-enabling
// self-recovery.
type KernelRollLease struct {
	// NodeID is the cluster node-id the orchestrator is actively rolling.
	NodeID int `json:"node_id"`
	// Holder identifies the orchestrator (host/pid/run-id) for diagnostics.
	Holder string `json:"holder,omitempty"`
	// ExpiresAt is the lease TTL deadline; past it the lease is dead.
	ExpiresAt time.Time `json:"expires_at"`
}

// DefaultKernelRollLeasePath is where the orchestrator drops the per-node lease
// and where self-recovery reads it.
const DefaultKernelRollLeasePath = "/var/lib/xpf/kernel-roll.lease"

// SelfRecoveryCluster is the minimal cluster surface the self-recovery needs.
// The daemon supplies an adapter over its cluster.Manager.
type SelfRecoveryCluster interface {
	// LocalDrained reports whether THIS node is drained (all enabled RGs in
	// ManualFailover / weight 0 — the ForceSecondary state).
	LocalDrained() (bool, error)
	// LocalDrainedSince returns the earliest ManualFailoverAt among the
	// drained RGs (zero when not drained or the start is unknown). It lets
	// self-recovery require that the lease it acts on postdates the current
	// drain (#15181): a lease that already expired before this drain began
	// cannot be the fingerprint of the roll that caused this drain.
	LocalDrainedSince() (time.Time, error)
	// PeerHealthyPrimary reports whether the peer is alive AND owns the RGs
	// (a real primary that can keep forwarding while we rejoin).
	PeerHealthyPrimary() (bool, error)
	// ResetFailover clears the local manual-failover on all RGs (rejoin as
	// eligible; VRRP preempt rules then govern primary).
	ResetFailover() error
}

// SelfRecoveryConfig configures a KernelSelfRecovery.
type SelfRecoveryConfig struct {
	// NodeID is THIS node's cluster node-id (matched against a lease's NodeID).
	NodeID int
	// LeasePath is the kernel-roll lease file (default DefaultKernelRollLeasePath).
	LeasePath string
	// Grace is how long the node must continuously observe the
	// drained-no-lease-healthy-peer condition before auto-ResetFailover. It
	// absorbs the normal boot→rejoin settle so a legitimately-mid-roll node
	// (whose lease is briefly missing during a write) is not prematurely reset.
	Grace time.Duration
	// Now is the clock (injectable for tests).
	Now func() time.Time
	// Logf is an optional progress sink.
	Logf func(format string, args ...any)
	// Armed reports whether a kernel candidate is STILL armed on this node
	// (journal state >= ARMED and not yet PROMOTED/REVERTED). When it returns
	// true a candidate trial is genuinely in flight — the promotion oneshot will
	// resolve it to PROMOTED or REVERTED — so self-recovery MUST NOT rejoin the
	// node even if the orchestrator's lease has expired (r2 AGY: a legitimately
	// long-hanging roll whose lease TTL elapsed would otherwise be torn back into
	// the election as an unverified candidate -> split-brain). Optional; if nil,
	// self-recovery does not gate on armed state (tests / non-kernel callers).
	Armed func() (bool, error)
}

func (c *SelfRecoveryConfig) withDefaults() {
	if c.LeasePath == "" {
		c.LeasePath = DefaultKernelRollLeasePath
	}
	if c.Grace == 0 {
		c.Grace = 90 * time.Second
	}
	if c.Now == nil {
		c.Now = time.Now
	}
	if c.Logf == nil {
		c.Logf = func(string, ...any) {}
	}
}

// KernelSelfRecovery is the bounded local self-recovery state machine.
type KernelSelfRecovery struct {
	cfg SelfRecoveryConfig
	cl  SelfRecoveryCluster
	// drainedSince is when this node first observed the recoverable condition
	// (drained + no active lease for us + healthy peer); zero when not observed.
	drainedSince time.Time
	// leaseExpiresAt is the ExpiresAt of the lease classified by the most
	// recent readLeaseState call; Tick uses it for the drain-start gate and
	// to consume exactly the lease it acted on (#15181).
	leaseExpiresAt time.Time
}

// NewKernelSelfRecovery builds the self-recovery helper.
func NewKernelSelfRecovery(cfg SelfRecoveryConfig, cl SelfRecoveryCluster) *KernelSelfRecovery {
	cfg.withDefaults()
	return &KernelSelfRecovery{cfg: cfg, cl: cl}
}

// leaseState classifies the kernel-roll lease w.r.t. THIS node.
type leaseState int

const (
	leaseNone        leaseState = iota // no (readable) lease present
	leaseActiveOurs                    // unexpired lease naming this node
	leaseExpiredOurs                   // expired lease naming this node
	leaseOther                         // lease names the OTHER node
)

// readLeaseState classifies the on-disk lease. The DISTINCTION drives the fix
// for AGY's "self-recovery fires during manual maintenance / #1917" (r2):
// self-recovery acts ONLY on leaseExpiredOurs — the unambiguous fingerprint of
// a CRASHED kernel-roll orchestrator (it wrote a lease naming us, then died
// without clearing it). leaseNone is NOT a self-recovery trigger: a manually
// drained node or a #1917 binary-rolling drain never wrote a kernel-roll lease,
// so we leave it alone.
func (s *KernelSelfRecovery) readLeaseState() leaseState {
	s.leaseExpiresAt = time.Time{}
	data, err := os.ReadFile(s.cfg.LeasePath)
	if err != nil {
		// A genuinely absent lease is the common case (no roll in progress) — not
		// worth logging. A non-NotExist error (permission/I/O) IS actionable: log
		// it. Either way return leaseNone, which is a NO-OP in Tick (it acts only
		// on leaseExpiredOurs), so a transient read error can only DELAY recovery
		// (the safe direction), never trigger an unintended ResetFailover.
		if !os.IsNotExist(err) {
			s.cfg.Logf("kernel self-recovery: lease %s unreadable (%v); treating as no-lease "+
				"this tick (will retry)", s.cfg.LeasePath, err)
		}
		return leaseNone
	}
	var l KernelRollLease
	if err := json.Unmarshal(data, &l); err != nil {
		// A transient partial read during the orchestrator's atomic write — treat
		// as "no decision this tick" (none); the grace timer + next tick re-read
		// absorb it (r2 AGY non-atomic-write transient).
		s.cfg.Logf("kernel self-recovery: ignoring unparsable lease %s: %v", s.cfg.LeasePath, err)
		return leaseNone
	}
	// A well-formed lease MUST carry a real TTL deadline. A semantic-empty body
	// (`{}`) or one that omits expires_at decodes to the zero time AND NodeID 0
	// (the zero value); on node 0 that would slip past the NodeID guard and,
	// because any real Now() is After the zero time, classify as an ALREADY-
	// EXPIRED lease naming us — spuriously arming self-recovery and tearing a
	// deliberately drained node back into the election during a maintenance
	// window (#4872 C). Require expires_at: a missing/zero deadline is not a
	// valid lease. Treat it as no-decision (leaseNone is a NO-OP in Tick), the
	// safe direction that never triggers an unintended ResetFailover.
	if l.ExpiresAt.IsZero() {
		s.cfg.Logf("kernel self-recovery: ignoring lease %s missing required expires_at "+
			"(NodeID=%d); treating as no-lease this tick", s.cfg.LeasePath, l.NodeID)
		return leaseNone
	}
	if l.NodeID != s.cfg.NodeID {
		return leaseOther
	}
	s.leaseExpiresAt = l.ExpiresAt
	if s.cfg.Now().Before(l.ExpiresAt) {
		return leaseActiveOurs
	}
	s.cfg.Logf("kernel self-recovery: EXPIRED lease for node %d (orchestrator crashed mid-roll?)", l.NodeID)
	return leaseExpiredOurs
}

// consumeLease removes the lease self-recovery is about to act on, under
// the same flock the orchestrator uses (kernel-roll.lock next to the
// lease), and only when the on-disk lease still names this node with the
// expiry that authorized recovery (#15181). A successor's renewed or
// re-acquired lease (different expiry) is left untouched and reported as
// not consumed. An already-missing lease counts as consumed. Consuming
// BEFORE ResetFailover means a failed reset does not re-fire.
func (s *KernelSelfRecovery) consumeLease() (bool, error) {
	dir := filepath.Dir(s.cfg.LeasePath)
	lock, err := os.OpenFile(filepath.Join(dir, "kernel-roll.lock"),
		os.O_CREATE|os.O_RDWR, 0o644)
	if err != nil {
		return false, fmt.Errorf("open kernel-roll lock: %w", err)
	}
	defer lock.Close()
	if err := unix.Flock(int(lock.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		return false, nil
	}
	defer func() { _ = unix.Flock(int(lock.Fd()), unix.LOCK_UN) }()
	data, err := os.ReadFile(s.cfg.LeasePath)
	if err != nil {
		if os.IsNotExist(err) {
			return true, nil
		}
		return false, fmt.Errorf("re-read kernel-roll lease: %w", err)
	}
	var l KernelRollLease
	if err := json.Unmarshal(data, &l); err != nil {
		return false, nil
	}
	if l.NodeID != s.cfg.NodeID || !l.ExpiresAt.Equal(s.leaseExpiresAt) {
		return false, nil
	}
	if err := os.Remove(s.cfg.LeasePath); err != nil && !os.IsNotExist(err) {
		return false, fmt.Errorf("consume kernel-roll lease: %w", err)
	}
	return true, nil
}

// Tick evaluates the recovery condition once. Call it at startup and on a timer.
// It auto-ResetFailovers only after the condition holds continuously for Grace.
// Returns true iff it performed a ResetFailover this tick.
func (s *KernelSelfRecovery) Tick() (bool, error) {
	// Self-recovery fires ONLY on an EXPIRED lease naming this node — the
	// unambiguous fingerprint of a CRASHED kernel-roll orchestrator (r2 AGY):
	//   - leaseActiveOurs: a roll is legitimately in progress — never recover.
	//   - leaseOther / leaseNone: NOT our kernel roll — a manually drained node
	//     or a #1917 binary-rolling drain never wrote a lease naming us, so we
	//     must NOT auto-rejoin (that would break the operator's / #1917's
	//     maintenance window — the cross-feature interaction AGY flagged).
	//   - leaseExpiredOurs: the orchestrator wrote our lease then died without
	//     clearing it — THIS is the case self-recovery exists for.
	st := s.readLeaseState()
	if st != leaseExpiredOurs {
		s.drainedSince = time.Time{}
		return false, nil
	}

	// A still-ARMED journal means a candidate trial is genuinely in flight (the
	// promotion oneshot will drive it to PROMOTED or REVERTED), regardless of how
	// long it has taken — an expired orchestrator lease does NOT make it safe to
	// rejoin (r2 AGY long-hanging-roll TTL split-brain). Refuse self-recovery
	// while armed; the bounded promote/revert path owns the resolution. The
	// election hold (kernelUpgradeHold) keeps the node SECONDARY meanwhile.
	if s.cfg.Armed != nil {
		armed, err := s.cfg.Armed()
		if err != nil {
			// An observation error breaks the CONTINUOUS-evidence requirement:
			// reset the grace clock so a run of errored ticks (e.g. a transient
			// management outage) cannot silently age the deadline and let the next
			// positive tick rejoin immediately (#4872 D). Grace must accrue only
			// while every predicate is positively observed.
			s.drainedSince = time.Time{}
			return false, fmt.Errorf("kernel self-recovery: armed check: %w", err)
		}
		if armed {
			s.drainedSince = time.Time{}
			s.cfg.Logf("kernel self-recovery: lease expired but a candidate is STILL ARMED; " +
				"a trial is in flight (promote/revert owns it) -> NOT recovering")
			return false, nil
		}
	}

	drained, err := s.cl.LocalDrained()
	if err != nil {
		// Observation error -> reset the grace clock (see #4872 D above).
		s.drainedSince = time.Time{}
		return false, fmt.Errorf("kernel self-recovery: local drained check: %w", err)
	}
	if !drained {
		s.drainedSince = time.Time{} // not drained -> reset the timer
		return false, nil
	}

	// #15181: the expired lease must postdate THIS drain. The orchestrator
	// acquires the lease before draining, so a crashed roll that caused
	// this drain wrote a lease expiring after the drain began. A lease
	// that already expired before the drain began belongs to an earlier,
	// unrelated roll and must not tear a later operator drain back into
	// the election. An unknown drain start (zero) fails closed.
	drainedSince, err := s.cl.LocalDrainedSince()
	if err != nil {
		s.drainedSince = time.Time{}
		return false, fmt.Errorf("kernel self-recovery: local drained-since check: %w", err)
	}
	if drainedSince.IsZero() || !s.leaseExpiresAt.After(drainedSince) {
		s.drainedSince = time.Time{}
		s.cfg.Logf("kernel self-recovery: expired lease (expires %s) does not postdate "+
			"the current drain (since %s); NOT recovering a later unrelated drain (#15181)",
			s.leaseExpiresAt, drainedSince)
		return false, nil
	}

	peerOK, err := s.cl.PeerHealthyPrimary()
	if err != nil {
		// Observation error -> reset the grace clock (see #4872 D above).
		s.drainedSince = time.Time{}
		return false, fmt.Errorf("kernel self-recovery: peer health check: %w", err)
	}
	if !peerOK {
		// Drained but the peer is NOT a healthy primary — a real dual-down /
		// split scenario. Do NOT auto-rejoin (that could race a recovering
		// peer); leave it for the orchestrator/operator.
		s.drainedSince = time.Time{}
		s.cfg.Logf("kernel self-recovery: drained but peer is not a healthy primary; " +
			"NOT auto-recovering (needs orchestrator/operator)")
		return false, nil
	}

	now := s.cfg.Now()
	if s.drainedSince.IsZero() {
		s.drainedSince = now
		s.cfg.Logf("kernel self-recovery: observed drained+no-lease+healthy-peer; "+
			"will auto-ResetFailover in %s if it persists", s.cfg.Grace)
		return false, nil
	}
	if now.Sub(s.drainedSince) < s.cfg.Grace {
		return false, nil // still within grace
	}

	// Condition held for Grace -> the orchestrator is gone and left us drained.
	// Consume the lease BEFORE resetting (#15181): a lease left on disk
	// would re-fire against every later operator drain of this node.
	consumed, err := s.consumeLease()
	if err != nil {
		s.drainedSince = time.Time{}
		return false, fmt.Errorf("kernel self-recovery: consume lease: %w", err)
	}
	if !consumed {
		s.drainedSince = time.Time{}
		s.cfg.Logf("kernel self-recovery: lease changed before consumption; NOT recovering this tick")
		return false, nil
	}
	s.cfg.Logf("kernel self-recovery: drained+orphaned for %s with a healthy peer; " +
		"auto-ResetFailover (rejoin as eligible)")
	if err := s.cl.ResetFailover(); err != nil {
		return false, fmt.Errorf("kernel self-recovery: ResetFailover: %w", err)
	}
	s.drainedSince = time.Time{}
	return true, nil
}
