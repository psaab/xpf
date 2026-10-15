package cluster

import "sort"

// Adapter predicates for the #1930 INC-2 kernel-channel bounded local
// self-recovery (pkg/upgrade.KernelSelfRecovery). They are read-only views over
// the RG/peer state plus a reset-all wrapper; the recovery POLICY (lease,
// grace, when to act) lives in pkg/upgrade so this file only exposes the facts.

// LocalDrained reports whether THIS node is in the ForceSecondary-drained state:
// every ENABLED redundancy group is manually-failed-over with weight 0 (i.e. the
// node deliberately yielded all RGs to the peer). A node with no enabled RGs is
// NOT considered drained (there is nothing to recover).
func (m *Manager) LocalDrained() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	enabled := 0
	for _, rg := range m.groups {
		if rg.State == StateDisabled {
			continue
		}
		enabled++
		if !rg.ManualFailover || rg.Weight != 0 {
			return false
		}
	}
	return enabled > 0
}

// PeerHealthyPrimary reports whether the peer is alive AND currently owns at
// least one redundancy group as primary — i.e. a real primary that is carrying
// traffic while this (drained) node could safely rejoin as eligible. Used by
// self-recovery to refuse auto-rejoin during a real dual-down / split.
func (m *Manager) PeerHealthyPrimary() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if !m.peerAlive {
		return false
	}
	for _, pg := range m.peerGroups {
		if pg.State == StatePrimary {
			return true
		}
	}
	return false
}

// SetKernelUpgradeHold holds this node SECONDARY in election unconditionally
// (#1930 INC-2 — a kernel-upgrade candidate boot must not become primary until
// the promotion gate verifies the dataplane). Unlike ManualFailover this is NOT
// auto-cleared for an isolated node, so a candidate that cannot see the peer
// still cannot blackhole traffic by claiming primary (r2 AGY Critical). Set it
// BEFORE Start() on a candidate boot. Idempotent.
// reason must be one of the KernelUpgradeHold* constants above; it is what the
// status surfaces render, so a caller that cannot say WHY it is holding should
// not be holding (#6495).
func (m *Manager) SetKernelUpgradeHold(reason string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.kernelUpgradeHold = true
	m.kernelUpgradeHoldReason = reason
	// Defense in depth: the daemon sets the hold before the first election, so
	// normally no group is primary yet. But setting the hold only BLOCKS future
	// promotions — it must also DEMOTE any group that is already primary, so the
	// hold is correct regardless of call ordering (r2 AGY Finding 1). Idempotent:
	// a no-op when nothing is primary (the common candidate-boot case).
	ids := make([]int, 0, len(m.groups))
	for id := range m.groups {
		ids = append(ids, id)
	}
	sort.Ints(ids)
	for _, id := range ids {
		rg := m.groups[id]
		if rg.State == StatePrimary {
			rg.State = StateSecondary
			rg.FailoverCount++
			rg.transferCommitRolePinned = false
			m.sendEvent(rg.GroupID, StatePrimary, StateSecondary, "kernel-upgrade hold armed")
		}
	}
}

// The operator-facing explanations rendered wherever a node is held SECONDARY
// by the kernel-upgrade gate (#6495).
//
// There are TWO of them because the daemon sets this ONE flag for two
// materially different reasons, and the operator's next action differs between
// them. A single string would be a false statement in one of the two cases:
//
//   - Candidate: a candidate kernel is genuinely ARMED. The hold releases when
//     the durable promotion marker confirms the running kernel. Nothing to do
//     but wait for the promotion gate.
//   - UnreadableJournal: the #5682 fail-closed hold. IsArmed returned an ERROR
//     — the journal exists but cannot be read or parsed — so the daemon could
//     not establish whether anything is armed and held fail-closed. There may
//     be no candidate at all. The operator's action is to fix /var/lib/xpf, not
//     to wait for a promotion that may never come.
//
// Telling an operator "held until the promotion marker confirms the running
// kernel" on a fail-closed hold asserts a candidate exists and that a marker
// will resolve it, both of which may be false. That is the same class of defect
// as the invisibility this issue is about, one layer in.
//
// These live HERE, next to the flag they explain, rather than in pkg/upgrade:
// pkg/cluster owns the hold (the flag, the election gate, the status
// annotation), pkg/upgrade only records what was armed. The daemon carries the
// active one across when it assembles the kernel-upgrade status, so `show
// chassis cluster status` and `show system kernel-upgrade` render one string.
const (
	KernelUpgradeHoldCandidate = "kernel-candidate promotion gate (held until the promotion marker confirms the running kernel)"

	KernelUpgradeHoldUnreadableJournal = "kernel-upgrade journal unreadable — held fail-closed (#5682) until the state can be re-read; whether a candidate is armed is UNKNOWN, so this hold may not clear on its own"
)

// KernelUpgradeHeld reports whether the kernel-upgrade election hold is set.
// Used by the daemon's reconcile loop to release the hold against the durable
// promotion marker: the promotion gate runs in a SEPARATE process
// (xpf-kernel-promote.service, After=xpfd) that clears only the on-disk journal
// and writes the marker, so the running daemon must notice the verified
// promotion (marker == running kernel) and release the hold itself.
func (m *Manager) KernelUpgradeHeld() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.kernelUpgradeHold
}

// KernelUpgradeHoldReason returns the operator-facing explanation for the
// current hold, or "" when no hold is set (#6495).
//
// KernelUpgradeHeld() alone answers only "held: yes/no", which surfaces the
// hold without letting an operator tell WHICH hold it is — and the two have
// different remedies. Callers rendering the hold must use this, not a literal.
func (m *Manager) KernelUpgradeHoldReason() string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if !m.kernelUpgradeHold {
		return ""
	}
	return m.kernelUpgradeHoldReason
}

// ClearKernelUpgradeHold releases the kernel-upgrade election hold and re-runs
// election so the node can take its normal role. Callers: (1) the daemon's
// reconcileKernelUpgradeHold once the promotion marker confirms THIS kernel was
// verified+promoted, and (2) ResetAllFailover (the local self-recovery rejoin).
// The orchestrator's gRPC `rejoin` clears the hold via a third path —
// Manager.ResetFailover drops it inline per-RG so the node is election-eligible
// the INSTANT rejoin returns, closing the never-both-down gap (r2 Codex HIGH:
// otherwise the driver drains the peer while this node is still held). A
// reverted/failed roll deliberately KEEPS the hold (fail-safe); it is then
// dropped by the reboot to known-good, where it is never re-set.
func (m *Manager) ClearKernelUpgradeHold() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.kernelUpgradeHold {
		m.kernelUpgradeHold = false
		m.kernelUpgradeHoldReason = ""
		// Re-elect with the same peer-aware dispatch the rest of the manager
		// uses: an isolated cleared node (peerAlive=false) must go through the
		// single-node path to claim primary; runElection alone would not promote
		// it. Both require m.mu held (we hold it).
		if m.peerAlive {
			m.runElection()
		} else {
			m.electSingleNode()
		}
	}
}

// ResetAllFailover clears manual failover on every redundancy group (rejoin as
// eligible; the election + VRRP preempt rules then decide primary). Used by the
// kernel self-recovery when an orchestrator crash left this node orphaned-drained.
// It also clears any kernel-upgrade election hold (the rejoin path).
func (m *Manager) ResetAllFailover() error {
	m.mu.RLock()
	ids := make([]int, 0, len(m.groups))
	for id := range m.groups {
		ids = append(ids, id)
	}
	m.mu.RUnlock()
	sort.Ints(ids)
	if len(ids) == 0 {
		m.ClearKernelUpgradeHold()
		return nil
	}
	for _, id := range ids {
		if err := m.ResetFailover(id); err != nil {
			return err
		}
	}
	return nil
}
