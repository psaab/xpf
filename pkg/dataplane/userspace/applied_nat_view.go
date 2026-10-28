package userspace

import "github.com/psaab/xpf/pkg/config"

// appliedSnapshot records the config + generation the Manager treats as
// applied by the helper. Full applies, successful retained-snapshot publishes,
// and status-loop catch-up all refresh it. FIB-only and neighbor-only generation
// changes do not. It is the generation paired with the helper's applied view.
//
// #2079: the NAT pool-utilization-alarm monitor must evaluate a single
// generation-coherent (config, counters) pair. Neither m.publishedSnapshot
// (too LOOSE — it advances on content-dedup no-op publishes and on the
// neighbor-regen update_neighbors path, which the helper records only as
// last_fib_generation, not last_snapshot_generation) nor
// m.lastSnapshot.Generation (too STRICT — BumpFIBGeneration /
// RegenerateNeighborSnapshot bump it WITHOUT a snapshot publish, so it can
// exceed the helper's last_snapshot_generation) is correct. appliedSnapshot
// is the applied identity tracked by markAppliedSnapshotLocked.

type appliedSnapshot struct {
	Config            *config.Config
	Generation        uint64
	CaptureGeneration uint64
}

// AppliedNATPoolStatus is one source-NAT pool's deduplicated live
// utilization sample, taken from the helper's last-applied generation. It
// is a config-package-free projection of SourceNATPoolStatus so that
// downstream consumers (pkg/natpoolalarm) need not depend on this package's
// wire types.
type AppliedNATPoolStatus struct {
	PoolName string
	// AddressCount is the helper's unique expanded address count (#10700),
	// used as the ports-utilization capacity denominator. Do not rederive it
	// from raw config members: overlapping members are deduplicated at apply.
	AddressCount int
	PortLow      uint16
	PortHigh     uint16
	UsedPorts    uint64
	// ExhaustionTotal is the selected row's cumulative allocator-reported
	// exhaustion events (#9902 F-026).
	ExhaustionTotal uint64
	// AllocatorID is the selected row's reporting allocator instance id
	// (#9902 F-026).
	AllocatorID uint64
	// LiveFlows / MaxTrackedFlows are the pool's live tracked-flow count and
	// tracked-flow cap (#9896) — the constraint that actually refuses new
	// flows. Zero MaxTrackedFlows (older helper) makes the flow leg
	// inapplicable downstream.
	LiveFlows       uint64
	MaxTrackedFlows uint64
	// PersistentLeases is the pool's idle-lease table occupancy (#9896 fold
	// 2): fresh-lease admission refuses at the same cap, so the alarm's
	// flow leg evaluates max(LiveFlows, PersistentLeases). Meaningful only
	// when MaxTrackedFlows > 0.
	PersistentLeases uint64
}

// AppliedNATView is a single generation-coherent snapshot for the NAT
// pool-utilization-alarm monitor (#2079). Config and Pools both belong to
// the helper's LAST-APPLIED generation. The monitor reads only cached
// in-memory state through this accessor — no control-socket I/O.
type AppliedNATView struct {
	// Config is the helper's currently applied configuration (may be nil
	// before the first apply lands). Source of truth for pool kind
	// (deterministic vs not) and rule references.
	Config *config.Config
	// Pools is deduplicated by pool name from the last 1 Hz status poll
	// (rules sharing a pool share one Arc<PortAllocatorShared> and report
	// identical UsedPorts, so one entry per pool is taken — never summed).
	Pools map[string]AppliedNATPoolStatus
	// AppliedGeneration is the generation the helper has applied.
	AppliedGeneration uint64
	// HelperCoherent is true when the cached status generation equals the
	// applied generation — i.e. the cached pool counters belong to the same
	// generation as Config. False during an in-flight apply window.
	HelperCoherent bool
	// Available is false when the dataplane helper is not running or no
	// apply has happened yet; the monitor HOLDs (makes no decision) then.
	Available bool
	// StatusSequence is m.lastStatusSeq at sample time (#9902 F-026): the
	// exhaustion monitor's freshness token.
	StatusSequence uint64
	// ProcGen is m.procGen at sample time (#9902 F-026): the
	// exhaustion monitor's helper-incarnation token.
	ProcGen uint64
}

// markAppliedSnapshotLocked captures the just-applied snapshot's config and
// generation as the helper-applied source for AppliedNATView. Caller MUST
// hold m.mu and MUST call this only AFTER a successful snapshot publish
// (full or retained-snapshot partial) or status-loop catch-up where the helper
// already echoes m.lastSnapshot.Generation.
//
// r11 (Codex r10 BLOCKER — deferred-apply reconcile-skew): the helper sets
// last_snapshot_generation the instant it ACCEPTS a snapshot
// (userspace-dp snapshot.rs:63), but a DeferWorkers (RETH-MAC bring-up) apply
// stores the snapshot and SKIPS reconcile_status_bindings — so the NAT pool
// counters (read from the coordinator's forwarding state, swapped only on
// reconcile) are still the OLD generation until the post-NotifyLinkCycle
// rebind. Capturing the NEW generation here would make AppliedNATView report
// HelperCoherent=true (status gen == applied gen) while config and counters
// are mismatched. So we record the applied snapshot ONLY on a RECONCILED
// apply: skip the capture while workers are deferred (m.deferWorkers) — the
// post-rebind capture in NotifyLinkCycle records it once the helper has
// reconciled. m.appliedSnapshot therefore stays at the previous reconciled
// generation, so coherency correctly evaluates false (HOLD) during the defer
// window.

// helperHoldsLastSnapshotLocked reports whether the helper provably holds
// m.lastSnapshot: this Manager published that generation, no full-snapshot
// publish is still pending, the helper's last status echoes the generation,
// and no apply/partial outcome is unknown. This is the status-loop catch-up
// predicate (process_status.go) plus the pending latch, reused by the
// post-link-cycle rebind (#16521) so it only marks applied snapshots the
// helper actually accepted. Caller MUST hold m.mu.
func (m *Manager) helperHoldsLastSnapshotLocked() bool {
	if m.lastSnapshot == nil {
		return false
	}
	gen := m.lastSnapshot.Generation
	return m.publishedSnapshot == gen && gen != 0 &&
		!m.pendingFullSnapshotMetadata &&
		m.lastStatus.LastSnapshotGeneration >= gen &&
		!m.applySnapshotOutcomeUnknown && m.partialOutcomeUnknown == 0
}

func (m *Manager) markAppliedSnapshotLocked() {
	if m.lastSnapshot == nil {
		return
	}
	if m.deferWorkers {
		// Deferred (not-yet-reconciled) apply — do NOT record. The
		// post-NotifyLinkCycle rebind reconcile captures the applied
		// snapshot once the helper's forwarding state is the new generation.
		return
	}
	m.appliedSnapshot = appliedSnapshot{
		Config:            m.lastSnapshot.Config,
		Generation:        m.lastSnapshot.Generation,
		CaptureGeneration: m.lastSnapshot.IpsecTunnelSnapshotGeneration,
	}
	if committer := m.captureAuthorityCommitter; committer != nil {
		committer(m.appliedSnapshot.Generation, m.lastSnapshot)
	}
	if committer := m.appliedConfigCommitter; committer != nil {
		committer(m.appliedSnapshot.Generation, m.appliedSnapshot.Config)
	}
	if committer := m.policySnapshotCommitter; committer != nil {
		committer(m.appliedSnapshot.Generation)
	}
}

// AppliedConfig returns the config from the helper's last reconciled snapshot.
// It is nil before an applied snapshot lands. The snapshot is immutable once
// published and remains the authority while a replacement publish is deferred.
func (m *Manager) AppliedConfig() *config.Config {
	if m == nil {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.appliedSnapshot.Config
}

// AppliedSnapshotGeneration returns the generation of the Manager's current
// helper-applied snapshot. Unlike LastApplyResult, this identity also advances
// after successful retained-snapshot partial publishes.
func (m *Manager) AppliedSnapshotGeneration() uint64 {
	if m == nil {
		return 0
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.appliedSnapshot.Generation
}

// AppliedNATSnapshotVerdicts is the per-rule runtime NOT-INSTALLED verdict
// carried by the helper's last reconciled snapshot (#16547). The snapshot
// builder stamps PoolUnusable/PoolUnusableReason at build time — including
// the #7717 runtime interface-SNAT overlap quarantine
// (iface_snat_egress_overlap), which is invisible to the config-only verdict
// (config.SourceNATRuleNotInstalledReason) because the overlapping address
// is learned at runtime (DHCP/netlink), not configured. Show surfaces read
// this view instead of re-deriving the quarantine from config.
type AppliedNATSnapshotVerdicts struct {
	Available bool
	// SourceNATRules maps rule name -> PoolUnusableReason for every
	// source-NAT snapshot row with PoolUnusable set.
	SourceNATRules map[string]string
	// SourceNATPools maps pool name -> PoolUnusableReason, derived from
	// the snapshot rows referencing that pool. A pool is reported only
	// when every snapshot row referencing it is unusable; a usable row
	// referencing the same pool keeps the pool armed.
	SourceNATPools map[string]string
	// NAT64Rules maps NAT64 rule-set name -> PoolUnusableReason.
	NAT64Rules map[string]string
}

// AppliedNATSnapshotVerdicts returns the runtime disarm verdicts from the
// helper's last reconciled snapshot (m.appliedSnapshot's generation). It
// reads only cached in-memory state under m.mu — no control-socket I/O —
// so show surfaces may call it at operator-request rate without adding a
// control-socket request above 1/s. Available is false before the first
// reconciled apply lands; callers then fall back to the config-only
// verdict (an unavailable runtime view must not manufacture a quarantine).
func (m *Manager) AppliedNATSnapshotVerdicts() AppliedNATSnapshotVerdicts {
	if m == nil {
		return AppliedNATSnapshotVerdicts{}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.appliedSnapshot.Generation == 0 || m.lastSnapshot == nil {
		return AppliedNATSnapshotVerdicts{}
	}
	// The verdicts describe the snapshot the helper has reconciled, which
	// is m.appliedSnapshot.Generation. m.lastSnapshot may be newer (a
	// deferred publish the helper has not accepted yet); reading it would
	// report a quarantine the dataplane is not yet enforcing. Only the
	// retained snapshot whose generation matches the applied generation
	// is authoritative here. When they differ, report unavailable rather
	// than a stale-or-future verdict.
	if m.lastSnapshot.Generation != m.appliedSnapshot.Generation {
		return AppliedNATSnapshotVerdicts{}
	}
	snap := m.lastSnapshot
	out := AppliedNATSnapshotVerdicts{
		Available:      true,
		SourceNATRules: make(map[string]string),
		SourceNATPools: make(map[string]string),
		NAT64Rules:     make(map[string]string),
	}
	poolBad := make(map[string]string)
	poolUsable := make(map[string]bool)
	for i := range snap.SourceNAT {
		row := &snap.SourceNAT[i]
		if row.PoolName != "" && !row.PoolUnusable {
			poolUsable[row.PoolName] = true
		}
		if !row.PoolUnusable {
			continue
		}
		reason := row.PoolUnusableReason
		if reason == "" {
			reason = "pool_unusable"
		}
		if _, exists := out.SourceNATRules[row.Name]; !exists {
			out.SourceNATRules[row.Name] = reason
		}
		if row.PoolName != "" {
			if _, exists := poolBad[row.PoolName]; !exists {
				poolBad[row.PoolName] = reason
			}
		}
	}
	for name, reason := range poolBad {
		if !poolUsable[name] {
			out.SourceNATPools[name] = reason
		}
	}
	for i := range snap.NAT64 {
		row := &snap.NAT64[i]
		if !row.PoolUnusable {
			continue
		}
		reason := row.PoolUnusableReason
		if reason == "" {
			reason = "pool_unusable"
		}
		if _, exists := out.NAT64Rules[row.Name]; !exists {
			out.NAT64Rules[row.Name] = reason
		}
	}
	return out
}

// AppliedNATView returns the generation-coherent NAT view for the #2079
// pool-utilization-alarm monitor: the helper's last-applied config paired
// with the deduplicated pool counters from the same applied generation. It
// reads only cached in-memory state under m.mu (no control-socket I/O).
func (m *Manager) AppliedNATView() AppliedNATView {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Helper must be running for any of the cached state to be meaningful.
	if m.proc == nil || m.proc.Process == nil {
		return AppliedNATView{Available: false}
	}
	if m.appliedSnapshot.Generation == 0 || m.appliedSnapshot.Config == nil {
		// No full apply has landed yet — nothing applied to evaluate.
		return AppliedNATView{Available: false}
	}

	// r11: coherency additionally requires workers NOT be deferred. During a
	// RETH-MAC bring-up defer window the helper has accepted the new snapshot
	// generation (status echoes it) but has NOT reconciled its forwarding
	// state — the NAT pool counters are still the old generation. Belt-and-
	// suspenders alongside the deferred-apply capture skip: even if the daemon
	// has already cleared m.deferWorkers in the narrow window before the
	// rebind, the capture-skip keeps m.appliedSnapshot at the previous
	// reconciled generation, so the equality below is already false. This
	// guard makes the HOLD explicit for the in-window state.
	coherent := !m.deferWorkers &&
		m.lastStatus.LastSnapshotGeneration == m.appliedSnapshot.Generation
	pools := make(map[string]AppliedNATPoolStatus, len(m.lastStatus.SourceNATPools))
	// selectedMax tracks each selected row's MaxTrackedFlows for the
	// constructed-first rule below.
	selectedMax := make(map[string]uint64, len(m.lastStatus.SourceNATPools))
	for _, p := range m.lastStatus.SourceNATPools {
		if p.PoolName == "" {
			continue
		}
		// Dedup by pool name, preferring CONSTRUCTED allocators (#9902
		// F-026): a poisoned rule (#9874) keeps its pool_mode but builds no
		// allocator, and its status row reports MaxTrackedFlows == 0 — the
		// signal is the zero CAP, not a zeroed row (a default allocator
		// still mints a nonzero allocator_id at allocator.rs:1412) — so
		// first-wins would take the poisoned row whenever it sorts first.
		// Constructed ⟺ MaxTrackedFlows>0 is airtight (the gate requires
		// total_pool>0 + no failure + !poisoned, and a constructed
		// capacity≥1 always yields max≥1; the default is 0), so a
		// constructed row displaces a default one; ties keep the first.
		// NEVER sum. This fixes selection for UsedPorts too (same rows).
		if _, seen := pools[p.PoolName]; seen {
			if selectedMax[p.PoolName] > 0 || p.MaxTrackedFlows == 0 {
				continue
			}
		}
		selectedMax[p.PoolName] = p.MaxTrackedFlows
		pools[p.PoolName] = AppliedNATPoolStatus{
			PoolName:         p.PoolName,
			AddressCount:     p.AddressCount,
			PortLow:          p.PortLow,
			PortHigh:         p.PortHigh,
			UsedPorts:        p.UsedPorts,
			ExhaustionTotal:  p.ExhaustionTotal,
			AllocatorID:      p.AllocatorID,
			LiveFlows:        p.LiveFlows,
			MaxTrackedFlows:  p.MaxTrackedFlows,
			PersistentLeases: p.PersistentLeases,
		}
	}

	return AppliedNATView{
		Config:            m.appliedSnapshot.Config,
		Pools:             pools,
		AppliedGeneration: m.appliedSnapshot.Generation,
		HelperCoherent:    coherent,
		Available:         true,
		StatusSequence:    m.lastStatusSeq,
		ProcGen:           m.procGen,
	}
}
