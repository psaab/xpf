package userspace

// HA state machine for the userspace dataplane: redundancy-group ownership
// (UpdateRGActive), the watchdog heartbeat and its update_ha_state IPC
// throttle, the helper HA-state publish/clear (including the #5487 retry
// debt), HA group inventory seeding and shim-map refresh, the desired
// forwarding-arm reconcile, and HA takeover readiness.

import (
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/cilium/ebpf"
	"github.com/psaab/xpf/pkg/config"

	"github.com/psaab/xpf/pkg/dataplane"
)

// syncHAWatchdogOnlyLocked syncs HA state to the helper from the periodic
// poll. Uses syncHAStateLocked which only refreshes watchdog timestamps
// (not Active state) to avoid racing with UpdateRGActive.
func (m *Manager) syncHAWatchdogOnlyLocked() error {
	return m.syncHAStateLocked()
}

func (m *Manager) syncHAStateLocked() error {
	if m.proc == nil || m.proc.Process == nil {
		return nil
	}
	// Refresh watchdog timestamps from BPF but preserve the Active state
	// set by UpdateRGActive. Re-reading Active from BPF maps races with
	// the periodic status poll — if the poll syncs first, the helper sees
	// no delta and skips FlushFlowCaches + DemoteOwnerRG.
	if err := m.refreshHAWatchdogOnlyFromMapsLocked(); err != nil {
		return err
	}
	if len(m.haGroups) == 0 {
		return nil
	}
	groups := make([]HAGroupStatus, 0, len(m.haGroups))
	for _, group := range m.haGroups {
		groups = append(groups, group)
	}
	sort.Slice(groups, func(i, j int) bool {
		return groups[i].RGID < groups[j].RGID
	})
	// Log the HA state being sent to helper for debugging demotion detection.
	for _, g := range groups {
		if g.RGID > 0 && g.RGID <= 3 {
			slog.Debug("userspace: syncHAState sending", "rg", g.RGID, "active", g.Active, "watchdog", g.WatchdogTimestamp)
		}
	}
	var status ProcessStatus
	req := ControlRequest{
		Type: "update_ha_state",
		HAState: &HAStateUpdateRequest{
			Groups: groups,
		},
	}
	if err := m.requestLocked(req, &status); err != nil {
		return err
	}
	// Record the exact full group set the current helper acknowledged before
	// applying its returned status. A later apply may reseed m.haGroups to a
	// smaller configured set while the helper still owns this inventory; the
	// lock-free watchdog snapshot must retain that membership until a new full
	// publish lands.
	m.helperHAStatePublished = true
	m.haWatchdogHelperInventory = append(m.haWatchdogHelperInventory[:0], groups...)
	m.publishHAWatchdogSnapshotLocked()
	if err := m.applyHelperStatusLocked(&status); err != nil {
		return err
	}
	return m.syncDesiredForwardingStateLocked()
}

// clearHelperHAStateLocked publishes an empty HA group set to the helper so it
// drops any redundancy-group state a prior clustered apply pushed. It is the
// non-cluster counterpart to syncHAStateLocked: on a standalone node the helper
// must observe an empty ha_state, otherwise its per-packet gate
// (enforce_ha_resolution_snapshot) keeps treating transit ForwardCandidates as
// HAInactive (owner_rg_id<=0 && !ha_state.is_empty()) and drops them. Sending an
// empty update is idempotent — the helper's update_ha_state rebuilds ha_state
// from the supplied groups, so an empty slice clears it (afxdp/ha.rs). This runs
// only on snapshot apply for non-cluster nodes (rare), not on the hot path.
func (m *Manager) clearHelperHAStateLocked() error {
	if m.clearHelperHAStateHook != nil {
		err := m.clearHelperHAStateHook()
		if err == nil {
			m.helperHAStatePublished = false
			m.haWatchdogHelperInventory = nil
			m.publishHAWatchdogSnapshotLocked()
		}
		return err
	}
	if m.proc == nil || m.proc.Process == nil {
		return nil
	}
	var status ProcessStatus
	req := ControlRequest{
		Type: "update_ha_state",
		HAState: &HAStateUpdateRequest{
			Groups: []HAGroupStatus{},
		},
	}
	if err := m.requestLocked(req, &status); err != nil {
		return err
	}
	m.helperHAStatePublished = false
	m.haWatchdogHelperInventory = nil
	m.publishHAWatchdogSnapshotLocked()
	return m.applyHelperStatusLocked(&status)
}

// clearHelperHAStateWithDebtLocked runs the idempotent standalone HA-state
// clear and records a retry debt if it fails (#5487). The apply path still
// surfaces the error (fail-closed), but the debt lets the status poll retry
// the clear until it succeeds — a transient control-socket error on a
// cluster->standalone reconfig must not permanently strand stale helper HA
// groups (which keep owner_rg_id<=0 transit ForwardCandidates HAInactive). On
// success the debt is cleared. Both standalone clear sites in the apply path
// use this instead of the bare clear.
func (m *Manager) clearHelperHAStateWithDebtLocked() error {
	if err := m.clearHelperHAStateLocked(); err != nil {
		m.pendingHAStateClear = true
		return err
	}
	m.pendingHAStateClear = false
	return nil
}

// clearHelperHAStateWithDebtEnsureRetryLocked runs the standalone clear via
// clearHelperHAStateWithDebtLocked and, when it fails, guarantees the periodic
// status loop is running before the error propagates (#5873). The recorded
// pendingHAStateClear debt has exactly one retry consumer — the status-loop
// tick (retryPendingHAStateClearLocked). Both apply-path clear sites can return
// the failure BEFORE reaching the normal ensureStatusLoopLocked() call: the
// first-startup full-publish path (returns from the failed-clear branch just
// above ensureStatusLoopLocked) and the deferred-XSK resume path (returns
// without ever calling it). Either way, without a running loop the debt is
// orphaned — nothing ever retries the idempotent clear, so stale helper HA
// groups keep the owner-RG-0 transit ForwardCandidates HAInactive (drop)
// indefinitely, contradicting the debt's eventual-cleanup contract. Ensuring
// the loop here (idempotent — guarded on m.syncCancel) gives the just-recorded
// debt a worker on its very first tick. The clear still fails closed: the raw
// error is returned so the caller surfaces the apply failure. Ordering: record
// debt (inside WithDebt) -> ensure loop -> return err.
func (m *Manager) clearHelperHAStateWithDebtEnsureRetryLocked() error {
	if err := m.clearHelperHAStateWithDebtLocked(); err != nil {
		m.ensureStatusLoopLocked()
		return err
	}
	return nil
}

// retryPendingHAStateClearLocked settles a stranded standalone HA-state clear
// debt from the status poll tick. It runs OUTSIDE the m.clusterHA HA-sync guard
// (that guard is exactly why a standalone clear is never retried), but only
// while the node is actually standalone: retrying an empty update_ha_state on a
// clustered node would wipe the live redundancy-group HA state.
func (m *Manager) retryPendingHAStateClearLocked() {
	if !m.pendingHAStateClear || m.clusterHA {
		return
	}
	if err := m.clearHelperHAStateWithDebtLocked(); err != nil {
		slog.Warn("userspace: standalone HA-state clear retry failed; will retry next tick", "err", err)
	}
}

func (m *Manager) refreshHAStateFromMapsLocked() error {
	rgMap := m.bpfShim.Map("rg_active")
	if rgMap == nil {
		return errors.New("rg_active map not loaded")
	}
	wdMap := m.bpfShim.Map("ha_watchdog")
	if wdMap == nil {
		return errors.New("ha_watchdog map not loaded")
	}
	merged, err := mergeHAStateFromMaps(rgMap, wdMap, m.haGroups)
	if err != nil {
		return err
	}
	if len(merged) == 0 {
		return nil
	}
	m.haGroups = merged
	m.publishHAWatchdogSnapshotLocked()
	return nil
}

func (m *Manager) seedHAGroupInventoryLocked(cfg *config.Config) {
	if cfg == nil || cfg.Chassis.Cluster == nil {
		// #1928: a non-cluster config has no redundancy groups. Drop any HA
		// groups retained from a prior clustered apply so the manager's view
		// matches reality and the startup path does not re-publish phantom HA
		// state to the helper (the source of the standalone transit-drop bug).
		m.haGroups = make(map[int]HAGroupStatus)
		m.publishHAWatchdogSnapshotLocked()
		return
	}
	seeded := make(map[int]HAGroupStatus, len(cfg.Chassis.Cluster.RedundancyGroups)+1)
	if group, ok := m.haGroups[0]; ok {
		group.RGID = 0
		seeded[0] = group
	}
	for _, rg := range cfg.Chassis.Cluster.RedundancyGroups {
		if rg == nil || rg.ID < 0 {
			continue
		}
		group := m.haGroups[rg.ID]
		group.RGID = rg.ID
		seeded[rg.ID] = group
	}
	m.haGroups = seeded
	m.publishHAWatchdogSnapshotLocked()
}

// refreshHAWatchdogOnlyFromMapsLocked updates only the watchdog timestamps
// in m.haGroups from BPF maps, preserving the Active state set by
// UpdateRGActive. This avoids the race where re-reading Active from BPF
// causes the helper to miss demotion deltas.
func (m *Manager) refreshHAWatchdogOnlyFromMapsLocked() error {
	wdMap := m.bpfShim.Map("ha_watchdog")
	if wdMap == nil {
		return nil
	}
	var (
		wdKey uint32
		wdVal uint64
	)
	wdIter := wdMap.Iterate()
	for wdIter.Next(&wdKey, &wdVal) {
		if group, ok := m.haGroups[int(wdKey)]; ok {
			group.WatchdogTimestamp = wdVal
			m.haGroups[int(wdKey)] = group
		}
	}
	m.publishHAWatchdogSnapshotLocked()
	return wdIter.Err()
}

func mergeHAStateFromMaps(rgMap, wdMap *ebpf.Map, existing map[int]HAGroupStatus) (map[int]HAGroupStatus, error) {
	seen := make(map[int]HAGroupStatus, len(existing))
	for rgID, group := range existing {
		seen[rgID] = group
	}

	var (
		rgKey uint32
		rgVal uint8
	)
	rgIter := rgMap.Iterate()
	for rgIter.Next(&rgKey, &rgVal) {
		group := seen[int(rgKey)]
		group.RGID = int(rgKey)
		group.Active = rgVal != 0
		seen[int(rgKey)] = group
	}
	if err := rgIter.Err(); err != nil {
		return nil, fmt.Errorf("iterate rg_active: %w", err)
	}

	var (
		wdKey uint32
		wdVal uint64
	)
	wdIter := wdMap.Iterate()
	for wdIter.Next(&wdKey, &wdVal) {
		group := seen[int(wdKey)]
		group.RGID = int(wdKey)
		group.WatchdogTimestamp = wdVal
		seen[int(wdKey)] = group
	}
	if err := wdIter.Err(); err != nil {
		return nil, fmt.Errorf("iterate ha_watchdog: %w", err)
	}
	return seen, nil
}

func (m *Manager) desiredForwardingArmedLocked() bool {
	if !m.lastStatus.Capabilities.ForwardingSupported {
		return false
	}
	// Keep bindings armed as soon as the helper is allowed to forward.
	// Startup settle and XSK bring-up are now controlled by the
	// userspace_ctrl map (see mapNameUserspaceCtrl in maps.go) and
	// the liveness probe in applyHelperStatusLocked(). Disarming the
	// helper here races against the initial armed=true request and tears
	// down AF_XDP before the probe can ever observe RX progress.
	if !m.clusterHA {
		return true
	}
	if m.configHasDataRGLocked() {
		// Keep the helper armed on standby HA nodes so stale-MAC traffic can
		// stay in the userspace fabric redirect path during ownership moves.
		// Per-packet HA resolution still decides whether traffic is forwarded
		// locally or redirected to the active peer.
		return true
	}
	for _, group := range m.haGroups {
		if group.Active {
			return true
		}
	}
	return false
}

// TakeoverReady reports whether the userspace dataplane is already in a state
// where an HA ownership move can rely on it for forwarding immediately.
// This intentionally rejects "startup-like" states so HA cutover does not
// begin queue bring-up work during UpdateRGActive().
func (m *Manager) TakeoverReady() (bool, []string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.takeoverReadyLocked()
}

func (m *Manager) takeoverReadyLocked() (bool, []string) {
	var reasons []string
	if m.proc == nil || m.proc.Process == nil {
		reasons = append(reasons, "userspace helper not running")
	}
	if !m.lastStatus.Enabled {
		reasons = append(reasons, "userspace helper not enabled")
	}
	if !m.lastStatus.Capabilities.ForwardingSupported {
		if len(m.lastStatus.Capabilities.UnsupportedReasons) > 0 {
			reasons = append(reasons, m.lastStatus.Capabilities.UnsupportedReasons...)
		} else {
			reasons = append(reasons, "userspace forwarding unsupported")
		}
	}
	if !m.lastStatus.ForwardingArmed {
		reasons = append(reasons, "userspace forwarding not armed")
	}
	if m.mode == ModeEBPFOnly {
		reasons = append(reasons, "userspace dataplane not active")
	}
	if m.xskLivenessFailed {
		reasons = append(reasons, "userspace XSK liveness failed")
	}
	if !m.xskLivenessProven && !m.standbyBindingsReadyLocked() {
		reasons = append(reasons, "userspace XSK liveness not proven")
	}
	if m.sessionMirrorFailed {
		reason := "userspace session mirror unhealthy"
		if m.sessionMirrorErr != "" {
			reason += ": " + m.sessionMirrorErr
		}
		reasons = append(reasons, reason)
	}
	// #9642: an indebted node must not advertise takeover readiness. Its
	// classifier maps are at an unpublished plan with ctrl held at 0; handing
	// it an RG would cut transit over until the debt converges. Name the
	// unpublished generation so the operator sees what is owed.
	if m.snapshotRetryDebtLocked() {
		reasons = append(reasons, fmt.Sprintf(
			"userspace snapshot retry debt outstanding (generation %d unpublished)",
			m.lastSnapshot.Generation))
	}
	// Gate on the LOCAL event-stream listener being bound — the primary push
	// channel from the local helper into the daemon's peer-sync pipeline. A bind
	// failure (path-too-long, EADDRINUSE, permission) must not be accepted as a
	// healthy startup merely because the slower DrainSessionDeltas polling
	// fallback exists (#5273). This gates on the listener being UP, not on the
	// local helper currently being connected (IsConnected): transient stream
	// disconnects are covered by polling. ensureProcessLocked already fails
	// bring-up when the listener cannot bind, so a running proc normally has a
	// bound stream; this defense-in-depth gate keeps that contract explicit.
	if m.eventStream == nil || !m.eventStream.ListenerBound() {
		reasons = append(reasons, "userspace event stream listener not bound")
	}
	return len(reasons) == 0, reasons
}

func (m *Manager) standbyBindingsReadyLocked() bool {
	if m.hasActiveDataRGLocked() {
		return false
	}
	if len(m.lastStatus.Bindings) == 0 || len(m.lastStatus.Queues) == 0 {
		return false
	}
	for _, q := range m.lastStatus.Queues {
		if !q.Armed || !q.Ready {
			return false
		}
	}
	for _, b := range m.lastStatus.Bindings {
		if !b.Armed || !b.Ready {
			return false
		}
	}
	return true
}

func (m *Manager) recordSessionMirrorFailureLocked(err error) {
	m.sessionMirrorFailed = true
	if err != nil {
		m.sessionMirrorErr = err.Error()
	}
}

// recordSessionMirrorSuccessLocked clears the sticky session-mirror failure
// state after a genuinely successful mirror IPC to the helper (#5247). The
// flag means "the helper session control socket last failed"; it is set on any
// mirror failure and gates HA takeover-readiness (takeoverReadyLocked), but was
// previously cleared ONLY on a helper process restart (see stopLocked). A
// single transient control-socket failure during bulk session sync therefore
// latched the standby "not takeover-ready" until the helper respawned. Since
// the flag tracks socket health — not "every session is mirrored" — one proven
// mirror is sufficient to declare the socket healthy again, so a later success
// self-heals the state without a restart. No-op when the helper is not running:
// syncSession{V4,V6}Locked returns nil without sending in that case, so there
// was no real mirror to prove health (and stopLocked already cleared the flag).
// noteSyncedMirrorFailureLocked accounts a FAILED synced-session mirror for the
// cluster install paths (#6785). It is shared by SetClusterSyncedSessionV4 and
// V6 rather than duplicated: the two entry points would otherwise carry two
// copies of one health decision, and a divergence between them is always a bug
// — an IPv6-only misclassification would disarm HA takeover on exactly the
// deployments hardest to notice it on. Callers hold m.mu.
//
// The classification is the point. A SEMANTIC refusal (stale generation, import
// cap, translated-tuple reserve) is the correct answer from a HEALTHY helper:
// the peer sent something stale, or this node is at its own ceiling. It is
// counted as debt — the peer believes it synced a session this node does not
// hold — and the caller still compensates its BPF write, because the helper did
// not take the session. But it must NOT set the sticky mirror-failure flag,
// which gates HA takeover-readiness (#5247): latching a working standby "not
// takeover-ready" the first time a peer oversubscribed it is a worse failure
// than the split truth being fixed, and a silent one.
//
// A refusal does not take the SUCCESS path either. That flag means "a mirror
// last succeeded", and a refusal is not a mirror; clearing a sticky failure on
// the strength of a refused write would let a helper that refuses everything
// read as recovered.
func (m *Manager) noteSyncedMirrorFailureLocked(err error) {
	if errors.Is(err, dataplane.ErrSyncedImportRefused) {
		m.syncedImportRefusals.Add(1)
		slog.Debug("userspace: helper refused a synced session import; "+
			"rolling back the BPF mirror", "err", err)
		return
	}
	m.recordSessionMirrorFailureLocked(err)
	slog.Debug("userspace: session mirror failed", "err", err)
}

func (m *Manager) recordSessionMirrorSuccessLocked() {
	if m.proc == nil {
		return
	}
	m.sessionMirrorFailed = false
	m.sessionMirrorErr = ""
}

func (m *Manager) hasActiveDataRGLocked() bool {
	for _, group := range m.haGroups {
		if group.RGID > 0 && group.Active {
			return true
		}
	}
	return false
}

func (m *Manager) shouldExtendXSKLivenessIdleLocked(currentRX uint64, allBindingsBound bool) bool {
	if currentRX != 0 {
		return false
	}
	if m.shouldAutoProveIdleStandbyXSKLocked(currentRX, allBindingsBound) {
		return false
	}
	if allBindingsBound {
		return true
	}
	return !m.hasActiveDataRGLocked()
}

func (m *Manager) shouldAutoProveIdleStandbyXSKLocked(currentRX uint64, allBindingsBound bool) bool {
	return currentRX == 0 && allBindingsBound && !m.hasActiveDataRGLocked()
}

func (m *Manager) configHasDataRGLocked() bool {
	if m.lastSnapshot == nil || m.lastSnapshot.Config == nil || m.lastSnapshot.Config.Chassis.Cluster == nil {
		return false
	}
	for _, rg := range m.lastSnapshot.Config.Chassis.Cluster.RedundancyGroups {
		if rg != nil && rg.ID > 0 {
			return true
		}
	}
	return false
}

// disarmBeforeUnsupportedPublishLocked disarms helper forwarding BEFORE a full
// apply_snapshot publish, but ONLY when keeping the helper armed would fail
// OPEN. There are two distinct cases (#3261 refines the original #2124 disarm):
//
// CLASS (ii) — a genuinely-unsupported dataplane semantic
// (deriveUserspaceCapabilities returns ForwardingSupported=false: screen
// SYN-cookie material, color-aware 3-color policers, persistent SNAT under HA).
// These have NO fail-closed snapshot representation — there is no sentinel the
// helper integrity preflight can reject — so the dataplane genuinely cannot
// forward and the legitimate disarm still applies.
//
// CLASS (i) — unrepresentable policy CONTENT (caps.PolicyContentRejected is
// non-empty: a policy names an application protocol/port or address the matcher
// cannot represent). buildOneRuleSnapshot emits the `__unsupported__` sentinel
// for such a rule, and a CURRENT helper rejects it via its non-mutating
// integrity preflight while staying armed (keeping previous-good, or leaving
// the default-deny PolicyState on a fresh boot). Disarming here would XDP_PASS
// transit to the kernel and bypass that reject — the fail-OPEN #3261 closes —
// so we KEEP the helper armed. The ONLY exception is an OLDER local helper that
// predates the preflight: it would silently drop the sentinel and process the
// resulting match-any rule with forwarding armed. We disarm just that narrow
// case, keyed on the helper's reported snapshot protocol version (the helper
// ships in the same .deb as the daemon, so this is only a transient
// helper-upgrade-lag window on a single node), NOT on the content being
// unrepresentable.
//
// caps are read from the snapshot being published (snap.Capabilities), NOT
// re-derived from cfg: only the snapshot value is feed-aware (#2049) and
// reflects the ACTUAL per-rule sentinels, so a healthy dynamic-address feed
// policy is not mistaken for unrepresentable content. The disarm is issued only
// when a running helper currently believes it is armed, so steady-state
// representable configs take no extra control round-trip. The post-publish
// desired-state sync still reconciles the final state.
func (m *Manager) disarmBeforeUnsupportedPublishLocked(snap *ConfigSnapshot) error {
	if snap == nil || snap.Config == nil {
		return nil
	}
	if m.proc == nil || m.proc.Process == nil || !m.lastStatus.ForwardingArmed {
		return nil
	}
	caps := snap.Capabilities
	disarm := !caps.ForwardingSupported // class (ii): genuine semantic gap
	reason := "unsupported-config"
	if !disarm && len(caps.PolicyContentRejected) > 0 &&
		m.lastStatus.ConfigSnapshotProtocolVersion < ProtocolVersion {
		// class (i) on a pre-preflight helper: it cannot be trusted to reject
		// the sentinel, so disarming is the only fail-closed option here.
		disarm = true
		reason = "unrepresentable-policy-content-on-pre-preflight-helper"
	}
	if !disarm {
		return nil
	}
	// #8447: SAY SO. This is a total forwarding STOP entered deliberately on a
	// config that COMMITS CLEANLY, and until now the only trace of it was
	// `Forwarding supported: false` inside a `show` nobody runs when the
	// symptom is "the link went down". `reason` was computed here purely to
	// decorate an error string on the failure path, so the SUCCESS path — the
	// one that actually stops traffic — emitted nothing at all.
	//
	// The reasons ARE the operator's diagnosis: deriveUserspaceCapabilities
	// sets ForwardingSupported false for an unsupported configuration (a
	// color-aware three-color policer, say), forwarding is disarmed here before
	// the publish, and desiredForwardingArmedLocked then keeps it disarmed while
	// the 1 Hz reconcile short-circuits silently. What the operator sees is a
	// connectivity outage on a commit that succeeded.
	//
	// #8573 note: the example this paragraph used to give — persistent-NAT on a
	// chassis cluster, refused because "leases are not HA-synchronized" — is
	// gone. That premise was measured false on the loss userspace cluster and
	// the gate was removed, so the specimen was replaced rather than left to rot
	// into a reason no config can reach.
	//
	// WARN, not Info: a transition into not-forwarding is a state change, and
	// it is one-time per publish rather than per-packet or per-tick, so it
	// cannot flood (the logging rules in CLAUDE.md).
	slog.Warn("userspace dataplane: DISARMING forwarding — the committed "+
		"configuration is not supported by this dataplane, so transit will "+
		"STOP until the unsupported configuration is removed",
		"reason", reason,
		"unsupported", strings.Join(caps.UnsupportedReasons, "; "),
		"policy_content_rejected", len(caps.PolicyContentRejected))

	var status ProcessStatus
	if err := m.requestLocked(ControlRequest{
		Type:       "set_forwarding_state",
		Forwarding: &ForwardingControlRequest{Armed: false},
	}, &status); err != nil {
		return fmt.Errorf("disarm userspace forwarding before %s publish: %w", reason, err)
	}
	// #9770: the disarm landed; reclaim pre-enable orphans under the session fence.
	// No-op post-enable by design (failback recovery needs those rows).
	m.drainAndClearSteeringRowsLocked("unsupported-publish-disarm")
	if err := m.applyHelperStatusLocked(&status); err != nil {
		return fmt.Errorf("sync helper status after pre-publish disarm: %w", err)
	}
	return nil
}

func (m *Manager) syncDesiredForwardingStateLocked() error {
	if m.proc == nil || m.proc.Process == nil {
		return nil
	}
	// #6871 (round 6): DEFER, do not send, while a RETH MAC link cycle owns the
	// dataplane. set_forwarding_state lands in handlers/forwarding.rs, which
	// calls reconcile_status_bindings UNCONDITIONALLY -> afxdp.reconcile ->
	// SPAWNS WORKER THREADS. PrepareLinkCycle has just joined those threads so
	// the NIC can unmap their UMEM pages; respawning them mid-cycle is the
	// use-after-unmap #5103 exists to prevent.
	//
	// The gate is HERE, at the emitter, rather than at any one caller, because
	// three callers reach it and only one of them was covered. The 1 Hz status
	// tick's call (process_status.go) is already inside the tick's own lease
	// skip, and the compile path's (manager_compile.go) runs under the daemon's
	// applySem, which the RETH MAC loop also holds — but UpdateHAWatchdog's does
	// NOT: the daemon's watchdog heartbeat is its own 500ms goroutine
	// (daemon_ha_sync.go) with no applySem, and its first/change/backstop branch
	// reaches this function through syncHAStateLocked. Gating here covers all
	// three, and any future caller that publishes forwarding state THROUGH THIS
	// FUNCTION; gating UpdateHAWatchdog would have closed one hole and left the
	// shape that produced it.
	//
	// #6871 (round 7): the scope of that sentence is exactly as written, and an
	// earlier revision overstated it as "all three and any future fourth". This
	// gate is not a chokepoint for the request type. Three other sites build a
	// raw set_forwarding_state of their own and do not consult the lease:
	//
	//   - SetForwardingArmed (manager_status.go) — the operator verb, which is
	//     gated at its OWN entry point instead (errLinkCycleInFlight);
	//   - disarmBeforeUnsupportedPublishLocked (below in this file) — UNGATED,
	//     reachable only from the compile/publish path, i.e. under applySem;
	//   - disarmSnapshotProtocolFailureLocked (manager_compile.go) — UNGATED,
	//     reachable from the same compile path and from the policy-scheduler and
	//     route-overlay republishes, all of which serialize on applySem too.
	//
	// So there is no runtime escape today, but the reason is applySem for those
	// two, not this gate. A future publisher that runs off applySem — as the
	// watchdog heartbeat does — would need its own answer, and this line is the
	// place that says so rather than implying it is already handled.
	//
	// The watchdog's OTHER half is deliberately NOT suppressed, and the reason is
	// concrete rather than cautious. The shim map write in UpdateHAWatchdog is the
	// kernel-visible liveness signal the BPF ~2s stale window depends on. The
	// update_ha_state IPC is that same signal in its socket form: it is the ONLY
	// thing that refreshes the helper's per-RG forwarding lease
	// (Coordinator::update_ha_state -> HAGroupRuntime::active_lease_until ->
	// ActiveUntil(watchdog + HA_WATCHDOG_STALE_AFTER_SECS), 10s in
	// userspace-dp/src/afxdp/mod.rs), and is_forwarding_active consults that lease
	// per packet. Gating it for the length of a link cycle — whose lease TTL is
	// 60s — would expire the helper's forwarding lease outright. That is an
	// OUTAGE, strictly worse than the respawn race being closed, and it is why
	// the gate is on the set_forwarding_state emitter rather than on
	// UpdateHAWatchdog as a whole.
	//
	// update_ha_state is also safe to let through on its own terms, though not
	// for the absolute reason an earlier revision gave (#6871 round 7: "reaches
	// neither reconcile_status_bindings nor any other worker spawn" is not
	// literally true). Its handler (server/handlers/ha.rs) does call
	// refresh_status on success, and refresh_status can repair the WG and GRE
	// auxiliary threads. What it does NOT do is call reconcile_status_bindings or
	// anything else that spawns the AF_XDP PACKET workers — the only threads
	// whose UMEM a link cycle's unmap can race. And after a successful
	// stop_workers the helper has already cleared its worker/WG/GRE records, so
	// refresh_status finds nothing to repair either. The conclusion stands; the
	// phrasing now matches the handler.
	//
	// Deferral, not loss: the decision is LEVEL-triggered on persistent state
	// (desiredForwardingArmedLocked vs m.lastStatus.ForwardingArmed), so the
	// first call after the lease ends re-evaluates the same delta and sends it.
	// The 1 Hz tick alone guarantees that within a second of NotifyLinkCycle,
	// and returning nil (rather than an error) is what keeps this a deferral —
	// the callers log or propagate an error, and nothing here has failed.
	if m.linkCycleInFlight() {
		slog.Debug("userspace: deferring set_forwarding_state; RETH MAC link cycle in flight")
		return nil
	}
	desired := m.desiredForwardingArmedLocked()
	if m.lastStatus.ForwardingArmed == desired {
		return nil
	}
	// #6165: the ~1s desired-state reconcile must honor the SAME
	// required-generation protocol gate that #6163/#5648 added to
	// SetForwardingArmed. A compile- or scheduler-path disarm
	// (disarmSnapshotProtocolFailureLocked, fired by
	// ensureRequiredSnapshotProtocolLocked when the running helper's accepted
	// snapshot protocol version is too old to honor a config that REQUIRES a
	// newer one — policy schedulers, persistent source NAT) leaves the helper
	// disarmed while desiredForwardingArmedLocked() still returns true (it only
	// checks ForwardingSupported, never the snapshot protocol). Without this
	// gate the next reconcile tick re-arms the protocol-stale image and
	// forwards a config the helper cannot represent — the fail-OPEN #6163
	// closed on the explicit operator-arm path, reachable here from the
	// UpdatePolicyScheduleState scheduler-tick disarm (which, unlike an
	// operator commit, does not revert the active config, so m.lastSnapshot
	// keeps requiring the protocol). Scoped exactly like SetForwardingArmed:
	// only the ARM direction is gated; a disarm (desired==false — shutdown,
	// demotion, disarmSnapshotProtocolFailureLocked) must NEVER be blocked, and
	// it re-polls the helper first so a helper that has since upgraded still
	// arms normally. Fail closed: leave the helper disarmed and surface the
	// error to the poll caller (logged), rather than re-arm a stale image.
	//
	// #6722 WIDENED WHAT THIS REFUSES. Three of the four gates in the chain are
	// no-ops unless the config uses their feature; the fourth
	// (ensureEgressZoneProtocolLocked) takes no config and fires for ANY
	// last-applied config, because every snapshot carries EgressZone. This tick
	// therefore now refuses to arm a version-mismatched helper on every config,
	// not only a protocol-requiring one — the right answer, since such a helper
	// cannot decode a v5 snapshot at all, and the reason the refusal must live
	// HERE and not only at the operator-arm path: this runs unattended about
	// once a second, so an ungated tick re-arms the stale image with nobody
	// asking. What still scopes it is the OBSERVED helper version, which is
	// unknown before the first handshake and returns nil then (#1960 no-brick).
	// Bound by TestEgressZoneProtocolGatesBothArmPaths_6722/ha-reconcile-tick,
	// which drives an EMPTY config.Config{} so no sibling gate can be the one
	// answering.
	if desired && m.lastSnapshot != nil && m.lastSnapshot.Config != nil {
		if err := m.ensureRequiredSnapshotProtocolLocked(m.lastSnapshot); err != nil {
			return err
		}
	}
	// #7465: refuse to ARM a clustered helper that has never been sent an HA
	// inventory. The helper's per-packet gate reads an empty ha_state as "this
	// box is not clustered" and lets LocalDelivery through
	// (forwarding/ha.rs enforce_ha_resolution_snapshot), so arming before the
	// first update_ha_state opens a fail-OPEN window on host-destined traffic.
	//
	// This is reachable because an ORDINARY apply failure does not disarm or
	// stop the helper — daemon_apply_dataplane.go records a deferred commit
	// error and continues (#5679), and compileErrorMustAbortApply is true only
	// for the required-protocol gate. So an apply that fails in the window
	// between the snapshot publish and syncHAStateLocked (a transient control
	// socket error in applyHelperStatusLocked, refreshHAStateFromMapsLocked or
	// syncHAStateLocked) leaves a live helper holding a snapshot and no
	// inventory — and the 1 Hz poll then arms it.
	//
	// Scoped exactly like the #6165 gate above: ARM direction only. A disarm
	// must NEVER be blocked, and the delta check above has already established
	// that desired != current, so reaching here with desired==true is an arm.
	// #9629 demotion-pending bound: a session refresh may mint a lease only
	// while the stored active lease remains valid, and each receipt-anchored
	// lease lasts at most (10,11] seconds. UpdateRGActive is authoritative for
	// the ownership flip and its applied-gate reconcile retries every 2 seconds.
	// A continuously renewed stale ownership can therefore last until that
	// authoritative demotion or bounded recovery lands; expired stored ownership
	// is always fail-closed and cannot be resurrected here.
	//
	// Fail closed and LOUD: a clustered helper that is never told its inventory
	// simply does not forward, and the error surfaces on the poll caller's log
	// and the apply path. That is a bounded, visible availability loss, versus a
	// silent fail-open on the packet path.
	if desired && m.clusterHA && !m.helperHAStatePublished {
		return fmt.Errorf(
			"refusing to arm forwarding: chassis-cluster helper has no HA inventory yet " +
				"(no successful update_ha_state); arming now would let the helper read an " +
				"empty ha_state as standalone and deliver host-destined traffic it should " +
				"gate on redundancy-group ownership")
	}
	if m.clusterHA {
		slog.Info(
			"userspace: forwarding arm state change",
			"desired", desired,
			"current", m.lastStatus.ForwardingArmed,
			"config_has_data_rg", m.configHasDataRGLocked(),
			"ha_group_count", len(m.haGroups),
		)
	}
	var status ProcessStatus
	req := ControlRequest{
		Type: "set_forwarding_state",
		Forwarding: &ForwardingControlRequest{
			Armed: desired,
		},
	}
	if err := m.requestLocked(req, &status); err != nil {
		return err
	}
	if !desired {
		// #9770: the disarm half of this sync landed; reclaim pre-enable orphans
		// under the session fence. Never on the arm half (re-arm republishes live
		// rows); no-op post-enable by design (failback recovery needs those rows).
		m.drainAndClearSteeringRowsLocked("desired-state-disarm")
	}
	return m.applyHelperStatusLocked(&status)
}

func (m *Manager) UpdateRGActive(rgID int, active bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Update BPF rg_active UNDER the lock so the periodic poll can't
	// read the new BPF value and sync to the helper before we do.
	// This prevents the race where the poll eats the demotion delta.
	if err := m.bpfShim.UpdateRGActive(rgID, active); err != nil {
		return err
	}

	prior, known := m.haGroups[rgID]
	group := prior
	group.RGID = rgID
	group.Active = active
	m.haGroups[rgID] = group
	m.publishHAWatchdogSnapshotLocked()

	// Only log on real transitions. The reconcile loop retries this
	// call whenever applied != desired (see #757), so emitting INFO
	// on every call floods journald when the helper is down. The rate
	// is the reconcileRGStateLoop ticker in daemon_ha.go — 2s, plus
	// early wakes on dropped-event notifications — times the RG count,
	// so ~1.5 lines/sec on the cluster's three RGs, sustained for as
	// long as the helper stays down. (#6871: an earlier revision said "9+
	// lines/sec", derived from a 500ms period that loop has never had.)
	// First-seen registration counts as a transition.
	if !known || prior.Active != active {
		slog.Info("userspace: RG state updated (helper stays in control)",
			"rg", rgID, "active", active)
	}

	// HA ownership moves must not start queue bootstrap or neighbor repair
	// work here. TakeoverReady() already requires the helper to be armed and
	// XSK liveness to be proven before cutover begins, so activation must be
	// a narrow ownership-state update rather than a second startup path.

	// Sync HA state DIRECTLY to helper without re-reading from BPF maps.
	// The periodic status poll also reads rg_active and syncs to the helper,
	// racing with us. If the poll syncs first, our direct update_ha_state
	// sends the same state → no delta detected → no new RG-epoch bump or
	// helper-side HA transition handling.
	// By sending directly with the groups we already have, we guarantee
	// the helper sees the transition.
	//
	// Only suppress ctrl during ACTIVATION transitions. During demotion,
	// ctrl can stay enabled — the demoted RG's sessions are cleaned up by
	// the helper, and rg_active in BPF is already 0. Disabling ctrl
	// globally during demotion disrupts forwarding for other active RGs
	// and causes the standby to lose userspace readiness (#457).
	if active {
		m.rgTransitionInFlight.Store(true)
		defer m.rgTransitionInFlight.Store(false)
	}
	groups := make([]HAGroupStatus, 0, len(m.haGroups))
	for _, g := range m.haGroups {
		groups = append(groups, g)
	}
	sort.Slice(groups, func(i, j int) bool {
		return groups[i].RGID < groups[j].RGID
	})
	var status ProcessStatus
	req := ControlRequest{
		Type: "update_ha_state",
		HAState: &HAStateUpdateRequest{
			Groups: groups,
		},
	}
	// Log the HA state being sent to helper (info level only for RG transitions).
	for _, g := range groups {
		if g.RGID >= 0 && g.RGID <= 3 {
			slog.Debug("userspace: syncHAState sending", "rg", g.RGID, "active", g.Active, "watchdog", g.WatchdogTimestamp)
		}
	}
	if err := m.requestLocked(req, &status); err != nil {
		return err
	}
	m.helperHAStatePublished = true
	m.haWatchdogHelperInventory = append(m.haWatchdogHelperInventory[:0], groups...)
	m.publishHAWatchdogSnapshotLocked()
	if active {
		// The helper has already acknowledged the RG activation update.
		// Clear the transition guard before applying the returned status so
		// the acked activation does not force one global ctrl-disabled cycle.
		m.rgTransitionInFlight.Store(false)
	}
	m.lastRGActivateTime = time.Now()
	// UpdateRGActive is the authoritative active-change publish. Record the
	// throttle baseline so the watchdog heartbeat path (UpdateHAWatchdog) does
	// not immediately re-fire a redundant update_ha_state right after a failover,
	// precisely when the control socket is busiest with takeover work.
	m.markHAWatchdogIPCSyncedLocked()
	if err := m.applyHelperStatusLocked(&status); err != nil {
		return err
	}

	return nil
}

// haWatchdogIPCSyncState records the last per-RG state published to the helper
// over the update_ha_state socket IPC. It is the throttle baseline read by
// shouldSyncHAWatchdogIPCLocked.
type haWatchdogIPCSyncState struct {
	timestamp uint64
	active    bool
}

// haWatchdogSnapshot is the immutable, lock-free watchdog input published by
// the manager while holding m.mu. It exists because an apply_snapshot can hold
// m.mu across a long helper RPC; the watchdog must still be able to reach the
// session socket during that interval (#9629, GPT-1/Spark MAJOR-1).
type haWatchdogSnapshot struct {
	groups            []HAGroupStatus
	sessionFastPath   bool
	processLive       bool
	processGen        uint64
	sessionSocketPath string
}

// haWatchdogGroupsLocked returns the group membership compatible with the
// helper's last acknowledged inventory. A config apply reseeds m.haGroups
// before replaying the fixed 16-entry kernel maps; using that narrowed map for
// a contended session refresh would make Rust reject every request as a
// membership change. Keep the old helper keys until the next full main-path
// publish lands, while overlaying only watchdog timestamps. Active ownership
// remains the acknowledged helper value until UpdateRGActive's main request
// succeeds, preserving the transition fence.
func (m *Manager) haWatchdogGroupsLocked() []HAGroupStatus {
	if !m.helperHAStatePublished || len(m.haWatchdogHelperInventory) == 0 {
		return nil
	}
	desired := make(map[int]HAGroupStatus, len(m.haGroups))
	for id, group := range m.haGroups {
		desired[id] = group
	}
	groups := make([]HAGroupStatus, 0, len(m.haWatchdogHelperInventory))
	for _, prior := range m.haWatchdogHelperInventory {
		group := prior
		if current, ok := desired[prior.RGID]; ok &&
			current.WatchdogTimestamp > group.WatchdogTimestamp {
			group.WatchdogTimestamp = current.WatchdogTimestamp
		}
		groups = append(groups, group)
	}
	sort.Slice(groups, func(i, j int) bool {
		return groups[i].RGID < groups[j].RGID
	})
	return groups
}

// publishHAWatchdogSnapshotLocked publishes a complete watchdog input
// generation. Every field read by the degraded path is copied before the
// atomic store; the pointed-to slice is never mutated afterward.
//
// The processGen field is an independent helper-session epoch, not m.procGen:
// crash handling must retire it before reset publishes processLive=false while
// the restart timer still remains fenced on the dead helper's procGen.
//
// Caller holds m.mu. This function does not perform I/O and does not acquire
// any lock other than the atomic pointer's internal synchronization.
func (m *Manager) publishHAWatchdogSnapshotLocked() {
	groups := m.haWatchdogGroupsLocked()
	processLive := m.proc != nil && m.proc.Process != nil
	sessionFastPath := m.helperHAStatePublished &&
		m.helperStatusObserved &&
		m.lastStatus.HaSessionRefreshSupported &&
		processLive &&
		len(groups) != 0
	processGen := m.haWatchdogProcessGen.Load()
	m.haWatchdogSnapshot.Store(&haWatchdogSnapshot{
		groups:            groups,
		sessionFastPath:   sessionFastPath,
		processLive:       processLive,
		processGen:        processGen,
		sessionSocketPath: sessionSocketPathFor(m.cfg.ControlSocket),
	})
}

// tryUpdateHAWatchdogWhileManagerMuHeld is the actual Manager entry-point
// escape hatch for the long snapshot-held m.mu case. A failed TryLock is not
// itself permission to send: only a previously published capability and
// inventory can take this path. That preserves the first-inventory and
// helper-restart fences owned by the locked control path.
//
// The degraded throttle has its own leaf mutex. It is held only through the
// monotonic full-set merge and throttle decision, then released before
// requestHAWatchdogSession, so this path cannot turn a slow socket into
// another lock convoy.
func (m *Manager) tryUpdateHAWatchdogWhileManagerMuHeld(
	rgID int,
	timestamp uint64,
) (bool, error) {
	snapshot := m.haWatchdogSnapshot.Load()
	if snapshot == nil {
		return false, nil
	}
	if snapshot.processGen != m.haWatchdogProcessGen.Load() {
		return true, nil
	}
	// Mirror the locked path's proc-nil no-op without waiting for m.mu. This
	// also prevents a stale capability snapshot from talking to a departed
	// helper during the reset publication window.
	if !snapshot.processLive {
		return true, nil
	}
	if !snapshot.sessionFastPath || len(snapshot.groups) == 0 {
		return false, nil
	}

	var found bool
	for _, group := range snapshot.groups {
		if group.RGID == rgID {
			found = true
			break
		}
	}
	// Never synthesize a group on the refresh-only path. The main path owns
	// inventory creation and transitions, including the standalone CLEAR fence.
	if !found {
		return false, nil
	}

	m.haDegradedMu.Lock()
	if m.haDegradedCurrent == nil {
		m.haDegradedCurrent = make(map[int]haWatchdogIPCSyncState, len(snapshot.groups))
	}
	seen := make(map[int]struct{}, len(snapshot.groups))
	for _, group := range snapshot.groups {
		seen[group.RGID] = struct{}{}
		current, ok := m.haDegradedCurrent[group.RGID]
		if !ok {
			current = haWatchdogIPCSyncState{
				timestamp: group.WatchdogTimestamp,
				active:    group.Active,
			}
		} else {
			// Active is authoritative from the latest m.mu-published
			// snapshot; timestamps are monotonic because this path may
			// observe several RG calls while m.mu remains held.
			current.active = group.Active
			if group.WatchdogTimestamp > current.timestamp {
				current.timestamp = group.WatchdogTimestamp
			}
		}
		if group.RGID == rgID && timestamp > current.timestamp {
			current.timestamp = timestamp
		}
		m.haDegradedCurrent[group.RGID] = current
	}
	for id := range m.haDegradedCurrent {
		if _, ok := seen[id]; !ok {
			delete(m.haDegradedCurrent, id)
		}
	}

	observationTimestamp := timestamp
	for _, current := range m.haDegradedCurrent {
		if current.timestamp > observationTimestamp {
			observationTimestamp = current.timestamp
		}
	}
	due := !m.haDegradedHaveLastSent ||
		observationTimestamp >= m.haDegradedLastSentAt+haWatchdogIPCBackstopSecs
	if !due {
		for id, current := range m.haDegradedCurrent {
			last, ok := m.haDegradedLastSent[id]
			if !ok || last.active != current.active {
				due = true
				break
			}
		}
	}
	var groups []HAGroupStatus
	if due {
		groups = make([]HAGroupStatus, 0, len(m.haDegradedCurrent))
		for id, current := range m.haDegradedCurrent {
			groups = append(groups, HAGroupStatus{
				RGID:              id,
				Active:            current.active,
				WatchdogTimestamp: current.timestamp,
			})
		}
		sort.Slice(groups, func(i, j int) bool {
			return groups[i].RGID < groups[j].RGID
		})
		if m.haDegradedLastSent == nil {
			m.haDegradedLastSent = make(map[int]haWatchdogIPCSyncState, len(groups))
		}
		clear(m.haDegradedLastSent)
		for id, current := range m.haDegradedCurrent {
			m.haDegradedLastSent[id] = current
		}
		m.haDegradedLastSentAt = observationTimestamp
		m.haDegradedHaveLastSent = true
	}
	m.haDegradedMu.Unlock()
	if !due {
		return true, nil
	}

	err := m.requestHAWatchdogSessionAtPathForGeneration(
		groups, snapshot.sessionSocketPath, snapshot.processGen)
	if errors.Is(err, errHARefreshNeedsControlSocket) ||
		errors.Is(err, errHARefreshStaleProcess) {
		// A healthy helper refused a transition/clear, or the helper generation
		// was retired while this request queued. The main path will retry it;
		// both outcomes are throttle-success and never mark helper state as
		// published from the degraded path.
		return true, nil
	}
	return true, err
}

// haWatchdogIPCBackstopSecs bounds how far the watchdog timestamp (CLOCK_MONOTONIC
// seconds) may advance between update_ha_state socket IPCs for a given RG while
// its Active state is unchanged. The daemon heartbeat ticks every 500ms, so an
// unthrottled UpdateHAWatchdog would issue the full JSON IPC at 2/s per RG —
// exactly the >1/s control-socket caller CLAUDE.md warns starves session
// installs during bulk sync. A 3s backstop drops that to at most ~0.33/s per RG
// (a 6x reduction) while leaving a >3x margin under the helper's ~10s stale-lease
// window, so the helper's HA view never expires from lack of a refresh. The
// kernel-visible shim map write still happens every tick — only the JSON IPC is
// throttled here.
const haWatchdogIPCBackstopSecs = 3

// shouldSyncHAWatchdogIPCLocked decides whether UpdateHAWatchdog must publish the
// full HA state to the helper over the control socket this tick. It fires:
//   - on the first heartbeat for an RG after startup/seed (no baseline yet),
//   - IMMEDIATELY on any Active-state change (failover/failback — the throttle
//     never blocks this; it is the load-bearing failover-timing path), or
//   - as a periodic backstop once the watchdog timestamp has advanced past
//     haWatchdogIPCBackstopSecs since the last IPC for that RG.
//
// Otherwise it returns false and the tick is satisfied by the shim map write
// alone. Caller holds m.mu.
func (m *Manager) shouldSyncHAWatchdogIPCLocked(rgID int, active bool, timestamp uint64) bool {
	if m.haWatchdogIPCSynced == nil {
		return true
	}
	last, ok := m.haWatchdogIPCSynced[rgID]
	if !ok {
		return true
	}
	if active != last.active {
		return true
	}
	return timestamp >= last.timestamp+haWatchdogIPCBackstopSecs
}

// markHAWatchdogIPCSyncedLocked records the current per-RG watchdog timestamp and
// Active state as the throttle baseline. syncHAStateLocked publishes the FULL
// group set, so every group's state is recorded — this stops the remaining RGs'
// heartbeat calls in the same tick from each re-firing the IPC. Caller holds m.mu.
func (m *Manager) markHAWatchdogIPCSyncedLocked() {
	if m.haWatchdogIPCSynced == nil {
		m.haWatchdogIPCSynced = make(map[int]haWatchdogIPCSyncState, len(m.haGroups))
	}
	for rgID, g := range m.haGroups {
		m.haWatchdogIPCSynced[rgID] = haWatchdogIPCSyncState{
			timestamp: g.WatchdogTimestamp,
			active:    g.Active,
		}
	}
	// Keep the degraded path's merged current payload and last-send baseline
	// aligned with the full set just published by the locked path. This is a
	// single scalar backstop, not one deadline per RG.
	m.haDegradedMu.Lock()
	if m.haDegradedCurrent == nil {
		m.haDegradedCurrent = make(map[int]haWatchdogIPCSyncState, len(m.haGroups))
	}
	if m.haDegradedLastSent == nil {
		m.haDegradedLastSent = make(map[int]haWatchdogIPCSyncState, len(m.haGroups))
	}
	clear(m.haDegradedCurrent)
	clear(m.haDegradedLastSent)
	groups := m.haWatchdogGroupsLocked()
	for _, group := range groups {
		state := haWatchdogIPCSyncState{
			timestamp: group.WatchdogTimestamp,
			active:    group.Active,
		}
		m.haDegradedCurrent[group.RGID] = state
		m.haDegradedLastSent[group.RGID] = state
	}
	m.haDegradedLastSentAt = 0
	for _, group := range groups {
		if group.WatchdogTimestamp > m.haDegradedLastSentAt {
			m.haDegradedLastSentAt = group.WatchdogTimestamp
		}
	}
	m.haDegradedHaveLastSent = len(groups) != 0
	m.haDegradedMu.Unlock()
}

func (m *Manager) UpdateHAWatchdog(rgID int, timestamp uint64) error {
	// Fast path: write the kernel-visible watchdog timestamp to the shim map on
	// EVERY tick. The BPF ~2s stale window relies on this, so it is never
	// throttled. Indirected through haWatchdogMapWrite so unit tests can exercise
	// the IPC-throttle path below without a loaded BPF map.
	mapWrite := m.haWatchdogMapWrite
	if mapWrite == nil {
		mapWrite = m.bpfShim.UpdateHAWatchdog
	}
	if err := mapWrite(rgID, timestamp); err != nil {
		return err
	}

	// A snapshot/apply can hold m.mu across a long control-socket round trip.
	// Try the lock once so the actual production entry point, not just the
	// session sender, can use the independent session refresh during that hold.
	// If the immutable snapshot is unavailable (old helper, no inventory, or a
	// bare test Manager), fall through to the legacy lock-first path.
	if !m.mu.TryLock() {
		if handled, err := m.tryUpdateHAWatchdogWhileManagerMuHeld(rgID, timestamp); handled {
			return err
		}
		m.mu.Lock()
	}
	group := m.haGroups[rgID]
	group.RGID = rgID
	group.WatchdogTimestamp = timestamp
	m.haGroups[rgID] = group
	m.publishHAWatchdogSnapshotLocked()

	// Throttle the update_ha_state socket IPC. Nothing to send before the helper
	// is up; the first tick after it comes up seeds the baseline and syncs.
	if m.proc == nil || m.proc.Process == nil {
		m.mu.Unlock()
		return nil
	}
	if !m.shouldSyncHAWatchdogIPCLocked(rgID, group.Active, timestamp) {
		m.mu.Unlock()
		return nil
	}
	// Capability gate (#9629): explicit helper-status bit, NOT the snapshot
	// protocol version (this behavior adds no snapshot-wire bump, so old and
	// new helpers report the same version and version inference would be
	// unsound). False when never observed → legacy main path. Branched BEFORE
	// any refresh so the legacy arm below stays byte-for-byte (single inner
	// BPF refresh, unchanged failure timing) instead of paying two reads.
	sessionFastPath := m.helperStatusObserved && m.lastStatus.HaSessionRefreshSupported
	if !sessionFastPath {
		// Record the baseline BEFORE the send so a post-send applyHelperStatusLocked
		// or transient socket error cannot trigger a per-tick resync storm: the next
		// backstop (<= haWatchdogIPCBackstopSecs) retries, and the shim map write
		// keeps the kernel watchdog fresh in the meantime.
		m.markHAWatchdogIPCSyncedLocked()
		defer m.mu.Unlock()
		return m.syncHAStateLocked()
	}
	// Session arm: refresh from the maps BEFORE snapshot/mark (preserves
	// syncHAStateLocked's refresh-then-build order): the mark records fresh
	// full-set timestamps so the remaining RGs' heartbeat calls in the same
	// tick stay throttled (one full-set publish per tick, not one IPC per RG).
	// On map failure, still mark (today's no-storm throttle: the baseline is
	// recorded even when the sync fails) and return — no publish, no flag.
	if err := m.refreshHAWatchdogOnlyFromMapsLocked(); err != nil {
		m.markHAWatchdogIPCSyncedLocked()
		m.mu.Unlock()
		return err
	}
	// Snapshot the full group set under the lock (deterministic RGID order,
	// matching syncHAStateLocked); the send below runs outside m.mu.
	groups := make([]HAGroupStatus, 0, len(m.haGroups))
	for _, g := range m.haGroups {
		groups = append(groups, g)
	}
	sort.Slice(groups, func(i, j int) bool { return groups[i].RGID < groups[j].RGID })
	sessionSocketPath := m.sessionSocketPath()
	processGen := m.haWatchdogProcessGen.Load()
	// Record the baseline BEFORE the send (same no-storm rationale as above).
	// Marked ONCE here, never re-marked after the send (a stale snapshot
	// overwriting a fresher UpdateRGActive baseline would fire one redundant
	// immediate IPC at failover).
	m.markHAWatchdogIPCSyncedLocked()
	m.mu.Unlock()
	// Session path: lease-only refresh OUTSIDE m.mu, so a 10s apply holding
	// m.mu never blocks the 3s watchdog backstop (G1). Transport errors return
	// to the daemon caller, which Warn-and-continues per RG per tick
	// (daemon_ha_comms_wiring) and retries next tick/backstop. The final
	// generation check runs after sessionMu acquisition, so a queued sender
	// cannot reach a replacement helper.
	err := m.requestHAWatchdogSessionAtPathForGeneration(
		groups, sessionSocketPath, processGen)
	if errors.Is(err, errHARefreshNeedsControlSocket) ||
		errors.Is(err, errHARefreshStaleProcess) {
		// Healthy helper, transition/CLEAR owned by the main path, or a
		// retired helper generation. Treat both as throttle-success; neither
		// should be reported as a watchdog transport failure.
		return nil
	}
	return err
}

func activeHAGroupSignature(groups map[int]HAGroupStatus) string {
	if len(groups) == 0 {
		return ""
	}
	active := make([]int, 0, len(groups))
	for rgID, group := range groups {
		if group.Active {
			active = append(active, rgID)
		}
	}
	if len(active) == 0 {
		return ""
	}
	sort.Ints(active)
	parts := make([]string, 0, len(active))
	for _, rgID := range active {
		parts = append(parts, strconv.Itoa(rgID))
	}
	return strings.Join(parts, ",")
}

func activeHAGroupSignatureSlice(groups []HAGroupStatus) string {
	if len(groups) == 0 {
		return ""
	}
	active := make([]int, 0, len(groups))
	for _, group := range groups {
		if group.Active {
			active = append(active, group.RGID)
		}
	}
	if len(active) == 0 {
		return ""
	}
	sort.Ints(active)
	parts := make([]string, 0, len(active))
	for _, rgID := range active {
		parts = append(parts, strconv.Itoa(rgID))
	}
	return strings.Join(parts, ",")
}
