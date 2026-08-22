package userspace

import (
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"net"
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
		return m.clearHelperHAStateHook()
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

// SyncFabricState pushes current fabric snapshots (with fresh peer MACs)
// to the Rust helper. Called from the daemon after refreshFabricFwd succeeds
// so the helper has up-to-date fabric MAC info for cross-chassis redirect.
func (m *Manager) SyncFabricState() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.proc == nil || m.proc.Process == nil || m.lastSnapshot == nil {
		return
	}
	build := m.fabricSnapshotBuilder
	if build == nil {
		build = buildFabricSnapshots
	}
	// #6691 round 11: the refresh carries MACs, ifindexes and link state — never
	// a device-level binding verdict. The builder re-samples the kernel, and a
	// verdict re-decided here would apply to a snapshot whose interface rows are
	// still the applied ones, on two planes that neither replan on this path.
	// alignFabricVerdicts (fabric.go) holds the reasoning.
	fabrics := alignFabricVerdicts(build(m.lastSnapshot.Config), m.lastSnapshot)
	if len(fabrics) == 0 {
		return
	}
	var status ProcessStatus
	req := ControlRequest{
		Type:    "update_fabrics",
		Fabrics: fabrics,
	}
	if err := m.requestLocked(req, &status); err != nil {
		slog.Debug("userspace: failed to sync fabric state", "err", err)
		return
	}
	// #5306: persist the resolved fabrics into the Go-side lastSnapshot. The
	// update_fabrics send above already handed the helper the freshly-resolved
	// peer MACs, but the partial-rebuild publish paths
	// (PublishRouteOverlaySnapshot, the policy-scheduler republish, the #5134
	// worker-arm re-apply) each start from `next := *m.lastSnapshot` and rebuild
	// ONLY Routes, re-publishing every other section — Fabrics included —
	// verbatim. Without this writeback that verbatim Fabrics is the STALE,
	// unresolved-MAC set baked in at the last full apply, so the next such
	// apply_snapshot silently reverts the helper to the unresolved fabric MAC —
	// exactly during the HA window fabric cross-chassis forwarding exists to
	// preserve. Write back only after the send succeeds (mutate-after-success):
	// a transient control-socket error leaves lastSnapshot.Fabrics matching what
	// the helper actually has. Mirrors RegenerateNeighborSnapshot's post-publish
	// writeback for the neighbor table.
	m.persistResolvedFabricsLocked(fabrics)
}

// persistResolvedFabricsLocked writes the fabric snapshots SyncFabricState just
// pushed to the helper back into m.lastSnapshot so the partial-rebuild publish
// paths (which do `next := *m.lastSnapshot` and refresh only Routes) carry the
// resolved peer MAC forward instead of reverting to the stale set (#5306).
//
// It mirrors RegenerateNeighborSnapshot's post-publish bookkeeping: advance the
// generation + publishedSnapshot and refresh lastSnapshotHash so the status
// reconcile loop does not mistake the mutated snapshot for an unpublished
// generation (a redundant full apply_snapshot) and the content-dedup gate
// compares against the now-current content. No-op when the fabric set is
// unchanged so the daemon's post-refreshFabricFwd SyncFabricState cadence does
// not churn the generation on every steady-state call. Caller holds m.mu.
func (m *Manager) persistResolvedFabricsLocked(fabrics []FabricSnapshot) {
	if m.lastSnapshot == nil {
		return
	}
	if fabricSnapshotsEqual(m.lastSnapshot.Fabrics, fabrics) {
		return
	}
	m.lastSnapshot.Fabrics = fabrics
	m.generation++
	m.lastSnapshot.Generation = m.generation
	m.publishedSnapshot = m.lastSnapshot.Generation
	if h, ok := snapshotContentHash(m.lastSnapshot); ok {
		m.lastSnapshotHash = h
	}
}

// fabricSnapshotsEqual reports whether two fabric snapshot slices are
// element-wise identical. FabricSnapshot is a flat struct of comparable fields,
// so a direct == comparison suffices — no reflect (retirement-boundary canary,
// TestUserspaceManagerDoesNotImportReflectOrUnsafe).
func fabricSnapshotsEqual(a, b []FabricSnapshot) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// ExportAllSessionsViaEventStream tells the Rust helper to push all current
// sessions through the event stream as Open events. The Go daemon receives
// them via handleEventStreamDelta and queues them to the peer automatically.
// This replaces the old BulkSync path that iterated BPF maps from Go.
func (m *Manager) ExportAllSessionsViaEventStream() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.proc == nil || m.proc.Process == nil {
		return errors.New("userspace dataplane helper not running")
	}
	var status ProcessStatus
	if err := m.requestLocked(ControlRequest{Type: "export_all_sessions"}, &status); err != nil {
		return err
	}
	return m.applyHelperStatusLocked(&status)
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
	return nil
}

func (m *Manager) seedHAGroupInventoryLocked(cfg *config.Config) {
	if cfg == nil || cfg.Chassis.Cluster == nil {
		// #1928: a non-cluster config has no redundancy groups. Drop any HA
		// groups retained from a prior clustered apply so the manager's view
		// matches reality and the startup path does not re-publish phantom HA
		// state to the helper (the source of the standalone transit-drop bug).
		m.haGroups = make(map[int]HAGroupStatus)
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
	var status ProcessStatus
	if err := m.requestLocked(ControlRequest{
		Type:       "set_forwarding_state",
		Forwarding: &ForwardingControlRequest{Armed: false},
	}, &status); err != nil {
		return fmt.Errorf("disarm userspace forwarding before %s publish: %w", reason, err)
	}
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
	m.mu.Lock()
	defer m.mu.Unlock()
	group := m.haGroups[rgID]
	group.RGID = rgID
	group.WatchdogTimestamp = timestamp
	m.haGroups[rgID] = group

	// Throttle the update_ha_state socket IPC. Nothing to send before the helper
	// is up; the first tick after it comes up seeds the baseline and syncs.
	if m.proc == nil || m.proc.Process == nil {
		return nil
	}
	if !m.shouldSyncHAWatchdogIPCLocked(rgID, group.Active, timestamp) {
		return nil
	}
	// Record the baseline BEFORE the send so a post-send applyHelperStatusLocked
	// or transient socket error cannot trigger a per-tick resync storm: the next
	// backstop (<= haWatchdogIPCBackstopSecs) retries, and the shim map write
	// keeps the kernel watchdog fresh in the meantime.
	m.markHAWatchdogIPCSyncedLocked()
	return m.syncHAStateLocked()
}

type userspaceCounterSnapshot struct {
	rxPackets         uint64
	txPackets         uint64
	forwardPackets    uint64
	sessionCreates    uint64
	sessionExpires    uint64
	policyDenied      uint64
	hostInboundDenied uint64
	screenDrops       uint64
	// #3343: per-screen-reason drop tallies, indexed by the
	// dataplane.ScreenReasonCounters ordinal. Summed across bindings and pushed
	// into each reason's GlobalCtrScreen* counter so the per-reason
	// screen-statistics surfaces are no longer stuck at 0.
	screenReasonDrops [dataplane.ScreenReasonDropCount]uint64
	synCookieSent     uint64
	synCookieValid    uint64
	synCookieInvalid  uint64
	synCookieBypass   uint64
	snatPackets       uint64
	dnatPackets       uint64
	nat64Translations uint64
	// #4477: source-NAT allocation failures, summed across bindings. Pushed
	// into dataplane.GlobalCtrNATAllocFail; also a term of the aggregate
	// "Packets dropped" total pushed into dataplane.GlobalCtrDrops.
	natAllocFail uint64
}

// totalDrops (#4477) is the aggregate "Packets dropped" figure surfaced by
// GlobalCtrDrops. It sums the firewall's ENFORCEMENT drops — policy
// denies, screen/IDS drops, host-inbound admission denies, and source-NAT
// allocation failures. These are exactly the four breakdown lines rendered
// beneath "Packets dropped" in `show security flow statistics`, so the
// aggregate equals the sum of its parts (a total-with-breakdown, not a
// double count into any single reason's own index). Before #4477 GlobalCtrDrops
// was never written and printed a false, always-0 value.
//
// #4508: this is ENFORCEMENT drops only, NOT the literal total of every packet
// the dataplane discards. Deliberately EXCLUDED (counted elsewhere or not
// folded here), so "Packets dropped" UNDERCOUNTS total discards:
//   - no-route / missing-neighbor drops — bumped as route_miss_packets /
//     neighbor_miss_packets and surfaced separately as "Route misses:" in the
//     helper status (see pkg/dataplane/userspace/format/status.go);
//   - fabric-forwarding drops (dataplane.GlobalCtrFabricFwdDrop, idx 32);
//   - VLAN-push failures (dataplane.GlobalCtrVlanPushFail, idx 40);
//   - NAT64 fail-closed drops (distinct from source-NAT alloc failure).
//
// If a true total is ever wanted, extend this sum to include those indices —
// but keep the display label verbatim for vSRX parity. Doc: the "Packets
// dropped scope" caveat in docs/junos-cli-reference.md.
func (s userspaceCounterSnapshot) totalDrops() uint64 {
	return s.policyDenied + s.screenDrops + s.hostInboundDenied + s.natAllocFail
}

// sumBindingCounters aggregates counters across all bindings in a status response.
func sumBindingCounters(status *ProcessStatus) userspaceCounterSnapshot {
	var s userspaceCounterSnapshot
	for i := range status.Bindings {
		b := &status.Bindings[i]
		s.rxPackets += b.RXPackets
		s.txPackets += b.TXPackets
		s.forwardPackets += b.ForwardCandidatePkts
		s.sessionCreates += b.SessionCreates
		s.sessionExpires += b.SessionExpires
		s.policyDenied += b.PolicyDeniedPackets
		s.hostInboundDenied += b.HostInboundDeniedPackets
		s.screenDrops += b.ScreenDrops
		// #3343: sum each per-reason ordinal. The Rust helper always sends a
		// fixed-length array, but guard the length so a short/old wire payload
		// (or an over-length future one) cannot panic the status poll.
		for i := 0; i < len(b.ScreenReasonDrops) && i < dataplane.ScreenReasonDropCount; i++ {
			s.screenReasonDrops[i] += b.ScreenReasonDrops[i]
		}
		s.synCookieSent += b.SYNCookieSynAckSent
		s.synCookieValid += b.SYNCookieAckValid
		s.synCookieInvalid += b.SYNCookieAckInvalid
		s.synCookieBypass += b.SYNCookieBypass
		s.snatPackets += b.SNATPackets
		s.dnatPackets += b.DNATPackets
		s.nat64Translations += b.Nat64Translations
		s.natAllocFail += b.NatAllocFail
	}
	return s
}

// syncBPFCountersPreIncrementObserver is a test-only seam: it fires inside
// syncBPFCountersLocked after the delta baseline has advanced
// (prevBindingCounters = cur) but BEFORE the IncrementGlobalCounter loop
// applies those deltas to the offset map. It is nil in production (the only
// runtime cost is a nil check on the 1/s counter sync). The #5098 review-fold
// atomicity test uses it to drive a concurrent ClearAllCounters through the
// exact window a status poll can be interrupted at, proving the clear cannot
// leave a residual in the just-reset offset.
var syncBPFCountersPreIncrementObserver func()

// syncBPFCountersLocked computes counter deltas since the last status poll
// and writes them into the BPF global_counters per-CPU array map.
// This ensures that packets forwarded by the userspace helper (which bypass
// the BPF pipeline) are reflected in ReadGlobalCounter results.
func (m *Manager) syncBPFCountersLocked(status *ProcessStatus) {
	cur := sumBindingCounters(status)
	prev := m.prevBindingCounters
	m.prevBindingCounters = cur

	// On the first poll (prev is all zeros) the entire cumulative count
	// becomes the delta. This is correct — the helper has been counting
	// since launch, and none of those packets appeared in BPF counters.
	type counterDelta struct {
		index uint32
		delta uint64
	}

	deltas := []counterDelta{
		{dataplane.GlobalCtrRxPackets, safeDelta(cur.rxPackets, prev.rxPackets)},
		{dataplane.GlobalCtrTxPackets, safeDelta(cur.txPackets, prev.txPackets)},
		{dataplane.GlobalCtrSessionsNew, safeDelta(cur.sessionCreates, prev.sessionCreates)},
		{dataplane.GlobalCtrSessionsClosed, safeDelta(cur.sessionExpires, prev.sessionExpires)},
		// #4477: bridge the aggregate "Packets dropped" total (policy deny +
		// screen + host-inbound deny + NAT-alloc-fail) into GlobalCtrDrops and
		// source-NAT allocation failures into GlobalCtrNATAllocFail. Both
		// indices were never written before #4477 — ReadGlobalCounter returned a
		// clean (0, nil) so `show security flow statistics` ("Packets dropped" /
		// "NAT allocation failures"), REST, Prometheus, and the CLI printed a
		// false 0 with no #3345 ErrCounterNotPopulated disclosure. Bridging real
		// deltas populates them so the disclosure correctly stays silent.
		{dataplane.GlobalCtrDrops, safeDelta(cur.totalDrops(), prev.totalDrops())},
		{dataplane.GlobalCtrNATAllocFail, safeDelta(cur.natAllocFail, prev.natAllocFail)},
		{dataplane.GlobalCtrPolicyDeny, safeDelta(cur.policyDenied, prev.policyDenied)},
		// #3326: surface host-inbound admission denies into the counter the CLI,
		// gRPC status, REST, and Prometheus collector already read
		// (GlobalCtrHostInboundDeny). The Rust helper counts each host-inbound
		// drop per-binding; this delta-push mirrors the policy-deny plumbing so
		// host-inbound enforcement is observable (was always 0 before #3326).
		{dataplane.GlobalCtrHostInboundDeny, safeDelta(cur.hostInboundDenied, prev.hostInboundDenied)},
		{dataplane.GlobalCtrScreenDrops, safeDelta(cur.screenDrops, prev.screenDrops)},
		// Challenge decisions are not "sent" until the worker admits a
		// SYN-ACK reply into bounded TX. Secret-unavailable and reply
		// budget drops remain userspace-local diagnostics.
		{dataplane.GlobalCtrSyncookieSent, safeDelta(cur.synCookieSent, prev.synCookieSent)},
		{dataplane.GlobalCtrSyncookieValid, safeDelta(cur.synCookieValid, prev.synCookieValid)},
		{dataplane.GlobalCtrSyncookieInvalid, safeDelta(cur.synCookieInvalid, prev.synCookieInvalid)},
		{dataplane.GlobalCtrSyncookieBypass, safeDelta(cur.synCookieBypass, prev.synCookieBypass)},
		// #2161: surface NAT64 translations into the global counter the CLI,
		// gRPC status, and Prometheus collector already read
		// (GlobalCtrNAT64Xlate). The Rust helper counts each v6<->v4 xlate
		// per-binding; this delta-push mirrors the snat/dnat plumbing so
		// `show security flow statistics` reflects live NAT64 translation.
		{dataplane.GlobalCtrNAT64Xlate, safeDelta(cur.nat64Translations, prev.nat64Translations)},
	}

	// #3343: push each per-screen-reason drop delta into its GlobalCtrScreen*
	// index, mirroring the aggregate GlobalCtrScreenDrops / SYN-cookie plumbing
	// above. Without this every per-reason counter the CLI/gRPC/REST/Prometheus
	// screen-statistics surfaces read stayed at 0 even while the aggregate rose
	// under attack. Ordinal i maps to dataplane.ScreenReasonCounters[i].Index.
	for i := range dataplane.ScreenReasonCounters {
		deltas = append(deltas, counterDelta{
			index: dataplane.ScreenReasonCounters[i].Index,
			delta: safeDelta(cur.screenReasonDrops[i], prev.screenReasonDrops[i]),
		})
	}

	if syncBPFCountersPreIncrementObserver != nil {
		syncBPFCountersPreIncrementObserver()
	}

	for _, d := range deltas {
		if d.delta == 0 {
			continue
		}
		if err := m.bpfShim.IncrementGlobalCounter(d.index, d.delta); err != nil {
			slog.Debug("userspace: failed to increment BPF global counter",
				"index", d.index, "delta", d.delta, "err", err)
		}
	}

	// #2218: mirror the helper's per-rule SNAT/DNAT/static-NAT translation hit
	// counters into the bpfShim offset map so Manager.ReadNATRuleCounter (and
	// `show security nat source/destination/static rule`) reports live hits.
	// The helper reports cumulative totals keyed by the compiler-assigned
	// counter ID; SetNATRuleCounterOffset stores them absolutely.
	for i := range status.NATRuleCounters {
		c := &status.NATRuleCounters[i]
		if c.CounterID == 0 {
			continue
		}
		m.bpfShim.SetNATRuleCounterOffset(uint32(c.CounterID), dataplane.CounterValue{
			Packets: c.Packets,
			Bytes:   c.Bytes,
		})
	}

	// #3651: mirror the helper's pre-summed per-zone traffic totals into the
	// bpfShim zone-counter offset map so Manager.ReadZoneCounters (and thus
	// `show security zones` Traffic statistics, REST /security/zones, and the
	// Prometheus collector) reports live per-zone volume instead of
	// ErrCounterNotPopulated ("not available"). The helper reports cumulative
	// totals keyed by the stable zone id.
	//
	// REPLACE the whole map rather than setting row by row. The published block
	// is a complete sparse set rebuilt each poll, so a zone that disappears from
	// it must disappear here too: a per-row SetZoneCounterOffset can only add or
	// overwrite, which strands the last value of any zone the helper stops
	// reporting and leaves every read surface serving a FROZEN total. That is
	// reachable in normal operation — a zone pushed past the helper's hot-path
	// slot capacity by a later config keeps its retained totals but stops being
	// counted, so its row drops out while the zone stays configured. See
	// ReplaceZoneCounterOffsets for the full disappearance taxonomy.
	zoneRows := make(map[uint16][2]dataplane.CounterValue, len(status.ZoneTrafficCounters))
	for i := range status.ZoneTrafficCounters {
		z := &status.ZoneTrafficCounters[i]
		zoneRows[z.ZoneID] = [2]dataplane.CounterValue{
			{Packets: z.IngressPackets, Bytes: z.IngressBytes},
			{Packets: z.EgressPackets, Bytes: z.EgressBytes},
		}
	}
	m.bpfShim.ReplaceZoneCounterOffsets(zoneRows)

	// #3651: the same mirror for the helper's pre-summed per-zone FLOOD-event
	// totals, so Manager.ReadFloodCounters (and thus `show security screen
	// ids-option statistics`) reports live SYN/ICMP/UDP flood-event counts
	// instead of ErrCounterNotPopulated ("not available"). Only the three counts
	// are sourced; FloodState's legacy WindowStart/SynproxyActive fields
	// belonged to the deleted eBPF rate-limiter state and stay zero.
	//
	// REPLACE the whole map rather than setting row by row, for the identical
	// reason as the traffic block above: the published set is complete and
	// rebuilt each poll, so a zone that disappears from it must disappear here
	// too. A per-row SetFloodCounterOffset can only add or overwrite, which
	// strands the last value of any zone the helper stops reporting and leaves
	// the screen-statistics surface serving a FROZEN flood count. That is
	// reachable in normal operation — a zone pushed past the helper's slot
	// capacity by a later config keeps its retained counts but stops being
	// counted, so its row drops out while the zone stays configured. See
	// ReplaceFloodCounterOffsets for the full disappearance taxonomy.
	floodRows := make(map[uint16]dataplane.FloodState, len(status.ZoneFloodCounters))
	for i := range status.ZoneFloodCounters {
		f := &status.ZoneFloodCounters[i]
		floodRows[f.ZoneID] = dataplane.FloodState{
			SynCount:  f.SynFloodEvents,
			ICMPCount: f.ICMPFloodEvents,
			UDPCount:  f.UDPFloodEvents,
		}
	}
	m.bpfShim.ReplaceFloodCounterOffsets(floodRows)
}

// safeDelta returns cur - prev. On counter reset (prev > cur), returns cur
// as the delta so counters don't undercount after helper restarts.
func safeDelta(cur, prev uint64) uint64 {
	if cur < prev {
		return cur // counter reset: treat current cumulative as delta
	}
	return cur - prev
}

func (m *Manager) SetSessionV4(key dataplane.SessionKey, val dataplane.SessionValue) error {
	if err := m.bpfShim.SetSessionV4(key, val); err != nil {
		return err
	}
	if !shouldMirrorUserspaceSession(val.IsReverse) {
		return nil
	}
	m.mirrorSessionPairV4(key, val)
	return nil
}

// mirrorSessionPairV4 mirrors a forward session and its pre-installed reverse
// companion (#310) to the Rust helper.
//
// #5007: it resolves BOTH requests against ONE consistent config snapshot by
// building them under a single uninterrupted m.mu hold — BEFORE any control
// socket I/O drops the lock — then transmits both. buildSessionSyncRequestV4
// resolves egress/zone/tunnel-endpoint metadata from m.lastSnapshot (and the
// compile result); a concurrent ApplyConfig publishes a new m.lastSnapshot
// while holding m.mu, so resolving both requests during one continuous hold
// guarantees the forward/reverse pair derives from the SAME snapshot.
// Transmitting only after both builds preserves the deliberate "socket I/O
// must not block snapshot publishes" property (the transmit drops m.mu for the
// send).
//
// #5698: the transmit goes through syncSessionPairLocked, which holds
// m.sessionMu for BOTH requests. The single m.mu unlock says nothing about
// session-socket ordering — the per-request path frees m.sessionMu between
// requests, and a concurrent generation-0 forward delete landing in that gap
// removes both halves in the helper, after which this pair's already-built
// explicit reverse re-creates a standalone reverse-only permit. One
// m.sessionMu hold removes the gap. It does not make the pair ATOMIC: a
// transport failure on the reverse still leaves the forward installed alone.
func (m *Manager) mirrorSessionPairV4(key dataplane.SessionKey, val dataplane.SessionValue) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.proc == nil {
		return
	}
	reqs := make([]SessionSyncRequest, 0, 2)
	reqs = append(reqs, m.buildSessionSyncRequestV4("upsert", key, &val))
	// Pre-install the reverse companion so the Rust worker has it before
	// RG activation, avoiding activation-time synthesis (#310).
	if val.ReverseKey.Protocol != 0 {
		revVal := val
		revVal.IsReverse = 1
		revVal.ReverseKey = key
		revVal.IngressZone = val.EgressZone
		revVal.EgressZone = val.IngressZone
		// Clear FIB cache — reverse egress must be re-resolved locally.
		revVal.FibIfindex = 0
		revVal.FibVlanID = 0
		revVal.FibDmac = [6]byte{}
		revVal.FibSmac = [6]byte{}
		revVal.FibGen = 0
		reqs = append(reqs, m.buildSessionSyncRequestV4("upsert", val.ReverseKey, &revVal))
	}
	// Snapshot reads are complete; transmit both requests under ONE sessionMu
	// hold so nothing interleaves between the halves (#5698). The mirror upsert
	// is best-effort (the periodic session sync reconciles a transient miss),
	// so the helper IPC error is intentionally discarded.
	_ = m.syncSessionPairLocked(reqs...)
}

func (m *Manager) SetClusterSyncedSessionV4(key dataplane.SessionKey, val dataplane.SessionValue) error {
	installVal := val
	installVal.FibIfindex = 0
	installVal.FibVlanID = 0
	installVal.FibDmac = [6]byte{}
	installVal.FibSmac = [6]byte{}
	installVal.FibGen = 0
	// The helper already synthesizes the correct reverse companion from the
	// forward cluster-synced entry using local forwarding and HA state. An
	// explicit reverse cluster update can overwrite that locally-derived
	// companion with peer NAT/FIB metadata, so only mirror forward entries. A
	// reverse entry is never mirrored, so there is no mirror failure to
	// compensate: write the BPF mirror and return.
	if !shouldMirrorUserspaceSession(val.IsReverse) {
		return m.bpfShim.SetSessionV4(key, installVal)
	}
	// Forward entry: make the install transactional (#5305). Capture the
	// pre-image of the BPF session entry BEFORE writing it, then mirror to the
	// helper. On mirror failure RESTORE the pre-image (rewrite the prior value,
	// or DELETE the key if it was absent) so a failed cluster-synced install
	// leaves the BPF map exactly as it was. Otherwise the pinned map holds a
	// session the helper never received — a split truth the GC and fallback
	// bulk export would propagate as if the install had succeeded, producing
	// nondeterministic HA session ownership after takeover.
	//
	// snapshot + write + mirror + compensate run under m.mu so the sequence is
	// atomic w.r.t. any other m.mu-holding path; the per-peer receiver apply
	// loop is single-threaded (pkg/cluster/sync_conn.go installClusterSyncedV4),
	// so no concurrent install of the SAME key races. syncSessionV4Locked drops
	// m.mu only for the socket send and reacquires it before returning, so the
	// compensate that follows still observes our own BPF write.
	m.mu.Lock()
	defer m.mu.Unlock()
	prior, hadPrior, err := m.snapshotBPFSessionV4Locked(key)
	if err != nil {
		// The pre-image could not be read; refuse the install rather than write
		// an entry that could not later be rolled back on a mirror failure.
		return fmt.Errorf("snapshot synced v4 session pre-image: %w", err)
	}
	if err := m.bpfShim.SetSessionV4(key, installVal); err != nil {
		return err
	}
	if err := m.syncSessionV4Locked("upsert", key, &installVal); err != nil {
		m.recordSessionMirrorFailureLocked(err)
		slog.Debug("userspace: session mirror failed", "err", err)
		compErr := m.restoreBPFSessionV4Locked(key, prior, hadPrior)
		return errors.Join(
			fmt.Errorf("mirror synced v4 session to userspace helper: %w", err),
			compErr,
		)
	}
	// A successful mirror proves the helper session socket is healthy again;
	// clear any sticky failure so the standby regains takeover-readiness
	// without waiting for a helper restart (#5247).
	m.recordSessionMirrorSuccessLocked()
	return nil
}

// bpfSessionReadAbsent reports whether a bpfShim session GET error means the
// key is ABSENT rather than a hard read failure. The transactional snapshot
// (#5305) treats an absent pre-image as existed=false with a nil error so a
// later mirror-failure rollback DELETES the freshly-installed key; any OTHER
// read error is surfaced so the install is refused rather than leaving an
// entry that could not be rolled back (the fail-safe direction).
//
// It accepts the SAME key-absent error set as the Layer-1
// dataplane.sessionNotFound predicate — ebpf.ErrKeyNotExist OR unix.ENOENT,
// via the shared dataplane.IsKeyNotFound helper — so the two transaction
// layers agree on what "key absent" means (#6194). With the production cilium
// bpfShim the two sentinels never diverge (a missing lookup yields
// ErrKeyNotExist, not bare ENOENT), so this is a consistency fix, not a live
// bug; sharing one predicate removes the latent skew.
func bpfSessionReadAbsent(err error) bool {
	return dataplane.IsKeyNotFound(err)
}

// snapshotBPFSessionV4Locked reads the current BPF-mirror value for key so a
// failed cluster-synced install can be rolled back to it (#5305). Returns
// (value, existed, err); a missing key is existed=false with a nil error.
// Named "Locked" for the m.mu convention of the compensation sequence — it
// touches only the independently-locked bpfShim map, not m.mu directly.
func (m *Manager) snapshotBPFSessionV4Locked(key dataplane.SessionKey) (dataplane.SessionValue, bool, error) {
	val, err := m.bpfShim.GetSessionV4(key)
	if err != nil {
		if bpfSessionReadAbsent(err) {
			return dataplane.SessionValue{}, false, nil
		}
		return dataplane.SessionValue{}, false, err
	}
	return val, true, nil
}

// restoreBPFSessionV4Locked reverts the BPF session entry for key to the
// pre-install snapshot: rewrite the prior value, or delete the key if it was
// absent (#5305). Deleting an already-absent key is treated as success.
func (m *Manager) restoreBPFSessionV4Locked(key dataplane.SessionKey, prior dataplane.SessionValue, hadPrior bool) error {
	if hadPrior {
		if err := m.bpfShim.SetSessionV4(key, prior); err != nil {
			return fmt.Errorf("restore synced v4 session pre-image: %w", err)
		}
		return nil
	}
	if err := m.bpfShim.DeleteSession(key); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		return fmt.Errorf("remove orphan synced v4 session: %w", err)
	}
	return nil
}

func (m *Manager) SetSessionV6(key dataplane.SessionKeyV6, val dataplane.SessionValueV6) error {
	if err := m.bpfShim.SetSessionV6(key, val); err != nil {
		return err
	}
	if !shouldMirrorUserspaceSession(val.IsReverse) {
		return nil
	}
	m.mirrorSessionPairV6(key, val)
	return nil
}

// mirrorSessionPairV6 is the IPv6 analogue of mirrorSessionPairV4 — see that
// method for the #5007 single-snapshot rationale and the #5698 contiguous-
// transmit rationale. It builds the forward request and its reverse companion
// under one uninterrupted m.mu hold, then transmits both through
// syncSessionPairLocked (one m.sessionMu hold for the pair).
func (m *Manager) mirrorSessionPairV6(key dataplane.SessionKeyV6, val dataplane.SessionValueV6) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.proc == nil {
		return
	}
	reqs := make([]SessionSyncRequest, 0, 2)
	reqs = append(reqs, m.buildSessionSyncRequestV6("upsert", key, &val))
	// Pre-install the reverse companion so the Rust worker has it before
	// RG activation, avoiding activation-time synthesis (#310).
	if val.ReverseKey.Protocol != 0 {
		revVal := val
		revVal.IsReverse = 1
		revVal.ReverseKey = key
		revVal.IngressZone = val.EgressZone
		revVal.EgressZone = val.IngressZone
		// Clear FIB cache — reverse egress must be re-resolved locally.
		revVal.FibIfindex = 0
		revVal.FibVlanID = 0
		revVal.FibDmac = [6]byte{}
		revVal.FibSmac = [6]byte{}
		revVal.FibGen = 0
		reqs = append(reqs, m.buildSessionSyncRequestV6("upsert", val.ReverseKey, &revVal))
	}
	// Snapshot reads are complete; transmit both requests under ONE sessionMu
	// hold so nothing interleaves between the halves (#5698). The mirror upsert
	// is best-effort (the periodic session sync reconciles a transient miss),
	// so the helper IPC error is intentionally discarded.
	_ = m.syncSessionPairLocked(reqs...)
}

func (m *Manager) SetClusterSyncedSessionV6(key dataplane.SessionKeyV6, val dataplane.SessionValueV6) error {
	installVal := val
	installVal.FibIfindex = 0
	installVal.FibVlanID = 0
	installVal.FibDmac = [6]byte{}
	installVal.FibSmac = [6]byte{}
	installVal.FibGen = 0
	// Reverse entries are never mirrored (see SetClusterSyncedSessionV4): write
	// the BPF mirror and return — no mirror failure to compensate.
	if !shouldMirrorUserspaceSession(val.IsReverse) {
		return m.bpfShim.SetSessionV6(key, installVal)
	}
	// Forward entry: transactional install (#5305) — the IPv6 analogue of
	// SetClusterSyncedSessionV4. Snapshot the BPF pre-image, write, mirror, and
	// restore the pre-image on mirror failure so a failed install never leaves
	// an orphan split-truth BPF entry the helper never received.
	m.mu.Lock()
	defer m.mu.Unlock()
	prior, hadPrior, err := m.snapshotBPFSessionV6Locked(key)
	if err != nil {
		return fmt.Errorf("snapshot synced v6 session pre-image: %w", err)
	}
	if err := m.bpfShim.SetSessionV6(key, installVal); err != nil {
		return err
	}
	if err := m.syncSessionV6Locked("upsert", key, &installVal); err != nil {
		m.recordSessionMirrorFailureLocked(err)
		slog.Debug("userspace: session mirror failed", "err", err)
		compErr := m.restoreBPFSessionV6Locked(key, prior, hadPrior)
		return errors.Join(
			fmt.Errorf("mirror synced v6 session to userspace helper: %w", err),
			compErr,
		)
	}
	// A successful mirror proves the helper session socket is healthy again;
	// clear any sticky failure so the standby regains takeover-readiness
	// without waiting for a helper restart (#5247).
	m.recordSessionMirrorSuccessLocked()
	return nil
}

// snapshotBPFSessionV6Locked is the IPv6 sibling of snapshotBPFSessionV4Locked
// (#5305).
func (m *Manager) snapshotBPFSessionV6Locked(key dataplane.SessionKeyV6) (dataplane.SessionValueV6, bool, error) {
	val, err := m.bpfShim.GetSessionV6(key)
	if err != nil {
		if bpfSessionReadAbsent(err) {
			return dataplane.SessionValueV6{}, false, nil
		}
		return dataplane.SessionValueV6{}, false, err
	}
	return val, true, nil
}

// restoreBPFSessionV6Locked is the IPv6 sibling of restoreBPFSessionV4Locked
// (#5305).
func (m *Manager) restoreBPFSessionV6Locked(key dataplane.SessionKeyV6, prior dataplane.SessionValueV6, hadPrior bool) error {
	if hadPrior {
		if err := m.bpfShim.SetSessionV6(key, prior); err != nil {
			return fmt.Errorf("restore synced v6 session pre-image: %w", err)
		}
		return nil
	}
	if err := m.bpfShim.DeleteSessionV6(key); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		return fmt.Errorf("remove orphan synced v6 session: %w", err)
	}
	return nil
}

func shouldMirrorUserspaceSession(isReverse uint8) bool {
	return isReverse == 0
}

func (m *Manager) DeleteSession(key dataplane.SessionKey) error {
	// Look up the session value BEFORE deleting from the BPF map so we
	// can retrieve the ReverseKey for the pre-installed companion (#351).
	val, valErr := m.bpfShim.GetSessionV4(key)

	if err := m.bpfShim.DeleteSession(key); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	_ = m.syncSessionV4Locked("delete", key, nil)
	// Also delete the reverse companion that SetSessionV4 pre-installed.
	if valErr == nil && val.ReverseKey.Protocol != 0 {
		_ = m.syncSessionV4Locked("delete", val.ReverseKey, nil)
	}
	return nil
}

func (m *Manager) DeleteSessionV6(key dataplane.SessionKeyV6) error {
	// Look up the session value BEFORE deleting from the BPF map so we
	// can retrieve the ReverseKey for the pre-installed companion (#351).
	val, valErr := m.bpfShim.GetSessionV6(key)

	if err := m.bpfShim.DeleteSessionV6(key); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	_ = m.syncSessionV6Locked("delete", key, nil)
	// Also delete the reverse companion that SetSessionV6 pre-installed.
	if valErr == nil && val.ReverseKey.Protocol != 0 {
		_ = m.syncSessionV6Locked("delete", val.ReverseKey, nil)
	}
	return nil
}

// sessionHelperDeleteChunk bounds how many per-session helper "delete" IPCs the
// batch/clear session paths transmit under a single control-socket unlock so a
// large clear stays cooperative and cannot monopolize the shared control socket
// (#5096). syncSessionRequestsLocked drops and reacquires m.mu once per chunk,
// giving a concurrent snapshot publish a window between chunks, and takes
// m.sessionMu once per REQUEST so live session installs can interleave INSIDE a
// chunk. A chunk this large deliberately stays interleavable: the contiguous
// transmit (syncSessionPairLocked, #5698) is capped at sessionPairMaxRequests
// precisely because holding m.sessionMu across 256 round trips would starve
// those installs for minutes.
const sessionHelperDeleteChunk = 256

// BatchDeleteSessions deletes a batch of IPv4 sessions from the BPF mirror AND
// issues an authoritative "delete" to the Rust helper for every key (#5096).
//
// The LegacyDataPlaneAdapter embeds the bpfShim as its dataplane.DataPlane, so
// without this method Go promotion would dispatch a batch delete to the mirror
// map ONLY — leaving the helper, which owns packet lookup/lifetime, forwarding
// under the just-revoked decision until it re-publishes the mirror ~10s later.
// The singular DeleteSession already routes per-session deletes to the helper;
// this does the same for the batch path used by policy invalidation and the
// cluster-stale sweep. The bpf mirror's delete count is returned unchanged so
// caller count semantics are preserved.
func (m *Manager) BatchDeleteSessions(keys []dataplane.SessionKey) (int, error) {
	deleted, err := m.bpfShim.BatchDeleteSessions(keys)
	// Attempt the helper delete for every key regardless of the mirror result:
	// a batch where a key vanished concurrently returns ErrKeyNotExist with a
	// partial count, and the helper delete of an already-absent key is a no-op,
	// so skipping on error would strand the still-present helper sessions.
	//
	// The batch path (policy invalidation, cluster-stale sweep) keeps the
	// #5096 best-effort contract — the periodic session sync and GC delta
	// reconcile a transient helper miss — so the helper IPC error is
	// intentionally discarded here. The operator clear-all path propagates it
	// instead (ClearAllSessions, #5881).
	_ = m.deleteHelperSessionsV4(keys)
	return deleted, err
}

// BatchDeleteSessionsV6 is the IPv6 analogue of BatchDeleteSessions (#5096).
func (m *Manager) BatchDeleteSessionsV6(keys []dataplane.SessionKeyV6) (int, error) {
	deleted, err := m.bpfShim.BatchDeleteSessionsV6(keys)
	_ = m.deleteHelperSessionsV6(keys)
	return deleted, err
}

// ClearAllSessions clears the BPF mirror AND issues an authoritative "delete" to
// the Rust helper for every session so an operator `clear security flow session
// all` actually stops forwarding under revoked decisions (#5096). The helper
// exposes no bulk-clear verb (only the per-session "delete" the singular path
// uses), so every mirror key — forward AND reverse conntrack entries — must be
// deleted on the helper too.
//
// The keys are NOT snapshotted here. Enumerating the full v4+v6 mirror into
// wrapper-owned slices while the shim's own clear snapshots them AGAIN (plus the
// dynamic-DNAT key lists) stacked ~1 GB of duplicate key slices in RSS on a
// max-loaded 10M/family table — enough for the recovery command to stall or
// OOM-kill the daemon (#5304). Instead the shim's ClearAllSessionsChunked drives
// a per-chunk callback: it collects a bounded chunk, deletes it from the mirror,
// and hands that same bounded chunk here for deletion on the helper, so neither
// side ever holds more than one chunk of keys. deleteHelperSessions{V4,V6} keeps
// the #5096 chunked-transmission behaviour (sessionHelperDeleteChunk).
//
// The Rust helper is AUTHORITATIVE in userspace mode — it owns packet
// lookup/forwarding while the BPF mirror is a read model. A helper-delete IPC
// failure therefore means a session the operator asked to revoke may still be
// forwarding, even though the mirror was emptied. Losing that error (as the
// pre-#5881 void callbacks did) let `clear security flow session all` report
// success while sessions lived on — a security bug. So the first helper-delete
// error is captured across chunks and, when the mirror clear itself succeeded,
// surfaced as ClearAllSessions's returned error. The bpf mirror's partial
// (v4, v6) counts are still returned alongside the error, matching the #5882
// non-atomic clear-all reporting contract, so a caller learns what the mirror
// side revoked while also learning the authoritative revocation is unconfirmed.
// A mirror-side error still takes precedence and is returned as before.
//
// #5380 residual: the per-chunk callbacks skip the helper delete once a
// transport failure is recorded, so a full clear-all under a hung helper pays
// ~one round-trip deadline total rather than one per 4096-key mirror chunk.
// See the helperDown guard below.
func (m *Manager) ClearAllSessions() (int, int, error) {
	var helperErr error
	recordHelperErr := func(err error) {
		if err != nil && helperErr == nil {
			helperErr = err
		}
	}
	// Fast-fail the WHOLE clear-all once the helper transport is down, not just
	// the 256-request loop inside a single deleteHelperSessions call (#5380
	// only aborted that inner loop). ClearAllSessionsChunked invokes these
	// callbacks ONCE PER sessionClearSnapshotChunk (4096-key) mirror chunk, and
	// the callbacks return void, so an inner abort does not propagate up: the
	// shim keeps handing every remaining chunk to a hung helper. A max table is
	// ~10M keys / 4096 ≈ 2440 chunks per family, so without this guard a
	// clear-all under a hung helper still pays ~one round-trip deadline PER
	// chunk (~2 h/family) even though each chunk's own delete already
	// fast-fails. Once a TRANSPORT failure has been recorded, skip the helper
	// delete for the remaining chunks so the clear-all pays ~one deadline
	// total. Only errSessionHelperUnreachable (a hung/unreachable helper) trips
	// the skip; an application-level rejection (helper alive, resp.OK=false) is
	// NOT wrapped as the sentinel, so a live helper that refuses one delete
	// keeps clearing the rest of the batch (#5881). The BPF mirror still clears
	// fully — the shim deletes each chunk BEFORE invoking the callback — and
	// helperErr stays set, so the #5881 error-propagation and #5882
	// partial-count contracts are unchanged.
	helperDown := func() bool { return errors.Is(helperErr, errSessionHelperUnreachable) }
	v4, v6, mirrorErr := m.bpfShim.ClearAllSessionsChunked(
		func(keys []dataplane.SessionKey) {
			if helperDown() {
				return
			}
			recordHelperErr(m.deleteHelperSessionsV4(keys))
		},
		func(keys []dataplane.SessionKeyV6) {
			if helperDown() {
				return
			}
			recordHelperErr(m.deleteHelperSessionsV6(keys))
		},
	)
	if mirrorErr != nil {
		return v4, v6, mirrorErr
	}
	if helperErr != nil {
		return v4, v6, fmt.Errorf("clear-all: authoritative helper session revocation failed: %w", helperErr)
	}
	return v4, v6, nil
}

// deleteHelperSessionsV4 tells the Rust helper to delete every key so the batch
// and clear session paths converge the helper's authoritative session table
// with the BPF mirror (#5096). Requests are transmitted in bounded chunks (see
// sessionHelperDeleteChunk) so a large clear does not monopolize the shared
// control socket. A "delete" request built with a nil value carries only the
// 5-tuple, so no snapshot read happens under m.mu.
//
// It returns the FIRST helper IPC error across all chunks (nil if all
// succeeded, or if there is no live helper). The best-effort batch callers
// discard it; ClearAllSessions propagates it so a failed authoritative
// revocation is reported rather than reported as success (#5881).
func (m *Manager) deleteHelperSessionsV4(keys []dataplane.SessionKey) error {
	if len(keys) == 0 {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.proc == nil {
		return nil
	}
	var firstErr error
	for start := 0; start < len(keys); start += sessionHelperDeleteChunk {
		end := start + sessionHelperDeleteChunk
		if end > len(keys) {
			end = len(keys)
		}
		reqs := make([]SessionSyncRequest, 0, end-start)
		for i := start; i < end; i++ {
			reqs = append(reqs, m.buildSessionSyncRequestV4("delete", keys[i], nil))
		}
		if err := m.syncSessionRequestsLocked(reqs...); err != nil {
			if firstErr == nil {
				firstErr = err
			}
			// Helper unreachable/hung: stop chunking. Every remaining chunk
			// would fast-fail identically, so a large clear (10M keys ≈ 40K
			// chunks) does not spend one round-trip deadline PER chunk (#5380).
			if errors.Is(err, errSessionHelperUnreachable) {
				break
			}
		}
	}
	return firstErr
}

// deleteHelperSessionsV6 is the IPv6 analogue of deleteHelperSessionsV4 (#5096).
func (m *Manager) deleteHelperSessionsV6(keys []dataplane.SessionKeyV6) error {
	if len(keys) == 0 {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.proc == nil {
		return nil
	}
	var firstErr error
	for start := 0; start < len(keys); start += sessionHelperDeleteChunk {
		end := start + sessionHelperDeleteChunk
		if end > len(keys) {
			end = len(keys)
		}
		reqs := make([]SessionSyncRequest, 0, end-start)
		for i := start; i < end; i++ {
			reqs = append(reqs, m.buildSessionSyncRequestV6("delete", keys[i], nil))
		}
		if err := m.syncSessionRequestsLocked(reqs...); err != nil {
			if firstErr == nil {
				firstErr = err
			}
			// Helper unreachable/hung: stop chunking (see deleteHelperSessionsV4).
			if errors.Is(err, errSessionHelperUnreachable) {
				break
			}
		}
	}
	return firstErr
}

func (m *Manager) syncSessionV4Locked(op string, key dataplane.SessionKey, val *dataplane.SessionValue) error {
	if m.proc == nil {
		return nil
	}
	req := m.buildSessionSyncRequestV4(op, key, val)
	return m.syncSessionRequestLocked(req)
}

func (m *Manager) buildSessionSyncRequestV4(op string, key dataplane.SessionKey, val *dataplane.SessionValue) SessionSyncRequest {
	req := SessionSyncRequest{
		Operation:  op,
		AddrFamily: dataplane.AFInet,
		Protocol:   key.Protocol,
		SrcIP:      net.IP(key.SrcIP[:]).String(),
		DstIP:      net.IP(key.DstIP[:]).String(),
		SrcPort:    networkUint16ToHost(key.SrcPort),
		DstPort:    networkUint16ToHost(key.DstPort),
	}
	if val != nil {
		req.IngressZone = m.zoneNameByID(val.IngressZone)
		req.EgressZone = m.zoneNameByID(val.EgressZone)
		// #919/#922: forward the raw u16 IDs alongside the legacy
		// strings; the Rust daemon prefers IDs when nonzero.
		req.IngressZoneID = val.IngressZone
		req.EgressZoneID = val.EgressZone
		req.EgressIfindex, req.TXIfindex, req.OwnerRGID = m.sessionSyncEgressLocked(int(val.FibIfindex), val.FibVlanID, req.EgressZone)
		req.TunnelEndpointID = m.sessionSyncTunnelEndpointIDLocked(req.EgressIfindex)
		if val.LogFlags&dataplane.LogFlagUserspaceTunnelEndpoint != 0 && val.FibGen != 0 {
			req.TunnelEndpointID = val.FibGen
		}
		if req.TunnelEndpointID != 0 {
			if endpoint, ok := m.sessionSyncTunnelEndpointLocked(req.TunnelEndpointID); ok {
				req.EgressIfindex = endpoint.Ifindex
				req.OwnerRGID = endpoint.RedundancyGroup
			} else {
				req.EgressIfindex = 0
				req.OwnerRGID = 0
			}
			req.TXIfindex = 0
			req.TXVLANID = 0
			req.NeighborMAC = ""
			req.SrcMAC = ""
		} else {
			req.TXVLANID = val.FibVlanID
			req.NeighborMAC = macString(val.FibDmac[:])
			req.SrcMAC = macString(val.FibSmac[:])
		}
		req.NATSrcIP = ipString(nativeUint32ToIP(val.NATSrcIP))
		req.NATDstIP = ipString(nativeUint32ToIP(val.NATDstIP))
		req.NATSrcPort = networkUint16ToHost(val.NATSrcPort)
		req.NATDstPort = networkUint16ToHost(val.NATDstPort)
		req.FabricIngress = val.LogFlags&dataplane.LogFlagUserspaceFabricIngress != 0
		req.IsReverse = val.IsReverse != 0
		// #2785: carry the per-policy `then log` selection to the peer helper
		// so the synced session logs the same RT_FLOW records after failover.
		req.LogSessionInit = val.LogFlags&dataplane.LogFlagSessionInit != 0
		req.LogSessionClose = val.LogFlags&dataplane.LogFlagSessionClose != 0
		// #2170: mirror the install generation to the helper so its in-memory
		// SyncedSessionEntry can enforce the same generation guard.
		req.Generation = val.Generation
		// #3301: carry the admitting policy's firewall metadata so a
		// peer-PROMOTED session resolves the admitting policy (PolicyID),
		// increments the correct per-rule hit counter (PolicyCounterIdx), and
		// ages on the per-application idle timeout (AppTimeout, seconds) after
		// failover. 0 => unattributed / no counter / global timeout, the
		// pre-#3301 behavior an old helper still applies via serde(default).
		req.PolicyID = val.PolicyID
		req.PolicyCounterIdx = val.PolicyCounterIdx
		req.InactivityTimeout = val.AppTimeout
		// #5212: carry the originating node's stable RT_FLOW session id so the
		// peer helper adopts it on import instead of minting a fresh local id.
		req.RTFlowSessionID = val.RTFlowSessionID
		if val.Flags&dataplane.SessFlagSNAT == 0 {
			req.NATSrcIP = ""
			req.NATSrcPort = 0
		}
		if val.Flags&dataplane.SessFlagDNAT == 0 {
			req.NATDstIP = ""
			req.NATDstPort = 0
		}
	}
	return req
}

func (m *Manager) syncSessionV6Locked(op string, key dataplane.SessionKeyV6, val *dataplane.SessionValueV6) error {
	if m.proc == nil {
		return nil
	}
	req := m.buildSessionSyncRequestV6(op, key, val)
	return m.syncSessionRequestLocked(req)
}

func (m *Manager) buildSessionSyncRequestV6(op string, key dataplane.SessionKeyV6, val *dataplane.SessionValueV6) SessionSyncRequest {
	req := SessionSyncRequest{
		Operation:  op,
		AddrFamily: dataplane.AFInet6,
		Protocol:   key.Protocol,
		SrcIP:      net.IP(key.SrcIP[:]).String(),
		DstIP:      net.IP(key.DstIP[:]).String(),
		SrcPort:    networkUint16ToHost(key.SrcPort),
		DstPort:    networkUint16ToHost(key.DstPort),
	}
	if val != nil {
		req.IngressZone = m.zoneNameByID(val.IngressZone)
		req.EgressZone = m.zoneNameByID(val.EgressZone)
		// #919/#922: forward the raw u16 IDs alongside the legacy
		// strings; the Rust daemon prefers IDs when nonzero.
		req.IngressZoneID = val.IngressZone
		req.EgressZoneID = val.EgressZone
		req.EgressIfindex, req.TXIfindex, req.OwnerRGID = m.sessionSyncEgressLocked(int(val.FibIfindex), val.FibVlanID, req.EgressZone)
		req.TunnelEndpointID = m.sessionSyncTunnelEndpointIDLocked(req.EgressIfindex)
		if val.LogFlags&dataplane.LogFlagUserspaceTunnelEndpoint != 0 && val.FibGen != 0 {
			req.TunnelEndpointID = val.FibGen
		}
		if req.TunnelEndpointID != 0 {
			if endpoint, ok := m.sessionSyncTunnelEndpointLocked(req.TunnelEndpointID); ok {
				req.EgressIfindex = endpoint.Ifindex
				req.OwnerRGID = endpoint.RedundancyGroup
			} else {
				req.EgressIfindex = 0
				req.OwnerRGID = 0
			}
			req.TXIfindex = 0
			req.TXVLANID = 0
			req.NeighborMAC = ""
			req.SrcMAC = ""
		} else {
			req.TXVLANID = val.FibVlanID
			req.NeighborMAC = macString(val.FibDmac[:])
			req.SrcMAC = macString(val.FibSmac[:])
		}
		req.NATSrcIP = ipString(net.IP(val.NATSrcIP[:]))
		req.NATDstIP = ipString(net.IP(val.NATDstIP[:]))
		req.NATSrcPort = networkUint16ToHost(val.NATSrcPort)
		req.NATDstPort = networkUint16ToHost(val.NATDstPort)
		req.FabricIngress = val.LogFlags&dataplane.LogFlagUserspaceFabricIngress != 0
		req.IsReverse = val.IsReverse != 0
		// #2785: carry the per-policy `then log` selection to the peer helper
		// so the synced session logs the same RT_FLOW records after failover.
		req.LogSessionInit = val.LogFlags&dataplane.LogFlagSessionInit != 0
		req.LogSessionClose = val.LogFlags&dataplane.LogFlagSessionClose != 0
		// #2170: mirror the install generation to the helper.
		req.Generation = val.Generation
		// #3301: carry the admitting policy's firewall metadata (see V4).
		req.PolicyID = val.PolicyID
		req.PolicyCounterIdx = val.PolicyCounterIdx
		req.InactivityTimeout = val.AppTimeout
		// #4565: carry the NAT64 translated pool SOURCE (non-zero marks a NAT64
		// cross-family session) so the peer helper rebuilds the reverse (v4->v6)
		// BIB after promotion. The generic nat_src/nat_dst fields cannot carry a
		// v4 pool source in a v6 session's slot unambiguously — this dedicated
		// dotted-quad is the helper's authoritative snat_v4.
		if val.Nat64SnatV4 != ([4]byte{}) {
			req.Nat64SnatV4 = net.IP(val.Nat64SnatV4[:]).String()
		}
		// #5212: carry the originating node's stable RT_FLOW session id (see V4).
		req.RTFlowSessionID = val.RTFlowSessionID
		if val.Flags&dataplane.SessFlagSNAT == 0 {
			req.NATSrcIP = ""
			req.NATSrcPort = 0
		}
		if val.Flags&dataplane.SessFlagDNAT == 0 {
			req.NATDstIP = ""
			req.NATDstPort = 0
		}
	}
	return req
}

func (m *Manager) sessionSyncTunnelEndpointIDLocked(egressIfindex int) uint16 {
	snapshot := m.lastSnapshot
	if snapshot == nil || egressIfindex <= 0 {
		return 0
	}
	for _, endpoint := range snapshot.TunnelEndpoints {
		if endpoint.Ifindex == egressIfindex {
			return endpoint.ID
		}
	}
	return 0
}

func (m *Manager) sessionSyncTunnelEndpointLocked(id uint16) (TunnelEndpointSnapshot, bool) {
	snapshot := m.lastSnapshot
	if snapshot == nil || id == 0 {
		return TunnelEndpointSnapshot{}, false
	}
	for _, endpoint := range snapshot.TunnelEndpoints {
		if endpoint.ID == id {
			return endpoint, true
		}
	}
	return TunnelEndpointSnapshot{}, false
}

func (m *Manager) syncSessionRequestLocked(req SessionSyncRequest) error {
	// Build the control request under mu (for data access), then release mu
	// before the socket I/O so snapshot publishes aren't blocked.
	ctrlReq := ControlRequest{
		Type:           "sync_session",
		SuppressStatus: true,
		SessionSync:    &req,
	}
	m.mu.Unlock()
	err := m.requestSessionSync(ctrlReq)
	m.mu.Lock()
	if err != nil {
		slog.Debug("userspace session sync mirror failed", "operation", req.Operation, "err", err)
	}
	return err
}

// sendSessionSyncBatch transmits reqs through send, which performs one
// session-socket round trip per request. It is the single implementation of the
// batch loop shared by syncSessionRequestsLocked (send = the per-request
// locking wrapper) and syncSessionPairLocked (send = the unlocked inner, under
// one caller-held sessionMu), so the two transmit paths cannot drift apart on
// error handling.
//
// It attempts every request as long as the helper keeps answering — an
// APPLICATION-level rejection of one request (helper alive, resp.OK=false) does
// not stop the loop, so a bulk revocation drops as many helper sessions as it
// can. It returns the FIRST helper IPC error encountered, or nil if all
// succeeded.
//
// #5380: if a request fails at the TRANSPORT layer (dial/write/read wrapped
// with errSessionHelperUnreachable), the helper is down or hung and every
// remaining request would pay the full per-request deadline too. A bulk delete
// chunk is up to sessionHelperDeleteChunk (256) requests, so looping on would
// stall bulk session ops — and repeatedly hold sessionMu, starving live session
// installs — for ~256 * sessionSyncRoundtripDeadline (~13 min). So the batch
// fast-fails: it stops after the first transport failure and returns it. The
// mirror is best-effort — the periodic sweep retries once the helper is healthy
// again.
func sendSessionSyncBatch(reqs []SessionSyncRequest, send func(ControlRequest) error) error {
	var firstErr error
	for i := range reqs {
		ctrlReq := ControlRequest{
			Type:           "sync_session",
			SuppressStatus: true,
			SessionSync:    &reqs[i],
		}
		if err := send(ctrlReq); err != nil {
			slog.Debug("userspace session sync mirror failed", "operation", reqs[i].Operation, "err", err)
			if firstErr == nil {
				firstErr = err
			}
			// Helper unreachable/hung: abort the batch instead of paying the
			// per-request deadline once per remaining request (#5380).
			if errors.Is(err, errSessionHelperUnreachable) {
				break
			}
		}
	}
	return firstErr
}

// syncSessionRequestsLocked transmits one or more PRE-BUILT session-sync
// requests to the Rust helper over the session socket. Like
// syncSessionRequestLocked it drops m.mu once for the socket I/O (so snapshot
// publishes are not blocked by a session install) and reacquires it before
// returning; the caller keeps the lock across the call. It performs NO
// snapshot reads — callers MUST have built every request under a single,
// uninterrupted prior m.mu hold so a forward/reverse companion pair is
// resolved against one consistent snapshot (#5007).
//
// The single m.mu unlock buys exactly two things and NOTHING more: the
// deliberate "socket I/O must not block snapshot publishes" property, and the
// #5007 one-snapshot build (every request was resolved before the lock was
// dropped). It does NOT make the transmit contiguous. This path acquires and
// releases m.sessionMu once PER request (requestSessionSync), so m.sessionMu is
// free between consecutive requests and an unrelated session-socket mutation —
// an operator clear, a policy invalidation, a GC delete, a stale-session
// reconciliation — can land between them (#5698). That interleaving is the
// CORRECT behaviour here: a bulk caller passes up to sessionHelperDeleteChunk
// (256) requests, and holding sessionMu across a chunk that large would starve
// live session installs for minutes — the exact harm the #5380 fast-fail
// exists to avoid. Contiguity, where a group genuinely must not be split,
// comes from syncSessionPairLocked's single sessionMu hold instead.
//
// It returns the FIRST helper IPC error encountered, or nil if all succeeded.
// Best-effort mirror callers (batch delete) discard the result; the
// authoritative clear-all path (#5881) propagates it so a failed helper
// revocation is reported instead of masquerading as success.
func (m *Manager) syncSessionRequestsLocked(reqs ...SessionSyncRequest) error {
	if len(reqs) == 0 {
		return nil
	}
	m.mu.Unlock()
	firstErr := sendSessionSyncBatch(reqs, m.requestSessionSync)
	m.mu.Lock()
	return firstErr
}

// sessionPairMaxRequests is the hard cap on how many requests
// syncSessionPairLocked will transmit under ONE m.sessionMu hold. The only
// group that needs an uninterrupted transmit is a forward session plus its
// pre-installed reverse companion (#310), so two is the real bound; the
// constant exists so a future caller cannot quietly turn the contiguous path
// into a bulk path. Holding sessionMu across a large group would starve live
// session installs — see the #5380 note on sendSessionSyncBatch — so a group
// larger than this falls back to the per-request discipline rather than
// trading a rare interleave for a multi-minute install stall.
const sessionPairMaxRequests = 2

// syncSessionPairLocked transmits a SMALL, PRE-BUILT group of session-sync
// requests to the Rust helper with nothing interleaved between them.
//
// Like syncSessionRequestsLocked it drops m.mu once for the socket I/O and
// reacquires it before returning, so snapshot publishes are still never blocked
// by a session install and the #5007 one-snapshot build still holds. The
// difference is m.sessionMu: this path takes it ONCE for the whole group
// instead of once per request, so no other session-socket caller can run
// between the group's members. That closes the #5698 window in which a
// generation-0 forward delete landed between a pair's forward and its reverse:
// the delete removed BOTH halves in the helper, and the pair's already-built
// explicit reverse then re-created a standalone reverse-only permit.
//
// The group is capped at sessionPairMaxRequests. A larger group falls back to
// syncSessionRequestsLocked's per-request locking: an oversized contiguous hold
// would starve live session installs, which is a worse failure than the
// interleave it would prevent. The fallback is logged because reaching it means
// a caller mis-sized the group — it is unreachable from the pair mirrors, which
// build at most two requests.
//
// Error semantics are identical to syncSessionRequestsLocked (see
// sendSessionSyncBatch): first error wins, application-level rejections do not
// stop the group, a transport failure aborts it.
//
// RESIDUAL (deliberately out of scope): this makes the pair's transmit
// contiguous, not atomic. If the SECOND request fails at the transport layer
// the helper is left with a half-installed pair; nothing rolls the first half
// back. Closing that needs a helper-side pair transaction over the wire.
func (m *Manager) syncSessionPairLocked(reqs ...SessionSyncRequest) error {
	if len(reqs) == 0 {
		return nil
	}
	if len(reqs) > sessionPairMaxRequests {
		slog.Error("userspace session pair transmit oversized; falling back to "+
			"per-request locking (no contiguity guarantee)",
			"requests", len(reqs), "max", sessionPairMaxRequests)
		return m.syncSessionRequestsLocked(reqs...)
	}
	m.mu.Unlock()
	m.sessionMu.Lock()
	firstErr := sendSessionSyncBatch(reqs, m.requestSessionSyncLocked)
	m.sessionMu.Unlock()
	m.mu.Lock()
	return firstErr
}

func (m *Manager) zoneNameByID(zoneID uint16) string {
	if zoneID == 0 {
		return ""
	}
	cr := m.bpfShim.LastCompileResult()
	if cr == nil {
		return ""
	}
	// #3719: a StableZoneID collision maps two zone names to the same id in
	// ZoneIDs. The dataplane installs only the sorted-FIRST name (the survivor
	// config.QuarantinedZoneNames keeps), so resolve deterministically to that
	// name instead of returning whichever name a map-iteration coin flip yields
	// — which could name the QUARANTINED zone that forwards nothing.
	owner := ""
	for name, id := range cr.ZoneIDs {
		if id != zoneID {
			continue
		}
		if owner == "" || name < owner {
			owner = name
		}
	}
	return owner
}

func nativeUint32ToIP(v uint32) net.IP {
	if v == 0 {
		return nil
	}
	var raw [4]byte
	binary.NativeEndian.PutUint32(raw[:], v)
	return net.IPv4(raw[0], raw[1], raw[2], raw[3]).To4()
}

func networkUint16ToHost(v uint16) uint16 {
	var raw [2]byte
	binary.NativeEndian.PutUint16(raw[:], v)
	return binary.BigEndian.Uint16(raw[:])
}

func ipString(ip net.IP) string {
	if ip == nil {
		return ""
	}
	if v4 := ip.To4(); v4 != nil && v4.Equal(net.IPv4zero) {
		return ""
	}
	if v6 := ip.To16(); v6 != nil && v6.Equal(net.IPv6zero) {
		return ""
	}
	return ip.String()
}

func macString(raw []byte) string {
	if len(raw) < 6 {
		return ""
	}
	allZero := true
	for i := 0; i < 6; i++ {
		if raw[i] != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		return ""
	}
	return net.HardwareAddr(raw[:6]).String()
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

func userspaceBootstrapProbeInterfaces(cfg *config.Config) []string {
	if cfg == nil {
		return nil
	}
	seen := make(map[string]bool)
	out := make([]string, 0, len(cfg.Interfaces.Interfaces)*2)
	names := make([]string, 0, len(cfg.Interfaces.Interfaces))
	for ifName := range cfg.Interfaces.Interfaces {
		names = append(names, ifName)
	}
	sort.Strings(names)
	for _, ifName := range names {
		ifc := cfg.Interfaces.Interfaces[ifName]
		if ifc == nil {
			continue
		}
		base := config.LinuxIfName(ifName)
		if !seen[base] {
			seen[base] = true
			out = append(out, base)
		}
		if len(ifc.Units) == 0 {
			continue
		}
		unitNums := make([]int, 0, len(ifc.Units))
		for unitNum := range ifc.Units {
			unitNums = append(unitNums, unitNum)
		}
		sort.Ints(unitNums)
		for _, unitNum := range unitNums {
			unit := ifc.Units[unitNum]
			if unit == nil || unit.VlanID <= 0 {
				continue
			}
			linuxName := fmt.Sprintf("%s.%d", base, unit.VlanID)
			if seen[linuxName] {
				continue
			}
			seen[linuxName] = true
			out = append(out, linuxName)
		}
	}
	return out
}

func (m *Manager) sessionSyncEgressLocked(fibIfindex int, fibVlanID uint16, egressZone string) (egressIfindex, txIfindex, ownerRGID int) {
	snapshot := m.lastSnapshot
	if snapshot == nil {
		return fibIfindex, fibIfindex, 0
	}
	if fibIfindex <= 0 {
		// FibIfindex is unresolved but we can still derive owner_rg_id
		// from the session's egress zone so the sync peer doesn't have
		// to fall back to the imprecise any_rg_active heuristic.
		return fibIfindex, fibIfindex, resolveOwnerRGFromZone(snapshot, egressZone)
	}
	if iface, ok := findUserspaceEgressInterfaceSnapshot(snapshot, fibIfindex, fibVlanID); ok {
		egress := iface.Ifindex
		if egress <= 0 {
			egress = fibIfindex
		}
		tx := iface.ParentIfindex
		if tx <= 0 {
			tx = egress
		}
		return egress, tx, iface.RedundancyGroup
	}
	return fibIfindex, fibIfindex, 0
}

// resolveOwnerRGFromZone returns the RedundancyGroup for the first interface
// in the given egress zone. This is used as a fallback when FibIfindex is 0
// so the sync sender can still propagate a meaningful owner_rg_id to the peer.
func resolveOwnerRGFromZone(snapshot *ConfigSnapshot, egressZone string) int {
	if snapshot == nil || egressZone == "" {
		return 0
	}
	for _, iface := range snapshot.Interfaces {
		if iface.Zone == egressZone && iface.RedundancyGroup > 0 {
			return iface.RedundancyGroup
		}
	}
	return 0
}

func findUserspaceEgressInterfaceSnapshot(snapshot *ConfigSnapshot, fibIfindex int, fibVlanID uint16) (InterfaceSnapshot, bool) {
	if snapshot == nil {
		return InterfaceSnapshot{}, false
	}
	if fibVlanID != 0 {
		for _, iface := range snapshot.Interfaces {
			if iface.ParentIfindex == fibIfindex && iface.VLANID == int(fibVlanID) {
				return iface, true
			}
		}
	}
	for _, iface := range snapshot.Interfaces {
		if iface.Ifindex == fibIfindex {
			return iface, true
		}
	}
	for _, iface := range snapshot.Interfaces {
		if iface.ParentIfindex == fibIfindex {
			return iface, true
		}
	}
	return InterfaceSnapshot{}, false
}
