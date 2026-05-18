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

// SyncFabricState pushes current fabric snapshots (with fresh peer MACs)
// to the Rust helper. Called from the daemon after refreshFabricFwd succeeds
// so the helper has up-to-date fabric MAC info for cross-chassis redirect.
func (m *Manager) SyncFabricState() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.proc == nil || m.proc.Process == nil || m.lastSnapshot == nil {
		return
	}
	fabrics := buildFabricSnapshots(m.lastSnapshot.Config)
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
	}
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
	rgMap := m.inner.Map("rg_active")
	if rgMap == nil {
		return errors.New("rg_active map not loaded")
	}
	wdMap := m.inner.Map("ha_watchdog")
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
	wdMap := m.inner.Map("ha_watchdog")
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
	// Startup settle and XSK bring-up are now controlled by userspace_ctrl
	// and the liveness probe in applyHelperStatusLocked(). Disarming the
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

func (m *Manager) syncDesiredForwardingStateLocked() error {
	if m.proc == nil || m.proc.Process == nil {
		return nil
	}
	desired := m.desiredForwardingArmedLocked()
	if m.lastStatus.ForwardingArmed == desired {
		return nil
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
	if err := m.inner.UpdateRGActive(rgID, active); err != nil {
		return err
	}

	prior, known := m.haGroups[rgID]
	group := prior
	group.RGID = rgID
	group.Active = active
	m.haGroups[rgID] = group

	// Only log on real transitions. The reconcile loop retries this
	// call whenever applied != desired (see #757), so emitting INFO
	// on every call floods journald at 9+ lines/sec when the helper
	// is down. First-seen registration counts as a transition.
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
	if err := m.applyHelperStatusLocked(&status); err != nil {
		return err
	}

	return nil
}

func (m *Manager) UpdateHAWatchdog(rgID int, timestamp uint64) error {
	if err := m.inner.UpdateHAWatchdog(rgID, timestamp); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	group := m.haGroups[rgID]
	group.RGID = rgID
	group.WatchdogTimestamp = timestamp
	m.haGroups[rgID] = group
	return m.syncHAStateLocked()
}

type userspaceCounterSnapshot struct {
	rxPackets        uint64
	txPackets        uint64
	forwardPackets   uint64
	sessionCreates   uint64
	sessionExpires   uint64
	policyDenied     uint64
	screenDrops      uint64
	synCookieValid   uint64
	synCookieInvalid uint64
	synCookieBypass  uint64
	snatPackets      uint64
	dnatPackets      uint64
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
		s.screenDrops += b.ScreenDrops
		s.synCookieValid += b.SYNCookieAckValid
		s.synCookieInvalid += b.SYNCookieAckInvalid
		s.synCookieBypass += b.SYNCookieBypass
		s.snatPackets += b.SNATPackets
		s.dnatPackets += b.DNATPackets
	}
	return s
}

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
		{dataplane.GlobalCtrPolicyDeny, safeDelta(cur.policyDenied, prev.policyDenied)},
		{dataplane.GlobalCtrScreenDrops, safeDelta(cur.screenDrops, prev.screenDrops)},
		// Challenge decisions are not SYN-cookie "sent" events until the
		// userspace helper can transmit bounded SYN-ACK replies.
		{dataplane.GlobalCtrSyncookieValid, safeDelta(cur.synCookieValid, prev.synCookieValid)},
		{dataplane.GlobalCtrSyncookieInvalid, safeDelta(cur.synCookieInvalid, prev.synCookieInvalid)},
		{dataplane.GlobalCtrSyncookieBypass, safeDelta(cur.synCookieBypass, prev.synCookieBypass)},
	}

	for _, d := range deltas {
		if d.delta == 0 {
			continue
		}
		if err := m.inner.IncrementGlobalCounter(d.index, d.delta); err != nil {
			slog.Debug("userspace: failed to increment BPF global counter",
				"index", d.index, "delta", d.delta, "err", err)
		}
	}
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
	if err := m.inner.SetSessionV4(key, val); err != nil {
		return err
	}
	if !shouldMirrorUserspaceSession(val.IsReverse) {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	// Send the forward session to the Rust worker.
	_ = m.syncSessionV4Locked("upsert", key, &val)
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
		_ = m.syncSessionV4Locked("upsert", val.ReverseKey, &revVal)
	}
	return nil
}

func (m *Manager) SetClusterSyncedSessionV4(key dataplane.SessionKey, val dataplane.SessionValue) error {
	installVal := val
	installVal.FibIfindex = 0
	installVal.FibVlanID = 0
	installVal.FibDmac = [6]byte{}
	installVal.FibSmac = [6]byte{}
	installVal.FibGen = 0
	if err := m.inner.SetSessionV4(key, installVal); err != nil {
		return err
	}
	// The helper already synthesizes the correct reverse companion from the
	// forward cluster-synced entry using local forwarding and HA state. An
	// explicit reverse cluster update can overwrite that locally-derived
	// companion with peer NAT/FIB metadata, so only mirror forward entries.
	if !shouldMirrorUserspaceSession(val.IsReverse) {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.syncSessionV4Locked("upsert", key, &installVal); err != nil {
		m.recordSessionMirrorFailureLocked(err)
		slog.Debug("userspace: session mirror failed", "err", err)
		return fmt.Errorf("mirror synced v4 session to userspace helper: %w", err)
	}
	return nil
}

func (m *Manager) SetSessionV6(key dataplane.SessionKeyV6, val dataplane.SessionValueV6) error {
	if err := m.inner.SetSessionV6(key, val); err != nil {
		return err
	}
	if !shouldMirrorUserspaceSession(val.IsReverse) {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	// Send the forward session to the Rust worker.
	_ = m.syncSessionV6Locked("upsert", key, &val)
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
		_ = m.syncSessionV6Locked("upsert", val.ReverseKey, &revVal)
	}
	return nil
}

func (m *Manager) SetClusterSyncedSessionV6(key dataplane.SessionKeyV6, val dataplane.SessionValueV6) error {
	installVal := val
	installVal.FibIfindex = 0
	installVal.FibVlanID = 0
	installVal.FibDmac = [6]byte{}
	installVal.FibSmac = [6]byte{}
	installVal.FibGen = 0
	if err := m.inner.SetSessionV6(key, installVal); err != nil {
		return err
	}
	if !shouldMirrorUserspaceSession(val.IsReverse) {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.syncSessionV6Locked("upsert", key, &installVal); err != nil {
		m.recordSessionMirrorFailureLocked(err)
		slog.Debug("userspace: session mirror failed", "err", err)
		return fmt.Errorf("mirror synced v6 session to userspace helper: %w", err)
	}
	return nil
}

func shouldMirrorUserspaceSession(isReverse uint8) bool {
	return isReverse == 0
}

func (m *Manager) DeleteSession(key dataplane.SessionKey) error {
	// Look up the session value BEFORE deleting from the BPF map so we
	// can retrieve the ReverseKey for the pre-installed companion (#351).
	val, valErr := m.inner.GetSessionV4(key)

	if err := m.inner.DeleteSession(key); err != nil {
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
	val, valErr := m.inner.GetSessionV6(key)

	if err := m.inner.DeleteSessionV6(key); err != nil {
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

func (m *Manager) zoneNameByID(zoneID uint16) string {
	if zoneID == 0 {
		return ""
	}
	if cr := m.inner.LastCompileResult(); cr != nil {
		for name, id := range cr.ZoneIDs {
			if id == zoneID {
				return name
			}
		}
	}
	return ""
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
