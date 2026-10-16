package userspace

import (
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"time"
)

// ErrPersistentNatLeaseScopeProtocolIncompatible means the helper has not
// proved that it understands the persistent-lease routing scope and
// permission fields. Lease export/import are live control verbs, so these
// paths fail closed when status is unavailable or unobserved.
var ErrPersistentNatLeaseScopeProtocolIncompatible = errors.New(
	"userspace persistent NAT lease protocol incompatible")

func (m *Manager) ensurePersistentNatLeaseProtocolLocked(required int, feature string) error {
	if m.helperStatusObserved &&
		m.lastStatus.ConfigSnapshotProtocolVersion >= required {
		return nil
	}

	var status ProcessStatus
	if err := m.requestLocked(ControlRequest{Type: "status"}, &status); err != nil {
		return fmt.Errorf("%w: could not verify helper protocol before lease request: %v",
			ErrPersistentNatLeaseScopeProtocolIncompatible, err)
	}
	m.recordHelperStatusLocked(&status)
	if status.ConfigSnapshotProtocolVersion < required {
		return fmt.Errorf(
			"%w: helper protocol version %d is below required %d for persistent-NAT lease %s",
			ErrPersistentNatLeaseScopeProtocolIncompatible,
			status.ConfigSnapshotProtocolVersion,
			required,
			feature,
		)
	}
	return nil
}

func (m *Manager) ensurePersistentNatLeasePermissionProtocolLocked() error {
	return m.ensurePersistentNatLeaseProtocolLocked(
		MinProtocolPersistentNatLeasePermissions, "permissions")
}

func (m *Manager) ensurePersistentNatLeaseScopeProtocolLocked() error {
	return m.ensurePersistentNatLeaseProtocolLocked(
		MinProtocolPersistentNatLeaseScope, "scope")
}

func validatePersistentNatRemotes(remotes []PersistentNatRemote) error {
	if len(remotes) > MaxPersistentNatLeaseRemotes {
		return fmt.Errorf("permission list has %d remotes; maximum is %d",
			len(remotes), MaxPersistentNatLeaseRemotes)
	}
	for i, remote := range remotes {
		addr, err := netip.ParseAddr(remote.IP)
		if err != nil || addr.Zone() != "" {
			return fmt.Errorf("permission remote %d has invalid IP %q", i, remote.IP)
		}
	}
	return nil
}

func validateIdleLeaseScopes(leases []IdleLeaseWire) error {
	for i, lease := range leases {
		if lease.RoutingScope == nil {
			return fmt.Errorf(
				"%w: helper returned idle lease %d without routing_scope",
				ErrPersistentNatLeaseScopeProtocolIncompatible, i)
		}
		if err := validatePersistentNatRemotes(lease.PermittedRemotes); err != nil {
			return fmt.Errorf("%w: helper returned idle lease %d with invalid permissions: %v",
				ErrPersistentNatLeaseScopeProtocolIncompatible, i, err)
		}
	}
	return nil
}

func validateDisplayLeaseScopes(leases []DisplayLeaseWire) error {
	for i, lease := range leases {
		if lease.RoutingScope == nil {
			return fmt.Errorf(
				"%w: helper returned display lease %d without routing_scope",
				ErrPersistentNatLeaseScopeProtocolIncompatible, i)
		}
		if err := validatePersistentNatRemotes(lease.PermittedRemotes); err != nil {
			return fmt.Errorf("%w: helper returned display lease %d with invalid permissions: %v",
				ErrPersistentNatLeaseScopeProtocolIncompatible, i, err)
		}
	}
	return nil
}

// #8121: idle persistent-NAT lease export/import over the helper control
// socket.
//
// All lease calls set SuppressStatus. The control socket is shared with the
// 1/s status poll, HA session sync, session installs, snapshot sync and
// forwarding sync, and CLAUDE.md is explicit that a new caller at >1/s starves
// session installs during bulk sync. These run on a slow cadence (see the
// daemon's lease ticker) and have no use for a status blob, so the request
// itself neither asks for one nor pays to carry it back. The compatibility
// fence may issue one status probe when no observed helper version is cached;
// subsequent calls use that observation.

// ExportIdleLeases returns locally-exportable persistent-NAT leases that have
// no live flows but remain inside their persistence timeout. Session sync
// cannot observe this idle population; peer-imported leases are filtered by the
// allocator so they are not echoed back.
func (m *Manager) ExportIdleLeases() ([]IdleLeaseWire, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.exportIdleLeasesLocked()
}

func (m *Manager) exportIdleLeasesLocked() ([]IdleLeaseWire, error) {
	if m.proc == nil {
		return nil, errors.New("userspace dataplane helper not running")
	}
	if err := m.ensurePersistentNatLeasePermissionProtocolLocked(); err != nil {
		return nil, err
	}
	resp, err := m.requestDetailedLocked(ControlRequest{
		Type:           "export_idle_leases",
		SuppressStatus: true,
	})
	if err != nil {
		return nil, err
	}
	if err := validateIdleLeaseScopes(resp.IdleLeases); err != nil {
		return nil, err
	}
	return resp.IdleLeases, nil
}

// ExportPersistentNatLeaseBatch pairs the lease snapshot with the durable
// sender origin/generation. Both are captured under m.mu so a clear cannot
// stamp a pre-clear lease snapshot with its post-clear generation.
func (m *Manager) ExportPersistentNatLeaseBatch() (PersistentNatLeaseBatch, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.loadPersistentNatLeaseGenerationLocked(); err != nil {
		return PersistentNatLeaseBatch{}, err
	}
	if err := m.finishPendingPersistentNatClearLocked(); err != nil {
		return PersistentNatLeaseBatch{}, err
	}
	leases, err := m.exportIdleLeasesLocked()
	if err != nil {
		return PersistentNatLeaseBatch{}, err
	}
	state := m.persistentNatLeaseGeneration
	return PersistentNatLeaseBatch{
		OriginID:   state.OriginID,
		Generation: state.Generation,
		Leases:     leases,
	}, nil
}

// ImportPersistentNatLeaseBatch applies one peer-originated set. A newer
// durable generation is a clear barrier: persist it before clearing local
// allocator state, then import the new-generation records. Older peer
// generations are rejected indefinitely; local-clear equal-generation fences
// are bounded to protect against delayed pre-clear snapshots without starving
// peers that continue advertising at an unchanged generation.
func (m *Manager) ImportPersistentNatLeaseBatch(batch PersistentNatLeaseBatch) error {
	if !validPersistentNatLeaseOrigin11486(batch.OriginID) {
		return errors.New("persistent-NAT lease batch has invalid origin identity")
	}
	for i, lease := range batch.Leases {
		if lease.RoutingScope == nil {
			return fmt.Errorf(
				"%w: imported lease %d has no routing_scope",
				ErrPersistentNatLeaseScopeProtocolIncompatible, i)
		}
		if err := validatePersistentNatRemotes(lease.PermittedRemotes); err != nil {
			return fmt.Errorf("%w: imported lease %d has invalid permissions: %v",
				ErrPersistentNatLeaseScopeProtocolIncompatible, i, err)
		}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.loadPersistentNatLeaseGenerationLocked(); err != nil {
		return err
	}
	state := clonePersistentNatLeaseGenerationState11486(m.persistentNatLeaseGeneration)
	if batch.OriginID == state.OriginID {
		return errors.New("refusing persistent-NAT lease batch from local origin")
	}
	now := m.persistentNatLeaseNowLocked()
	if m.prunePersistentNatLocalClearFencesLocked(state, now) {
		if err := m.storePersistentNatLeaseGenerationLocked(state); err != nil {
			return err
		}
	}
	if clearGeneration, cleared := state.LocalClearRemoteGenerations[batch.OriginID]; cleared &&
		batch.Generation <= clearGeneration {
		if m.persistentNatLocalClearDropLoggedAt == nil {
			m.persistentNatLocalClearDropLoggedAt = make(map[string]time.Time)
		}
		lastLogged := m.persistentNatLocalClearDropLoggedAt[batch.OriginID]
		if lastLogged.IsZero() || now.Sub(lastLogged) >= persistentNatLocalClearFenceLifetime {
			slog.Warn("persistent-NAT lease batch rejected by temporary local-clear fence; peer leases may resume after the fence expires or a newer generation arrives",
				"origin", batch.OriginID, "generation", batch.Generation,
				"clear_generation", clearGeneration, "expires_at",
				time.Unix(0, state.LocalClearRemoteGenerationEnds[batch.OriginID]).UTC(),
				"issue", "#13909")
			m.persistentNatLocalClearDropLoggedAt[batch.OriginID] = now
		}
		return nil
	}
	if generation, ok := state.RemoteGenerations[batch.OriginID]; ok && batch.Generation < generation {
		return nil
	}
	generation, known := state.RemoteGenerations[batch.OriginID]
	if !known && batch.Generation == 0 {
		state = clonePersistentNatLeaseGenerationState11486(state)
		state.RemoteGenerations[batch.OriginID] = 0
		if err := m.storePersistentNatLeaseGenerationLocked(state); err != nil {
			return err
		}
	} else if !known || batch.Generation > generation {
		state = clonePersistentNatLeaseGenerationState11486(state)
		state.RemoteGenerations[batch.OriginID] = batch.Generation
		state.PendingRemote[batch.OriginID] = true
		delete(state.LocalClearRemoteGenerations, batch.OriginID)
		delete(state.LocalClearRemoteGenerationEnds, batch.OriginID)
		if err := m.storePersistentNatLeaseGenerationLocked(state); err != nil {
			return err
		}
	}
	if err := m.finishPendingPersistentNatClearLocked(); err != nil {
		return err
	}
	if len(batch.Leases) == 0 {
		return nil
	}
	if err := m.ensurePersistentNatLeasePermissionProtocolLocked(); err != nil {
		return err
	}
	_, err := m.requestDetailedLocked(ControlRequest{
		Type:                     "import_idle_leases",
		SuppressStatus:           true,
		IdleLeases:               batch.Leases,
		ClearGenerationValidated: true,
	})
	return err
}

// prunePersistentNatLocalClearFencesLocked drops fences that have reached
// their bounded replay-protection interval or have been superseded by a newer
// durable generation. Caller holds m.mu.
func (m *Manager) prunePersistentNatLocalClearFencesLocked(state persistentNatLeaseGenerationState, now time.Time) bool {
	changed := false
	for origin, generation := range state.LocalClearRemoteGenerations {
		expiresAt := state.LocalClearRemoteGenerationEnds[origin]
		remoteGeneration := state.RemoteGenerations[origin]
		if now.UnixNano() >= expiresAt || remoteGeneration > generation {
			delete(state.LocalClearRemoteGenerations, origin)
			delete(state.LocalClearRemoteGenerationEnds, origin)
			changed = true
		}
	}
	return changed
}

// ImportIdleLeases imports leases at the local helper boundary. Cluster sync
// callers must use ImportPersistentNatLeaseBatch so a missing generation can
// never bypass the durable revocation watermark.
func (m *Manager) ImportIdleLeases(leases []IdleLeaseWire) error {
	if len(leases) == 0 {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.importIdleLeasesLocked(leases)
}

func (m *Manager) importIdleLeasesLocked(leases []IdleLeaseWire) error {
	if m.proc == nil {
		return errors.New("userspace dataplane helper not running")
	}
	if err := validateIdleLeaseScopes(leases); err != nil {
		return err
	}
	for i, lease := range leases {
		if err := validatePersistentNatRemotes(lease.PermittedRemotes); err != nil {
			return fmt.Errorf("%w: imported lease %d has invalid permissions: %v",
				ErrPersistentNatLeaseScopeProtocolIncompatible, i, err)
		}
	}
	if err := m.ensurePersistentNatLeasePermissionProtocolLocked(); err != nil {
		return err
	}
	_, err := m.requestDetailedLocked(ControlRequest{
		Type:           "import_idle_leases",
		SuppressStatus: true,
		IdleLeases:     leases,
	})
	return err
}

// ExportPersistentLeaseDisplay returns every persistent-NAT lease this node
// would HONOUR — the allocator's own reuse predicate, `active_flows > 0 ||
// expires_at_ns > now_ns` — for the SHOW table (#8615).
//
// This is the read ExportIdleLeases cannot be: that one is filtered to the IDLE
// population because it feeds the HA sync path, where carrying a live-flow count
// is forbidden. This verb feeds a display only, travels on its own record type,
// and has no import counterpart.
//
// Same SuppressStatus discipline and same slow cadence as the calls above — the
// caller is the 30s show-table refresher, not an interactive path.
func (m *Manager) ExportPersistentLeaseDisplay() ([]DisplayLeaseWire, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.proc == nil {
		return nil, errors.New("userspace dataplane helper not running")
	}
	if err := m.ensurePersistentNatLeaseScopeProtocolLocked(); err != nil {
		return nil, err
	}
	resp, err := m.requestDetailedLocked(ControlRequest{
		Type:           "export_persistent_lease_display",
		SuppressStatus: true,
	})
	rows, err := displayLeasesFromResponse(resp, err)
	if err != nil {
		return nil, err
	}
	if err := validateDisplayLeaseScopes(rows); err != nil {
		return nil, err
	}
	return rows, nil
}

// ErrPersistentLeaseDisplayUnsupported means the running helper predates #8615
// and does not implement the display verb. The caller degrades to
// ExportIdleLeases, which answers the same question for the IDLE population
// only.
//
// A distinct sentinel rather than a generic error because the two outcomes have
// different remedies AND different truth: "this helper is older, you are seeing
// the idle half" is a degraded but honest table, while a genuine failure must
// leave the previous snapshot standing rather than assert an emptiness nobody
// observed (#8607).
var ErrPersistentLeaseDisplayUnsupported = errors.New(
	"userspace helper does not support export_persistent_lease_display")

// displayLeasesFromResponse is the classification half, extracted from the
// request path for the reason sessionCountersFromResponse states: the request
// path has no test seam, and an inline choice cannot be bound by a test.
//
// An UNSUPPORTED verb must not become an empty result. Returning `nil, nil` for
// an old helper would tell the refresher "this node holds no bindings", which
// renders as "No persistent NAT bindings" — the exact false statement #8607
// exists to remove, now produced by the fix for #8615.
func displayLeasesFromResponse(resp ControlResponse, err error) ([]DisplayLeaseWire, error) {
	if err != nil {
		if isUnknownVerbError(err) {
			return nil, ErrPersistentLeaseDisplayUnsupported
		}
		return nil, err
	}
	return resp.DisplayLeases, nil
}

// ClearPersistentNATLeases revokes every lease in the authoritative helper
// allocator (#10784) and advances the durable outbound clear generation.
func (m *Manager) ClearPersistentNATLeases() (uint64, error) {
	count, _, _, err := m.ClearPersistentNATLeasesWithGeneration("", 0)
	return count, err
}

// ClearPersistentNATLeasesWithGeneration applies a local clear and, when
// supplied, records the peer's clear generation as a durable replay floor.
// The pending marker is fsynced before the helper mutation; retries complete
// that clear before any leases can be exported or imported.
func (m *Manager) ClearPersistentNATLeasesWithGeneration(peerOrigin string, peerGeneration uint64) (uint64, string, uint64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.proc == nil {
		return 0, "", 0, errors.New("userspace dataplane helper not running")
	}
	if peerOrigin != "" && (!validPersistentNatLeaseOrigin11486(peerOrigin)) {
		return 0, "", 0, errors.New("peer persistent-NAT clear has invalid origin identity")
	}
	if err := m.loadPersistentNatLeaseGenerationLocked(); err != nil {
		return 0, "", 0, err
	}
	state := clonePersistentNatLeaseGenerationState11486(m.persistentNatLeaseGeneration)
	if peerOrigin != "" && peerOrigin == state.OriginID {
		return 0, "", 0, errors.New("peer persistent-NAT clear origin matches local origin")
	}
	// A clear revokes all locally held leases. During the bounded replay
	// window, fence each known peer at its observed generation so delayed
	// same-generation batches cannot restore pre-clear state. Exempt a
	// forwarded peer clear only when it advances that peer's generation;
	// that newer generation can carry genuinely post-clear leases.
	now := m.persistentNatLeaseNowLocked()
	m.prunePersistentNatLocalClearFencesLocked(state, now)
	for origin, generation := range state.RemoteGenerations {
		if origin == peerOrigin && peerGeneration > generation {
			delete(state.LocalClearRemoteGenerations, origin)
			delete(state.LocalClearRemoteGenerationEnds, origin)
			continue
		}
		state.LocalClearRemoteGenerations[origin] = generation
		state.LocalClearRemoteGenerationEnds[origin] = now.Add(persistentNatLocalClearFenceLifetime).UnixNano()
	}
	if state.Generation == ^uint64(0) {
		return 0, "", 0, errors.New("persistent-NAT clear generation exhausted")
	}
	state.Generation++
	state.PendingLocalClear = true
	if peerOrigin != "" {
		old, seen := state.RemoteGenerations[peerOrigin]
		if !seen && len(state.RemoteGenerations) >= maxPersistentNatGenerationPeers11486 {
			return 0, "", 0, errors.New("persistent-NAT lease generation peer limit reached")
		}
		if !seen || peerGeneration > old {
			state.RemoteGenerations[peerOrigin] = peerGeneration
			state.PendingRemote[peerOrigin] = true
		}
	}
	if err := m.storePersistentNatLeaseGenerationLocked(state); err != nil {
		return 0, "", 0, err
	}
	count, err := m.clearPersistentNatLeasesLocked()
	if err != nil {
		return 0, "", 0, err
	}
	state = clonePersistentNatLeaseGenerationState11486(m.persistentNatLeaseGeneration)
	state.PendingLocalClear = false
	for origin := range state.PendingRemote {
		state.PendingRemote[origin] = false
	}
	if err := m.storePersistentNatLeaseGenerationLocked(state); err != nil {
		return count, state.OriginID, state.Generation, err
	}
	return count, state.OriginID, state.Generation, nil
}

func (m *Manager) clearPersistentNatLeaseGenerationPendingLocked(state persistentNatLeaseGenerationState) bool {
	if state.PendingLocalClear {
		return true
	}
	for _, pending := range state.PendingRemote {
		if pending {
			return true
		}
	}
	return false
}

func (m *Manager) finishPendingPersistentNatClearLocked() error {
	state := m.persistentNatLeaseGeneration
	if !m.clearPersistentNatLeaseGenerationPendingLocked(state) {
		return nil
	}
	if m.proc == nil {
		return errors.New("userspace dataplane helper not running")
	}
	if _, err := m.clearPersistentNatLeaseHelperLocked(); err != nil {
		return err
	}
	state = clonePersistentNatLeaseGenerationState11486(m.persistentNatLeaseGeneration)
	state.PendingLocalClear = false
	for origin := range state.PendingRemote {
		state.PendingRemote[origin] = false
	}
	return m.storePersistentNatLeaseGenerationLocked(state)
}

func (m *Manager) clearPersistentNatLeasesLocked() (uint64, error) {
	resp, err := m.clearPersistentNatLeaseHelperLocked()
	if err != nil {
		return 0, err
	}
	return resp.PersistentNatLeaseCount, nil
}

func (m *Manager) clearPersistentNatLeaseHelperLocked() (ControlResponse, error) {
	resp, err := m.requestDetailedLocked(ControlRequest{
		Type:           "clear_persistent_nat_leases",
		SuppressStatus: true,
	})
	if err != nil {
		return ControlResponse{}, fmt.Errorf("clear authoritative persistent NAT leases: %w", err)
	}
	return resp, nil
}
