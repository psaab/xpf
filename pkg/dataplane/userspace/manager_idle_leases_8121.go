package userspace

import (
	"errors"
	"fmt"
)

// ErrPersistentNatLeaseScopeProtocolIncompatible means the helper has not
// proved that it understands the v25 persistent-lease routing_scope field.
// Lease export/import are live control verbs, so unlike config compilation
// these paths fail closed when status is unavailable or unobserved.
var ErrPersistentNatLeaseScopeProtocolIncompatible = errors.New(
	"userspace persistent NAT lease scope protocol incompatible")

// ensurePersistentNatLeaseScopeProtocolLocked is the live-verb compatibility
// fence for every lease control request. A cached status is usable only after
// it was actually observed from the running helper; a zero-value or failed
// probe is not evidence that an old helper is safe to receive scoped JSON.
func (m *Manager) ensurePersistentNatLeaseScopeProtocolLocked() error {
	if m.helperStatusObserved &&
		m.lastStatus.ConfigSnapshotProtocolVersion >= MinProtocolPersistentNatLeaseScope {
		return nil
	}

	var status ProcessStatus
	if err := m.requestLocked(ControlRequest{Type: "status"}, &status); err != nil {
		return fmt.Errorf("%w: could not verify helper protocol before lease request: %v",
			ErrPersistentNatLeaseScopeProtocolIncompatible, err)
	}
	// requestLocked leaves status at its zero value when a test hook or a
	// malformed response does not provide the status object. Record that
	// observation, then reject it below rather than treating zero as domain 0.
	m.recordHelperStatusLocked(&status)
	if status.ConfigSnapshotProtocolVersion < MinProtocolPersistentNatLeaseScope {
		return fmt.Errorf(
			"%w: helper protocol version %d is below required %d for scoped persistent-NAT leases",
			ErrPersistentNatLeaseScopeProtocolIncompatible,
			status.ConfigSnapshotProtocolVersion,
			MinProtocolPersistentNatLeaseScope,
		)
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

// ExportIdleLeases returns every persistent-NAT lease this node holds that has
// NO live flows but is still inside its persistence timeout — the population
// session sync cannot observe, because a lease is learned from a session.
func (m *Manager) ExportIdleLeases() ([]IdleLeaseWire, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.proc == nil {
		return nil, errors.New("userspace dataplane helper not running")
	}
	if err := m.ensurePersistentNatLeaseScopeProtocolLocked(); err != nil {
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

// ImportIdleLeases installs a peer's idle leases. A nil/empty batch is a no-op
// rather than a round trip: on a healthy pair most pushes carry nothing, and
// spending a socket turn to say so is the contention this file's header is
// about.
func (m *Manager) ImportIdleLeases(leases []IdleLeaseWire) error {
	if len(leases) == 0 {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.proc == nil {
		return errors.New("userspace dataplane helper not running")
	}
	if err := validateIdleLeaseScopes(leases); err != nil {
		return err
	}
	if err := m.ensurePersistentNatLeaseScopeProtocolLocked(); err != nil {
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
