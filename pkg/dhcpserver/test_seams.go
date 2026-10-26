package dhcpserver

import (
	"log/slog"
	"time"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/ddns"
)

// Test-only helpers for pkg/dhcpserver.Manager, following the
// pkg/dhcp/test_seams.go convention: they live in the production
// package so tests (here and in other packages) can build managers
// without shelling out to systemctl or writing under /etc/kea. Not
// for production callers.

// NewManagerForTesting builds a Manager with injectable systemctl
// seams and config file paths.
//
//   - confPath4/confPath6: where generated Kea configs are written
//     (tests pass t.TempDir() paths).
//   - runSystemctl: replaces the real `systemctl <args...>` shell-out
//     (restart/stop). Return nil for success.
//   - unitActive: replaces the `systemctl is-active <unit>` query used
//     for authoritative reconcile (#1778). This convenience seam wraps a
//     bool-only fake as always-succeeding (nil query error); tests that
//     need to exercise the #4870 fail-closed query-error path inject an
//     error-returning fake via SetUnitActiveForTesting.
func NewManagerForTesting(
	confPath4, confPath6 string,
	runSystemctl func(args ...string) error,
	unitActive func(unit string) bool,
) *Manager {
	return &Manager{
		confPath4:    confPath4,
		confPath6:    confPath6,
		runSystemctl: runSystemctl,
		unitActive:   func(unit string) (bool, error) { return unitActive(unit), nil },
		warn:         slog.Warn,
	}
}

// SetUnitActiveForTesting overrides the `systemctl is-active` seam with a
// tri-state fake so tests can exercise the #4870 fail-closed path where
// the query itself fails (timeout/exec error) rather than returning a
// definitive active/inactive answer.
func (m *Manager) SetUnitActiveForTesting(fn func(unit string) (bool, error)) {
	m.unitActive = fn
}

// SetLeaseSyncSeamsForTesting injects the #2239 lease-sync test seams: a
// fake control-socket dialer (a stub Kea server can implement the lease_cmds
// wire), per-family control-socket paths, and per-family memfile paths. Any
// zero argument leaves the production default. A manager configured through
// this seam defaults to a definitively stopped Kea unit; call
// SetUnitActiveForTesting after this method when a test needs another state.
// Used by lease_sync tests in this package and cross-package tests.
func (m *Manager) SetLeaseSyncSeamsForTesting(
	dial keaSocketDialer,
	ctrlSocket4, ctrlSocket6, leaseFile4, leaseFile6 string,
) {
	m.unitActive = func(string) (bool, error) { return false, nil }
	m.keaDial = dial
	m.ctrlSocket4 = ctrlSocket4
	m.ctrlSocket6 = ctrlSocket6
	m.leaseFile4 = leaseFile4
	m.leaseFile6 = leaseFile6
}

// SetWarnForTesting replaces the manager's warning sink (default
// slog.Warn) so tests can assert that generate-time configuration
// warnings — e.g. ambiguous Kea subnet selection (#1835 F1) — fire.
func (m *Manager) SetWarnForTesting(fn func(msg string, args ...any)) {
	m.warn = fn
}

// SetKeaOwnerLookupForTesting injects the Kea runtime-user resolver used by
// the memfile pre-seed chown (#2450). A test passes a fake that returns a
// known uid/gid (so the pre-seed chowns to it without a real _kea user) or
// ok=false (to exercise the absent-user best-effort fallback). Must be called
// before the first pre-seed (the resolution is cached behind a sync.Once).
func (m *Manager) SetKeaOwnerLookupForTesting(fn func() (uid, gid int, ok bool)) {
	m.keaOwnerLookup = fn
}

// NewDDNSManagerForTesting builds a DDNSManager with injectable state +
// lease paths, clock, and a per-Reconcile updater factory (#1387 inc-2).
// It is used by OTHER packages' tests (e.g. pkg/daemon) to drive the
// production resolve-per-Reconcile manager without real /var/lib paths.
// updater is the fixed fallback used when newUpdater is nil. It wires the
// package-local Kea-memfile lease parser into the pkg/ddns engine (#2691 P1a)
// so the manager reads the synthetic memfiles a cross-package test writes via
// DDNSLeasePaths. The DDNSManager type + the engine now live in pkg/ddns; this
// is a thin wrapper that keeps the existing seam signature unchanged.
func NewDDNSManagerForTesting(
	updater DNSUpdater,
	statePath, leasePath4, leasePath6, nodeID string,
	now func() time.Time,
	newUpdater func(c *config.DHCPDynamicDNSConfig) (DNSUpdater, error),
) *DDNSManager {
	return ddns.NewManagerForTesting(
		keaLeaseParser, updater, statePath, leasePath4, leasePath6, nodeID, now, newUpdater,
	)
}

// ApplyFailedForTesting reports whether the most recently COMPLETED apply
// attempt failed (#6535). Read-only: unlike ClaimApplyRetry it does not consume
// the retry window, so a test can wait for the async worker to record a failure
// without disarming the converger it is about to exercise.
func (m *Manager) ApplyFailedForTesting() bool {
	m.retryMu.Lock()
	defer m.retryMu.Unlock()
	return m.applyFailed
}
