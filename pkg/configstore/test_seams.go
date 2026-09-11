package configstore

// Test-only helpers for configstore.Store. Lives in the production
// package so tests (here and in dependent packages) can inject
// persistence failures without internal-export tricks. Not for
// production callers. Mirrors the pkg/dhcp/test_seams.go convention.

import (
	"time"

	"github.com/psaab/xpf/pkg/config"
)

// SetWriteActiveForTesting overrides active-config persistence
// (#1799). fn(tree) replaces db.WriteActive on every persist path
// (Commit, CommitWithDescription, CommitConfirmed, SyncApply,
// performAutoRollback, Save, and the degraded-persist retry loop).
// Pass nil to restore the real DB write. Callers must not use this
// from production code paths.
func (s *Store) SetWriteActiveForTesting(fn func(*config.ConfigTree) error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.writeActiveFn = fn
}

// SetWriteActiveMarkerForTesting overrides the marker-aware active-config
// persistence path (#1922 step-0). fn(tree, committed) replaces
// db.WriteActiveMarker so tests can observe the committed bit the Item 1b
// first-commit rollback writes. Pass nil to restore the real DB write. Not
// for production callers.
func (s *Store) SetWriteActiveMarkerForTesting(fn func(*config.ConfigTree, bool) error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.writeActiveMarkerFn = fn
}

// ConfirmGenForTesting returns the current commit-confirmed generation
// token (#1922 Item 1a). Tests use it to call PromoteRollback /
// executeConfirmedRollback with the generation that armed the pending
// confirm timer, since the confirm timer's closure captures the gen
// privately. Not for production callers.
func (s *Store) ConfirmGenForTesting() uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.confirmGen
}

// InvokeRollbackTimerForTesting drives the EXACT dispatch logic the
// commit-confirmed auto-rollback timer runs on expiry (#1922 Item 1a):
// read the registered rollbackExecutor under s.mu, then invoke it (with
// the given generation) WITHOUT holding s.mu, falling back to
// performAutoRollback when no executor is registered. Tests use it to
// exercise the real timer branch deterministically without waiting for a
// wall-clock minute. Not for production callers.
func (s *Store) InvokeRollbackTimerForTesting(gen uint64) {
	s.fireConfirmTimer(gen)
}

// CancelConfirmTimerForTesting stops a pending commit-confirmed timer without
// resolving or persisting anything, so a test that loads a SECOND store from the
// same files (to model a restart) does not leave the first store's timer running
// (#9615). Not for production callers.
func (s *Store) CancelConfirmTimerForTesting() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cancelPendingConfirmTimerLocked()
}

// SetPersistRetryBackoffForTesting overrides the degraded-persist
// retry loop's initial/max backoff (#1799) so tests can drive the
// loop deterministically with tiny intervals. Must be called BEFORE
// the failure that spawns the retry goroutine. Zero values restore
// the production defaults (1s initial, doubling to a 60s cap).
func (s *Store) SetPersistRetryBackoffForTesting(initial, max time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.persistRetryInitialBackoff = initial
	s.persistRetryMaxBackoff = max
}
