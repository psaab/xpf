package configstore

// Durable FIRST-rollback teardown debt (#12155).
//
// A FIRST commit-confirmed window that expires while xpfd is down rolls back
// durably in recoverPendingConfirmLocked (committed=0, confirm.json removed)
// but — unlike the live-timer path through executeConfirmedRollback →
// enterBootstrapMode — never tears down the abandoned commit's takeover
// artifacts (10-xpf-*.network, the FRR managed section). The box then boots
// bootstrap class with apply suppressed, so the sweeper never runs and the
// abandoned files + FRR section survive.
//
// The daemon teardown runs in a boot phase AFTER Store.Load (the FRR manager
// does not exist until manager-init), and xpfd can exit between Load and the
// phase. An in-memory flag alone would lose the cleanup. The debt is therefore
// a durable marker file under .configdb, written BEFORE confirm.json is
// removed and deleted only after the daemon teardown converges:
//
//   - recovery sets the in-memory flag + writes the marker on the expired
//     FirstCommit branch; a marker-write failure retains confirm.json +
//     confirmResolvePendingPersist so the next boot re-drives the rollback;
//   - Load re-arms the in-memory flag from the marker file at the top, so a
//     crash between Load and the teardown phase retries the teardown on the
//     next boot;
//   - the daemon's boot teardown clears marker + flag only when the teardown
//     converges; a DEGRADED teardown keeps both for retry.
//
// The marker is a single file, not a new confirm.json field: the record format
// is a downgrade-sensitive safety envelope (unknown fields refused), which
// remains unchanged by this separate teardown state.

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
)

// firstCommitTeardownMarkerBase is the .configdb filename recording that an
// expired FIRST-window durable rollback still owes its daemon-side takeover
// teardown (#12155). Content is a one-line human-readable marker; presence is
// the signal, not the bytes.
const firstCommitTeardownMarkerBase = "first-commit-teardown.json"

// firstCommitTeardownMarkerText is the marker content. It carries the issue
// and the owed action so an operator inspecting .configdb can tell what the
// debt is without reading code.
const firstCommitTeardownMarkerText = "{\"issue\":\"#12155\",\"action\":\"teardown-first-commit-takeover\"}\n"

// firstCommitTeardownMarkerPath returns the marker path for the DB dir.
func firstCommitTeardownMarkerPath(dbDir string) string {
	return filepath.Join(dbDir, firstCommitTeardownMarkerBase)
}

// loadFirstCommitTeardownLocked re-arms the teardown debt from disk. Call at
// the top of Load (under s.mu) before any recovery can run, so a marker left
// by a previous boot's rollback — or by a crash between this boot's Load and
// the daemon teardown phase — still drives teardown. It never clears: only
// ClearFirstCommitTeardown (after converged teardown) clears.
func (s *Store) loadFirstCommitTeardownLocked() {
	s.firstCommitTeardownOwed = false
	s.firstCommitTeardownMarkerDurable = false
	s.firstCommitTeardownRollbackDurable = false
	if s.db == nil {
		return
	}
	path := firstCommitTeardownMarkerPath(s.db.dir)
	if _, err := os.Lstat(path); err == nil {
		s.firstCommitTeardownOwed = true
		s.firstCommitTeardownMarkerDurable = true
		s.firstCommitTeardownRollbackDurable = true
		return
	} else if !os.IsNotExist(err) {
		// An observation failure must not silently drop teardown debt: retain
		// it in memory and let the eventual durable clear retry the directory
		// operation. The next boot re-observes; the marker itself is untouched.
		s.firstCommitTeardownOwed = true
		s.firstCommitTeardownRollbackDurable = true
		slog.Warn("could not check FIRST-rollback teardown debt marker; teardown may be owed but unobserved",
			"path", path, "err", err, "issue", "#12155")
	}
}

// noteFirstCommitTeardownLocked records teardown debt for an expired FIRST
// rollback whose active write already landed. It sets the in-memory flag AND
// writes the durable marker; the caller must retain confirm.json +
// confirmResolvePendingPersist on error so the next boot re-drives the
// rollback instead of booting committed=0 with the debt lost. Caller holds s.mu.
func (s *Store) noteFirstCommitTeardownLocked() error {
	s.firstCommitTeardownOwed = true
	s.firstCommitTeardownRollbackDurable = true
	if s.db == nil || s.firstCommitTeardownMarkerDurable {
		return nil
	}
	if err := rbWriteFileDurable(firstCommitTeardownMarkerPath(s.db.dir),
		[]byte(firstCommitTeardownMarkerText), 0600); err != nil {
		return fmt.Errorf("persist FIRST-rollback teardown debt: %w", err)
	}
	s.firstCommitTeardownMarkerDurable = true
	return nil
}

// deferFirstCommitTeardownMarkerLocked keeps confirm.json as the recovery
// source and schedules the existing persistence retry loop to retry marker
// publication. Caller holds s.mu.
func (s *Store) deferFirstCommitTeardownMarkerLocked(err error) {
	s.confirmResolvePendingPersist = true
	s.persistDegraded = true
	s.journalLog(&JournalEntry{
		Action:    "persist_error",
		Detail:    fmt.Sprintf("persist FIRST-rollback teardown debt: %v", err),
		Principal: "system:configstore",
	})
	slog.Error("failed to persist FIRST-rollback teardown debt; retaining confirm.json for retry",
		"err", err, "issue", "#12155")
	s.ensurePersistRetryLoopLocked()
}

// FirstCommitTeardownOwed reports whether this boot must remain fail-closed
// and perform the daemon-side takeover teardown for an expired FIRST window
// (#12155). It is set as recovery starts, including while active rollback
// persistence is pending, or re-armed from a prior boot's durable marker.
func (s *Store) FirstCommitTeardownOwed() bool {
	if s == nil {
		return false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.firstCommitTeardownOwed
}

// ClearFirstCommitTeardown drops teardown debt only after daemon cleanup
// converged and the rollback active write is durable (#12155). It removes the
// marker (unlink + dir fsync, the #4864 durable-transition shape) and clears
// the in-memory flag. On failure, debt and its available recovery record remain.
func (s *Store) ClearFirstCommitTeardown() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.firstCommitTeardownOwed {
		return nil
	}
	if !s.firstCommitTeardownRollbackDurable {
		return fmt.Errorf("cannot clear FIRST-rollback teardown debt before rollback persistence is durable")
	}
	if s.db != nil {
		path := firstCommitTeardownMarkerPath(s.db.dir)
		if err := rbRemove(path); err != nil {
			if !os.IsNotExist(err) {
				return fmt.Errorf("remove FIRST-rollback teardown debt: %w", err)
			}
		}
		if err := rbSyncDir(filepath.Dir(path)); err != nil {
			return fmt.Errorf("sync dir after remove FIRST-rollback teardown debt: %w", err)
		}
		if !s.firstCommitTeardownMarkerDurable {
			// The marker write failed earlier, so recovery intentionally kept
			// confirm.json. Teardown has now succeeded; resolve that retained
			// record through the ordinary tombstone/deletion path. A failed
			// removal remains the store's normal confirm-removal retry debt.
			s.resolveConfirmRemovalLocked("first_commit_teardown_complete")
		}
	}
	s.firstCommitTeardownOwed = false
	s.firstCommitTeardownMarkerDurable = false
	s.firstCommitTeardownRollbackDurable = false
	return nil
}
