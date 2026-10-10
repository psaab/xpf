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
//   - recovery records the abandoned and rollback config hashes in the marker; if
//     marker publication fails after the rollback write, confirm.json is retained
//     and the next Load reconstructs debt from that recovery record before resolving it;
//   - Load re-arms debt from a durable marker and suppresses it when a later active
//     config no longer matches the marker's rollback hash;
//   - the daemon clears marker + flag only when teardown converges; a DEGRADED
//     teardown keeps both for retry.
//
// The marker is a single file, not a new confirm.json field: the record format
// is a downgrade-sensitive safety envelope (unknown fields refused), which
// remains unchanged by this separate teardown state.

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
)

type firstCommitTeardownMarker struct {
	Issue        string `json:"issue"`
	Action       string `json:"action"`
	Generation   string `json:"generation,omitempty"`
	RollbackHash string `json:"rollback_hash,omitempty"`
}

// firstCommitTeardownMarkerBase is the .configdb filename recording that an
// expired FIRST-window durable rollback still owes its daemon-side takeover
// teardown (#12155). Presence signals debt; the JSON content binds the
// abandoned and rollback config hashes when available.
const firstCommitTeardownMarkerBase = "first-commit-teardown.json"

// firstCommitTeardownMarkerText is the legacy/minimal marker content used by
// tests and old-format fixtures. Current writes include config-generation hashes.
const firstCommitTeardownMarkerText = "{\"issue\":\"#12155\",\"action\":\"teardown-first-commit-takeover\"}\n"

// firstCommitTeardownMarkerPath returns the marker path for the DB dir.
func firstCommitTeardownMarkerPath(dbDir string) string {
	return filepath.Join(dbDir, firstCommitTeardownMarkerBase)
}

// loadFirstCommitTeardownLocked re-arms teardown debt from disk. Call at the
// top of Load (under s.mu) before recovery can run.
func (s *Store) loadFirstCommitTeardownLocked() {
	s.firstCommitTeardownOwed = false
	s.firstCommitTeardownGeneration = ""
	s.firstCommitTeardownRollbackHash = ""
	s.firstCommitTeardownMarkerDurable = false
	s.firstCommitTeardownRollbackDurable = false
	if s.db == nil {
		return
	}
	path := firstCommitTeardownMarkerPath(s.db.dir)
	data, err := os.ReadFile(path)
	if err == nil {
		s.firstCommitTeardownOwed = true
		s.firstCommitTeardownMarkerDurable = true
		s.firstCommitTeardownRollbackDurable = true
		var marker firstCommitTeardownMarker
		if json.Unmarshal(data, &marker) == nil {
			s.firstCommitTeardownGeneration = marker.Generation
			s.firstCommitTeardownRollbackHash = marker.RollbackHash
		}
		return
	}
	if os.IsNotExist(err) {
		return
	}
	// An observation failure must not silently drop teardown debt.
	s.firstCommitTeardownOwed = true
	s.firstCommitTeardownRollbackDurable = true
	slog.Warn("could not check FIRST-rollback teardown debt marker; teardown may be owed but unobserved",
		"path", path, "err", err, "issue", "#12155")
}

// discardSupersededFirstCommitTeardownLocked prevents an old rollback marker
// from authorizing teardown after a later config became active. The persisted
// committed bit is authoritative: a replacement can be byte-identical to the
// rollback target, while a content mismatch alone is not proof of a commit.
// A failed marker unlink is harmless; each later Load repeats this decision.
func (s *Store) discardSupersededFirstCommitTeardownLocked(activeHash string) {
	if !s.firstCommitTeardownOwed {
		return
	}
	if !s.everCommitted {
		if s.firstCommitTeardownRollbackHash != "" &&
			activeHash != s.firstCommitTeardownRollbackHash {
			slog.Warn("active config differs from the rollback hash while FIRST teardown is still uncommitted; retaining fail-closed debt",
				"issue", "#12155")
		}
		return
	}
	if s.db != nil && s.firstCommitTeardownMarkerDurable {
		path := firstCommitTeardownMarkerPath(s.db.dir)
		if err := rbRemove(path); err == nil || os.IsNotExist(err) {
			if syncErr := rbSyncDir(filepath.Dir(path)); syncErr != nil {
				slog.Warn("could not durably remove superseded FIRST-rollback debt marker",
					"path", path, "err", syncErr, "issue", "#12155")
			}
		} else {
			slog.Warn("could not remove superseded FIRST-rollback debt marker",
				"path", path, "err", err, "issue", "#12155")
		}
	}
	s.firstCommitTeardownOwed = false
	s.firstCommitTeardownGeneration = ""
	s.firstCommitTeardownRollbackHash = ""
	s.firstCommitTeardownMarkerDurable = false
	s.firstCommitTeardownRollbackDurable = false
}

// noteFirstCommitTeardownLocked records teardown debt for an expired FIRST
// rollback whose active write already landed. The durable marker binds the
// abandoned and rollback config-content hashes; caller holds s.mu.
func (s *Store) noteFirstCommitTeardownLocked() error {
	s.firstCommitTeardownOwed = true
	s.firstCommitTeardownRollbackDurable = true
	if s.db == nil || s.firstCommitTeardownMarkerDurable {
		return nil
	}
	data, err := json.Marshal(firstCommitTeardownMarker{
		Issue: "#12155", Action: "teardown-first-commit-takeover",
		Generation:   s.firstCommitTeardownGeneration,
		RollbackHash: s.firstCommitTeardownRollbackHash,
	})
	if err != nil {
		return fmt.Errorf("encode FIRST-rollback teardown debt: %w", err)
	}
	data = append(data, '\n')
	if err := rbWriteFileDurable(firstCommitTeardownMarkerPath(s.db.dir), data, 0600); err != nil {
		return fmt.Errorf("persist FIRST-rollback teardown debt: %w", err)
	}
	s.firstCommitTeardownMarkerDurable = true
	return nil
}

// FirstCommitTeardownGeneration reports the abandoned config-content hash used
// to validate its durable bootstrap lifeline snapshot.
func (s *Store) FirstCommitTeardownGeneration() string {
	if s == nil {
		return ""
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.firstCommitTeardownGeneration
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
	s.firstCommitTeardownGeneration = ""
	s.firstCommitTeardownRollbackHash = ""
	s.firstCommitTeardownMarkerDurable = false
	s.firstCommitTeardownRollbackDurable = false
	return nil
}
