package configstore

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// FirstCommitHostAuthCloseout records the first-commit timeout rollback whose
// host-authorization retirement may have been interrupted by a process crash.
// The config store owns the durable record because its promotion is the event
// that creates the boot-time retirement obligation.
type FirstCommitHostAuthCloseout struct {
	Generation uint64 `json:"generation"`
}

func (db *DB) firstCommitHostAuthCloseoutPath() string {
	return filepath.Join(db.dir, "first-commit-hostauth-closeout.json")
}

// WriteFirstCommitHostAuthCloseout persists the retirement obligation before
// the rollback promotion. A crash after the active config becomes empty can
// therefore replay host-auth cleanup on the next bootstrap boot.
func (db *DB) WriteFirstCommitHostAuthCloseout(generation uint64) error {
	if generation == 0 {
		return errors.New("first-commit host-auth closeout generation must be nonzero")
	}
	data, err := json.Marshal(FirstCommitHostAuthCloseout{Generation: generation})
	if err != nil {
		return fmt.Errorf("marshal first-commit host-auth closeout: %w", err)
	}
	if err := rbWriteFileDurable(db.firstCommitHostAuthCloseoutPath(), data, 0o600); err != nil {
		return fmt.Errorf("persist first-commit host-auth closeout: %w", err)
	}
	return nil
}

// ReadFirstCommitHostAuthCloseout returns the outstanding retirement
// obligation, or nil when there is none. Corrupt/degenerate records fail
// visibly so startup never silently treats an unreadable obligation as done.
func (db *DB) ReadFirstCommitHostAuthCloseout() (*FirstCommitHostAuthCloseout, error) {
	data, err := rbReadBoundedFile(db.firstCommitHostAuthCloseoutPath(), 1024)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("read first-commit host-auth closeout: %w", err)
	}
	var record FirstCommitHostAuthCloseout
	if err := json.Unmarshal(data, &record); err != nil {
		return nil, fmt.Errorf("decode first-commit host-auth closeout: %w", err)
	}
	if record.Generation == 0 {
		return nil, errors.New("first-commit host-auth closeout has zero generation")
	}
	return &record, nil
}

// DeleteFirstCommitHostAuthCloseout durably discharges the retirement
// obligation. An absent record still reaches the directory sync so a retry
// after an unlink-before-fsync failure cannot report false completion.
func (db *DB) DeleteFirstCommitHostAuthCloseout() error {
	path := db.firstCommitHostAuthCloseoutPath()
	if err := rbRemove(path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("delete first-commit host-auth closeout: %w", err)
	}
	if err := rbSyncDir(filepath.Dir(path)); err != nil {
		return fmt.Errorf("sync dir after deleting first-commit host-auth closeout: %w", err)
	}
	return nil
}

// Store methods below bind the durable record to the current first-commit
// rollback generation. The store read lock is held through the filesystem
// operation so a concurrent confirmation/re-arm cannot swap the obligation.

// BeginFirstCommitHostAuthCloseout writes the crash-recovery obligation only
// if gen still names the pending first-commit rollback. It returns false for a
// stale/superseded callback, true when the durable obligation is written.
func (s *Store) BeginFirstCommitHostAuthCloseout(gen uint64) (bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if gen != s.confirmGen || s.confirmPrevTree == nil || !s.confirmPrevFirst {
		return false, nil
	}
	if s.db == nil {
		return false, errors.New("config DB unavailable for first-commit host-auth closeout")
	}
	if err := s.db.WriteFirstCommitHostAuthCloseout(gen); err != nil {
		return false, err
	}
	return true, nil
}

// PendingFirstCommitHostAuthCloseout reads the durable boot-replay obligation.
func (s *Store) PendingFirstCommitHostAuthCloseout() (*FirstCommitHostAuthCloseout, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.db == nil {
		return nil, errors.New("config DB unavailable for first-commit host-auth closeout")
	}
	return s.db.ReadFirstCommitHostAuthCloseout()
}

// CompleteFirstCommitHostAuthCloseout discharges the obligation only if it
// still names gen. A newer rollback's record must never be cleared by an older
// closeout finishing late.
func (s *Store) CompleteFirstCommitHostAuthCloseout(gen uint64) error {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.db == nil {
		return errors.New("config DB unavailable for first-commit host-auth closeout")
	}
	record, err := s.db.ReadFirstCommitHostAuthCloseout()
	if err != nil || record == nil || record.Generation != gen {
		return err
	}
	return s.db.DeleteFirstCommitHostAuthCloseout()
}

// ClearSupersededFirstCommitHostAuthCloseout drops a prior rollback's
// obligation after a newer durable active config has superseded it and the
// ordinary startup apply will reconcile that config.
func (s *Store) ClearSupersededFirstCommitHostAuthCloseout() error {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.db == nil {
		return errors.New("config DB unavailable for first-commit host-auth closeout")
	}
	return s.db.DeleteFirstCommitHostAuthCloseout()
}
