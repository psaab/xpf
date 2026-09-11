package configstore

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/psaab/xpf/pkg/config"
)

// #9530: during a control-link partition both nodes self-elect RG0 primary and
// both stores are writable. A commit made on the node that later yields is then
// replaced by the winner's older config on heal: SyncApply had no notion of a
// commit the peer never held, so it returned nil and the commit survived only in
// the loser's rollback history.
//
// A node cannot tell that from its own history alone. "Active differs from the
// last sync" is also true after every routine RG0 failover in which the old
// primary committed, and "a push was written" proves nothing in the heal window
// itself, because the peer is still primary there and rejects it. So the store
// keeps a mark instead:
//   - a local promotion of the active config made while the peer is
//     unreachable marks the new active as UNSHARED (persisted, so a restart
//     before the heal does not lose it). The mark is sticky: a later local
//     commit carries it to the new active;
//   - the daemon clears it by pushing exactly that content while it is RG0
//     primary and the peer reads secondary (NoteActiveSharedWithPeer). In the
//     dual-active heal window the peer still reads primary, so the mark stays;
//   - a peer sync that replaces a still-unshared active records a
//     SyncDivergence and logs it at Error. The discarded config is in rollback
//     history, and ConfigSyncDivergence names its slot.

// unsharedRecord marks the active config as holding a local commit the cluster
// peer has not been shown to hold.
type unsharedRecord struct {
	Digest string    `json:"digest"`
	At     time.Time `json:"at"`
}

// SyncDivergence describes a peer config sync that replaced an active config
// holding a local commit the peer never held (#9530).
type SyncDivergence struct {
	// DiscardedDigest identifies the replaced config, now in rollback history.
	DiscardedDigest string
	// DiscardedAt is when the unshared local commit was made.
	DiscardedAt time.Time
	// AdoptedDigest identifies the peer's config that replaced it.
	AdoptedDigest string
	// At is when the sync replaced it.
	At time.Time
}

func (db *DB) unsharedPath() string {
	return filepath.Join(db.dir, "unshared.json")
}

// WriteUnshared persists the unshared-commit mark durably, through the same seam
// as the commit-confirmed state.
func (db *DB) WriteUnshared(rec *unsharedRecord) error {
	data, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	if err := rbWriteFileDurable(db.unsharedPath(), data, 0600); err != nil {
		return fmt.Errorf("persist unshared-commit mark: %w", err)
	}
	return nil
}

// ReadUnshared loads the unshared-commit mark, or (nil, nil) when none is
// persisted. A record without a digest names nothing and is rejected.
func (db *DB) ReadUnshared() (*unsharedRecord, error) {
	// Bounded, and refusing a non-regular file, like every other authoritative
	// read in this package (#8597).
	data, err := ReadBoundedFile(db.unsharedPath(), MaxConfigSize)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read unshared-commit mark: %w", err)
	}
	var rec unsharedRecord
	if err := json.Unmarshal(data, &rec); err != nil {
		return nil, fmt.Errorf("parse unshared-commit mark: %w", err)
	}
	if rec.Digest == "" {
		return nil, errors.New("unshared-commit mark has no digest")
	}
	return &rec, nil
}

// DeleteUnshared removes the mark and syncs the directory, so a crash cannot
// replay a mark that was already cleared.
func (db *DB) DeleteUnshared() error {
	if err := rbRemove(db.unsharedPath()); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("delete unshared-commit mark: %w", err)
	}
	if err := rbSyncDir(filepath.Dir(db.unsharedPath())); err != nil {
		return fmt.Errorf("sync dir after delete unshared-commit mark: %w", err)
	}
	return nil
}

func activeTreeDigest(tree *config.ConfigTree) string {
	if tree == nil {
		return ""
	}
	return configTextDigest(tree.Format())
}

// SetPeerReachableFn wires the cluster peer's reachability (#9530). The store
// calls it under s.mu on every local promotion of the active config, so it must
// not call back into the store. A standalone store leaves it nil and never marks
// anything.
func (s *Store) SetPeerReachableFn(fn func() bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.peerReachableFn = fn
}

// noteLocalActivePromotionLocked runs after every LOCAL promotion of the active
// config: commit, commit confirmed, and the commit-confirmed timeout rollback.
// Callers hold s.mu.
func (s *Store) noteLocalActivePromotionLocked() {
	// The active config changed after a divergence alarm, so the alarm no longer
	// describes what this node runs.
	s.divergence = nil
	if s.peerReachableFn == nil {
		return
	}
	// The mark is sticky: a commit on top of unshared content still carries
	// content the peer has not been shown to hold, even once the peer is back.
	if s.unshared == nil && s.peerReachableFn() {
		return
	}
	s.setUnsharedLocked(&unsharedRecord{Digest: activeTreeDigest(s.active), At: time.Now().UTC()})
}

func (s *Store) setUnsharedLocked(rec *unsharedRecord) {
	s.unshared = rec
	if s.db == nil {
		return
	}
	if err := s.db.WriteUnshared(rec); err != nil {
		slog.Warn("configstore: could not persist the unshared-commit mark; it holds for this process only",
			"err", err, "issue", "#9530")
	}
}

func (s *Store) clearUnsharedLocked() {
	if s.unshared == nil {
		return
	}
	s.unshared = nil
	if s.db == nil {
		return
	}
	if err := s.db.DeleteUnshared(); err != nil {
		slog.Warn("configstore: could not remove the unshared-commit mark", "err", err, "issue", "#9530")
	}
}

// NoteActiveSharedWithPeer records that pushedText reached a peer able to apply
// it (#9530). The caller pushed it as RG0 primary while the peer read secondary.
// The mark clears only when pushedText is exactly the marked content.
func (s *Store) NoteActiveSharedWithPeer(pushedText string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.unshared != nil && configTextDigest(pushedText) == s.unshared.Digest {
		s.clearUnsharedLocked()
	}
}

// classifySyncLocked decides, before a peer sync replaces the active config,
// whether the replacement discards a local commit the peer never held. Callers
// hold s.mu.
func (s *Store) classifySyncLocked(incoming *config.ConfigTree) *SyncDivergence {
	if s.unshared == nil {
		return nil
	}
	in := activeTreeDigest(incoming)
	switch {
	case in == s.unshared.Digest:
		// The peer holds exactly the marked content, so it was shared after all.
		s.clearUnsharedLocked()
		return nil
	case activeTreeDigest(s.active) != s.unshared.Digest:
		// The mark describes content this node no longer runs, for example after
		// a boot-time commit-confirmed revert. It names nothing the sync discards.
		s.clearUnsharedLocked()
		return nil
	}
	return &SyncDivergence{
		DiscardedDigest: s.unshared.Digest,
		DiscardedAt:     s.unshared.At,
		AdoptedDigest:   in,
		At:              time.Now().UTC(),
	}
}

// recordSyncDivergenceLocked runs after a peer sync promoted its config. d is
// classifySyncLocked's result for that sync. Callers hold s.mu.
func (s *Store) recordSyncDivergenceLocked(d *SyncDivergence) {
	if d == nil {
		// A different config arriving after an alarm means the operator acted on
		// the winner; the same config re-pushed keeps the alarm.
		if s.divergence != nil && s.divergence.AdoptedDigest != activeTreeDigest(s.active) {
			s.divergence = nil
		}
		return
	}
	s.clearUnsharedLocked()
	s.divergence = d
	slog.Error("configstore: a peer config sync replaced a local commit the peer never held; "+
		"the discarded config is rollback 1",
		"discarded_digest", d.DiscardedDigest, "committed_at", d.DiscardedAt,
		"adopted_digest", d.AdoptedDigest, "issue", "#9530")
}

// ConfigSyncDivergence reports the last divergence a peer sync caused (#9530),
// with the rollback slot that holds the discarded config now. The slot moves as
// later configs push history, and is 0 once the config has aged out of it.
func (s *Store) ConfigSyncDivergence() (SyncDivergence, int, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.divergence == nil {
		return SyncDivergence{}, 0, false
	}
	slot := 0
	for i, e := range s.history.List() {
		if e != nil && e.Config != nil && activeTreeDigest(e.Config) == s.divergence.DiscardedDigest {
			slot = i + 1
			break
		}
	}
	return *s.divergence, slot, true
}

// ConfigSyncDivergenceAlarm renders the last divergence as one alarm line for
// `show system alarms`, or "" when there is none (#9530).
func (s *Store) ConfigSyncDivergenceAlarm() string {
	div, slot, ok := s.ConfigSyncDivergence()
	if !ok {
		return ""
	}
	where := fmt.Sprintf("rollback %d", slot)
	if slot == 0 {
		where = "no longer in rollback history"
	}
	return fmt.Sprintf("config sync replaced a local commit the cluster peer never held "+
		"(committed %s, replaced %s); the discarded config is %s",
		div.DiscardedAt.Format(time.RFC3339), div.At.Format(time.RFC3339), where)
}

// loadUnsharedMarkLocked restores the mark at boot. Callers hold s.mu.
func (s *Store) loadUnsharedMarkLocked() {
	if s.db == nil {
		return
	}
	rec, err := s.db.ReadUnshared()
	if err != nil {
		slog.Warn("configstore: ignoring an unreadable unshared-commit mark", "err", err, "issue", "#9530")
		return
	}
	s.unshared = rec
}
