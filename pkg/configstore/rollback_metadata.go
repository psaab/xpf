package configstore

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

// rollbackMetadataFile stores the non-config attributes of the canonical text
// rollback slots. The slot bytes remain untouched, so the journal's config
// hash continues to be the sha256 of ConfigTree.Format(). Hash plus the
// rewritten file's device/inode/mtime bind each metadata record to the exact
// slot generation it describes: hash catches changed bytes, while identity
// catches an atomic rewrite of identical bytes before the sidecar rename.
//
// Generation (#10723 F2) binds the slot set to one save and the active file
// generation it follows. Every entry from a save carries the same generation.
// The active config hash plus its durable device/inode/mtime catch a crash after
// active.json replacement but before history rewriting began; per-slot identity,
// content hash, and generation tags catch a crash or failed write during the
// rewrite. A mismatch in one slot rejects that slot; matching later slots remain
// independently verifiable. Zero is legacy (pre-#10723 sidecar without these
// fields): generation and active-generation checks are skipped.
type rollbackMetadataFile struct {
	Version       int                         `json:"version"`
	Generation    uint64                      `json:"generation,omitempty"`
	ActiveHash    string                      `json:"active_hash,omitempty"`
	ActiveDevice  uint64                      `json:"active_device,omitempty"`
	ActiveInode   uint64                      `json:"active_inode,omitempty"`
	ActiveModTime time.Time                   `json:"active_mod_time,omitempty"`
	Entries       []rollbackSlotMetadataEntry `json:"entries"`
}

type rollbackSlotMetadataEntry struct {
	Hash       string    `json:"hash"`
	Device     uint64    `json:"device"`
	Inode      uint64    `json:"inode"`
	ModTime    time.Time `json:"mod_time"`
	Timestamp  time.Time `json:"timestamp"`
	Comment    string    `json:"comment,omitempty"`
	Generation uint64    `json:"generation,omitempty"`
}

const (
	rollbackMetadataFilename = "rollback-meta.json"
	rollbackMetadataVersion  = 1
)

func (s *Store) rollbackMetadataPath() string {
	if s.db != nil {
		return filepath.Join(s.db.dir, rollbackMetadataFilename)
	}
	return filepath.Join(filepath.Dir(s.filePath), ".configdb", rollbackMetadataFilename)
}

func rollbackSlotHash(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

type rollbackSlotIdentity struct {
	Device  uint64
	Inode   uint64
	ModTime time.Time
}

func rollbackSlotIdentityForPath(path string) (rollbackSlotIdentity, bool) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() {
		return rollbackSlotIdentity{}, false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return rollbackSlotIdentity{}, false
	}
	return rollbackSlotIdentity{
		Device:  uint64(stat.Dev),
		Inode:   uint64(stat.Ino),
		ModTime: info.ModTime(),
	}, true
}

func (s *Store) writeRollbackMetadata(entries []rollbackSlotMetadataEntry) error {
	generation := uint64(0)
	for _, entry := range entries {
		if entry.Generation > generation {
			generation = entry.Generation
		}
	}
	return s.writeRollbackMetadataGeneration(generation, entries)
}

func (s *Store) writeRollbackMetadataGeneration(generation uint64, entries []rollbackSlotMetadataEntry) error {
	path := s.rollbackMetadataPath()
	activeHash, activeIdentity := s.rollbackActiveBindingForWrite()
	data, err := json.MarshalIndent(rollbackMetadataFile{
		Version:       rollbackMetadataVersion,
		Generation:    generation,
		ActiveHash:    activeHash,
		ActiveDevice:  activeIdentity.Device,
		ActiveInode:   activeIdentity.Inode,
		ActiveModTime: activeIdentity.ModTime,
		Entries:       entries,
	}, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal rollback metadata: %w", err)
	}
	if err := checkPersistSize(path, len(data)); err != nil {
		return err
	}
	if err := rbWriteFileDurable(path, data, 0600); err != nil {
		return fmt.Errorf("persist rollback metadata: %w", err)
	}
	return nil
}

func (s *Store) readRollbackMetadata() []rollbackSlotMetadataEntry {
	_, _, _, entries := s.readRollbackMetadataSnapshot()
	return entries
}

func (s *Store) readRollbackMetadataSnapshot() (uint64, string, rollbackSlotIdentity, []rollbackSlotMetadataEntry) {
	path := s.rollbackMetadataPath()
	data, err := ReadBoundedFile(path, MaxConfigSize)
	if err != nil {
		if !os.IsNotExist(err) {
			slog.Warn("ignoring unreadable rollback metadata", "path", path, "err", err)
		}
		return 0, "", rollbackSlotIdentity{}, nil
	}
	var file rollbackMetadataFile
	if err := json.Unmarshal(data, &file); err != nil {
		slog.Warn("ignoring malformed rollback metadata", "path", path, "err", err)
		return 0, "", rollbackSlotIdentity{}, nil
	}
	if file.Version != rollbackMetadataVersion {
		slog.Warn("ignoring unsupported rollback metadata", "path", path, "version", file.Version)
		return 0, "", rollbackSlotIdentity{}, nil
	}
	return file.Generation, file.ActiveHash,
		rollbackSlotIdentity{
			Device: file.ActiveDevice, Inode: file.ActiveInode, ModTime: file.ActiveModTime,
		}, file.Entries
}

func (s *Store) rollbackActivePath() string {
	if s.db != nil {
		return s.db.activePath()
	}
	return filepath.Join(filepath.Dir(s.filePath), ".configdb", "active.json")
}

func (s *Store) rollbackActiveBindingForWrite() (string, rollbackSlotIdentity) {
	if s.db == nil {
		return "", rollbackSlotIdentity{}
	}
	tree := s.active
	if tree == nil {
		var err error
		tree, err = s.db.ReadActive()
		if err != nil {
			return "", rollbackSlotIdentity{}
		}
	}
	identity, ok := rollbackSlotIdentityForPath(s.rollbackActivePath())
	if !ok || tree == nil {
		return "", rollbackSlotIdentity{}
	}
	return guardedConfigHash(tree), identity
}

func (s *Store) rollbackActiveBindingFromDisk() (string, rollbackSlotIdentity, bool) {
	if s.db == nil {
		return "", rollbackSlotIdentity{}, false
	}
	tree, err := s.db.ReadActive()
	if err != nil || tree == nil {
		return "", rollbackSlotIdentity{}, false
	}
	identity, ok := rollbackSlotIdentityForPath(s.rollbackActivePath())
	if !ok {
		return "", rollbackSlotIdentity{}, false
	}
	return guardedConfigHash(tree), identity, true
}


func rollbackMetadataForSlot(entries []rollbackSlotMetadataEntry, slot int, data []byte, identity rollbackSlotIdentity, identityOK bool) (time.Time, string, bool) {
	if !identityOK || slot < 0 || slot >= len(entries) {
		return time.Time{}, "", false
	}
	entry := entries[slot]
	if entry.Hash == "" || entry.Hash != rollbackSlotHash(data) ||
		entry.Device != identity.Device || entry.Inode != identity.Inode ||
		!entry.ModTime.Equal(identity.ModTime) {
		return time.Time{}, "", false
	}
	return entry.Timestamp, entry.Comment, true
}
