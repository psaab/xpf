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
type rollbackMetadataFile struct {
	Version int                          `json:"version"`
	Entries []rollbackSlotMetadataEntry `json:"entries"`
}

type rollbackSlotMetadataEntry struct {
	Hash      string    `json:"hash"`
	Device    uint64    `json:"device"`
	Inode     uint64    `json:"inode"`
	ModTime   time.Time `json:"mod_time"`
	Timestamp time.Time `json:"timestamp"`
	Comment   string    `json:"comment,omitempty"`
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
	info, err := os.Stat(path)
	if err != nil {
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
	path := s.rollbackMetadataPath()
	data, err := json.MarshalIndent(rollbackMetadataFile{
		Version: rollbackMetadataVersion,
		Entries: entries,
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
	path := s.rollbackMetadataPath()
	data, err := ReadBoundedFile(path, MaxConfigSize)
	if err != nil {
		if !os.IsNotExist(err) {
			slog.Warn("ignoring unreadable rollback metadata", "path", path, "err", err)
		}
		return nil
	}
	var file rollbackMetadataFile
	if err := json.Unmarshal(data, &file); err != nil {
		slog.Warn("ignoring malformed rollback metadata", "path", path, "err", err)
		return nil
	}
	if file.Version != rollbackMetadataVersion {
		slog.Warn("ignoring unsupported rollback metadata", "path", path, "version", file.Version)
		return nil
	}
	return file.Entries
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
