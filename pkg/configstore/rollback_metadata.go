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

// apiAuthMigrationStagingFile records a staged api-auth credential transition
// (#10825 F1). It is durable before active.json changes and carries exact
// expected/original slot hashes and metadata. During this transition, only an
// old sidecar plus its old active identity, or a newly rebound sidecar matching
// the new active identity, can authorize those staged slot bytes. It is deleted
// after the active binding and numbered slots converge.
type apiAuthMigrationStagingFile struct {
	Version              int                         `json:"version"`
	OldHash              string                      `json:"old_hash"`
	OldDevice            uint64                      `json:"old_device,omitempty"`
	OldInode             uint64                      `json:"old_inode,omitempty"`
	OldModTime           time.Time                   `json:"old_mod_time,omitempty"`
	NewHash              string                      `json:"new_hash"`
	OriginalGeneration   uint64                      `json:"original_generation,omitempty"`
	OriginalSlotMetadata []rollbackSlotMetadataEntry `json:"original_slot_metadata,omitempty"`
	SlotHashes           []string                    `json:"slot_hashes,omitempty"`
	SlotTombstones       []bool                      `json:"slot_tombstones,omitempty"`
}

const (
	apiAuthMigrationStagingFilename = "api-auth-migration.json"
	apiAuthMigrationStagingVersion  = 1
)

func (s *Store) apiAuthMigrationStagingPath() string {
	if s.db != nil {
		return filepath.Join(s.db.dir, apiAuthMigrationStagingFilename)
	}
	return filepath.Join(filepath.Dir(s.filePath), ".configdb", apiAuthMigrationStagingFilename)
}

func (s *Store) writeAPIAuthMigrationStaging(oldHash string, oldIdentity rollbackSlotIdentity, newHash string,
	originalGeneration uint64, originalEntries []rollbackSlotMetadataEntry,
	slotHashes []string, slotTombstones []bool) error {
	path := s.apiAuthMigrationStagingPath()
	data, err := json.MarshalIndent(apiAuthMigrationStagingFile{
		Version:              apiAuthMigrationStagingVersion,
		OldHash:              oldHash,
		OldDevice:            oldIdentity.Device,
		OldInode:             oldIdentity.Inode,
		OldModTime:           oldIdentity.ModTime,
		NewHash:              newHash,
		OriginalGeneration:   originalGeneration,
		OriginalSlotMetadata: originalEntries,
		SlotHashes:           slotHashes,
		SlotTombstones:       slotTombstones,
	}, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal api-auth migration staging: %w", err)
	}
	if err := checkPersistSize(path, len(data)); err != nil {
		return err
	}
	if err := rbWriteFileDurable(path, data, 0600); err != nil {
		return fmt.Errorf("persist api-auth migration staging: %w", err)
	}
	return nil
}

// readAPIAuthMigrationStaging returns the staged transition, or ok=false when
// no usable record is available. Staging consistency fails closed if a record
// exists but is unreadable or malformed.
func (s *Store) readAPIAuthMigrationStaging() (apiAuthMigrationStagingFile, bool) {
	path := s.apiAuthMigrationStagingPath()
	data, err := ReadBoundedFile(path, MaxConfigSize)
	if err != nil {
		if !os.IsNotExist(err) {
			slog.Warn("unreadable api-auth migration staging will fail closed", "path", path, "err", err)
		}
		return apiAuthMigrationStagingFile{}, false
	}
	var file apiAuthMigrationStagingFile
	if err := json.Unmarshal(data, &file); err != nil {
		slog.Warn("malformed api-auth migration staging will fail closed", "path", path, "err", err)
		return apiAuthMigrationStagingFile{}, false
	}
	if file.Version != apiAuthMigrationStagingVersion || file.OldHash == "" || file.NewHash == "" {
		slog.Warn("unsupported api-auth migration staging will fail closed", "path", path, "version", file.Version)
		return apiAuthMigrationStagingFile{}, false
	}
	if len(file.SlotHashes) != len(file.SlotTombstones) {
		slog.Warn("api-auth migration staging has inconsistent rollback slots and will fail closed", "path", path)
		return apiAuthMigrationStagingFile{}, false
	}
	return file, true
}

func (s *Store) deleteAPIAuthMigrationStaging() {
	path := s.apiAuthMigrationStagingPath()
	if err := rbRemove(path); err != nil {
		if !os.IsNotExist(err) {
			slog.Warn("failed to remove converged api-auth migration staging; will retry on next boot", "path", path, "err", err)
		}
		return
	}
	if err := rbSyncDir(filepath.Dir(path)); err != nil {
		slog.Warn("failed to sync dir after removing api-auth migration staging", "path", path, "err", err)
	}
}

// apiAuthMigrationAliasMatches reports whether the sidecar binding and active
// file are the old or new side of the staged credential transition. This is
// deliberately limited to exact saved hashes/identities; every unrelated
// active mismatch retains the normal #10723 refusal.
func apiAuthMigrationAliasMatches(file apiAuthMigrationStagingFile, ok bool, sidecarHash string,
	sidecarIdentity rollbackSlotIdentity, diskHash string, diskIdentity rollbackSlotIdentity) bool {
	if !ok {
		return false
	}
	if sidecarHash == file.NewHash && diskHash == file.NewHash {
		return sidecarIdentity.Inode == 0 ||
			(sidecarIdentity.Device == diskIdentity.Device &&
				sidecarIdentity.Inode == diskIdentity.Inode &&
				sidecarIdentity.ModTime.Equal(diskIdentity.ModTime))
	}
	if sidecarHash == "" && sidecarIdentity.Inode == 0 {
		if diskHash == file.OldHash {
			return file.OldInode == 0 || (diskIdentity.Device == file.OldDevice &&
				diskIdentity.Inode == file.OldInode && file.OldModTime.Equal(diskIdentity.ModTime))
		}
		return diskHash == file.NewHash
	}
	if sidecarHash != file.OldHash {
		return false
	}
	if sidecarIdentity.Inode != 0 &&
		(file.OldInode == 0 || file.OldDevice != sidecarIdentity.Device ||
			file.OldInode != sidecarIdentity.Inode || !file.OldModTime.Equal(sidecarIdentity.ModTime)) {
		return false
	}
	if diskHash == file.OldHash {
		return file.OldInode == 0 || (diskIdentity.Device == file.OldDevice &&
			diskIdentity.Inode == file.OldInode && file.OldModTime.Equal(diskIdentity.ModTime))
	}
	return diskHash == file.NewHash
}

func (s *Store) apiAuthMigrationStagingConsistent() bool {
	file, ok := s.readAPIAuthMigrationStaging()
	if !ok {
		_, err := os.Lstat(s.apiAuthMigrationStagingPath())
		return os.IsNotExist(err)
	}
	_, sidecarHash, sidecarIdentity, _ := s.readRollbackMetadataSnapshot()
	diskHash, diskIdentity, diskOK := s.rollbackActiveBindingFromDisk()
	if !diskOK || !apiAuthMigrationAliasMatches(
		file, true, sidecarHash, sidecarIdentity, diskHash, diskIdentity) {
		return false
	}
	for slot := range file.SlotHashes {
		data, err := ReadBoundedFile(s.rollbackPath(slot+1), MaxConfigSize)
		if err != nil {
			if os.IsNotExist(err) || slot >= len(file.SlotTombstones) || !file.SlotTombstones[slot] {
				return false
			}
			continue
		}
		identity, identityOK := rollbackSlotIdentityForPath(s.rollbackPath(slot + 1))
		if !apiAuthMigrationSlotMatches(file, slot, data, identity, identityOK) {
			return false
		}
	}
	return true
}

func apiAuthMigrationSlotMatches(file apiAuthMigrationStagingFile, slot int, data []byte,
	identity rollbackSlotIdentity, identityOK bool) bool {
	if slot < 0 {
		return false
	}
	hash := rollbackSlotHash(data)
	if slot < len(file.SlotHashes) && file.SlotHashes[slot] != "" &&
		file.SlotHashes[slot] == hash {
		return true
	}
	if !identityOK || slot >= len(file.OriginalSlotMetadata) {
		return false
	}
	entry := file.OriginalSlotMetadata[slot]
	return entry.Hash != "" && entry.Hash == hash &&
		entry.Generation == file.OriginalGeneration &&
		entry.Device == identity.Device && entry.Inode == identity.Inode &&
		entry.ModTime.Equal(identity.ModTime)
}

// rollbackMetadataTimestampForSlot returns the recorded Timestamp/Comment for a
// slot index regardless of content hash or identity, for the migration window
// where slots were rewritten (hashes necessarily differ) but the recorded
// attributes must be preserved rather than regenerated.
func rollbackMetadataTimestampForSlot(entries []rollbackSlotMetadataEntry, slot int) (time.Time, string, bool) {
	if slot < 0 || slot >= len(entries) {
		return time.Time{}, "", false
	}
	return entries[slot].Timestamp, entries[slot].Comment, true
}

func (s *Store) convergeAPIAuthMigrationStaging() error {
	_, ok := s.readAPIAuthMigrationStaging()
	if !ok {
		return nil
	}
	generation, metaHash, metaIdentity, _ := s.readRollbackMetadataSnapshot()
	diskHash, diskIdentity, diskOK := s.rollbackActiveBindingFromDisk()
	if generation == 0 || !diskOK || metaIdentity.Inode == 0 ||
		metaHash != diskHash || metaIdentity.Device != diskIdentity.Device ||
		metaIdentity.Inode != diskIdentity.Inode || !metaIdentity.ModTime.Equal(diskIdentity.ModTime) {
		return fmt.Errorf("rollback manifest does not match the active generation after api-auth migration")
	}
	s.deleteAPIAuthMigrationStaging()
	return nil
}
