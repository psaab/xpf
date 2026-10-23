package configstore

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/psaab/xpf/pkg/config"
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
//
// Next-active preparation (#16064): immediately before WriteActive, Commit
// durably writes rollback preparation metadata. Its primary active binding
// still describes the current history, while next_active_hash describes the
// committed tree that is about to become active. PendingHash on each entry
// names the post-commit slot content at that same position, and
// PendingTimestamp/PendingComment carry that future entry's attributes, so a
// partially rewritten slot is restored with ITS OWN timestamp/comment rather
// than borrowing another position's. If power is lost after the active
// rename, history slots retain their old bytes but load at their old
// pre-shift positions; each is admitted only when its hash equals the
// previous committed entry at index-1 (or the previous active hash for slot
// 1). If power is lost after some slot rewrites, those rewritten slots are
// admitted from PendingHash with their pending attributes. Active identity
// mismatch alone therefore no longer mass-tombstones byte-verifiable history;
// unrelated active content and unmatched bytes still fail closed. A normal
// completed commit publishes current metadata with all preparation fields
// cleared before it returns.
type rollbackMetadataFile struct {
	Version       int                         `json:"version"`
	Generation    uint64                      `json:"generation,omitempty"`
	ActiveHash    string                      `json:"active_hash,omitempty"`
	ActiveDevice  uint64                      `json:"active_device,omitempty"`
	ActiveInode   uint64                      `json:"active_inode,omitempty"`
	ActiveModTime time.Time                   `json:"active_mod_time,omitempty"`
	Entries       []rollbackSlotMetadataEntry `json:"entries"`
	// NextActiveHash is the guarded hash of the committed tree whose active
	// rename this preparation record immediately precedes (#16064). It certifies
	// the one-generation skew whenever the durable active.json hash matches it,
	// including when it equals ActiveHash (same-content commit): the active
	// file identity still moved, so the skew is real.
	NextActiveHash string `json:"next_active_hash,omitempty"`
}

type rollbackSlotMetadataEntry struct {
	Hash       string    `json:"hash"`
	Device     uint64    `json:"device"`
	Inode      uint64    `json:"inode"`
	ModTime    time.Time `json:"mod_time"`
	Timestamp  time.Time `json:"timestamp"`
	Comment    string    `json:"comment,omitempty"`
	Generation uint64    `json:"generation,omitempty"`
	// PendingHash (#16064) is the rollback-slot content hash that will occupy
	// this same slot position during a prepared in-flight commit. It lets boot
	// recover partially rewritten history without shifting positions.
	PendingHash string `json:"pending_hash,omitempty"`
	// PendingTimestamp/PendingComment (#16064) are the history attributes of
	// the FUTURE entry whose content PendingHash names. A slot admitted via
	// PendingHash must be stamped with these, not with the committed entry's
	// attributes at this or any other position.
	PendingTimestamp time.Time `json:"pending_timestamp,omitempty"`
	PendingComment   string    `json:"pending_comment,omitempty"`
	// CurrentHash/CurrentTimestamp/CurrentComment (#16064 fold 3) snapshot the
	// CURRENT on-disk slot bytes at this index and their owning history
	// entry's attributes, captured during preparation independently of the
	// committed Hash field. Bound to CurrentHash exactly: a slot admitted
	// via CurrentHash carries CurrentTimestamp/CurrentComment.
	CurrentHash      string    `json:"current_hash,omitempty"`
	CurrentTimestamp time.Time `json:"current_timestamp,omitempty"`
	CurrentComment   string    `json:"current_comment,omitempty"`
	// PendingDevice/PendingInode/PendingModTime (#16064 fold 6) are the slot
	// file identity RECORDED AT PREPARATION for this index. Every slot save
	// is temp+rename, so a landed rewrite always installs a new inode (and
	// new mtime): at load, identity != recorded preparation identity proves
	// THIS slot's rewrite landed, while identity == recorded proves it did
	// not — per-slot landed detection for the equal-content case, where
	// hashes cannot distinguish landed from untouched.
	PendingDevice  uint64    `json:"pending_device,omitempty"`
	PendingInode   uint64    `json:"pending_inode,omitempty"`
	PendingModTime time.Time `json:"pending_mod_time,omitempty"`
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

// rollbackSlotBytesParseAsConfig reports whether slot bytes would be
// admitted by loadRollbackHistory as a live config (non-empty, not the
// tombstone marker, parses to a non-empty tree). Used by the #15023
// rebind to decide whether a tombstone's on-disk bytes are a resurrectable
// prior generation (must be replaced by the marker) or already refuse at
// load (identity can be kept as-is).
func rollbackSlotBytesParseAsConfig(data []byte) bool {
	if len(bytes.TrimSpace(data)) == 0 ||
		bytes.HasPrefix(data, []byte(rollbackTombstoneMarkerPrefix)) {
		return false
	}
	tree, errs := config.NewParser(string(data)).Parse()
	return len(errs) == 0 && tree != nil && len(tree.Children) > 0
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

func (s *Store) writeRollbackMetadataGeneration(generation uint64, entries []rollbackSlotMetadataEntry) error {
	return s.writeRollbackMetadataGenerationNext(generation, entries, "")
}

func (s *Store) writeRollbackMetadataGenerationNext(generation uint64,
	entries []rollbackSlotMetadataEntry, nextActiveHash string) error {
	return s.writeRollbackMetadataGenerationNextBound(generation, entries, nextActiveHash, "")
}

func (s *Store) writeRollbackMetadataGenerationNextBound(generation uint64,
	entries []rollbackSlotMetadataEntry, nextActiveHash, boundActiveHash string) error {
	path := s.rollbackMetadataPath()
	activeHash, activeIdentity := s.rollbackActiveBindingForWrite()
	if boundActiveHash != "" {
		activeHash = boundActiveHash
	}
	data, err := json.MarshalIndent(rollbackMetadataFile{
		Version:        rollbackMetadataVersion,
		Generation:     generation,
		ActiveHash:     activeHash,
		ActiveDevice:   activeIdentity.Device,
		ActiveInode:    activeIdentity.Inode,
		ActiveModTime:  activeIdentity.ModTime,
		Entries:        entries,
		NextActiveHash: nextActiveHash,
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

// rebindRollbackMetadataLocked rewrites rollback-meta.json so it binds the
// CURRENT s.history slot set to the CURRENT on-disk active.json (#14578).
// Callers that rewrite active.json without shifting history (commit-confirmed
// timeout revert, boot recovery, persist-retry heal) must call this after a
// successful active write; otherwise the stale active hash/inode makes the
// next loadRollbackHistory tombstone every slot (#10723 generation check).
// The generation is bumped so the rebound sidecar is a new generation, not a
// mutation of the old one.
//
// Slot identity is derived from the IN-MEMORY history, never from whatever
// bytes happen to be on disk (#15023): for a live entry the expected bytes
// are entry.Config.Format(); the slot file is rewritten durably whenever
// its on-disk bytes diverge (including an oversized/unreadable read), and
// only the identity captured after that write is recorded. For a tombstone
// the marker is always (re)written so stale pre-tombstone bytes cannot be
// blessed. A slot that cannot be made to match its in-memory entry is
// recorded with an invalid (zero) identity so the next load tombstones it,
// and the rebind stays degraded instead of clearing the flag.
// Best-effort degrade-not-fail like saveRollbackFiles: a failure sets
// rollbackPersistDegraded and journals, never fails the promotion.
// Caller must hold s.mu (write lock) and have just durably written active.
func (s *Store) rebindRollbackMetadataLocked() {
	if s.filePath == "" || s.db == nil {
		return
	}
	entries := s.history.List()
	prevGen, _, _, _ := s.readRollbackMetadataSnapshot()
	generation := prevGen + 1
	if generation == 0 {
		generation = 1
	}
	metadata := make([]rollbackSlotMetadataEntry, len(entries))
	degraded := false
	for i, entry := range entries {
		path := s.rollbackPath(i + 1)
		var data []byte
		var identity rollbackSlotIdentity
		var identityOK bool
		if entry.Config == nil {
			// #15023: always record the marker for a tombstone — never
			// hash whatever bytes are on disk, which would bless a
			// stale slot whose marker write previously failed. If the
			// file still parses as a real config (a prior generation's
			// bytes, e.g. tombstoned at load by the #10723 generation
			// check), restore the marker durably so it cannot be
			// resurrected after restart (#7176). Bytes that already
			// refuse at load (marker, empty, parse error) keep their
			// identity: the slot tombstones either way, and rewriting
			// them would regress the #14578 boot-recovery ladder,
			// whose trailing slots are exactly such tombstones while
			// sibling slots still hold live configs.
			data = []byte(rollbackTombstoneMarker)
			b, rerr := ReadBoundedFile(path, MaxConfigSize)
			switch {
			case rerr == nil && bytes.Equal(b, data):
				identity, identityOK = rollbackSlotIdentityForPath(path)
			case rerr == nil && rollbackSlotBytesParseAsConfig(b):
				if werr := rbWriteFileDurable(path, data, 0600); werr != nil {
					slog.Warn("failed to rewrite rollback tombstone during rebind", "path", path, "err", werr, "issue", "#15023")
					degraded = true
				} else {
					identity, identityOK = rollbackSlotIdentityForPath(path)
				}
			default:
				identity, identityOK = rollbackSlotIdentityForPath(path)
			}
		} else {
			// #15023: hash the in-memory Format(), not disk bytes. A prior
			// slot-write failure (ENOSPC/EIO) or a crash during a
			// commit-confirmed slot shift can leave a different
			// generation's bytes at this index; trusting them would
			// bless the stale generation and clear the degraded flag.
			data = []byte(entry.Config.Format())
			if b, err := ReadBoundedFile(path, MaxConfigSize); err == nil && bytes.Equal(b, data) {
				identity, identityOK = rollbackSlotIdentityForPath(path)
			}
			if !identityOK {
				// Slot missing, diverged, unreadable, or oversized:
				// rewrite it durably so the rebound metadata points at
				// the in-memory entry's real bytes.
				if werr := rbWriteFileDurable(path, data, 0600); werr != nil {
					slog.Warn("failed to rewrite rollback file during rebind", "path", path, "err", werr, "issue", "#15023")
					degraded = true
					if isPostRenameDurabilityFailure(werr) {
						identity, identityOK = rollbackSlotIdentityForPath(path)
					}
				} else {
					identity, identityOK = rollbackSlotIdentityForPath(path)
				}
			}
		}
		if !identityOK {
			// Record an invalid identity so the next load tombstones
			// this slot instead of admitting bytes the rebind could
			// not verify (#15023 fail-closed).
			degraded = true
			identity = rollbackSlotIdentity{}
		}
		metadata[i] = rollbackSlotMetadataEntry{
			Hash:       rollbackSlotHash(data),
			Device:     identity.Device,
			Inode:      identity.Inode,
			ModTime:    identity.ModTime,
			Timestamp:  entry.Timestamp,
			Comment:    entry.Comment,
			Generation: generation,
		}
	}
	if err := s.writeRollbackMetadataGeneration(generation, metadata); err != nil {
		slog.Warn("failed to rebind rollback metadata", "path", s.rollbackMetadataPath(), "err", err, "issue", "#14578")
		degraded = true
	}
	if degraded && !s.rollbackPersistDegraded {
		s.journalLog(&JournalEntry{
			Action:    "rollback_persist_error",
			Detail:    "rollback metadata rebind after active rewrite failed; rollback history may be stale after restart (#14578)",
			Principal: "system:configstore",
		})
	}
	if degraded {
		s.rollbackPersistDegraded = true
	} else {
		// A successful rebind means every slot was verified against (or
		// rewritten to) its in-memory entry and the sidecar now matches
		// disk exactly, mirroring saveRollbackFiles' unconditional clear
		// on success (#15023: a merely re-hashed stale slot no longer
		// counts as success).
		s.rollbackPersistDegraded = false
	}
}

// rollbackMetadataSnapshot is the parsed rollback sidecar: generation, active
// binding, and entries are the durable #10723 binding; NextActiveHash carries
// the #16064 preparation binding for a commit whose active rename may already
// have landed.
type rollbackMetadataSnapshot struct {
	Generation     uint64
	ActiveHash     string
	Identity       rollbackSlotIdentity
	Entries        []rollbackSlotMetadataEntry
	NextActiveHash string
}

func (s *Store) readRollbackMetadata() []rollbackSlotMetadataEntry {
	return s.readRollbackMetadataSnapshotFull().Entries
}

func (s *Store) readRollbackMetadataSnapshot() (uint64, string, rollbackSlotIdentity, []rollbackSlotMetadataEntry) {
	snap := s.readRollbackMetadataSnapshotFull()
	return snap.Generation, snap.ActiveHash, snap.Identity, snap.Entries
}

func (s *Store) readRollbackMetadataSnapshotFull() rollbackMetadataSnapshot {
	path := s.rollbackMetadataPath()
	data, err := ReadBoundedFile(path, MaxConfigSize)
	if err != nil {
		if !os.IsNotExist(err) {
			slog.Warn("ignoring unreadable rollback metadata", "path", path, "err", err)
		}
		return rollbackMetadataSnapshot{}
	}
	var file rollbackMetadataFile
	if err := json.Unmarshal(data, &file); err != nil {
		slog.Warn("ignoring malformed rollback metadata", "path", path, "err", err)
		return rollbackMetadataSnapshot{}
	}
	if file.Version != rollbackMetadataVersion {
		slog.Warn("ignoring unsupported rollback metadata", "path", path, "version", file.Version)
		return rollbackMetadataSnapshot{}
	}
	return rollbackMetadataSnapshot{
		Generation: file.Generation,
		ActiveHash: file.ActiveHash,
		Identity: rollbackSlotIdentity{
			Device: file.ActiveDevice, Inode: file.ActiveInode, ModTime: file.ActiveModTime,
		},
		Entries:        file.Entries,
		NextActiveHash: file.NextActiveHash,
	}
}

// prepareRollbackForCommit durably publishes current history plus the #16064
// next-active dual binding BEFORE WriteActive. futureEntries mirrors the
// caller's post-push history: [previous active, current history...]. The
// committed Hash fields stay bound to the pre-commit sidecar that boot may
// still be holding, and PendingHash/PendingTimestamp/PendingComment describe
// the future entry at each position so a partially completed rewrite can be
// recovered with its own attributes. Generation remains the committed
// generation. A recovered (skew-loaded) store re-arms preparation on its
// next commit because the sidecar's identity is stale but its hash binding
// still matches s.active. Skipped only when there is no primary binding to
// preserve (fresh or legacy DB, or the sidecar names a different active).
func (s *Store) prepareRollbackForCommit(committedTree *config.ConfigTree, description string) error {
	if s.filePath == "" || s.db == nil || s.active == nil || committedTree == nil {
		return nil
	}
	snap := s.readRollbackMetadataSnapshotFull()
	if snap.Generation == 0 || snap.ActiveHash == "" || snap.Identity.Inode == 0 {
		return nil
	}
	// #16064 fold: a skew-recovered store's sidecar still names the PREVIOUS
	// active hash while s.active is the certified next active. That mismatch
	// is precisely the re-arm case and must not skip preparation.
	if snap.ActiveHash != guardedConfigHash(s.active) &&
		!(snap.NextActiveHash != "" && snap.NextActiveHash == guardedConfigHash(s.active)) {
		return nil
	}
	// The caller's in-memory history is already the authority in both the
	// clean and skew-recovered states; committed sidecar entries break their
	// binding if a prior crash consumed entries (e.g. an admitted tombstone
	// at the tail), which is exactly the re-arm case (#16064 fold 3). Every
	// entry here is therefore rebuilt fresh from format bytes.
	futureEntries := []*HistoryEntry{{Config: s.active.Clone(), Timestamp: time.Now(), Comment: description}}
	futureEntries = append(futureEntries, s.history.List()...)
	limit := s.history.MaxSize()
	if limit > 0 && len(futureEntries) > limit {
		futureEntries = futureEntries[:limit]
	}
	preparedLen := len(futureEntries)
	if hl := len(s.history.List()); hl > preparedLen {
		preparedLen = hl
	}
	recoveredSkew := snap.NextActiveHash != "" && snap.NextActiveHash == guardedConfigHash(s.active) &&
		snap.ActiveHash != guardedConfigHash(s.active)
	prepared := make([]rollbackSlotMetadataEntry, preparedLen)
	for i := 0; i < preparedLen; i++ {
		var entry *HistoryEntry
		if i < len(futureEntries) {
			entry = futureEntries[i]
		}
		data := []byte(rollbackTombstoneMarker)
		if entry != nil && entry.Config != nil {
			data = []byte(entry.Config.Format())
		}
		preparedEntry := rollbackSlotMetadataEntry{
			Generation: snap.Generation,
		}
		// Committed Hash/attrs describe the sidecar slot at THIS index as
		// the loader's chain will read it: future[0]'s predecessor is the
		// committed active, future[i]'s predecessor is committed[i-1].
		// Preserve the sidecar's committed binding verbatim; only the
		// loader's skew path may reinterpret it, never the writer.
		if i < len(snap.Entries) {
			preparedEntry.Hash = snap.Entries[i].Hash
			preparedEntry.Timestamp = snap.Entries[i].Timestamp
			preparedEntry.Comment = snap.Entries[i].Comment
			preparedEntry.Device = snap.Entries[i].Device
			preparedEntry.Inode = snap.Entries[i].Inode
			preparedEntry.ModTime = snap.Entries[i].ModTime
		}
		if recoveredSkew {
			// Committed = CURRENT slots in recovered (pre-shift) positions:
			// slot 1 = previous committed entry 0, slot i = history[i-2],
			// stamped with that entry's committed attributes.
			// Fold 3: snapshot EVERY current slot (hash + attrs) in recovered
			// pre-shift positions, sourced from the in-memory history that
			// the loader itself just verified: disk slot k holds history[k-1]
			// with that entry's attributes. Entry index here is future index
			// (entry 0 = new slot 1 = previous active generation), so disk
			// slot i+1 holds history[i] and preparedEntry for future[i] must
			// carry history[i]'s hash+attrs as its committed binding.
			{
				histList := s.history.List()
				if i == 0 && len(snap.Entries) > 0 {
					// Slot 1 currently holds the previous committed entry 0.
					preparedEntry.Hash = snap.Entries[0].Hash
					preparedEntry.Timestamp = snap.Entries[0].Timestamp
					preparedEntry.Comment = snap.Entries[0].Comment
				} else if i-1 < len(histList) && histList[i-1] != nil && histList[i-1].Config != nil {
					preparedEntry.Hash = rollbackSlotHash([]byte(histList[i-1].Config.Format()))
					preparedEntry.Timestamp = histList[i-1].Timestamp
					preparedEntry.Comment = histList[i-1].Comment
				} else {
					preparedEntry.Hash = rollbackSlotHash([]byte(rollbackTombstoneMarker))
				}
			}
			// Current-slot identity for the committed binding.
			if identity, ok := rollbackSlotIdentityForPath(s.rollbackPath(i + 1)); ok {
				preparedEntry.Device = identity.Device
				preparedEntry.Inode = identity.Inode
				preparedEntry.ModTime = identity.ModTime
			} else {
				preparedEntry.Device, preparedEntry.Inode, preparedEntry.ModTime = 0, 0, time.Time{}
			}
		}
		preparedEntry.PendingHash = rollbackSlotHash(data)
		if entry != nil {
			preparedEntry.PendingTimestamp = entry.Timestamp
			preparedEntry.PendingComment = entry.Comment
		}
		// Fold 3: snapshot current slot bytes for EVERY entry, sourced from
		// the production current-slot history in EVERY state: slot i+1's
		// current content is history[i], independent of committed Hash.
		if histList := s.history.List(); i < len(histList) && histList[i] != nil && histList[i].Config != nil {
			preparedEntry.CurrentHash = rollbackSlotHash([]byte(histList[i].Config.Format()))
			preparedEntry.CurrentTimestamp = histList[i].Timestamp
			preparedEntry.CurrentComment = histList[i].Comment
		} else {
			preparedEntry.CurrentHash = rollbackSlotHash([]byte(rollbackTombstoneMarker))
		}
		// Fold 6: record THIS slot's file identity at preparation time.
		// saveRollbackFiles rewrites every slot via temp+rename, so at load
		// a different inode proves this slot landed; the recorded identity
		// (0 when the file does not exist yet) proves it did not.
		if id, ok := rollbackSlotIdentityForPath(s.rollbackPath(i + 1)); ok {
			preparedEntry.PendingDevice = id.Device
			preparedEntry.PendingInode = id.Inode
			preparedEntry.PendingModTime = id.ModTime
		}
		prepared[i] = preparedEntry
	}
	boundActive := snap.ActiveHash
	if recoveredSkew {
		boundActive = guardedConfigHash(s.active)
	}
	return s.writeRollbackMetadataGenerationNextBound(
		snap.Generation, prepared, guardedConfigHash(committedTree), boundActive)
}

// rollbackSkewSlotAdmission is the production #16064 loader gate: given the
// sidecar snapshot, whether the certified pending skew is in effect, and a
// slot's 1-based index and content hash, it reports whether the slot survives
// at its pre-shift position and which attributes it carries.
func rollbackSkewSlotAdmission(snap rollbackMetadataSnapshot, pendingSkew bool, i int,
	slotHash string, identity rollbackSlotIdentity, identityOK bool) (valid bool, ts time.Time, comment string) {
	if !pendingSkew {
		return false, time.Time{}, ""
	}
	metadata := snap.Entries
	// Fold 6 landed detection: every slot save is temp+rename, so a landed
	// rewrite installs a NEW inode. For bytes matching both hashes
	// (equal-content slot), compare the load-time identity against the
	// identity recorded at preparation: differs (or preparation identity
	// was 0/absent and a file now exists) = THIS slot landed -> PENDING
	// attrs; identical = untouched -> CURRENT attrs. Identity unavailable
	// at load (identityOK=false) withholds the pending upgrade fail-closed.
	if i-1 < len(metadata) && metadata[i-1].CurrentHash != "" &&
		slotHash == metadata[i-1].CurrentHash {
		if metadata[i-1].PendingHash != "" && slotHash == metadata[i-1].PendingHash {
			rec := rollbackSlotIdentity{Device: metadata[i-1].PendingDevice, Inode: metadata[i-1].PendingInode, ModTime: metadata[i-1].PendingModTime}
			landed := false
			if identityOK {
				if rec.Inode == 0 {
					landed = true // file absent at preparation, exists now
				} else {
					landed = identity.Device != rec.Device || identity.Inode != rec.Inode || !identity.ModTime.Equal(rec.ModTime)
				}
			}
			if landed {
				return true, metadata[i-1].PendingTimestamp, metadata[i-1].PendingComment
			}
		}
		return true, metadata[i-1].CurrentTimestamp, metadata[i-1].CurrentComment
	}
	if i-1 < len(metadata) && metadata[i-1].PendingHash != "" &&
		slotHash == metadata[i-1].PendingHash {
		return true, metadata[i-1].PendingTimestamp, metadata[i-1].PendingComment
	}
	// Fallback mapping (pre-shift chain): the crashed commit's predecessor
	// list is [old active, old slot1, old slot2, ...] = [snap.ActiveHash,
	// metadata[0].Hash, metadata[1].Hash, ...]. Slot i still holds the bytes
	// of that predecessor list at index i-1 BEFORE the shift renumbers them,
	// so slot 1 pairs with snap.ActiveHash and slot i>=2 pairs with
	// metadata[i-2].Hash. This is the correct mapping, guarded by the exact
	// loader regression below. (Old analysis: this was suspected off-by-one;
	// byte-probing disk state showed pre-shift slot bytes match exactly.)
	want := ""
	if i == 1 {
		want = snap.ActiveHash
	} else if i-2 < len(metadata) {
		want = metadata[i-2].Hash
	}
	if want == "" || slotHash != want {
		return false, time.Time{}, ""
	}
	if ts, c, found := rollbackMetadataTimestampForSlot(metadata, i-1); found {
		return true, ts, c
	}
	return true, time.Time{}, ""
}

// classifyRollbackSlotBytes characterizes rollbackSkewSlotAdmission's
// hash-edge decisions for table tests:
//
//   - pending[pos] (the prepared future content hash) admits, stamped with
//     pending attributes;
//   - the pre-shift chain (active hash at pos 0, committed[pos-1] after)
//     admits, stamped with committed attributes;
//   - anything else refuses.
//
// pendingOK is the certified-skew gate; when it is false nothing admits.
func classifyRollbackSlotBytes(pendingOK bool, snap rollbackMetadataSnapshot, pos int,
	slotHash string) (admit, viaPending bool) {
	valid, _, _ := rollbackSkewSlotAdmission(snap, pendingOK, pos+1, slotHash, rollbackSlotIdentity{}, false)
	if !valid {
		return false, false
	}
	if pos < len(snap.Entries) && snap.Entries[pos].PendingHash != "" &&
		slotHash == snap.Entries[pos].PendingHash {
		return true, true
	}
	return true, false
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

// rollbackMetadataForOversizedSlot validates an unreadable-by-bound slot
// against the manifest without materializing its contents. The file is only
// eligible when it is a regular oversized file, and its full streaming hash
// and identity must match the saved metadata.
func rollbackMetadataForOversizedSlot(entries []rollbackSlotMetadataEntry, slot int, path string) (time.Time, string, bool) {
	if slot < 0 || slot >= len(entries) {
		return time.Time{}, "", false
	}
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return time.Time{}, "", false
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() <= MaxConfigSize {
		return time.Time{}, "", false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return time.Time{}, "", false
	}
	sum := sha256.New()
	if _, err := io.Copy(sum, f); err != nil {
		return time.Time{}, "", false
	}
	entry := entries[slot]
	if entry.Hash == "" || entry.Hash != hex.EncodeToString(sum.Sum(nil)) ||
		entry.Device != uint64(stat.Dev) || entry.Inode != stat.Ino ||
		!entry.ModTime.Equal(info.ModTime()) {
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
