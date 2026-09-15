// Package journal implements the configstore commit audit trail as a
// compact, rotated, tail-readable JSONL log (#1896).
//
// History: the v1 journal (pkg/configstore/journal.go, deleted in
// #1896) appended the FULL compiled *config.Config per commit and every
// history view re-read and re-unmarshaled the entire file — O(lifetime
// commits x config size) per `show system commit`, no rotation, and the
// compiled payload (including secrets) sat in a 0644 file forever while
// being read by nobody: both renderers print only Timestamp, Action and
// Detail, and full config trees already live in the rollback slots with
// explicit retention.
//
// v2 entries are compact metadata only and the file is written
// owner-only 0600 (#4579 A4-02): although the metadata is not itself a
// secret store, Detail carries the operator's free-text commit comment
// verbatim, so the journal matches the 0600 posture of the rest of the
// config surface (#4056) instead of sitting world-readable. Reads are
// reverse tail scans bounded by the requested limit; the file rotates
// by size with a keep-N segment policy; appends are fsynced
// (operator-paced — the
// commit path already pays several fsyncs for active.json and rollback
// slot 1, see #1894). Legacy fat v1 lines decode tolerantly (unknown
// JSON fields are ignored), and the first append after upgrade rotates
// an over-threshold legacy file to segment .1 intact, so old history
// stays visible until it ages out. First use — the first Log or Tail —
// runs a one-time permission-repair pass (#5188): every OWNED segment
// (the current file plus its rotation siblings .1../.N) is lstat'd and,
// if a pre-0600 build left it more permissive than owner-only, chmod'd
// to 0600, and rotation re-asserts 0600 on the renamed segment. This
// closes the residual #4579 A4-02 left: O_APPEND ignores the perm arg on
// an EXISTING inode, so an upgraded 0644 current file — and any rotated
// secret-bearing legacy .N segment — otherwise stayed world-readable
// with no migration pass at all. The repair only ever tightens (a
// stricter-than-0600 file is left alone), refuses to follow a symlink
// (lstat, never chmod through it to an arbitrary target), and surfaces
// failures as warnings rather than swallowing them. Boot never reads the
// journal at all.
package journal

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/psaab/xpf/pkg/fsatomic"
)

// Entry is a single audit record (schema v2). Legacy v1 entries carried
// full compiled-config "before"/"after" payloads; those fields are gone
// — tolerant decode drops them — and the rollback files (the canonical
// full-config history, saveRollbackFiles in pkg/configstore) carry the
// trees instead.
type Entry struct {
	// Schema is 2 for entries written by this package and 0 for
	// legacy v1 lines. Forensic marker only — decode is tolerant in
	// both directions.
	Schema    int       `json:"v,omitempty"`
	Timestamp time.Time `json:"timestamp"`
	// Action: "commit", "commit_confirmed", "auto_rollback",
	// "config_sync", "persist_error", "persist_recovered",
	// "system_action" (destructive maintenance verb, #4108 F8).
	Action string `json:"action"`
	// Detail is the human-readable description (commit comment or
	// error text).
	Detail string `json:"detail,omitempty"`
	// ConfigHash is the sha256 (hex) of the post-action active
	// config tree's Format() text — the same text saveRollbackFiles
	// writes to rollback slots, so `sha256sum <conf>.N` correlates a
	// retained rollback file to its journal entry. Best-effort
	// correlation while the slot is retained (slots shift every
	// commit and only ~50 are kept), NOT a referential-integrity
	// guarantee. Empty for entries that carry no config
	// (persist_error / persist_recovered).
	ConfigHash string `json:"config_hash,omitempty"`
}

// SchemaV2 marks entries written by this package.
const SchemaV2 = 2

const (
	// DefaultMaxSegmentBytes rotates the current segment once it
	// reaches 1 MiB (~4-7k compact entries).
	DefaultMaxSegmentBytes = 1 << 20
	// DefaultMaxSegments keeps 2 rotated segments next to the
	// current one: bounded worst-case disk ≈ 3 MiB + one fat legacy
	// segment until it ages out.
	DefaultMaxSegments = 2

	// readChunk is the reverse-scan chunk size. Larger lines (legacy
	// fat v1 entries) are assembled across chunks.
	readChunk = 64 << 10

	// maxTailLineBytes caps reverse-scan line assembly (AGY plan-r1
	// F4): a corrupt newline-free segment would otherwise buffer the
	// whole file. 16 MiB is far above any real legacy fat entry; a
	// fragment past the cap is discarded and the scanner resyncs at
	// the previous newline, dropping only the poisoned line.
	maxTailLineBytes = 16 << 20
)

// Journal is an append-only, size-rotated JSONL audit log. All methods
// are goroutine-safe via an internal mutex: ListCommitHistory readers
// do NOT hold the configstore Store.mu, and without internal locking a
// reader that opens the current segment while Log rotates it to ".1"
// would read the same inode under both names and duplicate entries.
//
// Lock discipline (#4829): j.mu guards the SEGMENT STATE (rotation, the
// current-file inode, the buffered append), NOT the per-write fsync.
// Log holds j.mu only for rotation + open + the buffered f.Write, then
// RELEASES it before the synchronous f.Sync/SyncDir. A concurrent Tail
// takes the same j.mu, so it is still serialized against rotation (no
// duplicate inode) and against the write itself (no torn read), but it
// no longer blocks for the writer's fsync duration.
type Journal struct {
	mu              sync.Mutex
	path            string
	maxSegmentBytes int64
	maxSegments     int
	// migrated guards the one-time permission-repair pass (#5188) so it
	// runs once on first use, under j.mu, and is a no-op thereafter.
	migrated bool
	// syncFile fsyncs a fully-written segment for durability. It is a
	// field only so tests can inject a slow/blocking fsync and prove Tail
	// does not stall behind it (#4829); production always uses
	// (*os.File).Sync. Called with j.mu RELEASED.
	syncFile func(*os.File) error
	// syncDir fsyncs the directory after a create or rotation, so the
	// NAMESPACE change is durable. A seam for the same reason syncFile is one:
	// #9057's defect was that this call was SKIPPED when syncFile failed, and
	// an outcome-only assertion cannot see a directory fsync that did not
	// happen — fsync leaves no artifact. Defaults to fsatomic.SyncDir.
	syncDir func(string) error
	// inflight counts appends whose bytes are written but whose fsync has
	// not completed yet, keyed by the INODE they were written to (#7174
	// C06). Guarded by j.mu. Key 0 is the sentinel for "inode could not be
	// determined" — no real inode is 0, and rotation treats an outstanding
	// sentinel as unproven and defers, because it cannot show the segment it
	// is about to destroy is not the one being fsynced.
	//
	// This exists because the durability step runs with j.mu RELEASED
	// (#4829), so a writer can be parked between its f.Write and its f.Sync
	// while another writer rotates. Renames are harmless — they preserve the
	// inode, so the parked writer's bytes just move to ".1" — but the
	// rotation also DESTROYS the oldest segment, and once that inode is
	// unlinked the parked writer's fsync still succeeds and Log still returns
	// SUCCESS for an audit record that no longer exists anywhere.
	inflight map[uint64]int
}

// Option configures a Journal.
type Option func(*Journal)

// WithMaxSegmentBytes overrides the rotation threshold (tests).
func WithMaxSegmentBytes(n int64) Option {
	return func(j *Journal) { j.maxSegmentBytes = n }
}

// WithMaxSegments overrides how many rotated segments are kept (tests).
func WithMaxSegments(n int) Option {
	return func(j *Journal) { j.maxSegments = n }
}

// New creates a journal at the given file path. Out-of-range options
// are clamped to the defaults: maxSegments < 1 would make rotation
// resolve segmentPath(0) — the CURRENT file — and delete the live
// journal (AGY code-r1 F2), and maxSegmentBytes < 1 would rotate on
// every append.
func New(path string, opts ...Option) *Journal {
	j := &Journal{
		path:            path,
		maxSegmentBytes: DefaultMaxSegmentBytes,
		maxSegments:     DefaultMaxSegments,
		syncFile:        (*os.File).Sync,
		syncDir:         fsatomic.SyncDir,
		inflight:        make(map[uint64]int),
	}
	for _, o := range opts {
		o(j)
	}
	if j.maxSegments < 1 {
		j.maxSegments = DefaultMaxSegments
	}
	if j.maxSegmentBytes < 1 {
		j.maxSegmentBytes = DefaultMaxSegmentBytes
	}
	return j
}

// segmentPath returns the path of rotated segment n (1 = newest
// rotated). n == 0 is the current segment.
func (j *Journal) segmentPath(n int) string {
	if n == 0 {
		return j.path
	}
	return fmt.Sprintf("%s.%d", j.path, n)
}

// migratePermsLocked runs once on first use (Log or Tail) and repairs
// the permissions of every OWNED journal segment — the current file and
// its rotation siblings — to owner-only 0600 (#5188). #4579 A4-02 made
// NEW journals 0600, but O_APPEND ignores the perm arg on an existing
// inode, so an upgraded 0644 current file, and any rotated
// secret-bearing legacy .N segment, stayed world-readable with no
// migration pass. Only these journal-owned paths are touched, never an
// unrelated file. Caller holds j.mu.
func (j *Journal) migratePermsLocked() {
	if j.migrated {
		return
	}
	j.migrated = true
	for seg := 0; seg <= j.maxSegments; seg++ {
		chmodOwnerOnly(j.segmentPath(seg))
	}
}

// chmodOwnerOnly tightens path to 0600 when it is a regular file whose
// mode grants any access beyond owner read/write. It only ever tightens:
// a file that is already 0600 or stricter is left untouched, so a
// deliberately locked-down journal is never loosened. A symlink is
// refused — the path is lstat'd and the link is never followed to chmod
// an arbitrary target — and a missing path is a no-op. Failures are
// surfaced as warnings (#5188 "surface failures"), not swallowed.
func chmodOwnerOnly(path string) {
	fi, err := os.Lstat(path)
	if err != nil {
		if !os.IsNotExist(err) {
			slog.Warn("journal: lstat segment for permission repair failed",
				"path", path, "err", err)
		}
		return
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		slog.Warn("journal: refusing to chmod through a symlinked journal segment",
			"path", path)
		return
	}
	if !fi.Mode().IsRegular() {
		return // not an owned journal segment (device/socket/dir/etc.)
	}
	if fi.Mode().Perm()&^0o600 == 0 {
		return // already owner-only (or stricter): only tighten, never loosen
	}
	if err := os.Chmod(path, 0o600); err != nil {
		slog.Warn("journal: chmod journal segment to 0600 failed",
			"path", path, "err", err)
	}
}

// Log appends an entry, rotating first when the current segment is
// over the size threshold. The append is fsynced (the journal is the
// only audit record now that config payloads live in rollback storage,
// and appends are operator-paced); segment creation and rotation get a
// directory fsync so the namespace change survives power loss too.
//
// Lock discipline (#4829): j.mu is held ONLY for the segment-state
// mutation — rotation, open, the torn-tail check, and the buffered
// f.Write — inside appendLocked. The durability step (f.Sync and, on
// create/rotate, SyncDir) runs with j.mu RELEASED, because fsync
// provides durability, NOT visibility: the record's bytes are already in
// the page cache once f.Write returns. A concurrent Tail takes the same
// j.mu, so it observes the segment namespace either before appendLocked
// acquires the lock or after it releases the lock — never mid-rotation
// (no duplicate inode) and never mid-write (no torn read) — yet it no
// longer stalls for the writer's fsync (hundreds of ms on a busy disk).
// Durability is unchanged: Log returns success only after f.Sync (and,
// when the namespace changed, SyncDir) succeed.
//
// Concurrent Log callers serialize on the fast in-lock write via
// appendLocked, then fsync in parallel with j.mu released; O_APPEND makes
// each write land atomically at EOF, and every writer fsyncs its own fd,
// so durability holds regardless of interleaving.
func (j *Journal) Log(entry *Entry) error {
	if entry.Timestamp.IsZero() {
		entry.Timestamp = time.Now()
	}
	if entry.Schema == 0 {
		entry.Schema = SchemaV2
	}

	data, err := json.Marshal(entry)
	if err != nil {
		return fmt.Errorf("marshal journal entry: %w", err)
	}

	f, ino, created, rotated, err := j.appendLocked(data)
	if err != nil {
		return err
	}
	defer f.Close()
	// #7174 C06: the append is registered as in flight from the moment
	// appendLocked's f.Write returns until this fsync completes, so a
	// concurrent rotation cannot destroy the inode underneath it. Deferred so
	// every return path below clears it — a leaked registration would defer
	// rotation for the life of the process.
	defer j.releaseInflight(ino)

	// Durability with j.mu RELEASED (see the method doc). Do NOT move
	// these back under the lock: that reintroduces #4829, where a Tail
	// reader blocks for the writer's entire fsync duration.
	sync := j.syncFile
	if sync == nil {
		sync = (*os.File).Sync
	}
	// #9057: the NAMESPACE fsync runs even when the file sync failed. It used
	// to sit after an early `return` on sync(f), so a data-sync failure also
	// skipped the directory fsync — and those are independent durability
	// facts. The rotation renamed x -> x.1; losing that entry across an
	// unclean shutdown is a separate loss from losing the tail of the file,
	// and the site knew about the helper and skipped it on an error path,
	// which is why an outcome-only assertion could not see it.
	syncErr := sync(f)
	syncdir := j.syncDir
	if syncdir == nil {
		syncdir = fsatomic.SyncDir
	}
	if created || rotated {
		if err := syncdir(filepath.Dir(j.path)); err != nil {
			if syncErr != nil {
				return fmt.Errorf("sync journal: %w (and the journal directory fsync "+
					"also failed: %v)", syncErr, err)
			}
			return fmt.Errorf("sync journal dir: %w", err)
		}
	}
	if syncErr != nil {
		return fmt.Errorf("sync journal: %w", syncErr)
	}
	return nil
}

// appendLocked runs the lock-held part of Log: the one-time permission
// repair, rotation when the current segment is over threshold, opening
// the current segment, the torn-tail self-heal, and the buffered write of
// the newline-framed record. It returns the still-open file (the caller
// fsyncs it with j.mu released) plus whether the segment was created or
// rotated (both need a directory fsync). j.mu is held for the whole body,
// so the buffered f.Write completes and is visible in the page cache
// before the lock is released — any concurrent Tail that then acquires
// j.mu sees a complete record, never a torn one.
func (j *Journal) appendLocked(data []byte) (f *os.File, ino uint64, created, rotated bool, err error) {
	j.mu.Lock()
	defer j.mu.Unlock()

	j.migratePermsLocked()

	rotated, err = j.maybeRotateLocked()
	if err != nil {
		return nil, 0, false, false, err
	}

	if _, statErr := os.Stat(j.path); os.IsNotExist(statErr) {
		created = true
	}

	// O_RDWR (not O_WRONLY): the torn-tail check below reads the
	// last byte through the same fd.
	//
	// Owner-only 0600 (#4579 A4-02): v2 entries are metadata only
	// (Timestamp/Action/ConfigHash plus a free-text Detail), so the
	// journal is not a secret store the way active.json is. But Detail
	// carries the operator-supplied commit comment verbatim, and an
	// operator can put anything there — including, by mistake, a
	// credential ("rotated the vpn psk to hunter2"). The rest of the
	// .configdb-adjacent config surface is already 0600 (#4056); the
	// journal is written next to it and should match rather than sit
	// world-readable as a defense-in-depth gap. The daemon owns the file,
	// so 0600 does not affect append or tail read-back. NOTE: this perm
	// arg only applies when O_CREATE actually creates the file; on an
	// EXISTING inode O_APPEND ignores it, so migratePermsLocked() above
	// is what tightens an upgraded 0644 journal (#5188).
	// #7176 (C179-061): O_NOFOLLOW plus a post-open regular-file check.
	//
	// This package already refuses to CHMOD through a symlinked segment
	// (chmodOwnerOnly above: Lstat, reject ModeSymlink, require IsRegular) — it
	// just did not refuse to APPEND through one. The audit journal is the record
	// an operator reads to reconstruct what happened, so writing it into
	// someone else's file is worse than the permission gap that convention was
	// written for.
	//
	// Both checks are needed and neither subsumes the other:
	//
	//   - O_NOFOLLOW refuses when the FINAL path component is a symlink, and the
	//     kernel decides it at open time, so there is no TOCTOU window the way
	//     an Lstat-then-open would have.
	//   - O_NOFOLLOW happily opens a FIFO, device or socket planted directly at
	//     the path — those are not symlinks. A FIFO is the worst of them: with
	//     O_RDWR the open succeeds, writes land in the pipe buffer, and the
	//     daemon BLOCKS once it fills. So fstat the descriptor and require a
	//     regular file.
	//
	// The check is f.Stat() on the open descriptor, not os.Stat(j.path): a
	// path-based stat would be checking a different object from the one just
	// opened.
	//
	// Cost to a legitimate deployment: an operator who symlinks the journal FILE
	// itself now gets a clear error instead of silent indirection. Symlinking
	// the journal DIRECTORY still works — O_NOFOLLOW only constrains the final
	// component.
	f, err = os.OpenFile(j.path, os.O_APPEND|os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return nil, 0, false, false, fmt.Errorf("open journal: %w", err)
	}
	fi, statErr := f.Stat()
	if statErr != nil {
		f.Close()
		return nil, 0, false, false, fmt.Errorf("stat journal after open: %w", statErr)
	}
	if !fi.Mode().IsRegular() {
		mode := fi.Mode()
		f.Close()
		return nil, 0, false, false, fmt.Errorf(
			"journal path %s is not a regular file (mode %s) — refusing to append the "+
				"audit journal into it", j.path, mode)
	}
	// #7174 C06: the inode this record is about to land in. maybeRotateLocked
	// will not destroy it while the fsync is outstanding.
	ino = inodeOf(fi)

	// Torn-tail self-heal: a crash between a previous write and its
	// fsync can leave a partial final line. Starting this record on a
	// fresh line confines the damage to that one record (which the
	// tail reader's parse-or-skip rule already drops).
	buf := make([]byte, 0, len(data)+2)
	if tail, tailErr := f.Stat(); tailErr == nil && tail.Size() > 0 {
		last := make([]byte, 1)
		if _, readErr := f.ReadAt(last, tail.Size()-1); readErr == nil && last[0] != '\n' {
			buf = append(buf, '\n')
		}
	}
	buf = append(buf, data...)
	buf = append(buf, '\n')

	if _, writeErr := f.Write(buf); writeErr != nil {
		f.Close()
		return nil, 0, false, false, fmt.Errorf("write journal entry: %w", writeErr)
	}
	// #7174 C06: registered under j.mu, released by Log after the fsync. The
	// registration has to happen HERE, before the lock is dropped, or a
	// rotation could slip between the write and the registration.
	j.inflight[ino]++
	return f, ino, created, rotated, nil
}

// inodeOf reports fi's inode number, or 0 when it cannot be determined. 0 is a
// sentinel, not a real inode: rotation treats an outstanding 0 as an append it
// cannot place and defers rather than destroying a segment it cannot prove is
// unrelated (#7174 C06).
func inodeOf(fi os.FileInfo) uint64 {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0
	}
	return st.Ino
}

// releaseInflight clears one in-flight append registration for ino (#7174 C06).
func (j *Journal) releaseInflight(ino uint64) {
	j.mu.Lock()
	defer j.mu.Unlock()
	if n := j.inflight[ino]; n > 1 {
		j.inflight[ino] = n - 1
	} else {
		delete(j.inflight, ino)
	}
}

// maybeRotateLocked rotates the current segment when it is at or over
// the size threshold: the oldest kept segment is removed, every rotated
// segment shifts up one slot, and the current file becomes ".1". A
// crash mid-shift can leave a gap in the segment sequence (lost oldest
// retention); Tail tolerates gaps. Caller holds j.mu.
//
// #7174 C06: rotation DEFERS while an append to the segment it would destroy
// is still in flight. Exactly one inode dies per rotation — the oldest kept
// segment, removed below (the shifting renames only replace paths whose inode
// that Remove already unlinked) — and the renames themselves are harmless
// because a rename preserves the inode, so a parked writer's bytes simply move
// with it into ".1".
//
// The window exists because the durability step runs with j.mu RELEASED
// (#4829): a writer is registered in j.inflight from its f.Write until its
// f.Sync returns, and in that gap another writer can rotate. It takes
// maxSegments+1 rotations for a parked writer's inode to reach the oldest slot
// — three full segments of appends at the defaults — which is why this is an
// audit-integrity edge case rather than a routine loss. It is worth closing
// anyway because of HOW it fails: the parked writer's fsync on an unlinked
// inode SUCCEEDS, so Log returns success, the caller
// (Store.journalLog) has nothing to log a warning about, and the audit record
// is simply not there. Nothing anywhere reports a loss.
//
// Deferring is safe against starvation: the condition names ONE OLD inode, and
// new appends land on the current segment (a different inode), so nothing that
// arrives later can extend the deferral. The next append after that writer's
// fsync rotates. The cost of deferring is a current segment that overshoots
// maxSegmentBytes by one record.
func (j *Journal) maybeRotateLocked() (bool, error) {
	// Lstat, not Stat (#9897 F-108): a symlink planted at the current path
	// must be refused BEFORE the size check and the rename below. Stat
	// would size the TARGET (driving rotation off someone else's file) and
	// the Rename would then move the LINK itself into .1, laundering the
	// plant into a segment every later read follows. Only an (ok, isLink)
	// Lstat acts here; anything else falls through to the Stat, today's
	// error site. Accepted residual: a link swapped in between this gate
	// and the rename could still be laundered — but the readers now refuse
	// links (openSegmentNoFollow), so a laundered link is inert: Tail
	// errors loudly naming it instead of rendering spoofed history.
	if fi, lerr := os.Lstat(j.path); lerr == nil && fi.Mode()&os.ModeSymlink != 0 {
		target, rerr := os.Readlink(j.path)
		if rerr != nil {
			target = "<unreadable link target>"
		}
		return false, fmt.Errorf("journal path %s is a symlink to %s — refusing to "+
			"rotate through it (a stale link fails closed; remove it and the next "+
			"append recreates a regular current segment)", j.path, target)
	}
	fi, err := os.Stat(j.path)
	if err != nil || fi.Size() < j.maxSegmentBytes {
		return false, nil // missing/unreadable current segment: nothing to rotate
	}
	if j.oldestSegmentHasInflightAppendLocked() {
		return false, nil
	}
	if err := os.Remove(j.segmentPath(j.maxSegments)); err != nil && !os.IsNotExist(err) {
		return false, fmt.Errorf("rotate journal: remove oldest segment: %w", err)
	}
	for i := j.maxSegments - 1; i >= 1; i-- {
		if err := os.Rename(j.segmentPath(i), j.segmentPath(i+1)); err != nil && !os.IsNotExist(err) {
			return false, fmt.Errorf("rotate journal: shift segment %d: %w", i, err)
		}
	}
	if err := os.Rename(j.path, j.segmentPath(1)); err != nil {
		return false, fmt.Errorf("rotate journal: rotate current: %w", err)
	}
	// The renamed segment inherits the current file's mode. New v2 files
	// are 0600, but an un-migrated legacy 0644 current would carry
	// world-read into the rotated (secret-bearing) segment; re-assert
	// owner-only here so rotation never widens exposure (#5188).
	chmodOwnerOnly(j.segmentPath(1))
	return true, nil
}

// oldestSegmentHasInflightAppendLocked reports whether the segment the next
// rotation would DESTROY still has an append whose fsync has not completed
// (#7174 C06). Caller holds j.mu.
//
// Lstat, not Stat: a symlink planted at a segment path must be identified as
// the symlink's own inode. Following it would compare against the TARGET's
// inode, which is never one of ours, so a planted link would silently defeat
// the guard — and the rest of this package already refuses to follow a
// symlinked segment (chmodOwnerOnly, and appendLocked's O_NOFOLLOW).
func (j *Journal) oldestSegmentHasInflightAppendLocked() bool {
	// The 0 sentinel means some in-flight append's inode could not be
	// determined. Nothing can be proven about it, so defer.
	if j.inflight[0] > 0 {
		slog.Warn("journal: deferring rotation, an append with an unidentified segment is in flight")
		return true
	}
	oldest := j.segmentPath(j.maxSegments)
	fi, err := os.Lstat(oldest)
	if err != nil {
		return false // nothing there to destroy
	}
	ino := inodeOf(fi)
	if ino == 0 || j.inflight[ino] == 0 {
		return false
	}
	slog.Warn("journal: deferring rotation, an append to the oldest segment is still being fsynced",
		"segment", oldest)
	return true
}

// Tail returns up to limit most-recent entries in oldest-first order
// (matching the v1 ListEntries contract). The read is bounded: segments
// are scanned newest-first with a reverse chunked scan that stops as
// soon as limit entries have been collected, so Tail(50) reads O(50)
// entries regardless of journal lifetime. Unparseable lines (torn tail,
// corruption, foreign content) are skipped, the same tolerance v1 had.
// limit <= 0 reads everything (oldest segment first) — the legacy
// full-scan path kept for ListCommitHistory(0) callers.
func (j *Journal) Tail(limit int) ([]*Entry, error) {
	j.mu.Lock()
	defer j.mu.Unlock()

	j.migratePermsLocked()

	if limit <= 0 {
		return j.readAllLocked()
	}

	// newestFirst[0] is the most recent entry.
	var newestFirst []*Entry
	for seg := 0; seg <= j.maxSegments && len(newestFirst) < limit; seg++ {
		entries, err := tailSegment(j.segmentPath(seg), limit-len(newestFirst))
		if err != nil {
			return nil, err
		}
		newestFirst = append(newestFirst, entries...)
	}

	// Reverse to oldest-first.
	out := make([]*Entry, len(newestFirst))
	for i, e := range newestFirst {
		out[len(out)-1-i] = e
	}
	return out, nil
}

// readAllLocked is the unbounded path (limit <= 0): every segment,
// oldest first, parsed forward. Caller holds j.mu.
func (j *Journal) readAllLocked() ([]*Entry, error) {
	var out []*Entry
	for seg := j.maxSegments; seg >= 0; seg-- {
		f, oerr := openSegmentNoFollow(j.segmentPath(seg))
		if oerr != nil {
			if os.IsNotExist(oerr) {
				continue // gaps tolerated (crash mid-rotation)
			}
			return nil, oerr
		}
		data, rerr := io.ReadAll(f)
		f.Close()
		if rerr != nil {
			return nil, fmt.Errorf("read journal segment: %w", rerr)
		}
		for _, line := range bytes.Split(data, []byte{'\n'}) {
			if e := parseLine(line); e != nil {
				out = append(out, e)
			}
		}
	}
	return out, nil
}

// tailSegment returns up to limit entries from the END of one segment
// file, newest first. A missing segment yields (nil, nil).
func tailSegment(path string, limit int) ([]*Entry, error) {
	f, err := openSegmentNoFollow(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat journal segment: %w", err)
	}
	return tailScan(f, fi.Size(), limit)
}

// openSegmentNoFollow opens a journal segment for reading without following a
// symlinked final component (#9897 F-038) — the read-side twin of the
// O_NOFOLLOW + IsRegular discipline appendLocked already enforces. Without it
// a planted link makes `show system commit`/history render attacker-chosen
// JSONL as genuine history, while the append path correctly refuses the same
// link.
//
// Three checks, each load-bearing:
//
//   - Lstat pre-check: refuses deterministically, INCLUDING dangling links
//     (whose open fails ENOENT and would otherwise be skipped as a gap), and
//     names the link and its target. Message only, not enforcement.
//   - O_NOFOLLOW open: the kernel refuses a link swapped in after the Lstat,
//     so there is no TOCTOU window the way an Lstat-then-open would have (the
//     appendLocked doctrine). ELOOP — or any open failure on a path that is a
//     link — maps to the same refusal so the link+target invariant holds.
//   - O_NONBLOCK + fstat IsRegular: opening a FIFO O_RDONLY BLOCKS until a
//     writer appears, so a plain open hangs before Stat can refuse it (the
//     #6753 "or blocks" half). NONBLOCK is a no-op for regular files; the
//     fstat then refuses every non-regular descriptor (FIFO, device, socket,
//     directory) before a single byte is read.
//
// Absence passes through unwrapped so both callers keep mapping NotExist to a
// tolerated gap; every other failure returns final. Only the final component
// is constrained — a symlinked PARENT directory still works, matching the
// append path.
func openSegmentNoFollow(path string) (*os.File, error) {
	if fi, lerr := os.Lstat(path); lerr == nil && fi.Mode()&os.ModeSymlink != 0 {
		return nil, refuseSymlinkedSegment(path)
	}
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		if _, rerr := os.Readlink(path); rerr == nil {
			return nil, refuseSymlinkedSegment(path)
		}
		if os.IsNotExist(err) {
			return nil, err
		}
		return nil, fmt.Errorf("open journal segment: %w", err)
	}
	fi, serr := f.Stat()
	if serr != nil {
		f.Close()
		return nil, fmt.Errorf("stat journal segment: %w", serr)
	}
	if !fi.Mode().IsRegular() {
		mode := fi.Mode()
		f.Close()
		return nil, fmt.Errorf("journal segment %s is not a regular file (mode %s) — "+
			"refusing to read audit history from it", path, mode)
	}
	return f, nil
}

// refuseSymlinkedSegment reports that a journal segment path is a symlink. The
// refusal is LOUD (a Tail error, which every ListCommitHistory caller
// propagates) rather than a skip: silently omitting a linked segment would
// present partial history as complete, which for an audit trail is its own
// integrity hazard — and a planter with parent-dir write can already delete
// the journal outright, so erroring grants no new denial.
func refuseSymlinkedSegment(path string) error {
	target, rerr := os.Readlink(path)
	if rerr != nil {
		target = "<unreadable link target>"
	}
	return fmt.Errorf("journal segment %s is a symlink to %s — refusing to read "+
		"audit history through it", path, target)
}

// tailScan reads up to limit newline-terminated JSON entries from the
// end of r, newest first, reading backwards in readChunk-sized chunks.
// Lines longer than a chunk (legacy fat v1 entries) are assembled
// across chunks. Split out on (io.ReaderAt, size) so tests can prove
// boundedness with a counting reader.
func tailScan(r io.ReaderAt, size int64, limit int) ([]*Entry, error) {
	var entries []*Entry
	// pending holds the head fragment of the region processed so far:
	// a (possibly partial) line whose beginning may still be in an
	// earlier chunk, terminated by at most one '\n' at its end.
	var pending []byte
	// skipping means the line currently being assembled blew past
	// maxTailLineBytes (AGY plan-r1 F4); its bytes are discarded until
	// the scanner resyncs at the previous newline.
	skipping := false
	off := size
	for off > 0 && len(entries) < limit {
		n := int64(readChunk)
		if off < n {
			n = off
		}
		off -= n
		chunk := make([]byte, n)
		if _, err := r.ReadAt(chunk, off); err != nil {
			return nil, fmt.Errorf("read journal segment: %w", err)
		}
		buf := chunk
		if skipping {
			// Everything from the LAST newline onward belongs to the
			// poisoned over-cap line; drop it and resume normal
			// scanning on the bytes before it.
			ln := bytes.LastIndexByte(chunk, '\n')
			if ln < 0 {
				continue // whole chunk inside the poisoned line
			}
			buf = chunk[:ln+1]
			skipping = false
		} else if len(pending) > 0 {
			// File order: chunk precedes pending. chunk was allocated
			// with cap == len, so append copies — pending's backing
			// array is never aliased into a reused buffer.
			buf = append(chunk, pending...)
			pending = nil
		}
		// Lines fully contained in buf end at each '\n'; the bytes
		// before the first '\n' may continue in the previous chunk.
		nl := bytes.IndexByte(buf, '\n')
		if nl < 0 {
			pending = buf
		} else {
			complete := buf[nl+1:]
			pending = buf[:nl+1] // head fragment incl. its terminating '\n'
			lines := bytes.Split(complete, []byte{'\n'})
			for i := len(lines) - 1; i >= 0 && len(entries) < limit; i-- {
				if e := parseLine(lines[i]); e != nil {
					entries = append(entries, e)
				}
			}
		}
		// Cap check on EVERY pending update, not only the no-newline
		// path (AGY code-r1 F1): a fragment that retained its
		// terminating '\n' (e.g. an over-cap line that ends in a
		// newline) keeps satisfying IndexByte on later iterations and
		// would otherwise grow without bound.
		if len(pending) > maxTailLineBytes {
			pending = nil
			skipping = true
		}
	}
	// Whatever is left runs from offset 0: the file's first line (or
	// the whole file when it contains no newline at all).
	if len(pending) > 0 && len(entries) < limit {
		if e := parseLine(bytes.TrimSuffix(pending, []byte{'\n'})); e != nil {
			entries = append(entries, e)
		}
	}
	return entries, nil
}

// parseLine decodes one JSONL line; nil for blank or unparseable lines
// (torn tail, corruption — v1 had the same skip rule). Unknown fields —
// the legacy "before"/"after" config payloads — are ignored by
// encoding/json, which is the whole back-compat story: a fat v1 line
// decodes to its Timestamp/Action/Detail, exactly what the renderers
// print.
func parseLine(line []byte) *Entry {
	line = bytes.TrimSpace(line)
	if len(line) == 0 {
		return nil
	}
	e := &Entry{}
	if err := json.Unmarshal(line, e); err != nil {
		return nil
	}
	// An object that decodes but carries no action/timestamp is not a
	// journal entry (e.g. a stray "{}" from corruption) — drop it the
	// way v1's renderers would have shown garbage. Keep anything with
	// an action, even zero-timestamp, to stay tolerant of hand edits.
	if e.Action == "" && e.Timestamp.IsZero() {
		return nil
	}
	return e
}
