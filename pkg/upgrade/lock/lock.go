// Package lock provides a host-wide advisory lock that serializes every
// mutating xpf upgrade operation on a single host (#1965).
//
// Background: the upgrade subsystem (pkg/upgrade, cmd/xpfd/upgrade*.go,
// debian/*) durably writes a crash-safe journal, repoints symlinks, and
// installs systemd drop-ins with NO host-local serialization. Two
// mutators racing (operator `xpfd upgrade` vs the Debian postinst cut, a
// binary cut vs `xpfd upgrade kernel arm`, a `--rolling` driver vs a local
// cut) silently corrupt that state: both loadJournal() the same snapshot,
// modify independent copies, and saveJournal() last-write-wins, losing the
// PreviousVersion / rollback target. Unlike a fixed-name temp-symlink
// collision (which errors cleanly via EEXIST), the journal race is silent.
//
// The fix is one host-wide advisory lock taken by every MUTATING upgrade
// entry point — binary cut, rolling driver, postinst cut, and the mutating
// `xpfd upgrade kernel` sub-verbs (arm/promote/drain/rejoin). Read-only
// status commands stay lock-free.
//
// Design:
//   - The lock is an exclusive non-blocking BSD advisory lock
//     (flock(2), LOCK_EX|LOCK_NB) on /run/xpf/upgrade.lock.
//   - /run is tmpfs and reboot-clearing, which is exactly right: the lock
//     guards against CONCURRENT mutators, while crash recovery is journal-
//     driven (the durable journal lives under /var/lib/xpf). A reboot that
//     interrupts an upgrade leaves no stale lock; the resume reads the
//     journal, not the lock.
//   - /run/xpf is created (mkdir -p) before the acquire — a fresh boot's
//     tmpfs may not have it yet.
//   - Owner metadata (PID, subcommand, target version/kernel, start time)
//     is written into the lock file AFTER the flock succeeds, so a busy
//     error can name the CURRENT owner instead of merely reporting "busy".
//   - flock is advisory and tied to the OPEN FILE DESCRIPTION, not the
//     path: a second open()+flock() on the same path returns EWOULDBLOCK
//     while another fd holds LOCK_EX. The lock is released by closing the
//     fd (Handle.Release), and the kernel also releases it on process
//     exit, so a crashed holder never wedges the host.
//
// Stale-owner-metadata correctness (#1984): the owner metadata is the only
// thing a busy acquirer reads to NAME the holder, and it is written AFTER
// the flock. Without care a busy acquirer can read a PREVIOUS owner's JSON
// as if it were the current holder's, misreporting a long-exited process.
// The mutual exclusion (the flock) is unaffected — this is diagnostics
// correctness. Two truncations, both performed WHILE THE FLOCK IS HELD,
// keep the file empty across the entire ownerless interval (best-effort: a
// truncate failure is logged/ignored, never failing acquire or release —
// the other truncate and the next acquirer's truncate are the backstops, so
// the worst case degrades to the pre-fix stale read, never a mutex fault):
//   - truncate-on-acquire: the instant AcquireAt holds the flock it
//     Truncate(0)s the file, so the acquire->write window (before the new
//     owner records its own metadata) and a swallowed metadata-write
//     failure both leave an EMPTY file rather than stale JSON. readOwner
//     returns nil on an empty file, so a concurrent busy reader degrades
//     to "busy, owner unknown".
//   - truncate-on-release-under-lock: Release Truncate(0)s the file BEFORE
//     dropping the flock, so the file is already empty the instant the
//     NEXT acquirer can flock it — closing the flock->truncate scheduling
//     gap that truncate-on-acquire alone would leave open.
//
// Both are f.Truncate(0) on the HELD fd. os.Remove is deliberately NOT
// used: flock binds the inode (open file description), so unlinking the
// path while another fd has it open / awaits it lets a fresh O_CREAT
// acquirer flock a DIFFERENT inode — a split mutex (the #1875 "never rm
// the lock file" lesson). /run is tmpfs (reboot-clearing), so a lingering
// zero-length lock file is harmless.
package lock

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/unix"
)

// DefaultPath is the host-wide upgrade lock file. /run is tmpfs (reboot-
// clearing) — see the package doc for why that is correct.
const DefaultPath = "/run/xpf/upgrade.lock"

// Owner is the metadata persisted into the lock file by the current
// holder. It is written after the flock succeeds and read back by a
// would-be acquirer so a busy error names the owner.
type Owner struct {
	// PID is the holding process id.
	PID int `json:"pid"`
	// Subcommand is the mutating operation, e.g. "upgrade",
	// "upgrade --rolling", "upgrade kernel arm".
	Subcommand string `json:"subcommand"`
	// Target is the target version or kernel (best-effort, may be empty
	// when not yet known at acquire time).
	Target string `json:"target,omitempty"`
	// StartedAt is when the holder acquired the lock.
	StartedAt time.Time `json:"started_at"`
}

func (o Owner) String() string {
	tgt := o.Target
	if tgt == "" {
		tgt = "(unknown)"
	}
	return fmt.Sprintf("pid=%d subcommand=%q target=%s started=%s",
		o.PID, o.Subcommand, tgt, o.StartedAt.Format(time.RFC3339))
}

// Handle is a held upgrade lock. Release MUST be called (via defer) on
// every exit path — normal, error, and panic — to drop the lock; the
// kernel also drops it on process exit as a backstop.
type Handle struct {
	f        *os.File
	released bool
}

// ErrBusy is returned by Acquire when another process holds the lock. The
// error text names the current owner (read from the lock file) when it is
// readable.
type ErrBusy struct {
	Path  string
	Owner *Owner // nil if owner metadata could not be read
}

func (e *ErrBusy) Error() string {
	if e.Owner != nil {
		return fmt.Sprintf("another upgrade is in progress (holds %s): %s",
			e.Path, e.Owner.String())
	}
	return fmt.Sprintf("another upgrade is in progress (holds %s; owner metadata unavailable)", e.Path)
}

// IsBusy reports whether err is (or wraps) an ErrBusy.
func IsBusy(err error) bool {
	var b *ErrBusy
	return errors.As(err, &b)
}

// Acquire takes the host-wide upgrade lock at DefaultPath, returning a
// Handle whose Release drops it. It is a non-blocking exclusive flock: if
// another process holds the lock, it returns an *ErrBusy naming the owner.
//
// On success Acquire returns (handle, nil): once the flock is held, the
// returned error is always nil. The owner metadata (PID, subcommand,
// target, start time) is recorded in the lock file best-effort AFTER the
// flock succeeds; a metadata-write failure is logged to stderr and never
// surfaced as an Acquire error (it would otherwise tempt callers to discard
// the held handle and leak the fd). A nil error therefore unambiguously
// means "lock held".
func Acquire(subcommand, target string) (*Handle, error) {
	return AcquireAt(DefaultPath, subcommand, target)
}

// AcquireAt is Acquire against an explicit path (for tests; production
// always uses DefaultPath via Acquire).
//
// #16050: the parent directory is created 0750 and the lock file 0600,
// and both modes are asserted (chmod) on every acquire — creation mode
// alone is insufficient because a shell first-creator (debian/xpf.preinst
// `mkdir -p` + flock(1)) may have created them 0755/0644 under a permissive
// umask. On Linux an exclusive flock can be taken on a readable O_RDONLY
// fd, so a world-readable lock file in a world-traversable directory lets
// any local user block every upgrade indefinitely. The chmod runs before
// the flock: a chmod failure while we do not yet hold the lock must refuse
// the acquire rather than proceed on a lock an unprivileged user can also
// take.
func AcquireAt(path, subcommand, target string) (*Handle, error) {
	// /run is tmpfs and may lack our subdir on a fresh boot.
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return nil, fmt.Errorf("upgrade lock: create %s: %w", dir, err)
	}
	if err := os.Chmod(dir, 0o750); err != nil {
		return nil, fmt.Errorf("upgrade lock: tighten %s to 0750: %w", dir, err)
	}

	// O_CREATE so the first acquirer makes the file; no O_TRUNC so a busy
	// acquirer can still read the holder's metadata.
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, fmt.Errorf("upgrade lock: open %s: %w", path, err)
	}
	// Assert 0600 on use as well as at creation (see doc above): the file
	// may pre-exist 0644 from a shell first-creator.
	if err := f.Chmod(0o600); err != nil {
		f.Close()
		return nil, fmt.Errorf("upgrade lock: tighten %s to 0600: %w", path, err)
	}

	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		// Busy (EWOULDBLOCK) — read the holder's metadata so the error
		// names the owner. Any read failure degrades to a nil Owner.
		owner := readOwner(f)
		f.Close()
		if errors.Is(err, unix.EWOULDBLOCK) {
			return nil, &ErrBusy{Path: path, Owner: owner}
		}
		return nil, fmt.Errorf("upgrade lock: flock %s: %w", path, err)
	}

	h := &Handle{f: f}

	// We hold the flock. Zero the file IMMEDIATELY, before recording our own
	// metadata (#1984). Any concurrent busy reader that races into the
	// acquire->write window now sees an EMPTY file (readOwner returns nil),
	// degrading to "busy, owner unknown" rather than naming the PREVIOUS
	// owner. This also closes the write-failure window below: if writeOwnerFn
	// fails, the file is already empty instead of holding stale JSON. The
	// truncate is on the HELD fd, so no concurrent writer can race it. It is
	// non-fatal — the lock is the flock, not the file contents — so a failure
	// is logged and execution continues (writeOwner's own Truncate(0) retries
	// the clear, and a Release-time truncate is the final backstop).
	if terr := f.Truncate(0); terr != nil {
		fmt.Fprintf(os.Stderr,
			"upgrade lock: held %s but failed to clear stale owner metadata: %v\n",
			path, terr)
	}

	// We hold the lock — record owner metadata. Truncate first so a stale
	// (larger) prior record never leaves trailing bytes. The metadata write
	// is TRULY best-effort: a write failure is non-fatal to holding the lock
	// (the lock is the flock, not the file contents), so we must NOT return a
	// non-nil error here. Callers uniformly treat a non-nil Acquire error as
	// "lock not held" and return WITHOUT deferring Release — returning the
	// held handle alongside an error would leak the held fd until process
	// exit (Codex MAJOR #1). Instead we swallow the write error and log it to
	// stderr; the busy path then simply degrades to a nil Owner (busy, owner
	// unknown). The flock — the actual mutual exclusion — is fully held.
	if werr := writeOwnerFn(f, Owner{
		PID:        os.Getpid(),
		Subcommand: subcommand,
		Target:     target,
		StartedAt:  time.Now(),
	}); werr != nil {
		fmt.Fprintf(os.Stderr,
			"upgrade lock: held %s but failed to record owner metadata (busy errors will not name this owner): %v\n",
			path, werr)
	}
	return h, nil
}

// Release drops the lock and closes the fd. It is idempotent and safe to
// call from a defer on every path (normal, error, panic). Closing the fd
// releases the flock; the kernel also releases on process exit.
func (h *Handle) Release() error {
	if h == nil || h.released {
		return nil
	}
	h.released = true
	// Zero the file BEFORE dropping the flock (#1984). The next acquirer can
	// only flock this inode after we LOCK_UN/Close, so truncating here means
	// the file is already empty the instant ownership becomes available —
	// closing the flock->truncate scheduling gap that truncate-on-acquire
	// alone would leave (a racing reader in the next owner's acquire->write
	// window would otherwise read OUR now-stale metadata). We still hold the
	// flock, so no concurrent writer can race this truncate. This is
	// f.Truncate(0) on the HELD fd, NOT os.Remove: unlinking the path would
	// let a fresh O_CREAT acquirer flock a different inode and split the
	// mutex (the #1875 lesson). The truncate error is ignored — release must
	// not fail on a best-effort metadata clear, and the kernel drops the
	// flock on Close regardless. We still log a failure so an operator can
	// see the (rare) case where the next owner's busy errors could name us.
	if terr := h.f.Truncate(0); terr != nil {
		fmt.Fprintf(os.Stderr,
			"upgrade lock: failed to clear owner metadata on release (the next owner's busy errors may briefly name this one): %v\n",
			terr)
	}
	// releaseUnlockFn is the seam through which Release drops the flock. It
	// runs AFTER the truncate and BEFORE Close, so a test can assert the file
	// is already empty at the instant ownership is about to be handed off —
	// proving the truncate happened under the held flock (not after unlock).
	releaseUnlockFn(h.f)
	return h.f.Close()
}

// releaseUnlockFn drops the flock during Release. Production uses
// releaseUnlock (an explicit LOCK_UN); tests substitute a hook that first
// asserts the file is already empty, proving Release truncates BEFORE it
// unlocks (i.e. while the flock is still held).
var releaseUnlockFn = releaseUnlock

// releaseUnlock drops the BSD advisory lock. Explicit LOCK_UN is redundant
// with the Close that follows (closing the fd releases the lock tied to the
// open file description) but makes the release intent obvious; its error is
// ignored since Close is the authoritative drop.
func releaseUnlock(f *os.File) {
	_ = unix.Flock(int(f.Fd()), unix.LOCK_UN)
}

// writeOwnerFn is the seam through which AcquireAt records owner metadata.
// Production uses writeOwner; tests substitute a failing writer to prove the
// best-effort contract (a metadata-write failure still yields a held lock and
// a nil Acquire error).
var writeOwnerFn = writeOwner

// writeOwner truncates the lock file and writes the owner metadata as
// pretty JSON. The fd already holds the flock.
func writeOwner(f *os.File, o Owner) error {
	data, err := json.MarshalIndent(o, "", "  ")
	if err != nil {
		return err
	}
	if err := f.Truncate(0); err != nil {
		return err
	}
	if _, err := f.WriteAt(data, 0); err != nil {
		return err
	}
	// Best-effort durability; the lock's correctness does not depend on the
	// metadata reaching disk (tmpfs anyway).
	_ = f.Sync()
	return nil
}

// readOwner reads and parses the owner metadata from an open lock file.
// Returns nil on any read/parse failure (degrade to "busy, owner unknown").
func readOwner(f *os.File) *Owner {
	data, err := os.ReadFile(f.Name())
	if err != nil || len(data) == 0 {
		return nil
	}
	var o Owner
	if err := json.Unmarshal(data, &o); err != nil {
		return nil
	}
	return &o
}
