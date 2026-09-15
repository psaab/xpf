// Package fsatomic provides the project's two file-replacement writers
// (#1894): WriteFileAtomic (temp-in-same-dir + rename, namespace
// atomicity only) and WriteFileDurable (the same plus temp-file fsync
// and parent-directory fsync, so the replacement survives power loss).
//
// Persistence classes (see docs/engineering-style.md, "Persistence
// classes"):
//
//   - DurableState — must survive power loss (active config, rollback
//     history, rescue config, master.key, DHCPv6 DUID, frr.conf):
//     use WriteFileDurable.
//   - AtomicGeneratedConfig — regenerated on boot/apply; a torn file is
//     unacceptable but a lost-on-power-cut update is fine (swanctl,
//     Kea, networkd snippets): use WriteFileAtomic. This class exists
//     precisely so hot apply paths never pay an fsync.
//   - BestEffortKernelKnob — procfs/sysfs writes: keep direct
//     os.WriteFile; rename is impossible on those filesystems.
//
// Semantics shared by both writers (deliberate, reviewed in
// docs/pr/1893-configstore-durability/plan.md):
//
//   - The target INODE is replaced and perm is enforced on every write.
//     This differs from os.WriteFile over an existing file, which keeps
//     the existing inode's mode/owner. Pass WithPreserveExisting to
//     lift mode/ownership from an existing target instead (fchmod /
//     fchown on the temp fd, never a path race). Pass WithOwner(uid,
//     gid) to install the new inode already owned by a specific
//     user/group (fchown the temp fd before rename — required for
//     DurableState authorized_keys so a crash can never leave
//     root-owned keys sshd refuses). If both WithOwner and
//     WithPreserveExisting are set, owner = WithOwner's, mode =
//     preserved-existing's.
//   - A symlinked target is replaced by a regular file unless
//     WithResolveSymlinks is passed, in which case the write lands on
//     the resolved target (and, for WriteFileDurable, the directory
//     fsync targets the RESOLVED target's parent).
//   - Hardlinks: rename inherently breaks nlink>1 write-through — other
//     links keep the old inode. No call site in this project hardlinks
//     these files; documented rather than guarded.
//   - The temp file is removed on every failure path before rename.
//     After a crash, leaked ".<base>.tmp-*" temps are possible; writers
//     of frequently-rewritten files should sweep them (configstore's
//     NewDB does).
//
// Durability note: a WriteFileDurable error AFTER the rename (directory
// fsync failure) means the new content is visible in the namespace but
// its durability is unknown. Such a failure is returned as a typed
// *PostRenameSyncError (#5185) so a caller that keeps durable-on-disk
// state in lockstep with applied in-memory state (configstore commit)
// can DISTINGUISH it from a pre-rename failure: a pre-rename error leaves
// the OLD content intact (a clean rejection is correct), whereas the
// post-rename error leaves the NEW content visible — a restart would load
// it — so the caller must converge to the new content rather than report
// a plain rejection. Callers that only treat the write as failed still
// work unchanged: *PostRenameSyncError is a plain error whose Error()
// names the stage and whose Unwrap() exposes the underlying fsync error.
package fsatomic

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// PostRenameSyncError reports a WriteFileDurable failure that happened
// AFTER the rename succeeded — the parent-directory fsync failed (#5185).
// At this point the NEW content is already visible in the namespace (a
// reader, or a daemon restart, sees `data`); only its durability across
// power loss is unknown. This is categorically different from any
// pre-rename failure (create/write/chmod/chown/temp-fsync/close/rename),
// where the rename never happened and the OLD content is intact.
//
// A caller that must keep durable-on-disk state consistent with applied
// in-memory state — configstore Commit/CommitConfirmed — type-asserts on
// this via errors.As to CONVERGE to the new content (make memory/applied
// match what a restart would load) instead of returning a clean rejection
// while the new content is durable on disk. A caller that does not care
// treats it as an opaque error unchanged.
type PostRenameSyncError struct {
	// Path is the target the rename landed on (the new content is visible
	// here).
	Path string
	// Err is the underlying directory-fsync error.
	Err error
}

func (e *PostRenameSyncError) Error() string {
	return fmt.Sprintf("fsatomic: directory fsync after rename to %s failed: %v "+
		"(new content is visible; durability across power loss is unknown)", e.Path, e.Err)
}

// Unwrap exposes the underlying fsync error so errors.Is/As on the wrapped
// cause still works.
func (e *PostRenameSyncError) Unwrap() error { return e.Err }

type options struct {
	preserveExisting bool
	resolveSymlinks  bool
	owner            *ownerIDs
}

// Option configures WriteFileAtomic / WriteFileDurable.
type Option func(*options)

// WithPreserveExisting lifts mode and ownership from an existing target
// file instead of enforcing the caller's perm. Ownership is restored
// with fchown on the temp fd only when it actually differs from the
// temp file's owner; a chown failure is surfaced, never silently
// renamed over a differently-owned target (FRR #1883 semantics).
func WithPreserveExisting() Option {
	return func(o *options) { o.preserveExisting = true }
}

// WithOwner sets the owner (uid/gid) of the temp file via fchown on the
// open fd BEFORE the rename, so the final path is installed already
// correctly-owned — there is no post-rename chown race. This is the
// mechanism the DurableState authorized_keys writers need: a plain
// WriteFileDurable replaces the target inode with a root-owned temp, and
// a crash before a separate post-rename chown would leave root-owned
// 0600 keys that sshd refuses (EACCES → lockout). WithOwner closes that
// window by owning the inode atomically at install time.
//
// Precedence vs WithPreserveExisting: WithPreserveExisting may lift the
// MODE from an existing target, but an explicit WithOwner always WINS
// OWNERSHIP. If both are passed, owner = WithOwner's uid/gid, mode =
// the preserved-existing mode.
func WithOwner(uid, gid int) Option {
	return func(o *options) { o.owner = &ownerIDs{uid: uid, gid: gid} }
}

// WithResolveSymlinks resolves a symlinked path to its target before
// writing, so the rename replaces the real file rather than the link.
// A dangling symlink resolves to its (not-yet-existing) destination,
// matching what os.WriteFile through the link would have created.
func WithResolveSymlinks() Option {
	return func(o *options) { o.resolveSymlinks = true }
}

// Test seams (#1894 injected-failure tests). Production code must never
// mutate these.
var (
	createTemp = os.CreateTemp
	renameFile = os.Rename
	statFile   = os.Stat
	openDir    = os.Open
	writeTemp  = func(f *os.File, b []byte) (int, error) { return f.Write(b) }
	chmodTemp  = func(f *os.File, m os.FileMode) error { return f.Chmod(m) }
	chownTemp  = func(f *os.File, uid, gid int) error { return f.Chown(uid, gid) }
	syncFile   = func(f *os.File) error { return f.Sync() }
	closeTemp  = func(f *os.File) error { return f.Close() }

	// afterRenameSyncDir is the POST-rename directory-fsync seam (#5185).
	// It is separate from syncFile (which serves the pre-rename temp-file
	// fsync AND SyncDir) so a test can force the durability-sync failure
	// that occurs strictly AFTER a successful rename — the
	// PostRenameSyncError path — without also failing the pre-rename temp
	// fsync. Defaults to SyncDir; production code must never mutate it.
	afterRenameSyncDir = SyncDir
)

// WriteFileAtomic replaces path with data via create-temp-in-same-dir,
// write, fchmod, close-with-error-check, rename. Namespace atomicity
// only — NO fsync: after a power cut the rename may be lost or land on
// not-yet-flushed data. For the AtomicGeneratedConfig class.
func WriteFileAtomic(path string, data []byte, perm os.FileMode, opts ...Option) error {
	return writeFile(path, data, perm, false, opts...)
}

// WriteFileDurable is WriteFileAtomic plus an fsync of the temp file
// before the rename and an fsync of the (resolved) parent directory
// after it, making both the content and the namespace change durable
// across power loss. For the DurableState class.
func WriteFileDurable(path string, data []byte, perm os.FileMode, opts ...Option) error {
	return writeFile(path, data, perm, true, opts...)
}

// SyncDir fsyncs a directory, making previously-completed renames and
// unlinks inside it durable. Lets a multi-file shuffle (e.g. the
// configstore rollback-slot rewrite + stale-slot cleanup) batch its
// namespace durability into one fsync.
func SyncDir(dir string) error {
	d, err := openDir(dir)
	if err != nil {
		return fmt.Errorf("open dir %s: %w", dir, err)
	}
	defer d.Close()
	// Go's os.File.Sync routes through internal/poll.FD.Fsync, which
	// already retries EINTR (ignoringEINTR) — no extra loop needed.
	if err := syncFile(d); err != nil {
		return fmt.Errorf("fsync dir %s: %w", dir, err)
	}
	return nil
}

// MkdirAllDurable is os.MkdirAll plus an fsync of every directory whose
// entry set the call may have changed: each newly-created level and the
// deepest pre-existing ancestor (which gained the topmost new entry).
// Without this, a DurableState file written into a just-created
// directory can survive a power cut while the directory itself does not
// — fsyncing a file's parent (WriteFileDurable) persists the file's
// entry in that directory, not the directory's own entry in ITS parent
// (Codex code-r1 High on PR #1900). When the full path already exists
// this degrades to plain MkdirAll with zero fsyncs.
func MkdirAllDurable(dir string, perm os.FileMode) error {
	// Record the levels that do not exist yet, deepest first, before
	// creating anything. A racing creator only makes this list an
	// overestimate, which costs harmless extra fsyncs.
	var created []string
	p := filepath.Clean(dir)
	for {
		if _, err := os.Stat(p); err == nil {
			break
		}
		created = append(created, p)
		parent := filepath.Dir(p)
		if parent == p {
			break
		}
		p = parent
	}
	if err := os.MkdirAll(dir, perm); err != nil {
		return err
	}
	if len(created) == 0 {
		return nil
	}
	// Each new level's entry lives in its parent: fsync the new levels
	// (shallowest last is fine — order is irrelevant once all renames/
	// mkdirs have happened) plus the pre-existing ancestor p.
	for _, c := range created {
		if err := SyncDir(c); err != nil {
			return err
		}
	}
	return SyncDir(p)
}

// resolveSymlinkTarget returns the path the write should land on when
// symlink resolution is requested. EvalSymlinks succeeds only when the
// whole chain exists; for a *dangling* final symlink, fall back to
// Readlink so the write creates the link's destination (what writing
// through the link would have done). A non-symlink path is returned
// as-is. Lifted verbatim from pkg/frr's atomicWriteFile (#1883).
func resolveSymlinkTarget(path string) string {
	if resolved, err := filepath.EvalSymlinks(path); err == nil {
		return resolved
	}
	if linkDest, lerr := os.Readlink(path); lerr == nil {
		if filepath.IsAbs(linkDest) {
			return linkDest
		}
		return filepath.Join(filepath.Dir(path), linkDest)
	}
	return path
}

type ownerIDs struct {
	uid, gid int
}

func fileOwner(fi os.FileInfo) (ownerIDs, bool) {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return ownerIDs{}, false
	}
	return ownerIDs{uid: int(st.Uid), gid: int(st.Gid)}, true
}

func tempOwner(f *os.File) (ownerIDs, bool) {
	fi, err := f.Stat()
	if err != nil {
		return ownerIDs{}, false
	}
	return fileOwner(fi)
}

func writeFile(path string, data []byte, perm os.FileMode, durable bool, opts ...Option) error {
	var o options
	for _, opt := range opts {
		opt(&o)
	}

	target := path
	if o.resolveSymlinks {
		target = resolveSymlinkTarget(path)
	}

	mode := perm
	var (
		setOwner bool
		owner    ownerIDs
	)
	if o.preserveExisting {
		if fi, err := statFile(target); err == nil {
			mode = fi.Mode().Perm()
			if ids, ok := fileOwner(fi); ok {
				setOwner = true
				owner = ids
			}
		}
	}
	// WithOwner always wins ownership (explicit beats preserved-existing);
	// the mode lifted by WithPreserveExisting above is left untouched.
	if o.owner != nil {
		setOwner = true
		owner = *o.owner
	}

	dir := filepath.Dir(target)
	tmp, err := createTemp(dir, "."+filepath.Base(target)+".tmp-")
	if err != nil {
		return fmt.Errorf("create temp file in %s: %w", dir, err)
	}
	tmpName := tmp.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(tmpName)
		}
	}()

	n, err := writeTemp(tmp, data)
	if err != nil {
		_ = closeTemp(tmp)
		return fmt.Errorf("write temp file: %w", err)
	}
	// #9898 F-115: assert the write count. os.File.Write already reports a
	// short count as an error (os/file.go), so in production this is
	// defense-in-depth rather than a reachable truncation — but the seam
	// is the contract, and a seam that silently accepts n != len(data)
	// would install a truncated file with success returned. Fail here, so
	// the rename below can never publish a short temp over a good target.
	if n != len(data) {
		_ = closeTemp(tmp)
		return fmt.Errorf("write temp file: short write (%d of %d bytes with nil error) — "+
			"refusing to install a truncated file", n, len(data))
	}
	// Mode/ownership on the open fd (fchmod/fchown) before rename: the
	// final path never appears with a transient mode and there is no
	// path race on the temp name.
	if err := chmodTemp(tmp, mode); err != nil {
		_ = closeTemp(tmp)
		return fmt.Errorf("chmod temp file: %w", err)
	}
	if setOwner {
		if cur, ok := tempOwner(tmp); !ok || cur != owner {
			if err := chownTemp(tmp, owner.uid, owner.gid); err != nil {
				_ = closeTemp(tmp)
				return fmt.Errorf("chown temp file to %d:%d: %w", owner.uid, owner.gid, err)
			}
		}
	}
	if durable {
		// Flush data+metadata before the rename so the rename can never
		// surface a zero-length/partial file after power loss. EINTR is
		// retried inside the stdlib (internal/poll ignoringEINTR).
		if err := syncFile(tmp); err != nil {
			_ = closeTemp(tmp)
			return fmt.Errorf("sync temp file: %w", err)
		}
	}
	if err := closeTemp(tmp); err != nil {
		return fmt.Errorf("close temp file: %w", err)
	}
	if err := renameFile(tmpName, target); err != nil {
		return fmt.Errorf("rename %s -> %s: %w", tmpName, target, err)
	}
	cleanup = false
	if durable {
		// Make the rename itself durable. Uses the RESOLVED target's
		// parent — with WithResolveSymlinks the symlink's own directory
		// is irrelevant to where the namespace change happened. A failure
		// HERE is post-rename: the new content is already visible in the
		// namespace, so wrap it in *PostRenameSyncError (#5185) — the old
		// content is gone and a caller must not report a clean rejection.
		if err := afterRenameSyncDir(dir); err != nil {
			return &PostRenameSyncError{Path: target, Err: err}
		}
	}
	return nil
}
