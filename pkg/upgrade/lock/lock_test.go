package lock

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// lockPath returns a short tmpdir lock path. We deliberately avoid /dev/shm
// TMPDIR collisions; t.TempDir() is process-scoped and cleaned per test.
func lockPath(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "upgrade.lock")
}

func TestAcquireAndRelease(t *testing.T) {
	p := lockPath(t)
	h, err := AcquireAt(p, "upgrade", "1.2.3")
	if err != nil {
		t.Fatalf("first acquire: %v", err)
	}

	// The lock file must carry the owner metadata.
	data, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("read lock file: %v", err)
	}
	if !strings.Contains(string(data), `"subcommand": "upgrade"`) ||
		!strings.Contains(string(data), `"target": "1.2.3"`) {
		t.Fatalf("owner metadata missing/incorrect: %s", data)
	}

	if err := h.Release(); err != nil {
		t.Fatalf("release: %v", err)
	}
	// Release is idempotent.
	if err := h.Release(); err != nil {
		t.Fatalf("second release should be a no-op: %v", err)
	}

	// After release the lock is reacquirable.
	h2, err := AcquireAt(p, "upgrade", "1.2.4")
	if err != nil {
		t.Fatalf("reacquire after release: %v", err)
	}
	_ = h2.Release()
}

func TestSecondAcquireIsBusy(t *testing.T) {
	p := lockPath(t)
	h, err := AcquireAt(p, "upgrade --rolling", "2.0.0")
	if err != nil {
		t.Fatalf("first acquire: %v", err)
	}
	defer h.Release()

	// flock is tied to the open file description; a second open()+flock()
	// on the SAME path from the SAME process still returns EWOULDBLOCK.
	_, err = AcquireAt(p, "upgrade", "2.0.1")
	if err == nil {
		t.Fatal("second acquire should fail while the lock is held")
	}
	if !IsBusy(err) {
		t.Fatalf("second acquire should be ErrBusy, got %T: %v", err, err)
	}
	// The busy error must NAME the owner, not just say "busy".
	if !strings.Contains(err.Error(), "rolling") || !strings.Contains(err.Error(), "2.0.0") {
		t.Fatalf("busy error should name the owner subcommand/target: %v", err)
	}
}

func TestReleaseOnPanicViaDefer(t *testing.T) {
	p := lockPath(t)

	func() {
		defer func() {
			_ = recover()
		}()
		h, err := AcquireAt(p, "upgrade", "panic-test")
		if err != nil {
			t.Fatalf("acquire: %v", err)
		}
		defer h.Release() // must run on panic unwind
		panic("boom")
	}()

	// After the panic unwound through the deferred Release, the lock is
	// reacquirable.
	h, err := AcquireAt(p, "upgrade", "after-panic")
	if err != nil {
		t.Fatalf("lock not released after panic: %v", err)
	}
	_ = h.Release()
}

func TestReleaseOnErrorPath(t *testing.T) {
	p := lockPath(t)

	// Simulate a mutator that acquires, hits an error, and returns through
	// a deferred Release.
	run := func() (err error) {
		h, aerr := AcquireAt(p, "upgrade", "err-test")
		if aerr != nil {
			return aerr
		}
		defer h.Release()
		return os.ErrInvalid // simulated downstream error
	}
	if err := run(); err == nil {
		t.Fatal("expected the simulated error to propagate")
	}
	// Lock must be free now.
	h, err := AcquireAt(p, "upgrade", "after-err")
	if err != nil {
		t.Fatalf("lock not released after error path: %v", err)
	}
	_ = h.Release()
}

// TestReleaseOnProcessExit proves the kernel drops the flock when the
// holding PROCESS exits even without an explicit Release — the crash
// backstop. A child process acquires the lock and exits; the parent then
// acquires it.
func TestReleaseOnProcessExit(t *testing.T) {
	if os.Getenv("XPF_LOCK_CHILD") == "1" {
		// Child: acquire and exit immediately WITHOUT releasing.
		p := os.Getenv("XPF_LOCK_PATH")
		if _, err := AcquireAt(p, "upgrade", "child"); err != nil {
			os.Exit(2)
		}
		os.Exit(0)
	}

	p := lockPath(t)
	cmd := exec.Command(os.Args[0], "-test.run", "TestReleaseOnProcessExit")
	cmd.Env = append(os.Environ(), "XPF_LOCK_CHILD=1", "XPF_LOCK_PATH="+p)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("child failed to acquire/exit: %v\n%s", err, out)
	}

	// Child has exited; the kernel released its flock. We can acquire.
	deadline := time.Now().Add(2 * time.Second)
	for {
		h, err := AcquireAt(p, "upgrade", "parent")
		if err == nil {
			_ = h.Release()
			return
		}
		if !IsBusy(err) {
			t.Fatalf("unexpected acquire error: %v", err)
		}
		if time.Now().After(deadline) {
			t.Fatalf("lock not released after child exit within deadline")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// TestMetadataWriteFailureStillHoldsLock proves the best-effort contract
// (Codex MAJOR #1): when recording owner metadata fails, Acquire must STILL
// return a held lock with a NIL error, because callers treat a non-nil
// Acquire error as "lock not held" and return WITHOUT deferring Release — a
// (held handle, non-nil error) pair would leak the fd until process exit.
func TestMetadataWriteFailureStillHoldsLock(t *testing.T) {
	p := lockPath(t)

	prev := writeOwnerFn
	writeOwnerFn = func(*os.File, Owner) error {
		return os.ErrInvalid // force the metadata write to fail
	}
	t.Cleanup(func() { writeOwnerFn = prev })

	h, err := AcquireAt(p, "upgrade", "meta-fail")
	if err != nil {
		t.Fatalf("metadata-write failure must NOT fail Acquire (would tempt callers to leak the held fd); got err=%v", err)
	}
	if h == nil {
		t.Fatal("Acquire returned a nil handle on a successful flock")
	}

	// The lock must genuinely be held: a second acquire is busy. Restore the
	// real writer first so the busy probe behaves normally.
	writeOwnerFn = prev
	if _, err2 := AcquireAt(p, "upgrade", "second"); !IsBusy(err2) {
		t.Fatalf("lock not actually held after a metadata-write failure; second acquire err=%v", err2)
	}

	// Releasing the held handle frees the lock.
	if rerr := h.Release(); rerr != nil {
		t.Fatalf("release: %v", rerr)
	}
	h2, err := AcquireAt(p, "upgrade", "after-release")
	if err != nil {
		t.Fatalf("reacquire after release: %v", err)
	}
	_ = h2.Release()
}

// staleOwnerJSON is a plausible previous-owner record used to seed the lock
// file in the stale-read regression tests. It mimics what a crashed holder
// (kernel-released flock, file never truncated) leaves behind.
const staleOwnerJSON = `{
  "pid": 424242,
  "subcommand": "upgrade --rolling",
  "target": "9.9.9-stale",
  "started_at": "2000-01-01T00:00:00Z"
}`

// TestReleaseTruncatesUnderLock proves Release zeroes the lock file BEFORE
// dropping the flock (#1984), and that it does so WHILE THE FLOCK IS STILL
// HELD (not merely "empty after Release returns"). After a normal
// acquire+release the file must be empty so the NEXT acquirer's busy readers
// never name the just-released owner. This test FAILS if the release-time
// Truncate(0) is removed — the file would still hold the released owner's
// JSON — AND, via the releaseUnlockFn seam, FAILS if the truncate were
// reordered to AFTER the flock drop (a plain "read after Release" assertion
// could not catch that reordering — Codex review #1995).
func TestReleaseTruncatesUnderLock(t *testing.T) {
	p := lockPath(t)

	h, err := AcquireAt(p, "upgrade", "1.0.0")
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	// Sanity: while held, the file carries this owner's metadata.
	if data, rerr := os.ReadFile(p); rerr != nil || len(data) == 0 {
		t.Fatalf("held lock file should carry owner metadata; len=%d err=%v", len(data), rerr)
	}

	// Intercept the flock drop: at the instant Release is about to unlock, the
	// truncate must already have run (file empty) — proving the truncate is
	// under the held flock, before the next acquirer can ever flock the inode.
	prevUnlock := releaseUnlockFn
	var emptyAtUnlock, unlockSeen bool
	releaseUnlockFn = func(f *os.File) {
		unlockSeen = true
		if data, rerr := os.ReadFile(f.Name()); rerr == nil && len(data) == 0 {
			emptyAtUnlock = true
		}
		prevUnlock(f)
	}
	t.Cleanup(func() { releaseUnlockFn = prevUnlock })

	if rerr := h.Release(); rerr != nil {
		t.Fatalf("release: %v", rerr)
	}
	if !unlockSeen {
		t.Fatal("releaseUnlockFn was not invoked — Release no longer drops the flock through the seam")
	}
	if !emptyAtUnlock {
		t.Fatal("Release dropped the flock with the file still non-empty — the truncate must run BEFORE unlock, under the held flock")
	}
	releaseUnlockFn = prevUnlock

	// The released file must be empty (the inode is kept; only contents are
	// cleared). os.Remove is intentionally NOT used, so the file still exists.
	data, rerr := os.ReadFile(p)
	if rerr != nil {
		t.Fatalf("lock file should still exist after release (os.Remove must NOT be used): %v", rerr)
	}
	if len(data) != 0 {
		t.Fatalf("release must truncate the lock file under the flock; file still holds %d bytes: %q", len(data), data)
	}

	// Cross-check the diagnostic consequence: a fresh busy reader sees no
	// owner. Hold the lock again and probe it from a second acquire.
	h2, err := AcquireAt(p, "upgrade", "2.0.0")
	if err != nil {
		t.Fatalf("reacquire after release: %v", err)
	}
	defer h2.Release()
	// h2 has written its OWN metadata by now, so a busy probe names h2 — that
	// is correct (current holder), not the released owner. Confirm it never
	// names the released "1.0.0".
	_, berr := AcquireAt(p, "upgrade", "3.0.0")
	if !IsBusy(berr) {
		t.Fatalf("expected busy, got %v", berr)
	}
	if strings.Contains(berr.Error(), "1.0.0") {
		t.Fatalf("busy error named the RELEASED owner instead of the current holder: %v", berr)
	}
}

// TestAcquireTruncatesStaleMetadataBeforeWrite proves the acquire-time
// Truncate(0) (#1984): a NEW holder zeroes the file the instant it holds the
// flock, BEFORE recording its own metadata, so a concurrent busy reader in
// the acquire->write window never reads a PREVIOUS owner's JSON.
//
// The file is seeded directly with stale JSON (simulating a crashed holder
// whose flock the kernel released but whose metadata was never cleared — the
// case the release-truncate cannot cover). A blocking writeOwnerFn seam pins
// the new holder between the acquire-truncate and the metadata write while a
// second acquire probes the file.
//
// This test FAILS if the acquire-time Truncate(0) is removed: the seeded
// stale owner would still be in the file when the probe reads it, so ErrBusy
// would name pid=424242 / "9.9.9-stale".
func TestAcquireTruncatesStaleMetadataBeforeWrite(t *testing.T) {
	p := lockPath(t)

	// Seed stale metadata as if a crashed prior holder left it. Create the
	// file with no flock held so the new holder below can acquire it.
	if err := os.WriteFile(p, []byte(staleOwnerJSON), 0o644); err != nil {
		t.Fatalf("seed stale metadata: %v", err)
	}

	entered := make(chan struct{})
	release := make(chan struct{})
	// unblock frees the blocked holder goroutine. Wrapped in sync.Once so the
	// happy-path close and the t.Cleanup safety close are both safe — without
	// the deferred cleanup a t.Fatalf before the happy-path close would leak
	// the goroutine blocked on <-release (Codex/AGY review #1995).
	var unblockOnce sync.Once
	unblock := func() { unblockOnce.Do(func() { close(release) }) }
	t.Cleanup(unblock)

	prev := writeOwnerFn
	writeOwnerFn = func(f *os.File, o Owner) error {
		// We are now PAST the acquire-truncate and the flock is held. Signal
		// the probe, then block before writing this holder's metadata so the
		// probe observes the acquire->write window.
		close(entered)
		<-release
		return prev(f, o)
	}
	t.Cleanup(func() { writeOwnerFn = prev })

	acquired := make(chan *Handle, 1)
	acqErr := make(chan error, 1)
	go func() {
		h, err := AcquireAt(p, "upgrade", "new-holder")
		if err != nil {
			acqErr <- err
			return
		}
		acquired <- h
	}()

	select {
	case <-entered:
	case err := <-acqErr:
		t.Fatalf("new holder failed to acquire: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for the new holder to enter writeOwner")
	}

	// The new holder now HOLDS the flock and has run the acquire-truncate but
	// has NOT yet written its metadata. Probe it: ErrBusy with a NIL owner.
	_, berr := AcquireAt(p, "upgrade", "probe")
	if !IsBusy(berr) {
		t.Fatalf("expected ErrBusy during acquire->write window, got %T: %v", berr, berr)
	}
	var be *ErrBusy
	if !errors.As(berr, &be) {
		t.Fatalf("expected *ErrBusy, got %T: %v", berr, berr)
	}
	if be.Owner != nil {
		t.Fatalf("busy read in the acquire->write window must NOT name an owner; got %s", be.Owner.String())
	}
	// Specifically: it must never report the seeded stale owner.
	if strings.Contains(berr.Error(), "424242") || strings.Contains(berr.Error(), "9.9.9-stale") {
		t.Fatalf("acquire-truncate failed: busy read named the STALE previous owner: %v", berr)
	}

	// Let the new holder finish writing its metadata, then confirm a busy
	// read now correctly names IT.
	unblock()
	select {
	case h := <-acquired:
		defer h.Release()
	case err := <-acqErr:
		t.Fatalf("new holder acquire returned error after unblock: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for the new holder to finish acquiring")
	}
	_, berr2 := AcquireAt(p, "upgrade", "probe2")
	if !IsBusy(berr2) {
		t.Fatalf("expected busy after metadata written, got %v", berr2)
	}
	if !strings.Contains(berr2.Error(), "new-holder") {
		t.Fatalf("busy error should now name the new holder; got %v", berr2)
	}
}

// TestAcquireClearsStaleMetadataOnWriteFailure proves window 2 (#1984): when
// the metadata write fails AFTER the acquire-truncate, the file is left EMPTY
// (already cleared by the acquire-truncate) rather than holding the previous
// owner's JSON. A busy read therefore degrades to "owner unknown", never the
// stale owner.
//
// This test FAILS if the acquire-time Truncate(0) is removed: with a failing
// writeOwnerFn the seeded stale JSON would survive and a busy read would name
// it.
func TestAcquireClearsStaleMetadataOnWriteFailure(t *testing.T) {
	p := lockPath(t)

	if err := os.WriteFile(p, []byte(staleOwnerJSON), 0o644); err != nil {
		t.Fatalf("seed stale metadata: %v", err)
	}

	prev := writeOwnerFn
	writeOwnerFn = func(*os.File, Owner) error {
		return os.ErrInvalid // fail the metadata write AFTER acquire-truncate
	}
	t.Cleanup(func() { writeOwnerFn = prev })

	h, err := AcquireAt(p, "upgrade", "write-fails")
	if err != nil {
		// Best-effort contract: a metadata-write failure must NOT fail Acquire.
		t.Fatalf("metadata-write failure must not fail Acquire: %v", err)
	}
	defer h.Release()

	// The on-disk file must be empty: the acquire-truncate cleared the stale
	// JSON and the failed write left nothing behind.
	data, rerr := os.ReadFile(p)
	if rerr != nil {
		t.Fatalf("read lock file: %v", rerr)
	}
	if len(data) != 0 {
		t.Fatalf("acquire-truncate should have cleared stale metadata before the failed write; file holds %d bytes: %q", len(data), data)
	}

	// Restore the real writer so the busy probe behaves normally, then confirm
	// a busy read reports owner-unknown, NOT the seeded stale owner.
	writeOwnerFn = prev
	_, berr := AcquireAt(p, "upgrade", "probe")
	if !IsBusy(berr) {
		t.Fatalf("expected busy, got %v", berr)
	}
	if strings.Contains(berr.Error(), "424242") || strings.Contains(berr.Error(), "9.9.9-stale") {
		t.Fatalf("write-failure path leaked the stale owner into the busy error: %v", berr)
	}
	var be *ErrBusy
	if errors.As(berr, &be) && be.Owner != nil {
		t.Fatalf("busy read after a swallowed write failure must report owner-unknown; got %s", be.Owner.String())
	}
}

func TestMkdirCreatesRunDir(t *testing.T) {
	// Point at a nested non-existent dir; Acquire must mkdir -p it.
	p := filepath.Join(t.TempDir(), "xpf", "nested", "upgrade.lock")
	h, err := AcquireAt(p, "upgrade", "mkdir")
	if err != nil {
		t.Fatalf("acquire should create the parent dir: %v", err)
	}
	defer h.Release()
	if _, err := os.Stat(filepath.Dir(p)); err != nil {
		t.Fatalf("parent dir not created: %v", err)
	}
}

// TestAcquireTightensPermissiveModes16050 is the #16050 regression: a
// pre-existing 0755 parent + 0644 lock file (the shell first-creator shape:
// debian/xpf.preinst `mkdir -p` + flock(1) under umask 022) must be
// tightened to 0750/0600 on acquire, and a fresh acquire under umask 0
// must still land 0750/0600. On Linux flock(LOCK_EX) succeeds on a
// readable O_RDONLY fd, so the pre-fix 0755/0644 pair let any local user
// block every upgrade; these mode assertions are that check, made
// without needing a second uid.
//
// RED-on-revert: restoring MkdirAll(0o755)/OpenFile(0o644) without the
// chmods leaves the seeded modes untouched (first subtest) and lands
// 0755/0644 under umask 0 (second subtest); restoring only the file
// chmod still fails the dir assertion.
func TestAcquireTightensPermissiveModes16050(t *testing.T) {
	assertModes := func(t *testing.T, dir, path string) {
		t.Helper()
		if fi, err := os.Stat(dir); err != nil {
			t.Fatalf("stat dir: %v", err)
		} else if got := fi.Mode().Perm(); got != 0o750 {
			t.Fatalf("lock dir mode = %04o, want 0750 (#16050)", got)
		}
		if fi, err := os.Stat(path); err != nil {
			t.Fatalf("stat lock: %v", err)
		} else if got := fi.Mode().Perm(); got != 0o600 {
			t.Fatalf("lock file mode = %04o, want 0600 (#16050)", got)
		}
	}

	t.Run("pre-existing permissive modes are tightened", func(t *testing.T) {
		dir := filepath.Join(t.TempDir(), "xpf")
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		p := filepath.Join(dir, "upgrade.lock")
		if err := os.WriteFile(p, []byte("stale"), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(p, 0o644); err != nil {
			t.Fatal(err)
		}
		h, err := AcquireAt(p, "upgrade", "perms")
		if err != nil {
			t.Fatalf("acquire over permissive modes: %v", err)
		}
		defer h.Release()
		assertModes(t, dir, p)
	})

	t.Run("fresh create under umask zero lands tight", func(t *testing.T) {
		old := syscall.Umask(0)
		defer syscall.Umask(old)
		p := filepath.Join(t.TempDir(), "xpf", "upgrade.lock")
		h, err := AcquireAt(p, "upgrade", "perms")
		if err != nil {
			t.Fatalf("acquire: %v", err)
		}
		defer h.Release()
		assertModes(t, filepath.Dir(p), p)
	})
}

// firstUntraversableAncestor reports the first pre-existing ancestor,
// from filesystem root toward root, that the nobody probe cannot traverse.
// It tests execute access as the actual probe identity because ownership,
// group membership, and ACLs can make mode-bit-only checks inaccurate.
func firstUntraversableAncestor(root, setpriv string) (string, error) {
	testPath, err := exec.LookPath("test")
	if err != nil {
		return "", fmt.Errorf("find test command for nobody traversal probe: %w", err)
	}
	var ancestors []string
	for anc := root; ; anc = filepath.Dir(anc) {
		ancestors = append(ancestors, anc)
		if filepath.Dir(anc) == anc {
			break
		}
	}
	for i := len(ancestors) - 1; i >= 0; i-- {
		out, err := exec.Command(setpriv, "--reuid=nobody", "--regid=nogroup",
			"--clear-groups", testPath, "-x", ancestors[i]).CombinedOutput()
		if err == nil {
			continue
		}
		if i == len(ancestors)-1 {
			return "", fmt.Errorf("nobody traversal probe failed for filesystem root (%v, %q)", err, out)
		}
		return ancestors[i], nil
	}
	return "", nil
}

func skipIfUntraversableAncestor(t *testing.T, root, setpriv string) {
	t.Helper()
	ancestor, err := firstUntraversableAncestor(root, setpriv)
	if err != nil {
		t.Fatalf("check pre-existing ancestor traversability: %v", err)
	}
	if ancestor != "" {
		t.Skipf("root/nobody flock probe skipped: pre-existing ancestor %s is not traversable by nobody (#17756)", ancestor)
	}
}

// TestSkipRootProbeForUntraversableAncestor17756 runs the actual #16050
// test in a child test process whose temp root is intentionally private.
// Removing the skip call from that test makes the child fail in the
// permissive control probe instead of reporting the expected skip.
func TestSkipRootProbeForUntraversableAncestor17756(t *testing.T) {
	if _, err := exec.LookPath("setpriv"); err != nil || os.Geteuid() != 0 {
		t.Skip("requires root and setpriv to exercise the nobody probe")
	}
	root, err := os.MkdirTemp("/tmp", "xpf-lock-17756-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(root)
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}

	env := make([]string, 0, len(os.Environ())+2)
	for _, entry := range os.Environ() {
		if strings.HasPrefix(entry, "TMPDIR=") || strings.HasPrefix(entry, "GOTMPDIR=") {
			continue
		}
		env = append(env, entry)
	}
	env = append(env, "TMPDIR="+root, "GOTMPDIR="+root)
	cmd := exec.Command(os.Args[0], "-test.run=^TestUnprivilegedCannotFlockUpgradeLock16050$", "-test.v")
	cmd.Env = env
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("root-arm child failed instead of skipping (%v, %q)", err, out)
	}
	output := string(out)
	if !strings.Contains(output, "--- SKIP: TestUnprivilegedCannotFlockUpgradeLock16050") ||
		!strings.Contains(output, "root/nobody flock probe skipped: pre-existing ancestor "+root) {
		t.Fatalf("root-arm child did not report the expected skip for %s: %q", root, output)
	}
	fi, err := os.Stat(root)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o700 {
		t.Fatalf("pre-existing temp root mode changed: got %04o, want 0700", fi.Mode().Perm())
	}
}

// openTestOwnedAncestors makes the directories this test created under
// its dedicated temp root traversable (0755). It walks from base up to,
// but NOT including, root — both created by t.TempDir()/os.MkdirTemp
// for this test — and chmods only those. Pre-existing ancestors above
// root (the GOTMPDIR/os.TempDir() root and everything above it) are
// never touched (#16720): an earlier version walked to "/" with only
// "/tmp" as a stop word, rewriting shared 0775/1777 ancestors to 0755
// and failing on the first root-owned one (e.g. /var/tmp) under any
// GOTMPDIR/TMPDIR other than /tmp. If a pre-existing ancestor is not
// already traversable by the probe uid, the caller skips only the
// root (nobody-probe) arm (#17756, per #16720): an inaccessible
// ancestor reports an environment limitation, not a lock defect,
// and it is never a reason to rewrite host state.
func openTestOwnedAncestors(t *testing.T, root, base string) {
	t.Helper()
	rel, err := filepath.Rel(root, base)
	if err != nil || rel == "." || strings.HasPrefix(rel, "..") {
		t.Fatalf("temp base %q is not strictly under dedicated root %q", base, root)
	}
	// Collect base..child-of-root, then chmod root-first.
	var dirs []string
	for d := base; d != root; d = filepath.Dir(d) {
		dirs = append(dirs, d)
		if filepath.Dir(d) == d {
			t.Fatalf("walking ancestors of %q never reached root %q", base, root)
		}
	}
	dirs = append(dirs, root)
	for i := len(dirs) - 1; i >= 0; i-- {
		if err := os.Chmod(dirs[i], 0o755); err != nil {
			t.Fatalf("chmod test-owned ancestor %s: %v", dirs[i], err)
		}
	}
}

// statPerm returns the permission bits of path.
func statPerm(t *testing.T, path string) os.FileMode {
	t.Helper()
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	return fi.Mode().Perm()
}

// TestUnprivilegedCannotFlockUpgradeLock16050 is the decisive #16050
// check at the syscall level: after Acquire, an O_RDONLY open+flock
// attempt by a process that cannot read the 0600 file must fail, while
// before the fix (0644) it would succeed and block the upgrade. It runs
// the probe as uid/gid nobody via setpriv when available and running as
// root; otherwise (non-root test binary, which cannot demonstrate the
// cross-uid case) it asserts the mode bits that make that probe fail,
// so the cell never silently passes for the wrong reason.
func TestUnprivilegedCannotFlockUpgradeLock16050(t *testing.T) {
	// Use a dedicated temp root this test owns. GOTMPDIR/os.TempDir()
	// only chooses where that root is created; the root and everything
	// under it are created by this test (t.TempDir nests 001/ under a
	// per-test MkdirTemp root) and removed by cleanup, so chmodding
	// exactly those is safe under any temp root (#16720). Pre-existing
	// ancestors above the root are never chmodded; their modes are
	// asserted unchanged below. The lock dir stays 0750: nobody must
	// fail there or at the 0600 file — either is the #16050 property.
	//
	// Snapshot the pre-existing ancestors (the temp root's parent
	// chain up to the filesystem root) before any chmod, and verify
	// afterwards that none changed. Under /tmp this chain is short;
	// under GOTMPDIR=/var/tmp/x/y it includes /var/tmp/x and
	// /var/tmp/x/y, the acceptance case from #16720. Ancestors may
	// change concurrently for unrelated reasons in theory, but a
	// 0775/1777 -> 0755 change on this exact chain during this short
	// cell is the defect signature; the pre-fix loop produced it
	// deterministically.
	base := t.TempDir()
	tempRoot := filepath.Dir(base) // per-test MkdirTemp root; base is its 001/
	type ancestorMode struct {
		path string
		perm os.FileMode
	}
	var preExisting []ancestorMode
	for anc := filepath.Dir(tempRoot); ; anc = filepath.Dir(anc) {
		preExisting = append(preExisting, ancestorMode{anc, statPerm(t, anc)})
		if filepath.Dir(anc) == anc {
			break
		}
	}
	defer func() {
		for _, a := range preExisting {
			if got := statPerm(t, a.path); got != a.perm {
				t.Errorf("pre-existing ancestor %s mode changed %04o -> %04o: test must not chmod directories it does not own (#16720)", a.path, a.perm, got)
			}
		}
	}()
	// Open only the test-owned directories: tempRoot (the MkdirTemp
	// root, 0700) and base (its 001/ subdir). Without this the nobody
	// probe would fail for the wrong reason (EACCES on the temp root,
	// not on the lock).
	openTestOwnedAncestors(t, tempRoot, base)
	p := filepath.Join(base, "xpf", "upgrade.lock")
	h, err := AcquireAt(p, "upgrade", "perms")
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	defer h.Release()

	setpriv, lookErr := exec.LookPath("setpriv")
	if os.Geteuid() != 0 || lookErr != nil {
		// Cannot drop privileges here; the mode assertions in
		// TestAcquireTightensPermissiveModes16050 are the portable half.
		// Assert them here too so this cell is never vacuous.
		fi, err := os.Stat(p)
		if err != nil {
			t.Fatal(err)
		}
		if fi.Mode().Perm() != 0o600 {
			t.Fatalf("lock mode = %04o, want 0600", fi.Mode().Perm())
		}
		return
	}
	// Skip only the cross-uid arm when a pre-existing ancestor prevents
	// nobody from reaching the test root. This is an environmental
	// limitation, not a lock-mode failure (#17756).
	skipIfUntraversableAncestor(t, filepath.Dir(tempRoot), setpriv)
	// Control first: with the modes loosened to the pre-fix 0755/0644
	// and our own flock released, the same nobody probe MUST succeed —
	// otherwise a failure below would prove only that the probe cannot
	// flock at all (e.g. a 0700 ancestor), not that the tight modes
	// block it. Re-acquire afterwards for the blocked probe.
	h.Release()
	dir := filepath.Dir(p)
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, 0o644); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command(setpriv, "--reuid=nobody", "--regid=nogroup",
		"--clear-groups", "flock", "-n", p, "true").CombinedOutput(); err != nil {
		t.Fatalf("control probe: nobody flock failed on permissive 0755/0644 modes (%v, %q) — probe cannot demonstrate the fix", err, out)
	}
	// Restore the fixed modes, re-acquire, and require the probe to
	// fail: flock(1) opens O_RDONLY, which 0600 (inside a 0750 dir)
	// denies before contention is even reached.
	if err := os.Chmod(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, 0o600); err != nil {
		t.Fatal(err)
	}
	h2, err := AcquireAt(p, "upgrade", "perms")
	if err != nil {
		t.Fatalf("re-acquire: %v", err)
	}
	defer h2.Release()
	ran := false
	defer func() {
		if !ran {
			t.Error("unprivileged flock probe never ran")
		}
	}()
	ran = true
	out, err := exec.Command(setpriv, "--reuid=nobody", "--regid=nogroup",
		"--clear-groups", "flock", "-n", p, "true").CombinedOutput()
	if err == nil {
		t.Fatalf("unprivileged flock on %s succeeded (output %q) — a local user can still block upgrades (#16050)", p, out)
	}
}
