package cluster

import (
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// #6826: what does a RETURNED Manager.Stop imply about the cross-process epoch
// flock?
//
// Manager.Stop joins the boot-epoch refinement worker with a bounded budget
// (bootEpochStopJoinBudget) and, on timeout, warns and returns. The worker is
// not cancelled — withEpochFileLock has already taken LOCK_EX and defers its
// release until after the callback's durable write and fsync, so a Stop whose
// budget expires mid-callback returns to its caller while a lock that OTHER
// PROCESSES can see is still held.
//
// That matters here rather than in general because restart is the documented
// recovery path for this subsystem: a day-2 chassis-cluster topology or
// identity change is REFUSED at commit and requires a process restart
// (pkg/daemon/cluster_topology_preflight.go). The incoming process is exactly
// the party positioned to find the outgoing one's lock still held.
//
// The behaviour was documented but never pinned, so it could drift either way
// unnoticed. These cells pin it.

// tryEpochFlock reports whether the epoch lock at path can be taken RIGHT NOW
// by an independent open file description.
//
// A second os.OpenFile creates a separate open file DESCRIPTION, and flock(2)
// associates a lock with the description rather than the process — so this
// contends with a lock held elsewhere in this same process exactly as another
// process would. The cell below asserts that property directly rather than
// assuming it, because the whole test is worthless if it does not hold.
func tryEpochFlock(t *testing.T, path string) bool {
	t.Helper()
	f, err := os.OpenFile(path+".lock", os.O_CREATE|os.O_RDWR, 0o644)
	if err != nil {
		t.Fatalf("open lock file: %v", err)
	}
	defer f.Close()
	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		return false
	}
	_ = unix.Flock(int(f.Fd()), unix.LOCK_UN)
	return true
}

// TestEpochLockFileTightened16050 is the #16050 regression for the epoch
// lock: a pre-existing 0644 .lock file must be tightened to 0600 by
// withEpochFileLock (creation mode asserted on use). RED-on-revert:
// restoring OpenFile(0o644) without the chmod leaves 0644.
func TestEpochLockFileTightened16050(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ha-boot-epoch")
	lockPath := path + ".lock"
	if err := os.WriteFile(lockPath, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(lockPath, 0o644); err != nil {
		t.Fatal(err)
	}
	ran := false
	withEpochFileLock(path, func() { ran = true })
	if !ran {
		t.Fatal("epoch lock callback did not run")
	}
	if fi, err := os.Stat(lockPath); err != nil {
		t.Fatal(err)
	} else if got := fi.Mode().Perm(); got != 0o600 {
		t.Fatalf("epoch lock mode = %04o, want 0600 (#16050)", got)
	}
}

// countLockFDs16050 returns how many of this process's open fds point at
// path (via /proc/self/fd symlinks), or -1 where unavailable.
func countLockFDs16050(path string) int {
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		return -1
	}
	n := 0
	for _, e := range entries {
		if target, err := os.Readlink(filepath.Join("/proc/self/fd", e.Name())); err == nil && target == path {
			n++
		}
	}
	return n
}

// TestEpochLockReleasesFD16050 pins the fd lifecycle of
// withEpochFileLock: the .lock fd must be Closed on the success path
// AND on the #16050 chmod-error decline path (whose return originally
// sat before `defer f.Close()` and leaked the fd).
//
// RED-on-revert: moving `defer f.Close()` back below the chmod (or
// removing it) leaves the count at 1 after the chmod-error call.
func TestEpochLockReleasesFD16050(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ha-boot-epoch")
	lockPath := path + ".lock"
	if n := countLockFDs16050(lockPath); n < 0 {
		t.Skip("/proc/self/fd unavailable on this platform")
	} else if n != 0 {
		t.Fatalf("precondition: %d fds already open on %s", n, lockPath)
	}

	// Success path: callback runs under the lock; fd closed on return.
	ran := false
	withEpochFileLock(path, func() { ran = true })
	if !ran {
		t.Fatal("success path: callback did not run")
	}
	if n := countLockFDs16050(lockPath); n != 0 {
		t.Fatalf("success path: %d fd(s) still open on %s — fd leaked", n, lockPath)
	}

	// Chmod-error path: make path+".lock" a symlink to /proc/self/mem.
	// OpenFile(O_RDWR) on it succeeds (mem is openable), but Chmod
	// follows the symlink and fails EPERM — reaching exactly the
	// chmod-decline return that used to sit before `defer f.Close()`.
	// The mem fd's /proc/self/fd target is the resolved /proc/<pid>/mem
	// (not countable by a stable path), so count TOTAL fds: +1 means
	// the decline leaked.
	totalFDs := func() int {
		entries, err := os.ReadDir("/proc/self/fd")
		if err != nil {
			return -1
		}
		return len(entries)
	}
	memPath := filepath.Join(t.TempDir(), "ha-boot-epoch")
	memLock := memPath + ".lock"
	if err := os.Symlink("/proc/self/mem", memLock); err != nil {
		t.Fatal(err)
	}
	before := totalFDs()
	ran = false
	withEpochFileLock(memPath, func() { ran = true })
	if ran {
		t.Fatal("chmod-error path: callback ran despite chmod failure")
	}
	if after := totalFDs(); after != before {
		t.Fatalf("chmod-error path: open fd count %d before, %d after — fd leaked", before, after)
	}

	// Open-error path: point the lock through a regular file so
	// OpenFile fails before any fd exists.
	blocker := filepath.Join(t.TempDir(), "blocker")
	if err := os.WriteFile(blocker, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	badPath := filepath.Join(blocker, "sub", "ha-boot-epoch")
	ran = false
	withEpochFileLock(badPath, func() { ran = true })
	if ran {
		t.Fatal("open-error path: callback ran despite lock open failure")
	}
	if n := countLockFDs16050(badPath + ".lock"); n != 0 {
		t.Fatalf("open-error path: %d fd(s) still open — fd leaked", n)
	}
}

// TestSecondDescriptionContendsWithAHeldEpochFlock6826 is the ground-truth
// control for the cells below. If a second description did NOT contend, every
// "the lock is free" assertion in this file would pass vacuously.
func TestSecondDescriptionContendsWithAHeldEpochFlock6826(t *testing.T) {
	path := filepath.Join(t.TempDir(), "epoch")
	if !tryEpochFlock(t, path) {
		t.Fatal("setup: an unheld epoch lock must be takeable")
	}
	held, err := os.OpenFile(path+".lock", os.O_CREATE|os.O_RDWR, 0o644)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer held.Close()
	if err := unix.Flock(int(held.Fd()), unix.LOCK_EX); err != nil {
		t.Fatalf("hold LOCK_EX: %v", err)
	}
	if tryEpochFlock(t, path) {
		t.Fatal("a second open file description must NOT be able to take a held " +
			"LOCK_EX — without this every lock-availability assertion in this file " +
			"passes for the wrong reason")
	}
	_ = unix.Flock(int(held.Fd()), unix.LOCK_UN)
	if !tryEpochFlock(t, path) {
		t.Fatal("the lock must be takeable again once released")
	}
}

// parkWorkerHoldingEpochFlock installs an epochFlock seam that takes the REAL
// lock and then parks the worker while holding it, which is the state #6826 is
// about. Returns a channel closed once the worker is parked, and an unpark.
//
// The park is deliberately AFTER origFlock rather than before it. An existing
// test in this package parks BEFORE, which holds the worker outside the lock;
// that is the right shape for its question and the wrong shape for this one.
func parkWorkerHoldingEpochFlock(t *testing.T) (parked <-chan struct{}, unpark func()) {
	t.Helper()
	at := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	orig := epochFlock
	epochFlock = func(fd int, how int) error {
		err := orig(fd, how) // take the real LOCK_EX first
		once.Do(func() {
			close(at)
			<-release
		})
		return err
	}
	t.Cleanup(func() { epochFlock = orig })
	var unparkOnce sync.Once
	unpark = func() { unparkOnce.Do(func() { close(release) }) }
	t.Cleanup(unpark)
	return at, unpark
}

// TestStopReturnsWhileEpochFlockIsStillHeld6826 is the defect, pinned.
//
// This asserts the CURRENT contract, which is "a returned Stop does NOT imply
// the flock is released". It is written this way on purpose: the invariant
// recorded at the lock site says exactly that, and a test that asserted the
// opposite would be asserting a fix nobody has made. If someone later makes
// Stop imply release, this cell reds and points at the invariant comment — which
// is the drift-detection the issue asked for, in whichever direction it drifts.
func TestStopReturnsWhileEpochFlockIsStillHeld6826(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "epoch")
	orig := bootEpochPath
	bootEpochPath = path
	t.Cleanup(func() { bootEpochPath = orig })

	parked, unpark := parkWorkerHoldingEpochFlock(t)

	m := NewManager(0, 42)
	_ = m.heartbeatBootEpoch() // spawns the refinement worker

	select {
	case <-parked:
	case <-time.After(10 * time.Second):
		t.Fatal("the refinement worker never reached the file lock")
	}

	// The worker is now inside withEpochFileLock holding LOCK_EX. Stop's join
	// budget cannot be met, so it must time out and return.
	stopped := make(chan struct{})
	go func() { m.Stop(); close(stopped) }()
	select {
	case <-stopped:
	case <-time.After(bootEpochStopJoinBudget + 30*time.Second):
		t.Fatal("Stop did not return — the bounded join is the whole point of " +
			"bootEpochStopJoinBudget; an unbounded one parks shutdown behind a wedged store")
	}

	if tryEpochFlock(t, path) {
		t.Fatal("#6826: the epoch flock was FREE after a timed-out Stop returned. " +
			"That is a stronger guarantee than the code makes — withEpochFileLock " +
			"defers LOCK_UN until after the callback's durable write and fsync, and " +
			"nothing cancels the worker. If this became true deliberately, update the " +
			"invariant at withEpochFileLock and at joinBootEpochRefine to say so.")
	}

	// Drain before returning. The worker is still parked holding the lock and
	// the fd; letting the test return here races t.TempDir's RemoveAll against
	// the worker's write and fails cleanup with "directory not empty". Joining
	// here is NOT the assertion — that was made above, against the timed-out
	// Stop — it is teardown.
	unpark()
	if !m.joinBootEpochRefine(30 * time.Second) {
		t.Error("teardown: the unparked worker never exited")
	}
}

// TestIncomingProcessDeclinesRatherThanBlocking6826 is the other half of the
// invariant: given that a returned Stop does not imply the lock is free, an
// INCOMING process must not park behind it.
//
// Holds the lock from an independent open file description — the outgoing
// process's still-running worker — and requires withEpochFileLock to give up
// within its budget and DECLINE, rather than block until the holder releases.
//
// The assertion is on ELAPSED TIME against the budget, not on a bare
// "it returned": a blocking LOCK_EX would also return here, just after the
// holder let go, so a cell that only checked completion would pass on the
// pre-fix code.
func TestIncomingProcessDeclinesRatherThanBlocking6826(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "epoch")

	held, err := os.OpenFile(path+".lock", os.O_CREATE|os.O_RDWR, 0o644)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer held.Close()
	if err := unix.Flock(int(held.Fd()), unix.LOCK_EX); err != nil {
		t.Fatalf("hold LOCK_EX: %v", err)
	}

	// Count attempts, so the bounded wait is proven to PACE itself rather than
	// busy-spin. Without the retry interval the loop still declines on time and
	// every other assertion here still passes — measured — while burning a core
	// for the whole budget on the shutdown and startup paths.
	var attempts int64
	origFlock := epochFlock
	epochFlock = func(fd int, how int) error {
		atomic.AddInt64(&attempts, 1)
		return origFlock(fd, how)
	}
	t.Cleanup(func() { epochFlock = origFlock })

	// RELEASE THE LOCK LATE, well after the acquire budget. Without this a
	// BLOCKING implementation never returns and the cell fails by HANGING —
	// which is a red, but a red with no assertion and no diagnostic. Releasing
	// late means a blocking implementation completes too, just slowly, so the
	// elapsed-time assertion below is what fires and it names the defect.
	go func() {
		time.Sleep(bootEpochLockAcquireBudget * 2)
		_ = unix.Flock(int(held.Fd()), unix.LOCK_UN)
	}()

	ran := false
	start := time.Now()
	withEpochFileLock(path, func() { ran = true })
	elapsed := time.Since(start)

	if ran {
		t.Fatal("#6826: the callback RAN while another description held LOCK_EX — " +
			"withEpochFileLock must not proceed without the lock")
	}
	// Ceiling sits BELOW the late release above, so a blocking acquisition —
	// which would succeed at 2x the budget — fails here on time rather than on
	// having run the callback.
	if elapsed > bootEpochLockAcquireBudget+bootEpochLockAcquireBudget/2 {
		t.Errorf("#6826: waited %v for a contended lock, budget is %v — an incoming "+
			"process must decline rather than park behind an outgoing one's worker",
			elapsed, bootEpochLockAcquireBudget)
	}
	// Paced, not spinning. The ceiling is the budget divided by the retry
	// interval with generous slack for scheduler jitter; a spin loop exceeds it
	// by orders of magnitude.
	ceiling := int64(bootEpochLockAcquireBudget/bootEpochLockRetryInterval) * 8
	if n := atomic.LoadInt64(&attempts); n > ceiling {
		t.Errorf("#6826: %d lock attempts in %v (ceiling %d) — the bounded wait must "+
			"sleep between attempts, not busy-spin a core through the whole budget",
			n, elapsed, ceiling)
	}
	// Non-vacuity: it must actually have WAITED, not skipped the attempt.
	if elapsed < bootEpochLockRetryInterval {
		t.Errorf("#6826: returned in %v, faster than one retry interval (%v) — the "+
			"bounded wait must actually retry, or a lock released microseconds later "+
			"is needlessly declined", elapsed, bootEpochLockRetryInterval)
	}
}

// TestNonContentionErrnoDeclinesImmediately6826 pins the OTHER half of the
// retry rule: EWOULDBLOCK is contention and is retried, every other errno is a
// real failure and returns at once.
//
// Without this cell, "retry every errno until the budget expires" passes the
// whole suite — measured, it did. That turns a fast, correct decline into a
// three-second one on a store that will never grant the lock, on the shutdown
// and startup paths where the delay is most visible.
func TestNonContentionErrnoDeclinesImmediately6826(t *testing.T) {
	path := filepath.Join(t.TempDir(), "epoch")

	var calls int64
	orig := epochFlock
	epochFlock = func(int, int) error {
		atomic.AddInt64(&calls, 1)
		return unix.ENOLCK
	}
	t.Cleanup(func() { epochFlock = orig })

	ran := false
	start := time.Now()
	withEpochFileLock(path, func() { ran = true })
	elapsed := time.Since(start)

	if ran {
		t.Fatal("the callback must not run when the lock could not be taken")
	}
	if n := atomic.LoadInt64(&calls); n != 1 {
		t.Errorf("ENOLCK was attempted %d times; a non-contention errno must NOT be "+
			"retried — the lock is not going to become available and the caller pays "+
			"the whole budget for nothing", n)
	}
	if elapsed >= bootEpochLockAcquireBudget {
		t.Errorf("declining on ENOLCK took %v, at or beyond the %v contention budget — "+
			"a real failure must be immediate", elapsed, bootEpochLockAcquireBudget)
	}
}

// TestContendedEpochLockAcquireIsRaceFree6826 is the -race probe, shaped so it
// cannot report a false green.
//
// THE OBVIOUS SHAPE IS A FALSE GREEN. A contender loop and an acquirer loop
// with EQUAL iteration counts lets the cheap side finish inside the expensive
// side's first pass, so the two barely overlap and -race observes almost
// nothing while the test reports success. Here the acquirer is the expensive
// side (it waits out a retry interval at minimum), so the contender loops until
// the acquirer signals done rather than a fixed count, and the achieved
// contention RATE is reported so a run that degenerated to no overlap is
// visible instead of silently passing.
func TestContendedEpochLockAcquireIsRaceFree6826(t *testing.T) {
	if testing.Short() {
		t.Skip("contention probe: -short")
	}
	path := filepath.Join(t.TempDir(), "epoch")

	done := make(chan struct{})
	var contentions int64
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-done:
				return
			default:
			}
			f, err := os.OpenFile(path+".lock", os.O_CREATE|os.O_RDWR, 0o644)
			if err != nil {
				return
			}
			if unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB) == nil {
				atomic.AddInt64(&contentions, 1)
				_ = unix.Flock(int(f.Fd()), unix.LOCK_UN)
			}
			_ = f.Close()
		}
	}()

	// #7674: wait until the contender has PROVABLY taken the lock at least once
	// before the acquire loop starts.
	//
	// The acquirer is fast — 40 acquisitions complete in ~300us on an idle box —
	// and under `go test ./...` this package runs alongside dozens of others. The
	// contender goroutine could therefore go unscheduled for the entire loop, and
	// the `got == 0` check below then fired reporting that the probe proved
	// nothing. That report was true, and it was a statement about the SCHEDULER
	// rather than about the lock: the floor was reading the machine. Measured on
	// master: "40 acquisitions in 283.121us, contender completed 0 lock cycles".
	//
	// ONE edge, and only BEFORE the contended region. A per-acquisition handshake
	// would establish happens-before between the contender and the acquisition it
	// races, which is precisely the absence `-race` looks for — the probe would go
	// quiet against the very hazard it exists to detect. The contender keeps
	// looping freely throughout the loop below.
	waitForContenderProgress(t, &contentions, 5*time.Second)
	before := atomic.LoadInt64(&contentions)

	const acquires = 40
	ran := 0
	start := time.Now()
	for i := 0; i < acquires; i++ {
		withEpochFileLock(path, func() { ran++ })
	}
	// The contender is provably running by now, but a fixed 40 acquisitions can
	// still fit inside a single scheduling quantum. Extend until the contender has
	// demonstrably interleaved with THIS loop, so the overlap `-race` needs is
	// measured rather than inferred from the pre-loop cycle.
	overlapDeadline := time.Now().Add(5 * time.Second)
	for atomic.LoadInt64(&contentions) == before {
		if time.Now().After(overlapDeadline) {
			close(done)
			wg.Wait()
			t.Fatalf("the contender took the lock %d times before the acquire loop but "+
				"not once during it, over 5s — the two sides are not interleaving and "+
				"-race observed nothing", before)
		}
		withEpochFileLock(path, func() { ran++ })
	}
	elapsed := time.Since(start)
	close(done)
	wg.Wait()

	// `ran` may exceed `acquires` when the overlap extension above ran; what must
	// hold is that EVERY acquisition ran its callback, so a count short of the
	// fixed floor means an uncontended lock was refused.
	if ran < acquires {
		t.Errorf("only %d/%d acquisitions ran their callback — an uncontended lock "+
			"must always be takeable", ran, acquires)
	}
	got := atomic.LoadInt64(&contentions)
	rate := float64(got) / elapsed.Seconds()
	t.Logf("contention probe: %d acquisitions in %v, contender completed %d "+
		"lock cycles (%.0f/s)", acquires, elapsed, got, rate)
	// Overlap is now guaranteed by the extension loop above, which fails loudly
	// and names what never arrived rather than reaching here with zero. Keep the
	// floor as a belt-and-braces invariant on the accounting itself.
	if got <= before {
		t.Errorf("contention count did not advance during the acquire loop "+
			"(before=%d, after=%d) — the extension loop should have caught this",
			before, got)
	}
}

// waitForContenderProgress blocks until the contender goroutine has completed at
// least one lock cycle, so the acquire loop is issued into a window that is
// provably being contended rather than one the scheduler has not reached yet.
//
// Bounded, and fails naming what never arrived — a probe that silently proceeds
// uncontended is the degenerate case this exists to prevent.
func waitForContenderProgress(t *testing.T, contentions *int64, within time.Duration) {
	t.Helper()
	deadline := time.Now().Add(within)
	for atomic.LoadInt64(contentions) == 0 {
		if time.Now().After(deadline) {
			t.Fatalf("the contender completed no lock cycles in %s — it was never "+
				"scheduled, so the acquire loop would run uncontended and the probe "+
				"would be degenerate", within)
		}
		time.Sleep(time.Millisecond)
	}
}
