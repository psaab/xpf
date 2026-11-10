package testguard

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
)

// #19088 cells. Each one builds the state it asserts on with raw netns calls,
// so the census is checked independently of the helpers it guards.

func baseNetns19088(t *testing.T) string {
	t.Helper()
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	link, err := ThreadNetnsLink()
	if err != nil {
		t.Fatalf("read the test thread's netns: %v", err)
	}
	return link
}

func skipWithoutNetns19088(t *testing.T, err error) {
	t.Helper()
	if os.Getenv("XPF_REQUIRE_NETNS") != "" {
		t.Fatalf("cannot create a network namespace: %v (XPF_REQUIRE_NETNS is set)", err)
	}
	t.Skipf("cannot create a network namespace (needs CAP_SYS_ADMIN; run under scripts/testguard-run.sh): %v", err)
}

// offLeader19088 runs fn on a goroutine that is NOT on the thread-group
// leader, and waits for it. A goroutine that exits while locked on the leader
// does not terminate the thread: the runtime wedges the main thread instead,
// so it would stay in whatever namespace fn left it in, and every later
// census would see it. A goroutine that finds itself on the leader keeps it
// locked while a fresh goroutine, which cannot land there, runs fn.
func offLeader19088(fn func()) {
	done := make(chan struct{})
	go func() {
		defer close(done)
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		if unix.Gettid() == os.Getpid() {
			offLeader19088(fn)
			return
		}
		fn()
	}()
	<-done
}

// threadsIn19088 is the census filtered to one namespace.
func threadsIn19088(t *testing.T, link string) []string {
	t.Helper()
	in, err := ThreadCensus{}.ThreadsIn(link, "")
	if err != nil {
		t.Fatalf("thread census: %v", err)
	}
	return in
}

// waitNoThreadIn19088 polls until no thread is left in link. A goroutine that
// exits while locked hands its thread to the runtime, which terminates it
// asynchronously.
func waitNoThreadIn19088(t *testing.T, base, link string) {
	t.Helper()
	if link == base {
		t.Fatalf("FIXTURE: waiting for threads to leave the package namespace %s itself", base)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		in := threadsIn19088(t, link)
		if len(in) == 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("threads still in %s after 5s: %+v", link, in)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

type held19088 struct {
	tid  int
	link string
	err  error
}

// holdThreadInNewNetns19088 parks a goroutine, locked, in a fresh namespace
// until release is closed; it then restores and unlocks it with raw calls.
func holdThreadInNewNetns19088(release <-chan struct{}) <-chan held19088 {
	ready := make(chan held19088, 1)
	go offLeader19088(func() {
		runtime.LockOSThread()
		orig, err := netns.Get()
		if err != nil {
			runtime.UnlockOSThread()
			ready <- held19088{err: err}
			return
		}
		defer orig.Close()
		ns, err := netns.New()
		if err != nil {
			ready <- held19088{err: err}
			// Exit locked: if New moved the thread, it is discarded.
			return
		}
		defer ns.Close()
		link, err := ThreadNetnsLink()
		ready <- held19088{tid: unix.Gettid(), link: link, err: err}
		<-release
		if netns.Set(orig) == nil {
			runtime.UnlockOSThread()
		}
	})
	return ready
}

// The positive control: the census sees a thread that is in another
// namespace, by tid and namespace, and stops seeing it once it is back.
func TestThreadCensusSeesAThreadInAnotherNetns19088(t *testing.T) {
	base := baseNetns19088(t)
	release := make(chan struct{})
	h := <-holdThreadInNewNetns19088(release)
	if h.err != nil {
		close(release)
		skipWithoutNetns19088(t, h.err)
	}
	in := threadsIn19088(t, h.link)
	close(release)
	if len(in) != 1 || in[0] != strconv.Itoa(h.tid) {
		t.Fatalf("census of %s = %+v, want exactly thread %d", h.link, in, h.tid)
	}
	waitNoThreadIn19088(t, base, h.link)
}

// fakeTasks19088 is a task listing of the given tids, read from a real
// directory so the entries are genuine os.DirEntry values.
func fakeTasks19088(t *testing.T, tids ...string) []os.DirEntry {
	t.Helper()
	dir := t.TempDir()
	for _, tid := range tids {
		if err := os.Mkdir(filepath.Join(dir, tid), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	return entries
}

// The census fails instead of reporting clean whenever it cannot observe
// every thread (the #19049 contract, now shared with the package guard).
func TestThreadCensusFailsClosedWhenBlind19088(t *testing.T) {
	links := map[string]string{"10": "net:[1]", "11": "net:[2]"}
	readLink := func(task string) (string, error) {
		tid := filepath.Base(task)
		switch links[tid] {
		case "":
			return "", fs.ErrNotExist
		case "einval":
			return "", syscall.EINVAL
		case "esrch":
			return "", syscall.ESRCH
		}
		return links[tid], nil
	}
	census := func(entries []os.DirEntry, listErr error) ThreadCensus {
		return ThreadCensus{
			ReadTaskDir:     func(string) ([]os.DirEntry, error) { return entries, listErr },
			ReadThreadNetns: readLink,
		}
	}
	all := fakeTasks19088(t, "9", "10", "11")
	out, err := census(all, nil).ThreadsOutside("net:[1]", "9")
	if err != nil || len(out) != 1 || out[0] != "11 in net:[2]" {
		t.Fatalf("control: census of a readable listing = %v, %v; want [11 in net:[2]]", out, err)
	}
	if _, err := census(nil, errors.New("injected: listing failed")).ThreadsOutside("net:[1]", "9"); err == nil {
		t.Fatal("a failed listing was taken as a clean census")
	}
	if _, err := census(all[:2], errors.New("injected: getdents failed part-way")).ThreadsOutside("net:[1]", "9"); err == nil {
		t.Fatal("a listing that failed part-way was taken as a clean census")
	}
	links["11"] = "einval"
	if _, err := census(all, nil).ThreadsOutside("net:[1]", "9"); err == nil {
		t.Fatal("a thread whose namespace could not be read was counted as clean")
	}
	links["11"] = "esrch"
	if out, err := census(all, nil).ThreadsOutside("net:[1]", "9"); err != nil || len(out) != 0 {
		t.Fatalf("a thread that exited during the census = %v, %v; want it skipped", out, err)
	}
	if _, err := census(fakeTasks19088(t, "9"), nil).ThreadsOutside("net:[1]", "9"); err == nil {
		t.Fatal("a census that inspected no thread but the caller's own reported clean")
	}
}

// Release puts the thread back before unlocking it: once the goroutine is
// done, no thread is left in the namespace it visited.
func TestReleaseRestoresTheThreadBeforeUnlocking19088(t *testing.T) {
	base := baseNetns19088(t)
	type out struct {
		link       string
		newErr     error
		releaseErr error
	}
	done := make(chan out, 1)
	go offLeader19088(func() {
		n, err := LockThreadNetns()
		if err != nil {
			done <- out{newErr: err}
			return
		}
		ns, err := netns.New()
		if err != nil {
			done <- out{newErr: err, releaseErr: n.Release()}
			return
		}
		defer ns.Close()
		link, _ := ThreadNetnsLink()
		done <- out{link: link, releaseErr: n.Release()}
	})
	o := <-done
	if o.newErr != nil {
		skipWithoutNetns19088(t, o.newErr)
	}
	if o.releaseErr != nil {
		t.Fatalf("Release: %v", o.releaseErr)
	}
	if o.link == base {
		t.Fatalf("FIXTURE: the thread never left %s", base)
	}
	waitNoThreadIn19088(t, base, o.link)
}

// Release cannot restore (the recorded handle is not a network namespace):
// it reports that and keeps the thread locked, so the goroutine's exit
// discards the thread. Unlocking it instead would leave it, still in the
// namespace it visited, in the scheduler's pool.
func TestReleaseKeepsAThreadItCannotRestoreLocked19088(t *testing.T) {
	base := baseNetns19088(t)
	type out struct {
		link       string
		newErr     error
		releaseErr error
	}
	done := make(chan out, 1)
	go offLeader19088(func() {
		n, err := LockThreadNetns()
		if err != nil {
			done <- out{newErr: err}
			return
		}
		ns, err := netns.New()
		if err != nil {
			done <- out{newErr: err, releaseErr: n.Release()}
			return
		}
		defer ns.Close()
		link, _ := ThreadNetnsLink()
		notNetns, err := unix.Open("/dev/null", unix.O_RDONLY|unix.O_CLOEXEC, 0)
		if err != nil {
			done <- out{newErr: err}
			return
		}
		_ = n.orig.Close()
		n.orig = netns.NsHandle(notNetns)
		done <- out{link: link, releaseErr: n.Release()}
		// The goroutine exits here, still locked.
	})
	o := <-done
	if o.newErr != nil {
		skipWithoutNetns19088(t, o.newErr)
	}
	if o.releaseErr == nil {
		t.Fatal("Release reported success with an unusable namespace handle")
	}
	if o.link == base {
		t.Fatalf("FIXTURE: the thread never left %s", base)
	}
	waitNoThreadIn19088(t, base, o.link)
}

type fakeTB19088 struct {
	cleanups []func()
	errors   []string
}

func (f *fakeTB19088) Helper()           {}
func (f *fakeTB19088) Cleanup(fn func()) { f.cleanups = append(f.cleanups, fn) }
func (f *fakeTB19088) Errorf(format string, args ...any) {
	f.errors = append(f.errors, format)
}
func (f *fakeTB19088) runCleanups() {
	for i := len(f.cleanups) - 1; i >= 0; i-- {
		f.cleanups[i]()
	}
}

// netns.New unshares and THEN opens the new namespace. If the open fails, the
// thread is already inside the new namespace. EnterNewNetns's error arm must
// put it back, not just unlock it (Codex review of #19049, finding 3).
func TestEnterNewNetnsUndoesAPartialCreate19088(t *testing.T) {
	base := baseNetns19088(t)
	var unshared string
	var unshareErr error
	newNetns = func() (netns.NsHandle, error) {
		if unshareErr = unix.Unshare(unix.CLONE_NEWNET); unshareErr != nil {
			return netns.None(), unshareErr
		}
		unshared, _ = ThreadNetnsLink()
		return netns.None(), errors.New("injected: opening the new namespace failed")
	}
	t.Cleanup(func() { newNetns = netns.New })
	done := make(chan error, 1)
	go offLeader19088(func() {
		_, err := EnterNewNetns(&fakeTB19088{})
		done <- err
	})
	err := <-done
	if unshareErr != nil {
		skipWithoutNetns19088(t, unshareErr)
	}
	if err == nil || !strings.Contains(err.Error(), "injected") {
		t.Fatalf("EnterNewNetns = %v, want the injected create failure", err)
	}
	if unshared == "" || unshared == base {
		t.Fatalf("FIXTURE: the injected create did not move the thread (%q)", unshared)
	}
	waitNoThreadIn19088(t, base, unshared)
}

// The normal path: inside the test the thread is in a fresh namespace; the
// test's cleanup puts it back.
func TestEnterNewNetnsRestoresAtCleanup19088(t *testing.T) {
	base := baseNetns19088(t)
	type out struct {
		inside string
		err    error
		errs   []string
	}
	done := make(chan out, 1)
	go offLeader19088(func() {
		tb := &fakeTB19088{}
		_, err := EnterNewNetns(tb)
		if err != nil {
			done <- out{err: err}
			return
		}
		inside, _ := ThreadNetnsLink()
		tb.runCleanups()
		done <- out{inside: inside, errs: tb.errors}
	})
	o := <-done
	if o.err != nil {
		skipWithoutNetns19088(t, o.err)
	}
	if o.inside == base {
		t.Fatalf("FIXTURE: EnterNewNetns left the thread in %s", base)
	}
	if len(o.errs) != 0 {
		t.Fatalf("cleanup reported %v", o.errs)
	}
	waitNoThreadIn19088(t, base, o.inside)
}

// InNetnsPath must return the CALLING thread to the namespace it was in, not
// the thread-group leader's (#19088: inNetns12034 restored to
// /proc/self/ns/net). The caller here sits in a private namespace, off the
// leader, and visits the leader's namespace.
func TestInNetnsPathReturnsTheCallersThread19088(t *testing.T) {
	base := baseNetns19088(t)
	type out struct {
		before, during, after string
		err, skipErr          error
	}
	done := make(chan out, 1)
	release := make(chan struct{})
	go func() {
		runtime.LockOSThread()
		if unix.Gettid() == os.Getpid() {
			// This goroutine holds the leader, so the next one cannot get it.
			defer runtime.UnlockOSThread()
			go func() {
				runtime.LockOSThread()
				defer runtime.UnlockOSThread()
				done <- callerOffLeader19088()
			}()
			<-release
			return
		}
		defer runtime.UnlockOSThread()
		done <- callerOffLeader19088()
	}()
	o := <-done
	close(release)
	if o.skipErr != nil {
		skipWithoutNetns19088(t, o.skipErr)
	}
	if o.err != nil {
		t.Fatalf("InNetnsPath: %v", o.err)
	}
	if o.before == base || o.during != base {
		t.Fatalf("FIXTURE: caller in %s, visited %s; want a private caller visiting %s", o.before, o.during, base)
	}
	if o.after != o.before {
		t.Fatalf("after InNetnsPath the caller's thread is in %s, want its own %s", o.after, o.before)
	}
}

// callerOffLeader19088 runs on a locked thread that is not the leader: it
// enters a private namespace, visits the leader's through InNetnsPath, and
// reports where the thread is at each step. It restores the thread itself.
func callerOffLeader19088() (o struct {
	before, during, after string
	err, skipErr          error
}) {
	orig, err := netns.Get()
	if err != nil {
		o.skipErr = err
		return
	}
	defer orig.Close()
	ns, err := netns.New()
	if err != nil {
		o.skipErr = err
		runtime.LockOSThread() // never released: if New moved the thread, it is discarded
		return
	}
	defer ns.Close()
	o.before, _ = ThreadNetnsLink()
	o.err = InNetnsPath("/proc/"+strconv.Itoa(os.Getpid())+"/ns/net", func() error {
		o.during, _ = ThreadNetnsLink()
		return nil
	})
	o.after, _ = ThreadNetnsLink()
	if netns.Set(orig) != nil {
		runtime.LockOSThread() // keep it: the caller's deferred unlock leaves it locked
	}
	return
}

type fakeM19088 func() int

func (f fakeM19088) Run() int { return f() }

// Run fails the package when a thread is outside its namespace at the end,
// and otherwise passes m's own code through.
func TestRunFailsWhenAThreadIsLeftInAnotherNetns19088(t *testing.T) {
	release := make(chan struct{})
	var h held19088
	leaky := fakeM19088(func() int {
		h = <-holdThreadInNewNetns19088(release)
		return 0
	})
	code := run(leaky, ThreadCensus{}, 300*time.Millisecond)
	close(release)
	if h.err != nil {
		skipWithoutNetns19088(t, h.err)
	}
	if code == 0 {
		t.Fatal("run passed with a thread left in another network namespace")
	}
	base := baseNetns19088(t)
	waitNoThreadIn19088(t, base, h.link)
	if code := run(fakeM19088(func() int { return 0 }), ThreadCensus{}, time.Second); code != 0 {
		t.Fatalf("run of a clean package = %d, want 0", code)
	}
	if code := run(fakeM19088(func() int { return 3 }), ThreadCensus{}, time.Second); code != 3 {
		t.Fatalf("run of a failing clean package = %d, want its own 3", code)
	}
}
