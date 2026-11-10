package testguard

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
)

// #19088: a package's tests share one process and its OS threads. A test that
// moves a thread into a network namespace of its own must put the thread back
// BEFORE it unlocks it. Unlocked while it is still in the private namespace,
// the thread goes back to the scheduler, and whatever goroutine lands on it
// next, in any later test, runs in a namespace whose loopback is down.
// 127.0.0.1 then reads as "network is unreachable" and [::1] as "cannot
// assign requested address" (#19049).
//
// The helpers below are the only way the guarded packages switch a thread's
// network namespace (CheckNetnsThreadDiscipline enforces that), and Run checks
// at the end of the package that no thread was left behind.

// threadNetnsPath names the CALLING thread's network namespace.
// /proc/self/ns/net is not that: it is the thread-group leader's, which can
// differ from the calling thread's whenever the leader or the caller has
// switched.
const threadNetnsPath = "/proc/thread-self/ns/net"

// newNetns is netns.New, a seam so a cell can model its partial failure.
var newNetns = netns.New

// ThreadNetns is the network namespace a locked OS thread was in when
// LockThreadNetns recorded it.
type ThreadNetns struct {
	orig     netns.NsHandle
	link     string
	tid      int
	released bool
}

// ThreadNetnsLink returns the calling thread's network namespace identity
// (the "net:[inode]" link). Call it on a locked goroutine; on an unlocked one
// the answer can describe a thread the goroutine has already left.
func ThreadNetnsLink() (string, error) {
	link, err := os.Readlink(threadNetnsPath)
	if err != nil {
		return "", err
	}
	if strings.TrimSpace(link) == "" {
		return "", errors.New("empty namespace identity")
	}
	return link, nil
}

// LockThreadNetns locks the calling goroutine to its OS thread and records the
// thread's current network namespace, so the thread can be switched elsewhere
// and later returned by Release. On error the thread is unlocked again:
// nothing has been switched yet.
func LockThreadNetns() (*ThreadNetns, error) {
	runtime.LockOSThread()
	link, err := ThreadNetnsLink()
	if err != nil {
		runtime.UnlockOSThread()
		return nil, fmt.Errorf("read this thread's netns: %w", err)
	}
	fd, err := unix.Open(threadNetnsPath, unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		runtime.UnlockOSThread()
		return nil, fmt.Errorf("open this thread's netns: %w", err)
	}
	return &ThreadNetns{orig: netns.NsHandle(fd), link: link, tid: unix.Gettid()}, nil
}

// Release puts the thread back into the recorded namespace and unlocks it only
// once it reads back as that namespace. If the restore or the check fails, the
// thread stays locked: when its goroutine exits, the Go runtime terminates the
// thread (or, for the thread-group leader, wedges it) instead of handing it,
// still in a foreign namespace, to another goroutine. A wedged leader stays
// in that namespace, and Run reports it: a restore failed. Call it on the goroutine that locked (a deferred call, or a
// t.Cleanup of the test that locked). A second call is a no-op.
func (n *ThreadNetns) Release() error {
	if n == nil || n.released {
		return nil
	}
	if tid := unix.Gettid(); tid != n.tid {
		return fmt.Errorf("testguard: Release on thread %d, but the namespace was recorded on thread %d; the thread is left as it is", tid, n.tid)
	}
	n.released = true
	err := netns.Set(n.orig)
	if err == nil {
		var link string
		link, err = ThreadNetnsLink()
		if err == nil && link != n.link {
			err = fmt.Errorf("the thread reads %s after the restore, want %s", link, n.link)
		}
	}
	_ = n.orig.Close()
	if err != nil {
		return fmt.Errorf("testguard: restore thread %d to %s: %w (the thread stays locked and is discarded when its goroutine exits)", n.tid, n.link, err)
	}
	runtime.UnlockOSThread()
	return nil
}

// InNetns runs fn on the calling goroutine's thread inside target, then puts
// the thread back (Release). The error joins fn's error and any failure to
// enter or leave target.
func InNetns(target netns.NsHandle, fn func() error) (err error) {
	n, err := LockThreadNetns()
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, n.Release()) }()
	if err := netns.Set(target); err != nil {
		return fmt.Errorf("enter netns: %w", err)
	}
	return fn()
}

// InNetnsPath is InNetns for the namespace at path, for example
// "/proc/<pid>/ns/net" of a process that lives in it.
func InNetnsPath(path string, fn func() error) error {
	target, err := netns.GetFromPath(path)
	if err != nil {
		return fmt.Errorf("open netns %s: %w", path, err)
	}
	defer target.Close()
	return InNetns(target, fn)
}

// TB is the part of testing.TB the namespace helpers use.
type TB interface {
	Helper()
	Cleanup(func())
	Errorf(format string, args ...any)
}

// EnterNewNetns locks the test goroutine's thread and moves it into a fresh
// network namespace until the test ends. The test's cleanup puts the thread
// back and only then unlocks it (Release). It returns the new namespace,
// closed at cleanup.
//
// On error nothing is left switched. netns.New unshares BEFORE it opens the
// new namespace, so a failed open leaves the thread inside it; the error arm
// therefore restores through Release rather than just unlocking.
func EnterNewNetns(t TB) (netns.NsHandle, error) {
	t.Helper()
	ns, _, err := EnterNewNetnsFrom(t)
	return ns, err
}

// EnterNewNetnsFrom is EnterNewNetns that also returns the namespace link the
// thread was in before it entered the new one, read on the locked thread.
func EnterNewNetnsFrom(t TB) (netns.NsHandle, string, error) {
	t.Helper()
	n, err := LockThreadNetns()
	if err != nil {
		return netns.None(), "", err
	}
	ns, err := newNetns()
	if err != nil {
		return netns.None(), "", errors.Join(fmt.Errorf("create netns: %w", err), n.Release())
	}
	t.Cleanup(func() {
		if err := n.Release(); err != nil {
			t.Errorf("%v", err)
		}
		_ = ns.Close()
	})
	return ns, n.link, nil
}

// EnterNetns locks the test goroutine's thread and moves it into target until
// the test ends, then puts it back the same way EnterNewNetns does. Subtests
// run on fresh, unlocked goroutines, so a subtest that must act inside its
// parent's namespace joins it with this.
func EnterNetns(t TB, target netns.NsHandle) error {
	t.Helper()
	n, err := LockThreadNetns()
	if err != nil {
		return err
	}
	if err := netns.Set(target); err != nil {
		return errors.Join(fmt.Errorf("enter netns: %w", err), n.Release())
	}
	t.Cleanup(func() {
		if err := n.Release(); err != nil {
			t.Errorf("%v", err)
		}
	})
	return nil
}

// ThreadCensus observes the network namespace of every thread of this process.
// It is the one census the package guard (Run) and pkg/daemon's #19049 Q53
// cell share. Its contract, from #19049's review cycles: it returns an
// error, never a partial answer, when it could not observe every thread.
//   - The listing failed, even with entries returned. os.ReadDir, never
//     filepath.Glob: Glob discards a directory read error and returns the
//     matches read so far, so a listing that failed before reaching a
//     stranded thread would pass.
//   - A read failed other than because the thread exited (ENOENT/ESRCH).
//   - No thread besides self was inspected. A Go process always runs more
//     threads than the caller's own, so such a census observed nothing.
//
// The readers are seams; nil means the real /proc/self/task.
type ThreadCensus struct {
	ReadTaskDir     func(dir string) ([]os.DirEntry, error)
	ReadThreadNetns func(task string) (string, error)
}

const taskDir = "/proc/self/task"

// Links returns each thread's namespace link by tid, every thread but self.
func (c ThreadCensus) Links(self string) (map[string]string, error) {
	readDir := c.ReadTaskDir
	if readDir == nil {
		readDir = os.ReadDir
	}
	readNetns := c.ReadThreadNetns
	if readNetns == nil {
		readNetns = func(task string) (string, error) { return os.Readlink(task + "/ns/net") }
	}
	entries, err := readDir(taskDir)
	if err != nil {
		return nil, fmt.Errorf("list this process's threads (%d entries before the error): %w; "+
			"a partial listing can omit the stranded thread", len(entries), err)
	}
	links := map[string]string{}
	for _, e := range entries {
		tid := e.Name()
		if tid == self {
			continue
		}
		link, err := readNetns(taskDir + "/" + tid)
		if err != nil {
			// A thread that exits between the listing and the read has left
			// every namespace. Any other error means the census could not
			// observe the thread: that is a failure, never "no leak".
			if errors.Is(err, fs.ErrNotExist) || errors.Is(err, syscall.ESRCH) {
				continue
			}
			return nil, fmt.Errorf("read thread %s's netns: %w; the census cannot tell which namespace it is in", tid, err)
		}
		links[tid] = link
	}
	if len(links) == 0 {
		return nil, fmt.Errorf("the census inspected no thread besides the caller's own (%d listed); it observed nothing", len(entries))
	}
	return links, nil
}

// ThreadsIn returns the tids (but self) whose namespace is link, sorted.
func (c ThreadCensus) ThreadsIn(link, self string) ([]string, error) {
	return c.filter(self, func(l string) bool { return l == link })
}

// ThreadsOutside returns the tids (but self) whose namespace is not link,
// sorted, as "tid in net:[...]".
func (c ThreadCensus) ThreadsOutside(link, self string) ([]string, error) {
	links, err := c.Links(self)
	if err != nil {
		return nil, err
	}
	var out []string
	for tid, l := range links {
		if l != link {
			out = append(out, tid+" in "+l)
		}
	}
	sort.Strings(out)
	return out, nil
}

func (c ThreadCensus) filter(self string, keep func(string) bool) ([]string, error) {
	links, err := c.Links(self)
	if err != nil {
		return nil, err
	}
	var out []string
	for tid, l := range links {
		if keep(l) {
			out = append(out, tid)
		}
	}
	sort.Strings(out)
	return out, nil
}

// SelfTid is the calling thread's id as the census names it. Call it on a
// locked goroutine.
func SelfTid() string { return strconv.Itoa(unix.Gettid()) }

// threadSettle bounds how long Run waits for threads to leave a foreign
// namespace. A goroutine that exits while locked hands its thread to the
// runtime, which terminates it asynchronously.
const threadSettle = 5 * time.Second

// Run runs a package's tests and then requires every OS thread of the process
// to be back in the network namespace the package started in (#19088). A
// thread left outside it means a test released a thread it had moved into
// another namespace, or a goroutine locked in one is still running. Either
// way a later goroutine, in a later test or package run, can land on it.
// Run returns m.Run's code, or 1 if that was 0 and the check failed. Call it
// from TestMain after ExitIfUnsafe:
//
//	func TestMain(m *testing.M) {
//		testguard.ExitIfUnsafe()
//		os.Exit(testguard.Run(m))
//	}
func Run(m interface{ Run() int }) int {
	return run(m, ThreadCensus{}, threadSettle)
}

func run(m interface{ Run() int }, census ThreadCensus, settle time.Duration) int {
	runtime.LockOSThread()
	base, err := ThreadNetnsLink()
	self := SelfTid()
	if err == nil {
		var foreign []string
		if foreign, err = census.ThreadsOutside(base, self); err == nil && len(foreign) > 0 {
			err = errors.New(describeForeign(base, foreign))
		}
	}
	runtime.UnlockOSThread()
	if err != nil {
		fmt.Fprintf(os.Stderr, "testguard: before the tests: %v\n", err)
		return 1
	}
	code := m.Run()
	deadline := time.Now().Add(settle)
	for {
		runtime.LockOSThread()
		self := SelfTid()
		foreign, err := census.ThreadsOutside(base, self)
		// The census leaves out the caller's own thread; check it too.
		if link, lerr := ThreadNetnsLink(); err == nil && (lerr != nil || link != base) {
			foreign = append(foreign, self+" in "+link)
			err = lerr
		}
		runtime.UnlockOSThread()
		if err == nil && len(foreign) == 0 {
			return code
		}
		if time.Now().After(deadline) {
			if err != nil {
				fmt.Fprintf(os.Stderr, "testguard: after the tests: cannot take the thread census against %s: %v\n", base, err)
			} else {
				fmt.Fprintf(os.Stderr, "testguard: after the tests: %s\n", describeForeign(base, foreign))
			}
			if code == 0 {
				code = 1
			}
			return code
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func describeForeign(base string, foreign []string) string {
	return fmt.Sprintf("%d OS thread(s) outside the package's network namespace %s: thread %s. "+
		"A test released a thread it had moved into another namespace without moving it back, "+
		"or a goroutine locked in one is still running. Switch threads only through "+
		"testguard.LockThreadNetns/Release, InNetns or EnterNewNetns, which restore before they unlock (#19088)",
		len(foreign), base, strings.Join(foreign, ", thread "))
}
