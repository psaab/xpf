package daemon

import (
	"os"
	"strconv"
	"testing"

	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"

	"github.com/psaab/xpf/internal/testguard"
)

type innetns12034Result19088 struct {
	before, during, after string
	err, skip             error
}

// innetns12034OffLeader19088 enters a private namespace on a locked thread
// that is NOT the thread-group leader, visits the leader's namespace through
// inNetns12034, and reports where the thread is at each step. On the leader,
// /proc/self/ns/net is the thread's own namespace and the #19088 defect
// cannot show, so a goroutine that finds itself there keeps the leader
// locked and hands the work to a fresh goroutine, which cannot land on it.
func innetns12034OffLeader19088(done chan<- innetns12034Result19088) {
	n, err := testguard.LockThreadNetns()
	if err != nil {
		done <- innetns12034Result19088{skip: err}
		return
	}
	defer func() { _ = n.Release() }()
	if unix.Gettid() == os.Getpid() {
		inner := make(chan innetns12034Result19088, 1)
		go innetns12034OffLeader19088(inner)
		done <- <-inner
		return
	}
	private, err := netns.New()
	if err != nil {
		done <- innetns12034Result19088{skip: err}
		return
	}
	defer private.Close()
	var r innetns12034Result19088
	r.before, _ = testguard.ThreadNetnsLink()
	r.err = inNetns12034(strconv.Itoa(os.Getpid()), func() error {
		r.during, _ = testguard.ThreadNetnsLink()
		return nil
	})
	r.after, _ = testguard.ThreadNetnsLink()
	done <- r
}

// TestInNetns12034ReturnsTheCallersThread19088: inNetns12034 must return the
// calling thread to the namespace IT was in. It used to "restore" to
// /proc/self/ns/net, the leader's namespace (#19088), which here is the
// package namespace, so the caller came back out of its private namespace.
func TestInNetns12034ReturnsTheCallersThread19088(t *testing.T) {
	done := make(chan innetns12034Result19088, 1)
	go innetns12034OffLeader19088(done)
	r := <-done
	if r.skip != nil {
		if os.Getenv("XPF_REQUIRE_NETNS") != "" {
			t.Fatalf("cannot enter a private netns: %v (XPF_REQUIRE_NETNS is set)", r.skip)
		}
		t.Skipf("cannot enter a private netns: %v", r.skip)
	}
	if r.err != nil {
		t.Fatalf("inNetns12034: %v", r.err)
	}
	if r.before == "" || r.before == r.during {
		t.Fatalf("FIXTURE: the caller (%s) must sit outside the namespace it visits (%s)", r.before, r.during)
	}
	if r.after != r.before {
		t.Fatalf("after inNetns12034 the caller's thread is in %s, want its own %s", r.after, r.before)
	}
}
