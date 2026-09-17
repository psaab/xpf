package daemon

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/dataplane"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

type gateLinkRuntime9848 struct {
	dataplane.RuntimeDataPlane
	count              atomic.Int64
	reads              atomic.Int64
	readComplete       chan struct{}
	readCompleteAt     int
	secondReadComplete chan struct{}
	eventReadComplete  chan struct{}
}

func (r *gateLinkRuntime9848) AttachedXDPLinkCount() int {
	n := r.reads.Add(1)
	firstReadAt := r.readCompleteAt
	if firstReadAt == 0 {
		firstReadAt = 3
	}
	if r.readComplete != nil && n == int64(firstReadAt) {
		close(r.readComplete) // first watcher/gate-loop census
	}
	if r.secondReadComplete != nil && n == 4 {
		close(r.secondReadComplete) // second census (subscribe re-sync)
	}
	if r.eventReadComplete != nil && n == 5 {
		close(r.eventReadComplete) // census after a DELLINK wake
	}
	return int(r.count.Load())
}

func (r *gateLinkRuntime9848) SetAttachedLinksObserver(func()) {}

func newOpenGate9848(t *testing.T) (*Daemon, *gateLinkRuntime9848, string, string) {
	t.Helper()
	v4, v6 := withTempTransitForwardSysctls(t, "0")
	withBarrierRecorder(t)
	rt := &gateLinkRuntime9848{}
	rt.count.Store(1)
	d := &Daemon{}
	d.setDataplane(rt)
	d.markDataplaneArmed("test")
	waitTransitKnobs9725(t, v4, v6, "1")
	return d, rt, v4, v6
}

func TestTransitGateLinkWatchClosesOnDelete9848(t *testing.T) {
	d, rt, v4, v6 := newOpenGate9848(t)
	rt.readComplete = make(chan struct{})
	rt.secondReadComplete = make(chan struct{})
	rt.eventReadComplete = make(chan struct{})
	updatesReady := make(chan struct{})
	sendDelete := make(chan struct{})
	d.transitGateLinkSubscribe = func(ch chan<- netlink.LinkUpdate, done <-chan struct{}, onErr func(error)) error {
		close(updatesReady)
		go func() {
			select {
			case <-sendDelete:
				ch <- netlink.LinkUpdate{Header: unix.NlMsghdr{Type: unix.RTM_DELLINK}}
			case <-done:
			}
			<-done
		}()
		return nil
	}
	d.transitGateLinkResubBackoff = time.Millisecond

	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	oldInterval := transitGateTickInterval
	transitGateTickInterval = time.Hour
	t.Cleanup(func() { transitGateTickInterval = oldInterval })
	d.startTransitGateLoop(ctx, &wg)
	d.startTransitGateLinkWatch(ctx, &wg)
	t.Cleanup(func() { cancel(); wg.Wait() })

	select {
	case <-rt.readComplete:
	case <-time.After(time.Second):
		t.Fatal("gate loop did not perform its initial census")
	}
	select {
	case <-updatesReady:
	case <-time.After(time.Second):
		t.Fatal("link watcher did not subscribe")
	}
	select {
	case <-rt.secondReadComplete:
	case <-time.After(time.Second):
		t.Fatal("link watcher did not perform its initial gate re-sync")
	}
	// The watcher has read the attached state before this kernel-only
	// unregister equivalent: no dataplane writer or apply.
	rt.count.Store(0)
	close(sendDelete)
	// DELLINK is coalesced into the gate loop's buffered wake path. Waiting for
	// the post-wake census proves this test would fail if the event were ignored.
	select {
	case <-rt.eventReadComplete:
	case <-time.After(time.Second):
		t.Fatal("link watcher did not wake the gate after DELLINK")
	}
	waitTransitKnobs9725(t, v4, v6, "0")
}

func TestTransitGateLinkWatchResubscribeReasserts9848(t *testing.T) {
	d, rt, v4, v6 := newOpenGate9848(t)
	rt.readComplete = make(chan struct{})
	rt.secondReadComplete = make(chan struct{})
	firstClose := make(chan struct{})
	secondSubscribed := make(chan struct{})
	var subscriptions atomic.Int64
	d.transitGateLinkResubBackoff = time.Millisecond
	d.transitGateLinkSubscribe = func(ch chan<- netlink.LinkUpdate, done <-chan struct{}, onErr func(error)) error {
		switch subscriptions.Add(1) {
		case 1:
			go func() {
				<-firstClose
				close(ch) // ENOBUFS-equivalent terminal subscription close.
			}()
		case 2:
			close(secondSubscribed)
			go func() { <-done }()
		default:
			t.Fatalf("unexpected subscription retry")
		}
		return nil
	}

	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	d.startTransitGateLinkWatch(ctx, &wg)
	t.Cleanup(func() { cancel(); wg.Wait() })

	select {
	case <-rt.readComplete:
	case <-time.After(time.Second):
		t.Fatal("link watcher did not perform its initial gate re-sync")
	}
	rt.count.Store(0) // lost DELLINK notification window
	close(firstClose)
	select {
	case <-secondSubscribed:
	case <-time.After(time.Second):
		t.Fatal("link watcher did not resubscribe after channel close")
	}
	// The second subscribe must re-read kernel truth even though the event was
	// lost while the first socket was overflowing.
	select {
	case <-rt.secondReadComplete:
	case <-time.After(time.Second):
		t.Fatal("link watcher did not re-sync after resubscribe")
	}
	waitTransitKnobs9725(t, v4, v6, "0")
}

func TestTransitGateLinkWatchUnrelatedDeleteKeepsOpen9848(t *testing.T) {
	d, rt, v4, v6 := newOpenGate9848(t)
	rt.readComplete = make(chan struct{})
	rt.secondReadComplete = make(chan struct{})
	rt.eventReadComplete = make(chan struct{})
	updatesReady := make(chan struct{})
	sendDelete := make(chan struct{})
	d.transitGateLinkSubscribe = func(ch chan<- netlink.LinkUpdate, done <-chan struct{}, onErr func(error)) error {
		close(updatesReady)
		go func() {
			select {
			case <-sendDelete:
				ch <- netlink.LinkUpdate{Header: unix.NlMsghdr{Type: unix.RTM_DELLINK}}
			case <-done:
			}
			<-done
		}()
		return nil
	}
	d.transitGateLinkResubBackoff = time.Millisecond

	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	oldInterval := transitGateTickInterval
	transitGateTickInterval = time.Hour
	t.Cleanup(func() { transitGateTickInterval = oldInterval })
	d.startTransitGateLoop(ctx, &wg)
	d.startTransitGateLinkWatch(ctx, &wg)
	t.Cleanup(func() { cancel(); wg.Wait() })
	select {
	case <-rt.readComplete:
	case <-time.After(time.Second):
		t.Fatal("gate loop did not perform its initial census")
	}
	select {
	case <-updatesReady:
	case <-time.After(time.Second):
		t.Fatal("link watcher did not establish event subscription")
	}
	select {
	case <-rt.secondReadComplete:
	case <-time.After(time.Second):
		t.Fatal("link watcher did not perform its initial gate re-sync")
	}
	// One XDP-bearing link remains attached while this unrelated device is
	// deleted. The watcher must process the DELLINK before the assertion.
	close(sendDelete)
	select {
	case <-rt.eventReadComplete:
	case <-time.After(time.Second):
		t.Fatal("link watcher did not wake the gate after DELLINK")
	}
	if got := int(rt.count.Load()); got != 1 {
		t.Fatalf("fixture count = %d, want one remaining XDP link", got)
	}
	waitTransitKnobs9725(t, v4, v6, "1")
}

func TestTransitGateLinkWatchUnarmedResyncKeepsClosed9848(t *testing.T) {
	v4, v6 := withTempTransitForwardSysctls(t, "0")
	f := withBarrierRecorder(t)
	rt := &gateLinkRuntime9848{}
	rt.count.Store(1) // attachment alone must not open an unarmed gate
	d := &Daemon{}
	d.setDataplane(rt)
	d.dataplaneArmed.Store(false)
	subscribed := make(chan struct{})
	reasserted := make(chan struct{})
	f.barrierInstall = func() error {
		close(reasserted)
		return nil
	}
	d.transitGateLinkSubscribe = func(ch chan<- netlink.LinkUpdate, done <-chan struct{}, onErr func(error)) error {
		close(subscribed)
		go func() { <-done }()
		return nil
	}
	d.transitGateLinkResubBackoff = time.Millisecond

	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	d.startTransitGateLinkWatch(ctx, &wg)
	t.Cleanup(func() { cancel(); wg.Wait() })
	select {
	case <-subscribed:
	case <-time.After(time.Second):
		t.Fatal("link watcher did not subscribe")
	}
	select {
	case <-reasserted:
	case <-time.After(time.Second):
		t.Fatal("link watcher did not reassert the unarmed gate")
	}
	// The watcher path must preserve the two-conjunct predicate: an attached
	// link cannot reopen transit while dataplaneArmed is false.
	waitTransitKnobs9725(t, v4, v6, "0")
}
