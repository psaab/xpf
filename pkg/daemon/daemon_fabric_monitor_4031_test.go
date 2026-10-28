package daemon

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vishvananda/netlink"
)

// fabricSubRecorder records how many times each fabric netlink subscription
// was started and which subscription round's done channel was closed by the
// monitor. A closed done channel is the observable that the monitor released
// that netlink socket (no fd leak) — the #4031 sibling-leak proof.
type fabricSubRecorder struct {
	mu              sync.Mutex
	linkSubs        int
	neighSubs       int
	linkDoneClosed  []int
	neighDoneClosed []int
}

func (r *fabricSubRecorder) nextLink() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.linkSubs++
	return r.linkSubs
}

func (r *fabricSubRecorder) nextNeigh() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.neighSubs++
	return r.neighSubs
}

func (r *fabricSubRecorder) recordLinkDone(n int) {
	r.mu.Lock()
	r.linkDoneClosed = append(r.linkDoneClosed, n)
	r.mu.Unlock()
}

func (r *fabricSubRecorder) recordNeighDone(n int) {
	r.mu.Lock()
	r.neighDoneClosed = append(r.neighDoneClosed, n)
	r.mu.Unlock()
}

func (r *fabricSubRecorder) linkSubCalls() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.linkSubs
}

func (r *fabricSubRecorder) neighSubCalls() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.neighSubs
}

func (r *fabricSubRecorder) linkDoneWasClosed(n int) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, v := range r.linkDoneClosed {
		if v == n {
			return true
		}
	}
	return false
}

func (r *fabricSubRecorder) neighDoneWasClosed(n int) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, v := range r.neighDoneClosed {
		if v == n {
			return true
		}
	}
	return false
}

// drainFabricRefresh consumes slot 0's refreshCh into an atomic counter so a
// test can assert the monitor kept triggering fabric refreshes after a
// resubscribe. Returns the counter and a stop func.
func drainFabricRefresh(ch <-chan struct{}) (*int32, func()) {
	var count int32
	stop := make(chan struct{})
	go func() {
		for {
			select {
			case <-stop:
				return
			case <-ch:
				atomic.AddInt32(&count, 1)
			}
		}
	}()
	return &count, func() { close(stop) }
}

// TestMonitorFabricStateResubscribesOnLinkChannelClose is a #4031 RED-on-revert
// test for the LINK subscription branch. The first link subscription simulates
// a recoverable ENOBUFS receive-buffer overflow: it closes the update channel
// (exactly how vishvananda/netlink surfaces a receive error). The pre-#4031
// loop returned on that close — permanently dead — AND leaked the sibling
// neighbor socket (it never closed neighDone). The fixed monitor must:
//   - RESUBSCRIBE (a second link subscription is established),
//   - CLOSE the sibling neighbor socket from round 1 (no fd leak), and
//   - CONTINUE — re-sync fabric forwarding and deliver a subsequent fabric
//     link event (triggerFabricRefresh fires again).
//
// On revert, the monitor exits after the first close: linkSubCalls stays at 1,
// the round-1 neighbor done is never closed (leak), and no further refresh
// fires -> this test times out (RED).
func TestMonitorFabricStateResubscribesOnLinkChannelClose(t *testing.T) {
	rec := &fabricSubRecorder{}

	linkSubscribe := func(ch chan<- netlink.LinkUpdate, done <-chan struct{}) error {
		n := rec.nextLink()
		go func() {
			// Mirror the netlink socket teardown: when done closes, record it
			// (the monitor released this fd).
			go func() { <-done; rec.recordLinkDone(n) }()
			if n == 1 {
				// Simulate ENOBUFS: close the update channel and return.
				close(ch)
				return
			}
			// Second subscription: stream a real fabric link event, then stay
			// live until the monitor tears the subscription down.
			ch <- netlink.LinkUpdate{Link: linkFor(11, "fab0", true)}
			<-done
			close(ch)
		}()
		return nil
	}

	neighSubscribe := func(ch chan<- netlink.NeighUpdate, done <-chan struct{}) error {
		n := rec.nextNeigh()
		go func() {
			go func() { <-done; rec.recordNeighDone(n) }()
			<-done
			close(ch)
		}()
		return nil
	}

	d := &Daemon{
		fabricSlots:             [2]fabricSlot{{name: "fabric", iface: "fab0", refreshCh: make(chan struct{}, 64)}, {name: "fabric1"}},
		fabricLinkSubscribe:     linkSubscribe,
		fabricNeighSubscribe:    neighSubscribe,
		fabricStateResubBackoff: time.Millisecond,
	}
	refreshes, stopDrain := drainFabricRefresh(d.fabricSlots[0].refreshCh)
	defer stopDrain()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	doneCh := make(chan struct{})
	go func() {
		d.monitorFabricState(ctx)
		close(doneCh)
	}()

	// Resubscribe happened (>=2 link subscriptions).
	if !waitUntil(t, 2*time.Second, func() bool { return rec.linkSubCalls() >= 2 }) {
		t.Fatalf("monitor did not resubscribe after link channel close; linkSubCalls=%d", rec.linkSubCalls())
	}
	// The round-1 sibling neighbor socket was released (no fd leak).
	if !waitUntil(t, 2*time.Second, func() bool { return rec.neighDoneWasClosed(1) }) {
		t.Fatalf("round-1 sibling neighbor socket leaked (neighDone never closed) after link channel close")
	}
	// The monitor kept triggering fabric refreshes after resubscribe (catch-up
	// re-sync + the streamed fab0 event). >=2 proves it did not go dark.
	if !waitUntil(t, 2*time.Second, func() bool { return atomic.LoadInt32(refreshes) >= 2 }) {
		t.Fatalf("monitor stopped triggering fabric refreshes after resubscribe; refreshes=%d", atomic.LoadInt32(refreshes))
	}

	cancel()
	select {
	case <-doneCh:
	case <-time.After(2 * time.Second):
		t.Fatal("monitorFabricState did not exit after context cancel")
	}
}

// TestMonitorFabricStateResubscribesOnNeighChannelClose is the #4031
// RED-on-revert test for the NEIGHBOR subscription branch: a recoverable close
// of the neighbor channel must resubscribe and must release the sibling LINK
// socket (the mirror-image leak).
func TestMonitorFabricStateResubscribesOnNeighChannelClose(t *testing.T) {
	rec := &fabricSubRecorder{}

	linkSubscribe := func(ch chan<- netlink.LinkUpdate, done <-chan struct{}) error {
		n := rec.nextLink()
		go func() {
			go func() { <-done; rec.recordLinkDone(n) }()
			<-done // stay live until torn down
			close(ch)
		}()
		return nil
	}

	neighSubscribe := func(ch chan<- netlink.NeighUpdate, done <-chan struct{}) error {
		n := rec.nextNeigh()
		go func() {
			go func() { <-done; rec.recordNeighDone(n) }()
			if n == 1 {
				close(ch) // simulate ENOBUFS on the neighbor socket
				return
			}
			<-done
			close(ch)
		}()
		return nil
	}

	d := &Daemon{
		fabricSlots:             [2]fabricSlot{{name: "fabric", refreshCh: make(chan struct{}, 64)}, {name: "fabric1"}},
		fabricLinkSubscribe:     linkSubscribe,
		fabricNeighSubscribe:    neighSubscribe,
		fabricStateResubBackoff: time.Millisecond,
	}
	_, stopDrain := drainFabricRefresh(d.fabricSlots[0].refreshCh)
	defer stopDrain()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	doneCh := make(chan struct{})
	go func() {
		d.monitorFabricState(ctx)
		close(doneCh)
	}()

	if !waitUntil(t, 2*time.Second, func() bool { return rec.neighSubCalls() >= 2 }) {
		t.Fatalf("monitor did not resubscribe after neigh channel close; neighSubCalls=%d", rec.neighSubCalls())
	}
	if !waitUntil(t, 2*time.Second, func() bool { return rec.linkDoneWasClosed(1) }) {
		t.Fatalf("round-1 sibling link socket leaked (linkDone never closed) after neigh channel close")
	}

	cancel()
	select {
	case <-doneCh:
	case <-time.After(2 * time.Second):
		t.Fatal("monitorFabricState did not exit after context cancel")
	}
}

// TestMonitorFabricStateContextCancelExits verifies the loop exits cleanly on
// context cancellation while both subscriptions are live and idle, closing
// both netlink sockets (no leak, no resubscribe churn).
func TestMonitorFabricStateContextCancelExits(t *testing.T) {
	rec := &fabricSubRecorder{}

	linkSubscribe := func(ch chan<- netlink.LinkUpdate, done <-chan struct{}) error {
		n := rec.nextLink()
		go func() {
			go func() { <-done; rec.recordLinkDone(n) }()
			<-done
			close(ch)
		}()
		return nil
	}
	neighSubscribe := func(ch chan<- netlink.NeighUpdate, done <-chan struct{}) error {
		n := rec.nextNeigh()
		go func() {
			go func() { <-done; rec.recordNeighDone(n) }()
			<-done
			close(ch)
		}()
		return nil
	}

	d := &Daemon{
		fabricSlots:             [2]fabricSlot{{name: "fabric", refreshCh: make(chan struct{}, 64)}, {name: "fabric1"}},
		fabricLinkSubscribe:     linkSubscribe,
		fabricNeighSubscribe:    neighSubscribe,
		fabricStateResubBackoff: time.Millisecond,
	}
	_, stopDrain := drainFabricRefresh(d.fabricSlots[0].refreshCh)
	defer stopDrain()

	ctx, cancel := context.WithCancel(context.Background())
	doneCh := make(chan struct{})
	go func() {
		d.monitorFabricState(ctx)
		close(doneCh)
	}()

	// Let both subscriptions establish, then cancel.
	if !waitUntil(t, 2*time.Second, func() bool {
		return rec.linkSubCalls() >= 1 && rec.neighSubCalls() >= 1
	}) {
		t.Fatal("subscriptions were not established")
	}
	time.Sleep(10 * time.Millisecond)
	cancel()

	select {
	case <-doneCh:
	case <-time.After(2 * time.Second):
		t.Fatal("monitorFabricState did not exit on context cancel")
	}
	// Both sockets released on the clean-exit path.
	if !waitUntil(t, 2*time.Second, func() bool {
		return rec.linkDoneWasClosed(1) && rec.neighDoneWasClosed(1)
	}) {
		t.Fatal("context-cancel exit leaked a netlink socket (a done channel was never closed)")
	}
	// A single live subscription, no churn.
	if got := rec.linkSubCalls(); got != 1 {
		t.Fatalf("expected exactly 1 link subscription for an idle monitor, got %d", got)
	}
}
