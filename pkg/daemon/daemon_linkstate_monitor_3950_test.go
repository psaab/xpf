package daemon

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// linkStateEmitRecorder captures link up/down transitions emitted by the
// monitor so a test can assert on them without wiring an SNMP agent.
type linkStateEmitRecorder struct {
	mu     sync.Mutex
	events []linkStateEvent
}

type linkStateEvent struct {
	index   int
	name    string
	up      bool
	adminUp bool
}

func (r *linkStateEmitRecorder) emit(index int, name string, up, adminUp bool) {
	r.mu.Lock()
	r.events = append(r.events, linkStateEvent{index, name, up, adminUp})
	r.mu.Unlock()
}

func (r *linkStateEmitRecorder) snapshot() []linkStateEvent {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]linkStateEvent, len(r.events))
	copy(out, r.events)
	return out
}

// linkFor builds a minimal netlink.Link carrying just the attrs the link
// monitor reads (index, name, oper state).
func linkFor(index int, name string, up bool) netlink.Link {
	oper := netlink.LinkOperState(netlink.OperDown)
	if up {
		oper = netlink.OperUp
	}
	return &netlink.Device{LinkAttrs: netlink.LinkAttrs{
		Index:     index,
		Name:      name,
		OperState: oper,
		Flags:     net.FlagUp,
	}}
}

// waitUntil polls cond until true or the deadline, so tests never hang the
// whole suite on a regression (they fail fast instead).
func waitUntil(t *testing.T, d time.Duration, cond func() bool) bool {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if cond() {
			return true
		}
		time.Sleep(time.Millisecond)
	}
	return cond()
}

// TestMonitorLinkStateResubscribesOnENOBUFS is the #3950 RED-on-revert
// test. The first subscription simulates a receive-buffer overflow: it
// reports ENOBUFS via the error callback and closes the update channel —
// exactly how vishvananda/netlink surfaces ENOBUFS to a consumer. The
// pre-#3950 loop returned on that channel close and the monitor died
// permanently. The fixed loop must:
//   - RESUBSCRIBE (a second subscription is established),
//   - RE-SYNC via LinkList and emit a catch-up trap for the down transition
//     that happened while the buffer overflowed (idx 5 went UP -> DOWN), and
//   - CONTINUE streaming, delivering the subsequent real event (idx 6 UP).
//
// On revert (return on channel close), neither the catch-up nor the
// streamed event is emitted and this test times out -> RED.
func TestMonitorLinkStateResubscribesOnENOBUFS(t *testing.T) {
	rec := &linkStateEmitRecorder{}

	var listCalls int
	var listMu sync.Mutex
	linkList := func() ([]netlink.Link, error) {
		listMu.Lock()
		listCalls++
		n := listCalls
		listMu.Unlock()
		if n == 1 {
			// Boot seed: idx 5 is up.
			return []netlink.Link{linkFor(5, "ge-0-0-1", true)}, nil
		}
		// Post-ENOBUFS catch-up: idx 5 has since gone down (the transition
		// whose notification was dropped by the overflow).
		return []netlink.Link{linkFor(5, "ge-0-0-1", false)}, nil
	}

	var subCalls int
	subscribe := func(ch chan<- netlink.LinkUpdate, done <-chan struct{}, onErr func(error)) error {
		subCalls++
		n := subCalls
		go func() {
			defer close(ch)
			if n == 1 {
				// Simulate a receive-buffer overflow: report ENOBUFS, then
				// let the channel close (the netlink lib's terminal behavior).
				onErr(unix.ENOBUFS)
				return
			}
			// Second subscription: stream a real link-up event, then block
			// until the monitor tears the subscription down (ctx cancel).
			ch <- netlink.LinkUpdate{Link: linkFor(6, "ge-0-0-2", true)}
			<-done
		}()
		return nil
	}

	d := &Daemon{
		linkStateList:         linkList,
		linkStateSubscribe:    subscribe,
		linkStateEmit:         rec.emit,
		linkStateResubBackoff: time.Millisecond,
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	doneCh := make(chan struct{})
	go func() {
		d.monitorLinkState(ctx)
		close(doneCh)
	}()

	// Wait for BOTH the catch-up down (idx 5) and the streamed up (idx 6).
	ok := waitUntil(t, 2*time.Second, func() bool {
		var sawDown5, sawUp6 bool
		for _, e := range rec.snapshot() {
			if e.index == 5 && !e.up {
				sawDown5 = true
			}
			if e.index == 6 && e.up {
				sawUp6 = true
			}
		}
		return sawDown5 && sawUp6
	})
	if !ok {
		t.Fatalf("monitor did not resubscribe + catch up + continue after ENOBUFS; emitted=%+v subCalls=%d",
			rec.snapshot(), subCalls)
	}

	if subCalls < 2 {
		t.Fatalf("expected at least 2 subscriptions (resubscribe after ENOBUFS), got %d", subCalls)
	}

	cancel()
	select {
	case <-doneCh:
	case <-time.After(2 * time.Second):
		t.Fatal("monitorLinkState did not exit after context cancel")
	}
}

// TestMonitorLinkStateContextCancelExits verifies the loop exits cleanly on
// context cancellation (no resubscribe churn, no hang) while a subscription
// is live and idle.
func TestMonitorLinkStateContextCancelExits(t *testing.T) {
	rec := &linkStateEmitRecorder{}

	subscribe := func(ch chan<- netlink.LinkUpdate, done <-chan struct{}, onErr func(error)) error {
		go func() {
			defer close(ch)
			<-done // stay subscribed until torn down
		}()
		return nil
	}

	d := &Daemon{
		linkStateList:         func() ([]netlink.Link, error) { return nil, nil },
		linkStateSubscribe:    subscribe,
		linkStateEmit:         rec.emit,
		linkStateResubBackoff: time.Millisecond,
	}

	ctx, cancel := context.WithCancel(context.Background())
	doneCh := make(chan struct{})
	go func() {
		d.monitorLinkState(ctx)
		close(doneCh)
	}()

	// Give the monitor a moment to establish the subscription, then cancel.
	time.Sleep(20 * time.Millisecond)
	cancel()

	select {
	case <-doneCh:
	case <-time.After(2 * time.Second):
		t.Fatal("monitorLinkState did not exit on context cancel")
	}
	if got := rec.snapshot(); len(got) != 0 {
		t.Fatalf("expected no traps for an idle subscription, got %+v", got)
	}
}

// TestMonitorLinkStateStreamsNormalEvent verifies the happy path: a link
// up/down transition streamed by a healthy subscription emits a trap, and
// the boot seed does NOT emit a trap for interfaces already up.
func TestMonitorLinkStateStreamsNormalEvent(t *testing.T) {
	rec := &linkStateEmitRecorder{}

	linkList := func() ([]netlink.Link, error) {
		// Seed: idx 7 already up at boot (must NOT emit).
		return []netlink.Link{linkFor(7, "ge-0-0-3", true)}, nil
	}

	subscribe := func(ch chan<- netlink.LinkUpdate, done <-chan struct{}, onErr func(error)) error {
		go func() {
			defer close(ch)
			// A new interface (idx 8) comes up: a real transition -> trap.
			ch <- netlink.LinkUpdate{Link: linkFor(8, "ge-0-0-4", true)}
			<-done
		}()
		return nil
	}

	d := &Daemon{
		linkStateList:         linkList,
		linkStateSubscribe:    subscribe,
		linkStateEmit:         rec.emit,
		linkStateResubBackoff: time.Millisecond,
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	doneCh := make(chan struct{})
	go func() {
		d.monitorLinkState(ctx)
		close(doneCh)
	}()

	ok := waitUntil(t, 2*time.Second, func() bool {
		for _, e := range rec.snapshot() {
			if e.index == 8 && e.up {
				return true
			}
		}
		return false
	})
	if !ok {
		t.Fatalf("streamed link-up event was not emitted; got %+v", rec.snapshot())
	}

	// The boot-seeded already-up interface must not have produced a trap.
	for _, e := range rec.snapshot() {
		if e.index == 7 {
			t.Fatalf("boot seed emitted a trap for an already-up interface: %+v", e)
		}
	}

	cancel()
	select {
	case <-doneCh:
	case <-time.After(2 * time.Second):
		t.Fatal("monitorLinkState did not exit after context cancel")
	}
}
