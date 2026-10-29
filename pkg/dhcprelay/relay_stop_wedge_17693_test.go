package dhcprelay

import (
	"context"
	"sync"
	"testing"
	"time"
)

// #17693: bootstrap folds service-stop failures into DEGRADED reporting, but
// Manager.Apply formerly joined removed relay goroutines without a timeout or
// error result. A wedged owner therefore blocked rollback forever. This relay
// stands in for an owner that does not close done after cancellation; no socket,
// interface, or kernel operation is involved.
func TestRelayStopWedgeSurfaces17693(t *testing.T) {
	originalTimeout := relayStopTimeout
	relayStopTimeout = 50 * time.Millisecond
	defer func() { relayStopTimeout = originalTimeout }()

	factory, _ := recordingFactory()
	m := testManager(factory)
	done := make(chan struct{})
	replacedDone := make(chan struct{})
	v6Done := make(chan struct{})
	m.relays["xpf-test-wedged17693"] = &interfaceRelay{
		ifaceName: "xpf-test-wedged17693",
		cancel:    func() {},
		done:      done,
	}
	var releaseDoneOnce, releaseReplacedOnce, releaseV6Once sync.Once
	releaseDone := func() { releaseDoneOnce.Do(func() { close(done) }) }
	releaseReplaced := func() { releaseReplacedOnce.Do(func() { close(replacedDone) }) }
	releaseV6 := func() { releaseV6Once.Do(func() { close(v6Done) }) }
	t.Cleanup(func() {
		releaseDone()
		releaseReplaced()
		releaseV6()
		m.Stop()
	})

	result := make(chan error, 1)
	go func() { result <- m.Apply(context.Background(), nil) }()
	select {
	case err := <-result:
		if err == nil {
			releaseDone()
			t.Fatal("a wedged relay stop must be reported, not folded into a clean apply")
		}
	case <-time.After(time.Second):
		releaseDone() // release an unbounded join if the timeout regresses.
		<-result
		t.Fatal("wedged relay stop blocked bootstrap service reconciliation")
	}

	// An incomplete stop remains visible and blocks replacement until the
	// owner exits. A later reconcile can then start the desired replacement.
	if got := len(m.Stats()); got != 1 {
		releaseDone()
		t.Fatalf("managed relay count while owner is wedged = %d, want 1", got)
	}
	releaseDone()
	if err := m.Apply(context.Background(), nil); err != nil {
		t.Fatalf("retry after relay owner exited: %v", err)
	}
	if got := len(m.Stats()); got != 0 {
		t.Fatalf("managed relay count after completed stop = %d, want 0", got)
	}

	old := &interfaceRelay{
		ifaceName: "xpf-test-replaced17693",
		cancel:    func() {},
		done:      replacedDone,
		spec:      relaySpec{servers: []string{"192.0.2.1"}},
		pending:   newPendingTable(10, pendingTTL, time.Now),
	}
	m.relays[old.ifaceName] = old
	replacement := relayConfig([]string{"192.0.2.2"}, false, old.ifaceName)
	if err := m.Apply(context.Background(), replacement); err == nil {
		releaseReplaced()
		t.Fatal("a wedged old relay must prevent a replacement from starting")
	}
	if got := m.relays[old.ifaceName]; got != old {
		releaseReplaced()
		t.Fatalf("managed relay after failed restart = %p, want retained old relay %p", got, old)
	}
	releaseReplaced()
	if err := m.Apply(context.Background(), replacement); err != nil {
		t.Fatalf("reconcile after old owner exited: %v", err)
	}
	if got := m.relays[old.ifaceName]; got == old {
		t.Fatal("later reconcile left the timed-out, canceled relay in place instead of starting its replacement")
	}

	m.v6.relays["xpf-test-wedged6-17693"] = &dhcpV6Relay{
		ifaceName: "xpf-test-wedged6-17693",
		cancel:    func() {},
		done:      v6Done,
	}
	if err := m.Apply(context.Background(), replacement); err == nil {
		releaseV6()
		t.Fatal("a wedged DHCPv6 relay stop must also be reported")
	}
	if got := len(m.Stats()); got != 2 {
		releaseV6()
		t.Fatalf("managed relay count while DHCPv6 owner is wedged = %d, want 2", got)
	}
	releaseV6()
	if err := m.Apply(context.Background(), replacement); err != nil {
		t.Fatalf("retry after DHCPv6 relay owner exited: %v", err)
	}
	if got := len(m.Stats()); got != 1 {
		t.Fatalf("managed relays after DHCPv6 stop = %d, want retained v4 relay (1)", got)
	}
	if err := m.Apply(context.Background(), nil); err != nil {
		t.Fatalf("stop retained v4 relay: %v", err)
	}
	if got := len(m.Stats()); got != 0 {
		t.Fatalf("managed relays after final stop = %d, want 0", got)
	}
}
