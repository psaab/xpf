package daemon

import (
	"net"
	"testing"
)

func TestRetainFabricFwdOnNeighborMissWithoutCachedEntry(t *testing.T) {
	d := &Daemon{}
	if d.retainFabricFwdOnNeighborMiss(0, net.ParseIP("10.99.13.2"), "fab0", false) {
		t.Fatal("expected missing neighbor without cached fabric state to remain not ready")
	}
	if d.fabricEntryPopulated(0) {
		t.Fatal("fabric entry should not become populated")
	}
}

func TestRetainFabricFwdOnNeighborMissWithCachedEntry(t *testing.T) {
	d := &Daemon{}
	d.fabricMu.Lock()
	d.fabricSlots[0].populated = true
	d.fabricMu.Unlock()

	if !d.retainFabricFwdOnNeighborMiss(0, net.ParseIP("10.99.13.2"), "fab0", false) {
		t.Fatal("expected cached fabric entry to survive a transient neighbor miss")
	}
	if !d.fabricEntryPopulated(0) {
		t.Fatal("cached fabric entry should remain populated")
	}
}

func TestRetainFabricFwdOnNeighborMissWithCachedSecondaryEntry(t *testing.T) {
	d := &Daemon{}
	d.fabricMu.Lock()
	d.fabricSlots[1].populated = true
	d.fabricMu.Unlock()

	if !d.retainFabricFwdOnNeighborMiss(1, net.ParseIP("10.99.13.1"), "fab1", false) {
		t.Fatal("expected cached secondary fabric entry to survive a transient neighbor miss")
	}
	if !d.fabricEntryPopulated(1) {
		t.Fatal("cached secondary fabric entry should remain populated")
	}
}

// TestTriggerFabricRefreshWakesBothFabrics asserts that a single fabric
// event wakes BOTH the fab0 and fab1 refresh loops. The netlink monitor
// does not tag events per-fabric, so any fabric link/neighbor change must
// re-resolve both entries. Before #4038 both loops selected on ONE shared
// channel, so a lone non-blocking send was received by exactly one waiting
// goroutine and the other fabric's event was lost until the 30s tick.
//
// RED-on-revert: drop the slot-1 send from triggerFabricRefresh (or point
// populateFabricFwdSlot(1) back at the shared channel) and the fab1 assertion
// fails — the dual-fabric event is dropped.
func TestTriggerFabricRefreshWakesBothFabrics(t *testing.T) {
	d := &Daemon{
		fabricSlots: [2]fabricSlot{{name: "fabric", refreshCh: make(chan struct{}, 1)}, {name: "fabric1", refreshCh: make(chan struct{}, 1)}},
	}

	d.triggerFabricRefresh()

	select {
	case <-d.fabricSlots[0].refreshCh:
	default:
		t.Fatal("fab0 refresh channel not signaled by triggerFabricRefresh")
	}
	select {
	case <-d.fabricSlots[1].refreshCh:
	default:
		t.Fatal("fab1 refresh channel not signaled — dual-fabric event lost (#4038)")
	}
}

// TestTriggerFabricRefreshCoalesces verifies the non-blocking sends coalesce:
// a second trigger before either loop drains leaves exactly one pending
// signal per channel (capacity 1) and never blocks the caller.
func TestTriggerFabricRefreshCoalesces(t *testing.T) {
	d := &Daemon{
		fabricSlots: [2]fabricSlot{{name: "fabric", refreshCh: make(chan struct{}, 1)}, {name: "fabric1", refreshCh: make(chan struct{}, 1)}},
	}

	d.triggerFabricRefresh()
	d.triggerFabricRefresh() // must not block even though both are full.

	if got := len(d.fabricSlots[0].refreshCh); got != 1 {
		t.Fatalf("fab0 channel depth = %d, want coalesced to 1", got)
	}
	if got := len(d.fabricSlots[1].refreshCh); got != 1 {
		t.Fatalf("fab1 channel depth = %d, want coalesced to 1", got)
	}
}

// TestTriggerFabricRefreshSingleFabricNoPanic verifies the single-fabric
// case: fab1 is not configured so slot 1's refreshCh is nil. A non-blocking
// send on a nil channel is never ready, so the default arm runs and the
// caller must not block or panic.
func TestTriggerFabricRefreshSingleFabricNoPanic(t *testing.T) {
	d := &Daemon{
		fabricSlots: [2]fabricSlot{{name: "fabric", refreshCh: make(chan struct{}, 1)}, {name: "fabric1"}},
		// Slot 1 refreshCh intentionally left nil (single-fabric cluster).
	}

	d.triggerFabricRefresh()

	select {
	case <-d.fabricSlots[0].refreshCh:
	default:
		t.Fatal("fab0 refresh channel not signaled in single-fabric mode")
	}
}
