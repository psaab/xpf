// #5250 (A6-b2 F1): ForEachSnapshotNeighbor invoked the caller's callback
// while holding m.mu, so any callback that re-entered a Manager accessor
// (SnapshotHasIfindex, LookupSnapshotNeighbor, ...) SELF-DEADLOCKED the
// daemon, and every callback held the manager lock across arbitrary work
// (the force-probe path emits netlink/control-socket traffic) on the same
// lock the control socket already contends for. The walk now snapshots the
// (ifindex, ip) pairs under the lock and calls fn with the lock released.
//
// FAIL-ON-REVERT: restore `m.mu.Lock(); defer m.mu.Unlock()` around the fn
// call and this test HANGS on the re-entrant accessor until the deadline
// below fires it RED.
package userspace

import (
	"net"
	"testing"
	"time"
)

func TestForEachSnapshotNeighborCallbackNotUnderLock_5250(t *testing.T) {
	m := &Manager{
		neighborIndex: map[neighborIndexKey]*NeighborSnapshot{
			{ifindex: 7, ip: "10.0.1.5"}:  {Ifindex: 7, IP: "10.0.1.5", Family: "inet"},
			{ifindex: 7, ip: "10.0.1.6"}:  {Ifindex: 7, IP: "10.0.1.6", Family: "inet"},
			{ifindex: 9, ip: "fe80::1"}:   {Ifindex: 9, IP: "fe80::1", Family: "inet6"},
			{ifindex: 9, ip: "not-an-ip"}: {Ifindex: 9, IP: "not-an-ip", Family: "inet"},
		},
	}

	type visit struct {
		ifindex int
		ip      string
	}
	done := make(chan []visit, 1)
	go func() {
		var seen []visit
		m.ForEachSnapshotNeighbor(func(ifindex int, ip net.IP) {
			// Re-entrancy is the point: this takes m.mu itself. Under the
			// pre-fix code this blocks forever on the lock fn is called with.
			if !m.SnapshotHasIfindex(ifindex) {
				t.Errorf("SnapshotHasIfindex(%d) = false for a neighbor just yielded", ifindex)
			}
			seen = append(seen, visit{ifindex, ip.String()})
		})
		done <- seen
	}()

	select {
	case seen := <-done:
		if len(seen) != 3 {
			t.Fatalf("visited %d neighbors (%v), want 3 (the unparseable IP is skipped)", len(seen), seen)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("ForEachSnapshotNeighbor deadlocked: the callback re-entered a Manager accessor while m.mu was still held")
	}

	// The lock really is free afterwards (no leaked hold on the snapshot copy).
	if !m.SnapshotHasIfindex(7) {
		t.Fatal("SnapshotHasIfindex(7) = false after the walk")
	}
}
