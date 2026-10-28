package daemon

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/vishvananda/netlink"

	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)

// #17060 — fabric slot state is epoch-scoped. Pre-fix, stopClusterComms
// nilled only the refresh channels: both slots' iface/peer/populated state
// (and the helper identity constraints) survived teardown, RefreshFabricFwd
// re-probed/refreshed the dead slots from three fire-and-forget
// `go d.RefreshFabricFwd()` sites with context.Background(), and
// reconcileRGState's fabric gate read the stale populated latches (masked
// only by the #15918 helper conjunct).

// seedFabricSlots17060 installs both slots as a populate epoch would:
// addressed, identity-remembered, populated, with a queued probe pending,
// plus published refresh channels and the live helper constraints.
func seedFabricSlots17060(t *testing.T, d *Daemon) (ch0, ch1 chan struct{}) {
	t.Helper()
	peer0 := "10.99.0.2"
	peer1 := "10.99.1.2"
	t.Cleanup(func() {
		dpuserspace.RegisterFabricPeerMACConstraint(peer0, nil)
		dpuserspace.RegisterFabricPeerMACConstraint(peer1, nil)
	})
	mac := mustMAC(t, fabPeerTestPeerMAC)
	dpuserspace.RegisterFabricPeerMACConstraint(peer0, mac)
	dpuserspace.RegisterFabricPeerMACConstraint(peer1, mac)

	ch0 = make(chan struct{}, 1)
	ch1 = make(chan struct{}, 1)
	d.clusterCommsMu.Lock()
	d.fabricRefreshCh = ch0
	d.fabricRefreshCh1 = ch1
	d.clusterCommsMu.Unlock()

	d.fabricMu.Lock()
	d.fabricIface, d.fabricOverlay = "ge-0-0-0", "fab0"
	d.fabricPeerIP = net.ParseIP(peer0)
	d.fabricPeerMAC = mac
	d.fabricPopulated = true
	d.fabricIface1, d.fabricOverlay1 = "ge-0-0-5", "fab1"
	d.fabricPeerIP1 = net.ParseIP(peer1)
	d.fabricPeerMAC1 = mac
	d.fabric1Populated = true
	d.lastFabricProbe = time.Now()
	d.lastFabricProbe1 = time.Now()
	d.fabricProbePending = true
	d.fabricProbePending1 = true
	d.fabricMu.Unlock()
	return ch0, ch1
}

func assertFabricSlotsZeroed17060(t *testing.T, d *Daemon) {
	t.Helper()
	d.fabricMu.RLock()
	defer d.fabricMu.RUnlock()
	if d.fabricIface != "" || d.fabricOverlay != "" || d.fabricPeerIP != nil ||
		len(d.fabricPeerMAC) != 0 || d.fabricPopulated {
		t.Fatalf("fab0 slot survived teardown: iface=%q overlay=%q peer=%v mac=%v populated=%v (#17060)",
			d.fabricIface, d.fabricOverlay, d.fabricPeerIP, d.fabricPeerMAC, d.fabricPopulated)
	}
	if d.fabricIface1 != "" || d.fabricOverlay1 != "" || d.fabricPeerIP1 != nil ||
		len(d.fabricPeerMAC1) != 0 || d.fabric1Populated {
		t.Fatalf("fab1 slot survived teardown: iface=%q overlay=%q peer=%v mac=%v populated=%v (#17060)",
			d.fabricIface1, d.fabricOverlay1, d.fabricPeerIP1, d.fabricPeerMAC1, d.fabric1Populated)
	}
	if !d.lastFabricProbe.IsZero() || !d.lastFabricProbe1.IsZero() ||
		d.fabricProbePending || d.fabricProbePending1 {
		t.Fatal("probe rate-limit/pending state survived teardown (#17060)")
	}
	if got0, got1 := d.snapshotFabricRefreshChans(); got0 != nil || got1 != nil {
		t.Fatalf("refresh channels survived teardown: %v %v", got0, got1)
	}
}

// TestStopClusterCommsClearsFabricSlots17060 is the vq32 lifecycle probe
// as a hermetic cell: both slots seeded, the REAL stopClusterComms, then
// zeroed slots and dropped helper constraints. RED pre-fix (slots and
// constraints survive; channels were already nilled).
func TestStopClusterCommsClearsFabricSlots17060(t *testing.T) {
	d := &Daemon{}
	seedFabricSlots17060(t, d)

	d.stopClusterComms()

	assertFabricSlotsZeroed17060(t, d)
	// The constraint map has no exported getter; a cleared constraint is
	// proven behaviourally by TestFabricConstraintClearedOnStop17060.
}

// TestFabricConstraintClearedOnStop17060: after teardown, an ambiguous
// link-local segment for the old peer address must fail closed. While the
// identity constraint lived, sole-decoy resolution would bind to it (see
// fabricPeerMACConstraint's role in SelectFabricPeerLinkLocalMAC); with it
// cleared and two candidates present, resolution refuses.
func TestFabricConstraintClearedOnStop17060(t *testing.T) {
	d, rec := fabPeerTestDaemon(t, []netlink.Neigh{
		fabPeerNeigh(t, "fe80::dec0", fabPeerTestDecoyMAC),
		fabPeerNeigh(t, "fe80::b", fabPeerTestPeerMAC),
	})
	// Arm the identity as an earlier address-matched resolution would.
	d.rememberFabricPeerMAC(0, mustMAC(t, fabPeerTestPeerMAC))
	// Seed the slot state stop must clear.
	d.fabricMu.Lock()
	d.fabricIface, d.fabricOverlay = "ge-0-0-0", "fab0"
	d.fabricPeerIP = net.ParseIP("10.99.13.2")
	d.fabricPopulated = true
	d.fabricMu.Unlock()

	d.stopClusterComms()

	if fabPeerRefresh(t, d) {
		t.Fatal("refresh resolved after teardown — stale identity constraint survived stopClusterComms (#17060)")
	}
	if got := rec.programmedPeerMACs(); len(got) != 0 {
		t.Fatalf("peer MAC programmed after teardown: %v (#17060)", got)
	}
}

// refreshFabricPeerChained17060 mirrors refreshFabricPeer's only
// fabricMu latch write, chained under fabricMu by the caller so the
// -race cell can order it against RefreshFabricFwd without reaching
// netlink or the dataplane. The production latch write is identical
// (slot-selected bool under fabricMu); see refreshFabricPeer.
func refreshFabricPeerChained17060(d *Daemon, slot int, ok bool) {
	// Caller holds fabricMu.
	if slot == 1 {
		d.fabric1Populated = ok
	} else {
		d.fabricPopulated = ok
	}
}

// TestRefreshFabricFwdRaceWithPopulateLatch17060 runs RefreshFabricFwd
// concurrently with the populate loop's latch writes under -race. The
// latch writer holds fabricMu across its write (the production refresh
// does the same), and RefreshFabricFwd only queues pokes under fabricMu
// and non-blocking channel sends — it never reads slot state outside
// fabricMu and never blocks. Asserts each slot ends at its last write.
func TestRefreshFabricFwdRaceWithPopulateLatch17060(t *testing.T) {
	d := &Daemon{}
	seedFabricSlots17060(t, d)

	const rounds = 200
	last := make([]bool, 2)
	var wg sync.WaitGroup
	for slot := range 2 {
		wg.Add(1)
		go func(slot int) {
			defer wg.Done()
			for i := range rounds {
				ok := i%2 == 0
				d.fabricMu.Lock()
				refreshFabricPeerChained17060(d, slot, ok)
				d.fabricMu.Unlock()
				last[slot] = ok
			}
		}(slot)
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		for range rounds {
			d.RefreshFabricFwd()
		}
	}()
	wg.Wait()

	// Drain any coalesced pokes so no sender remains; then the latch must
	// equal each writer's final write (RefreshFabricFwd never writes it).
	d.fabricMu.RLock()
	got := []bool{d.fabricPopulated, d.fabric1Populated}
	d.fabricMu.RUnlock()
	for slot := 0; slot < 2; slot++ {
		if got[slot] != last[slot] {
			t.Fatalf("slot %d populated=%v, want last write %v — RefreshFabricFwd raced the latch (#17060)",
				slot, got[slot], last[slot])
		}
	}
}

// TestRefreshFabricFwdAfterStopIsNoOp17060: with comms stopped, an event
// poke must not resolve, probe, or latch anything for the removed fabric.
// linkByNameFn errors, so any probe/refresh attempt returns before a
// transmit; the resolver is never reached because refresh runs only on
// the (absent) epoch loops.
func TestRefreshFabricFwdAfterStopIsNoOp17060(t *testing.T) {
	d := &Daemon{}
	seedFabricSlots17060(t, d)
	d.stopClusterComms()
	assertFabricSlotsZeroed17060(t, d)

	// Any link lookup from here would be a stale-slot access.
	d.linkByNameFn = func(string) (netlink.Link, error) {
		return nil, errors.New("link lookup after stopClusterComms (#17060)")
	}
	d.RefreshFabricFwd() // must not block, panic, or latch
	assertFabricSlotsZeroed17060(t, d)
}

// TestRefreshFabricFwdWakesEpochLoops17060 is the positive/control cell:
// on a live epoch, RefreshFabricFwd still wakes BOTH populate loops (and
// queues the rate-limited probe), so the event-driven refresh behaviour
// the three former `go` sites relied on is unchanged. Hermetic: the
// loops are replaced by receivers on the seeded channels, and the probe
// runs through linkByNameFn-error links (returns before any transmit).
func TestRefreshFabricFwdWakesEpochLoops17060(t *testing.T) {
	d := &Daemon{}
	ch0, ch1 := seedFabricSlots17060(t, d)
	// Reset probe timestamps so queueFabricProbe queues fresh probes.
	d.fabricMu.Lock()
	d.lastFabricProbe = time.Time{}
	d.lastFabricProbe1 = time.Time{}
	d.fabricProbePending = false
	d.fabricProbePending1 = false
	d.fabricMu.Unlock()
	d.linkByNameFn = func(string) (netlink.Link, error) {
		return nil, errors.New("no link in hermetic cell")
	}

	d.RefreshFabricFwd()

	for name, ch := range map[string]chan struct{}{"fab0": ch0, "fab1": ch1} {
		select {
		case <-ch:
		default:
			t.Fatalf("%s loop not woken by RefreshFabricFwd (#17060)", name)
		}
	}
	d.fabricMu.RLock()
	p0, p1 := d.fabricProbePending, d.fabricProbePending1
	d.fabricMu.RUnlock()
	if !p0 || !p1 {
		t.Fatalf("queued probes = (%v,%v), want both queued for the epoch loops (#17060)", p0, p1)
	}
	// The epoch loop consumes the flag and probes with the epoch ctx;
	// here the error link makes probeFabricNeighbor return pre-transmit.
	if !d.takeFabricProbePending(0) || d.takeFabricProbePending(0) {
		t.Fatal("fab0 probe flag must be consumable exactly once")
	}
	d.probeFabricNeighbor(context.Background(), "fab0", net.ParseIP("10.99.0.2"))
}
