package daemon

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/vishvananda/netlink"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)

// #17060 — fabric slot state is epoch-scoped. Before the fix, stopClusterComms
// nilled only the refresh channels: iface/peer/populated state and helper
// identity constraints survived teardown, and reconcileRGState could observe a
// stale populated latch (masked only by the #15918 helper conjunct).

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
	d.fabricSlots[0].refreshCh = ch0
	d.fabricSlots[1].refreshCh = ch1
	d.clusterCommsMu.Unlock()

	d.fabricMu.Lock()
	d.fabricSlots[0].iface, d.fabricSlots[0].overlay = "ge-0-0-0", "fab0"
	d.fabricSlots[0].peerIP = net.ParseIP(peer0)
	d.fabricSlots[0].peerMAC = mac
	d.fabricSlots[0].populated = true
	d.fabricSlots[1].iface, d.fabricSlots[1].overlay = "ge-0-0-5", "fab1"
	d.fabricSlots[1].peerIP = net.ParseIP(peer1)
	d.fabricSlots[1].peerMAC = mac
	d.fabricSlots[1].populated = true
	for slot := range d.fabricSlots {
		d.fabricSlots[slot].lastProbe = time.Now()
		d.fabricSlots[slot].probePending = true
	}
	d.fabricMu.Unlock()
	return ch0, ch1
}

func assertFabricSlotsZeroed17060(t *testing.T, d *Daemon) {
	t.Helper()
	chans := d.snapshotFabricRefreshChans()
	if chans[0] != nil || chans[1] != nil {
		t.Fatalf("refresh channels survived teardown: %v %v", chans[0], chans[1])
	}
	d.fabricMu.RLock()
	defer d.fabricMu.RUnlock()
	for slot := range d.fabricSlots {
		s := &d.fabricSlots[slot]
		if s.iface != "" || s.overlay != "" || s.peerIP != nil ||
			len(s.peerMAC) != 0 || s.populated {
			t.Fatalf("fabric slot %d survived teardown: iface=%q overlay=%q peer=%v mac=%v populated=%v (#17060)",
				slot, s.iface, s.overlay, s.peerIP, s.peerMAC, s.populated)
		}
		if !s.lastProbe.IsZero() || s.probePending || !s.lastLog.IsZero() {
			t.Fatalf("fabric slot %d probe/log state survived teardown (#17060)", slot)
		}
	}
}

// TestStopClusterCommsClearsFabricSlots17060 is the vq32 lifecycle probe
// as a hermetic cell: both slots seeded, the REAL stopClusterComms, then
// zeroed slots and dropped helper constraints. RED pre-fix (slots and
// constraints survive; channels were already nilled).
func TestStopClusterCommsClearsFabricSlots17060(t *testing.T) {
	d := &Daemon{}
	seedFabricSlots17060(t, d)
	d.fabricMu.Lock()
	d.fabricSlots[0].lastLog = time.Now()
	d.fabricSlots[1].lastLog = time.Now()
	d.fabricMu.Unlock()
	d.stopClusterComms()

	assertFabricSlotsZeroed17060(t, d)
	// The constraint map has no exported getter; a cleared constraint is
	// proven behaviourally by TestFabricConstraintClearedOnStop17060.

	// Restart through the real fabric-forwarding start helper. The populate
	// loops publish slot configuration before their initial probe; hold that
	// probe lookup so the assertion sees state freshly written by this epoch.
	// The hermetic link seam fails before netlink access or probe transmission,
	// so this cell asserts config repopulation, not the populated readiness latch.
	refreshEntered := make(chan string, 2)
	releaseRefresh := make(chan struct{})
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(releaseRefresh) }) }
	d.store = newConfigStore(t, t.TempDir()+"/config.conf")
	d.fabricLinkSubscribe = func(chan<- netlink.LinkUpdate, <-chan struct{}, func(error)) error {
		return nil
	}
	d.fabricNeighSubscribe = func(chan<- netlink.NeighUpdate, <-chan struct{}, func(error)) error {
		return nil
	}

	cc := &config.ClusterConfig{
		FabricInterface:    "ge-0-0-0",
		FabricPeerAddress:  "10.99.0.2",
		Fabric1Interface:   "ge-0-0-5",
		Fabric1PeerAddress: "10.99.1.2",
	}
	wantIface0 := d.resolveFabricParent(cc.FabricInterface)
	wantIface1 := d.resolveFabricParent(cc.Fabric1Interface)
	// The start helper passes an empty overlay when it equals the parent;
	// populateFabricFwd normalizes that to the parent before storing it.
	wantOverlay0 := config.LinuxIfName(cc.FabricInterface)
	wantOverlay1 := config.LinuxIfName(cc.Fabric1Interface)
	d.linkByNameFn = func(name string) (netlink.Link, error) {
		if name == wantIface0 || name == wantIface1 {
			refreshEntered <- name
			<-releaseRefresh
		}
		// Fail startup-probe lookups before transmission; hold the parent
		// refresh lookups above until after the state assertion.
		return nil, errors.New("hermetic restart link lookup")
	}
	ctx, gen, _ := d.beginClusterCommsEpoch(context.Background())
	ch0, ch1 := make(chan struct{}, 1), make(chan struct{}, 1)
	if !d.publishFabricRefreshChansIfCurrent(gen, [2]chan struct{}{ch0, ch1}) {
		t.Fatal("could not publish restarted fabric channels (#17060)")
	}
	d.startFabricForwardingLoops(ctx, gen, cc, [2]chan struct{}{ch0, ch1})
	t.Cleanup(func() {
		release()
		d.stopClusterComms()
	})

	entered := make(map[string]bool, 2)
	for range 2 {
		select {
		case name := <-refreshEntered:
			entered[name] = true
		case <-time.After(5 * time.Second):
			t.Fatal("restarted populate loops did not reach their refreshes (#17060)")
		}
	}
	d.fabricMu.RLock()
	restarted := d.fabricSlots[0].iface == wantIface0 &&
		d.fabricSlots[0].overlay == wantOverlay0 && d.fabricSlots[0].peerIP.Equal(net.ParseIP(cc.FabricPeerAddress)) &&
		d.fabricSlots[1].iface == wantIface1 && d.fabricSlots[1].overlay == wantOverlay1 &&
		d.fabricSlots[1].peerIP.Equal(net.ParseIP(cc.Fabric1PeerAddress))
	d.fabricMu.RUnlock()
	if !entered[wantIface0] || !entered[wantIface1] || !restarted {
		d.fabricMu.RLock()
		gotIface0, gotOverlay0, gotPeer0 := d.fabricSlots[0].iface, d.fabricSlots[0].overlay, d.fabricSlots[0].peerIP.String()
		gotIface1, gotOverlay1, gotPeer1 := d.fabricSlots[1].iface, d.fabricSlots[1].overlay, d.fabricSlots[1].peerIP.String()
		d.fabricMu.RUnlock()
		t.Fatalf("new epoch did not republish both fabric slot configs: entered=%v restarted=%v got=(%q,%q,%s)/(%q,%q,%s) want=(%q,%q,%s)/(%q,%q,%s) (#17060)",
			entered, restarted, gotIface0, gotOverlay0, gotPeer0, gotIface1, gotOverlay1, gotPeer1,
			wantIface0, wantOverlay0, cc.FabricPeerAddress, wantIface1, wantOverlay1, cc.Fabric1PeerAddress)
	}
	release()
	d.stopClusterComms()
	assertFabricSlotsZeroed17060(t, d)
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
	d.fabricMu.Lock()
	d.fabricSlots[0].peerIP = net.ParseIP("10.99.13.2")
	d.fabricMu.Unlock()
	d.rememberFabricPeerMAC(0, mustMAC(t, fabPeerTestPeerMAC))
	// Seed the slot state stop must clear.
	d.fabricMu.Lock()
	d.fabricSlots[0].iface, d.fabricSlots[0].overlay = "ge-0-0-0", "fab0"
	d.fabricSlots[0].populated = true
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
	d.fabricSlots[slot].populated = ok
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
	got := []bool{d.fabricSlots[0].populated, d.fabricSlots[1].populated}
	d.fabricMu.RUnlock()
	for slot := range 2 {
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
	d.fabricSlots[0].lastProbe = time.Time{}
	d.fabricSlots[1].lastProbe = time.Time{}
	d.fabricSlots[0].probePending = false
	d.fabricSlots[1].probePending = false
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
	p0, p1 := d.fabricSlots[0].probePending, d.fabricSlots[1].probePending
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

// blockingFabricRecorder17060 is a FabricPeerResolver whose ResolveFabricPeer
// blocks until released, so the test can hold a REAL populate loop inside
// refreshFabricPeer (past resolution, before the populated latch) while
// stopClusterComms runs concurrently. SyncFabricState records pushes so
// the test can prove no helper state was pushed for the cleared epoch.
type blockingFabricRecorder17060 struct {
	mu      sync.Mutex
	syncs   int
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

func newBlockingFabricRecorder17060() *blockingFabricRecorder17060 {
	return &blockingFabricRecorder17060{
		entered: make(chan struct{}),
		release: make(chan struct{}),
	}
}

func (r *blockingFabricRecorder17060) ResolveFabricPeer(_ int, _, _ int, _ string, localMAC net.HardwareAddr) dpuserspace.FabricPeerResolution {
	r.once.Do(func() { close(r.entered) })
	<-r.release
	mac, _ := net.ParseMAC(fabPeerTestPeerMAC)
	return dpuserspace.FabricPeerResolution{PeerMAC: mac, LocalMAC: localMAC}
}

func (r *blockingFabricRecorder17060) SyncFabricState(_ context.Context) error {
	r.mu.Lock()
	r.syncs++
	r.mu.Unlock()
	return nil
}

func (r *blockingFabricRecorder17060) SetRGActive(_ context.Context, _ int, _ bool) error {
	return nil
}

func (r *blockingFabricRecorder17060) SetHAWatchdog(_ context.Context, _ int, _ uint64) error {
	return nil
}

func (r *blockingFabricRecorder17060) syncCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.syncs
}

type blockingFabricDP17060 struct {
	dataplane.RuntimeDataPlane
	rec *blockingFabricRecorder17060
}

func (p *blockingFabricDP17060) HA() dataplane.HAController { return p.rec }

func (p *blockingFabricDP17060) ResolveFabricPeer(slot int, overlayIfindex, parentIfindex int, peer string, localMAC net.HardwareAddr) dpuserspace.FabricPeerResolution {
	return p.rec.ResolveFabricPeer(slot, overlayIfindex, parentIfindex, peer, localMAC)
}

// TestPopulateLoopCancelledBufferedWakeDoesNotProbe17060 covers the periodic
// wake arms, after the initial populate probe has succeeded. For each slot it
// holds the initial refresh in the resolver, then makes both ctx.Done() and a
// buffered refresh poke ready before releasing it. Since select may choose
// either arm, retries continue until the wake arm consumed a poke, proving
// that the cancelled-wake path was exercised. The matching synthetic
// neighbour keeps every allowed initial probe hermetic; overlay lookup counts
// prove the cancelled wake did not enter probeFabricNeighbor.
func TestPopulateLoopCancelledBufferedWakeDoesNotProbe17060(t *testing.T) {
	for _, tc := range []struct {
		name, fabIface, overlay, peer string
		parentIdx, overlayIdx         int
		run                           func(*Daemon, context.Context, chan struct{})
	}{
		{
			name: "fab0", fabIface: "ge-0-0-0", overlay: "fab0",
			peer: "10.99.20.2", parentIdx: 111, overlayIdx: 112,
			run: func(d *Daemon, ctx context.Context, ch chan struct{}) {
				epoch := &clusterCommsEpoch{}
				epoch.fabricPopulateWG.Add(1)
				d.populateFabricFwdSlot(ctx, epoch, 0, "ge-0-0-0", "fab0", "10.99.20.2", ch)
			},
		},
		{
			name: "fab1", fabIface: "ge-0-0-5", overlay: "fab1",
			peer: "10.99.21.2", parentIdx: 121, overlayIdx: 122,
			run: func(d *Daemon, ctx context.Context, ch chan struct{}) {
				epoch := &clusterCommsEpoch{}
				epoch.fabricPopulateWG.Add(1)
				d.populateFabricFwdSlot(ctx, epoch, 1, "ge-0-0-5", "fab1", "10.99.21.2", ch)
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sawWakeArm := false
			for attempt := 0; attempt < 32 && !sawWakeArm; attempt++ {
				parent := &testLink{attrs: netlink.LinkAttrs{
					Name: tc.fabIface, Index: tc.parentIdx, OperState: netlink.OperUp,
					TxQLen: 10000, HardwareAddr: mustMAC(t, fabPeerTestLocalMAC),
				}}
				overlay := &testLink{attrs: netlink.LinkAttrs{
					Name: tc.overlay, Index: tc.overlayIdx, ParentIndex: tc.parentIdx,
					OperState: netlink.OperUp, TxQLen: 10000,
					HardwareAddr: mustMAC(t, fabPeerTestLocalMAC),
				}}
				links := map[string]*testLink{tc.fabIface: parent, tc.overlay: overlay}
				var mu sync.Mutex
				overlayLookups := 0
				d := &Daemon{
					linkByNameFn: func(name string) (netlink.Link, error) {
						mu.Lock()
						defer mu.Unlock()
						if name == tc.overlay {
							overlayLookups++
						}
						if link, ok := links[name]; ok {
							return link, nil
						}
						return nil, errors.New("hermetic wake test: unknown link")
					},
					neighListFn: func(ifindex, family int) ([]netlink.Neigh, error) {
						if ifindex == tc.overlayIdx && family == netlink.FAMILY_V4 {
							return []netlink.Neigh{fabPeerNeigh(t, tc.peer, fabPeerTestPeerMAC)}, nil
						}
						return nil, nil
					},
				}
				rec := newBlockingFabricRecorder17060()
				d.setDataplane(&blockingFabricDP17060{rec: rec})
				ctx, cancel := context.WithCancel(context.Background())
				ch := make(chan struct{}, 1)
				done := make(chan struct{})
				go func() {
					defer close(done)
					tc.run(d, ctx, ch)
				}()
				select {
				case <-rec.entered:
				case <-time.After(5 * time.Second):
					cancel()
					close(rec.release)
					t.Fatal("populate loop did not reach its initial refresh resolver (#17060)")
				}
				mu.Lock()
				baselineLookups := overlayLookups
				mu.Unlock()

				d.fabricMu.Lock()
				slot := 0
				if tc.name == "fab1" {
					slot = 1
				}
				d.fabricSlots[slot].probePending = true
				d.fabricMu.Unlock()
				ch <- struct{}{}
				cancel()
				close(rec.release)
				select {
				case <-done:
				case <-time.After(5 * time.Second):
					t.Fatal("populate loop did not exit after cancelled wake (#17060)")
				}
				mu.Lock()
				gotLookups := overlayLookups
				mu.Unlock()
				if gotLookups != baselineLookups {
					t.Fatalf("cancelled buffered wake probed %s: overlay lookups=%d, want unchanged %d (#17060)",
						tc.name, gotLookups, baselineLookups)
				}
				select {
				case <-ch:
					// Cancellation won select; retry so the wake arm itself is covered.
				default:
					sawWakeArm = true
				}
				d.clearFabricSlots()
			}
			if !sawWakeArm {
				t.Fatal("select never consumed the buffered poke while cancellation was ready (#17060)")
			}
		})
	}
}

// TestPopulateLoopJoinedBeforeSlotClear17060 runs REAL populate loops
// (fab0 + fab1, both sharing peer 10.99.0.2) concurrently with the REAL
// stopClusterComms. The fab0 loop is held inside refreshFabricPeer by a
// blocking resolver at the moment stop cancels the epoch; stop must JOIN
// both loops (fabricPopulateWG) before clearFabricSlots, so afterwards
// both slots stay cleared and the shared peer's helper constraint stays
// dropped. Sharing one peer address across both slots also pins the
// clearFabricSlots dedupe branch and the fab1 constraint drop.
//
// RED pre-fold: the loops were launched bare and never joined, so the
// blocked refresh latched fabricPopulated (and rememberFabricPeerMAC
// re-armed the constraint) after the clear.
func TestPopulateLoopJoinedBeforeSlotClear17060(t *testing.T) {
	const sharedPeer = "10.99.0.2"
	dpuserspace.RegisterFabricPeerMACConstraint(sharedPeer, nil)
	t.Cleanup(func() { dpuserspace.RegisterFabricPeerMACConstraint(sharedPeer, nil) })

	rec := newBlockingFabricRecorder17060()
	parent0 := &testLink{attrs: netlink.LinkAttrs{
		Name: "ge-0-0-0", Index: 11, OperState: netlink.OperUp, TxQLen: 10000,
		HardwareAddr: mustMAC(t, fabPeerTestLocalMAC),
	}}
	overlay0 := &testLink{attrs: netlink.LinkAttrs{
		Name: "fab0", Index: 12, ParentIndex: 11, OperState: netlink.OperUp, TxQLen: 10000,
		HardwareAddr: mustMAC(t, fabPeerTestLocalMAC),
	}}
	parent1 := &testLink{attrs: netlink.LinkAttrs{
		Name: "ge-0-0-5", Index: 21, OperState: netlink.OperUp, TxQLen: 10000,
		HardwareAddr: mustMAC(t, fabPeerTestLocalMAC),
	}}
	overlay1 := &testLink{attrs: netlink.LinkAttrs{
		Name: "fab1", Index: 22, ParentIndex: 21, OperState: netlink.OperUp, TxQLen: 10000,
		HardwareAddr: mustMAC(t, fabPeerTestLocalMAC),
	}}
	// Address-matched neighbour so rememberFabricPeerMAC arms the
	// constraint before the blocked resolver parks the loop.
	peerNeigh := fabPeerNeigh(t, sharedPeer, fabPeerTestPeerMAC)
	neighFn := func(ifindex, family int) ([]netlink.Neigh, error) {
		if family == netlink.FAMILY_V4 && (ifindex == 12 || ifindex == 11 || ifindex == 22 || ifindex == 21) {
			return []netlink.Neigh{peerNeigh}, nil
		}
		return nil, nil
	}
	d := &Daemon{
		linkByNameFn: mockLinkByName(map[string]*testLink{
			"ge-0-0-0": parent0, "fab0": overlay0,
			"ge-0-0-5": parent1, "fab1": overlay1,
		}),
		neighListFn: neighFn,
	}
	d.setDataplane(&blockingFabricDP17060{rec: rec})

	// Wire the comms-epoch plumbing stopClusterComms drives: a live
	// epoch context + cancel, and published refresh channels. The
	// epoch owns both populate loops, which are registered under
	// clusterCommsMu before their goroutines start.
	ctx, gen, _ := d.beginClusterCommsEpoch(context.Background())
	ch0 := make(chan struct{}, 1)
	ch1 := make(chan struct{}, 1)
	if !d.publishFabricRefreshChansIfCurrent(gen, [2]chan struct{}{ch0, ch1}) {
		t.Fatal("could not publish epoch refresh channels")
	}
	d.clusterCommsMu.Lock()
	epoch := d.clusterCommsEpoch
	epoch.fabricPopulateWG.Add(2)
	d.clusterCommsMu.Unlock()

	go d.populateFabricFwdSlot(ctx, epoch, 0, "ge-0-0-0", "fab0", sharedPeer, ch0)
	go d.populateFabricFwdSlot(ctx, epoch, 1, "ge-0-0-5", "fab1", sharedPeer, ch1)

	// Wait until a loop is parked inside the blocking resolver: it has
	// already stored its config and (via the address-matched neighbour)
	// armed the shared constraint, and its next step is the latch.
	select {
	case <-rec.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("populate loop never reached the resolver (#17060)")
	}

	// Stop concurrently; release the parked refresh only after stop has
	// had the chance to cancel (its join must wait for the loop).
	stopDone := make(chan struct{})
	go func() {
		d.stopClusterComms()
		close(stopDone)
	}()
	// Give stop a moment to cancel + reach the join, then let the
	// in-flight refresh finish (latch attempt + ctx-guarded sync).
	time.Sleep(50 * time.Millisecond)
	close(rec.release)

	select {
	case <-stopDone:
	case <-time.After(5 * time.Second):
		t.Fatal("stopClusterComms did not return — populate join deadlocked (#17060)")
	}

	// Both slots must stay cleared even though a live loop raced stop.
	assertFabricSlotsZeroed17060(t, d)
	if got := rec.syncCount(); got != 0 {
		t.Fatalf("SyncFabricState pushed %d time(s) for a cleared epoch (#17060)", got)
	}
	// Shared-peer constraint must stay dropped: with two link-local
	// candidates and no constraint, resolution must fail closed. A
	// resurrected non-nil constraint would let the sole-matching
	// candidate resolve. Probe via the live resolver directly.
	probeNeigh := func(_, family int) ([]netlink.Neigh, error) {
		if family == netlink.FAMILY_V6 {
			return []netlink.Neigh{
				fabPeerNeigh(t, "fe80::dec0", fabPeerTestDecoyMAC),
				fabPeerNeigh(t, "fe80::b", fabPeerTestPeerMAC),
			}, nil
		}
		return nil, nil
	}
	res := dpuserspace.ResolveFabricPeerWithNeighbours(12, 11, sharedPeer,
		mustMAC(t, fabPeerTestLocalMAC), probeNeigh)
	if res.PeerMAC != nil {
		t.Fatalf("shared-peer constraint resurrected after stop: resolved %v (#17060)", res.PeerMAC)
	}
}

// TestPopulateLoopCancelDuringFastRetryDoesNotProbe17060: cancellation
// landing while the fast-retry timer is pending must not emit another
// probe. The resolver never succeeds, so the loop sits in its 500ms
// retry sleep; cancelling there and waiting past the timer proves the
// post-select recheck returns before probeFabricNeighbor (overlay
// lookups stay at the first attempt's count).
func TestPopulateLoopCancelDuringFastRetryDoesNotProbe17060(t *testing.T) {
	parent := &testLink{attrs: netlink.LinkAttrs{
		Name: "ge-0-0-0", Index: 111, OperState: netlink.OperUp,
		TxQLen: 10000, HardwareAddr: mustMAC(t, fabPeerTestLocalMAC),
	}}
	overlay := &testLink{attrs: netlink.LinkAttrs{
		Name: "fab0", Index: 112, ParentIndex: 111,
		OperState: netlink.OperUp, TxQLen: 10000,
		HardwareAddr: mustMAC(t, fabPeerTestLocalMAC),
	}}
	links := map[string]*testLink{"ge-0-0-0": parent, "fab0": overlay}
	var mu sync.Mutex
	overlayLookups := 0
	d := &Daemon{
		linkByNameFn: func(name string) (netlink.Link, error) {
			mu.Lock()
			defer mu.Unlock()
			if name == "fab0" {
				overlayLookups++
			}
			if link, ok := links[name]; ok {
				return link, nil
			}
			return nil, errors.New("hermetic retry test: unknown link")
		},
		neighListFn: func(ifindex, family int) ([]netlink.Neigh, error) {
			return nil, nil // never resolved: loop keeps retrying
		},
	}
	rec := newBlockingFabricRecorder17060()
	close(rec.release) // resolver never blocks; refresh simply fails
	d.setDataplane(&blockingFabricDP17060{rec: rec})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	epoch := &clusterCommsEpoch{}
	epoch.fabricPopulateWG.Add(1)
	go func() {
		defer close(done)
		d.populateFabricFwdSlot(ctx, epoch, 0, "ge-0-0-0", "fab0", "10.99.20.2", make(chan struct{}, 1))
	}()
	// Wait for the first probe attempt, then cancel during the retry sleep.
	deadline := time.Now().Add(5 * time.Second)
	for {
		mu.Lock()
		n := overlayLookups
		mu.Unlock()
		if n > 0 {
			break
		}
		if time.Now().After(deadline) {
			cancel()
			t.Fatal("populate loop never probed")
		}
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("populate loop did not exit after cancel during fast retry (#17060)")
	}
	mu.Lock()
	got := overlayLookups
	mu.Unlock()
	if got != 2 {
		t.Fatalf("cancel during fast retry probed again: overlay lookups=%d, want 2 (probe + refresh of attempt 0 only) (#17060)", got)
	}
	d.clearFabricSlots()
}
// TestStopClusterCommsDoesNotJoinSuccessorFabricEpoch17060 constructs the
// cross-epoch interleaving directly: an old stop is blocked joining its loop,
// then a replacement epoch registers a live populate loop. The old stop must
// neither wait on nor clear the successor's channels.
func TestStopClusterCommsDoesNotJoinSuccessorFabricEpoch17060(t *testing.T) {
	d := &Daemon{
		fabricSlots: [2]fabricSlot{{name: "fabric"}, {name: "fabric1"}},
	}
	var blockOnce sync.Once
	loopEntered := make(chan struct{})
	loopRelease := make(chan struct{})
	d.linkByNameFn = func(string) (netlink.Link, error) {
		blockOnce.Do(func() {
			close(loopEntered)
			<-loopRelease
		})
		return nil, errors.New("hermetic epoch test")
	}

	oldCtx, _, _ := d.beginClusterCommsEpoch(context.Background())
	oldRelease := make(chan struct{})
	d.clusterCommsMu.Lock()
	oldEpoch := d.clusterCommsEpoch
	oldEpoch.fabricPopulateWG.Add(1)
	d.clusterCommsMu.Unlock()
	go func() {
		defer oldEpoch.fabricPopulateWG.Done()
		<-oldRelease
	}()
	oldStopDone := make(chan struct{})
	go func() {
		d.stopClusterComms()
		close(oldStopDone)
	}()
	select {
	case <-oldCtx.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("old stop did not cancel its epoch")
	}

	newCtx, newGen, newCancel := d.beginClusterCommsEpoch(context.Background())
	newChannels := [2]chan struct{}{make(chan struct{}, 1), make(chan struct{}, 1)}
	if !d.publishFabricRefreshChansIfCurrent(newGen, newChannels) {
		newCancel()
		close(oldRelease)
		t.Fatal("could not publish successor refresh channels")
	}
	newEpoch := d.registerFabricPopulateLoops(newGen, 1)
	if newEpoch == nil {
		newCancel()
		close(oldRelease)
		t.Fatal("could not register successor populate loop")
	}
	newLoopDone := make(chan struct{})
	go func() {
		defer close(newLoopDone)
		d.populateFabricFwdSlot(newCtx, newEpoch, 0, "ge-0-0-5", "", "10.99.31.2", newChannels[0])
	}()
	select {
	case <-loopEntered:
	case <-time.After(5 * time.Second):
		newCancel()
		close(loopRelease)
		close(oldRelease)
		<-oldStopDone
		t.Fatal("successor populate loop did not enter its hermetic link lookup")
	}

	d.fabricMu.RLock()
	published := d.fabricSlots[0].iface == "ge-0-0-5" &&
		d.fabricSlots[0].peerIP.Equal(net.ParseIP("10.99.31.2"))
	d.fabricMu.RUnlock()
	if !published {
		newCancel()
		close(loopRelease)
		close(oldRelease)
		<-oldStopDone
		t.Fatal("successor populate loop did not publish slot state")
	}

	// The old loop is still blocked, but its stop must finish as soon as that
	// loop exits even while the new epoch's populate loop is live.
	close(oldRelease)
	select {
	case <-oldStopDone:
	case <-time.After(5 * time.Second):
		newCancel()
		close(loopRelease)
		<-oldStopDone
		<-newLoopDone
		d.stopClusterComms()
		t.Fatal("old stop waited for a successor epoch's populate loop")
	}
	if got := d.snapshotFabricRefreshChans(); got != newChannels {
		newCancel()
		close(loopRelease)
		<-newLoopDone
		d.stopClusterComms()
		t.Fatalf("old stop cleared successor refresh channels: got=%v want=%v", got, newChannels)
	}
	d.fabricMu.RLock()
	survived := d.fabricSlots[0].iface == "ge-0-0-5" &&
		d.fabricSlots[0].peerIP.Equal(net.ParseIP("10.99.31.2"))
	d.fabricMu.RUnlock()
	if !survived {
		newCancel()
		close(loopRelease)
		<-newLoopDone
		d.stopClusterComms()
		t.Fatal("old stop cleared successor fabric slot state")
	}

	newCancel()
	close(loopRelease)
	<-newLoopDone
	d.stopClusterComms()
}

// TestRefreshFabricFwdWakesRealPopulateLoopProbesOnce17060 exercises the
// actual epoch populate loop end to end. The initial pass reaches its
// periodic/event-driven select, RefreshFabricFwd queues and wakes it, and the
// queued probe is consumed once before the event-driven refresh completes.
// Synthetic matching neighbors make both probes hermetic (no raw socket
// transmission or host netlink access).
func TestRefreshFabricFwdWakesRealPopulateLoopProbesOnce17060(t *testing.T) {
	const (
		parentName = "ge-0-0-0"
		overlay    = "fab0"
		peer       = "10.99.32.2"
	)
	parent := &testLink{attrs: netlink.LinkAttrs{
		Name: parentName, Index: 131, OperState: netlink.OperUp, TxQLen: 10000,
		HardwareAddr: mustMAC(t, fabPeerTestLocalMAC),
	}}
	overlayLink := &testLink{attrs: netlink.LinkAttrs{
		Name: overlay, Index: 132, ParentIndex: 131, OperState: netlink.OperUp,
		TxQLen: 10000, HardwareAddr: mustMAC(t, fabPeerTestLocalMAC),
	}}
	neigh := fabPeerNeigh(t, peer, fabPeerTestPeerMAC)
	var mu sync.Mutex
	neighScans := 0
	d := &Daemon{
		fabricSlots: [2]fabricSlot{{name: "fabric"}, {name: "fabric1"}},
		linkByNameFn: func(name string) (netlink.Link, error) {
			switch name {
			case parentName:
				return parent, nil
			case overlay:
				return overlayLink, nil
			default:
				return nil, errors.New("hermetic populate-loop test: unknown interface")
			}
		},
		neighListFn: func(ifindex, family int) ([]netlink.Neigh, error) {
			mu.Lock()
			neighScans++
			mu.Unlock()
			if family == netlink.FAMILY_V4 && (ifindex == 131 || ifindex == 132) {
				return []netlink.Neigh{neigh}, nil
			}
			return nil, nil
		},
	}
	rec := newBlockingFabricRecorder17060()
	close(rec.release)
	d.setDataplane(&blockingFabricDP17060{rec: rec})

	ctx, gen, cancel := d.beginClusterCommsEpoch(context.Background())
	defer cancel()
	refresh := make(chan struct{}, 1)
	if !d.publishFabricRefreshChansIfCurrent(gen, [2]chan struct{}{refresh, nil}) {
		t.Fatal("could not publish fabric refresh channel")
	}
	epoch := d.registerFabricPopulateLoops(gen, 1)
	if epoch == nil {
		t.Fatal("could not register real populate loop")
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		d.populateFabricFwdSlot(ctx, epoch, 0, parentName, overlay, peer, refresh)
	}()
	t.Cleanup(func() {
		d.stopClusterComms()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("real populate loop did not stop")
		}
	})

	waitForSync := func(want int) {
		t.Helper()
		deadline := time.Now().Add(5 * time.Second)
		for rec.syncCount() < want {
			if time.Now().After(deadline) {
				t.Fatalf("populate loop SyncFabricState count=%d, want %d", rec.syncCount(), want)
			}
			time.Sleep(time.Millisecond)
		}
	}
	waitForSync(1)
	mu.Lock()
	initialScans := neighScans
	mu.Unlock()
	if initialScans != 2 {
		t.Fatalf("initial probe + refresh neighbor scans=%d, want 2", initialScans)
	}

	d.RefreshFabricFwd()
	waitForSync(2)
	mu.Lock()
	totalScans := neighScans
	mu.Unlock()
	if totalScans != 4 {
		t.Fatalf("initial + event probe/refresh neighbor scans=%d, want 4 (one probe consumed once)",
			totalScans)
	}
	d.fabricMu.RLock()
	pending := d.fabricSlots[0].probePending
	d.fabricMu.RUnlock()
	if pending {
		t.Fatal("real populate loop did not consume the queued probe")
	}
}

// TestCancelledOldFabricLoopCannotClearSuccessorPeer17060 proves an old
// cancelled populate loop cannot mutate slot identity published by a newer
// generation, including the userspace peer-MAC constraint.
func TestCancelledOldFabricLoopCannotClearSuccessorPeer17060(t *testing.T) {
	const (
		oldPeer = "10.99.31.2"
		newPeer = "10.99.32.2"
	)
	d := &Daemon{fabricSlots: [2]fabricSlot{{name: "fabric"}, {name: "fabric1"}}}
	_, newGen, _ := d.beginClusterCommsEpoch(context.Background())
	oldCtx, cancelOld := context.WithCancel(context.Background())
	cancelOld()
	oldEpoch := &clusterCommsEpoch{generation: newGen - 1}
	oldEpoch.fabricPopulateWG.Add(1)

	wantMAC := mustMAC(t, fabPeerTestPeerMAC)
	d.fabricMu.Lock()
	d.fabricSlots[0].iface = "ge-0-0-5"
	d.fabricSlots[0].overlay = "fab0"
	d.fabricSlots[0].peerIP = net.ParseIP(newPeer)
	d.fabricSlots[0].peerMAC = wantMAC
	dpuserspace.RegisterFabricPeerMACConstraint(newPeer, wantMAC)
	d.fabricMu.Unlock()
	t.Cleanup(func() {
		d.stopClusterComms()
		dpuserspace.RegisterFabricPeerMACConstraint(oldPeer, nil)
		dpuserspace.RegisterFabricPeerMACConstraint(newPeer, nil)
	})

	d.populateFabricFwdSlot(oldCtx, oldEpoch, 0,
		"ge-0-0-0", "fab0", oldPeer, nil)

	d.fabricMu.RLock()
	slot := d.fabricSlots[0]
	d.fabricMu.RUnlock()
	if slot.iface != "ge-0-0-5" || slot.overlay != "fab0" ||
		!slot.peerIP.Equal(net.ParseIP(newPeer)) ||
		slot.peerMAC == nil || slot.peerMAC.String() != wantMAC.String() {
		t.Fatalf("cancelled old epoch changed successor slot identity: iface=%q overlay=%q peer=%v mac=%v",
			slot.iface, slot.overlay, slot.peerIP, slot.peerMAC)
	}

	// A sole decoy link-local neighbour is usable only if the successor's
	// address-matched identity constraint survived the stale loop.
	decoy := fabPeerNeigh(t, "fe80::dec0", fabPeerTestDecoyMAC)
	resolution := dpuserspace.ResolveFabricPeerWithNeighbours(132, 131, newPeer,
		mustMAC(t, fabPeerTestLocalMAC),
		func(_ int, family int) ([]netlink.Neigh, error) {
			if family == netlink.FAMILY_V6 {
				return []netlink.Neigh{decoy}, nil
			}
			return nil, nil
		})
	if resolution.PeerMAC != nil {
		t.Fatalf("successor constraint was cleared: sole decoy resolved as %s", resolution.PeerMAC)
	}
}
