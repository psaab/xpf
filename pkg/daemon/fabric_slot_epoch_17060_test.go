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
	if !d.lastFabricLog0.IsZero() || !d.lastFabricLog1.IsZero() {
		t.Fatal("fabric refresh failure log rate limits survived teardown (#17060)")
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
	d.fabricMu.Lock()
	d.lastFabricLog0 = time.Now()
	d.lastFabricLog1 = time.Now()
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
	d.fabricLinkSubscribe = func(chan<- netlink.LinkUpdate, <-chan struct{}) error {
		return nil
	}
	d.fabricNeighSubscribe = func(chan<- netlink.NeighUpdate, <-chan struct{}) error {
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
	if !d.publishFabricRefreshChansIfCurrent(gen, ch0, ch1) {
		t.Fatal("could not publish restarted fabric channels (#17060)")
	}
	d.startFabricForwardingLoops(ctx, cc, ch0, ch1)
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
	restarted := d.fabricIface == wantIface0 &&
		d.fabricOverlay == wantOverlay0 && d.fabricPeerIP.Equal(net.ParseIP(cc.FabricPeerAddress)) &&
		d.fabricIface1 == wantIface1 && d.fabricOverlay1 == wantOverlay1 &&
		d.fabricPeerIP1.Equal(net.ParseIP(cc.Fabric1PeerAddress))
	d.fabricMu.RUnlock()
	if !entered[wantIface0] || !entered[wantIface1] || !restarted {
		d.fabricMu.RLock()
		gotIface0, gotOverlay0, gotPeer0 := d.fabricIface, d.fabricOverlay, d.fabricPeerIP.String()
		gotIface1, gotOverlay1, gotPeer1 := d.fabricIface1, d.fabricOverlay1, d.fabricPeerIP1.String()
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
	// loops are registered on fabricPopulateWG exactly as
	// startFabricForwardingLoops registers them (Add on this stack).
	ctx, cancel := context.WithCancel(context.Background())
	d.clusterCommsMu.Lock()
	d.clusterCommsCtx = ctx
	d.clusterCommsCancel = cancel
	ch0 := make(chan struct{}, 1)
	ch1 := make(chan struct{}, 1)
	d.fabricRefreshCh = ch0
	d.fabricRefreshCh1 = ch1
	d.clusterCommsMu.Unlock()

	d.fabricPopulateWG.Add(1)
	go d.populateFabricFwd(ctx, "ge-0-0-0", "fab0", sharedPeer, ch0)
	d.fabricPopulateWG.Add(1)
	go d.populateFabricFwd1(ctx, "ge-0-0-5", "fab1", sharedPeer, ch1)

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
