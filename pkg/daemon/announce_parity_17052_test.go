package daemon

import (
	"context"
	"errors"
	"net"
	"reflect"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/vishvananda/netlink"
	"golang.org/x/sync/semaphore"

	"github.com/psaab/xpf/pkg/cluster"
	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/configstore"
	"github.com/psaab/xpf/pkg/vrrp"
)

// #17052 mode-parity: the (iface, IP, kind) sequence announced on RG
// activation must be identical in direct mode (full set via
// directSendGARPs) and legacy VRRP mode (VIPs via pkg/vrrp's real
// sendGARPReservedMode leg, plus the daemon's non-VIP half). Pre-fix,
// legacy mode sent NO router-LL NA and NO IPv6 pool NA, so this test's
// VRRP-mode leg was missing those kinds entirely.
//
// Order is asserted per target (no sorting): SendAnnounceTargets emits
// the shared target order in both modes, and a regression that permutes
// the per-target sequence must fail here, not be sorted away.
//
// Class U (hermetic): burst senders are the package seams; no sockets.

type announceCall17052 struct {
	Iface string
	IP    string
	Kind  string
	Count int
}

// installAnnounceCapture17052 swaps the daemon announce seams for
// ordered recorders. The GARP seam serves both VIP and pool-v4, so
// calls are recorded raw ("garp") and classified by the caller against
// the shared target set and burst count.
func installAnnounceCapture17052(t *testing.T, calls *[]announceCall17052) {
	t.Helper()
	origG, origN, origP, origProbe := directGARPBurstFn, directNABurstFn, directProxyNABurstFn, directARPProbeFn
	directGARPBurstFn = func(iface string, ip net.IP, count int, _ cluster.BurstStillValid) error {
		*calls = append(*calls, announceCall17052{iface, ip.String(), "garp", count})
		return nil
	}
	directNABurstFn = func(iface string, ip net.IP, count int, _ cluster.BurstStillValid) error {
		*calls = append(*calls, announceCall17052{iface, ip.String(), "na", count})
		return nil
	}
	directProxyNABurstFn = func(iface string, ip net.IP, count int, _ cluster.BurstStillValid) error {
		*calls = append(*calls, announceCall17052{iface, ip.String(), "pool-v6", count})
		return nil
	}
	directARPProbeFn = func(string, net.IP, net.IP) error { return nil }
	t.Cleanup(func() {
		directGARPBurstFn, directNABurstFn, directProxyNABurstFn, directARPProbeFn = origG, origN, origP, origProbe
	})
}

// announceCapture17052 is a mutex-guarded ordered recorder for the
// producer-race cell, where concurrent converger calls may send from
// several goroutines. Appends are serialised; reads snapshot under the
// same mutex.
type announceCapture17052 struct {
	mu    sync.Mutex
	calls []announceCall17052
}

func (c *announceCapture17052) len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.calls)
}

// installAnnounceCaptureSync17052 is installAnnounceCapture17052 with
// appends serialised through cap, for concurrent producers.
func installAnnounceCaptureSync17052(t *testing.T, cap *announceCapture17052) {
	t.Helper()
	origG, origN, origP, origProbe := directGARPBurstFn, directNABurstFn, directProxyNABurstFn, directARPProbeFn
	record := func(kind string) func(string, net.IP, int, cluster.BurstStillValid) error {
		return func(iface string, ip net.IP, count int, _ cluster.BurstStillValid) error {
			cap.mu.Lock()
			cap.calls = append(cap.calls, announceCall17052{iface, ip.String(), kind, count})
			cap.mu.Unlock()
			return nil
		}
	}
	directGARPBurstFn = record("garp")
	directNABurstFn = record("na")
	directProxyNABurstFn = record("pool-v6")
	directARPProbeFn = func(string, net.IP, net.IP) error { return nil }
	t.Cleanup(func() {
		directGARPBurstFn, directNABurstFn, directProxyNABurstFn, directARPProbeFn = origG, origN, origP, origProbe
	})
}

func paritySetLines(direct bool) string {
	mode := "set chassis cluster no-private-rg-election\n"
	if direct {
		mode = ""
	}
	return "" +
		"set chassis cluster cluster-id 1\n" +
		"set chassis cluster authentication-key test-cluster-psk-6611\n" +
		"set chassis cluster control-interface em0\n" +
		"set chassis cluster peer-address 10.99.0.2\n" +
		"set interfaces em0 unit 0 family inet address 10.99.0.1/24\n" +
		mode +
		"set chassis cluster redundancy-group 1 node 0 priority 200\n" +
		"set chassis cluster redundancy-group 1 node 1 priority 100\n" +
		"set interfaces reth0 redundant-ether-options redundancy-group 1\n" +
		"set interfaces ge-0/0/0 gigether-options redundant-parent reth0\n" +
		"set interfaces ge-7/0/0 gigether-options redundant-parent reth0\n" +
		"set interfaces reth0 unit 0 family inet address 10.0.0.1/24\n" +
		"set interfaces reth0 unit 0 family inet6 address 2001:db8::1/64\n" +
		"set security nat proxy-arp interface reth0 address 10.0.0.50\n" +
		"set security nat proxy-arp interface reth0 address 2001:db8::50\n"
}

// classify17052 maps raw captured calls onto (iface, IP, kind) keys IN
// CAPTURE ORDER. set classifies the expected side; calls classifies the
// observed side. VIP v4 GARPs carry the burst count, pool v4 a single
// frame; NAs split router-LL vs VIP-v6 by the shared target set.
func classify17052(calls []announceCall17052, targets []cluster.AnnounceTarget) []string {
	burst := 0
	routerLL := map[string]bool{}
	vip := map[string]bool{}
	for _, tg := range targets {
		if tg.Burst > burst {
			burst = tg.Burst
		}
		if tg.Kind == cluster.AnnounceRouterLL {
			routerLL[tg.Iface+"|"+tg.IP.String()] = true
		}
		if tg.Kind == cluster.AnnounceVIP {
			vip[tg.Iface+"|"+tg.IP.String()] = true
		}
	}
	var keys []string
	for _, c := range calls {
		key := c.Iface + "|" + c.IP
		switch c.Kind {
		case "pool-v6":
			keys = append(keys, key+"|pool-v6")
		case "garp":
			switch {
			case c.Count == 1:
				keys = append(keys, key+"|pool-v4")
			case c.Count == burst && vip[key]:
				keys = append(keys, key+"|vip")
			default:
				keys = append(keys, key+"|garp?count="+itoa17052(c.Count))
			}
		case "na":
			switch {
			case routerLL[key]:
				keys = append(keys, key+"|router-ll")
			case vip[key]:
				keys = append(keys, key+"|vip")
			default:
				keys = append(keys, key+"|na?")
			}
		}
	}
	return keys
}

func itoa17052(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	if neg {
		b = append([]byte{'-'}, b...)
	}
	return string(b)
}

// wantKeys17052 is the expected ordered sequence, straight from the
// shared derivation (never sorted).
func wantKeys17052(targets []cluster.AnnounceTarget) []string {
	var keys []string
	for _, tg := range targets {
		keys = append(keys, tg.Iface+"|"+tg.IP.String()+"|"+tg.Kind.String())
	}
	return keys
}

func TestAnnounceModeParity17052(t *testing.T) {
	// Direct-mode daemon.
	directStore := fenceTestStore(t, paritySetLines(true))
	var directCalls []announceCall17052
	installAnnounceCapture17052(t, &directCalls)
	state := newRGStateMachine()
	state.SetCluster(true)
	dd := &Daemon{
		store:             directStore,
		rgStates:          map[int]*rgStateMachine{1: state},
		directVIPOwned:    map[int]bool{1: true},
		directAnnounceSeq: map[int]uint64{1: 1},
	}
	if !dd.isNoRethVRRP() {
		t.Fatal("direct fixture must be direct mode")
	}
	dd.directSendGARPs(1)

	cfg := directStore.ActiveConfig()
	targets := cluster.AnnounceTargets(cfg, 1, vrrp.GatewayProbeTarget)
	if len(targets) == 0 {
		t.Fatal("shared target set is empty -- fixture broken")
	}
	kinds := map[string]bool{}
	for _, tg := range targets {
		kinds[tg.Kind.String()] = true
	}
	for _, k := range []string{"vip", "router-ll", "pool-v4", "pool-v6"} {
		if !kinds[k] {
			t.Fatalf("shared target set missing kind %s", k)
		}
	}
	want := wantKeys17052(targets)

	gotDirect := classify17052(directCalls, targets)
	if !reflect.DeepEqual(gotDirect, want) {
		t.Fatalf("direct-mode announced sequence mismatch:\n got %v\nwant %v", gotDirect, want)
	}

	// Legacy VRRP mode, cluster-first ordering (the B1 hazard): the
	// cluster promotion consumes the rg-state edge, so the announce
	// must fire on the cluster arm; the later VRRP MASTER handler call
	// (Changed=false) must not re-burst. The VIP half is asserted by
	// driving pkg/vrrp's real leg below; the daemon legs here are the
	// non-VIP half in shared-target order.
	vrrpStore := fenceTestStore(t, paritySetLines(false))
	vd := clusterFirstDaemon17052(t, vrrpStore)
	if vd.isNoRethVRRP() {
		t.Fatal("vrrp fixture must be legacy VRRP mode")
	}
	var vrrpCalls []announceCall17052
	installAnnounceCapture17052(t, &vrrpCalls)

	vd.handleClusterEvent(context.Background(), cluster.ClusterEvent{
		GroupID: 1, OldState: cluster.StateSecondary, NewState: cluster.StatePrimary,
	}, nil)
	s := vd.getOrCreateRGState(1)
	if !s.IsActive() {
		t.Fatal("setup: cluster-first promotion must activate RG1")
	}
	var wantNonVIP []string
	for _, tg := range targets {
		if tg.Kind != cluster.AnnounceVIP {
			wantNonVIP = append(wantNonVIP, tg.Iface+"|"+tg.IP.String()+"|"+tg.Kind.String())
		}
	}
	if got := classify17052(vrrpCalls, targets); !reflect.DeepEqual(got, wantNonVIP) {
		t.Fatalf("cluster-first legacy announce mismatch (B1: router-LL + pool must fire on the cluster edge):\n got %v\nwant %v", got, wantNonVIP)
	}

	// The VRRP MASTER event arrives second: SetVRRP reports
	// Changed=false, so no second non-VIP burst may fire.
	before := len(vrrpCalls)
	vd.handleVRRPEvent(context.Background(), vrrp.VRRPEvent{
		GroupID: 101, Interface: "reth0", State: vrrp.StateMaster,
	}, rgTransition{})
	if len(vrrpCalls) != before {
		t.Fatalf("VRRP-second event re-announced the non-VIP half: %v", vrrpCalls[before:])
	}

	// VIP parity through the REAL VRRP leg: CollectRethInstances ->
	// sendGARPReservedMode with captured pkg/vrrp seams, asserted in
	// the same per-target order as the shared walk.
	gotVIP := driveVRRPLeg17052(t, vrrpStore.ActiveConfig())
	var wantVIP []string
	for _, tg := range targets {
		if tg.Kind == cluster.AnnounceVIP {
			wantVIP = append(wantVIP, tg.Iface+"|"+tg.IP.String()+"|vip")
		}
	}
	if !reflect.DeepEqual(gotVIP, wantVIP) {
		t.Fatalf("VRRP-mode VIP sequence mismatch:\n got %v\nwant %v", gotVIP, wantVIP)
	}

	// Combined legacy sequence = VRRP VIP leg + daemon non-VIP leg must
	// equal the direct-mode full sequence AS A SET (the two producers
	// interleave in real time, so only set equality is meaningful across
	// producers -- per-producer order is pinned above).
	combined := append(append([]string{}, gotVIP...), classify17052(vrrpCalls, targets)...)
	sort.Strings(combined)
	sortedWant := append([]string{}, want...)
	sort.Strings(sortedWant)
	if !reflect.DeepEqual(combined, sortedWant) {
		t.Fatalf("legacy-mode combined announced set mismatch:\n got %v\nwant %v", combined, sortedWant)
	}
}

// nonVIPAnnouncedGen17052 reads the raw claimed generation for rgID
// under the marker mutex. A returned zero does not distinguish an absent
// claim from a stored generation zero.
func nonVIPAnnouncedGen17052(d *Daemon, rgID int) uint64 {
	d.nonVIPAnnounceMu.Lock()
	defer d.nonVIPAnnounceMu.Unlock()
	return d.nonVIPAnnounced[rgID]
}

// TestNonVIPAnnounceLifecycle17052 pins the marker lifecycle the
// converger is sold on (Rev18310b B1/B2): keyed to the REAL activation
// generation (inactive->active flips only), claimed atomically, cleared
// explicitly on deactivation, exactly one re-send per reactivation.
//
//	activate (cluster-first) -> claim gen N -> reconcile ticks (NO
//	re-send, however many epoch bumps they cause) -> VRRP MASTER second
//	(NO re-send) -> BACKUP (still active via cluster) -> cluster
//	demotion deactivates (marker cleared explicitly) -> reactivate via
//	VRRP MASTER (exactly one re-send, gen N+1).
//
// RED on the pre-fold code: the marker was keyed to CurrentDesired's
// epoch, which reconcileLocked bumps on EVERY input, so the first
// reconcile-style Reconcile below re-owed and re-sent the full burst.
func TestNonVIPAnnounceLifecycle17052(t *testing.T) {
	vrrpStore := fenceTestStore(t, paritySetLines(false))
	vd := clusterFirstDaemon17052(t, vrrpStore)
	if vd.isNoRethVRRP() {
		t.Fatal("vrrp fixture must be legacy VRRP mode")
	}
	var calls []announceCall17052
	installAnnounceCapture17052(t, &calls)
	s := vd.getOrCreateRGState(1)

	burstLen := func() int { return len(calls) }

	// 1. Activate cluster-first: exactly one burst, generation 1 claimed.
	vd.handleClusterEvent(context.Background(), cluster.ClusterEvent{
		GroupID: 1, OldState: cluster.StateSecondary, NewState: cluster.StatePrimary,
	}, nil)
	if !s.IsActive() {
		t.Fatal("setup: cluster-first promotion must activate RG1")
	}
	active, gen1 := s.CurrentActivation()
	if !active || gen1 != 1 {
		t.Fatalf("setup: first activation must be generation 1, got active=%v gen=%d", active, gen1)
	}
	first := burstLen()
	if first == 0 {
		t.Fatal("cluster-first activation sent no non-VIP burst")
	}
	if got := nonVIPAnnouncedGen17052(vd, 1); got != gen1 {
		t.Fatalf("marker must claim the observed generation %d, got %d", gen1, got)
	}
	if vd.legacyNonVIPAnnouncePending(1) {
		t.Fatal("announce must not be pending right after its claim")
	}

	// 2. Reconcile ticks: Reconcile bumps the volatile epoch on every
	// pass (the B1 mechanism) but must NOT move the activation
	// generation, re-owe, or re-send.
	epochBefore := s.Epoch()
	for range 3 {
		s.Reconcile(true, map[string]bool{"reth0": true})
		vd.convergeLegacyNonVIPAnnounce(1)
	}
	if s.Epoch() == epochBefore {
		t.Fatal("setup: reconcile passes must bump the volatile epoch (B1 premise)")
	}
	if _, gen := s.CurrentActivation(); gen != gen1 {
		t.Fatalf("reconcile ticks moved the activation generation: %d -> %d", gen1, gen)
	}
	if burstLen() != first {
		t.Fatalf("reconcile ticks re-sent the non-VIP burst: %d calls, want %d (B1: epoch-keyed claim re-fires every tick)", burstLen(), first)
	}
	if vd.legacyNonVIPAnnouncePending(1) {
		t.Fatal("announce re-owed at the same activation generation after reconcile ticks")
	}

	// 3. VRRP MASTER arrives second (Changed=false): no re-send.
	vd.handleVRRPEvent(context.Background(), vrrp.VRRPEvent{
		GroupID: 101, Interface: "reth0", State: vrrp.StateMaster,
	}, rgTransition{})
	if burstLen() != first {
		t.Fatalf("VRRP-second event re-sent the non-VIP burst: %d calls, want %d", burstLen(), first)
	}

	// 4. Deactivate via VRRP BACKUP while cluster is still primary:
	// desired stays active (clusterPri || master) — the BACKUP arm must
	// NOT clear yet, and no burst fires. Then pre-apply the cluster's
	// inactive desired value before delivering the demotion event. This
	// keeps the lifecycle cell hermetic (the event's blackhole-route
	// syscall only runs on a Changed transition), while still asserting
	// the demotion arm clears a claim after desired has gone inactive.
	vd.handleVRRPEvent(context.Background(), vrrp.VRRPEvent{
		GroupID: 101, Interface: "reth0", State: vrrp.StateBackup,
	}, rgTransition{})
	if !s.IsActive() {
		t.Fatal("setup: BACKUP while cluster-primary must keep desired active")
	}
	if got := nonVIPAnnouncedGen17052(vd, 1); got != gen1 {
		t.Fatalf("marker cleared while still active: got %d, want claim %d", got, gen1)
	}
	vd.cluster.SetGroupStateForTesting(1, cluster.StateSecondary)
	s.SetCluster(false)
	if s.IsActive() {
		t.Fatal("setup: cluster demotion must pre-apply desired inactive")
	}
	if got := nonVIPAnnouncedGen17052(vd, 1); got != gen1 {
		t.Fatalf("state-machine deactivation alone cleared the claim: got %d, want %d", got, gen1)
	}
	if timer := vd.handleClusterEvent(context.Background(), cluster.ClusterEvent{
		GroupID: 1, OldState: cluster.StatePrimary, NewState: cluster.StateSecondary,
	}, nil); timer != nil {
		timer.Stop()
	}
	if s.IsActive() {
		t.Fatal("setup: cluster demotion after BACKUP must leave RG1 inactive")
	}
	if got := nonVIPAnnouncedGen17052(vd, 1); got != 0 {
		t.Fatalf("cluster demotion arm must clear the marker explicitly, got claim %d", got)
	}
	if burstLen() != first {
		t.Fatalf("deactivation sent a burst: %d calls, want %d", burstLen(), first)
	}
	// A pending check on the inactive RG is a pure read: it must not
	// (re)create or mutate any claim.
	if vd.legacyNonVIPAnnouncePending(1) {
		t.Fatal("inactive RG must not owe the announce")
	}
	if got := nonVIPAnnouncedGen17052(vd, 1); got != 0 {
		t.Fatalf("pending check mutated the marker on an inactive RG: claim %d", got)
	}

	// 5. Reactivate via VRRP MASTER (VRRP-first this time): exactly one
	// re-send at generation 2, and a following cluster event must not
	// re-send.
	vd.handleVRRPEvent(context.Background(), vrrp.VRRPEvent{
		GroupID: 101, Interface: "reth0", State: vrrp.StateMaster,
	}, rgTransition{})
	if !s.IsActive() {
		t.Fatal("setup: VRRP MASTER must reactivate RG1")
	}
	_, gen2 := s.CurrentActivation()
	if gen2 != gen1+1 {
		t.Fatalf("reactivation must be generation %d, got %d", gen1+1, gen2)
	}
	if burstLen() != 2*first {
		t.Fatalf("reactivation must re-send exactly one burst: %d calls, want %d", burstLen(), 2*first)
	}
	if got := nonVIPAnnouncedGen17052(vd, 1); got != gen2 {
		t.Fatalf("marker must claim reactivation generation %d, got %d", gen2, got)
	}
	vd.cluster.SetGroupStateForTesting(1, cluster.StatePrimary)
	if timer := vd.handleClusterEvent(context.Background(), cluster.ClusterEvent{
		GroupID: 1, OldState: cluster.StateSecondary, NewState: cluster.StatePrimary,
	}, nil); timer != nil {
		timer.Stop()
	}
	if burstLen() != 2*first {
		t.Fatalf("cluster-second event re-sent after reactivation: %d calls, want %d", burstLen(), 2*first)
	}
}

// TestNonVIPAnnounceClusterDemotionWhileVRRPMaster17052 pins the round-3
// demotion case: VRRP MASTER activates and claims a generation; a cluster
// demotion while VRRP remains MASTER must preserve that claim, and the next
// converger pass must not resend. BACKUP really deactivates it, allowing one
// send after the following MASTER reactivation.
func TestNonVIPAnnounceClusterDemotionWhileVRRPMaster17052(t *testing.T) {
	store := fenceTestStore(t, paritySetLines(false))
	vd := clusterFirstDaemon17052(t, store)
	var calls []announceCall17052
	installAnnounceCapture17052(t, &calls)
	s := vd.getOrCreateRGState(1)

	vd.handleVRRPEvent(context.Background(), vrrp.VRRPEvent{
		GroupID: 101, Interface: "reth0", State: vrrp.StateMaster,
	}, rgTransition{})
	active, gen1 := s.CurrentActivation()
	if !active || gen1 != 1 {
		t.Fatalf("VRRP MASTER must activate generation 1, got active=%v gen=%d", active, gen1)
	}
	first := len(calls)
	if first == 0 {
		t.Fatal("VRRP MASTER activation sent no non-VIP burst")
	}
	if got := nonVIPAnnouncedGen17052(vd, 1); got != gen1 {
		t.Fatalf("VRRP MASTER must claim generation %d, got %d", gen1, got)
	}

	// Model the cluster-primary state already established alongside VRRP
	// MASTER before delivering its demotion edge. Desired remains active
	// through VRRP ownership when clusterPri becomes false.
	s.SetCluster(true)
	vd.cluster.SetGroupStateForTesting(1, cluster.StateSecondary)
	if timer := vd.handleClusterEvent(context.Background(), cluster.ClusterEvent{
		GroupID: 1, OldState: cluster.StatePrimary, NewState: cluster.StateSecondary,
	}, nil); timer != nil {
		timer.Stop()
	}
	active, genAfterDemotion := s.CurrentActivation()
	if !active || genAfterDemotion != gen1 {
		t.Fatalf("cluster demotion must preserve active generation %d, got active=%v gen=%d", gen1, active, genAfterDemotion)
	}
	if got := nonVIPAnnouncedGen17052(vd, 1); got != gen1 {
		t.Fatalf("active cluster demotion cleared generation %d claim, got %d", gen1, got)
	}
	vd.convergeLegacyNonVIPAnnounce(1)
	if len(calls) != first {
		t.Fatalf("active cluster demotion caused a re-send: %d calls, want %d", len(calls), first)
	}

	// The BACKUP deactivation arm also installs blackhole routes on the
	// kernel-dataplane path. Publish the in-memory userspace-mode test
	// runtime so this lifecycle cell remains hermetic.
	vd.userspaceDemotionPrepUntil = make(map[int]time.Time)
	vd.setDataplane(newReconcileSnapshotDP("announce-17052-backup"))
	t.Cleanup(func() { vd.setDataplane(nil) })
	vd.handleVRRPEvent(context.Background(), vrrp.VRRPEvent{
		GroupID: 101, Interface: "reth0", State: vrrp.StateBackup,
	}, rgTransition{})
	vd.setDataplane(nil)
	if s.IsActive() {
		t.Fatal("BACKUP after cluster demotion must deactivate the RG")
	}
	if got := nonVIPAnnouncedGen17052(vd, 1); got != 0 {
		t.Fatalf("real deactivation must clear the claim, got %d", got)
	}

	vd.handleVRRPEvent(context.Background(), vrrp.VRRPEvent{
		GroupID: 101, Interface: "reth0", State: vrrp.StateMaster,
	}, rgTransition{})
	active, gen2 := s.CurrentActivation()
	if !active || gen2 != gen1+1 {
		t.Fatalf("reactivation must be generation %d, got active=%v gen=%d", gen1+1, active, gen2)
	}
	if len(calls) != 2*first {
		t.Fatalf("reactivation must send exactly one new burst: %d calls, want %d", len(calls), 2*first)
	}
	if got := nonVIPAnnouncedGen17052(vd, 1); got != gen2 {
		t.Fatalf("reactivation must claim generation %d, got %d", gen2, got)
	}
	// A deactivation cleanup delayed past reactivation may clear only its
	// observed generation, never the newer generation's claim.
	beforeLateClear := len(calls)
	vd.clearLegacyNonVIPAnnounce(1, gen1)
	if got := nonVIPAnnouncedGen17052(vd, 1); got != gen2 {
		t.Fatalf("late generation %d cleanup erased newer generation %d claim: got %d", gen1, gen2, got)
	}
	vd.convergeLegacyNonVIPAnnounce(1)
	if len(calls) != beforeLateClear {
		t.Fatalf("late generation cleanup caused a duplicate burst: calls=%d want=%d", len(calls), beforeLateClear)
	}
}

// TestNonVIPAnnounceRetriesAfterTotalFailure17052 pins retry-on-next-pass
// semantics. A generation with no successfully announced non-VIP target is
// unclaimed so reconciliation can retry; a successful retry claims it and
// later passes do not duplicate it.
func TestNonVIPAnnounceRetriesAfterTotalFailure17052(t *testing.T) {
	store := fenceTestStore(t, paritySetLines(false))
	vd := clusterFirstDaemon17052(t, store)
	origG, origN, origP, origProbe := directGARPBurstFn, directNABurstFn, directProxyNABurstFn, directARPProbeFn
	fail := true
	partial := false
	partialAttempt := 0
	var failedCalls, successfulCalls int
	send := func(string, net.IP, int, cluster.BurstStillValid) error {
		if fail {
			failedCalls++
			return errors.New("synthetic announce failure")
		}
		if partial {
			partialAttempt++
			if partialAttempt > 1 {
				failedCalls++
				return errors.New("synthetic partial announce failure")
			}
		}
		successfulCalls++
		return nil
	}
	directGARPBurstFn = send
	directNABurstFn = send
	directProxyNABurstFn = send
	directARPProbeFn = func(string, net.IP, net.IP) error { return nil }
	t.Cleanup(func() {
		directGARPBurstFn, directNABurstFn, directProxyNABurstFn, directARPProbeFn = origG, origN, origP, origProbe
	})

	s := vd.getOrCreateRGState(1)
	s.SetCluster(true)
	active, gen := s.CurrentActivation()
	if !active || gen == 0 {
		t.Fatalf("setup: expected active generation, got active=%v gen=%d", active, gen)
	}
	vd.convergeLegacyNonVIPAnnounce(1)
	if failedCalls == 0 || successfulCalls != 0 {
		t.Fatalf("setup: expected all sends to fail, failed=%d succeeded=%d", failedCalls, successfulCalls)
	}
	if got := nonVIPAnnouncedGen17052(vd, 1); got != 0 {
		t.Fatalf("all-failed generation must be unclaimed for retry, got claim %d", got)
	}
	if !vd.legacyNonVIPAnnouncePending(1) {
		t.Fatal("all-failed generation must remain pending")
	}

	fail = false
	vd.convergeLegacyNonVIPAnnounce(1)
	if successfulCalls == 0 {
		t.Fatal("next producer/reconcile pass did not retry the failed announce")
	}
	if got := nonVIPAnnouncedGen17052(vd, 1); got != gen {
		t.Fatalf("successful retry must claim generation %d, got %d", gen, got)
	}
	before := successfulCalls
	vd.convergeLegacyNonVIPAnnounce(1)
	if successfulCalls != before {
		t.Fatalf("successful generation was re-sent: %d successful sends, want %d", successfulCalls, before)
	}
	// A partial delivery stays claimed: retrying the full list would
	// duplicate the target that succeeded on the first attempt.
	s.SetCluster(false)
	s.SetCluster(true)
	_, gen2 := s.CurrentActivation()
	partial = true
	beforeSuccess, beforeFailure := successfulCalls, failedCalls
	vd.convergeLegacyNonVIPAnnounce(1)
	if successfulCalls != beforeSuccess+1 || failedCalls <= beforeFailure {
		t.Fatalf("setup: expected one success followed by failures, succeeded=%d failed=%d",
			successfulCalls-beforeSuccess, failedCalls-beforeFailure)
	}
	if got := nonVIPAnnouncedGen17052(vd, 1); got != gen2 {
		t.Fatalf("partial delivery must keep generation %d claimed, got %d", gen2, got)
	}
	beforeSuccess, beforeFailure = successfulCalls, failedCalls
	vd.convergeLegacyNonVIPAnnounce(1)
	if successfulCalls != beforeSuccess || failedCalls != beforeFailure {
		t.Fatalf("partial delivery retried and duplicated a target: successes=%d failures=%d",
			successfulCalls-beforeSuccess, failedCalls-beforeFailure)
	}
}

// TestNonVIPAnnounceProducerRace17052 interleaves repeated calls to
// convergeLegacyNonVIPAnnounce and legacyNonVIPAnnouncePending with
// same-generation Reconcile calls for one activation. Exactly one burst
// may be claimed/sent regardless of how those calls interleave. Run under -race
// (the campaign's named run includes it where configured); even without
// it, the claim-before-send mutex makes a double burst impossible and
// this cell asserts that outcome across many interleavings.
func TestNonVIPAnnounceProducerRace17052(t *testing.T) {
	vrrpStore := fenceTestStore(t, paritySetLines(false))
	vd := clusterFirstDaemon17052(t, vrrpStore)
	cap := &announceCapture17052{}
	installAnnounceCaptureSync17052(t, cap)
	s := vd.getOrCreateRGState(1)

	// Activate directly on the state machine (no producer has run yet),
	// then race every producer at the same generation.
	s.SetCluster(true)
	active, gen := s.CurrentActivation()
	if !active || gen != 1 {
		t.Fatalf("setup: want active generation 1, got active=%v gen=%d", active, gen)
	}
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(3)
		go func() { defer wg.Done(); vd.convergeLegacyNonVIPAnnounce(1) }()
		go func() { defer wg.Done(); _ = vd.legacyNonVIPAnnouncePending(1) }()
		go func() { defer wg.Done(); s.Reconcile(true, map[string]bool{"reth0": true}) }()
	}
	wg.Wait()
	// Exactly one burst total: count is the burst length of the first
	// (and only) send — a second send would at least double the frames
	// for the shared non-VIP targets.
	if cap.len() == 0 {
		t.Fatal("racing producers sent no burst for the activation")
	}
	oneBurst := cap.len()
	// Re-run all producers at the same generation: still no second burst.
	for range 4 {
		vd.convergeLegacyNonVIPAnnounce(1)
	}
	if cap.len() != oneBurst {
		t.Fatalf("producer race/replay sent a second burst: %d calls, want %d", cap.len(), oneBurst)
	}
	if got := nonVIPAnnouncedGen17052(vd, 1); got != gen {
		t.Fatalf("marker must claim generation %d after the race, got %d", gen, got)
	}
}

// TestNonVIPAnnounceMonotonicClaims17052 models an older producer that
// observed generation 2 but reaches the claim mutex after generation 3
// has already been claimed. The stale claim must neither regress the
// marker nor let a subsequent current-generation pass re-send.
func TestNonVIPAnnounceMonotonicClaims17052(t *testing.T) {
	store := fenceTestStore(t, paritySetLines(false))
	vd := clusterFirstDaemon17052(t, store)
	var calls []announceCall17052
	installAnnounceCapture17052(t, &calls)
	s := vd.getOrCreateRGState(1)
	s.SetCluster(true)
	s.SetCluster(false)
	s.SetCluster(true)
	_, gen2 := s.CurrentActivation()
	s.SetCluster(false)
	s.SetCluster(true)
	active, gen3 := s.CurrentActivation()
	if !active || gen3 != gen2+1 {
		t.Fatalf("setup: expected active generation %d, got active=%v gen=%d", gen2+1, active, gen3)
	}

	// An absent map entry is different from an existing claim whose
	// stored generation is zero.
	if !vd.claimLegacyNonVIPAnnounce(1, 0) {
		t.Fatal("an absent generation-zero claim must be claimable")
	}
	if vd.claimLegacyNonVIPAnnounce(1, 0) {
		t.Fatal("an existing generation-zero claim must not be claimable again")
	}
	if !vd.claimLegacyNonVIPAnnounce(1, gen3) {
		t.Fatalf("newer generation %d must supersede generation zero", gen3)
	}
	if res := vd.sendVRRPModeNonVIPAnnounce(1, gen3); res.Sent == 0 || len(calls) == 0 {
		t.Fatalf("generation %d setup send emitted no target calls: result=%+v calls=%v", gen3, res, calls)
	}
	first := len(calls)

	if vd.claimLegacyNonVIPAnnounce(1, gen2) {
		t.Fatalf("stale generation %d claim replaced newer generation %d", gen2, gen3)
	}
	if got := nonVIPAnnouncedGen17052(vd, 1); got != gen3 {
		t.Fatalf("stale claim regressed marker: got %d, want %d", got, gen3)
	}
	vd.convergeLegacyNonVIPAnnounce(1)
	if len(calls) != first {
		t.Fatalf("stale claim caused an extra target send: calls=%d, want %d", len(calls), first)
	}
}

// TestNonVIPAnnounceDelayedGenerationSend17052 claims generation 1,
// completes a deactivate/reactivate cycle, lets generation 2 send, and
// then starts the old generation-1 sender. It must be rejected before
// any target call even though the RG is active again.
func TestNonVIPAnnounceDelayedGenerationSend17052(t *testing.T) {
	store := fenceTestStore(t, paritySetLines(false))
	vd := clusterFirstDaemon17052(t, store)
	var calls []announceCall17052
	installAnnounceCapture17052(t, &calls)
	s := vd.getOrCreateRGState(1)
	s.SetCluster(true)
	active, gen1 := s.CurrentActivation()
	if !active || gen1 == 0 {
		t.Fatalf("setup: expected active generation, got active=%v gen=%d", active, gen1)
	}
	if !vd.claimLegacyNonVIPAnnounce(1, gen1) {
		t.Fatalf("setup: failed to claim generation %d", gen1)
	}

	s.SetCluster(false)
	vd.clearLegacyNonVIPAnnounce(1, gen1)
	s.SetCluster(true)
	active, gen2 := s.CurrentActivation()
	if !active || gen2 != gen1+1 {
		t.Fatalf("setup: expected reactivation generation %d, got active=%v gen=%d", gen1+1, active, gen2)
	}
	vd.convergeLegacyNonVIPAnnounce(1)
	if len(calls) == 0 || nonVIPAnnouncedGen17052(vd, 1) != gen2 {
		t.Fatalf("setup: generation %d did not send and claim: calls=%v claim=%d", gen2, calls, nonVIPAnnouncedGen17052(vd, 1))
	}
	generation2Calls := len(calls)

	if res := vd.sendVRRPModeNonVIPAnnounce(1, gen1); res.Sent != 0 || res.FirstErr != nil {
		t.Fatalf("delayed generation %d send should be rejected without an error, got %+v", gen1, res)
	}
	if len(calls) != generation2Calls {
		t.Fatalf("delayed generation %d emitted duplicate target calls: calls=%d, want %d", gen1, len(calls), generation2Calls)
	}
	if got := nonVIPAnnouncedGen17052(vd, 1); got != gen2 {
		t.Fatalf("delayed generation %d send changed newer claim: got %d, want %d", gen1, got, gen2)
	}
}

// clusterFirstDaemon17052 builds a legacy-mode daemon whose cluster
// manager agrees RG1 is primary, so handleClusterEvent drives the real
// cluster-first path (SetCluster consumes the activation edge).
func clusterFirstDaemon17052(t *testing.T, store *configstore.Store) *Daemon {
	t.Helper()
	cm := cluster.NewManager(0, 1)
	cm.UpdateConfig(&config.ClusterConfig{
		RedundancyGroups: []*config.RedundancyGroup{
			{ID: 0, NodePriorities: map[int]int{0: 200}},
			{ID: 1, NodePriorities: map[int]int{0: 200}},
		},
	})
	cm.SetGroupStateForTesting(1, cluster.StatePrimary)
	d := &Daemon{
		store:           store,
		cluster:         cm,
		rgStates:        make(map[int]*rgStateMachine),
		proxyARPNudgeCh: make(chan struct{}, 1),
		applySem:        semaphore.NewWeighted(1),
		nonVIPAnnounced: make(map[int]uint64),
		rethServices:    make(map[int]rethServicesEdgeStatus),
		blackholeRoutes: make(map[int][]netlink.Route),
	}
	// applyRethServicesForRG / addStableRethLinkLocal run on these
	// handlers; keep their netlink side effects out of the hermetic cell.
	origAdd, origRem := addStableLLToInterfaceFn, removeStableLLFromInterfaceFn
	addStableLLToInterfaceFn = func(string, net.IP) {}
	removeStableLLFromInterfaceFn = func(string, net.IP) {}
	t.Cleanup(func() { addStableLLToInterfaceFn, removeStableLLFromInterfaceFn = origAdd, origRem })
	return d
}

// driveVRRPLeg17052 runs the REAL pkg/vrrp VIP leg (CollectRethInstances
// -> sendGARPReservedMode at MASTER) with the vrrp burst seams captured
// via the exported test seams, returning the ordered (iface, IP, vip)
// keys the seams actually observed.
func driveVRRPLeg17052(t *testing.T, cfg *config.Config) []string {
	t.Helper()
	var keys []string
	restore := vrrp.SetGARPSeamsForTesting(
		func(iface string, ip net.IP, _ int, _ cluster.BurstStillValid) error {
			keys = append(keys, iface+"|"+ip.String()+"|vip")
			return nil
		},
		func(iface string, ip net.IP, _ int, _ cluster.BurstStillValid) error {
			keys = append(keys, iface+"|"+ip.String()+"|vip")
			return nil
		},
		func(string, net.IP, net.IP) error { return nil },
	)
	defer restore()
	vrrp.SendGARPReservedModeForTesting(cfg, 1)
	if len(keys) == 0 {
		t.Fatal("real VRRP leg emitted no bursts -- VIP parity would be vacuous")
	}
	return keys
}
