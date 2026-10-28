package daemon

import (
	"context"
	"net"
	"reflect"
	"sort"
	"testing"

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
		store:               store,
		cluster:             cm,
		rgStates:            make(map[int]*rgStateMachine),
		proxyARPNudgeCh:     make(chan struct{}, 1),
		applySem:            semaphore.NewWeighted(1),
		nonVIPAnnounced:     make(map[int]uint64),
		rethServicesApplied: make(map[int]bool),
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
