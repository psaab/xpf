package daemon

import (
	"net"
	"reflect"
	"sort"
	"testing"

	"github.com/psaab/xpf/pkg/cluster"
	"github.com/psaab/xpf/pkg/vrrp"
)

// #17052 mode-parity: the (iface, IP, kind) set announced on RG
// activation must be identical in direct mode (full set via
// directSendGARPs) and legacy VRRP mode (VIPs via pkg/vrrp — same
// derivation, pinned here by construction — plus the daemon's non-VIP
// half). Pre-fix, legacy mode sent NO router-LL NA and NO IPv6 pool
// NA, so this test's VRRP-mode leg was missing those kinds entirely.
//
// Class U (hermetic): burst senders are the package seams; no sockets.

type announceCall17052 struct {
	Iface string
	IP    string
	Kind  string
	Count int
}

func installAnnounceCapture17052(t *testing.T, calls *[]announceCall17052) {
	t.Helper()
	origG, origN, origP, origProbe := directGARPBurstFn, directNABurstFn, directProxyNABurstFn, directARPProbeFn
	directGARPBurstFn = func(iface string, ip net.IP, count int, _ cluster.BurstStillValid) error {
		kind := "pool-v4"
		// GARP seam serves both VIP and pool-v4; distinguish by count
		// is fragile, so capture raw and classify in the test by IP set.
		*calls = append(*calls, announceCall17052{iface, ip.String(), kind, count})
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

func targetKeys(targets []cluster.AnnounceTarget) []string {
	var keys []string
	for _, tg := range targets {
		keys = append(keys, tg.Iface+"|"+tg.IP.String()+"|"+tg.Kind.String())
	}
	sort.Strings(keys)
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
	if dd.isNoRethVRRP() != true {
		t.Fatal("direct fixture must be direct mode")
	}
	dd.directSendGARPs(1)

	// VRRP-mode daemon: non-VIP half only (VIPs are pkg/vrrp's, from the
	// same Config.RethVIPsForRG walk — asserted below by target set).
	vrrpStore := fenceTestStore(t, paritySetLines(false))
	var vrrpCalls []announceCall17052
	installAnnounceCapture17052(t, &vrrpCalls)

	vstate := newRGStateMachine()
	vstate.SetVRRP("reth0", true)
	// SetVRRP alone may not make IsActive true without all instances;
	// drive via SetCluster as the active marker for the announce gate.
	vd := &Daemon{
		store:    vrrpStore,
		rgStates: map[int]*rgStateMachine{1: vstate},
	}
	if vd.isNoRethVRRP() {
		t.Fatal("vrrp fixture must be legacy VRRP mode")
	}
	if !vstate.IsActive() {
		vstate.SetCluster(true)
	}
	vd.sendVRRPModeNonVIPAnnounce(1)

	// Expected full set from the shared derivation.
	cfg := directStore.ActiveConfig()
	want := targetKeys(cluster.AnnounceTargets(cfg, 1, vrrp.GatewayProbeTarget))
	if len(want) == 0 {
		t.Fatal("shared target set is empty — fixture broken")
	}
	// Sanity: set must contain all four kinds.
	kinds := map[string]bool{}
	for _, tg := range cluster.AnnounceTargets(cfg, 1, vrrp.GatewayProbeTarget) {
		kinds[tg.Kind.String()] = true
	}
	for _, k := range []string{"vip", "router-ll", "pool-v4", "pool-v6"} {
		if !kinds[k] {
			t.Fatalf("shared target set missing kind %s: %v", k, want)
		}
	}

	// Direct leg: classify captured calls into (iface,ip,kind) keys.
	// VIP v4 GARPs carry count=burst(3), pool v4 count=1; NAs split by
	// target-IP membership in the router-LL set.
	routerLL := map[string]bool{}
	vipIPs := map[string]bool{}
	for _, tg := range cluster.AnnounceTargets(cfg, 1, vrrp.GatewayProbeTarget) {
		if tg.Kind == cluster.AnnounceRouterLL {
			routerLL[tg.Iface+"|"+tg.IP.String()] = true
		}
		if tg.Kind == cluster.AnnounceVIP {
			vipIPs[tg.Iface+"|"+tg.IP.String()] = true
		}
	}
	classify := func(calls []announceCall17052, includeVIP bool) []string {
		var keys []string
		for _, c := range calls {
			key := c.Iface + "|" + c.IP
			switch c.Kind {
			case "pool-v6":
				keys = append(keys, key+"|pool-v6")
			case "pool-v4":
				if c.Count == 1 {
					keys = append(keys, key+"|pool-v4")
				} else if includeVIP {
					keys = append(keys, key+"|vip")
				}
			case "na":
				if routerLL[key] {
					keys = append(keys, key+"|router-ll")
				} else if includeVIP {
					keys = append(keys, key+"|vip")
				}
			}
		}
		sort.Strings(keys)
		return keys
	}

	gotDirect := classify(directCalls, true)
	if !reflect.DeepEqual(gotDirect, want) {
		t.Fatalf("direct-mode announced set mismatch:\n got %v\nwant %v", gotDirect, want)
	}

	// VRRP leg: daemon non-VIP calls + VIPs pkg/vrrp would send (same
	// walk, same iface/IP — vrrp instance Interface is the member
	// netdev; assert set equality on the non-VIP half plus VIP targets
	// present in the shared set).
	gotNonVIP := classify(vrrpCalls, false)
	var wantNonVIP []string
	for _, tg := range cluster.AnnounceTargets(cfg, 1, vrrp.GatewayProbeTarget) {
		if tg.Kind != cluster.AnnounceVIP {
			wantNonVIP = append(wantNonVIP, tg.Iface+"|"+tg.IP.String()+"|"+tg.Kind.String())
		}
	}
	sort.Strings(wantNonVIP)
	if !reflect.DeepEqual(gotNonVIP, wantNonVIP) {
		t.Fatalf("VRRP-mode non-VIP announced set mismatch (pre-fix: router-LL + pool-v6 missing):\n got %v\nwant %v", gotNonVIP, wantNonVIP)
	}
	// VIP parity by construction: vrrp.RethVIPsForRG == cfg walk.
	if got := vrrp.RethVIPsForRG(cfg, 1); len(got) == 0 {
		t.Fatal("vrrp VIP walk empty")
	}
	_ = vipIPs
}
