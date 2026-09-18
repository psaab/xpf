package daemon

import (
	"context"
	"encoding/binary"
	"net"
	"sync"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
	"golang.org/x/sys/unix"
)

// #8621: the daemon half of the proxy-ARP responder — which addresses it
// claims, whose ownership gates it, and whether the responder set actually
// follows the config.
//
// The kernel cannot answer for a pool address inside its own egress
// interface's connected subnet (see pkg/cluster/arp_responder_8621.go), so
// these decisions are the whole of what makes a configured `proxy-arp` stanza
// do anything.

func proxyARPCfg(iface string, addrs ...string) *config.Config {
	return &config.Config{
		Security: config.SecurityConfig{
			NAT: config.NATConfig{
				ProxyARP: []*config.ProxyARPEntry{{Interface: iface, Addresses: addrs}},
			},
		},
	}
}

// v4 addresses are collected; v6 ones are deliberately NOT, because the kernel
// answers v6 proxy NDP correctly for the same topology and a second responder
// would duplicate it. The v4 row is the positive control: without it, a
// collector that returns nothing at all would pass the v6 assertion.
func TestOnlyIPv4PoolAddressesAreClaimed8621(t *testing.T) {
	cfg := proxyARPCfg("reth0.80",
		"172.16.80.7/32",
		"2001:559:8585:80::7/128",
		"172.16.80.9",
		"not-an-address",
	)
	got := proxyARPPoolAddressesByInterface(cfg)
	set := got["reth0.80"]
	if _, ok := set["172.16.80.7"]; !ok {
		t.Fatalf("the v4 pool address was not claimed; got %v. Every other assertion "+
			"in this cell is satisfied by a collector that returns nothing", set)
	}
	if _, ok := set["172.16.80.9"]; !ok {
		t.Errorf("a bare (non-CIDR) v4 address was not claimed; got %v", set)
	}
	if len(set) != 2 {
		t.Errorf("claimed %d addresses, want exactly the 2 v4 ones: %v.\n\n"+
			"An IPv6 address here would mean a second responder for a family the "+
			"kernel already answers correctly — ndisc_recv_ns gates on a bare "+
			"pneigh_lookup with no route lookup, so it has none of the v4 defect. "+
			"A malformed address must be dropped rather than defaulted.", len(set), set)
	}
}

// The policy: this node answers for an address it proxies, on a group it owns.
func TestTheResponderAnswersOnlyForAddressesItProxies8621(t *testing.T) {
	d := &Daemon{arpResponders: newProxyARPResponders()}
	r := &proxyARPResponder{
		junosRef: "reth0.80",
		addrs:    map[string]struct{}{"172.16.80.7": {}},
	}
	policy := d.answerPolicyFor(r)

	// An address NOT in the snapshot must be refused regardless of everything
	// else. This is the assertion that separates this design from
	// proxy_arp_pvlan, which answers for every address on the segment.
	if policy("reth0.80", net.IP{172, 16, 80, 99}) {
		t.Error("answered for an address this node does not proxy")
	}
	// A v6 target must be refused by the policy too, not merely absent from the
	// snapshot — the responder is v4-only by construction.
	if policy("reth0.80", net.ParseIP("2001:559:8585:80::7")) {
		t.Error("answered for an IPv6 target")
	}
}

// THE LOAD-BEARING GATE. Ownership is read per REQUEST, not cached at start,
// because it changes on failover between reconciles. The RETH virtual MAC is
// PER NODE, so a standby that answers replies with its OWN MAC and draws pool
// traffic to itself — which is exactly the misdelivery #8405 measured (seven
// SYN-ACKs carrying the standby's MAC on a non-promiscuous NIC).
//
// RED ON REVERT: cache the suppression verdict in the responder instead of
// reading it here, or drop the `!d.proxyARPEntrySuppressed` term, and the
// suppressed half of this fails.
func TestOwnershipIsConsultedPerRequestAndSuppressesTheStandby8621(t *testing.T) {
	// The rgID a reconcile would have resolved for this interface. Derived
	// through the production predicate rather than written as a literal, so a
	// change to how the group is resolved reds here too.
	cfg := proxyARPCfg("reth0.80", "172.16.80.7/32")
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"reth0": {Name: "reth0", RedundancyGroup: 2},
	}
	rgID := proxyARPRedundancyGroupFor(cfg, "reth0.80")
	if rgID != 2 {
		t.Fatalf("fixture: the interface resolved to redundancy group %d, want 2. "+
			"With 0 the suppression gate short-circuits to 'answer' and every "+
			"assertion below passes for the wrong reason", rgID)
	}

	d := &Daemon{arpResponders: newProxyARPResponders()}
	r := &proxyARPResponder{
		junosRef: "reth0.80",
		rgID:     rgID,
		addrs:    map[string]struct{}{"172.16.80.7": {}},
	}
	policy := d.answerPolicyFor(r)
	target := net.IP{172, 16, 80, 7}

	// OWNER (all instances master) -> answer.
	st := d.getOrCreateRGState(2)
	st.mu.Lock()
	st.vrrpInstances = map[string]bool{"reth0.80": true}
	st.mu.Unlock()
	if !policy("reth0.80", target) {
		t.Fatal("the OWNING node refused to answer for its own pool address — this " +
			"is the case the whole responder exists for")
	}

	// NOT OWNER -> refuse, with NOTHING else changed. Same daemon, same
	// responder, same policy closure: only the live ownership moved.
	st.mu.Lock()
	st.vrrpInstances = map[string]bool{"reth0.80": false}
	st.mu.Unlock()
	if policy("reth0.80", target) {
		t.Fatal("a node that does NOT own the redundancy group answered. It would " +
			"reply with its own per-node RETH virtual MAC and draw pool return " +
			"traffic to itself — the #8405 misdelivery, caused by the fix for it")
	}

	// And back, in the same closure — proving the read is live rather than
	// latched on first use.
	st.mu.Lock()
	st.vrrpInstances = map[string]bool{"reth0.80": true}
	st.mu.Unlock()
	if !policy("reth0.80", target) {
		t.Fatal("ownership returned but the policy stayed refused: the verdict is " +
			"latched, so a failback would not resume answering until the next " +
			"reconcile")
	}
}

// THE WIRING, driven through the real reconcile rather than by calling
// syncProxyARPResponders directly. A responder that is correct but never
// started, or never stopped, is the whole defect wearing a passing test.
func TestReconcileStopsRespondersWhenProxyARPIsRemoved8621(t *testing.T) {
	prevApply := proxyARPApplyFn
	proxyARPApplyFn = func(_ *config.Config, _, _ map[string]int, _ map[int]string) ([]dataplane.ProxyARPAdded, map[string]map[int]struct{}, error) {
		return nil, map[string]map[int]struct{}{}, nil
	}
	t.Cleanup(func() { proxyARPApplyFn = prevApply })
	prevDisable := proxyARPDisableFn
	proxyARPDisableFn = func(_ map[string]map[int]struct{}) int { return 0 }
	t.Cleanup(func() { proxyARPDisableFn = prevDisable })

	d := &Daemon{arpResponders: newProxyARPResponders()}

	// A responder is running from a prior config.
	_, cancel := context.WithCancel(context.Background())
	stopped := false
	d.arpResponders.running["ge-0-0-2.80"] = &proxyARPResponder{
		cancel:   func() { stopped = true; cancel() },
		done:     make(chan struct{}),
		junosRef: "reth0.80",
		addrs:    map[string]struct{}{"172.16.80.7": {}},
	}

	// The commit removes proxy-arp entirely.
	d.reconcileProxyARP(&config.Config{})

	if !stopped {
		t.Fatal("reconcileProxyARP did not stop the responder when proxy-arp was " +
			"removed from the config. It would keep answering ARP for an address " +
			"this node no longer proxies")
	}
	if len(d.arpResponders.running) != 0 {
		t.Fatalf("responder set still holds %d entries after removal",
			len(d.arpResponders.running))
	}
}

// The same wiring in the OTHER direction, and the reason the sync call sits
// ABOVE reconcileProxyARP's early return: with nothing configured and nothing
// previously installed, the reconcile returns early — and a responder left
// running past that return answers for an address that is no longer proxied.
func TestTheEarlyReturnStillStopsResponders8621(t *testing.T) {
	d := &Daemon{arpResponders: newProxyARPResponders()}
	stopped := false
	d.arpResponders.running["ge-0-0-2.80"] = &proxyARPResponder{
		cancel:   func() { stopped = true },
		done:     make(chan struct{}),
		junosRef: "reth0.80",
	}
	// hasEntries == false AND no prior installed entries => the early return.
	d.reconcileProxyARP(nil)
	if !stopped {
		t.Fatal("a responder survived reconcileProxyARP's early-return path. That " +
			"path is taken on exactly the config where nothing should be answered")
	}
}

// THE LAST MILE. Everything above proves the decision is right and the frame is
// built right; this proves the frame actually leaves, addressed to the asker.
// Those are indistinguishable from inside the receive loop, and a responder that
// decides perfectly and transmits nothing is the defect it was written to fix.
func TestAnAnsweredRequestReachesTheWireAddressedToTheAsker8621(t *testing.T) {
	var sentPkt []byte
	var sentAddr *unix.SockaddrLinklayer
	prev := arpReplySend
	arpReplySend = func(_ int, pkt []byte, addr unix.Sockaddr) error {
		sentPkt = append([]byte(nil), pkt...)
		sentAddr, _ = addr.(*unix.SockaddrLinklayer)
		return nil
	}
	t.Cleanup(func() { arpReplySend = prev })

	ourMAC := net.HardwareAddr{0x02, 0xbf, 0x72, 0x16, 0x01, 0x00}
	askerMAC := net.HardwareAddr{0x10, 0x66, 0x6a, 0x8b, 0x91, 0xa4}
	poolIP := net.IP{172, 16, 80, 7}
	askerIP := net.IP{172, 16, 80, 174}
	r := &proxyARPResponder{mac: ourMAC, macSet: true}

	frame := arpRequestFrame(askerMAC, askerIP, poolIP)
	answerAll := func(_ string, _ net.IP) bool { return true }
	if err := respondToARPFrame(7, 42, "ge-0-0-2.80", r, answerAll, frame); err != nil {
		t.Fatalf("respondToARPFrame: %v", err)
	}
	if sentPkt == nil {
		t.Fatal("nothing was sent for a request this node answers — the decision " +
			"path is green and the frame never leaves")
	}
	if sentAddr == nil {
		t.Fatal("the reply was sent without a link-layer address")
	}
	if sentAddr.Ifindex != 42 {
		t.Errorf("sent on ifindex %d, want 42", sentAddr.Ifindex)
	}
	if got := net.HardwareAddr(sentAddr.Addr[:6]).String(); got != askerMAC.String() {
		t.Errorf("sent to link-layer %s, want the asker %s — a reply with correct "+
			"contents delivered to the wrong address teaches nobody anything",
			got, askerMAC)
	}
	if got := net.HardwareAddr(sentPkt[22:28]).String(); got != ourMAC.String() {
		t.Errorf("the frame on the wire claims sender hardware %s, want %s", got, ourMAC)
	}

	// CONTROL: a refused request must put NOTHING on the wire. Without this, a
	// responder that transmits unconditionally satisfies every assertion above.
	sentPkt, sentAddr = nil, nil
	refuseAll := func(_ string, _ net.IP) bool { return false }
	if err := respondToARPFrame(7, 42, "ge-0-0-2.80", r, refuseAll, frame); err != nil {
		t.Fatalf("respondToARPFrame (refusing): %v", err)
	}
	if sentPkt != nil {
		t.Fatal("a REFUSED request still put a frame on the wire")
	}
}

// TestResponderReconcileRefreshesVirtualMAC_10316 proves the live-MAC fix at
// the wire boundary. The socket remains open while reconcile swaps M1 -> M2;
// the next ARP reply must carry M2, not the MAC captured when the responder
// started. RED on the old code: syncProxyARPResponders only replaced addrs,
// so the reply continued to use its stale start-time MAC.
func TestResponderReconcileRefreshesVirtualMAC_10316(t *testing.T) {
	mac1 := net.HardwareAddr{0x02, 0xbf, 0x72, 0x16, 0x01, 0x00}
	mac2 := net.HardwareAddr{0x02, 0xbf, 0x72, 0x16, 0x02, 0x00}
	current := mac2
	originalLookup := proxyARPInterfaceByName
	proxyARPInterfaceByName = func(_ string) (*net.Interface, error) {
		return &net.Interface{HardwareAddr: append(net.HardwareAddr(nil), current...)}, nil
	}
	t.Cleanup(func() { proxyARPInterfaceByName = originalLookup })

	d := &Daemon{arpResponders: newProxyARPResponders()}
	r := &proxyARPResponder{
		junosRef: "reth0.80",
		addrs:    map[string]struct{}{"172.16.80.7": {}},
		mac:      mac1,
		macSet:  true,
	}
	d.arpResponders.running["ge-0-0-2"] = r
	cfg := proxyARPCfg("reth0.80", "172.16.80.7/32")

	// Reconcile is the live-set notification path: no responder restart and
	// no socket reopen occurs here.
	d.syncProxyARPResponders(cfg, map[string]string{"ge-0-0-2": "reth0.80"})
	if got := r.currentMAC(); got.String() != mac2.String() {
		t.Fatalf("reconcile left responder MAC at %s, want live MAC %s", got, mac2)
	}

	var sent []byte
	originalSend := arpReplySend
	arpReplySend = func(_ int, pkt []byte, _ unix.Sockaddr) error {
		sent = append([]byte(nil), pkt...)
		return nil
	}
	t.Cleanup(func() { arpReplySend = originalSend })
	frame := arpRequestFrame(
		net.HardwareAddr{0x10, 0x66, 0x6a, 0x8b, 0x91, 0xa4},
		net.IP{172, 16, 80, 174}, net.IP{172, 16, 80, 7})
	if err := respondToARPFrame(7, 42, "ge-0-0-2", r,
		func(_ string, _ net.IP) bool { return true }, frame); err != nil {
		t.Fatalf("respondToARPFrame: %v", err)
	}
	if len(sent) < 28 {
		t.Fatalf("no complete ARP reply captured: %d bytes", len(sent))
	}
	if got := net.HardwareAddr(sent[22:28]); got.String() != mac2.String() {
		t.Fatalf("ARP reply used stale MAC %s after reconcile; want %s", got, mac2)
	}
}

// TestResponderReconcileAndRepliesAreRaceFree_10316 is intended for -race.
// Reconcile writes the complete snapshot while a receive path reads it for
// policy and reply construction. The old code wrote rgID/junosRef outside
// addrsMu while the policy closure read rgID, producing a race under live
// reconcile plus inbound ARP.
func TestResponderReconcileAndRepliesAreRaceFree_10316(t *testing.T) {
	originalLookup := proxyARPInterfaceByName
	proxyARPInterfaceByName = func(_ string) (*net.Interface, error) {
		return &net.Interface{HardwareAddr: net.HardwareAddr{0x02, 0xbf, 0x72, 0x16, 0x02, 0x00}}, nil
	}
	t.Cleanup(func() { proxyARPInterfaceByName = originalLookup })

	d := &Daemon{arpResponders: newProxyARPResponders()}
	r := &proxyARPResponder{
		junosRef: "reth0.80",
		rgID:     2,
		addrs:    map[string]struct{}{"172.16.80.7": {}},
		mac:      net.HardwareAddr{0x02, 0xbf, 0x72, 0x16, 0x01, 0x00},
		macSet:  true,
	}
	d.arpResponders.running["ge-0-0-2"] = r
	cfg := proxyARPCfg("reth0.80", "172.16.80.7/32")
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"reth0": {Name: "reth0", RedundancyGroup: 2},
	}
	policy := d.answerPolicyFor(r)
	frame := arpRequestFrame(
		net.HardwareAddr{0x10, 0x66, 0x6a, 0x8b, 0x91, 0xa4},
		net.IP{172, 16, 80, 174}, net.IP{172, 16, 80, 7})

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := 0; i < 1000; i++ {
			d.syncProxyARPResponders(cfg, map[string]string{"ge-0-0-2": "reth0.80"})
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < 1000; i++ {
			// fd=-1 deliberately avoids a raw socket; the decision and MAC
			// snapshot still run, and the expected send error is irrelevant.
			_ = respondToARPFrame(-1, 42, "ge-0-0-2", r, policy, frame)
		}
	}()
	wg.Wait()
}

// arpRequestFrame builds a well-formed ARP request. Deliberately a local
// builder rather than an import of the cluster package's test helper: a test
// fixture shared across packages is a fixture two suites can no longer change
// independently.
func arpRequestFrame(senderMAC net.HardwareAddr, senderIP, target net.IP) []byte {
	pkt := make([]byte, 42)
	copy(pkt[0:6], []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff})
	copy(pkt[6:12], senderMAC)
	binary.BigEndian.PutUint16(pkt[12:14], unix.ETH_P_ARP)
	binary.BigEndian.PutUint16(pkt[14:16], 1)
	binary.BigEndian.PutUint16(pkt[16:18], 0x0800)
	pkt[18] = 6
	pkt[19] = 4
	binary.BigEndian.PutUint16(pkt[20:22], 1)
	copy(pkt[22:28], senderMAC)
	copy(pkt[28:32], senderIP.To4())
	copy(pkt[38:42], target.To4())
	return pkt
}
