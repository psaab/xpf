// #9139: IPsec SA sync and re-initiation were hardcoded to RG0.
//
// Active/active is a supported configuration (docs/active-active-new-connections.md
// designs it; `make test-active-active` gates it), and in the asymmetric case —
// RG0 primary node 0, RG1 primary node 1, IPsec anchored on an RG1 reth —
// NEITHER half of the feature ran. Node 1 holds the SAs and short-circuited on
// IsLocalPrimary(0) so it never advertised; node 0 advertised its own empty set,
// which ipsecSASyncAdvertise suppresses; and on node 1's death node 0 took RG1
// with no RG0 transition, so nothing re-initiated. charon does not cover for it:
// `start_action = start` is emitted only for `establish-tunnels immediately`.
//
// These cells are the Go half. The on-cluster half is `make test-failover` on
// the loss userspace cluster, recorded in the PR.

package daemon

import (
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/cluster"
	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/configstore"
)

// twoRGIPsecStore builds a cluster config with TWO data RGs, an IPsec gateway
// anchored on each one's reth, and a third gateway on a plain physical port.
func twoRGIPsecStore(t *testing.T) *configstore.Store {
	t.Helper()
	return testStoreWithSetConfig(t, []string{
		"set chassis cluster cluster-id 1",
		"set chassis cluster node 0",
		"set chassis cluster authentication-key test-cluster-psk-9139",
		"set chassis cluster ipsec-session-synchronization",
		"set chassis cluster redundancy-group 1 node 0 priority 200",
		"set chassis cluster redundancy-group 2 node 0 priority 100",
		"set interfaces reth1 redundant-ether-options redundancy-group 1",
		"set interfaces reth1 unit 0 family inet address 10.0.1.1/24",
		"set interfaces ge-0/0/0 gigether-options redundant-parent reth1",
		"set interfaces reth2 redundant-ether-options redundancy-group 2",
		"set interfaces reth2 unit 0 family inet address 10.0.2.1/24",
		"set interfaces ge-0/0/1 gigether-options redundant-parent reth2",
		"set interfaces ge-0/0/3 unit 0 family inet address 10.0.3.1/24",
		// One VPN per anchor.
		"set security ike gateway gw-rg1 address 198.51.100.1",
		"set security ike gateway gw-rg1 external-interface reth1.0",
		"set security ike gateway gw-rg2 address 198.51.100.2",
		"set security ike gateway gw-rg2 external-interface reth2.0",
		"set security ike gateway gw-plain address 198.51.100.3",
		"set security ike gateway gw-plain external-interface ge-0/0/3.0",
		"set security ipsec vpn vpn-rg1 ike gateway gw-rg1",
		"set security ipsec vpn vpn-rg2 ike gateway gw-rg2",
		"set security ipsec vpn vpn-plain ike gateway gw-plain",
	})
}

// The attribution itself: a connection's RG is the one that owns the reth its
// gateway's external-interface names.
func TestIPsecConnRedundancyGroupAttribution9139(t *testing.T) {
	cfg := twoRGIPsecStore(t).ActiveConfig()
	// FIXTURE GUARD: if the VPNs did not compile, every assertion below would
	// pass by returning the RG-0 default, which is the answer the defect gives.
	if len(cfg.Security.IPsec.VPNs) != 3 {
		t.Fatalf("FIXTURE: expected 3 VPNs, got %d — the cells below would pass "+
			"vacuously on the RG-0 default", len(cfg.Security.IPsec.VPNs))
	}
	for _, tc := range []struct {
		conn string
		want int
		why  string
	}{
		{"vpn-rg1", 1, "anchored on reth1, which is redundancy-group 1"},
		{"vpn-rg2", 2, "anchored on reth2, which is redundancy-group 2"},
		{"vpn-plain", 0, "anchored on a plain physical port: no RG, so the " +
			"historical RG0 default, which preserves pre-#9139 re-initiation"},
		{"nosuchvpn", 0, "an unknown connection name must default to RG0 rather " +
			"than be refused — refusing would silently STOP re-initiating a " +
			"tunnel that works today"},
	} {
		if got := ipsecConnRedundancyGroups(cfg, ipsecSANameIndex(cfg), tc.conn); len(got) != 1 || got[0] != tc.want {
			t.Errorf("ipsecConnRedundancyGroups(%q) = %v, want [%d] (%s)",
				tc.conn, got, tc.want, tc.why)
		}
	}
}

// THE CELL THAT MATTERS. On a partial failover the peer is still ALIVE and
// still owns another RG, so initiating its WHOLE advertised set would raise a
// second IKE SA to the same remote from a different local address. Trading a
// missed re-initiation for a duplicate one is not a fix.
func TestOwnsIPsecConnScopesToOwnedRGs9139(t *testing.T) {
	store := twoRGIPsecStore(t)
	cfg := store.ActiveConfig()
	cm := cluster.NewManager(0, 1)
	cm.UpdateConfig(cfg.Chassis.Cluster)
	// This node owns RG1 only: it has taken RG1 from the peer, which is alive
	// and still holds RG2.
	cm.SetGroupStateForTesting(0, cluster.StatePrimary)
	cm.SetGroupStateForTesting(1, cluster.StatePrimary)
	cm.SetGroupStateForTesting(2, cluster.StateSecondary)
	if !cm.IsLocalPrimary(1) || cm.IsLocalPrimary(2) {
		t.Fatal("FIXTURE: this cell needs RG1 owned and RG2 not owned, or it " +
			"cannot distinguish scoped from unscoped")
	}
	d := &Daemon{cluster: cm, store: store}

	if !d.ownsIPsecConn(cfg, ipsecSANameIndex(cfg), "vpn-rg1") {
		t.Error("the connection anchored on the RG this node just took MUST be " +
			"re-initiated — that is the outage #9139 is about")
	}
	if d.ownsIPsecConn(cfg, ipsecSANameIndex(cfg), "vpn-rg2") {
		t.Error("#9139: the connection anchored on an RG the LIVE peer still owns " +
			"must NOT be initiated. Both nodes would hold an SA to the same remote " +
			"from different local addresses.")
	}
	if !d.ownsIPsecConn(cfg, ipsecSANameIndex(cfg), "vpn-plain") {
		t.Error("an RG-less connection follows RG0, which this node owns")
	}
}

// The inverse: a node that owns NO redundancy group initiates nothing. Without
// this, a scoping bug that returned true unconditionally would pass the cell
// above (which only checks that RG2 is excluded while RG1 is included).
func TestOwnsIPsecConnOwnsNothingWhenSecondary9139(t *testing.T) {
	store := twoRGIPsecStore(t)
	cfg := store.ActiveConfig()
	cm := cluster.NewManager(0, 1)
	cm.UpdateConfig(cfg.Chassis.Cluster)
	for _, rg := range []int{0, 1, 2} {
		cm.SetGroupStateForTesting(rg, cluster.StateSecondary)
	}
	d := &Daemon{cluster: cm, store: store}
	for _, conn := range []string{"vpn-rg1", "vpn-rg2", "vpn-plain"} {
		if d.ownsIPsecConn(cfg, ipsecSANameIndex(cfg), conn) {
			t.Errorf("a node primary for NO redundancy group must not claim %q", conn)
		}
	}
}

// CONTROL: a standalone (non-cluster) daemon owns everything. The gate exists to
// stop two CLUSTER nodes initiating the same tunnel; with no second node there
// is nothing to collide with, and refusing here would break every standalone box.
func TestOwnsIPsecConnStandaloneOwnsEverything9139(t *testing.T) {
	store := twoRGIPsecStore(t)
	d := &Daemon{store: store} // no cluster manager
	if !d.ownsIPsecConn(store.ActiveConfig(), ipsecSANameIndex(store.ActiveConfig()), "vpn-rg2") {
		t.Error("a daemon with no cluster manager must own every connection")
	}
}

// A nil config must not silently attribute everything away. It returns RG0,
// which is the pre-#9139 behaviour, rather than an RG nobody owns — the
// fail-direction that would silently stop re-initiating on a config-less path.
func TestIPsecConnRedundancyGroupNilConfig9139(t *testing.T) {
	if got := ipsecConnRedundancyGroups(nil, nil, "vpn-rg1"); len(got) != 1 || got[0] != 0 {
		t.Errorf("nil config must degrade to RG0 (pre-#9139 behaviour), got %v", got)
	}
	var cfg *config.Config
	if got := ipsecConnRedundancyGroups(cfg, nil, ""); len(got) != 1 || got[0] != 0 {
		t.Errorf("empty name must degrade to RG0, got %v", got)
	}
}

// RG0 IS NOT NECESSARILY DECLARED, and the two cases must answer differently.
//
// cluster.Manager.UpdateConfig creates a group only for an RG the config
// declares, so IsLocalPrimary(0) is permanently FALSE on a config that omits
// `redundancy-group 0` — an unanchored connection gated on it would NEVER be
// re-initiated, which is worse than the behaviour this change extends. Where
// RG0 IS declared the honest answer is the narrower one: a node taking only a
// data RG while the peer keeps RG0 must not initiate a tunnel bound to an
// interface the peer still holds.
//
// The two cells differ ONLY in whether the config declares RG0, which is what
// makes the branch observable rather than assumed.
func TestOwnsIPsecConnRG0DeclaredVsNot9139(t *testing.T) {
	base := []string{
		"set chassis cluster cluster-id 1",
		"set chassis cluster node 0",
		"set chassis cluster authentication-key test-cluster-psk-9139",
		"set chassis cluster redundancy-group 1 node 0 priority 200",
		"set interfaces reth1 redundant-ether-options redundancy-group 1",
		"set interfaces reth1 unit 0 family inet address 10.0.1.1/24",
		"set interfaces ge-0/0/0 gigether-options redundant-parent reth1",
		"set interfaces ge-0/0/3 unit 0 family inet address 10.0.3.1/24",
		"set security ike gateway gw-plain address 198.51.100.3",
		"set security ike gateway gw-plain external-interface ge-0/0/3.0",
		"set security ipsec vpn vpn-plain ike gateway gw-plain",
	}

	t.Run("RG0 undeclared falls back to primary-for-anything", func(t *testing.T) {
		store := testStoreWithSetConfig(t, base)
		cfg := store.ActiveConfig()
		cm := cluster.NewManager(0, 1)
		cm.UpdateConfig(cfg.Chassis.Cluster)
		cm.SetGroupStateForTesting(1, cluster.StatePrimary)
		if _, known := cm.LocalGroupPrimary(0); known {
			t.Fatal("FIXTURE: this cell needs RG0 ABSENT from the manager; with it " +
				"present the fallback branch is never reached and the cell is vacuous")
		}
		d := &Daemon{cluster: cm, store: store}
		if !d.ownsIPsecConn(cfg, ipsecSANameIndex(cfg), "vpn-plain") {
			t.Error("#9139: with RG0 undeclared, IsLocalPrimary(0) is permanently " +
				"false, so gating on it would never re-initiate this tunnel — a " +
				"silent regression on a legal config shape")
		}
	})

	t.Run("RG0 declared and held by the peer excludes it", func(t *testing.T) {
		store := testStoreWithSetConfig(t, append(append([]string{}, base...),
			"set chassis cluster redundancy-group 0 node 0 priority 1"))
		cfg := store.ActiveConfig()
		cm := cluster.NewManager(0, 1)
		cm.UpdateConfig(cfg.Chassis.Cluster)
		cm.SetGroupStateForTesting(0, cluster.StateSecondary)
		cm.SetGroupStateForTesting(1, cluster.StatePrimary)
		if _, known := cm.LocalGroupPrimary(0); !known {
			t.Fatal("FIXTURE: this cell needs RG0 PRESENT in the manager")
		}
		d := &Daemon{cluster: cm, store: store}
		if d.ownsIPsecConn(cfg, ipsecSANameIndex(cfg), "vpn-plain") {
			t.Error("with RG0 declared and held by the LIVE peer, a node that took " +
				"only a data RG must not initiate a tunnel bound to an interface " +
				"the peer still holds")
		}
	})
}

// ── WIRING ─────────────────────────────────────────────────────────────────
//
// Measured on the first pass: with only the cells above, the three mutations
// that actually matter ALL SURVIVED — reverting the advertise gate to
// IsLocalPrimary(0), deleting the per-RG re-initiate leg from
// applyRethServicesForRG, and dropping the scoping inside reinitiateIPsecSAs.
// Every one of them is the fix; the filter they call was never the broken part.
// A green board there would have been a claim that the code is tested.

// The advertise gate, driven directly: a node primary for a DATA RG but not for
// RG0 must advertise. That node is the one holding the SAs in the asymmetric
// case, and IsLocalPrimary(0) is exactly what silenced it.
func TestIPsecSAAdvertiseGateCoversDataRGPrimary9139(t *testing.T) {
	store := twoRGIPsecStore(t)
	cm := cluster.NewManager(0, 1)
	cm.UpdateConfig(store.ActiveConfig().Chassis.Cluster)
	d := &Daemon{cluster: cm, store: store}

	// Primary for RG1 only — RG0 is not even a declared group here, which is
	// the shape that makes IsLocalPrimary(0) permanently false.
	cm.SetGroupStateForTesting(1, cluster.StatePrimary)
	cm.SetGroupStateForTesting(2, cluster.StateSecondary)
	if !d.ipsecSAAdvertiseEligible() {
		t.Error("#9139: the node primary for the data RG that ANCHORS the tunnel " +
			"must advertise its SA set. Gating on RG0 silenced exactly this node, " +
			"so the standby learned nothing and re-initiated nothing on failover.")
	}

	// CONTROL: a node primary for nothing must stay silent, or every standby
	// would advertise an empty set at the peer and clear its view.
	cm.SetGroupStateForTesting(1, cluster.StateSecondary)
	if d.ipsecSAAdvertiseEligible() {
		t.Error("a node primary for no redundancy group must not advertise")
	}

	// CONTROL: no cluster manager, no advertising.
	if (&Daemon{store: store}).ipsecSAAdvertiseEligible() {
		t.Error("a daemon with no cluster manager must not advertise")
	}
}

// The filter, driven through the real peer-set accessor rather than a slice
// literal, so the seam between "what the peer advertised" and "what we
// initiate" is the thing under test.
func TestIPsecSAsToReinitiateFiltersPeerSet9139(t *testing.T) {
	store := twoRGIPsecStore(t)
	cfg := store.ActiveConfig()
	cm := cluster.NewManager(0, 1)
	cm.UpdateConfig(cfg.Chassis.Cluster)
	cm.SetGroupStateForTesting(1, cluster.StatePrimary)
	cm.SetGroupStateForTesting(2, cluster.StateSecondary)
	d := &Daemon{cluster: cm, store: store}

	ss := cluster.NewSessionSync(":0", "", nil)
	ss.SetPeerIPsecSAsForTesting([]string{"vpn-rg1", "vpn-rg2"})
	got := d.ipsecSAsToReinitiate(ss.PeerIPsecSAs())

	if len(got) != 1 || got[0] != "vpn-rg1" {
		t.Fatalf("#9139: the peer's advertised set must be narrowed to the RG this "+
			"node owns. got %v, want [vpn-rg1].\n"+
			"  vpn-rg2 is anchored on an RG the LIVE peer still holds; initiating "+
			"it raises a second IKE SA to the same remote.", got)
	}
}

// THE CALL SITE. applyRethServicesForRG is the per-RG VRRP MASTER edge and had
// no IPsec leg at all — the reason an asymmetric failover re-initiated nothing.
// This drives that edge and observes the swanctl calls through the #9139 seam.
func TestApplyRethServicesForRGReinitiatesIPsec9139(t *testing.T) {
	store := testStoreWithSetConfig(t, []string{
		"set chassis cluster cluster-id 1",
		"set chassis cluster node 0",
		"set chassis cluster authentication-key test-cluster-psk-9139",
		"set chassis cluster ipsec-session-synchronization",
		"set chassis cluster redundancy-group 0 node 0 priority 1",
		"set chassis cluster redundancy-group 1 node 0 priority 200",
		"set chassis cluster redundancy-group 2 node 0 priority 100",
		"set interfaces reth1 redundant-ether-options redundancy-group 1",
		"set interfaces reth1 unit 0 family inet address 10.0.1.1/24",
		"set interfaces ge-0/0/0 gigether-options redundant-parent reth1",
		"set interfaces reth2 redundant-ether-options redundancy-group 2",
		"set interfaces reth2 unit 0 family inet address 10.0.2.1/24",
		"set interfaces ge-0/0/1 gigether-options redundant-parent reth2",
		"set security ike gateway gw-rg1 address 198.51.100.1",
		"set security ike gateway gw-rg1 external-interface reth1.0",
		"set security ike gateway gw-rg2 address 198.51.100.2",
		"set security ike gateway gw-rg2 external-interface reth2.0",
		"set security ipsec vpn vpn-rg1 ike gateway gw-rg1",
		"set security ipsec vpn vpn-rg2 ike gateway gw-rg2",
	})
	cfg := store.ActiveConfig()
	if !cfg.Chassis.Cluster.IPsecSASync {
		t.Fatal("FIXTURE: ipsec-sa-sync must be on, or the leg is gated off and " +
			"this cell passes for the wrong reason")
	}

	cm := cluster.NewManager(0, 1)
	cm.UpdateConfig(cfg.Chassis.Cluster)
	// The asymmetric case: this node already holds RG0 and is TAKING RG1 from a
	// peer that is still alive and still owns RG2. There is no RG0 transition,
	// which is why the RG0-only wiring never fired.
	cm.SetGroupStateForTesting(0, cluster.StatePrimary)
	cm.SetGroupStateForTesting(1, cluster.StatePrimary)
	cm.SetGroupStateForTesting(2, cluster.StateSecondary)

	ss := cluster.NewSessionSync(":0", "", nil)
	ss.SetPeerIPsecSAsForTesting([]string{"vpn-rg1", "vpn-rg2"})

	initiated := make(chan string, 8)
	d := &Daemon{
		cluster:         cm,
		store:           store,
		sessionSync:     ss,
		ipsecInitiateFn: func(name string) error { initiated <- name; return nil },
	}

	d.applyRethServicesForRG(1)

	// The leg is async (it runs on the VRRP event loop and swanctl shells out),
	// so wait rather than assume ordering.
	var got []string
	deadline := time.After(5 * time.Second)
collect:
	for {
		select {
		case name := <-initiated:
			got = append(got, name)
			if len(got) > 1 {
				break collect
			}
		case <-time.After(750 * time.Millisecond):
			break collect
		case <-deadline:
			break collect
		}
	}

	if len(got) == 0 {
		t.Fatal("#9139: taking RG1 re-initiated NOTHING. reinitiateIPsecSAs was " +
			"wired only to applyRG0OwnershipTransition, and this node was ALREADY " +
			"RG0 primary — so no RG0 transition fires and every tunnel anchored on " +
			"the reth whose VIP just moved here stays down until the REMOTE peer " +
			"initiates (charon emits start_action only for `establish-tunnels " +
			"immediately`).")
	}
	if len(got) != 1 || got[0] != "vpn-rg1" {
		t.Fatalf("the RG1 takeover must initiate exactly the RG1-anchored tunnel. "+
			"got %v, want [vpn-rg1] — vpn-rg2 belongs to an RG the live peer still "+
			"holds, and initiating it would raise a duplicate SA", got)
	}
}

// CONTROL for the leg: with ipsec-sa-sync OFF, taking an RG must initiate
// nothing. Without this, a leg that ignored the feature flag would pass the
// cell above and start issuing swanctl calls on every cluster.
func TestApplyRethServicesForRGRespectsSASyncFlag9139(t *testing.T) {
	store := testStoreWithSetConfig(t, []string{
		"set chassis cluster cluster-id 1",
		"set chassis cluster node 0",
		"set chassis cluster authentication-key test-cluster-psk-9139",
		"set chassis cluster redundancy-group 1 node 0 priority 200",
		"set interfaces reth1 redundant-ether-options redundancy-group 1",
		"set interfaces reth1 unit 0 family inet address 10.0.1.1/24",
		"set interfaces ge-0/0/0 gigether-options redundant-parent reth1",
		"set security ike gateway gw-rg1 address 198.51.100.1",
		"set security ike gateway gw-rg1 external-interface reth1.0",
		"set security ipsec vpn vpn-rg1 ike gateway gw-rg1",
	})
	cfg := store.ActiveConfig()
	if cfg.Chassis.Cluster.IPsecSASync {
		t.Fatal("FIXTURE: this cell needs ipsec-sa-sync OFF")
	}
	cm := cluster.NewManager(0, 1)
	cm.UpdateConfig(cfg.Chassis.Cluster)
	cm.SetGroupStateForTesting(1, cluster.StatePrimary)
	ss := cluster.NewSessionSync(":0", "", nil)
	ss.SetPeerIPsecSAsForTesting([]string{"vpn-rg1"})
	initiated := make(chan string, 4)
	d := &Daemon{
		cluster:         cm,
		store:           store,
		sessionSync:     ss,
		ipsecInitiateFn: func(name string) error { initiated <- name; return nil },
	}
	d.applyRethServicesForRG(1)
	select {
	case name := <-initiated:
		t.Fatalf("ipsec-sa-sync is OFF, so no SA may be initiated; got %q", name)
	case <-time.After(750 * time.Millisecond):
	}
}

// THE GATE'S CALL SITE, not the gate. Measured: severing
// `if !d.ipsecSAAdvertiseEligible()` inside advertiseIPsecSAOnce — leaving the
// gate function itself correct and fully covered by the cell above — SURVIVED.
// A standby would then read and advertise its own SA set at the primary, which
// is the regression the gate exists to prevent.
//
// The observable is whether the swanctl read HAPPENED: it is the first thing
// the function touches after the gate, so "the read did not occur" is exactly
// "the gate ran".
func TestAdvertiseIPsecSAOnceHonoursTheGate9139(t *testing.T) {
	store := twoRGIPsecStore(t)
	cm := cluster.NewManager(0, 1)
	cm.UpdateConfig(store.ActiveConfig().Chassis.Cluster)

	read := 0
	d := &Daemon{
		cluster:            cm,
		store:              store,
		ipsecActiveNamesFn: func() ([]string, error) { read++; return []string{"vpn-rg1"}, nil },
	}

	// SUBJECT: primary for NO redundancy group. The gate must stop it before
	// the read.
	cm.SetGroupStateForTesting(1, cluster.StateSecondary)
	cm.SetGroupStateForTesting(2, cluster.StateSecondary)
	if got := d.advertiseIPsecSAOnce("seed-fp", false); got != "seed-fp" {
		t.Errorf("a non-primary node must return lastFP unchanged; got %q", got)
	}
	if read != 0 {
		t.Errorf("#9139: advertiseIPsecSAOnce read the active SA set on a node "+
			"primary for NOTHING (%d reads). The gate's CALL SITE is severed: a "+
			"standby would advertise its own set at the primary.", read)
	}

	// POSITIVE CONTROL: primary for a data RG. The read MUST happen, or the
	// assertion above passes for a function that never does anything at all.
	cm.SetGroupStateForTesting(1, cluster.StatePrimary)
	d.advertiseIPsecSAOnce("", false)
	if read == 0 {
		t.Error("POSITIVE CONTROL FAILED: a node primary for a data RG must read " +
			"and advertise its SA set — without this, the zero-read assertion " +
			"above cannot distinguish a working gate from a dead function")
	}
}
