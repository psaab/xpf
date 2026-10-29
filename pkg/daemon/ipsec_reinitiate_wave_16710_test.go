// #16710: every RG takeover edge ran the same unscoped
// reinitiateIPsecSAs. Its #15194 belt terminates (--force) any owned name
// already live locally, so a later edge tore down and renegotiated the
// tunnels an earlier edge of the same takeover sequence had just restored,
// whenever the peer's advertised set still listed them.
//
// The fix scopes each pass to the transitioning RG (reinitiateIPsecSAsForRG):
// the RG0 edge handles declared-RG0 names, and a data-RG edge handles that
// RG's names. The undeclared-RG0 fallback is admitted only when one current
// config snapshot has a sole data RG matching this edge and the peer's last
// heartbeat has no RG0 entry. A multi-data-RG control and a stale edge for a
// removed RG keep that name out to preserve wave idempotency; other cells
// cover peer/config declarations, multi-RG names, and the belt.

package daemon

import (
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/cluster"
	"github.com/psaab/xpf/pkg/configstore"
)

// waveFixture16710 builds the two-RG store with declared RG0 and every RG
// secondary, so a test can promote RGs in wave order.
func waveFixture16710(t *testing.T) (*configstore.Store, *cluster.Manager) {
	t.Helper()
	store := twoRGIPsecStoreWithRG0(t)
	cfg := store.ActiveConfig()
	cm := cluster.NewManager(0, 1)
	cm.UpdateConfig(cfg.Chassis.Cluster)
	for _, rg := range []int{0, 1, 2} {
		cm.SetGroupStateForTesting(rg, cluster.StateSecondary)
	}
	return store, cm
}

type waveRecorder16710 struct {
	mu         sync.Mutex
	terminated []string
	initiated  []string
}

func (r *waveRecorder16710) recordTerminated(name string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.terminated = append(r.terminated, name)
	return nil
}

func (r *waveRecorder16710) recordInitiated(name string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.initiated = append(r.initiated, name)
	return nil
}

func (r *waveRecorder16710) snapshot() (terminated, initiated []string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.terminated...), append([]string(nil), r.initiated...)
}

func sortedCopy16710(in []string) []string {
	out := append([]string(nil), in...)
	sort.Strings(out)
	return out
}

func equalNames16710(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// waveDaemon16710 builds a daemon whose live-SA view grows with every
// initiate (the fake-charon effect the va35 probe modelled): once a name
// is initiated it reads back as locally live, so a second unscoped pass
// would belt-terminate it.
func waveDaemon16710(store *configstore.Store, cm *cluster.Manager, rec *waveRecorder16710) (*Daemon, *cluster.SessionSync) {
	ss := cluster.NewSessionSync(":0", "", nil)
	ss.SetPeerIPsecSAsForTesting([]string{"vpn-rg1", "vpn-rg2", "vpn-plain"})
	d := &Daemon{
		cluster:     cm,
		store:       store,
		sessionSync: ss,
		ipsecActiveNamesFn: func() ([]string, error) {
			_, initiated := rec.snapshot()
			return initiated, nil
		},
		ipsecTerminateFn: rec.recordTerminated,
		ipsecInitiateFn:  rec.recordInitiated,
	}
	return d, ss
}

// Shape A (va35): progressive ownership. RG1 is taken first, then RG2.
// The RG2 edge must not terminate or re-initiate vpn-rg1 / vpn-plain, which
// the RG1+RG0 state already restored. Pre-fix (unscoped) this wave
// force-terminated [vpn-rg1 vpn-plain] on the second edge.
func TestReinitiateWaveProgressiveOwnership16710(t *testing.T) {
	store, cm := waveFixture16710(t)
	rec := &waveRecorder16710{}
	d, _ := waveDaemon16710(store, cm, rec)

	// Edge 1: this node gains RG1 (RG0 already held in this shape — the
	// peer advertised all three names and RG0/unanchored follows RG0).
	cm.SetGroupStateForTesting(0, cluster.StatePrimary)
	cm.SetGroupStateForTesting(1, cluster.StatePrimary)
	d.reinitiateIPsecSAsForRG(1)
	// RG0 edge of the same sequence (RG0 was already primary; drive its
	// scoped pass so vpn-plain is restored by its own edge, as in
	// production where the RG0 transition precedes/accompanies it).
	d.reinitiateIPsecSAsForRG(0)

	terminated, initiated := rec.snapshot()
	if len(terminated) != 0 {
		t.Fatalf("#16710: first edges must terminate nothing, got %v", terminated)
	}
	if got, want := sortedCopy16710(initiated), []string{"vpn-plain", "vpn-rg1"}; !equalNames16710(got, want) {
		t.Fatalf("#16710: after RG1+RG0 edges initiated=%v want %v", initiated, want)
	}

	// Edge 2: this node later gains RG2. vpn-rg1 and vpn-plain are now
	// live locally (initiated above reads back as live).
	cm.SetGroupStateForTesting(2, cluster.StatePrimary)
	d.reinitiateIPsecSAsForRG(2)

	terminated, initiated = rec.snapshot()
	if len(terminated) != 0 {
		t.Fatalf("#16710: later RG2 edge force-terminated healthy SAs an earlier "+
			"edge just raised: %v (want 0 terminates across the whole wave)", terminated)
	}
	if got, want := sortedCopy16710(initiated), []string{"vpn-plain", "vpn-rg1", "vpn-rg2"}; !equalNames16710(got, want) {
		t.Fatalf("#16710: wave must initiate each name exactly once; initiated=%v want %v", initiated, want)
	}
	// Each name initiated exactly once (no duplicates from re-runs).
	seen := map[string]int{}
	for _, n := range initiated {
		seen[n]++
	}
	for n, c := range seen {
		if c != 1 {
			t.Fatalf("#16710: %s initiated %d times across the wave, want exactly 1 (all: %v)", n, c, initiated)
		}
	}
}

// The RG0 edge alone must handle only RG0/unanchored names — it must not
// initiate (or belt) data-RG tunnels.
func TestReinitiateRG0EdgeScopesToRG0Names16710(t *testing.T) {
	store, cm := waveFixture16710(t)
	rec := &waveRecorder16710{}
	d, _ := waveDaemon16710(store, cm, rec)
	for _, rg := range []int{0, 1, 2} {
		cm.SetGroupStateForTesting(rg, cluster.StatePrimary)
	}
	d.reinitiateIPsecSAsForRG(0)
	terminated, initiated := rec.snapshot()
	if len(terminated) != 0 {
		t.Fatalf("#16710: RG0 edge terminated %v, want nothing", terminated)
	}
	if got, want := sortedCopy16710(initiated), []string{"vpn-plain"}; !equalNames16710(got, want) {
		t.Fatalf("#16710: RG0 edge initiated=%v want %v (only RG0/unanchored)", initiated, want)
	}
}

// With multiple data RGs and undeclared RG0 there is no unique data edge for
// the unanchored fallback. Keep the name out of both edges so a later edge
// cannot belt-terminate the same SA the earlier edge raised.
func TestUndeclaredRG0FallbackDoesNotFanAcrossDataRGEdges17784(t *testing.T) {
	store := twoRGIPsecStore(t)
	cfg := store.ActiveConfig()
	cm := cluster.NewManager(0, 1)
	cm.UpdateConfig(cfg.Chassis.Cluster)
	if _, known := cm.LocalGroupPrimary(0); known {
		t.Fatal("FIXTURE: RG0 must be undeclared")
	}
	if _, known := cm.LocalGroupPrimary(2); !known {
		t.Fatal("FIXTURE: this control requires both RG1 and RG2")
	}
	rec := &waveRecorder16710{}
	d, _ := waveDaemon16710(store, cm, rec)

	cm.SetGroupStateForTesting(1, cluster.StatePrimary)
	d.reinitiateIPsecSAsForRG(1)
	_, initiated := rec.snapshot()
	if got, want := sortedCopy16710(initiated), []string{"vpn-rg1"}; !equalNames16710(got, want) {
		t.Fatalf("#17784/#16710: first data edge initiated=%v want %v", initiated, want)
	}

	cm.SetGroupStateForTesting(2, cluster.StatePrimary)
	d.reinitiateIPsecSAsForRG(2)
	terminated, initiated := rec.snapshot()
	if len(terminated) != 0 {
		t.Fatalf("#17784/#16710: later data edge terminated %v, want none", terminated)
	}
	if got, want := sortedCopy16710(initiated), []string{"vpn-rg1", "vpn-rg2"}; !equalNames16710(got, want) {
		t.Fatalf("#17784/#16710: multi-RG wave initiated=%v want %v", initiated, want)
	}
}

// A queued RG2 pass may run after a commit removes RG2. It must not mistake
// the new RG1-only config for proof that the stale RG2 edge is the sole edge.
func TestUndeclaredRG0FallbackBindsToSoleDataRG17784(t *testing.T) {
	store := twoRGIPsecStore(t)
	initial := store.ActiveConfig()
	cm := cluster.NewManager(0, 1)
	cm.UpdateConfig(initial.Chassis.Cluster)
	cm.SetGroupStateForTesting(1, cluster.StatePrimary)
	cm.SetGroupStateForTesting(2, cluster.StatePrimary)

	if _, err := store.LoadSet(
		"delete chassis cluster redundancy-group 2\n" +
			"delete interfaces reth2\n" +
			"delete interfaces ge-0/0/1\n" +
			"delete security ike gateway gw-rg2\n" +
			"delete security ipsec vpn vpn-rg2",
	); err != nil {
		t.Fatalf("remove RG2 from candidate: %v", err)
	}
	current, err := store.Commit()
	if err != nil {
		t.Fatalf("commit RG2 removal: %v", err)
	}
	if len(current.Chassis.Cluster.RedundancyGroups) != 1 ||
		current.Chassis.Cluster.RedundancyGroups[0].ID != 1 {
		t.Fatalf("FIXTURE: current config data RGs = %v, want only RG1",
			current.Chassis.Cluster.RedundancyGroups)
	}
	cm.UpdateConfig(current.Chassis.Cluster)
	cm.SetGroupStateForTesting(1, cluster.StatePrimary)

	rec := &waveRecorder16710{}
	ss := cluster.NewSessionSync(":0", "", nil)
	ss.SetPeerIPsecSAsForTesting([]string{"vpn-plain"})
	d := &Daemon{
		cluster:     cm,
		store:       store,
		sessionSync: ss,
		ipsecActiveNamesFn: func() ([]string, error) {
			_, initiated := rec.snapshot()
			return initiated, nil
		},
		ipsecTerminateFn: rec.recordTerminated,
		ipsecInitiateFn:  rec.recordInitiated,
	}

	// This queued edge belongs to the removed RG2. Only the surviving RG1
	// edge may offer the current config's unanchored fallback.
	d.reinitiateIPsecSAsForRG(2)
	if terminated, initiated := rec.snapshot(); len(terminated) != 0 || len(initiated) != 0 {
		t.Fatalf("#17784/#16710: stale RG2 edge acted after removal: terminated=%v initiated=%v",
			terminated, initiated)
	}
	// RG0 is not declared in the current config, so an unanchored candidate
	// cannot bypass the sole-data-edge binding through a stale RG0 pass.
	d.reinitiateIPsecSAsForRG(0)
	if terminated, initiated := rec.snapshot(); len(terminated) != 0 || len(initiated) != 0 {
		t.Fatalf("#17784/#16710: undeclared RG0 edge acted: terminated=%v initiated=%v",
			terminated, initiated)
	}

	d.reinitiateIPsecSAsForRG(1)
	terminated, initiated := rec.snapshot()
	if len(terminated) != 0 {
		t.Fatalf("#17784/#15194: sole RG1 edge terminated %v", terminated)
	}
	if got, want := sortedCopy16710(initiated), []string{"vpn-plain"}; !equalNames16710(got, want) {
		t.Fatalf("#17784: surviving sole RG1 edge initiated=%v want exactly one %v",
			initiated, want)
	}
}

// A one-data-RG edge with no peer RG0 heartbeat entry admits its unanchored
// name, while a spanning name still belongs to no single edge (#9511/#16710).
func TestReinitiateDataRGEdgeExcludesMultiRGName17784(t *testing.T) {
	store := syncedStore9511(t, []string{
		"set chassis cluster cluster-id 1",
		"set chassis cluster node 0",
		"set chassis cluster authentication-key test-cluster-psk-17784",
		"set chassis cluster control-interface em0",
		"set chassis cluster peer-address 10.99.0.2",
		"set interfaces em0 unit 0 family inet address 10.99.0.1/24",
		"set chassis cluster redundancy-group 1 node 0 priority 200",
		"set interfaces reth1 redundant-ether-options redundancy-group 1",
		"set interfaces reth1 unit 0 family inet address 10.0.1.1/24",
		"set interfaces ge-0/0/0 gigether-options redundant-parent reth1",
		"set interfaces ge-0/0/3 unit 0 family inet address 10.0.3.1/24",
		"set security ike gateway gw-rg1 address 198.51.100.1",
		"set security ike gateway gw-rg1 external-interface reth1.0",
		"set security ike gateway gw-plain address 198.51.100.3",
		"set security ike gateway gw-plain external-interface ge-0/0/3.0",
		"set security ipsec vpn blue ike gateway gw-rg1",
		"set security ipsec vpn blue pre-shared-key fixture-secret",
		"set security ipsec vpn blue bind-interface st0",
		"set security ipsec vpn blue traffic-selector red local-ip 10.0.1.0/24",
		"set security ipsec vpn blue traffic-selector red remote-ip 10.9.1.0/24",
		"set security ipsec vpn blue-red ike gateway gw-plain",
		"set security ipsec vpn blue-red pre-shared-key fixture-secret",
		"set security ipsec vpn blue-red bind-interface st1",
		"set security ipsec vpn lone ike gateway gw-plain",
		"set security ipsec vpn lone pre-shared-key fixture-secret",
		"set security ipsec vpn lone bind-interface st2",
	})
	cfg := store.ActiveConfig()
	cm := cluster.NewManager(0, 1)
	cm.UpdateConfig(cfg.Chassis.Cluster)
	cm.SetGroupStateForTesting(1, cluster.StatePrimary)
	if _, known := cm.LocalGroupPrimary(0); known {
		t.Fatal("FIXTURE: this cell requires RG0 to be undeclared")
	}
	rec := &waveRecorder16710{}
	ss := cluster.NewSessionSync(":0", "", nil)
	ss.SetPeerIPsecSAsForTesting([]string{"blue-red", "lone"})
	d := &Daemon{
		cluster:     cm,
		store:       store,
		sessionSync: ss,
		ipsecActiveNamesFn: func() ([]string, error) {
			return nil, nil
		},
		ipsecTerminateFn: rec.recordTerminated,
		ipsecInitiateFn:  rec.recordInitiated,
	}
	if got := ipsecConnRedundancyGroups(cfg, ipsecSANameIndex(cfg), "blue-red"); len(got) != 2 {
		t.Fatalf("FIXTURE: blue-red must span two candidate RGs, got %v", got)
	}
	d.reinitiateIPsecSAsForRG(1)
	terminated, initiated := rec.snapshot()
	if len(terminated) != 0 {
		t.Fatalf("#17784: scoped edge terminated %v, want none", terminated)
	}
	if got, want := sortedCopy16710(initiated), []string{"lone"}; !equalNames16710(got, want) {
		t.Fatalf("#17784: RG1 edge initiated=%v want %v (must exclude spanning blue-red)", initiated, want)
	}
}

// The data-RG edge handles that RG's names while excluding declared-RG0 and
// other-RG names.
func TestReinitiateDataRGEdgeScopesToThatRG16710(t *testing.T) {
	store, cm := waveFixture16710(t)
	rec := &waveRecorder16710{}
	d, _ := waveDaemon16710(store, cm, rec)
	for _, rg := range []int{0, 1, 2} {
		cm.SetGroupStateForTesting(rg, cluster.StatePrimary)
	}
	d.reinitiateIPsecSAsForRG(1)
	terminated, initiated := rec.snapshot()
	if len(terminated) != 0 {
		t.Fatalf("#16710: RG1 edge terminated %v, want nothing", terminated)
	}
	if got, want := sortedCopy16710(initiated), []string{"vpn-rg1"}; !equalNames16710(got, want) {
		t.Fatalf("#16710: RG1 edge initiated=%v want %v (declared RG0 stays on RG0 edge)", initiated, want)
	}

	// Decision-level: RG2 remains scoped to its own name, and RG0's declared
	// name remains on that edge despite RG1/RG2 ownership.
	if got := d.ipsecSAsToReinitiateForRG([]string{"vpn-rg1", "vpn-rg2", "vpn-plain"}, 2); len(got) != 1 || got[0] != "vpn-rg2" {
		t.Fatalf("#16710: RG2-scoped filter = %v, want [vpn-rg2]", got)
	}
	if got := d.ipsecSAsToReinitiateForRG([]string{"vpn-rg1", "vpn-rg2", "vpn-plain"}, 0); len(got) != 1 || got[0] != "vpn-plain" {
		t.Fatalf("#16710: RG0-scoped filter = %v, want [vpn-plain]", got)
	}
}

// Re-running the SAME edge (duplicate VRRP event / reconcile) must be
// belt-safe only for that edge's own stale duplicate, and must never
// reach another RG's live SA. Here the RG1 stale duplicate is belted on
// the RG1 edge (the shipped #15194 behaviour, now scoped), while a live
// vpn-rg2 SA survives an RG1 edge untouched.
func TestReinitiateEdgeBeltsOnlyOwnRGStaleDuplicate16710(t *testing.T) {
	store, cm := waveFixture16710(t)
	for _, rg := range []int{0, 1, 2} {
		cm.SetGroupStateForTesting(rg, cluster.StatePrimary)
	}
	rec := &waveRecorder16710{}
	ss := cluster.NewSessionSync(":0", "", nil)
	ss.SetPeerIPsecSAsForTesting([]string{"vpn-rg1", "vpn-rg2", "vpn-plain"})
	d := &Daemon{
		cluster:     cm,
		store:       store,
		sessionSync: ss,
		ipsecActiveNamesFn: func() ([]string, error) {
			// Both a stale vpn-rg1 duplicate (this edge's RG) and a healthy
			// live vpn-rg2 SA (another RG, raised by its own edge) exist.
			return []string{"vpn-rg1", "vpn-rg2"}, nil
		},
		ipsecTerminateFn: rec.recordTerminated,
		ipsecInitiateFn:  rec.recordInitiated,
	}
	d.reinitiateIPsecSAsForRG(1)
	terminated, initiated := rec.snapshot()
	if got, want := sortedCopy16710(terminated), []string{"vpn-rg1"}; !equalNames16710(got, want) {
		t.Fatalf("#16710/#15194: RG1 edge must belt only its own stale duplicate; terminated=%v want %v "+
			"(vpn-rg2 is live and belongs to another RG's edge)", terminated, want)
	}
	if got, want := sortedCopy16710(initiated), []string{"vpn-rg1"}; !equalNames16710(got, want) {
		t.Fatalf("#16710: RG1 edge initiated=%v want %v", initiated, want)
	}
}

// Wiring: the production data-RG edge (applyRethServicesForRG) drives the
// scoped pass — taking RG2 after RG1 must initiate vpn-rg2 exactly once
// and never terminate vpn-rg1. The leg is async, so wait for the RG2
// initiate rather than assuming ordering.
func TestApplyRethServicesWaveTerminatesNothing16710(t *testing.T) {
	store, cm := waveFixture16710(t)
	// Production shape: ipsec-session-synchronization is on in this
	// fixture; the manager must know every RG.
	rec := &waveRecorder16710{}
	d, _ := waveDaemon16710(store, cm, rec)

	cm.SetGroupStateForTesting(0, cluster.StatePrimary)
	cm.SetGroupStateForTesting(1, cluster.StatePrimary)
	d.reinitiateIPsecSAsForRG(1)

	cm.SetGroupStateForTesting(2, cluster.StatePrimary)
	d.applyRethServicesForRG(2)

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		_, initiated := rec.snapshot()
		found := false
		for _, n := range initiated {
			if n == "vpn-rg2" {
				found = true
			}
		}
		if found {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	// Settle briefly so any erroneous extra terminate/initiate lands.
	time.Sleep(300 * time.Millisecond)
	terminated, initiated := rec.snapshot()
	if len(terminated) != 0 {
		t.Fatalf("#16710: production RG2 edge terminated %v, want 0 across the wave", terminated)
	}
	counts := map[string]int{}
	for _, n := range initiated {
		counts[n]++
	}
	if counts["vpn-rg2"] != 1 || counts["vpn-rg1"] != 1 {
		t.Fatalf("#16710: production wave initiated=%v, want vpn-rg1 and vpn-rg2 exactly once each", initiated)
	}
	if counts["vpn-plain"] != 0 {
		t.Fatalf("#16710: RG edges must not initiate RG0/unanchored vpn-plain, got %v", initiated)
	}
}
