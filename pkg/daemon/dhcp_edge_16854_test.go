package daemon

import (
	"context"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/cluster"
	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dhcpserver"
)

// #16854: on the canonical two-RG topology (reth0 in RG1 with no DHCP,
// reth1 in RG2 with dhcp-local-server), a MASTER edge for the DHCP-less RG1
// on the node already serving RG2 must not run the takeover pre-seed (which
// quiesces the live Kea) nor the post-start peer seed. The Kea apply itself
// still runs; it is config-gated inside the Manager.

// memfileFallbackApplier16854 is a recording applier whose lease reads come
// from the memfile fallback (live=false), modelling a node whose Kea is
// stopped for the scopes it no longer serves.
type memfileFallbackApplier16854 struct {
	*recordingDHCPApplier9349
	leases4 []dhcpserver.SyncLease
}

func (r *memfileFallbackApplier16854) GetSyncLeases4WithSource(context.Context, time.Time) ([]dhcpserver.SyncLease, bool, error) {
	return r.leases4, false, nil
}
func (r *memfileFallbackApplier16854) GetSyncLeases6WithSource(context.Context, time.Time) ([]dhcpserver.SyncLease, bool, error) {
	return nil, false, nil
}

// twoRGCanonicalDaemon16854 builds the canonical topology: reth0 (RG1, no
// DHCP) and reth1 (RG2, dhcp-local-server group on 10.0.61.0/24), with the
// lease-sync knob on.
func twoRGCanonicalDaemon16854(t *testing.T) *Daemon {
	t.Helper()
	store := testStoreWithSetConfig(t, []string{
		"set chassis cluster cluster-id 1",
		"set chassis cluster authentication-key test-cluster-psk-6611",
		"set chassis cluster node 0",
		"set chassis cluster dhcp-lease-synchronization",
		"set chassis cluster redundancy-group 1 node 0 priority 200",
		"set chassis cluster no-private-rg-election",
		"set chassis cluster redundancy-group 2 node 0 priority 200",
		"set interfaces reth0 redundant-ether-options redundancy-group 1",
		"set interfaces reth0 unit 50 family inet address 172.16.50.8/24",
		"set interfaces reth0 vlan-tagging",
		"set interfaces reth0 unit 50 vlan-id 50",
		"set interfaces ge-0/0/0 gigether-options redundant-parent reth0",
		"set interfaces reth1 redundant-ether-options redundancy-group 2",
		"set interfaces reth1 unit 0 family inet address 10.0.61.1/24",
		"set interfaces ge-0/0/1 gigether-options redundant-parent reth1",
		"set system services dhcp-local-server group lan-pool interface reth1.0",
		"set system services dhcp-local-server group lan-pool pool lan-range subnet 10.0.61.0/24",
		"set system services dhcp-local-server group lan-pool pool lan-range address-range low 10.0.61.100 high 10.0.61.199",
	})
	d := &Daemon{
		rgStates:      make(map[int]*rgStateMachine),
		cluster:       cluster.NewManager(0, 1),
		store:         store,
		sessionSync:   cluster.NewSessionSync("127.0.0.1:0", "127.0.0.1:0", nil),
		dhcpLeaseSync: dhcpLeaseSyncState{nowCh: make(chan struct{}, 1)},
	}
	return d
}

func TestDHCPLessRGEdgeRunsNoTakeoverWork16854(t *testing.T) {
	d := twoRGCanonicalDaemon16854(t)
	rec := &recordingDHCPApplier9349{}
	d.dhcpServer = rec
	// This node serves RG2 (DHCP); RG1 (no DHCP) now activates on it.
	d.getOrCreateRGState(2).SetCluster(true)
	d.getOrCreateRGState(1).SetCluster(true)
	d.sessionSync.SetPeerDHCPLeaseSnapshotForTesting(4, dhcpserver.LeaseSyncSnapshot{
		Received: true, Generation: 7,
		Leases: []dhcpserver.SyncLease{{Family: 4, Address: "10.0.61.77", HWAddress: "bb:77"}},
		Scopes: []dhcpserver.LeaseScopeAuthority{
			{Family: 4, CIDR: "10.0.61.0/24", RGID: 2, Generation: 7, Served: false, Applied: false},
		},
	})

	d.applyRethServicesForRG(1)

	if len(rec.preSeed4StillMastering) != 0 || len(rec.preSeed6StillMastering) != 0 {
		t.Fatalf("DHCP-less RG1 edge ran the takeover pre-seed (quiesces live Kea): v4=%v v6=%v",
			rec.preSeed4StillMastering, rec.preSeed6StillMastering)
	}
	// The apply still runs so a failed earlier apply is re-driven; the
	// Manager skips the restart when the loaded config is unchanged.
	if len(rec.authorityAsync) != 1 {
		t.Fatalf("DHCP-less RG1 edge must still enqueue the config-gated apply, got %d", len(rec.authorityAsync))
	}
}

// Control: a MASTER edge for RG2 (the DHCP RG) on a node not yet serving it
// DOES run the takeover pre-seed and seed.
func TestDHCPRGEdgeRunsTakeoverWork16854(t *testing.T) {
	d := twoRGCanonicalDaemon16854(t)
	rec := &recordingDHCPApplier9349{}
	d.dhcpServer = rec
	d.getOrCreateRGState(2).SetCluster(true)
	d.sessionSync.SetPeerDHCPLeaseSnapshotForTesting(4, dhcpserver.LeaseSyncSnapshot{
		Received: true, Generation: 7,
		Leases: []dhcpserver.SyncLease{{Family: 4, Address: "10.0.61.77", HWAddress: "bb:77"}},
		Scopes: []dhcpserver.LeaseScopeAuthority{
			{Family: 4, CIDR: "10.0.61.0/24", RGID: 2, Generation: 7, Served: true, Applied: true},
		},
	})

	d.applyRethServicesForRG(2)

	if len(rec.preSeed4StillMastering) != 1 {
		t.Fatalf("RG2 (DHCP) edge must run the takeover pre-seed, got %v", rec.preSeed4StillMastering)
	}
}

func TestDHCPTakeoverWorkNeededByRG16854(t *testing.T) {
	d := twoRGCanonicalDaemon16854(t)
	cfg := d.store.ActiveConfig()
	if cfg == nil {
		t.Fatal("no active config")
	}
	both := map[int]bool{1: true, 2: true}
	if dhcpTakeoverWorkNeeded(cfg, 1, both) {
		t.Fatal("RG1 owns no DHCP group: its edge on the RG2-serving node needs no takeover work")
	}
	if !dhcpTakeoverWorkNeeded(cfg, 2, both) {
		t.Fatal("RG2 owns the DHCP group: its edge needs takeover work")
	}
	// First takeover (nothing else mastered): RG2 still needs the work.
	if !dhcpTakeoverWorkNeeded(cfg, 2, map[int]bool{2: true}) {
		t.Fatal("first RG2 takeover needs takeover work")
	}
}

func TestPushableLeasesSuppressesMemfileFallback16854(t *testing.T) {
	rows := []dhcpserver.SyncLease{{Family: 4, Address: "10.0.61.77", HWAddress: "bb:77"}}
	if got := pushableLeases(rows, false); len(got) != 0 {
		t.Fatalf("memfile-fallback rows must not be pushed, got %+v", got)
	}
	if got := pushableLeases(rows, true); len(got) != 1 {
		t.Fatalf("live rows must be pushed, got %+v", got)
	}
}

// A node mastering only the DHCP-less RG1, reading from its stopped Kea's
// memfile, pushes an empty set carrying a Served:false scope (negative proof
// for the receiver), never the stale rows.
func TestMemfileFallbackSnapshotIsEmptyWithServedFalse16854(t *testing.T) {
	d := twoRGCanonicalDaemon16854(t)
	stale := []dhcpserver.SyncLease{{Family: 4, Address: "10.0.61.77", HWAddress: "bb:77"}}
	d.dhcpServer = &memfileFallbackApplier16854{
		recordingDHCPApplier9349: &recordingDHCPApplier9349{},
		leases4:                  stale,
	}
	d.getOrCreateRGState(1).SetCluster(true)
	d.getOrCreateRGState(2).SetCluster(false)

	cfg := d.store.ActiveConfig()
	leases, live, err := d.dhcpServer.GetSyncLeases4WithSource(context.Background(), time.Now())
	if err != nil || live {
		t.Fatalf("fallback read = live=%v err=%v", live, err)
	}
	snap := d.makeDHCPLeaseSnapshot(cfg, 4, pushableLeases(leases, live), live)
	if len(snap.Leases) != 0 {
		t.Fatalf("node mastering only RG1 pushed stale memfile rows: %+v", snap.Leases)
	}
	found := false
	for _, scope := range snap.Scopes {
		if scope.CIDR == "10.0.61.0/24" {
			found = true
			if scope.Served || scope.Applied {
				t.Fatalf("fallback snapshot advertised serving proof: %+v", scope)
			}
		}
	}
	if !found {
		t.Fatalf("fallback snapshot carried no RG2 scope for negative proof: %+v", snap.Scopes)
	}
	// The config type is referenced so an unused import cannot hide a
	// topology drift in the helper above.
	var _ *config.Config = cfg
}

// #17886: an attributable served group must not hide a second group whose
// pool-to-RG attribution is mixed. The mixed group is filtered to a non-empty
// member set when RG2 is mastered, but is omitted from the proof's scope sets.
func TestDHCPTakeoverWorkNeededWithMixedGroup17886(t *testing.T) {
	d := twoRGCanonicalDaemon16854(t)
	cfg := d.store.ActiveConfig()
	if cfg == nil {
		t.Fatal("no active config")
	}
	// Add an RG3 member so the mixed group spans RG2 and RG3.
	cfg.Interfaces.Interfaces["reth2"] = &config.InterfaceConfig{
		Name: "reth2", RedundancyGroup: 3,
	}
	cfg.Interfaces.Interfaces["ge-0/0/2"] = &config.InterfaceConfig{
		Name: "ge-0/0/2", RedundantParent: "reth2",
	}
	groups := cfg.System.DHCPServer.DHCPLocalServer.Groups
	mixed := groups["lan-pool"]
	mixed.Interfaces = []string{"reth1.0", "reth2.0"}
	rg1 := *mixed
	rg1.Interfaces = []string{"reth0.50"}
	rg1Pool := *mixed.Pools[0]
	rg1Pool.Subnet = "10.0.60.0/24"
	rg1Pool.RangeLow = "10.0.60.100"
	rg1Pool.RangeHigh = "10.0.60.199"
	rg1.Pools = []*config.DHCPPool{&rg1Pool}
	cfg.System.DHCPServer.DHCPLocalServer.Groups = map[string]*config.DHCPServerGroup{
		"rg1-pool":      &rg1,
		"mixed-rg2-rg3": mixed,
	}
	masters := map[int]bool{1: true, 2: true, 3: false}
	if !dhcpTakeoverWorkNeeded(cfg, 2, masters) {
		t.Fatal("RG2 takeover must retain legacy work when a mixed group cannot be attributed")
	}
}
