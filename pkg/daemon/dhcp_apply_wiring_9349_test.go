package daemon

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dhcpserver"
)

// #9349: the DHCP branch of applyServicesReconcile had NO coverage in either
// mode. Measured with mutation testing during #9141 — both derivation calls
// could be severed and the entire Go suite stayed green:
//
//	desired := cfg.System.DHCPServer     // instead of desiredStandaloneDHCPConfig(cfg)
//	dhcpCfg := &cfg.System.DHCPServer    // instead of d.desiredClusterDHCPConfig(cfg)
//
// Neither is subtle. STANDALONE, Kea is handed RETH LOGICAL names (`reth1.0`),
// which are not kernel devices, so DHCP fails on every RETH-backed segment.
// CLUSTERED, Kea is handed the unfiltered config, so BOTH nodes serve every
// group regardless of redundancy-group mastership — dual-DHCP, the exact failure
// the #1835 F3 / #6520 design exists to prevent.
//
// The functions BELOW the call sites were well covered (#6520/#4647 on the
// filter, #9141 on the resolver, #6535 on the converger). What had no cell was
// the WIRING between the apply and the applier, and a cell for a function is
// blind to its caller not calling it.
//
// FAIL-ON-REVERT: replace either derivation with the raw
// `cfg.System.DHCPServer` and the matching cell below goes RED.

// recordingDHCPApplier9349 captures the config that actually reaches the
// applier. It implements dhcpApplier and does nothing else — a fake that
// re-implemented the derivation would supply the behaviour under test and could
// not observe production failing to.
type recordingDHCPApplier9349 struct {
	mu                     sync.Mutex
	applied                []config.DHCPServerConfig
	clusterApply           []config.DHCPServerConfig
	clusterNil             int
	authorityApply         []dhcpserver.LeaseApplyAuthority
	authorityClusterApply  []dhcpserver.LeaseApplyAuthority
	authorityAsync         []dhcpserver.LeaseApplyAuthority
	authorityAsyncCfg      []*config.DHCPServerConfig
	preSeed4StillMastering []bool
	preSeed6StillMastering []bool
}

func (r *recordingDHCPApplier9349) Apply(cfg *config.DHCPServerConfig) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if cfg != nil {
		r.applied = append(r.applied, *cfg)
	}
	return nil
}
func (r *recordingDHCPApplier9349) ApplyWithLeaseAuthority(cfg *config.DHCPServerConfig, authority dhcpserver.LeaseApplyAuthority) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if cfg != nil {
		r.applied = append(r.applied, *cfg)
	}
	r.authorityApply = append(r.authorityApply, authority)
	return nil
}

func (r *recordingDHCPApplier9349) ApplyClusterCommit(cfg *config.DHCPServerConfig) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if cfg == nil {
		r.clusterNil++
		return nil
	}
	r.clusterApply = append(r.clusterApply, *cfg)
	return nil
}
func (r *recordingDHCPApplier9349) ApplyClusterCommitWithLeaseAuthority(cfg *config.DHCPServerConfig, authority dhcpserver.LeaseApplyAuthority) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if cfg == nil {
		r.clusterNil++
	} else {
		r.clusterApply = append(r.clusterApply, *cfg)
	}
	r.authorityClusterApply = append(r.authorityClusterApply, authority)
	return nil
}

func (r *recordingDHCPApplier9349) ApplyAsync(*config.DHCPServerConfig, string) {}
func (r *recordingDHCPApplier9349) ApplyAsyncWithLeaseAuthority(cfg *config.DHCPServerConfig, _ string, authority dhcpserver.LeaseApplyAuthority) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.authorityAsyncCfg = append(r.authorityAsyncCfg, cfg)
	r.authorityAsync = append(r.authorityAsync, authority)
}
func (r *recordingDHCPApplier9349) ClaimApplyRetry(time.Time) bool { return false }
func (r *recordingDHCPApplier9349) SetLeaseSyncEnabled(bool)       {}
func (r *recordingDHCPApplier9349) Shutdown() error                { return nil }
func (r *recordingDHCPApplier9349) LeaseAuthorityResult(int) (uint64, []dhcpserver.LeaseScopeAuthority, bool) {
	return 0, nil, false
}
func (r *recordingDHCPApplier9349) IsRunning() bool             { return false }
func (r *recordingDHCPApplier9349) ApplyFailedForTesting() bool { return false }
func (r *recordingDHCPApplier9349) GetLeasesWithSource4() ([]dhcpserver.Lease, dhcpserver.LeaseSource) {
	return nil, dhcpserver.LeaseSource{}
}
func (r *recordingDHCPApplier9349) GetLeasesWithSource6() ([]dhcpserver.Lease, dhcpserver.LeaseSource) {
	return nil, dhcpserver.LeaseSource{}
}
func (r *recordingDHCPApplier9349) GetSyncLeases4(context.Context, time.Time) ([]dhcpserver.SyncLease, error) {
	return nil, nil
}
func (r *recordingDHCPApplier9349) GetSyncLeases6(context.Context, time.Time) ([]dhcpserver.SyncLease, error) {
	return nil, nil
}
func (r *recordingDHCPApplier9349) SeedSyncLeases4(context.Context, []dhcpserver.SyncLease, time.Time) (int, error) {
	return 0, nil
}
func (r *recordingDHCPApplier9349) SeedSyncLeases6(context.Context, []dhcpserver.SyncLease, time.Time) (int, error) {
	return 0, nil
}
func (r *recordingDHCPApplier9349) PreSeedMemfileMerged4(_ context.Context, _ []dhcpserver.SyncLease, _ time.Time, stillMastering bool) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.preSeed4StillMastering = append(r.preSeed4StillMastering, stillMastering)
	return nil
}
func (r *recordingDHCPApplier9349) PreSeedMemfileMerged6(_ context.Context, _ []dhcpserver.SyncLease, _ time.Time, stillMastering bool) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.preSeed6StillMastering = append(r.preSeed6StillMastering, stillMastering)
	return nil
}
func (r *recordingDHCPApplier9349) WaitControlSocket4(context.Context, time.Duration) bool {
	return false
}
func (r *recordingDHCPApplier9349) WaitControlSocket6(context.Context, time.Duration) bool {
	return false
}

func rethDHCPConfig9349(t *testing.T, cluster bool) *config.Config {
	t.Helper()
	cfg := &config.Config{}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"reth1":    {Name: "reth1", RedundancyGroup: 1},
		"ge-0/0/1": {Name: "ge-0/0/1", RedundantParent: "reth1"},
	}
	cfg.System.DHCPServer.DHCPLocalServer = &config.DHCPLocalServerConfig{
		Groups: map[string]*config.DHCPServerGroup{
			"g1": {Name: "g1", Interfaces: []string{"reth1.0"}},
		},
	}
	if cluster {
		cfg.Chassis.Cluster = &config.ClusterConfig{}
	}
	return cfg
}

// TestMasterEdgePassesStillMasteringToPreSeed9853 drives the staggered
// active-active transition through the daemon call site. RG1 is already MASTER
// when RG2 takes over, so a Kea-down pre-seed for RG2 must receive the
// stillMastering flag and preserve RG1's fallback union.
//
// Fail-on-revert: removing the per-RG state check or passing false makes this
// assertion RED even though the lower-level merge tests remain green.
func TestMasterEdgePassesStillMasteringToPreSeed9853(t *testing.T) {
	d := leaseSyncTestDaemon(t, "/tmp/9853-k4-missing", "/tmp/9853-k6-missing", true)
	rec := &recordingDHCPApplier9349{}
	d.dhcpServer = rec
	d.getOrCreateRGState(1).SetCluster(true)
	d.getOrCreateRGState(2).SetCluster(true)
	d.sessionSync.SetPeerDHCPLeasesForTesting(4, []dhcpserver.SyncLease{
		{Family: 4, Address: "10.0.72.80", HWAddress: "02:00:00:00:72:80",
			SubnetID: 2, Remaining: 3600, State: 0},
	})
	d.sessionSync.SetPeerDHCPLeasesForTesting(6, []dhcpserver.SyncLease{
		{Family: 6, Address: "2001:db8:72::80", DUID: "00:03:00:01:02:00:00:00:72:80",
			IAID: 80, LeaseType: "IA_NA", SubnetID: 2, Remaining: 3600, State: 0},
	})

	d.applyRethServicesForRG(2)

	if len(rec.preSeed4StillMastering) != 1 || !rec.preSeed4StillMastering[0] {
		t.Fatalf("v4 pre-seed did not receive stillMastering=true: %v", rec.preSeed4StillMastering)
	}
	if len(rec.preSeed6StillMastering) != 1 || !rec.preSeed6StillMastering[0] {
		t.Fatalf("v6 pre-seed did not receive stillMastering=true: %v", rec.preSeed6StillMastering)
	}
	if len(rec.authorityAsync) != 1 || rec.authorityAsync[0].Generation == 0 {
		t.Fatalf("transition did not pass lease authority to ApplyAsyncWithLeaseAuthority: %+v", rec.authorityAsync)
	}
	if len(rec.authorityAsyncCfg) != 1 || rec.authorityAsyncCfg[0] == nil {
		t.Fatalf("transition did not pass the desired config to ApplyAsyncWithLeaseAuthority")
	}
}

// TestFirstMasterEdgePassesPureBackupToPreSeed9853 covers the complementary
// case: when the transitioning RG is the only MASTER, its stopped-Kea
// pre-seed must receive false so peer-only replacement can remove stale LFC
// generations. Fail-on-revert: passing true unconditionally makes this RED.
func TestFirstMasterEdgePassesPureBackupToPreSeed9853(t *testing.T) {
	d := leaseSyncTestDaemon(t, "/tmp/9853-k4-pure-missing", "/tmp/9853-k6-pure-missing", true)
	rec := &recordingDHCPApplier9349{}
	d.dhcpServer = rec
	d.getOrCreateRGState(2).SetCluster(true)
	d.sessionSync.SetPeerDHCPLeasesForTesting(4, []dhcpserver.SyncLease{
		{Family: 4, Address: "10.0.72.81", HWAddress: "02:00:00:00:72:81",
			SubnetID: 2, Remaining: 3600, State: 0},
	})
	d.sessionSync.SetPeerDHCPLeasesForTesting(6, []dhcpserver.SyncLease{
		{Family: 6, Address: "2001:db8:72::81", DUID: "00:03:00:01:02:00:00:00:72:81",
			IAID: 81, LeaseType: "IA_NA", SubnetID: 2, Remaining: 3600, State: 0},
	})

	d.applyRethServicesForRG(2)

	if len(rec.preSeed4StillMastering) != 1 || rec.preSeed4StillMastering[0] {
		t.Fatalf("v4 pure-backup pre-seed did not receive false: %v", rec.preSeed4StillMastering)
	}
	if len(rec.preSeed6StillMastering) != 1 || rec.preSeed6StillMastering[0] {
		t.Fatalf("v6 pure-backup pre-seed did not receive false: %v", rec.preSeed6StillMastering)
	}
}

// STANDALONE: what reaches dhcpserver.Apply must have RETH names RESOLVED.
func TestStandaloneApplyReceivesTheResolvedConfig9349(t *testing.T) {
	cfg := rethDHCPConfig9349(t, false)
	rec := &recordingDHCPApplier9349{}
	d := &Daemon{dhcpServer: rec}

	_, _ = d.applyServicesReconcile(cfg)

	if len(rec.applied) == 0 {
		t.Fatal("dhcpserver.Apply was never called — the standalone DHCP branch did not run, so " +
			"nothing below is measured")
	}
	if len(rec.authorityApply) != 1 || rec.authorityApply[0].Generation == 0 {
		t.Fatalf("standalone apply did not pass lease authority to ApplyWithLeaseAuthority: %+v", rec.authorityApply)
	}
	got := rec.applied[len(rec.applied)-1]
	if got.DHCPLocalServer == nil {
		t.Fatal("Apply received no v4 family")
	}
	g := got.DHCPLocalServer.Groups["g1"]
	if g == nil || len(g.Interfaces) == 0 {
		t.Fatal("Apply received no group interfaces")
	}
	if g.Interfaces[0] == "reth1.0" {
		t.Fatalf("Kea was handed the AUTHORED RETH name %q. That is not a kernel device, so Kea "+
			"cannot bind it and DHCP fails on every RETH-backed segment (#9349)", g.Interfaces[0])
	}
	if g.Interfaces[0] != "ge-0-0-1.0" {
		t.Fatalf("Kea was handed %q, want the resolved member name %q", g.Interfaces[0], "ge-0-0-1.0")
	}

	// The apply must not have mutated the shared active config on the way
	// (#9141's property, re-asserted through the real wiring).
	if authored := cfg.System.DHCPServer.DHCPLocalServer.Groups["g1"].Interfaces[0]; authored != "reth1.0" {
		t.Errorf("the active config was rewritten to %q by the apply", authored)
	}
}

// CLUSTERED: what reaches ApplyClusterCommit must be the master-RG-FILTERED
// config, not the raw one. With no RG mastered, the filter yields nil.
func TestClusterApplyReceivesTheFilteredConfig9349(t *testing.T) {
	cfg := rethDHCPConfig9349(t, true)
	rec := &recordingDHCPApplier9349{}
	d := &Daemon{dhcpServer: rec}

	_, _ = d.applyServicesReconcile(cfg)

	if len(rec.applied) > 0 {
		t.Fatalf("the STANDALONE applier ran in cluster mode (%d calls) — the branch is inverted",
			len(rec.applied))
	}
	if rec.clusterNil == 0 && len(rec.clusterApply) == 0 {
		t.Fatal("ApplyClusterCommit was never called — the cluster DHCP branch did not run")
	}
	if len(rec.authorityClusterApply) != 1 || rec.authorityClusterApply[0].Generation == 0 {
		t.Fatalf("cluster apply did not pass lease authority to ApplyClusterCommitWithLeaseAuthority: %+v", rec.authorityClusterApply)
	}
	for _, got := range rec.clusterApply {
		if got.DHCPLocalServer == nil {
			continue
		}
		g := got.DHCPLocalServer.Groups["g1"]
		if g == nil {
			continue
		}
		if len(g.Interfaces) > 0 && g.Interfaces[0] == "reth1.0" {
			t.Fatalf("Kea was handed the UNFILTERED, unresolved config in cluster mode (%q). Both "+
				"nodes would then serve every group regardless of RG mastership — dual-DHCP, which "+
				"#1835 F3 / #6520 exist to prevent (#9349)", g.Interfaces[0])
		}
	}
}

// The interface must not have silently narrowed what production implements.
func TestProductionManagerSatisfiesTheApplier9349(t *testing.T) {
	var _ dhcpApplier = (*dhcpserver.Manager)(nil)
	var _ dhcpApplier = (*recordingDHCPApplier9349)(nil)
}
