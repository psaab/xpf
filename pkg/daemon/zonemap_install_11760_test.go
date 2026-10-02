package daemon

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/psaab/xpf/pkg/cluster"
	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
	"github.com/psaab/xpf/pkg/networkd"
	"github.com/psaab/xpf/pkg/vrrp"
	"golang.org/x/sync/semaphore"
)

func TestRestartWithIdenticalConfigInstallsZoneOwnership11760(t *testing.T) {
	store := testStoreWithSetConfig(t, []string{
		"set chassis cluster cluster-id 1",
		"set chassis cluster node 0",
		"set chassis cluster authentication-key test-11760-zone-map",
		"set chassis cluster redundancy-group 0 node 0 priority 200",
		"set chassis cluster redundancy-group 1 node 0 priority 200",
		"set interfaces reth0 redundant-ether-options redundancy-group 1",
		"set interfaces reth0 unit 0 family inet address 192.0.2.1/24",
		"set security zones security-zone trust interfaces reth0.0",
	})

	installFakeNetworkctl(t)
	cfg := store.ActiveConfig()
	dp := &runtimeOnlyApplyTestDP{
		applyResult: &dataplane.ApplyResult{ZoneIDs: buildZoneIDs(cfg)},
	}
	d := &Daemon{
		applySem: semaphore.NewWeighted(1),
		networkd: networkd.NewInDir(t.TempDir()),
		store:    store,
		vrrpMgr:  vrrp.NewManager(),
		opts:     Options{NoDataplane: true},
	}
	d.setDataplane(dp)

	// Boot apply finishes before cluster communications creates sessionSync.
	d.applyActiveConfig()
	if dp.applyCalls != 1 || !store.ActiveApplied() {
		t.Fatalf("boot apply calls=%d activeApplied=%v, want one successful apply", dp.applyCalls, store.ActiveApplied())
	}
	if d.getSessionSync() != nil {
		t.Fatal("fixture: boot apply unexpectedly had a session-sync object")
	}

	_, commsGen, _ := d.beginClusterCommsEpoch(context.Background())
	ss := cluster.NewSessionSync(":0", "10.0.0.2:4785", nil)
	ss.IsPrimaryFn = func() bool { return false }
	ss.IsPrimaryForRGFn = func(rgID int) bool { return rgID == 1 }
	if !d.publishSessionSyncIfCurrent(commsGen, ss) {
		t.Fatal("fixture: current session-sync publish was dropped")
	}

	// The peer sends the same active config during its sync handshake. This
	// must take the identical-config fast path without relying on another apply.
	active := store.ShowActive()
	historyLen := len(store.ListHistory())
	if err := d.handleConfigSync(active + "\n"); err != nil {
		t.Fatalf("identical config sync: %v", err)
	}
	if got := len(store.ListHistory()); got != historyLen {
		t.Fatalf("identical config sync changed history: got %d, want %d", got, historyLen)
	}

	if !ss.ShouldSyncZone(config.StableZoneID("trust")) {
		t.Fatal("restart-with-identical-config left the published session sync without trust-zone RG ownership")
	}
	if ss.ShouldSyncZone(config.StableZoneID("unmapped")) {
		t.Fatal("unmapped zones must retain the RG0-secondary fallback")
	}
}

func TestLocalSessionSyncOwnershipSeedRequiresAppliedConfig11760(t *testing.T) {
	lines := []string{
		"set chassis cluster cluster-id 1",
		"set chassis cluster node 0",
		"set chassis cluster authentication-key test-11760-zone-map",
		"set chassis cluster redundancy-group 0 node 0 priority 200",
		"set chassis cluster redundancy-group 1 node 0 priority 200",
		"set interfaces reth0 redundant-ether-options redundancy-group 1",
		"set interfaces reth0 unit 0 family inet address 192.0.2.1/24",
		"set security zones security-zone trust interfaces reth0.0",
	}

	t.Run("unapplied active config remains unwired", func(t *testing.T) {
		store := testStoreWithSetConfig(t, lines)
		ss := cluster.NewSessionSync(":0", "10.0.0.2:4785", nil)
		d := &Daemon{store: store}
		d.seedActiveSessionSyncZoneOwnership(ss)
		if ss.ZoneOwnershipInstalled() {
			t.Fatal("unapplied active config must retain the nil ownership sentinel")
		}
	})

	t.Run("applied active config is installed before publication", func(t *testing.T) {
		store := testStoreWithSetConfig(t, lines)
		store.MarkActiveApplied()
		ss := cluster.NewSessionSync(":0", "10.0.0.2:4785", nil)
		ss.IsPrimaryFn = func() bool { return false }
		ss.IsPrimaryForRGFn = func(rgID int) bool { return rgID == 1 }
		d := &Daemon{store: store}

		d.seedActiveSessionSyncZoneOwnership(ss)
		if !ss.ZoneOwnershipInstalled() {
			t.Fatal("applied active config did not seed constructor-local session sync")
		}
		if !ss.ShouldSyncZone(config.StableZoneID("trust")) {
			t.Fatal("pre-publish ownership seed omitted the active config's trust-zone RG")
		}
		if ss.ShouldSyncZone(config.StableZoneID("unmapped")) {
			t.Fatal("pre-publish ownership seed changed the unmapped-zone fallback")
		}
		if d.getSessionSync() != nil {
			t.Fatal("ownership was not seeded while the session sync was still local")
		}

		_, commsGen, _ := d.beginClusterCommsEpoch(context.Background())
		if !d.publishSessionSyncIfCurrent(commsGen, ss) || d.getSessionSync() != ss {
			t.Fatal("seeded session sync was not published")
		}
	})
}

func TestEquivalentConfigSkipInstallsZoneOwnership11760(t *testing.T) {
	store := newConfigStore(t, filepath.Join(t.TempDir(), "config.db"))
	ss := cluster.NewSessionSync(":0", "10.0.0.2:4785", nil)
	applyCalls := 0
	d := &Daemon{
		applySem:    semaphore.NewWeighted(1),
		sessionSync: ss,
		store:       store,
		applyBodyForTest: func(*config.Config) {
			applyCalls++
		},
	}

	if err := d.handleConfigSync(legacyAPIAuthConfig10825); err != nil {
		t.Fatalf("initial config sync: %v", err)
	}
	if applyCalls != 1 || ss.ZoneOwnershipInstalled() {
		t.Fatalf("initial sync calls=%d ownershipInstalled=%v, want one apply and unwired map", applyCalls, ss.ZoneOwnershipInstalled())
	}
	if err := d.handleConfigSync(legacyAPIAuthConfig10825); err != nil {
		t.Fatalf("equivalent config sync: %v", err)
	}
	if applyCalls != 1 {
		t.Fatalf("equivalent config sync apply calls = %d, want unchanged at 1", applyCalls)
	}
	if !ss.ZoneOwnershipInstalled() {
		t.Fatal("credential-equivalent config skip did not install an authoritative zone map")
	}
}
