package daemon

import (
	"context"
	"errors"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"golang.org/x/sync/semaphore"

	"github.com/psaab/xpf/pkg/cluster"
	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
)

type markerSyncRuntime12210 struct{}

func (markerSyncRuntime12210) Sessions() dataplane.SessionStore {
	return markerSyncSessionStore12210{}
}

func (markerSyncRuntime12210) Telemetry() dataplane.Telemetry {
	return dataplane.TelemetryOf(nil)
}

type markerSyncSessionStore12210 struct {
	dataplane.SessionStore
}

func (markerSyncSessionStore12210) ForEachV4(func(dataplane.SessionKey, dataplane.SessionValue) bool) error {
	return nil
}

func (markerSyncSessionStore12210) ForEachV6(func(dataplane.SessionKeyV6, dataplane.SessionValueV6) bool) error {
	return nil
}

func (markerSyncSessionStore12210) ReconcileClusterBulk(dataplane.ClusterBulkReconcileInput) (dataplane.ClusterBulkReconcileResult, error) {
	return dataplane.ClusterBulkReconcileResult{}, nil
}

func TestBootRetryReconstructsZoneSnapshotAndReceivesBulkAck12210(t *testing.T) {
	store := testStoreWithSetConfig(t, []string{
		"set chassis cluster cluster-id 1",
		"set chassis cluster node 0",
		"set chassis cluster authentication-key test-12210-zone-map",
		"set chassis cluster control-interface em0",
		"set chassis cluster peer-address 10.99.0.2",
		"set interfaces em0 unit 0 family inet address 10.99.0.1/24",
		"set chassis cluster redundancy-group 0 node 0 priority 200",
		"set chassis cluster redundancy-group 1 node 0 priority 200",
		"set interfaces reth0 redundant-ether-options redundancy-group 1",
		"set interfaces reth0 unit 0 family inet address 192.0.2.1/24",
		"set security zones security-zone trust interfaces reth0.0",
	})
	if store.ActiveApplied() {
		t.Fatal("fixture: active config must be unapplied before the failed boot apply")
	}

	transient := errors.New("boot apply: simulated dataplane publish failure")
	applies := 0
	d := &Daemon{
		applySem: semaphore.NewWeighted(1),
		store:    store,
		buildRuntimeDataPlaneForTest: func(string) (dataplane.RuntimeDataPlane, error) {
			return &runtimeOnlyApplyTestDP{}, nil
		},
		applyBodyForTest: func(*config.Config) { applies++ },
		applyErrForTest:  transient,
	}
	if err := d.setupDataplaneAndInitialConfig(); err != nil {
		t.Fatalf("setupDataplaneAndInitialConfig: %v", err)
	}
	if applies != 1 {
		t.Fatalf("failed boot applied active config %d times, want exactly once", applies)
	}
	if !d.configApplyOwed() || store.ActiveApplied() {
		t.Fatalf("failed boot state: debt owed=%v active applied=%v, want true/false", d.configApplyOwed(), store.ActiveApplied())
	}

	// The retry owns applySem before it captures and applies the active config.
	d.applyErrForTest = nil
	d.reassertConfigApplyOnce(context.Background())
	if applies != 2 {
		t.Fatalf("converging retry applied active config %d times total, want 2", applies)
	}
	if d.configApplyOwed() {
		t.Fatal("successful retry left config-apply debt owed")
	}
	markerApplied := store.ActiveApplied()

	// Fixture-sanity only: reconstruct a fresh session-sync object and seed it
	// manually. This does not exercise the production constructor's seed order.
	addrA, addrB := syncPairAddresses12210(t)
	local := cluster.NewSessionSync(addrA, addrB, markerSyncRuntime12210{})
	peer := cluster.NewSessionSync(addrB, addrA, markerSyncRuntime12210{})
	local.IsPrimaryFn = func() bool { return true }
	local.IsPrimaryForRGFn = func(int) bool { return true }
	peer.IsPrimaryFn = func() bool { return false }
	peer.IsPrimaryForRGFn = func(int) bool { return false }
	d.seedActiveSessionSyncZoneOwnership(local)
	zoneInstalled := local.ZoneOwnershipInstalled()
	commsCtx, commsGen, commsCancel := d.beginClusterCommsEpoch(context.Background())
	t.Cleanup(commsCancel)
	if !d.publishSessionSyncIfCurrent(commsGen, local) {
		t.Fatal("fixture: current communications epoch dropped the reconstructed sync object")
	}

	cfg := store.ActiveConfig()
	peer.SetZoneOwnership(buildZoneRGMap(cfg, buildZoneIDs(cfg)), buildZoneFoldRGMap(cfg), buildIngressFoldFn(cfg))
	if !peer.ZoneOwnershipInstalled() {
		t.Fatal("fixture: peer session sync must have its zone snapshot before bulk transfer")
	}

	peerAcked := make(chan struct{}, 1)
	peer.OnBulkSyncAckReceived = func() { peerAcked <- struct{}{} }
	local.OnBulkSyncAckReceived = d.onSessionSyncBulkAckReceived
	if err := local.Start(commsCtx); err != nil {
		t.Fatalf("start reconstructed session sync: %v", err)
	}
	t.Cleanup(local.Stop)
	peerCtx, peerCancel := context.WithCancel(context.Background())
	t.Cleanup(peerCancel)
	if err := peer.Start(peerCtx); err != nil {
		t.Fatalf("start peer session sync: %v", err)
	}
	t.Cleanup(peer.Stop)

	ackReceived := false
	select {
	case <-peerAcked:
		ackReceived = true
	case <-time.After(5 * time.Second):
	}

	if !markerApplied {
		t.Error("#12210: successful retry left the active config's applied marker unset")
	}
	if !zoneInstalled || !local.ShouldSyncZone(uint16(config.StableZoneID("trust"))) {
		t.Error("#12210: reconstructed session sync did not install the applied config's trust-zone ownership snapshot")
	}
	if !ackReceived {
		t.Error("#12210: peer did not receive a matching BulkAck for its authoritative bulk; the reconstructed node must reconcile from its seeded zone snapshot")
	}
	if epoch, _, pending := peer.PendingBulkAck(); pending {
		t.Errorf("#12210: peer still awaits BulkAck for epoch %d after the receiver's ACK callback", epoch)
	}
	// Fixture-sanity (non-discriminating): async OnBulkSyncAckReceived eventually
	// primes local peer sync, but this poll has no causal link to peerAcked and
	// passes on the base. Keep it separate from the marker/zone/BulkAck regression.
	primedDeadline := time.Now().Add(10 * time.Second)
	for !d.syncPeerBulkPrimed.Load() && time.Now().Before(primedDeadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if !d.syncPeerBulkPrimed.Load() {
		t.Error("#12210: timed out waiting for syncPeerBulkPrimed via async go s.OnBulkSyncAckReceived() dispatch (pkg/cluster/sync_conn_read.go); local sync did not observe the peer's matching BulkAck")
	}
	if local.Stats().BulkSyncEndTime == 0 {
		t.Error("#12210: reconstructed node did not complete peer-bulk reconciliation")
	}
}

func syncPairAddresses12210(t *testing.T) (string, string) {
	t.Helper()
	lnA, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve session-sync address A: %v", err)
	}
	addrA := lnA.Addr().String()
	lnB, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		_ = lnA.Close()
		t.Fatalf("reserve session-sync address B: %v", err)
	}
	addrB := lnB.Addr().String()
	if err := lnA.Close(); err != nil {
		t.Fatalf("release session-sync address A: %v", err)
	}
	if err := lnB.Close(); err != nil {
		t.Fatalf("release session-sync address B: %v", err)
	}
	return addrA, addrB
}

// TestStartClusterCommsSeedsOwnershipBeforePublishing12210 pins the production
// constructor ordering that the fixture-sanity integration test recreates.
func TestStartClusterCommsSeedsOwnershipBeforePublishing12210(t *testing.T) {
	src, err := os.ReadFile("daemon_ha_sync.go")
	if err != nil {
		t.Fatalf("read daemon_ha_sync.go: %v", err)
	}
	const fn = "func (d *Daemon) startClusterComms("
	start := strings.Index(string(src), fn)
	if start < 0 {
		t.Fatal("startClusterComms not found")
	}
	rest := string(src)[start+len(fn):]
	if end := strings.Index(rest, "\nfunc "); end >= 0 {
		rest = rest[:end]
	}
	// Comments are stripped before matching, mirroring
	// TestStartClusterCommsConsumesTheDropSignal_7071: a source-scanning
	// guard that reads its own explanatory prose is satisfied by the
	// sentence describing the thing it is meant to find.
	var code []string
	for _, line := range strings.Split(rest, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "//") {
			continue
		}
		code = append(code, line)
	}
	body := strings.Join(code, "\n")
	seed := strings.Index(body, "d.seedActiveSessionSyncZoneOwnership(ss)")
	publish := strings.Index(body, "d.publishSessionSyncIfCurrent(commsGen, ss)")
	// Non-vacuity: both calls must be present at all. Without this the
	// ordering assertion below would pass for free on a body that never
	// seeds or never publishes.
	if seed < 0 || publish < 0 {
		t.Fatalf("startClusterComms no longer seeds and publishes at all, so the seed-before-publish ordering is vacuous; seed=%d publish=%d", seed, publish)
	}
	if seed >= publish {
		t.Fatalf("startClusterComms must seed active zone ownership before publishing the session-sync object; seed=%d publish=%d", seed, publish)
	}
}
