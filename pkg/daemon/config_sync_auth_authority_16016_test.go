package daemon

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/cluster"
	"golang.org/x/sync/semaphore"

	"github.com/psaab/xpf/pkg/config"
)

func isolateAuthorityAnchors16016(t *testing.T) string {
	t.Helper()
	gracePath := filepath.Join(t.TempDir(), "unkeyed-authority-grace")
	restoreGrace := cluster.SetUnkeyedAuthorityGraceStatePathForTesting(gracePath)
	t.Cleanup(restoreGrace)
	restoreFabric := cluster.SetFabricAuthGraceStatePathForTesting(
		filepath.Join(t.TempDir(), "fabric-auth-grace"))
	t.Cleanup(restoreFabric)
	restoreEpoch := cluster.SetPeerEpochStatePathForTesting(
		filepath.Join(t.TempDir(), "peer-epoch"))
	t.Cleanup(restoreEpoch)
	return gracePath
}

func TestUnauthenticatedConfigSyncRejectedOnceLocallyKeyed16016(t *testing.T) {
	isolateAuthorityAnchors16016(t)
	store := newConfigStore(t, filepath.Join(t.TempDir(), "config.db"))
	initial := `chassis { cluster { cluster-id 1; authentication-key local-key-16016; control-interface em0; } }`
	if _, err := store.SyncApply(initial, nil); err != nil {
		t.Fatalf("seed local keyed config: %v", err)
	}
	manager := newClusterManager(false)
	manager.UpdateConfig(&config.ClusterConfig{
		ControlLinkAuthKey: config.NewSecret("local-key-16016"),
	})
	var applies int
	d := &Daemon{
		applySem: semaphore.NewWeighted(1),
		cluster:  manager,
		store:    store,
	}
	d.applyBodyForTest = func(*config.Config) { applies++ }

	incoming := renderSyncedConfigText(t,
		"chassis cluster cluster-id 1",
		"chassis cluster authentication-key forged-key-16016",
		"chassis cluster control-interface em0",
		"system host-name forged-16016",
	)
	err := d.handleConfigSyncWithProvenance(incoming, nil, false)
	if err == nil || !strings.Contains(err.Error(), "unauthenticated") {
		t.Fatalf("unauthenticated config on a locally keyed node was not rejected: %v", err)
	}
	if applies != 0 {
		t.Fatalf("unauthenticated config reached the daemon apply path %d times", applies)
	}
	active := store.ActiveConfig()
	if active == nil || active.Chassis.Cluster == nil ||
		active.Chassis.Cluster.ControlLinkAuthKey.Reveal() != "local-key-16016" {
		t.Fatal("unauthenticated config changed or stripped the local control-link PSK")
	}
}

func TestUnauthenticatedConfigCanProvisionFirstPeerKey16016(t *testing.T) {
	isolateAuthorityAnchors16016(t)
	store := newConfigStore(t, filepath.Join(t.TempDir(), "config.db"))
	initial := `chassis { cluster { cluster-id 1; control-interface control0; } }`
	if _, err := store.SyncApply(initial, nil); err != nil {
		t.Fatalf("seed unkeyed config: %v", err)
	}
	manager := newClusterManager(false)
	d := &Daemon{
		applySem: semaphore.NewWeighted(1),
		cluster:  manager,
		store:    store,
	}
	d.applyBodyForTest = func(*config.Config) {}

	incoming := renderSyncedConfigText(t,
		"chassis cluster cluster-id 1",
		"chassis cluster authentication-key peer-key-16016-strong",
		"chassis cluster control-interface control0",
		"system host-name key-push-16016",
	)
	if err := d.handleConfigSyncWithProvenance(incoming, nil, false); err != nil {
		t.Fatalf("unkeyed peer could not provision the first PSK: %v", err)
	}
	active := store.ActiveConfig()
	if active == nil || active.Chassis.Cluster == nil ||
		active.Chassis.Cluster.ControlLinkAuthKey.Reveal() != "peer-key-16016-strong" {
		t.Fatal("unkeyed peer's first-keying config was not installed")
	}
}

func TestUnauthenticatedConfigSyncRejectedAfterUnkeyedGrace16016(t *testing.T) {
	anchorPath := isolateAuthorityAnchors16016(t)
	expiredAt := time.Now().UTC().Add(-73 * time.Hour)
	record := fmt.Sprintf("v2 %d %d %d\n", expiredAt.UnixNano(), expiredAt.UnixNano(), int64(72*time.Hour))
	if err := os.WriteFile(anchorPath, []byte(record), 0o600); err != nil {
		t.Fatal(err)
	}

	store := newConfigStore(t, filepath.Join(t.TempDir(), "config.db"))
	initial := `chassis { cluster { cluster-id 1; control-interface control0; } }`
	if _, err := store.SyncApply(initial, nil); err != nil {
		t.Fatalf("seed unkeyed config: %v", err)
	}
	manager := newClusterManager(false)
	if !manager.UnkeyedAuthorityExpired() {
		t.Fatal("expired persisted anchor was not restored during manager config")
	}
	var applies int
	d := &Daemon{
		applySem: semaphore.NewWeighted(1),
		cluster:  manager,
		store:    store,
	}
	d.applyBodyForTest = func(*config.Config) { applies++ }

	incoming := renderSyncedConfigText(t,
		"chassis cluster cluster-id 1",
		"chassis cluster authentication-key forged-key-16016",
		"chassis cluster control-interface control0",
		"system host-name forged-after-grace-16016",
	)
	err := d.handleConfigSyncWithProvenance(incoming, nil, false)
	if err == nil || !strings.Contains(err.Error(), "grace expired") {
		t.Fatalf("expired unkeyed config sync was not refused: %v", err)
	}
	if applies != 0 {
		t.Fatalf("expired unauthenticated config reached apply path %d times", applies)
	}
	active := store.ActiveConfig()
	if active == nil || active.Chassis.Cluster == nil ||
		active.Chassis.Cluster.ControlLinkAuthKey.Reveal() != "" ||
		active.System.HostName != "" {
		t.Fatal("expired unauthenticated config changed the local configuration")
	}
}
func TestPeerSyncFirstKeyApplyPreservesGraceAnchor16016(t *testing.T) {
	anchorPath := isolateAuthorityAnchors16016(t)
	manager := newClusterManager(false)
	manager.UpdateConfig(&config.ClusterConfig{ControlInterface: "em0"})
	expiry := manager.UnkeyedGraceExpiry()
	if expiry.IsZero() {
		t.Fatal("initial local unkeyed config did not stamp a grace anchor")
	}

	fixture := newCredentialTailFixture6790(t)
	fixture.d.cluster = manager
	fixture.cfg.Chassis.Cluster = &config.ClusterConfig{
		ControlInterface:   "em0",
		ControlLinkAuthKey: config.NewSecret("peer-first-key-16016"),
	}
	ctx := withPeerSyncClusterConfigApply(context.Background())
	if err := fixture.d.applyTailReconcilesWithContext(ctx, fixture.cfg, applyPhaseErrors{}); err != nil {
		t.Fatalf("peer-sync apply tail: %v", err)
	}
	if !manager.ControlLinkAuthConfigured() {
		t.Fatal("peer first-key config was not installed")
	}
	if got := manager.UnkeyedGraceExpiry(); !got.Equal(expiry) {
		t.Fatalf("peer provenance changed grace expiry to %s, want original %s", got, expiry)
	}
	if _, err := os.Stat(anchorPath); err != nil {
		t.Fatalf("peer provenance deleted the original grace anchor: %v", err)
	}
}

func TestDaemonProvenanceFirstKeyThenAuthenticatedClearKeepsOriginalGrace16016(t *testing.T) {
	anchorPath := isolateAuthorityAnchors16016(t)
	store := newConfigStore(t, filepath.Join(t.TempDir(), "config.db"))
	initial := `chassis { cluster { cluster-id 1; control-interface control0; } }`
	if _, err := store.SyncApply(initial, nil); err != nil {
		t.Fatalf("seed unkeyed config: %v", err)
	}
	manager := newClusterManager(false)
	expiry := manager.UnkeyedGraceExpiry()
	if expiry.IsZero() {
		t.Fatal("unkeyed manager did not persist its initial grace cutoff")
	}
	d := &Daemon{
		applySem: semaphore.NewWeighted(1),
		cluster:  manager,
		store:    store,
	}
	d.applyBodyForTest = func(cfg *config.Config) {
		if cfg == nil || cfg.Chassis.Cluster == nil {
			t.Fatal("daemon sync apply omitted compiled cluster config")
		}
		manager.UpdateConfigFromPeer(cfg.Chassis.Cluster)
	}

	firstKey := renderSyncedConfigText(t,
		"chassis cluster cluster-id 1",
		"chassis cluster authentication-key first-peer-key-16016",
		"chassis cluster control-interface control0",
		"system host-name first-peer-key-16016",
	)
	if err := d.handleConfigSyncWithProvenance(firstKey, nil, false); err != nil {
		t.Fatalf("unkeyed frame could not provision the first peer key: %v", err)
	}
	if !manager.ControlLinkAuthConfigured() {
		t.Fatal("first-key config was not applied through the daemon callback")
	}
	if got := manager.UnkeyedGraceExpiry(); !got.Equal(expiry) {
		t.Fatalf("first-key peer sync moved original cutoff from %s to %s", expiry, got)
	}

	authenticatedClear := `chassis { cluster { cluster-id 1; control-interface control0; } } system { host-name authenticated-key-clear-16016; }`
	if err := d.handleConfigSyncWithProvenance(authenticatedClear, nil, true); err != nil {
		t.Fatalf("authenticated peer could not clear its key: %v", err)
	}
	if manager.ControlLinkAuthConfigured() {
		t.Fatal("authenticated key-clear did not update daemon cluster state")
	}
	if got := manager.UnkeyedGraceExpiry(); !got.Equal(expiry) || manager.UnkeyedAuthorityExpired() {
		t.Fatalf("authenticated key-clear changed the original grace window: expiry=%s want=%s expired=%t",
			got, expiry, manager.UnkeyedAuthorityExpired())
	}
	if _, err := os.Stat(anchorPath); err != nil {
		t.Fatalf("authenticated peer key-clear lost the original anchor: %v", err)
	}
}

func TestFabricOnlyCompiledConfigBootPinsGraceBeforeComms16016(t *testing.T) {
	anchorPath := isolateAuthorityAnchors16016(t)
	store := newConfigStore(t, filepath.Join(t.TempDir(), "config.db"))
	initial := `chassis { cluster { cluster-id 1; node 0; fabric-interface fab0; fabric-peer-address 192.0.2.2; } }`
	if _, err := store.SyncApply(initial, nil); err != nil {
		t.Fatalf("seed fabric-only compiled config: %v", err)
	}
	active := store.ActiveConfig()
	if active == nil || active.Chassis.Cluster == nil {
		t.Fatal("config store did not compile the fabric-only cluster stanza")
	}
	cc := active.Chassis.Cluster
	if cc.ControlInterface != "" || cc.FabricInterface != "fab0" || cc.FabricPeerAddress != "192.0.2.2" {
		t.Fatalf("compiled config is not fabric-only: %+v", cc)
	}

	manager := cluster.NewManager(0, 1)
	d := &Daemon{store: store, cluster: manager, opts: Options{NoDataplane: true}}
	var alarmObservedBeforeSessionSync bool
	manager.SetUnkeyedGraceAlarmHook(func(rung string, raised bool, expiry time.Time) {
		if rung == "stamped" && raised {
			alarmObservedBeforeSessionSync = d.getSessionSync() == nil
		}
	})
	ctx, cancel := context.WithCancel(context.Background())
	d.startClusterComms(ctx)
	expiry := manager.UnkeyedGraceExpiry()
	if expiry.IsZero() || manager.UnkeyedAuthorityExpired() {
		cancel()
		d.stopClusterComms()
		t.Fatalf("fabric-only start did not create an active grace cutoff: expiry=%s expired=%t",
			expiry, manager.UnkeyedAuthorityExpired())
	}
	if _, err := os.Stat(anchorPath); err != nil {
		cancel()
		d.stopClusterComms()
		t.Fatalf("fabric-only start did not persist its grace anchor: %v", err)
	}
	if !alarmObservedBeforeSessionSync {
		cancel()
		d.stopClusterComms()
		t.Fatal("fabric-only grace was not stamped before SessionSync could be published")
	}
	cancel()
	d.stopClusterComms()
}
func TestUnauthenticatedConfigSyncRechecksAuthorityAfterApplySemaphoreWait16016(t *testing.T) {
	isolateAuthorityAnchors16016(t)
	var mono atomic.Int64
	mono.Store(int64(time.Second))
	restoreClocks := cluster.SetUnkeyedAuthorityClocksForTesting(time.Now, mono.Load)
	t.Cleanup(restoreClocks)

	store := newConfigStore(t, filepath.Join(t.TempDir(), "config.db"))
	initial := `chassis { cluster { cluster-id 1; control-interface control0; } }`
	if _, err := store.SyncApply(initial, nil); err != nil {
		t.Fatalf("seed unkeyed config: %v", err)
	}
	manager := newClusterManager(false)
	if manager.UnkeyedAuthorityExpired() {
		t.Fatal("test precondition: grace expired before admission")
	}
	d := &Daemon{
		applySem: semaphore.NewWeighted(1),
		cluster:  manager,
		store:    store,
	}
	var applies int
	d.applyBodyForTest = func(*config.Config) { applies++ }
	waiting := make(chan struct{})
	d.testBeforeSyncApplySemAcquire = func() { close(waiting) }
	before := store.ShowActive()
	if err := d.applySem.Acquire(context.Background(), 1); err != nil {
		t.Fatal(err)
	}
	result := make(chan error, 1)
	incoming := renderSyncedConfigText(t,
		"chassis cluster cluster-id 1",
		"chassis cluster authentication-key first-key-16016-strong",
		"chassis cluster control-interface control0",
		"system host-name delayed-first-key-16016",
	)
	go func() {
		result <- d.handleConfigSyncWithProvenance(incoming, nil, false)
	}()
	select {
	case <-waiting:
	case <-time.After(time.Second):
		d.applySem.Release(1)
		t.Fatal("unauthenticated config did not reach the blocked apply-sem path")
	}
	select {
	case err := <-result:
		d.applySem.Release(1)
		t.Fatalf("config sync returned while applySem was held: %v", err)
	default:
	}

	mono.Store(int64(time.Second) + int64(73*time.Hour))
	d.applySem.Release(1)
	err := <-result
	if err == nil || !strings.Contains(err.Error(), "grace expired") {
		t.Fatalf("config admitted before cutoff was not refused after semaphore wait: %v", err)
	}
	if applies != 0 || store.ShowActive() != before {
		t.Fatalf("expired apply changed config: applies=%d before=%q after=%q", applies, before, store.ShowActive())
	}
	active := store.ActiveConfig()
	if active == nil || active.Chassis.Cluster == nil ||
		active.Chassis.Cluster.ControlLinkAuthKey.Reveal() != "" {
		t.Fatal("cutoff-racing unauthenticated config promoted its first PSK")
	}
	foundRefusal := false
	for _, event := range manager.EventHistoryFor(cluster.EventConfigSync) {
		if strings.Contains(event.Message, "Refused unauthenticated config sync at promotion") {
			foundRefusal = true
			break
		}
	}
	if !foundRefusal {
		t.Fatal("cutoff-racing config refusal was not recorded in cluster history")
	}
}
