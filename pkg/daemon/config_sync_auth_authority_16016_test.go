package daemon

import (
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sync/semaphore"

	"github.com/psaab/xpf/pkg/config"
)

func TestUnauthenticatedConfigSyncRejectedOnceLocallyKeyed16016(t *testing.T) {
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
	store := newConfigStore(t, filepath.Join(t.TempDir(), "config.db"))
	initial := `chassis { cluster { cluster-id 1; control-interface em0; } }`
	if _, err := store.SyncApply(initial, nil); err != nil {
		t.Fatalf("seed unkeyed config: %v", err)
	}
	manager := newClusterManager(false)
	manager.UpdateConfig(&config.ClusterConfig{})
	d := &Daemon{
		applySem: semaphore.NewWeighted(1),
		cluster:  manager,
		store:    store,
	}
	d.applyBodyForTest = func(*config.Config) {}

	incoming := renderSyncedConfigText(t,
		"chassis cluster cluster-id 1",
		"chassis cluster authentication-key peer-key-16016-strong",
		"chassis cluster control-interface em0",
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
