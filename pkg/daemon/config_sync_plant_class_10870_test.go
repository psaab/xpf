package daemon

import (
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sync/semaphore"

	"github.com/psaab/xpf/pkg/cluster"
	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/eventengine"
	"github.com/psaab/xpf/pkg/rpm"
)

func TestConfigSyncBindsSuperuserPlantClassToPeerAuthentication10870(t *testing.T) {
	store := newConfigStore(t, filepath.Join(t.TempDir(), "config.db"))
	d := &Daemon{
		applySem: semaphore.NewWeighted(1),
		cluster:  newClusterManager(false),
		store:    store,
	}
	d.applyBodyForTest = func(*config.Config) {}
	ss := cluster.NewSessionSync(":0", "10.0.0.2:4785", nil)
	d.wireSessionSyncConfigCallbacks(ss)

	lines := append([]string(nil), clusterLines9530...)
	lines = append(lines,
		"system host-name sync-base",
		`event-options policy p events ping_test_failed`,
		`event-options policy p plant-class super-user`,
		`event-options policy p then change-configuration commands "set system host-name sync-fired"`,
	)
	peerConfig := renderSyncedConfigText(t, lines...)

	if err := ss.OnConfigReceivedWithProvenance(peerConfig, nil, false); err != nil {
		t.Fatalf("unauthenticated peer config sync: %v", err)
	}
	cfg := store.ActiveConfig()
	if cfg == nil || len(cfg.EventOptions) != 1 {
		t.Fatalf("synced config missing event policy: %+v", cfg)
	}
	if got := cfg.EventOptions[0].PlantClass; got != "" {
		t.Fatalf("unauthenticated sync retained PlantClass=%q, want quarantined empty marker", got)
	}

	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("enter unrelated config commit: %v", err)
	}
	if err := store.SetFromInputAsPlantClass("", config.EventPlantClassSuperuser,
		`system host-name unrelated-commit`); err != nil {
		t.Fatalf("set unrelated host-name: %v", err)
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("commit unrelated host-name: %v", err)
	}
	store.ExitConfigure()
	cfg = store.ActiveConfig()
	if got := cfg.EventOptions[0].PlantClass; got != "" {
		t.Fatalf("unrelated commit restored PlantClass=%q, want quarantined empty marker", got)
	}

	if got := cfg.System.HostName; got != "unrelated-commit" {
		t.Fatalf("unrelated commit host-name=%q, want unrelated-commit", got)
	}

	engine := eventengine.New(store, nil)
	defer engine.Close()
	engine.ApplyWithConfig(cfg.EventOptions, cfg)
	engine.HandleEvent(rpm.Event{Name: "ping_test_failed", TestOwner: "owner", TestName: "probe"})
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) && engine.Stats().Rejected == 0 {
		time.Sleep(time.Millisecond)
	}
	if engine.Stats().Rejected == 0 {
		t.Fatal("unauthenticated super-user event policy was not rejected at fire time")
	}
	if got := store.ActiveConfig().System.HostName; got != "unrelated-commit" {
		t.Fatalf("unauthenticated super-user policy fired: host-name=%q", got)
	}
	engine.Close()

	if err := ss.OnConfigReceivedWithProvenance(peerConfig, nil, true); err != nil {
		t.Fatalf("authenticated peer config sync: %v", err)
	}
	cfg = store.ActiveConfig()
	if got := cfg.EventOptions[0].PlantClass; got != config.EventPlantClassSuperuser {
		t.Fatalf("authenticated sync PlantClass=%q, want %q", got, config.EventPlantClassSuperuser)
	}

	engine = eventengine.New(store, nil)
	defer engine.Close()
	engine.ApplyWithConfig(cfg.EventOptions, cfg)
	engine.HandleEvent(rpm.Event{Name: "ping_test_failed", TestOwner: "owner", TestName: "probe"})
	deadline = time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) && engine.Stats().Committed == 0 {
		time.Sleep(time.Millisecond)
	}
	if engine.Stats().Committed == 0 {
		t.Fatal("authenticated super-user event policy did not fire")
	}
	if got := store.ActiveConfig().System.HostName; got != "sync-fired" {
		t.Fatalf("authenticated super-user event policy host-name=%q, want sync-fired", got)
	}

}
