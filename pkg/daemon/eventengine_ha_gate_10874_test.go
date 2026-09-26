package daemon

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sync/semaphore"

	"github.com/psaab/xpf/pkg/cluster"
	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/rpm"
)

func TestEventEngineRemediationDefersAcrossRG0Failover10874(t *testing.T) {
	d := &Daemon{
		daemonCtx:        context.Background(),
		rpm:              rpm.New(),
		store:            newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf")),
		applySem:         semaphore.NewWeighted(1),
		applyBodyForTest: func(*config.Config) {},
	}
	d.initEventEngine()
	defer d.eventEngine.Close()

	if err := d.store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure seed: %v", err)
	}
	if err := d.store.SetFromInput("system host-name base"); err != nil {
		d.store.ExitConfigure()
		t.Fatalf("seed host-name: %v", err)
	}
	if _, err := d.store.Commit(); err != nil {
		d.store.ExitConfigure()
		t.Fatalf("seed commit: %v", err)
	}
	d.store.ExitConfigure()

	d.eventEngine.Apply([]*config.EventPolicy{{
		Name:         "wan-failover",
		Events:       []string{"ping_test_failed"},
		PlantClass:   config.EventPlantClassSuperuser,
		ThenCommands: []string{"set system host-name remediated"},
	}})

	// The standby closes publication before making its config store read-only.
	d.applyRG0OwnershipTransition(cluster.StateSecondary)
	if d.eventEngine.PublishEnabled() || !d.store.ClusterReadOnly() {
		t.Fatal("RG0 demotion must close event publication and config writes")
	}
	d.eventEngine.HandleEvent(rpm.Event{Name: "ping_test_failed", TestOwner: "WAN", TestName: "test"})
	deadline := time.Now().Add(time.Second)
	for d.eventEngine.Stats().QueueDepth != 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if d.eventEngine.Stats().QueueDepth != 0 {
		t.Fatal("action worker did not accept the queued remediation")
	}
	if stats := d.eventEngine.Stats(); stats.Rejected != 0 || stats.Committed != 0 {
		t.Fatalf("standby must retain, not reject or commit, the action: %+v", stats)
	}

	// There is no second FAIL edge on takeover; promotion must reopen the gate
	// and let the already-accepted action complete.
	d.applyRG0OwnershipTransition(cluster.StatePrimary)
	if !d.eventEngine.PublishEnabled() || d.store.ClusterReadOnly() {
		t.Fatal("RG0 promotion must reopen event publication and config writes")
	}
	deadline = time.Now().Add(5 * time.Second)
	for d.eventEngine.Stats().Committed == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if got := d.eventEngine.Stats(); got.Committed != 1 || got.Rejected != 0 {
		t.Fatalf("promotion must commit the retained action exactly once: %+v", got)
	}
	if got := d.store.ActiveConfig().System.HostName; got != "remediated" {
		t.Fatalf("active host-name after takeover=%q, want remediated", got)
	}
}
