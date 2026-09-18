package daemon

import (
	"context"
	"testing"
	"time"

	"golang.org/x/sync/semaphore"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/configstore"
	"github.com/psaab/xpf/pkg/rpm"
)

func TestEventEngineJournalPrincipal10301(t *testing.T) {
	s := newConfigStore(t, t.TempDir()+"/xpf.conf")
	d := &Daemon{
		daemonCtx:        context.Background(),
		store:            s,
		applySem:         semaphore.NewWeighted(1),
		applyBodyForTest: func(*config.Config) {},
	}
	d.initEventEngine()
	defer d.eventEngine.Close()
	d.eventEngine.Apply([]*config.EventPolicy{{
		Name:         "event-label",
		Events:       []string{"ping_test_failed"},
		PlantClass:   config.EventPlantClassSuperuser,
		ThenCommands: []string{"set system host-name event-label"},
	}})
	d.eventEngine.HandleEvent(rpm.Event{Name: "ping_test_failed", TestOwner: "test", TestName: "event-label"})
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && d.eventEngine.Stats().Committed < 1 {
		time.Sleep(5 * time.Millisecond)
	}
	if d.eventEngine.Stats().Committed < 1 {
		t.Fatal("event remediation did not commit")
	}
	entries, err := s.ListCommitHistory(0)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) == 0 || entries[len(entries)-1].Principal != "system:event-engine" {
		t.Fatalf("event remediation principal = %+v, want system:event-engine", entries)
	}
}

func TestShellCommitCallbackJournalPrincipal10301(t *testing.T) {
	s := newConfigStore(t, t.TempDir()+"/xpf.conf")
	if err := s.EnterConfigure(); err != nil {
		t.Fatal(err)
	}
	if err := s.SetFromInput("system host-name shell-callback"); err != nil {
		t.Fatal(err)
	}
	d := &Daemon{
		store:            s,
		applySem:         semaphore.NewWeighted(1),
		applyBodyForTest: func(*config.Config) {},
	}
	principal := "source=local-shell;uid=4242;user=opsuser;class=operator;session=none"
	ctx := configstore.WithJournalPrincipal(context.Background(), principal)
	if _, err := d.shellCommitFn()(ctx, "shell callback"); err != nil {
		t.Fatalf("shell callback commit: %v", err)
	}
	entries, err := s.ListCommitHistory(0)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) == 0 || entries[len(entries)-1].Principal != principal {
		t.Fatalf("shell callback principal = %+v, want %q", entries, principal)
	}
	if err := s.SetFromInput("system host-name shell-callback-confirmed"); err != nil {
		t.Fatal(err)
	}
	if _, err := d.shellCommitConfirmedFn()(ctx, 5); err != nil {
		t.Fatalf("shell confirmed callback: %v", err)
	}
	if err := s.ConfirmCommit(); err != nil {
		t.Fatal(err)
	}
	entries, err = s.ListCommitHistory(0)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) == 0 || entries[len(entries)-1].Principal != principal {
		t.Fatalf("shell confirmed callback principal = %+v, want %q", entries, principal)
	}
}

func TestBootstrapJournalPrincipal10301(t *testing.T) {
	d, _ := bootstrapDaemon(t, "system { host-name bootstrap-label; }\n", -1)
	if err := d.bootstrapFromFile(); err != nil {
		t.Fatalf("bootstrapFromFile: %v", err)
	}
	entries, err := d.store.ListCommitHistory(0)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) == 0 || entries[len(entries)-1].Principal != "system:bootstrap" {
		t.Fatalf("bootstrap principal = %+v, want system:bootstrap", entries)
	}
}
