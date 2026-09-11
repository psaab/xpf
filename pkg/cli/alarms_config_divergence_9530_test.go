package cli

import (
	"path/filepath"
	"strings"
	"testing"
)

// #9530: the local `show system alarms` lists a peer config sync that discarded a
// local commit the peer never held, naming the rollback slot. It renders the
// same store line as the gRPC path.
func TestShowSystemAlarmsListsAConfigSyncDivergence_9530(t *testing.T) {
	winner := newConfigStore(t, filepath.Join(t.TempDir(), "winner.conf"))
	if err := winner.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	if err := winner.SetFromInput("system host-name winner"); err != nil {
		t.Fatalf("SetFromInput: %v", err)
	}
	if _, err := winner.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	c0 := winner.ShowActive()

	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if _, err := store.SyncApply(c0, nil); err != nil {
		t.Fatalf("SyncApply: %v", err)
	}
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	store.SetPeerReachableFn(func() bool { return false })
	if err := store.SetFromInput("system host-name partition-commit"); err != nil {
		t.Fatalf("SetFromInput: %v", err)
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	store.SetClusterReadOnly(true)
	if _, err := store.SyncApply(c0, nil); err != nil {
		t.Fatalf("heal SyncApply: %v", err)
	}

	c := &CLI{store: store}
	var runErr error
	out := captureStdout(t, func() { runErr = c.handleShowSystem([]string{"alarms"}) })
	if runErr != nil {
		t.Fatalf("show system alarms: %v", runErr)
	}
	if !strings.Contains(out, "CRITICAL: config sync replaced a local commit") || !strings.Contains(out, "rollback 1") {
		t.Errorf("#9530: `show system alarms` does not list the discarded partition commit with its rollback slot:\n%s", out)
	}
}
