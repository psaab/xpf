package grpcapi

import (
	"path/filepath"
	"strings"
	"testing"
)

// #9530: `show system alarms` lists a peer config sync that discarded a local
// commit the peer never held, naming the rollback slot, ahead of the config
// validation warnings.
func TestShowAlarmsListsAConfigSyncDivergence_9530(t *testing.T) {
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
	s := &Server{store: store}

	var before strings.Builder
	s.showAlarms(&before)
	if strings.Contains(before.String(), "CRITICAL") {
		t.Fatalf("setup: an alarm is already listed: %s", before.String())
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

	var after strings.Builder
	s.showAlarms(&after)
	out := after.String()
	if !strings.Contains(out, "CRITICAL: config sync replaced a local commit") || !strings.Contains(out, "rollback 1") {
		t.Errorf("#9530: `show system alarms` does not list the discarded partition commit with its rollback slot:\n%s", out)
	}
}
