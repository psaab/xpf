package configstore

import (
	"errors"
	"os"
	"testing"
)

// TestSaveRescueConfigRejectsUncommittedEmptyActive_11803 proves an explicit
// rescue save cannot replace the tenant's existing safety net with a fresh
// store's uncommitted empty tree.
func TestSaveRescueConfigRejectsUncommittedEmptyActive_11803(t *testing.T) {
	store := newTestStore(t)
	if store.EverCommitted() {
		t.Fatal("premise broken: fresh store is already committed")
	}

	const knownGood = "system { host-name tenant-good; }\n"
	path := store.rescuePath()
	if err := os.WriteFile(path, []byte(knownGood), 0o600); err != nil {
		t.Fatalf("seed existing rescue config: %v", err)
	}

	err := store.SaveRescueConfig()
	got, readErr := os.ReadFile(path)
	if readErr != nil {
		t.Fatalf("read existing rescue config: %v", readErr)
	}
	if !errors.Is(err, ErrRescueSaveNoCommittedConfig) {
		t.Fatalf("SaveRescueConfig() error = %v, want ErrRescueSaveNoCommittedConfig", err)
	}
	if string(got) != knownGood {
		t.Fatalf("SaveRescueConfig() changed existing rescue config: got %q, want %q", got, knownGood)
	}
}

// TestSaveRescueConfigRejectsCommittedEmptyActive_11803 prevents an empty but
// committed active tree from replacing the last-known-good rescue file.
func TestSaveRescueConfigRejectsCommittedEmptyActive_11803(t *testing.T) {
	store := newTestStore(t)
	if _, err := store.SyncApply("", nil); err != nil {
		t.Fatalf("SyncApply empty committed config: %v", err)
	}
	if !store.EverCommitted() {
		t.Fatal("premise broken: SyncApply did not mark the empty active tree committed")
	}

	const knownGood = "system { host-name tenant-good; }\n"
	path := store.rescuePath()
	if err := os.WriteFile(path, []byte(knownGood), 0o600); err != nil {
		t.Fatalf("seed existing rescue config: %v", err)
	}
	err := store.SaveRescueConfig()
	got, readErr := os.ReadFile(path)
	if readErr != nil {
		t.Fatalf("read existing rescue config: %v", readErr)
	}
	if !errors.Is(err, ErrRescueSaveNoCommittedConfig) {
		t.Fatalf("SaveRescueConfig() error = %v, want ErrRescueSaveNoCommittedConfig", err)
	}
	if string(got) != knownGood {
		t.Fatalf("SaveRescueConfig() changed existing rescue config: got %q, want %q", got, knownGood)
	}
}
