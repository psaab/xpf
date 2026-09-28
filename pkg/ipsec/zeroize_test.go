package ipsec

import (
	"os"
	"path/filepath"
	"testing"
)

func TestEraseConnStateIfEmpty(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ipsec-conn-state.json")
	if err := os.WriteFile(path, []byte(`{"loaded":[],"pending_terminate":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := EraseConnStateIfEmpty(path); err != nil {
		t.Fatalf("erase trusted-empty state: %v", err)
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatalf("trusted-empty state survived: %v", err)
	}
}

func TestEraseConnStateIfEmptyPreservesTeardownDebt(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ipsec-conn-state.json")
	state := `{"loaded":["site-a"],"pending_terminate":["site-b"]}`
	if err := os.WriteFile(path, []byte(state), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := EraseConnStateIfEmpty(path); err == nil {
		t.Fatal("non-empty connection state must refuse erasure")
	}
	got, err := os.ReadFile(path)
	if err != nil || string(got) != state {
		t.Fatalf("failed erase changed teardown authority: body=%q err=%v", got, err)
	}
}

func TestEraseConnStateIfEmptyRemovesCrashTemps(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ipsec-conn-state.json")
	if err := os.WriteFile(path, []byte(`{"loaded":[],"pending_terminate":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	temp := filepath.Join(dir, ".ipsec-conn-state.json.tmp-12345")
	if err := os.WriteFile(temp, []byte(`{"loaded":["site-a"]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	other := filepath.Join(dir, ".unrelated.json.tmp-1")
	if err := os.WriteFile(other, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := EraseConnStateIfEmpty(path); err != nil {
		t.Fatalf("erase with crash temp: %v", err)
	}
	if _, err := os.Lstat(temp); !os.IsNotExist(err) {
		t.Fatalf("crash temp survived: %v", err)
	}
	if _, err := os.Lstat(other); err != nil {
		t.Fatalf("another writer's temp must survive: %v", err)
	}
}
