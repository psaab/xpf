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
