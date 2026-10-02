package grpcapi

import (
	"os"
	"path/filepath"
	"testing"
)

func TestUngatedZeroizeErasesPersistentNatGenerationState11486(t *testing.T) {
	root := t.TempDir()
	helperPath := filepath.Join(root, "helper-state.json")
	generationPath := filepath.Join(root, "persistent-nat-lease-generation.json")
	oldPath := zeroizePersistentNatGenerationStatePath
	zeroizePersistentNatGenerationStatePath = func() string { return generationPath }
	t.Cleanup(func() { zeroizePersistentNatGenerationStatePath = oldPath })
	for _, path := range []string{helperPath, generationPath} {
		if err := os.WriteFile(path, []byte(`{"state":true}`), 0o600); err != nil {
			t.Fatalf("write zeroize fixture %s: %v", path, err)
		}
	}
	if err := zeroizeVerifyPersistentNatGenerationState(); err == nil {
		t.Fatal("final verification accepted persistent-NAT generation state before cleanup")
	}

	if err := zeroizeEraseResetState(helperPath); err != nil {
		t.Fatalf("erase helper and generation state: %v", err)
	}
	if err := zeroizeVerifyPersistentNatGenerationState(); err != nil {
		t.Fatalf("verify generation state after cleanup: %v", err)
	}
	for _, path := range []string{helperPath, generationPath} {
		if _, err := os.Lstat(path); !os.IsNotExist(err) {
			t.Fatalf("zeroized state %s remains: %v", path, err)
		}
	}
}
