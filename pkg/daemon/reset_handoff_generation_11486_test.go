package daemon

import (
	"os"
	"path/filepath"
	"testing"
)

func TestResetCleanupIncludesPersistentNatGenerationState11486(t *testing.T) {
	root := t.TempDir()
	helperPath := filepath.Join(root, "helper-state.json")
	generationPath := filepath.Join(root, "persistent-nat-lease-generation.json")
	oldPath := resetPersistentNatGenerationStatePath
	resetPersistentNatGenerationStatePath = func() string { return generationPath }
	t.Cleanup(func() { resetPersistentNatGenerationStatePath = oldPath })
	for _, path := range []string{helperPath, generationPath} {
		if err := os.WriteFile(path, []byte(`{"state":true}`), 0o600); err != nil {
			t.Fatalf("write reset fixture %s: %v", path, err)
		}
	}

	if err := sweepResetHelperStateVerified(helperPath); err != nil {
		t.Fatalf("sweep helper and generation state: %v", err)
	}
	if err := verifyResetHelperStateErased(helperPath); err != nil {
		t.Fatalf("verify helper and generation state: %v", err)
	}
	for _, path := range []string{helperPath, generationPath} {
		if _, err := os.Lstat(path); !os.IsNotExist(err) {
			t.Fatalf("reset state %s remains: %v", path, err)
		}
	}
}
