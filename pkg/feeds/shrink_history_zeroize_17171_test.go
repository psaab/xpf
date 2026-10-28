package feeds

import (
	"os"
	"path/filepath"
	"testing"
)

func TestEraseShrinkHistoryCrashTempsParity17171(t *testing.T) {
	t.Run("regular removed", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "feed-shrink-history.json")
		temp := filepath.Join(dir, ".feed-shrink-history.json.tmp-1")
		if err := os.WriteFile(temp, []byte("temp"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := EraseShrinkHistoryCrashTemps(path); err != nil {
			t.Fatalf("regular erase: %v", err)
		}
		if _, err := os.Lstat(temp); !os.IsNotExist(err) {
			t.Fatalf("regular temp survived: %v", err)
		}
	})
	t.Run("absent is clean", func(t *testing.T) {
		if err := EraseShrinkHistoryCrashTemps(filepath.Join(t.TempDir(), "nope.json")); err != nil {
			t.Fatalf("absent erase must be nil, got %v", err)
		}
	})
}
