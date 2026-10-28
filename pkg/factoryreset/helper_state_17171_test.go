package factoryreset

import (
	"os"
	"path/filepath"
	"testing"
)

// TestSweepHelperStateParity17171: the canonical helper-state entry point
// through the shared primitive — regular erased, absent clean (symlink
// and hardlink are already pinned by TestSweepHelperStateTable17087).
// The symlinked-temp cell is #17171's defect: the temp beside the
// canonical must now be refused, not silently unlinked.
func TestSweepHelperStateParity17171(t *testing.T) {
	opts := SweepOpts{ErrPrefix: "zeroize: ", ReservedRecovery: "test recovery", SyncDir: wipeSyncDir}
	t.Run("regular removed", func(t *testing.T) {
		dir := t.TempDir()
		canonical := filepath.Join(dir, "userspace-dp.json")
		mustWriteFile(t, canonical, []byte(`{"flows":[]}`))
		if err := SweepHelperState(canonical, opts); err != nil {
			t.Fatalf("regular sweep: %v", err)
		}
		if _, err := os.Lstat(canonical); !os.IsNotExist(err) {
			t.Fatalf("canonical survived: %v", err)
		}
	})
	t.Run("absent is clean", func(t *testing.T) {
		p := filepath.Join(t.TempDir(), "nope.json")
		if err := SweepHelperState(p, opts); err != nil {
			t.Fatalf("absent sweep must be nil, got %v", err)
		}
	})
	t.Run("symlinked temp refused", func(t *testing.T) {
		dir := t.TempDir()
		canonical := filepath.Join(dir, "userspace-dp.json")
		target := filepath.Join(dir, "victim.txt")
		const body = "prior-tenant-session-state"
		mustWriteFile(t, canonical, []byte(`{"flows":[]}`))
		mustWriteFile(t, target, []byte(body))
		link := filepath.Join(dir, "userspace-dp.json.4250000000.1.tmp")
		if err := os.Symlink(target, link); err != nil {
			t.Fatal(err)
		}
		if err := SweepHelperState(canonical, opts); err == nil {
			t.Fatal("symlinked helper temp must fail the sweep, got nil")
		}
		if _, err := os.Lstat(link); err != nil {
			t.Fatalf("refusal must retain the link: %v", err)
		}
		if got, err := os.ReadFile(target); err != nil || string(got) != body {
			t.Fatalf("target bytes must survive refusal: %q err=%v", got, err)
		}
	})
}
