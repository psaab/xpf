package factoryreset

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/configstore"
)

// TestSweepHelperStateTable17087 is the single table guarding the shared
// helper-state sweep (#17087): both the daemon handoff sweep and the
// ungated offline wipe delegate to SweepHelperState, so a hardening
// (or a mutant) of the hardlink/symlink/reserved branches reds here AND
// in the daemon's TestSweepHelperStateVerifiedRefusesHardlinkedCanonical10769
// through the one body. Live-temp uses this process's own pid+starttime
// tuple so the temp classifies as a live writer's in-flight file.
func TestSweepHelperStateTable17087(t *testing.T) {
	opts := SweepOpts{
		ErrPrefix:        "zeroize: ",
		ReservedRecovery: "test recovery",
		SyncDir:          wipeSyncDir,
	}
	t.Run("hardlink refused before unlink", func(t *testing.T) {
		dir := t.TempDir()
		dest := filepath.Join(dir, "userspace-dp.json")
		mustWriteFile(t, dest, []byte(`{"flows":[]}`))
		sibling := filepath.Join(dir, "sibling.json")
		if err := os.Link(dest, sibling); err != nil {
			t.Fatalf("hardlink plant: %v", err)
		}
		for attempt := 1; attempt <= 2; attempt++ {
			var linkErr *configstore.FactoryResetHardlinkError
			if err := SweepHelperState(dest, opts); !errors.As(err, &linkErr) {
				t.Fatalf("attempt %d: expected FactoryResetHardlinkError, got %v", attempt, err)
			}
			for _, path := range []string{dest, sibling} {
				if _, serr := os.Lstat(path); serr != nil {
					t.Fatalf("attempt %d: refusal must remove nothing, %s stat err=%v", attempt, path, serr)
				}
			}
		}
	})
	t.Run("symlink refused", func(t *testing.T) {
		dir := t.TempDir()
		target := filepath.Join(dir, "real-state.json")
		mustWriteFile(t, target, []byte(`{"flows":[]}`))
		link := filepath.Join(dir, "state-link.json")
		if err := os.Symlink(target, link); err != nil {
			t.Fatal(err)
		}
		if err := SweepHelperState(link, opts); err == nil {
			t.Fatal("symlinked helper state must fail closed")
		}
		for _, path := range []string{link, target} {
			if _, err := os.Lstat(path); err != nil {
				t.Fatalf("refusal must remove nothing, %s stat err=%v", path, err)
			}
		}
	})
	t.Run("reserved alias fails closed and survives", func(t *testing.T) {
		dir := t.TempDir()
		canonical := filepath.Join(dir, ".reset-handoff")
		mustWriteFile(t, canonical, []byte("gate bytes must survive"))
		temp := canonical + ".4250000000.1.tmp"
		mustWriteFile(t, temp, []byte(`{"orphan":true}`))
		err := SweepHelperState(canonical, opts)
		if err == nil {
			t.Fatal("reserved-alias sweep must fail closed, got nil")
		}
		if !strings.Contains(err.Error(), "aliases reserved") || !strings.Contains(err.Error(), canonical) || !strings.Contains(err.Error(), "test recovery") {
			t.Fatalf("sweep error must name the reserved alias and recovery, got %v", err)
		}
		if got, rerr := os.ReadFile(canonical); rerr != nil || string(got) != "gate bytes must survive" {
			t.Fatalf("reserved canonical must survive byte-identical: %q err=%v", got, rerr)
		}
		if _, serr := os.Lstat(temp); !os.IsNotExist(serr) {
			t.Fatalf("temps beside reserved canonical must still be swept: %v", serr)
		}
		if err := VerifyHelperStateErased(canonical, opts); err == nil || !strings.Contains(err.Error(), "cannot be verified") {
			t.Fatalf("reserved alias must fail verification, got %v", err)
		}
	})
	t.Run("live temp fails closed", func(t *testing.T) {
		pid, start, ok := ownProcStartTuple(t)
		if !ok {
			t.Skip("no /proc in test environment")
		}
		dir := t.TempDir()
		canonical := filepath.Join(dir, "userspace-dp.json")
		live := canonical + "." + pid + "_" + start + ".1.tmp"
		mustWriteFile(t, live, []byte(`{"inflight":true}`))
		if err := SweepHelperState(canonical, opts); err == nil {
			t.Fatal("live helper writer temp must fail the sweep, got nil")
		}
		if _, err := os.Lstat(live); err != nil {
			t.Fatalf("live temp must survive the failed sweep: %v", err)
		}
	})
	t.Run("clean sweep removes canonical and dead temps", func(t *testing.T) {
		dir := t.TempDir()
		canonical := filepath.Join(dir, "userspace-dp.json")
		mustWriteFile(t, canonical, []byte(`{"flows":[]}`))
		legacy := canonical + ".4250000000.1.tmp"
		mustWriteFile(t, legacy, []byte(`{"orphan":true}`))
		if err := SweepHelperState(canonical, opts); err != nil {
			t.Fatalf("clean sweep: %v", err)
		}
		if err := VerifyHelperStateErased(canonical, opts); err != nil {
			t.Fatalf("verify after clean sweep: %v", err)
		}
		for _, path := range []string{canonical, legacy} {
			if _, err := os.Lstat(path); !os.IsNotExist(err) {
				t.Fatalf("%s survived the sweep: %v", path, err)
			}
		}
	})
}

// TestResetStatePaths17087 pins the path inventory: helper plus the
// generation path (via the test-redirected seam), deduplicated, with an
// empty helper contributing only the generation path.
func TestResetStatePaths17087(t *testing.T) {
	helper := "/tmp/xpf-test-helper/userspace-dp.json"
	generation := wipePersistentNatGenerationStatePath()
	if generation == "" {
		t.Fatal("test seam must redirect the generation path")
	}
	if got := ResetStatePaths(helper); len(got) != 2 || got[0] != helper || got[1] != generation {
		t.Fatalf("ResetStatePaths(%q) = %v, want [helper generation]", helper, got)
	}
	if got := ResetStatePaths(generation); len(got) != 1 || got[0] != generation {
		t.Fatalf("ResetStatePaths(generation) = %v, want deduped [generation]", got)
	}
	if got := ResetStatePaths(""); len(got) != 1 || got[0] != generation {
		t.Fatalf("ResetStatePaths(\"\") = %v, want [generation]", got)
	}
}
