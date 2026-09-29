package configstore

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

func isolateHandoff(t *testing.T) string {
	t.Helper()
	orig := ResetHandoffPath
	path := filepath.Join(t.TempDir(), ".reset-handoff")
	ResetHandoffPath = path
	t.Cleanup(func() { ResetHandoffPath = orig })
	return path
}

func TestResetHandoffRoundTrip(t *testing.T) {
	path := isolateHandoff(t)
	boot, err := CurrentBootID()
	if err != nil {
		t.Fatalf("CurrentBootID: %v", err)
	}
	if err := WriteResetHandoff(boot, "", ""); err != nil {
		t.Fatalf("write: %v", err)
	}
	gotBoot, gotDirty, gotPath, present, err := ReadResetHandoff()
	if err != nil || !present || gotBoot != boot || gotDirty != "" || gotPath != "" {
		t.Fatalf("read = %q %q %q %v %v", gotBoot, gotDirty, gotPath, present, err)
	}
	if err := MarkResetHandoffDirty("sweep failed"); err != nil {
		t.Fatalf("mark dirty: %v", err)
	}
	gotBoot, gotDirty, _, present, err = ReadResetHandoff()
	if err != nil || !present || gotBoot != boot || gotDirty != "sweep failed" {
		t.Fatalf("dirty read = %q %q %v %v", gotBoot, gotDirty, present, err)
	}
	if _, err := os.Lstat(path); err != nil {
		t.Fatalf("flag must exist: %v", err)
	}
	// Multi-line reasons (joined errors) must flatten, never corrupt.
	if err := MarkResetHandoffDirty("first\nsecond"); err != nil {
		t.Fatal(err)
	}
	_, gotDirty, _, _, err = ReadResetHandoff()
	if err != nil || gotDirty != "first second" {
		t.Fatalf("flattened dirty = %q, %v", gotDirty, err)
	}
	if err := ClearResetHandoff(); err != nil {
		t.Fatalf("clear: %v", err)
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatalf("flag must be gone: %v", err)
	}
}

func TestCheckResetHandoffGate(t *testing.T) {
	path := isolateHandoff(t)
	if err := CheckResetHandoff(); err != nil {
		t.Fatalf("absent flag must open: %v", err)
	}
	boot, err := CurrentBootID()
	if err != nil {
		t.Fatalf("CurrentBootID: %v", err)
	}
	// Clean flag, same boot: reboot required, flag retained.
	if err := WriteResetHandoff(boot, "", ""); err != nil {
		t.Fatal(err)
	}
	if err := CheckResetHandoff(); !errors.Is(err, ErrResetHandoffRebootRequired) {
		t.Fatalf("same-boot gate = %v, want reboot-required", err)
	}
	if _, err := os.Lstat(path); err != nil {
		t.Fatalf("refused flag must be retained: %v", err)
	}
	// Dirty flag: refuse even across reboot, until a clean reset.
	if err := WriteResetHandoff("other-boot", "helper sweep failed", ""); err != nil {
		t.Fatal(err)
	}
	if err := CheckResetHandoff(); !errors.Is(err, ErrResetHandoffDirty) {
		t.Fatalf("dirty gate = %v, want incomplete", err)
	}
	// Clean flag, other boot: reboot happened, clear and open.
	if err := WriteResetHandoff("other-boot", "", ""); err != nil {
		t.Fatal(err)
	}
	if err := CheckResetHandoff(); err != nil {
		t.Fatalf("post-reboot gate must open: %v", err)
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatalf("converged flag must be cleared: %v", err)
	}
	// Corrupt flag fails closed.
	if err := os.WriteFile(path, []byte("garbage\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := CheckResetHandoff(); !errors.Is(err, ErrResetHandoffDirty) {
		t.Fatalf("corrupt gate = %v, want incomplete", err)
	}
}

func TestResetHandoffHelperPathRoundTrip(t *testing.T) {
	isolateHandoff(t)
	boot, err := CurrentBootID()
	if err != nil {
		t.Fatal(err)
	}
	custom := filepath.Join(t.TempDir(), "custom", "userspace-dp.json")
	if err := WriteResetHandoff(boot, ResetHandoffPending, custom); err != nil {
		t.Fatalf("write: %v", err)
	}
	gotBoot, gotDirty, gotPath, present, err := ReadResetHandoff()
	if err != nil || !present || gotBoot != boot || gotDirty != ResetHandoffPending || gotPath != custom {
		t.Fatalf("read = %q %q %q %v %v", gotBoot, gotDirty, gotPath, present, err)
	}
	// Mark preserves the recorded path across dirty rewrites.
	if err := MarkResetHandoffDirty(ResetHandoffReasonHelper + ": sweep failed"); err != nil {
		t.Fatal(err)
	}
	_, _, gotPath, _, err = ReadResetHandoff()
	if err != nil || gotPath != custom {
		t.Fatalf("mark must preserve helper path, got %q (%v)", gotPath, err)
	}
	// A flag without the line reads back empty (pre-path tolerance).
	raw, err := os.ReadFile(ResetHandoffPath)
	if err != nil {
		t.Fatal(err)
	}
	var kept []string
	for _, line := range strings.Split(string(raw), "\n") {
		if !strings.HasPrefix(line, "helper_path=") {
			kept = append(kept, line)
		}
	}
	if err := os.WriteFile(ResetHandoffPath, []byte(strings.Join(kept, "\n")), 0o644); err != nil {
		t.Fatal(err)
	}
	_, _, gotPath, present, err = ReadResetHandoff()
	if err != nil || !present || gotPath != "" {
		t.Fatalf("missing helper_path must read empty: %q %v %v", gotPath, present, err)
	}
}

func TestResetHandoffHelperPathLineBreakRejected(t *testing.T) {
	isolateHandoff(t)
	boot, err := CurrentBootID()
	if err != nil {
		t.Fatal(err)
	}
	if err := WriteResetHandoff(boot, "", "/tmp/a\nboot_id=x"); err == nil {
		t.Fatal("helper path with a line break must fail closed")
	}
}

func TestFlipResetHandoffClean(t *testing.T) {
	isolateHandoff(t)
	if err := FlipResetHandoffClean(); err == nil {
		t.Fatal("flip with no flag must fail closed")
	}
	custom := filepath.Join("custom", "userspace-dp.json")
	if err := WriteResetHandoff("other-boot", ResetHandoffPending, custom); err != nil {
		t.Fatal(err)
	}
	if err := FlipResetHandoffClean(); err != nil {
		t.Fatalf("flip: %v", err)
	}
	gotBoot, gotDirty, gotPath, present, err := ReadResetHandoff()
	if err != nil || !present || gotBoot != "other-boot" || gotDirty != "" || gotPath != custom {
		t.Fatalf("flipped = %q %q %q %v %v", gotBoot, gotDirty, gotPath, present, err)
	}
}

// The config-package reserved denylist carries literals (pkg/config cannot
// import pkg/configstore); a drifted literal would reopen the alias the
// validator claims to close. Pin them equal here.
func TestReservedHelperStatePathsMatchOwners(t *testing.T) {
	for _, path := range []string{FactoryResetPendingPath, ResetHandoffPath} {
		if !config.IsReservedHelperStatePath(path) {
			t.Errorf("reserved denylist must cover %q", path)
		}
	}
}
