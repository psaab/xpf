package configstore

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
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
	if err := WriteResetHandoff(boot, ""); err != nil {
		t.Fatalf("write: %v", err)
	}
	gotBoot, gotDirty, present, err := ReadResetHandoff()
	if err != nil || !present || gotBoot != boot || gotDirty != "" {
		t.Fatalf("read = %q %q %v %v", gotBoot, gotDirty, present, err)
	}
	if err := MarkResetHandoffDirty("sweep failed"); err != nil {
		t.Fatalf("mark dirty: %v", err)
	}
	gotBoot, gotDirty, present, err = ReadResetHandoff()
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
	_, gotDirty, _, err = ReadResetHandoff()
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
	if err := WriteResetHandoff(boot, ""); err != nil {
		t.Fatal(err)
	}
	if err := CheckResetHandoff(); !errors.Is(err, ErrResetHandoffRebootRequired) {
		t.Fatalf("same-boot gate = %v, want reboot-required", err)
	}
	if _, err := os.Lstat(path); err != nil {
		t.Fatalf("refused flag must be retained: %v", err)
	}
	// Dirty flag: refuse even across reboot, until a clean reset.
	if err := WriteResetHandoff("other-boot", "helper sweep failed"); err != nil {
		t.Fatal(err)
	}
	if err := CheckResetHandoff(); !errors.Is(err, ErrResetHandoffDirty) {
		t.Fatalf("dirty gate = %v, want incomplete", err)
	}
	// Clean flag, other boot: reboot happened, clear and open.
	if err := WriteResetHandoff("other-boot", ""); err != nil {
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
