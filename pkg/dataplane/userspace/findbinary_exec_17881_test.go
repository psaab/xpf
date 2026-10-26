package userspace

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeExecFixture17881(t *testing.T, path, marker string) {
	t.Helper()
	body := "#!/bin/sh\nprintf '%s\\n'\n"
	if err := os.WriteFile(path, []byte(strings.Replace(body, "%s", marker, 1)), 0o755); err != nil {
		t.Fatal(err)
	}
}

func TestHelperBinaryCommandExecsOpenedInode17881(t *testing.T) {
	dir := t.TempDir()

	// Unswapped control: the normal descriptor-backed helper still runs.
	controlPath := filepath.Join(dir, "control-helper")
	writeExecFixture17881(t, controlPath, "CONTROL")
	control, err := openValidatedBinary(controlPath)
	if err != nil {
		t.Fatal(err)
	}
	controlCmd := helperBinaryCommand(control)
	controlOutput, err := controlCmd.Output()
	control.Close()
	if err != nil {
		t.Fatalf("run unswapped helper: %v", err)
	}
	if got := strings.TrimSpace(string(controlOutput)); got != "CONTROL" {
		t.Fatalf("unswapped helper output = %q, want CONTROL", got)
	}

	// Defect cell: replace the validated path after open/validation but
	// before Start. A pathname-based exec runs the replacement instead of
	// the inode that openValidatedBinary admitted.
	helperPath := filepath.Join(dir, "helper")
	replacementPath := filepath.Join(dir, "replacement")
	writeExecFixture17881(t, helperPath, "VALIDATED")
	writeExecFixture17881(t, replacementPath, "REPLACEMENT")
	validated, err := openValidatedBinary(helperPath)
	if err != nil {
		t.Fatal(err)
	}
	cmd := helperBinaryCommand(validated)
	if err := os.Rename(replacementPath, helperPath); err != nil {
		validated.Close()
		t.Fatal(err)
	}
	output, err := cmd.Output()
	validated.Close()
	if err != nil {
		t.Fatalf("run validated helper descriptor after pathname replacement: %v", err)
	}
	if got := strings.TrimSpace(string(output)); got != "VALIDATED" {
		t.Fatalf("helper output after replacing validated pathname = %q, want VALIDATED inode", got)
	}
}
