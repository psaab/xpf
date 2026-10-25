package cli

// #16725: the local CLI twin of GetSystemInfo{boot-messages} forked the
// same unfiltered `journalctl --boot -n 100`, returning the whole
// system journal instead of kernel boot messages only. It must carry
// the kernel filter (-k/--dmesg) exactly like the gRPC handler.
//
// RED on revert: dropping -k from showSystemBootMessages in
// cli_show_system.go makes the recorded argv lose its kernel filter
// and this test fails.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func stageRecordingJournalctl16725(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	binDir := filepath.Join(dir, "bin")
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		t.Fatalf("mkdir fake journalctl dir: %v", err)
	}
	script := "#!/bin/sh\n" +
		"printf '%s\\n' \"$@\" > \"$FAKE_JOURNALCTL_ARGS\"\n" +
		"printf 'fake kernel boot line\\n'\n"
	if err := os.WriteFile(filepath.Join(binDir, "journalctl"), []byte(script), 0o755); err != nil {
		t.Fatalf("write fake journalctl: %v", err)
	}
	argsPath := filepath.Join(dir, "journalctl-args")
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("FAKE_JOURNALCTL_ARGS", argsPath)
	return argsPath
}

func TestShowSystemBootMessagesKernelOnly16725(t *testing.T) {
	argsPath := stageRecordingJournalctl16725(t)
	c := &CLI{}

	var callErr error
	out := captureStdout(t, func() {
		callErr = c.showSystemBootMessages()
	})
	if callErr != nil {
		t.Fatalf("showSystemBootMessages: %v", callErr)
	}
	if !strings.Contains(out, "fake kernel boot line") {
		t.Fatalf("showSystemBootMessages output = %q, want fake journalctl output", out)
	}
	raw, err := os.ReadFile(argsPath)
	if err != nil {
		t.Fatalf("fake journalctl was not invoked (no args file): %v", err)
	}
	args := strings.Fields(string(raw))
	hasKernel := false
	hasBoot := false
	for _, a := range args {
		if a == "-k" || a == "--dmesg" {
			hasKernel = true
		}
		if a == "-b" || a == "--boot" {
			hasBoot = true
		}
	}
	if !hasKernel {
		t.Fatalf("showSystemBootMessages journalctl argv = %v, want kernel-only filter (-k/--dmesg) (#16725)", args)
	}
	if !hasBoot {
		t.Fatalf("showSystemBootMessages journalctl argv = %v, want current-boot filter (-b/--boot)", args)
	}
}
