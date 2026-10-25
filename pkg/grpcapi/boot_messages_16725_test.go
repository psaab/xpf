package grpcapi

// #16725: GetSystemInfo{boot-messages} is PermView, but it forked
// `journalctl --boot -n 100` — the whole system journal, read as root.
// That handed sshd/sudo/other-daemon log text to view-only classes,
// contradicting #4860 and the Junos contract (kernel boot messages
// only, i.e. /var/run/dmesg.boot). The handler must ask journalctl
// for kernel messages only (-k/--dmesg).
//
// RED on revert: dropping -k from the boot-messages argv in
// server_show_status.go makes the recorded argv lose its kernel
// filter and this test fails.

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
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

func TestGetSystemInfoBootMessagesKernelOnly16725(t *testing.T) {
	argsPath := stageRecordingJournalctl16725(t)
	s := newDiagForkServer(t)

	resp, err := s.GetSystemInfo(context.Background(), &pb.GetSystemInfoRequest{Type: "boot-messages"})
	if err != nil {
		t.Fatalf("GetSystemInfo{boot-messages}: %v", err)
	}
	if !strings.Contains(resp.Output, "fake kernel boot line") {
		t.Fatalf("GetSystemInfo{boot-messages} output = %q, want fake journalctl output", resp.Output)
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
		t.Fatalf("GetSystemInfo{boot-messages} journalctl argv = %v, want kernel-only filter (-k/--dmesg) (#16725: unfiltered --boot leaks the whole system journal to PermView)", args)
	}
	if !hasBoot {
		t.Fatalf("GetSystemInfo{boot-messages} journalctl argv = %v, want current-boot filter (-b/--boot)", args)
	}
}
