package sysservices

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestProbeSSHDWaitDelay17770(t *testing.T) {
	dir := t.TempDir()
	started := filepath.Join(dir, "started")
	fakeSystemctl := filepath.Join(dir, "systemctl")
	script := "#!/bin/sh\nprintf started > \"$XPF_SSHD_PROBE_MARKER\"\nsleep 5 &\nwait\n"
	if err := os.WriteFile(fakeSystemctl, []byte(script), 0o755); err != nil {
		t.Fatalf("write fake systemctl: %v", err)
	}
	t.Setenv("XPF_SSHD_PROBE_MARKER", started)
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))

	began := time.Now()
	if got := ProbeSSHDState(); got != SSHDUnknown {
		t.Fatalf("ProbeSSHDState() = %v, want unknown for the timed-out command", got)
	}
	elapsed := time.Since(began)
	if _, err := os.Stat(started); err != nil {
		t.Fatalf("fake systemctl did not start: %v", err)
	}
	if elapsed > 4*time.Second {
		t.Fatalf("ProbeSSHDState() took %v; context deadline plus WaitDelay should bound inherited-pipe wait", elapsed)
	}
}

func TestProbeSSHDMissingSystemctl17770(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	if got := ProbeSSHDState(); got != SSHDUnknown {
		t.Fatalf("ProbeSSHDState() with no systemctl = %v, want unknown", got)
	}
}
