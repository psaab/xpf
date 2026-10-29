package sysservices

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/diagcmd"
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
	if got := ProbeSSHDState(context.Background()); got != SSHDUnknown {
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
	if got := ProbeSSHDState(context.Background()); got != SSHDUnknown {
		t.Fatalf("ProbeSSHDState() with no systemctl = %v, want unknown", got)
	}
}

func TestProbeSSHDDetectsSocketActivation17770(t *testing.T) {
	dir := t.TempDir()
	unitLog := filepath.Join(dir, "units")
	fakeSystemctl := filepath.Join(dir, "systemctl")
	script := "#!/bin/sh\n" +
		"printf '%s\\n' \"$2\" >> \"$XPF_SSHD_UNIT_LOG\"\n" +
		"case \"$2\" in\n" +
		"  sshd.service) printf 'loaded\\ninactive\\ndead\\n' ;;\n" +
		"  ssh.socket) printf 'loaded\\nactive\\nlistening\\n' ;;\n" +
		"  *) exit 1 ;;\n" +
		"esac\n"
	if err := os.WriteFile(fakeSystemctl, []byte(script), 0o755); err != nil {
		t.Fatalf("write fake systemctl: %v", err)
	}
	t.Setenv("XPF_SSHD_UNIT_LOG", unitLog)
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))

	if got := ProbeSSHDState(context.Background()); got != SSHDRunningSocketActivated {
		t.Fatalf("ProbeSSHDState() = %v, want socket-activated running", got)
	}
	if got, err := os.ReadFile(unitLog); err != nil || string(got) != "sshd.service\nssh.socket\n" {
		t.Fatalf("systemctl units = %q, err=%v; want service then activation socket", got, err)
	}
}
func TestProbeSSHDConcurrentCallsShareDiagnosticBudget17770(t *testing.T) {
	dir := t.TempDir()
	runningDir := filepath.Join(dir, "running")
	startedDir := filepath.Join(dir, "started")
	for _, path := range []string{runningDir, startedDir} {
		if err := os.Mkdir(path, 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", path, err)
		}
	}
	fakeSystemctl := filepath.Join(dir, "systemctl")
	script := "#!/bin/sh\n" +
		"pid=$$\n" +
		"touch \"$XPF_SSHD_RUNNING_DIR/$pid\"\n" +
		"touch \"$XPF_SSHD_STARTED_DIR/$pid\"\n" +
		"sleep 0.3\n" +
		"rm -f \"$XPF_SSHD_RUNNING_DIR/$pid\"\n" +
		"printf 'loaded\\nactive\\nrunning\\n'\n"
	if err := os.WriteFile(fakeSystemctl, []byte(script), 0o755); err != nil {
		t.Fatalf("write fake systemctl: %v", err)
	}
	t.Setenv("XPF_SSHD_RUNNING_DIR", runningDir)
	t.Setenv("XPF_SSHD_STARTED_DIR", startedDir)
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))

	const requests = 8
	start := make(chan struct{})
	results := make(chan SSHDState, requests)
	for range requests {
		go func() {
			<-start
			results <- ProbeSSHDState(context.Background())
		}()
	}

	stopMonitor := make(chan struct{})
	var monitor sync.WaitGroup
	var maxProcesses int
	monitor.Add(1)
	go func() {
		defer monitor.Done()
		ticker := time.NewTicker(time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-stopMonitor:
				return
			case <-ticker.C:
				entries, err := os.ReadDir(runningDir)
				if err == nil && len(entries) > maxProcesses {
					maxProcesses = len(entries)
				}
			}
		}
	}()

	close(start)
	running, unknown, unexpected := 0, 0, 0
	for range requests {
		switch <-results {
		case SSHDRunning:
			running++
		case SSHDUnknown:
			unknown++
		default:
			unexpected++
		}
	}
	close(stopMonitor)
	monitor.Wait()

	started, err := os.ReadDir(startedDir)
	if err != nil {
		t.Fatalf("read started probes: %v", err)
	}

	if unexpected != 0 {
		t.Fatalf("received %d unexpected probe states", unexpected)
	}
	cap := diagcmd.DefaultLimiter.Cap()
	if maxProcesses > cap {
		t.Fatalf("max concurrent systemctl processes = %d, diagnostic budget = %d", maxProcesses, cap)
	}
	if len(started) != cap || running != cap || unknown != requests-cap {
		t.Fatalf("started=%d running=%d unknown=%d, want exactly %d admitted probes of %d requests",
			len(started), running, unknown, cap, requests)
	}
}
