// #17770 regression tests: the unmanaged-SSH row must render the
// OBSERVED sshd state, never an unconditional "running".
//
// These tests reference sysservices.SSHDState and the server's sshdStateFn
// seam, which do not exist pre-fix, so the package fails to build RED.
// The probe is stubbed, so the test does not touch the host sshd.
//
// Fail-on-revert: reverting renderer wiring to the hardcoded "running"
// literal makes the stopped and unknown cells fail.

package grpcapi

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
	"github.com/psaab/xpf/pkg/sysservices"
)

func TestShowSystemUnmanagedSSHReportsObservedState17770(t *testing.T) {
	cells := []struct {
		name  string
		state sysservices.SSHDState
		want  string
	}{
		{"running observed", sysservices.SSHDRunning, "SSH:            running (not managed"},
		{"stopped observed", sysservices.SSHDStopped, "SSH:            stopped (not managed"},
		{"socket activated", sysservices.SSHDRunningSocketActivated, "SSH:            running (socket-activated)"},
		{"unknown observed", sysservices.SSHDUnknown, "SSH:            unknown (not managed"},
	}
	for _, cell := range cells {
		t.Run(cell.name, func(t *testing.T) {
			s := newActiveConfigServer(t)
			s.sshdStateFn = func() sysservices.SSHDState { return cell.state }
			cfg := s.store.ActiveConfig()
			if cfg == nil {
				t.Fatal("no active config")
			}
			cfg.System.Services = &config.SystemServicesConfig{}

			var buf strings.Builder
			s.showSystemServices(context.Background(), &buf)
			out := buf.String()
			if !strings.Contains(out, cell.want) {
				t.Errorf("gRPC unmanaged SSH row = %q, want substring %q (probe=%v)\nfull output:\n%s",
					sshRowLine(out), cell.want, cell.state, out)
			}
			// The row must never claim a state the probe did not observe.
			running := cell.state == sysservices.SSHDRunning || cell.state == sysservices.SSHDRunningSocketActivated
			if !running && strings.Contains(sshRowLine(out), "running") {
				t.Errorf("gRPC unmanaged SSH row claims running while probe=%v:\n%s", cell.state, out)
			}
			if cell.state != sysservices.SSHDStopped && strings.Contains(sshRowLine(out), "stopped") {
				t.Errorf("gRPC unmanaged SSH row claims stopped while probe=%v:\n%s", cell.state, out)
			}
		})
	}
}

// sshRowLine extracts the SSH row from show-system-services output.
func sshRowLine(out string) string {
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "SSH:") {
			return line
		}
	}
	return "<no SSH row>"
}

func TestShowSystemUnmanagedSSHRequestCancellationStopsProbe17770(t *testing.T) {
	dir := t.TempDir()
	marker := filepath.Join(dir, "systemctl-pid")
	fakeSystemctl := filepath.Join(dir, "systemctl")
	script := "#!/bin/sh\nprintf '%s\\n' \"$$\" > \"$XPF_SSHD_PID_MARKER\"\nexec sleep 30\n"
	if err := os.WriteFile(fakeSystemctl, []byte(script), 0o755); err != nil {
		t.Fatalf("write fake systemctl: %v", err)
	}
	t.Setenv("XPF_SSHD_PID_MARKER", marker)
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Cleanup(func() {
		data, err := os.ReadFile(marker)
		if err != nil {
			return
		}
		pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
		if err == nil {
			_ = syscall.Kill(pid, syscall.SIGKILL)
		}
	})

	s := newActiveConfigServer(t)
	s.sshdStateFn = nil
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	type result struct {
		response *pb.ShowTextResponse
		err      error
	}
	done := make(chan result, 1)
	go func() {
		response, err := s.ShowText(ctx, &pb.ShowTextRequest{Topic: "system-services"})
		done <- result{response: response, err: err}
	}()

	deadline := time.Now().Add(time.Second)
	for {
		if _, err := os.Stat(marker); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("systemctl probe did not start")
		}
		time.Sleep(5 * time.Millisecond)
	}
	data, err := os.ReadFile(marker)
	if err != nil {
		t.Fatalf("read systemctl pid: %v", err)
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil {
		t.Fatalf("parse systemctl pid: %v", err)
	}

	cancel()
	select {
	case got := <-done:
		if got.err != nil {
			t.Fatalf("ShowText after cancellation: %v", got.err)
		}
		if got.response == nil || !strings.Contains(got.response.GetOutput(), "SSH:            unknown (not managed") {
			t.Fatalf("canceled probe did not render unknown: %+v", got.response)
		}
	case <-time.After(time.Second):
		t.Fatal("ShowText did not return promptly after request cancellation")
	}

	deadline = time.Now().Add(time.Second)
	for {
		err := syscall.Kill(pid, 0)
		if errors.Is(err, syscall.ESRCH) {
			break
		}
		if err != nil {
			t.Fatalf("check canceled systemctl process %d: %v", pid, err)
		}
		if time.Now().After(deadline) {
			t.Fatalf("systemctl process %d survived request cancellation", pid)
		}
		time.Sleep(5 * time.Millisecond)
	}
}
