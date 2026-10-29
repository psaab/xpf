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
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
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
			s.showSystemServices(&buf)
			out := buf.String()
			if !strings.Contains(out, cell.want) {
				t.Errorf("gRPC unmanaged SSH row = %q, want substring %q (probe=%v)\nfull output:\n%s",
					sshRowLine(out), cell.want, cell.state, out)
			}
			// The row must never claim a state the probe did not observe.
			if cell.state != sysservices.SSHDRunning && strings.Contains(sshRowLine(out), "running") {
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
