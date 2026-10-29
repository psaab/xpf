// #17770 regression: the unmanaged-SSH row must render the OBSERVED
// sshd state, never an unconditional "running".
//
// These tests reference sysservices.SSHDState and the CLI's sshdStateFn
// seam, which do not exist pre-fix, so the package fails to build RED.
// The probe is stubbed, keeping tests independent of the host sshd.
//
// Fail-on-revert: reverting renderer wiring to the hardcoded "running"
// literal makes the stopped and unknown cells fail.
package cli

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
		{"socket activated", sysservices.SSHDRunningSocketActivated, "SSH:            running (socket-activated)"},
		{"unknown observed", sysservices.SSHDUnknown, "SSH:            unknown (not managed"},
	}
	for _, cell := range cells {
		t.Run(cell.name, func(t *testing.T) {
			c := newCLIActiveConfigStore(t)
			c.sshdStateFn = func() sysservices.SSHDState { return cell.state }
			cfg := c.store.ActiveConfig()
			cfg.System.Services = &config.SystemServicesConfig{}

			var runErr error
			out := captureStdout(t, func() { runErr = c.showSystemServices() })
			if runErr != nil {
				t.Fatalf("showSystemServices(): %v", runErr)
			}
			row := sshRowLine17770(out)
			if !strings.Contains(row, cell.want) {
				t.Errorf("CLI unmanaged SSH row = %q, want substring %q (probe=%v)\nfull output:\n%s",
					row, cell.want, cell.state, out)
			}
			running := cell.state == sysservices.SSHDRunning || cell.state == sysservices.SSHDRunningSocketActivated
			if !running && strings.Contains(row, "running") {
				t.Errorf("CLI unmanaged SSH row claims running while probe=%v: %s", cell.state, row)
			}
		})
	}
}

func sshRowLine17770(out string) string {
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "SSH:") {
			return line
		}
	}
	return "<no SSH row>"
}
