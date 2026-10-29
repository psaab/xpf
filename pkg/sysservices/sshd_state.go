package sysservices

import (
	"context"
	"os/exec"
	"strings"
	"time"
)

// SSHDState is the observed operational state of the host sshd unit.
type SSHDState uint8

const (
	// SSHDUnknown means the state could not be established.
	SSHDUnknown SSHDState = iota
	// SSHDRunning means systemd reports the sshd unit active.
	SSHDRunning
	// SSHDStopped means the loaded sshd unit is inactive or failed.
	SSHDStopped
)

func (s SSHDState) String() string {
	switch s {
	case SSHDRunning:
		return "running"
	case SSHDStopped:
		return "stopped"
	default:
		return "unknown"
	}
}

// ProbeSSHDState observes sshd's systemd unit state. Any inability to query
// systemd, unknown unit, or unexpected state is reported as unknown rather
// than assuming sshd is running or stopped.
func ProbeSSHDState() SSHDState {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "systemctl", "show", "sshd.service",
		"--property=LoadState", "--property=ActiveState", "--value")
	// Killing systemctl does not close stdout inherited by its children.
	// Cap Output's pipe-drain wait as well as the command deadline.
	cmd.WaitDelay = 500 * time.Millisecond
	out, err := cmd.Output()
	if err != nil {
		return SSHDUnknown
	}
	return parseSSHDUnitState(string(out))
}

func parseSSHDUnitState(out string) SSHDState {
	fields := strings.Fields(out)
	if len(fields) != 2 {
		return SSHDUnknown
	}
	loadState, activeState := fields[0], fields[1]
	if loadState == "loaded" && activeState == "active" {
		return SSHDRunning
	}
	if (loadState == "loaded" || loadState == "masked") &&
		(activeState == "inactive" || activeState == "failed") {
		return SSHDStopped
	}
	return SSHDUnknown
}

// UnmanagedSSHLine formats the shared show-system-services SSH row when the
// service is not managed by xpf configuration.
func UnmanagedSSHLine(state SSHDState) string {
	line := "  SSH:            " + state.String() + " (not managed — no system services ssh"
	if state == SSHDRunning {
		line += "; sshd serves under base-image defaults"
	}
	return line + ")"
}
