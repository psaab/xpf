package sysservices

import (
	"context"
	"os/exec"
	"strings"
	"time"

	"github.com/psaab/xpf/pkg/diagcmd"
)

// SSHDState is the observed operational state of the host ssh service.
type SSHDState uint8

const (
	// SSHDUnknown means the state could not be established.
	SSHDUnknown SSHDState = iota
	// SSHDRunning means systemd reports the sshd service active.
	SSHDRunning
	// SSHDStopped means neither the sshd service nor its activation socket serves.
	SSHDStopped
	// SSHDRunningSocketActivated means ssh.socket is listening and can activate
	// the loaded, inactive sshd service on demand.
	SSHDRunningSocketActivated
)

func (s SSHDState) String() string {
	switch s {
	case SSHDRunning:
		return "running"
	case SSHDRunningSocketActivated:
		return "running (socket-activated)"
	case SSHDStopped:
		return "stopped"
	default:
		return "unknown"
	}
}

// ProbeSSHDState observes sshd.service and, when it is inactive, ssh.socket.
// An active service is running; a loaded inactive service with a listening
// socket is socket-activated; a confirmed inactive/absent socket is stopped.
// It shares the diagnostic process budget and reports unknown when canceled,
// over budget, or systemd cannot establish a trustworthy state.
func ProbeSSHDState(ctx context.Context) SSHDState {
	if ctx == nil || ctx.Err() != nil {
		return SSHDUnknown
	}
	release, err := diagcmd.DefaultLimiter.Acquire()
	if err != nil {
		return SSHDUnknown
	}
	defer release()

	probeCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	serviceOut, err := systemdUnitState(probeCtx, "sshd.service")
	if err != nil {
		return SSHDUnknown
	}
	service, ok := parseSystemdUnitState(serviceOut)
	if !ok {
		return SSHDUnknown
	}
	if service.isRunning() {
		return SSHDRunning
	}
	if !service.isStopped() {
		return SSHDUnknown
	}

	socketOut, err := systemdUnitState(probeCtx, "ssh.socket")
	if err != nil {
		return SSHDUnknown
	}
	return parseSSHDUnitStates(serviceOut, socketOut)

}

func systemdUnitState(ctx context.Context, unit string) (string, error) {
	cmd := exec.CommandContext(ctx, "systemctl", "show", unit,
		"--property=LoadState", "--property=ActiveState", "--property=SubState", "--value")
	// Killing systemctl does not close stdout inherited by its children.
	// Cap Output's pipe-drain wait as well as the command deadline.
	cmd.WaitDelay = 500 * time.Millisecond
	out, err := cmd.Output()
	if err != nil {
		return "", err
	}
	return string(out), nil
}

type systemdUnitStatus struct {
	load   string
	active string
	sub    string
}

func parseSystemdUnitState(out string) (systemdUnitStatus, bool) {
	fields := strings.Fields(out)
	if len(fields) != 3 {
		return systemdUnitStatus{}, false
	}
	return systemdUnitStatus{load: fields[0], active: fields[1], sub: fields[2]}, true
}

func (u systemdUnitStatus) isRunning() bool {
	return u.load == "loaded" && u.active == "active"
}

func (u systemdUnitStatus) isStopped() bool {
	return (u.load == "loaded" || u.load == "masked") &&
		(u.active == "inactive" || u.active == "failed")
}

func (u systemdUnitStatus) isListening() bool {
	return u.load == "loaded" && u.active == "active" && u.sub == "listening"
}

func (u systemdUnitStatus) isStoppedOrAbsent() bool {
	if u.isStopped() {
		return true
	}
	return u.load == "not-found" && u.active == "inactive"
}

func parseSSHDUnitStates(serviceOut, socketOut string) SSHDState {
	service, ok := parseSystemdUnitState(serviceOut)
	if !ok {
		return SSHDUnknown
	}
	if service.isRunning() {
		return SSHDRunning
	}
	if !service.isStopped() {
		return SSHDUnknown
	}
	socket, ok := parseSystemdUnitState(socketOut)
	if !ok {
		return SSHDUnknown
	}
	if service.load == "loaded" && service.active == "inactive" && socket.isListening() {
		return SSHDRunningSocketActivated
	}
	if socket.isStoppedOrAbsent() {
		return SSHDStopped
	}
	return SSHDUnknown
}

// UnmanagedSSHLine formats the shared show-system-services SSH row when the
// service is not managed by xpf configuration.
func UnmanagedSSHLine(state SSHDState) string {
	line := "  SSH:            " + state.String() + " (not managed — no system services ssh"
	switch state {
	case SSHDRunning:
		line += "; sshd serves under base-image defaults"
	case SSHDRunningSocketActivated:
		line += "; ssh.socket listens under base-image defaults"
	}
	return line + ")"
}
