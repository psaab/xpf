package snmp

import (
	"fmt"
	"syscall"

	"golang.org/x/sys/unix"
)

// snmpVRFSocketControl scopes a newly-created UDP socket to its VRF before
// bind/connect. An empty device leaves the socket in the process-default
// routing context.
func snmpVRFSocketControl(device string) func(string, string, syscall.RawConn) error {
	if device == "" {
		return nil
	}
	return func(_, _ string, raw syscall.RawConn) error {
		var socketErr error
		if err := raw.Control(func(fd uintptr) {
			socketErr = unix.SetsockoptString(int(fd), unix.SOL_SOCKET, unix.SO_BINDTODEVICE, device)
		}); err != nil {
			return fmt.Errorf("snmp: bind socket to VRF device %q: %w", device, err)
		}
		if socketErr != nil {
			return fmt.Errorf("snmp: bind socket to VRF device %q: %w", device, socketErr)
		}
		return nil
	}
}
