package cluster

import (
	"testing"

	"golang.org/x/sys/unix"
)

// TestHeartbeatSocketIsBoundToTheRequestedDevice12168 inspects the live
// receiver socket after StartHeartbeat succeeds, proving SO_BINDTODEVICE was
// applied rather than merely recording the requested device.
func TestHeartbeatSocketIsBoundToTheRequestedDevice12168(t *testing.T) {
	m := NewManager(0, 1)
	t.Cleanup(m.StopHeartbeat)

	if err := m.StartHeartbeat("127.0.0.1", "127.0.0.1", "lo", "lo"); err != nil {
		t.Fatalf("start heartbeat bound to loopback: %v", err)
	}
	if !m.HeartbeatRunning() {
		t.Fatal("heartbeat was not running after a successful socket bind")
	}

	m.mu.RLock()
	receiver := m.hbReceiver
	if receiver == nil {
		m.mu.RUnlock()
		t.Fatal("heartbeat receiver was not published")
	}
	conn := receiver.conn
	m.mu.RUnlock()
	raw, err := conn.SyscallConn()
	if err != nil {
		t.Fatalf("get heartbeat receiver socket: %v", err)
	}
	var boundDevice string
	var sockErr error
	if err := raw.Control(func(fd uintptr) {
		boundDevice, sockErr = unix.GetsockoptString(int(fd), unix.SOL_SOCKET, unix.SO_BINDTODEVICE)
	}); err != nil {
		t.Fatalf("inspect heartbeat receiver socket: %v", err)
	}
	if sockErr != nil {
		t.Fatalf("read SO_BINDTODEVICE: %v", sockErr)
	}
	if boundDevice != "lo" {
		t.Fatalf("heartbeat receiver SO_BINDTODEVICE = %q, want lo", boundDevice)
	}
}
