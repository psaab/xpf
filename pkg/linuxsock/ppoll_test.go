package linuxsock

import (
	"errors"
	"runtime"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// TestPpollRecvWakesOnSignalStop17231: a Recv parked in the real ppoll
// path on a silent socketpair returns ErrWakeStopped promptly after
// SignalStop, without the socket fd being closed.
func TestPpollRecvWakesOnSignalStop17231(t *testing.T) {
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET, 0)
	if err != nil {
		t.Fatalf("socketpair: %v", err)
	}
	defer unix.Close(fds[1])
	wakeFD, err := unix.Eventfd(0, unix.EFD_NONBLOCK|unix.EFD_CLOEXEC)
	if err != nil {
		unix.Close(fds[0])
		t.Fatalf("eventfd: %v", err)
	}
	p := NewPpollRecvForTest(fds[0], wakeFD)
	defer p.Close()

	done := make(chan error, 1)
	go func() {
		buf := make([]byte, 64)
		_, _, err := p.Recv(buf)
		done <- err
	}()
	runtime.Gosched()
	select {
	case err := <-done:
		t.Fatalf("Recv returned before SignalStop: %v", err)
	default:
	}
	start := time.Now()
	p.SignalStop()
	p.SignalStop() // idempotent
	select {
	case err := <-done:
		if !errors.Is(err, ErrWakeStopped) {
			t.Fatalf("Recv err = %v, want ErrWakeStopped", err)
		}
		if elapsed := time.Since(start); elapsed > 100*time.Millisecond {
			t.Fatalf("wake took %v, want <100ms (#17231)", elapsed)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Recv did not wake within 2s after SignalStop")
	}
	// Idempotent close must not panic / double-close.
	p.Close()
}
