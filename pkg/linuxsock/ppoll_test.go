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

// TestPpollRecvConsumesRXErrorReadiness17692: POLLERR-only readiness on
// the RX fd must break to Recvfrom (which surfaces the pending socket
// error) instead of looping in ppoll. The fake poll records its call
// count; more than one call means the loop spun.
func TestPpollRecvConsumesRXErrorReadiness17692(t *testing.T) {
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET, 0)
	if err != nil {
		t.Fatalf("socketpair: %v", err)
	}
	defer unix.Close(fds[0])
	defer unix.Close(fds[1])
	wakeFD, err := unix.Eventfd(0, unix.EFD_NONBLOCK|unix.EFD_CLOEXEC)
	if err != nil {
		t.Fatalf("eventfd: %v", err)
	}
	p := NewPpollRecvForTest(fds[0], wakeFD)
	defer p.Close()
	calls := 0
	p.AttachPollFnForTest(func(fds []unix.PollFd, timeout *unix.Timespec, sigmask *unix.Sigset_t) (int, error) {
		calls++
		fds[0].Revents = unix.POLLERR
		return 1, nil
	})
	// No data queued: Recvfrom on the empty socketpair returns EAGAIN,
	// which is the error surfacing this test wants (not a spin, not nil).
	unix.SetNonblock(fds[0], true)
	buf := make([]byte, 64)
	_, _, recvErr := p.Recv(buf)
	if recvErr == nil {
		t.Fatal("Recv returned nil error on POLLERR-only readiness with no data")
	}
	if calls != 1 {
		t.Fatalf("ppoll called %d times, want exactly 1 (no busy-spin)", calls)
	}
}
