package linuxsock

import (
	"encoding/binary"
	"errors"
	"sync"

	"golang.org/x/sys/unix"
)

// ErrWakeStopped is returned by PpollRecv.Recv when SignalStop has
// fired the wake eventfd. Callers map it (via their own context or
// stopped state) to a clean exit; it never indicates a socket error.
var ErrWakeStopped = errors.New("linuxsock: recv stopped by wake eventfd")

// PpollRecv is the shared cancellable raw-receive primitive (#17231).
//
// A bare blocking unix.Recvfrom on an AF_PACKET fd cannot be woken by
// close(2) on Linux: the in-flight syscall holds its own reference to
// the old file description and stays parked until a frame arrives,
// and the freed fd number can be reused by an unrelated socket which
// the parked recv then reads from (the LLDP #16669 hang and the
// proxy-ARP #17231 stale-reply defect are the two copies of this).
//
// PpollRecv instead ppolls on {fd, wakeFD}: Recv waits until fd is
// readable or SignalStop writes the wake eventfd, then reads exactly
// one frame. The socket itself is closed only by Close, which owners
// must call AFTER joining the goroutine parked in Recv
// (signal → join → close), so no recv is ever in flight on a closed
// or reused fd. fd stays blocking: ppoll guarantees readability
// before Recvfrom, so the read itself does not park.
//
// The recvFn seam replaces the real ppoll/Recvfrom for deterministic
// tests of owners' loop handling without a real socket.
type PpollRecv struct {
	fd     int
	wakeFD int
	recvFn func(buf []byte) (int, unix.Sockaddr, error)

	wakeOnce  sync.Once
	closeOnce sync.Once
}

// NewPpollRecv wraps fd (already opened via Socket and bound by the
// caller) with a wake eventfd. On error fd is NOT closed; the caller
// retains ownership.
func NewPpollRecv(fd int) (*PpollRecv, error) {
	wakeFD, err := unix.Eventfd(0, unix.EFD_NONBLOCK|unix.EFD_CLOEXEC)
	if err != nil {
		return nil, err
	}
	return &PpollRecv{fd: fd, wakeFD: wakeFD}, nil
}

// NewPpollRecvForTest builds a PpollRecv over caller-owned fds for
// tests that drive the real ppoll path against e.g. a socketpair.
// Close closes both fds (deduplicated), SignalStop writes wakeFD.
func NewPpollRecvForTest(fd, wakeFD int) *PpollRecv {
	return &PpollRecv{fd: fd, wakeFD: wakeFD}
}

// AttachRecvFnForTest replaces the real ppoll/Recvfrom path. For
// tests only; production leaves it unset.
func (p *PpollRecv) AttachRecvFnForTest(fn func(buf []byte) (int, unix.Sockaddr, error)) {
	p.recvFn = fn
}

// FD returns the wrapped socket fd, for Sendto by the owner. It is
// valid until Close; owners must not use it after joining + Close.
func (p *PpollRecv) FD() int { return p.fd }

// WakeFD returns the wake eventfd (tests / diagnostics).
func (p *PpollRecv) WakeFD() int { return p.wakeFD }

// Recv blocks in ppoll on {fd, wakeFD} until a frame is readable or
// SignalStop fires, then reads exactly one frame with Recvfrom. If
// both are ready the frame wins — the wake is level-triggered on the
// eventfd counter, so no wakeup is lost; owners must re-check their
// context/stopped state after every successful Recv before acting on
// the frame. Returns ErrWakeStopped when the wake fires first.
func (p *PpollRecv) Recv(buf []byte) (int, unix.Sockaddr, error) {
	if p.recvFn != nil {
		return p.recvFn(buf)
	}
	for {
		fds := []unix.PollFd{
			{Fd: int32(p.fd), Events: unix.POLLIN},
			{Fd: int32(p.wakeFD), Events: unix.POLLIN},
		}
		_, err := unix.Ppoll(fds, nil, nil)
		if err != nil {
			if err == unix.EINTR {
				continue
			}
			return 0, nil, err
		}
		if fds[0].Revents&unix.POLLIN != 0 {
			break
		}
		if fds[1].Revents&(unix.POLLIN|unix.POLLHUP|unix.POLLERR) != 0 {
			return 0, nil, ErrWakeStopped
		}
		// Spurious wakeup with neither fd readable: poll again.
	}
	return unix.Recvfrom(p.fd, buf, 0)
}

// SignalStop wakes a Recv parked in ppoll. It is idempotent and
// non-blocking. Receivers built without a wake fd (wakeFD <= 0, e.g.
// recvFn stubs) skip the write.
func (p *PpollRecv) SignalStop() {
	if p.wakeFD <= 0 {
		return
	}
	p.wakeOnce.Do(func() {
		var b [8]byte
		binary.LittleEndian.PutUint64(b[:], 1)
		_, _ = unix.Write(p.wakeFD, b[:])
	})
}

// Close releases the socket and the wake eventfd. It is idempotent.
// It MUST only run after the goroutine parked in Recv has returned
// (signal → join → close): closing fd while a Recvfrom is parked on
// it does not wake that syscall and frees the fd number for reuse
// under the parked reader.
func (p *PpollRecv) Close() {
	p.closeOnce.Do(func() {
		unix.Close(p.fd)
		if p.wakeFD > 0 && p.wakeFD != p.fd {
			unix.Close(p.wakeFD)
		}
	})
}
