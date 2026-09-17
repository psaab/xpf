package nfqueue

import (
	"errors"
	"fmt"
	"sync/atomic"

	"golang.org/x/sys/unix"
)

// TunSink is a measurement-only /dev/net/tun byte sink. It exists to price
// the TUN-write leg of Phase 0 memory and throughput experiments. It is NOT an
// adjudicated re-entry path: no generation, mark, route or policy semantics
// are attached. The r4 section 4.5 SO_MARK-on-TUN proposal is explicitly not
// implemented.
type TunSink struct {
	fd   int
	name string

	closed   atomic.Bool
	attempts atomic.Uint64
	written  atomic.Uint64
	bytes    atomic.Uint64
}

// OpenTunSink creates a non-persistent TUN device with no packet-information
// header. The caller owns the device lifetime; Close removes it when the
// descriptor is closed. Name must fit Linux IFNAMSIZ-1 bytes.
func OpenTunSink(name string) (*TunSink, error) {
	if name == "" {
		name = "xpf9506"
	}
	ifr, err := unix.NewIfreq(name)
	if err != nil {
		return nil, fmt.Errorf("nfqueue: tun name %q: %w", name, err)
	}
	ifr.SetUint16(unix.IFF_TUN | unix.IFF_NO_PI)
	fd, err := unix.Open("/dev/net/tun", unix.O_RDWR|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("nfqueue: open /dev/net/tun: %w", err)
	}
	if err := unix.IoctlIfreq(fd, unix.TUNSETIFF, ifr); err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("nfqueue: TUNSETIFF %q: %w", name, err)
	}
	return &TunSink{fd: fd, name: ifr.Name()}, nil
}

// Name returns the kernel-assigned TUN interface name.
func (s *TunSink) Name() string { return s.name }

// WriteFrame writes one complete L3 frame to the TUN descriptor. EAGAIN is
// returned rather than blocking so a saturated sink is observable and
// fail-closed by the measurement caller. The input is not retained.
func (s *TunSink) WriteFrame(frame []byte) (int, error) {
	if s.closed.Load() {
		return 0, ErrClosed
	}
	if len(frame) == 0 {
		return 0, errors.New("nfqueue: empty TUN frame")
	}
	s.attempts.Add(1)
	n, err := unix.Write(s.fd, frame)
	if n > 0 {
		s.written.Add(1)
		s.bytes.Add(uint64(n))
	}
	if err != nil {
		return n, fmt.Errorf("nfqueue: TUN write: %w", err)
	}
	if n != len(frame) {
		return n, fmt.Errorf("nfqueue: short TUN write: %d/%d", n, len(frame))
	}
	return n, nil
}

// Attempts returns the number of WriteFrame calls that reached the descriptor.
func (s *TunSink) Attempts() uint64 { return s.attempts.Load() }

// FramesWritten returns successful complete frame writes.
func (s *TunSink) FramesWritten() uint64 { return s.written.Load() }

// BytesWritten returns bytes accepted by the TUN descriptor.
func (s *TunSink) BytesWritten() uint64 { return s.bytes.Load() }

// Close is idempotent. Closing the descriptor removes this non-persistent TUN
// device and causes later writes to return ErrClosed.
func (s *TunSink) Close() error {
	if !s.closed.CompareAndSwap(false, true) {
		return nil
	}
	return unix.Close(s.fd)
}
