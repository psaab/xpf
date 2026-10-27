package nfqueue

// Test-only measurement sink (#17045): retained solely for measure tests.

import (
	"errors"
	"fmt"
	"sync/atomic"
	"time"
	"unsafe"

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

// verdictBatchForMeasure disposes a batch with one sendmmsg (test-only,
// #17045). Contract is transport all-or-error: a failed sendmmsg returns
// an error and counts it; the kernel applies each datagram independently,
// so a partial transport failure may dispose a prefix. The error reports
// how far the transport got; the suffix is terminal-but-uncertain and
// must be reconciled by the supervisor rather than retried.
func (q *Queue) verdictBatchForMeasure(v Verdict, pkts []*Packet) error {
	if len(pkts) == 0 {
		return nil
	}
	if v != VerdictAccept && v != VerdictDrop {
		q.verdictErrors.Add(uint64(len(pkts)))
		return fmt.Errorf("nfqueue: unsupported verdict %d", v)
	}
	if err := q.acquireSend(); err != nil {
		for _, pkt := range pkts {
			if pkt != nil && pkt.q == q {
				pkt.done.CompareAndSwap(false, true)
			}
		}
		q.verdictUncertain.Add(uint64(len(pkts)))
		return err
	}
	defer q.releaseSend()
	q.mu.Lock()
	if q.closed {
		q.mu.Unlock()
		q.verdictErrors.Add(uint64(len(pkts)))
		return ErrClosed
	}
	seen := make(map[*Packet]struct{}, len(pkts))
	for _, pkt := range pkts {
		if pkt == nil || pkt.q != q || pkt.done.Load() {
			q.mu.Unlock()
			q.verdictErrors.Add(1)
			return ErrAlreadyVerdicted
		}
		if _, ok := seen[pkt]; ok {
			q.mu.Unlock()
			q.verdictErrors.Add(1)
			return ErrAlreadyVerdicted
		}
		seen[pkt] = struct{}{}
	}
	for _, pkt := range pkts {
		if !pkt.done.CompareAndSwap(false, true) {
			q.mu.Unlock()
			q.verdictErrors.Add(1)
			return ErrAlreadyVerdicted
		}
	}
	q.mu.Unlock()
	msgs := make([]testLinuxMmsghdr, len(pkts))
	iovs := make([]unix.Iovec, len(pkts))
	bufs := make([][]byte, len(pkts))
	for i, pkt := range pkts {
		bufs[i] = buildVerdict(q.ID(), pkt.id, uint32(v))
		iovs[i] = unix.Iovec{Base: &bufs[i][0], Len: uint64(len(bufs[i]))}
		msgs[i].msg.Iov = &iovs[i]
		msgs[i].msg.Iovlen = 1
	}
	q.verdictAttempted.Add(uint64(len(pkts)))
	n, err := testSendmmsg(q.fd, msgs)
	sent := n
	if sent < 0 {
		sent = 0
	}
	if sent > len(pkts) {
		sent = len(pkts)
	}
	now := time.Now().UnixNano()
	for i := 0; i < sent; i++ {
		pkts[i].verdictAt.CompareAndSwap(0, now)
	}
	q.verdictSuccessful.Add(uint64(sent))
	q.verdictUncertain.Add(uint64(len(pkts) - sent))
	switch v {
	case VerdictAccept:
		q.accepted.Add(uint64(sent))
	case VerdictDrop:
		q.dropped.Add(uint64(sent))
	}
	if err != nil {
		q.verdictErrors.Add(uint64(len(pkts) - sent))
		if err == unix.EAGAIN || err == unix.EWOULDBLOCK {
			return fmt.Errorf("%w: batch verdict %s: sent %d/%d: %w", ErrVerdictTimeout, v, sent, len(pkts), err)
		}
		return fmt.Errorf("nfqueue: batch verdict %s: sent %d/%d: %w", v, sent, len(pkts), err)
	}
	if sent != len(pkts) {
		q.verdictErrors.Add(uint64(len(pkts) - sent))
		return fmt.Errorf("%w: batch verdict %s: sent %d/%d (short send)", ErrVerdictTimeout, v, sent, len(pkts))
	}
	return nil
}

// testLinuxMmsghdr mirrors Linux's struct mmsghdr ABI for testSendmmsg.
type testLinuxMmsghdr struct {
	msg unix.Msghdr
	len uint32
	_   uint32
}

func testSendmmsg(fd int, msgs []testLinuxMmsghdr) (int, error) {
	if len(msgs) == 0 {
		return 0, nil
	}
	r1, _, errno := unix.Syscall6(unix.SYS_SENDMMSG, uintptr(fd),
		uintptr(unsafe.Pointer(&msgs[0])), uintptr(len(msgs)), 0, 0, 0)
	if errno != 0 {
		return int(r1), errno
	}
	return int(r1), nil
}
