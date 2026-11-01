//go:build linux

package fabricsegment

import (
	"context"
	"errors"
	"fmt"
	"time"

	"golang.org/x/sys/unix"
)

// maxFramesPerSecond caps how many accepted frames the reader handles per
// second. Past it the reader sleeps out the second and the kernel drops the
// excess at the socket: a source-MAC storm can raise the alarm but cannot
// turn the watcher into a CPU sink.
const maxFramesPerSecond = 1000

// runTapSampler opens an AF_PACKET tap on the fabric parent and feeds every
// frame the knownSourceFilter accepts into tracker until ctx is done. It
// only sees kernel-path frames (what the XDP shim passes); AF_XDP fast-path
// frames never reach an AF_PACKET tap. It returns nil when ctx ended it and
// the error otherwise; the Monitor restarts it with backoff.
func runTapSampler(ctx context.Context, link Link, tracker *Tracker) error {
	fd, err := openTap(link)
	if err != nil {
		return fmt.Errorf("open the fabric tap on %s: %w", link.Parent, err)
	}
	defer unix.Close(fd)
	if err := readTap(ctx, fd, tracker); err != nil {
		return fmt.Errorf("read the fabric tap on %s: %w", link.Parent, err)
	}
	return nil
}

// readTap feeds every frame the bound tap fd receives into tracker until ctx
// is done (nil) or a read fails for good (the error). It starts no goroutine
// and never touches fd after it returns: a cancel is noticed within the 1 s
// SO_RCVTIMEO. (#18751 review: a goroutine that shut the fd down on cancel
// could hit an unrelated socket that had reused the fd number after the
// reader closed it, and AF_PACKET does not implement shutdown anyway.)
//
// ENETDOWN is transient. The kernel reports it once on a socket bound to a
// parent that went down (or was down at bind) and re-hooks the socket when
// the parent comes back up, so the reader keeps reading and ticking. An
// UNREGISTERED parent is not transient: the kernel also reports ENETDOWN,
// but unbinds the socket (ifindex -1) and never re-hooks it, and a parent
// deleted while already down unbinds it with no error at all. So on every
// ENETDOWN and every receive timeout the reader checks the binding and
// returns errParentGone; the Monitor then shows the link as not running and
// retries until the fabric refresh re-keys it (#18751 review).
func readTap(ctx context.Context, fd int, tracker *Tracker) error {
	buf := make([]byte, snapLen)
	windowStart := time.Now()
	inWindow := 0
	for ctx.Err() == nil {
		n, _, err := unix.Recvfrom(fd, buf, 0)
		now := time.Now()
		if err != nil {
			if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EINTR) || errors.Is(err, unix.ENETDOWN) {
				if tapUnbound(fd) {
					return errParentGone
				}
				tracker.Tick(now)
				continue
			}
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		tracker.ObserveFrame(buf[:n], now)
		if now.Sub(windowStart) >= time.Second {
			windowStart, inWindow = now, 0
			tracker.Tick(now)
		}
		inWindow++
		if inWindow >= maxFramesPerSecond {
			t := time.NewTimer(time.Second - now.Sub(windowStart))
			select {
			case <-ctx.Done():
				t.Stop()
				return nil
			case <-t.C:
			}
		}
	}
	return nil
}

// errParentGone stops a reader whose fabric parent was unregistered.
var errParentGone = errors.New("the fabric parent was unregistered; the tap is no longer bound")

// tapUnbound reports whether the kernel unbound the tap from its parent
// (packet_notifier sets the socket's ifindex to -1 on NETDEV_UNREGISTER).
func tapUnbound(fd int) bool {
	sa, err := unix.Getsockname(fd)
	if err != nil {
		return false
	}
	ll, ok := sa.(*unix.SockaddrLinklayer)
	return ok && ll.Ifindex == -1
}

func openTap(link Link) (int, error) {
	fd, err := newFilteredTap(link)
	if err != nil {
		return -1, err
	}
	if err := bindTap(fd, link); err != nil {
		unix.Close(fd)
		return -1, err
	}
	return fd, nil
}

// newFilteredTap creates the tap socket with protocol 0 and attaches the
// filter. Protocol 0 matters: an AF_PACKET socket created with ETH_P_ALL
// starts queueing frames from EVERY interface at socket(), before the filter
// is attached and before bind narrows it to the fabric parent, so a WAN
// frame from an arbitrary source could raise a false alarm at startup. With
// protocol 0 nothing is queued until bindTap names both the protocol and the
// interface.
func newFilteredTap(link Link) (int, error) {
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return -1, err
	}
	fail := func(err error) (int, error) {
		unix.Close(fd)
		return -1, err
	}
	prog, err := knownSourceFilter(link.LocalMAC, link.PeerMAC)
	if err != nil {
		return fail(err)
	}
	filter := make([]unix.SockFilter, len(prog))
	for i, ins := range prog {
		filter[i] = unix.SockFilter{Code: ins.Op, Jt: ins.Jt, Jf: ins.Jf, K: ins.K}
	}
	if err := unix.SetsockoptSockFprog(fd, unix.SOL_SOCKET, unix.SO_ATTACH_FILTER,
		&unix.SockFprog{Len: uint16(len(filter)), Filter: &filter[0]}); err != nil {
		return fail(err)
	}
	// This node's own transmissions are not evidence; best-effort on kernels
	// without the option (the filter drops our source MAC anyway).
	_ = unix.SetsockoptInt(fd, unix.SOL_PACKET, unix.PACKET_IGNORE_OUTGOING, 1)
	if err := unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &unix.Timeval{Sec: 1}); err != nil {
		return fail(err)
	}
	return fd, nil
}

// bindTap starts reception: ETH_P_ALL on the fabric parent only.
func bindTap(fd int, link Link) error {
	return unix.Bind(fd, &unix.SockaddrLinklayer{Protocol: htons(unix.ETH_P_ALL), Ifindex: link.ParentIfindex})
}

func htons(v uint16) uint16 { return v<<8 | v>>8 }
