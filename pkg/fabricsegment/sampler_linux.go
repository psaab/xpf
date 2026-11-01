//go:build linux

package fabricsegment

import (
	"context"
	"errors"
	"log/slog"
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
// frames never reach an AF_PACKET tap.
func runTapSampler(ctx context.Context, link Link, tracker *Tracker) {
	fd, err := openTap(link)
	if err != nil {
		slog.Warn("fabric segment: cannot open the fabric tap; non-peer source MACs are not watched (#18719)",
			"fabric", link.Name, "parent", link.Parent, "err", err)
		return
	}
	defer unix.Close(fd)
	readTap(ctx, fd, link, tracker)
}

// readTap feeds every frame the bound tap fd receives into tracker until ctx
// is done or the read fails. It does not close fd.
func readTap(ctx context.Context, fd int, link Link, tracker *Tracker) {
	go func() {
		<-ctx.Done()
		// Unblock a pending read promptly; the receive timeout below is the
		// backstop.
		_ = unix.Shutdown(fd, unix.SHUT_RD)
	}()
	buf := make([]byte, snapLen)
	windowStart := time.Now()
	inWindow := 0
	for ctx.Err() == nil {
		n, _, err := unix.Recvfrom(fd, buf, 0)
		now := time.Now()
		if err != nil {
			if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EINTR) {
				tracker.Tick(now)
				continue
			}
			if ctx.Err() == nil {
				slog.Warn("fabric segment: fabric tap read failed; watcher stopped (#18719)",
					"fabric", link.Name, "parent", link.Parent, "err", err)
			}
			return
		}
		tracker.ObserveFrame(buf[:n], now)
		if now.Sub(windowStart) >= time.Second {
			windowStart, inWindow = now, 0
			tracker.Tick(now)
		}
		inWindow++
		if inWindow >= maxFramesPerSecond {
			select {
			case <-ctx.Done():
				return
			case <-time.After(time.Second - now.Sub(windowStart)):
			}
		}
	}
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
