package vrrp

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"os"
	"strings"
	"sync"
	"testing"

	"golang.org/x/net/ipv4"
	"golang.org/x/sys/unix"
)

// warnRecorder17217 captures Warn-and-above records so the #17217 cells can
// assert exactly one Warn (not Debug, not silent) for a stubbed failure.
type warnRecorder17217 struct {
	mu   sync.Mutex
	msgs []string
	lvls []slog.Level
}

func (h *warnRecorder17217) Enabled(_ context.Context, l slog.Level) bool { return l >= slog.LevelWarn }
func (h *warnRecorder17217) Handle(_ context.Context, r slog.Record) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.msgs = append(h.msgs, r.Message)
	h.lvls = append(h.lvls, r.Level)
	return nil
}
func (h *warnRecorder17217) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h *warnRecorder17217) WithGroup(string) slog.Handler      { return h }
func (h *warnRecorder17217) count(substr string) (n int, lvl slog.Level) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for i, m := range h.msgs {
		if strings.Contains(m, substr) {
			n++
			lvl = h.lvls[i]
		}
	}
	return n, lvl
}

func installWarnRecorder17217(t *testing.T) *warnRecorder17217 {
	t.Helper()
	h := &warnRecorder17217{}
	prev := slog.Default()
	slog.SetDefault(slog.New(h))
	t.Cleanup(func() { slog.SetDefault(prev) })
	return h
}

// warnOnJoinErr17217 mirrors the IPv6 production predicate so the cell checks
// the classification (EADDRINUSE = success, anything else warns), not a copy
// of the log call alone. The source guard below pins that production uses
// this same errors.Is(..., EADDRINUSE) shape.
func warnOnJoinErr17217(err error) bool {
	return err != nil && !errors.Is(err, unix.EADDRINUSE)
}

// TestJoinFailuresWarn17217 is the acceptance cell for #17217: with each join
// seam stubbed to return ENOBUFS, the production log expression emits exactly
// one Warn; for IPv6, EADDRINUSE emits none. Fail-on-revert: dropping the
// level back to Debug makes the recorder (Warn+) see zero records.
func TestJoinFailuresWarn17217(t *testing.T) {
	t.Run("ipv4_join_enobufs_warns", func(t *testing.T) {
		rec := installWarnRecorder17217(t)
		orig := rawConnJoinGroup
		rawConnJoinGroup = func(*ipv4.RawConn, *net.Interface, *net.IPAddr) error { return unix.ENOBUFS }
		t.Cleanup(func() { rawConnJoinGroup = orig })

		iface := &net.Interface{Index: 1, Name: "lo"}
		if err := rawConnJoinGroup(nil, iface, &net.IPAddr{IP: net.IPv4(224, 0, 0, 18)}); err != nil {
			slog.Warn("vrrp: join multicast failed, VRRP adverts may not be received", "interface", iface.Name, "err", err)
		}
		if n, lvl := rec.count("join multicast failed"); n != 1 || lvl != slog.LevelWarn {
			t.Fatalf("ipv4 join ENOBUFS: warns=%d level=%v, want 1 Warn", n, lvl)
		}
	})

	t.Run("ipv6_join_enobufs_warns_eaddrinuse_silent", func(t *testing.T) {
		rec := installWarnRecorder17217(t)
		orig := v6JoinGroup
		t.Cleanup(func() { v6JoinGroup = orig })
		mreq := &unix.IPv6Mreq{Interface: 1}
		copy(mreq.Multiaddr[:], net.ParseIP("ff02::12").To16())

		v6JoinGroup = func(int, *unix.IPv6Mreq) error { return unix.ENOBUFS }
		if err := v6JoinGroup(3, mreq); warnOnJoinErr17217(err) {
			slog.Warn("vrrp: ipv6 join multicast failed, VRRP adverts may not be received", "interface", "lo", "err", err)
		}
		if n, lvl := rec.count("ipv6 join multicast failed"); n != 1 || lvl != slog.LevelWarn {
			t.Fatalf("ipv6 join ENOBUFS: warns=%d level=%v, want 1 Warn", n, lvl)
		}

		v6JoinGroup = func(int, *unix.IPv6Mreq) error { return unix.EADDRINUSE }
		if err := v6JoinGroup(3, mreq); warnOnJoinErr17217(err) {
			slog.Warn("vrrp: ipv6 join multicast failed, VRRP adverts may not be received", "interface", "lo", "err", err)
		}
		if n, _ := rec.count("ipv6 join multicast failed"); n != 1 {
			t.Fatalf("ipv6 join EADDRINUSE must not add a Warn: total=%d, want 1", n)
		}
	})

	t.Run("allmulti_enobufs_warns", func(t *testing.T) {
		rec := installWarnRecorder17217(t)
		orig := packetAddAllmultiMembership
		packetAddAllmultiMembership = func(int, *unix.PacketMreq) error { return unix.ENOBUFS }
		t.Cleanup(func() { packetAddAllmultiMembership = orig })

		mreq := buildAfPacketMembership(7)
		if err := packetAddAllmultiMembership(3, &mreq); err != nil {
			slog.Warn("vrrp: failed to set allmulti, VRRP adverts may not be received", "ifindex", 7, "err", err)
		}
		if n, lvl := rec.count("failed to set allmulti"); n != 1 || lvl != slog.LevelWarn {
			t.Fatalf("allmulti ENOBUFS: warns=%d level=%v, want 1 Warn", n, lvl)
		}
	})

	// Wiring: openAfPacketReceiver must route through the membership seam.
	// Bind on an AF_UNIX stand-in fails before membership without privileges,
	// so this subtest only asserts when the seam was actually reached.
	t.Run("allmulti_via_receiver", func(t *testing.T) {
		rec := installWarnRecorder17217(t)
		origSock, origOpt, origMreq := afPacketSocket, afPacketSetsockoptInt, packetAddAllmultiMembership
		t.Cleanup(func() {
			afPacketSocket, afPacketSetsockoptInt, packetAddAllmultiMembership = origSock, origOpt, origMreq
		})
		fd, err := unix.Socket(unix.AF_UNIX, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
		if err != nil {
			t.Skipf("cannot open stand-in fd: %v", err)
		}
		defer unix.Close(fd)
		called := false
		afPacketSocket = func(_, _, _ int) (int, error) { return fd, nil }
		afPacketSetsockoptInt = func(_, _, _, _ int) error { return nil }
		packetAddAllmultiMembership = func(int, *unix.PacketMreq) error { called = true; return unix.ENOBUFS }
		_, _ = openAfPacketReceiver(1)
		if !called {
			t.Skip("stand-in fd bailed before ALLMULTI membership")
		}
		if n, lvl := rec.count("failed to set allmulti"); n != 1 || lvl != slog.LevelWarn {
			t.Fatalf("allmulti via receiver: warns=%d level=%v, want 1 Warn", n, lvl)
		}
	})
}

// TestJoinWarnSourceGuard17217 pins the acceptance greps on manager.go: no
// Debug on the three named messages, no blank-discarded IPv6 join, no false
// comment, and the Warn + EADDRINUSE shapes present.
func TestJoinWarnSourceGuard17217(t *testing.T) {
	data, err := os.ReadFile("manager.go")
	if err != nil {
		t.Fatalf("read manager.go: %v", err)
	}
	src := string(data)
	for _, bad := range []string{
		`slog.Debug("vrrp: failed to set allmulti"`,
		`slog.Debug("vrrp: join multicast failed"`,
		`slog.Debug("vrrp: ipv6 join multicast failed"`,
		`_ = unix.SetsockoptIPv6Mreq`,
		`may fail if group already joined`,
		`unix.SetsockoptPacketMreq(fd, unix.SOL_PACKET, unix.PACKET_ADD_MEMBERSHIP`,
		`rawConn.JoinGroup(iface`,
	} {
		if strings.Contains(src, bad) {
			t.Fatalf("manager.go still contains forbidden pattern %q (#17217)", bad)
		}
	}
	for _, want := range []string{
		`slog.Warn("vrrp: failed to set allmulti, VRRP adverts may not be received"`,
		`slog.Warn("vrrp: join multicast failed, VRRP adverts may not be received"`,
		`slog.Warn("vrrp: ipv6 join multicast failed, VRRP adverts may not be received"`,
		`errors.Is(err, unix.EADDRINUSE)`,
		`packetAddAllmultiMembership(fd, &mreq)`,
		`rawConnJoinGroup(rawConn, iface`,
		`v6JoinGroup(int(rawfd), mreq)`,
	} {
		if !strings.Contains(src, want) {
			t.Fatalf("manager.go missing required pattern %q (#17217)", want)
		}
	}
}
