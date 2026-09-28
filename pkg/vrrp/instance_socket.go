package vrrp

import (
	"fmt"
	"log/slog"
	"net"
	"strings"

	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
	"golang.org/x/sys/unix"
)

// openSocket creates the per-instance raw socket bound to the interface.
func (vi *vrrpInstance) openSocket() error {
	return vi.openSocketWith(openPerInterfaceSocket, openAfPacketReceiver, openIPv6Socket)
}

// ensureVIPFamilySockets opens send/receive sockets for any family newly
// introduced by an in-place VIP update. Existing family sockets are retained
// when the last VIP of that family is removed: retaining a receiver is cheap
// and avoids socket teardown races; sendAdvert simply stops emitting that
// family until a later VIP commit uses it again.
func (vi *vrrpInstance) ensureVIPFamilySockets(vips []string) error {
	return vi.ensureVIPFamilySocketsWith(vips, openPerInterfaceSocket, openIPv6Socket)
}

func (vi *vrrpInstance) ensureVIPFamilySocketsWith(
	vips []string,
	openIPv4 func(string, *net.Interface, bool) (*ipv4.RawConn, net.PacketConn, error),
	openIPv6 func(string, *net.Interface, bool) (net.PacketConn, int, error),
) error {
	hasIPv4, hasIPv6 := vipFamiliesIn(vips)
	if !hasIPv4 && !hasIPv6 {
		hasIPv6 = vi.cfg.Family == "inet6"
		hasIPv4 = !hasIPv6
	}
	isVLAN := strings.Contains(vi.cfg.Interface, ".")
	var openErr error

	vi.socketMu.Lock()
	if hasIPv4 && vi.rawConn == nil {
		var rawConn *ipv4.RawConn
		var conn net.PacketConn
		rawConn, conn, openErr = openIPv4(vi.cfg.Interface, vi.iface, isVLAN)
		if openErr == nil {
			vi.rawConn = rawConn
			vi.conn = conn
		}
	}
	if openErr == nil && hasIPv6 && vi.ipv6Conn == nil {
		var conn net.PacketConn
		var fd int
		conn, fd, openErr = openIPv6(vi.cfg.Interface, vi.iface, isVLAN)
		if openErr == nil {
			vi.ipv6Conn = conn
			vi.ipv6FD = fd
			p6 := ipv6.NewPacketConn(conn)
			vi.ipv6Send = func(data []byte, cm *ipv6.ControlMessage, dst net.Addr) error {
				_, werr := p6.WriteTo(data, cm, dst)
				return werr
			}
		}
	}
	vi.socketMu.Unlock()

	// If AF_PACKET was unavailable, a family added after run() started needs
	// its own raw receiver. The once flags also cover the startup-vs-commit
	// race: exactly one side starts each family receiver.
	if vi.afPacketFD < 0 {
		vi.startFallbackReceivers()
	}
	if openErr != nil {
		return fmt.Errorf("open VRRP socket for newly configured family: %w", openErr)
	}
	return nil
}

func vipFamiliesIn(vips []string) (hasIPv4, hasIPv6 bool) {
	for _, vip := range vips {
		addr := vip
		if idx := strings.Index(addr, "/"); idx >= 0 {
			addr = addr[:idx]
		}
		if ip := net.ParseIP(addr); ip != nil {
			if ip.To4() != nil {
				hasIPv4 = true
			} else {
				hasIPv6 = true
			}
		}
	}
	return hasIPv4, hasIPv6
}

func (vi *vrrpInstance) startFallbackReceivers() {
	vi.socketMu.RLock()
	haveIPv4 := vi.rawConn != nil && vi.conn != nil
	haveIPv6 := vi.ipv6Conn != nil
	vi.socketMu.RUnlock()

	if haveIPv4 && vi.ipv4ReceiverStarted.CompareAndSwap(false, true) {
		go vi.receiver()
	}
	if haveIPv6 && vi.ipv6ReceiverStarted.CompareAndSwap(false, true) {
		slog.Warn("vrrp: af_packet unavailable, using separate IPv6 raw socket fallback",
			"key", vi.key())
		go vi.receiverIPv6()
	}
}

// openSocketWith is the dependency-injected implementation used by
// openSocket. Keeping the seams call-scoped (rather than mutable package
// globals) lets tests prove family-specific socket selection and rollback
// without introducing cross-test races.
func (vi *vrrpInstance) openSocketWith(
	openIPv4 func(string, *net.Interface, bool) (*ipv4.RawConn, net.PacketConn, error),
	openAFPacket func(int) (int, error),
	openIPv6 func(string, *net.Interface, bool) (net.PacketConn, int, error),
) error {
	isVLAN := strings.Contains(vi.cfg.Interface, ".")
	hasIPv4VIPs, hasIPv6VIPs := vi.vipFamilies()
	// A group without a parseable VIP is invalid at the config boundary, but
	// preserve the historical socket choice for direct/test callers while
	// honoring an explicit inet6 identity.
	if !hasIPv4VIPs && !hasIPv6VIPs {
		hasIPv6VIPs = vi.cfg.Family == "inet6"
		hasIPv4VIPs = !hasIPv6VIPs
	}

	// Open only the protocol sockets this election domain needs. Before #5083
	// an IPv6-only instance still required an IPv4 raw socket, so a host with a
	// working IPv6 VRRP stack but unavailable IPv4 raw socket could never start.
	if hasIPv4VIPs {
		rawConn, conn, err := openIPv4(vi.cfg.Interface, vi.iface, isVLAN)
		if err != nil {
			return err
		}
		vi.conn = conn
		vi.rawConn = rawConn
	}

	// Open AF_PACKET socket for receiving VRRP packets.
	// Raw IP sockets (proto 112) don't reliably receive multicast in
	// generic XDP mode — AF_PACKET taps fire before generic XDP in the
	// kernel's receive path, so they always see the packet regardless
	// of XDP processing. The raw IP socket is kept for sending only.
	fd, err := openAFPacket(vi.iface.Index)
	if err != nil {
		slog.Warn("vrrp: af_packet open failed, protocol raw-socket fallback only",
			"key", vi.key(), "err", err)
	} else {
		vi.afPacketFD = fd
	}

	// Resolve our local IPv4 address (primary IP, not a VIP) for:
	// 1. Source address in VRRP advertisements
	// 2. Filtering self-sent packets
	// We must skip VIP addresses because during split-brain both nodes
	// have the VIP — using it as source would cause the peer to filter
	// our adverts as "self-sent" (matching its own VIP).
	// Resolve our IPv4 + (deterministic, lowest) link-local IPv6 advert
	// source from the interface's current addresses. The manager addr-watcher
	// re-runs reresolveLocalAddrs on every address change so a source flushed
	// by the RETH MAC reprogram cycle is picked up rather than cached stale
	// (#2528).
	vi.reresolveLocalAddrs()

	// Open IPv6 raw socket if any VIPs are IPv6.
	if hasIPv6VIPs {
		v6Conn, v6FD, err := openIPv6(vi.cfg.Interface, vi.iface, isVLAN)
		if err != nil {
			// A configured family is an indivisible readiness contract. Publishing
			// the instance after a warning-only IPv6 failure made the manager and
			// HA gates report it running even though it could never advertise that
			// family. Release any already-open IPv4/AF_PACKET resources and fail
			// the manager's build-before-teardown proof instead.
			vi.closeSockets()
			return fmt.Errorf("open IPv6 VRRP socket: %w", err)
		}
		vi.ipv6Conn = v6Conn
		vi.ipv6FD = v6FD
		// Wrap the raw IPConn so we can attach an IPV6_PKTINFO control message
		// on every advert. The control message pins the outer IPv6 source to the
		// checksum source (#2644).
		p6 := ipv6.NewPacketConn(v6Conn)
		vi.ipv6Send = func(data []byte, cm *ipv6.ControlMessage, dst net.Addr) error {
			_, werr := p6.WriteTo(data, cm, dst)
			return werr
		}
	}

	return nil
}

// closeSockets releases and clears all per-instance descriptors before run()
// starts. It is used by the openSocket failure path, where stop() cannot be
// called because no goroutine will ever close stopped.
func (vi *vrrpInstance) closeSockets() {
	vi.closeSocketDescriptors()
	vi.clearSocketRefs()
}

func (vi *vrrpInstance) closeSocketDescriptors() {
	vi.socketMu.Lock()
	defer vi.socketMu.Unlock()
	if vi.conn != nil {
		vi.conn.Close()
	}
	if vi.ipv6Conn != nil {
		vi.ipv6Conn.Close()
	}
	if vi.afPacketFD >= 0 {
		unix.Close(vi.afPacketFD)
	}
}

func (vi *vrrpInstance) clearSocketRefs() {
	vi.conn = nil
	vi.rawConn = nil
	vi.ipv6Conn = nil
	vi.ipv6FD = -1
	vi.ipv6Send = nil
	vi.afPacketFD = -1
}
