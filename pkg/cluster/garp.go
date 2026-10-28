package cluster

import (
	"encoding/binary"
	"fmt"
	"log/slog"
	"net"
	"sync/atomic"
	"time"

	"github.com/psaab/xpf/pkg/linuxsock"
	"golang.org/x/sys/unix"
)

// burstSendErrors counts gratuitous ARP / unsolicited NA follow-up frames
// (the background-goroutine adverts that aid neighbor/switch convergence
// during failover) that failed to send. The first frame of every burst is
// sent synchronously and its error is returned to the caller; this counter
// only accumulates the follow-up failures that the background goroutine
// would otherwise drop on the floor. Exported via BurstSendErrors for
// observability (#2623).
var burstSendErrors atomic.Uint64

// BurstSendErrors returns the cumulative number of failover GARP/NA burst
// follow-up frames that failed to transmit. A non-zero, climbing value means
// the failover-convergence adverts are being dropped after the first frame —
// the logs that report the full burst count are not proof of delivery.
func BurstSendErrors() uint64 { return burstSendErrors.Load() }

// burstSend transmits one burst follow-up frame. It is a package var so tests
// can inject a sender that succeeds once then fails, proving the follow-up
// error handling (count + warn + counter) fires without intercepting the
// synchronous first send. Production wraps unix.Sendto.
var burstSend = func(fd int, pkt []byte, addr unix.Sockaddr) error {
	return unix.Sendto(fd, pkt, 0, addr)
}

// SendGratuitousARP sends gratuitous ARP on the specified interface for the
// given IP address. Sends both ARP Request and ARP Reply variants — some
// routers/switches only update their ARP cache from one or the other.
// Count specifies how many pairs to send (with 100ms gaps).
func SendGratuitousARP(iface string, ip net.IP, count int) error {
	if count <= 0 {
		count = 1
	}

	ip4 := ip.To4()
	if ip4 == nil {
		return fmt.Errorf("not an IPv4 address: %s", ip)
	}

	ifi, err := net.InterfaceByName(iface)
	if err != nil {
		return fmt.Errorf("interface %s: %w", iface, err)
	}

	reqPkt := buildGratuitousARP(ifi.HardwareAddr, ip4, 1) // ARP Request
	repPkt := buildGratuitousARP(ifi.HardwareAddr, ip4, 2) // ARP Reply

	fd, err := linuxsock.Socket(unix.AF_PACKET, unix.SOCK_RAW, int(htons(unix.ETH_P_ARP)))
	if err != nil {
		return fmt.Errorf("raw socket: %w", err)
	}
	defer unix.Close(fd)

	addr := unix.SockaddrLinklayer{
		Protocol: htons(unix.ETH_P_ARP),
		Ifindex:  ifi.Index,
		Halen:    6,
	}
	copy(addr.Addr[:], []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff})

	for i := 0; i < count; i++ {
		// Send ARP Request GARP first (more widely accepted).
		if err := unix.Sendto(fd, reqPkt, 0, &addr); err != nil {
			return fmt.Errorf("sendto request: %w", err)
		}
		// Send ARP Reply GARP (updates L2 switch MAC tables).
		if err := unix.Sendto(fd, repPkt, 0, &addr); err != nil {
			return fmt.Errorf("sendto reply: %w", err)
		}
		if i < count-1 {
			time.Sleep(100 * time.Millisecond)
		}
	}

	slog.Info("cluster: sent gratuitous ARP",
		"interface", iface, "ip", ip4.String(), "count", count)
	return nil
}

// buildGratuitousARP constructs a raw Ethernet+ARP gratuitous packet.
// opcode: 1 = ARP Request, 2 = ARP Reply.
func buildGratuitousARP(mac net.HardwareAddr, ip net.IP, opcode uint16) []byte {
	pkt := make([]byte, 42) // 14 ethernet + 28 ARP

	// Ethernet header
	copy(pkt[0:6], []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}) // dst: broadcast
	copy(pkt[6:12], mac)                                       // src: our MAC
	binary.BigEndian.PutUint16(pkt[12:14], unix.ETH_P_ARP)     // ethertype

	// ARP header
	binary.BigEndian.PutUint16(pkt[14:16], 1)      // hardware type: Ethernet
	binary.BigEndian.PutUint16(pkt[16:18], 0x0800) // protocol type: IPv4
	pkt[18] = 6                                    // hardware addr len
	pkt[19] = 4                                    // protocol addr len
	binary.BigEndian.PutUint16(pkt[20:22], opcode) // opcode

	// Sender hardware + protocol address
	copy(pkt[22:28], mac)
	copy(pkt[28:32], ip.To4())

	// Target: for GARP Request, target MAC is zero and target IP = sender IP.
	// For GARP Reply, target MAC is broadcast and target IP = sender IP.
	if opcode == 1 {
		// Request: target hardware = zero, target IP = our IP
		copy(pkt[38:42], ip.To4())
	} else {
		// Reply: target hardware = broadcast, target IP = our IP
		copy(pkt[32:38], []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff})
		copy(pkt[38:42], ip.To4())
	}

	return pkt
}

// BurstStillValid reports whether a GARP/NA burst follow-up loop is still
// allowed to transmit. It is captured at burst start and consulted before
// EVERY follow-up frame. The VRRP instance passes a closure that returns
// true only while the node is STILL master AND the garpEpoch matches the
// value observed when the burst was launched (#2867). The predicate is
// REQUIRED (#17158): the gated senders refuse a nil predicate, so the
// ungated pre-#2867 behaviour cannot be selected silently.
//
// The detached follow-up loop sends (count-1) frames over (count-1)*50ms.
// Without this gate, a node that abdicates (loses master / becomes backup)
// mid-burst keeps broadcasting gratuitous ARP / unsolicited NA for VIPs it
// no longer owns, re-poisoning neighbor caches toward a node that has
// already handed the VIP off — the exact blackhole GARP exists to prevent.
type BurstStillValid func() bool

// SendGratuitousARPBurstGated sends one immediate GARP pair (request + reply), then
// schedules (count-1) follow-up pairs at 50ms intervals in a background goroutine.
// Returns after the first pair is sent (<1ms), making it suitable for the
// critical failover path.
//
// stillValid is the abdication gate (#2867) and is REQUIRED (#17158): a nil
// predicate is refused with an error. Before #17158 an ungated twin took
// the short name SendGratuitousARPBurst; #2867 kept it and #2898 shipped
// through it. That twin is deleted; this gated form is the only burst.
func SendGratuitousARPBurstGated(iface string, ip net.IP, count int, stillValid BurstStillValid) error {
	if stillValid == nil {
		return fmt.Errorf("cluster: GARP burst on %s requires a non-nil BurstStillValid predicate (#17158)", iface)
	}
	if count <= 0 {
		count = 1
	}

	ip4 := ip.To4()
	if ip4 == nil {
		return fmt.Errorf("not an IPv4 address: %s", ip)
	}

	ifi, err := net.InterfaceByName(iface)
	if err != nil {
		return fmt.Errorf("interface %s: %w", iface, err)
	}

	reqPkt := buildGratuitousARP(ifi.HardwareAddr, ip4, 1) // ARP Request
	repPkt := buildGratuitousARP(ifi.HardwareAddr, ip4, 2) // ARP Reply

	fd, err := linuxsock.Socket(unix.AF_PACKET, unix.SOCK_RAW, int(htons(unix.ETH_P_ARP)))
	if err != nil {
		return fmt.Errorf("raw socket: %w", err)
	}

	addr := unix.SockaddrLinklayer{
		Protocol: htons(unix.ETH_P_ARP),
		Ifindex:  ifi.Index,
		Halen:    6,
	}
	copy(addr.Addr[:], []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff})

	// Send first pair synchronously (immediate).
	if err := unix.Sendto(fd, reqPkt, 0, &addr); err != nil {
		unix.Close(fd)
		return fmt.Errorf("sendto request: %w", err)
	}
	if err := unix.Sendto(fd, repPkt, 0, &addr); err != nil {
		unix.Close(fd)
		return fmt.Errorf("sendto reply: %w", err)
	}

	slog.Info("cluster: sent gratuitous ARP burst (1st pair)",
		"interface", iface, "ip", ip4.String(), "total", count)

	// Schedule remaining pairs in background. Follow-up sends are the
	// reliability mechanism for neighbor/switch convergence; a send error
	// after the first frame means the burst that the log already reported
	// as `total=count` did not fully go out. Count the failures, bump the
	// exported counter, and warn ONCE after the loop (never per-iteration —
	// per CLAUDE.md logging rules a per-send log here would flood). The
	// loop never aborts: a transient error on one frame must not suppress
	// the remaining adverts that may still reach the LAN.
	if count > 1 {
		go runARPBurstFollowups(fd, iface, ip4.String(), reqPkt, repPkt, addr, count, stillValid)
	} else {
		unix.Close(fd)
	}

	return nil
}

// runARPBurstFollowups sends the (count-1) follow-up GARP pairs at 50ms
// intervals, then closes fd. Extracted from SendGratuitousARPBurstGated so the
// follow-up error handling is unit-testable via the burstSend seam without a
// raw socket. Each failed frame bumps burstSendErrors and is logged at Debug
// (per-iteration logging at higher levels would flood — CLAUDE.md); a single
// Warn fires after the loop if any frame failed. The loop never aborts on a
// transient SEND error so the remaining adverts still get a chance to reach
// the LAN.
//
// It DOES abort — cleanly, before any frame — when stillValid returns false
// (#2867): the node has abdicated (no longer master, or garpEpoch bumped) and
// must stop announcing VIPs it no longer owns. The check runs after the 50ms
// sleep, immediately before the send, so an abdication that lands mid-sleep is
// honored on the very next iteration. A nil stillValid is refused (#17158):
// it sends nothing, so even a direct helper call cannot run ungated.
func runARPBurstFollowups(fd int, iface, ip string, reqPkt, repPkt []byte, addr unix.SockaddrLinklayer, count int, stillValid BurstStillValid) {
	defer unix.Close(fd)
	if stillValid == nil {
		slog.Debug("cluster: GARP burst follow-up refused (nil predicate)",
			"interface", iface, "ip", ip)
		return
	}
	var failed int
	for i := 1; i < count; i++ {
		time.Sleep(50 * time.Millisecond)
		if !stillValid() {
			slog.Debug("cluster: GARP burst follow-up aborted (abdicated)",
				"interface", iface, "ip", ip, "iter", i, "remaining", count-i)
			break
		}
		if err := burstSend(fd, reqPkt, &addr); err != nil {
			failed++
			slog.Debug("cluster: GARP burst follow-up send failed",
				"interface", iface, "ip", ip,
				"frame", "request", "iter", i, "err", err)
		}
		if err := burstSend(fd, repPkt, &addr); err != nil {
			failed++
			slog.Debug("cluster: GARP burst follow-up send failed",
				"interface", iface, "ip", ip,
				"frame", "reply", "iter", i, "err", err)
		}
	}
	if failed > 0 {
		burstSendErrors.Add(uint64(failed))
		slog.Warn("cluster: GARP burst follow-up sends failed",
			"interface", iface, "ip", ip,
			"failed", failed, "total_frames", (count-1)*2)
	}
}

// SendARPProbe sends a standard ARP Request for targetIP with senderIP as
// the ARP sender protocol address. The target (typically a router) updates
// its ARP cache with senderIP -> our MAC as a side effect, so senderIP MUST
// be the address whose MAC binding we want refreshed.
//
// On a VRRP failover this MUST be the VIP, not the interface's primary
// address: a RETH carries both, and refreshing the gateway's cache for the
// primary leaves the VIP -> MAC binding stale until it ages out (#2152).
// Callers that merely want a neighbor-table reprobe (no specific source)
// can pass the interface primary via PrimaryIPv4.
func SendARPProbe(iface string, senderIP, targetIP net.IP) error {
	sender4 := senderIP.To4()
	if sender4 == nil {
		return fmt.Errorf("sender not an IPv4 address: %s", senderIP)
	}
	target4 := targetIP.To4()
	if target4 == nil {
		return fmt.Errorf("target not an IPv4 address: %s", targetIP)
	}

	ifi, err := net.InterfaceByName(iface)
	if err != nil {
		return fmt.Errorf("interface %s: %w", iface, err)
	}

	pkt := buildARPRequest(ifi.HardwareAddr, sender4, target4)

	return arpProbeSend(ifi, pkt)
}

// arpProbeSend transmits a crafted ARP probe frame on iface via a raw
// AF_PACKET socket. It is a package var so tests can intercept the exact
// frame SendARPProbe emits (sender field at pkt[28:32]) without socket I/O,
// proving the wiring passes the VIP and not the interface primary (#2152).
var arpProbeSend = func(ifi *net.Interface, pkt []byte) error {
	fd, err := linuxsock.Socket(unix.AF_PACKET, unix.SOCK_RAW, int(htons(unix.ETH_P_ARP)))
	if err != nil {
		return fmt.Errorf("raw socket: %w", err)
	}
	defer unix.Close(fd)

	addr := unix.SockaddrLinklayer{
		Protocol: htons(unix.ETH_P_ARP),
		Ifindex:  ifi.Index,
		Halen:    6,
	}
	copy(addr.Addr[:], []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff})

	return unix.Sendto(fd, pkt, 0, &addr)
}

// PrimaryIPv4 returns the interface's first non-link-local IPv4 address,
// for use as an ARP sender IP when no specific source (such as a VRRP VIP)
// is required — e.g. a neighbor-table reprobe that just wants the kernel to
// repopulate ARP for a forwarded next-hop. This preserves the self-resolved
// sender semantics that SendARPProbe used before #2152 made the sender
// explicit. 169.254.x.x link-local addresses are skipped.
func PrimaryIPv4(iface string) (net.IP, error) {
	ifi, err := net.InterfaceByName(iface)
	if err != nil {
		return nil, fmt.Errorf("interface %s: %w", iface, err)
	}
	addrs, err := ifi.Addrs()
	if err != nil {
		return nil, fmt.Errorf("interface addrs: %w", err)
	}
	for _, a := range addrs {
		ipNet, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		ip4 := ipNet.IP.To4()
		if ip4 == nil {
			continue
		}
		// Skip link-local 169.254.x.x addresses.
		if ip4[0] == 169 && ip4[1] == 254 {
			continue
		}
		return ip4, nil
	}
	return nil, fmt.Errorf("no suitable IPv4 address on %s", iface)
}

func probeIPv6Source(addrs []net.Addr) net.IP {
	return probeIPv6SourceExcluding(addrs, nil)
}

func probeIPv6SourceExcluding(addrs []net.Addr, excluded net.IP) net.IP {
	var linkLocal net.IP
	for _, a := range addrs {
		ipNet, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		ip := ipNet.IP.To16()
		if ip == nil || ipNet.IP.To4() != nil || ip.Equal(excluded) {
			continue
		}
		if ip.IsLinkLocalUnicast() {
			if linkLocal == nil {
				linkLocal = append(net.IP(nil), ip...)
			}
			continue
		}
		if ip.IsGlobalUnicast() {
			return append(net.IP(nil), ip...)
		}
	}
	return linkLocal
}

// SendNDSolicitationFromInterface resolves a suitable IPv6 source address from
// the interface, then sends a standard Neighbor Solicitation for targetIP.
// Prefers a global/ULA address so the target refreshes the service address
// neighbor cache, but falls back to link-local if no other IPv6 exists.
func SendNDSolicitationFromInterface(iface string, targetIP net.IP) error {
	ifi, err := net.InterfaceByName(iface)
	if err != nil {
		return fmt.Errorf("interface %s: %w", iface, err)
	}
	addrs, err := ifi.Addrs()
	if err != nil {
		return fmt.Errorf("interface addrs: %w", err)
	}
	sourceIP := probeIPv6Source(addrs)
	if sourceIP == nil {
		return fmt.Errorf("no suitable IPv6 address on %s", iface)
	}
	return SendNDSolicitation(iface, sourceIP, targetIP)
}

// buildARPRequest constructs a standard ARP Request packet.
func buildARPRequest(srcMAC net.HardwareAddr, srcIP, dstIP net.IP) []byte {
	pkt := make([]byte, 42) // 14 ethernet + 28 ARP

	// Ethernet header
	copy(pkt[0:6], []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}) // dst: broadcast
	copy(pkt[6:12], srcMAC)                                    // src: our MAC
	binary.BigEndian.PutUint16(pkt[12:14], unix.ETH_P_ARP)     // ethertype

	// ARP header
	binary.BigEndian.PutUint16(pkt[14:16], 1)      // hardware type: Ethernet
	binary.BigEndian.PutUint16(pkt[16:18], 0x0800) // protocol type: IPv4
	pkt[18] = 6                                    // hardware addr len
	pkt[19] = 4                                    // protocol addr len
	binary.BigEndian.PutUint16(pkt[20:22], 1)      // opcode: ARP Request

	// Sender hardware + protocol address
	copy(pkt[22:28], srcMAC)
	copy(pkt[28:32], srcIP.To4())

	// Target: unknown MAC (zero), target IP
	copy(pkt[38:42], dstIP.To4())

	return pkt
}

// SendGratuitousIPv6 sends unsolicited ICMPv6 Neighbor Advertisements on the
// specified interface for the given IPv6 address. This is the IPv6 equivalent
// of gratuitous ARP — it updates neighbor caches on the LAN after failover.
func SendGratuitousIPv6(iface string, ip net.IP, count int) error {
	if count <= 0 {
		count = 1
	}

	ip6 := ip.To16()
	if ip6 == nil || ip6.To4() != nil {
		return fmt.Errorf("not an IPv6 address: %s", ip)
	}

	ifi, err := net.InterfaceByName(iface)
	if err != nil {
		return fmt.Errorf("interface %s: %w", iface, err)
	}

	pkt := buildVIPUnsolicitedNA(ifi.HardwareAddr, ip6)

	fd, err := linuxsock.Socket(unix.AF_PACKET, unix.SOCK_RAW, int(htons(unix.ETH_P_IPV6)))
	if err != nil {
		return fmt.Errorf("raw socket: %w", err)
	}
	defer unix.Close(fd)

	addr := unix.SockaddrLinklayer{
		Protocol: htons(unix.ETH_P_IPV6),
		Ifindex:  ifi.Index,
		Halen:    6,
	}
	// IPv6 all-nodes multicast MAC: 33:33:00:00:00:01
	copy(addr.Addr[:], []byte{0x33, 0x33, 0x00, 0x00, 0x00, 0x01})

	for i := 0; i < count; i++ {
		if err := unix.Sendto(fd, pkt, 0, &addr); err != nil {
			return fmt.Errorf("sendto: %w", err)
		}
		if i < count-1 {
			time.Sleep(100 * time.Millisecond)
		}
	}

	slog.Info("cluster: sent unsolicited IPv6 NA",
		"interface", iface, "ip", ip6.String(), "count", count)
	return nil
}

// SendGratuitousIPv6BurstGated sends one immediate unsolicited NA, then schedules
// (count-1) follow-ups at 50ms intervals in a background goroutine.
// Returns after the first NA is sent, making it suitable for the critical
// failover path.
//
// stillValid is the abdication gate (#2867) and is REQUIRED (#17158): a nil
// predicate is refused with an error. Before #17158 an ungated twin took
// the short name SendGratuitousIPv6Burst; that twin is deleted.
func SendGratuitousIPv6BurstGated(iface string, ip net.IP, count int, stillValid BurstStillValid) error {
	if stillValid == nil {
		return fmt.Errorf("cluster: IPv6 NA burst on %s requires a non-nil BurstStillValid predicate (#17158)", iface)
	}
	if count <= 0 {
		count = 1
	}

	ip6 := ip.To16()
	if ip6 == nil || ip6.To4() != nil {
		return fmt.Errorf("not an IPv6 address: %s", ip)
	}

	ifi, err := net.InterfaceByName(iface)
	if err != nil {
		return fmt.Errorf("interface %s: %w", iface, err)
	}
	pkt := buildVIPUnsolicitedNA(ifi.HardwareAddr, ip6)
	return sendUnsolicitedIPv6NABurstGated(iface, ifi, ip6, pkt, count, stillValid)
}

// SendProxyGratuitousIPv6BurstGated sends an unsolicited NA for a proxy-NDP
// target. Unlike a configured VIP, a proxy target is not assigned to the
// outgoing interface; RFC 4861 §4.4 requires the packet source to be another
// address actually assigned to that interface. Prefer an assigned global/ULA
// address when available. Linux's route-based source selection for ff02::1 can
// choose link-local, so this raw packet path does not mirror kernel selection.
// stillValid is REQUIRED as in SendGratuitousIPv6BurstGated (#17158).
func SendProxyGratuitousIPv6BurstGated(iface string, targetIP net.IP, count int, stillValid BurstStillValid) error {
	if stillValid == nil {
		return fmt.Errorf("cluster: proxy IPv6 NA burst on %s requires a non-nil BurstStillValid predicate (#17158)", iface)
	}
	if count <= 0 {
		count = 1
	}
	target := targetIP.To16()
	if target == nil || target.To4() != nil {
		return fmt.Errorf("not an IPv6 proxy target: %s", targetIP)
	}

	ifi, err := net.InterfaceByName(iface)
	if err != nil {
		return fmt.Errorf("interface %s: %w", iface, err)
	}
	addrs, err := ifi.Addrs()
	if err != nil {
		return fmt.Errorf("interface addresses %s: %w", iface, err)
	}
	pkt, err := buildProxyUnsolicitedNA(ifi.HardwareAddr, addrs, target)
	if err != nil {
		return fmt.Errorf("build proxy NA for %s: %w", iface, err)
	}
	return sendUnsolicitedIPv6NABurstGated(iface, ifi, target, pkt, count, stillValid)
}

func sendUnsolicitedIPv6NABurstGated(iface string, ifi *net.Interface, target net.IP, pkt []byte, count int, stillValid BurstStillValid) error {
	if stillValid == nil {
		return fmt.Errorf("cluster: IPv6 NA burst on %s requires a non-nil BurstStillValid predicate (#17158)", iface)
	}
	fd, err := linuxsock.Socket(unix.AF_PACKET, unix.SOCK_RAW, int(htons(unix.ETH_P_IPV6)))
	if err != nil {
		return fmt.Errorf("raw socket: %w", err)
	}

	addr := unix.SockaddrLinklayer{
		Protocol: htons(unix.ETH_P_IPV6),
		Ifindex:  ifi.Index,
		Halen:    6,
	}
	copy(addr.Addr[:], []byte{0x33, 0x33, 0x00, 0x00, 0x00, 0x01})

	// Send first NA synchronously (immediate).
	if err := unix.Sendto(fd, pkt, 0, &addr); err != nil {
		unix.Close(fd)
		return fmt.Errorf("sendto: %w", err)
	}

	slog.Info("cluster: sent unsolicited IPv6 NA burst (1st)",
		"interface", iface, "ip", target.String(), "total", count)

	// Schedule remaining NAs in background. As with the GARP burst above,
	// follow-up sends are the failover-convergence reliability mechanism;
	// count failures, bump the exported counter, and warn ONCE after the
	// loop (never per-iteration). The loop never aborts on a transient
	// error so the remaining NAs still get a chance to reach the LAN.
	if count > 1 {
		go runNABurstFollowups(fd, iface, target.String(), pkt, addr, count, stillValid)
	} else {
		unix.Close(fd)
	}

	return nil
}

// runNABurstFollowups sends the (count-1) follow-up unsolicited NAs at 50ms
// intervals, then closes fd. Extracted from SendGratuitousIPv6BurstGated for the
// same reason as runARPBurstFollowups: the follow-up error handling is
// unit-testable via the burstSend seam. Each failed NA bumps burstSendErrors
// and is logged at Debug; a single Warn fires after the loop if any failed.
// The loop never aborts on a transient SEND error.
//
// Like the ARP follow-up loop, it aborts cleanly (before any frame) when
// stillValid returns false (#2867) — the node has abdicated and must stop
// announcing VIPs it no longer owns. A nil stillValid is refused (#17158):
// it sends nothing, so even a direct helper call cannot run ungated.
func runNABurstFollowups(fd int, iface, ip string, pkt []byte, addr unix.SockaddrLinklayer, count int, stillValid BurstStillValid) {
	defer unix.Close(fd)
	if stillValid == nil {
		slog.Debug("cluster: NA burst follow-up refused (nil predicate)",
			"interface", iface, "ip", ip)
		return
	}
	var failed int
	for i := 1; i < count; i++ {
		time.Sleep(50 * time.Millisecond)
		if !stillValid() {
			slog.Debug("cluster: NA burst follow-up aborted (abdicated)",
				"interface", iface, "ip", ip, "iter", i, "remaining", count-i)
			break
		}
		if err := burstSend(fd, pkt, &addr); err != nil {
			failed++
			slog.Debug("cluster: NA burst follow-up send failed",
				"interface", iface, "ip", ip,
				"iter", i, "err", err)
		}
	}
	if failed > 0 {
		burstSendErrors.Add(uint64(failed))
		slog.Warn("cluster: NA burst follow-up sends failed",
			"interface", iface, "ip", ip,
			"failed", failed, "total_frames", count-1)
	}
}

// buildProxyUnsolicitedNA constructs a proxy-target NA using a source address
// selected from the outgoing interface's addresses. A proxy target is not
// itself a valid source for this packet.
func buildProxyUnsolicitedNA(mac net.HardwareAddr, addrs []net.Addr, target net.IP) ([]byte, error) {
	target6 := target.To16()
	if target6 == nil || target6.To4() != nil {
		return nil, fmt.Errorf("not an IPv6 proxy target: %s", target)
	}
	source := probeIPv6SourceExcluding(addrs, target6)
	if source == nil {
		return nil, fmt.Errorf("no suitable IPv6 source distinct from proxy target %s", target6)
	}
	if source.Equal(target6) || !interfaceHasIPv6Address(addrs, source) {
		return nil, fmt.Errorf("invalid proxy NA source %s for target %s", source, target6)
	}
	return buildUnsolicitedNA(mac, source, target6, false), nil
}

func interfaceHasIPv6Address(addrs []net.Addr, want net.IP) bool {
	for _, addr := range addrs {
		ipNet, ok := addr.(*net.IPNet)
		if ok && ipNet.IP.To16() != nil && ipNet.IP.To4() == nil && ipNet.IP.Equal(want) {
			return true
		}
	}
	return false
}

// buildVIPUnsolicitedNA builds a Router=1 announcement for a VIP or router
// identity, preserving the flag required for hosts to retain their default
// router entry.
func buildVIPUnsolicitedNA(mac net.HardwareAddr, ip net.IP) []byte {
	return buildUnsolicitedNA(mac, ip, ip, true)
}

// buildUnsolicitedNA constructs a raw Ethernet + IPv6 + ICMPv6 Neighbor
// Advertisement packet, sent to the all-nodes multicast address (ff02::1) per
// RFC 4861 §7.2.6 (unsolicited NA). Includes the Target Link-Layer Address
// option. The source must be assigned to the outgoing interface; the advertised
// target may instead be an address served by proxy NDP.
//
// #6934: the Override flag must remain set to replace stale neighbor entries.
// RFC 4861 §7.2.5 permits a receiver to keep an existing cache entry when the
// NA has Override=0, so an Override=0 announcement could not correct a peer
// still pointing at the old node.
func buildUnsolicitedNA(mac net.HardwareAddr, source, target net.IP, router bool) []byte {
	// 14 Ethernet + 40 IPv6 + 24 ICMPv6 NA (8 hdr + 16 target) + 8 TLLA option = 86
	pkt := make([]byte, 86)

	// --- Ethernet header (14 bytes) ---
	// Dst: IPv6 all-nodes multicast MAC 33:33:00:00:00:01
	copy(pkt[0:6], []byte{0x33, 0x33, 0x00, 0x00, 0x00, 0x01})
	copy(pkt[6:12], mac)
	binary.BigEndian.PutUint16(pkt[12:14], unix.ETH_P_IPV6)

	// --- IPv6 header (40 bytes) ---
	pkt[14] = 0x60 // Version 6, TC=0
	// pkt[15:18] = 0 (TC low + Flow Label)
	binary.BigEndian.PutUint16(pkt[18:20], 32) // Payload Length: ICMPv6 NA(24) + TLLA option(8)
	pkt[20] = 58                               // Next Header: ICMPv6
	pkt[21] = 255                              // Hop Limit
	// RFC 4861 §4.4: source is assigned to the interface sending this packet.
	copy(pkt[22:38], source.To16())
	// Destination: ff02::1 (all-nodes multicast)
	pkt[38] = 0xff
	pkt[39] = 0x02
	// pkt[40:52] = 0
	pkt[53] = 0x01

	// --- ICMPv6 Neighbor Advertisement (32 bytes) ---
	pkt[54] = 136 // Type: Neighbor Advertisement
	pkt[55] = 0   // Code: 0
	// pkt[56:58] = checksum (filled below)
	// Override=1 replaces stale mappings and Solicited=0 is required for
	// multicast NAs. Router depends on the advertised identity: VIP and
	// router link-local announcements use 1; proxy targets use 0.
	if router {
		// RFC 4861 §7.2.5: Router=0 removes a previously-known router from
		// the Default Router List. VIP and router link-local callers advertise
		// this node's forwarding identity, so they retain Router=1.
		pkt[58] = 0xA0 // Router=1 + Override=1; Solicited=0.
	} else {
		// Kernel NTF_PROXY entries omit NTF_ROUTER and answer Router=0.
		// Keep proxy announcements consistent with the later kernel response.
		pkt[58] = 0x20 // Override=1; Router=0, Solicited=0.
	}
	// pkt[59:62] = 0 (reserved)
	// Target may be a proxy address that is not assigned to this interface.
	copy(pkt[62:78], target.To16())

	// --- Target Link-Layer Address option (8 bytes) ---
	pkt[78] = 2 // Type: Target Link-Layer Address
	pkt[79] = 1 // Length: 1 (in units of 8 bytes)
	copy(pkt[80:86], mac)

	// Compute ICMPv6 checksum over pseudo-header + ICMPv6 body.
	csum := icmpv6Checksum(pkt[22:38], pkt[38:54], pkt[54:86])
	binary.BigEndian.PutUint16(pkt[56:58], csum)

	return pkt
}

// icmpv6Checksum computes the ICMPv6 checksum per RFC 4443 §2.3.
// It includes the IPv6 pseudo-header (src, dst, length, next-header=58).
func icmpv6Checksum(src, dst, payload []byte) uint16 {
	var sum uint32

	// Pseudo-header: source address (16 bytes)
	for i := 0; i < 16; i += 2 {
		sum += uint32(src[i])<<8 | uint32(src[i+1])
	}
	// Pseudo-header: destination address (16 bytes)
	for i := 0; i < 16; i += 2 {
		sum += uint32(dst[i])<<8 | uint32(dst[i+1])
	}
	// Pseudo-header: upper-layer packet length (4 bytes)
	plen := uint32(len(payload))
	sum += plen
	// Pseudo-header: next header = 58 (ICMPv6)
	sum += 58

	// Payload
	for i := 0; i < len(payload)-1; i += 2 {
		sum += uint32(payload[i])<<8 | uint32(payload[i+1])
	}
	if len(payload)%2 != 0 {
		sum += uint32(payload[len(payload)-1]) << 8
	}

	// Fold 32-bit sum to 16 bits
	for sum > 0xffff {
		sum = (sum >> 16) + (sum & 0xffff)
	}
	return ^uint16(sum)
}

// SendNDSolicitation sends an ICMPv6 Neighbor Solicitation to resolve
// the link-layer address of targetIP on the given interface. This is
// the IPv6 equivalent of an ARP request.
func SendNDSolicitation(iface string, sourceIP, targetIP net.IP) error {
	target6 := targetIP.To16()
	if target6 == nil || target6.To4() != nil {
		return fmt.Errorf("not an IPv6 address: %s", targetIP)
	}
	src6 := sourceIP.To16()
	if src6 == nil {
		return fmt.Errorf("not an IPv6 address: %s", sourceIP)
	}

	ifi, err := net.InterfaceByName(iface)
	if err != nil {
		return fmt.Errorf("interface %s: %w", iface, err)
	}

	pkt := buildNDSolicitation(ifi.HardwareAddr, src6, target6)

	fd, err := linuxsock.Socket(unix.AF_PACKET, unix.SOCK_RAW, int(htons(unix.ETH_P_IPV6)))
	if err != nil {
		return fmt.Errorf("raw socket: %w", err)
	}
	defer unix.Close(fd)

	// Solicited-node multicast MAC: 33:33:ff:XX:XX:XX (last 3 bytes of target)
	addr := unix.SockaddrLinklayer{
		Protocol: htons(unix.ETH_P_IPV6),
		Ifindex:  ifi.Index,
		Halen:    6,
	}
	copy(addr.Addr[:], []byte{0x33, 0x33, 0xff, target6[13], target6[14], target6[15]})

	return unix.Sendto(fd, pkt, 0, &addr)
}

// buildNDSolicitation constructs a raw Ethernet + IPv6 + ICMPv6 Neighbor
// Solicitation packet per RFC 4861 §4.3.
func buildNDSolicitation(mac net.HardwareAddr, srcIP, targetIP net.IP) []byte {
	// 14 Ethernet + 40 IPv6 + 24 ICMPv6 NS (8 hdr + 16 target) + 8 SLLA option = 86
	pkt := make([]byte, 86)

	// --- Ethernet header (14 bytes) ---
	// Dst: solicited-node multicast 33:33:ff:XX:XX:XX
	copy(pkt[0:6], []byte{0x33, 0x33, 0xff, targetIP[13], targetIP[14], targetIP[15]})
	copy(pkt[6:12], mac)
	binary.BigEndian.PutUint16(pkt[12:14], unix.ETH_P_IPV6)

	// --- IPv6 header (40 bytes) ---
	pkt[14] = 0x60                             // Version 6, TC=0
	binary.BigEndian.PutUint16(pkt[18:20], 32) // Payload Length: NS(24) + SLLA(8)
	pkt[20] = 58                               // Next Header: ICMPv6
	pkt[21] = 255                              // Hop Limit
	copy(pkt[22:38], srcIP.To16())
	// Destination: solicited-node multicast ff02::1:ffXX:XXXX
	pkt[38] = 0xff
	pkt[39] = 0x02
	// pkt[40:48] = 0
	pkt[49] = 0x01
	pkt[50] = 0xff
	copy(pkt[51:54], targetIP[13:16])

	// --- ICMPv6 Neighbor Solicitation (32 bytes) ---
	pkt[54] = 135 // Type: Neighbor Solicitation
	pkt[55] = 0   // Code: 0
	// pkt[56:58] = checksum (filled below)
	// pkt[58:62] = 0 (reserved)
	copy(pkt[62:78], targetIP.To16())

	// --- Source Link-Layer Address option (8 bytes) ---
	pkt[78] = 1 // Type: Source Link-Layer Address
	pkt[79] = 1 // Length: 1 (in units of 8 bytes)
	copy(pkt[80:86], mac)

	// Compute ICMPv6 checksum
	csum := icmpv6Checksum(pkt[22:38], pkt[38:54], pkt[54:86])
	binary.BigEndian.PutUint16(pkt[56:58], csum)

	return pkt
}

func htons(v uint16) uint16 {
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, v)
	return binary.NativeEndian.Uint16(b)
}

// triggerGARP is called on transition to primary. Native VRRP handles
// GARP for VRRP-backed RETH interfaces, so this is a no-op.
//
// Co-located with the gratuitous-ARP burst sender in this file so the GARP
// surface area stays in one place. #1541 plan v3 — moved out of
// cluster.go to keep the heartbeat manager file focused on heartbeat
// orchestration, not L2 takeover hooks.
func (m *Manager) triggerGARP(rgID int) {
	slog.Info("cluster: primary transition", "rg", rgID)
}
