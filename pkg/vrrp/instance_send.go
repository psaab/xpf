package vrrp

import (
	"fmt"
	"log/slog"
	"net"

	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

// emitEvent sends a state change event to the manager's event channel.
func (vi *vrrpInstance) emitEvent() {
	evt := VRRPEvent{
		Interface: vi.cfg.Interface,
		Family:    vi.cfg.Family,
		GroupID:   vi.cfg.GroupID,
		State:     vi.getState(),
		VIPs:      vi.cfg.VirtualAddresses,
	}
	select {
	case vi.eventCh <- evt:
	default:
		// Drop if channel full — warn unless we're shutting down.
		select {
		case <-vi.stopCh:
		default:
			slog.Warn("vrrp: event channel full, dropping event",
				"key", vi.key(), "state", evt.State)
			if vi.onEventDrop != nil {
				vi.onEventDrop()
			}
		}
	}
}

// sendAdvert sends a VRRPv3 advertisement with the given priority.
func (vi *vrrpInstance) sendAdvert(priority int) {
	// Shared with checkAdvertCapacity (advert_capacity.go) so the guard that
	// decides an advert CAN be built counts exactly the addresses this builder
	// puts in it (#6779).
	v4Addrs, v6Addrs := splitVIPsByFamily(vi.cfg.VirtualAddresses)

	// #8597 (muse-004 K20): snapshot the mu-guarded advertise interval ONCE,
	// under the lock, before either arm reads it.
	//
	// This ran on the instance run loop (a 30ms advert timer on RETH) reading
	// the config field directly while updateConfig writes it under vi.mu on the
	// manager goroutine — the #5087 day-2 path, reached by any commit that
	// changes reth-advertise-interval. `go test -race` reports it at
	// instance_send.go:46 against instance.go:378.
	//
	// One snapshot for both arms, not one call per arm: a dual-stack instance
	// sends a v4 and a v6 advert from the same call, and two reads could
	// straddle a writer and put DIFFERENT MaxAdverInt values in the two
	// families' packets. The peer derives its master-down interval from that
	// field, so the two families would then disagree about the failover
	// horizon — the flapping mechanism gemini-048 finding 06 describes.
	//
	// The value is milliseconds; the /10 below converts to the centiseconds
	// RFC 5798 puts on the wire. Normalize at the send boundary with the same
	// quantum/default used by the local timer: a tolerant negative or zero
	// value must not wrap through uint16, and an inexact millisecond value must
	// not make the peer's interval disagree with this instance's timer.
	advertMS := normalizeAdvertIntervalMS9914(vi.advertiseIntervalMS())
	advertCS := advertMS / 10

	// Send IPv4 advertisement if we have any IPv4 VIPs.
	if len(v4Addrs) > 0 {
		maxAdvert := uint16(advertCS) // milliseconds → centiseconds
		pkt := &VRRPPacket{
			VRID:         uint8(vi.cfg.GroupID),
			Priority:     uint8(priority),
			MaxAdvertInt: maxAdvert,
			IPAddresses:  v4Addrs,
		}
		if err := sendPacketFn(vi, pkt, false); err != nil {
			slog.Debug("vrrp: failed to send IPv4 advert",
				"key", vi.key(), "err", err)
		}
	}

	// Send IPv6 advertisement if we have any IPv6 VIPs.
	if len(v6Addrs) > 0 {
		maxAdvert := uint16(advertCS) // ms → centiseconds
		pkt := &VRRPPacket{
			VRID:         uint8(vi.cfg.GroupID),
			Priority:     uint8(priority),
			MaxAdvertInt: maxAdvert,
			IPAddresses:  v6Addrs,
		}
		if err := sendPacketFn(vi, pkt, true); err != nil {
			slog.Debug("vrrp: failed to send IPv6 advert",
				"key", vi.key(), "err", err)
		}
	}
}

// sendPacket sends a VRRP advertisement via the per-instance raw socket.
// sendPacketFn is the seam sendAdvert emits through. Production is
// (*vrrpInstance).sendPacket; tests replace it to observe what a single
// sendAdvert call actually put on the wire.
//
// #8597: it exists because the one-snapshot property of sendAdvert is otherwise
// unobservable. A per-arm locked read silences the race detector and still lets
// the v4 and v6 adverts of ONE call carry different MaxAdverInt values, and the
// only way to state that as a test is to see both packets.
var sendPacketFn = func(vi *vrrpInstance, pkt *VRRPPacket, isIPv6 bool) error {
	return vi.sendPacket(pkt, isIPv6)
}

func (vi *vrrpInstance) sendPacket(pkt *VRRPPacket, isIPv6 bool) error {
	if isIPv6 {
		return vi.sendPacketIPv6(pkt)
	}
	if vi.rawConn == nil {
		return nil
	}

	srcIP := vi.getLocalIP()
	if srcIP == nil {
		// Lazy resolve: the interface may not have had an address at socket
		// open time, or the addr-watcher invalidated a flushed source (#2528).
		// Skip VIPs — must send from the primary/base address. The atomic
		// setLocalIP makes this run-loop write race-clean against the
		// receiver-goroutine reads (#2258).
		srcIP = vi.resolveLocalIPv4(vi.vipAddrSet())
		if srcIP != nil {
			vi.setLocalIP(srcIP)
		}
		if srcIP == nil {
			return fmt.Errorf("no IPv4 address on %s", vi.cfg.Interface)
		}
	}

	dstIP := net.IPv4(224, 0, 0, 18)

	data, err := pkt.Marshal(false, srcIP, dstIP)
	if err != nil {
		return err
	}

	hdr := &ipv4.Header{
		Version:  4,
		Len:      20,
		TotalLen: 20 + len(data),
		TTL:      255,
		Protocol: vrrpProto,
		Src:      srcIP,
		Dst:      dstIP,
	}

	if err := vi.rawConn.SetMulticastInterface(vi.iface); err != nil {
		return fmt.Errorf("set multicast interface: %w", err)
	}

	cm := &ipv4.ControlMessage{
		IfIndex: vi.iface.Index,
	}

	if err := vi.rawConn.WriteTo(hdr, data, cm); err != nil {
		return fmt.Errorf("writeto: %w", err)
	}

	return nil
}

// sendPacketIPv6 sends a VRRPv3 IPv6 advertisement.
// Source: link-local address, Destination: ff02::12, Hop Limit: 255.
func (vi *vrrpInstance) sendPacketIPv6(pkt *VRRPPacket) error {
	if vi.ipv6Conn == nil {
		return nil
	}

	srcIP := vi.getLocalIPv6()
	if srcIP == nil {
		// Lazy resolve: deterministically select the lowest link-local
		// address. This happens when the interface didn't have a
		// link-local at openSocket() time (e.g. DAD still running). The
		// atomic setLocalIPv6 makes this run-loop write race-clean against
		// the receiver-goroutine reads (#2258).
		resolved := vi.resolveIPv6LinkLocal(vi.vipAddrSet())
		if resolved != nil {
			vi.setLocalIPv6(resolved)
			srcIP = resolved
			slog.Info("vrrp: late-resolved IPv6 link-local address",
				"key", vi.key(), "addr", srcIP)
		}
		if srcIP == nil {
			slog.Warn("vrrp: no link-local IPv6 address, skipping IPv6 advert",
				"key", vi.key(), "interface", vi.cfg.Interface)
			return fmt.Errorf("no link-local IPv6 address on %s", vi.cfg.Interface)
		}
	}

	dstIP := net.ParseIP("ff02::12")

	// RFC 5798 §5.2.9 / §6.1: an IPv6 VRRP advertisement lists ALL of the
	// virtual router's addresses, and the FIRST IPvX address in the payload
	// MUST be the virtual router's link-local. srcIP is exactly that
	// link-local (it is also the outer source and the pseudo-header checksum
	// source below, #2644), so prepend it ahead of the configured global
	// VIPs the caller placed in pkt.IPAddresses. Marshal derives the
	// "Count IPvX Addr" wire field from len(IPAddresses) (packet.go), so
	// prepending here bumps the count in lockstep — no separate count math.
	// Build a fresh slice rather than mutating the caller's v6Addrs so a
	// retried send does not prepend twice.
	llFirst := make([]net.IP, 0, len(pkt.IPAddresses)+1)
	llFirst = append(llFirst, srcIP)
	llFirst = append(llFirst, pkt.IPAddresses...)
	pkt.IPAddresses = llFirst

	// The pseudo-header checksum inside data is computed over srcIP. The
	// outer IPv6 source MUST equal srcIP or the receiver's checksum (which
	// is validated against the actual outer source) mismatches and the
	// advert is dropped (#2644).
	data, err := pkt.Marshal(true, srcIP, dstIP)
	if err != nil {
		return err
	}

	// Don't set Zone — the socket already has IPV6_MULTICAST_IF bound
	// to the interface. Setting Zone on the destination can cause EINVAL
	// on some kernels when the socket option is already set.
	dst := &net.IPAddr{
		IP: dstIP,
	}

	// Pin the outer source via IPV6_PKTINFO to the SAME address the
	// checksum was computed over (#2644). Without this the kernel selects
	// the outer source independently (RFC 6724) on the wildcard-bound
	// socket and can pick a different link-local than srcIP. IfIndex
	// scopes the link-local source to the VRRP interface (link-locals are
	// zone-scoped) and keeps the egress interface deterministic.
	cm := &ipv6.ControlMessage{
		Src:     srcIP,
		IfIndex: vi.iface.Index,
	}
	if vi.ipv6Send == nil {
		// Defensive: a wired ipv6Conn without a send seam should not
		// happen (openSocket sets both together), but fall back to the
		// raw conn rather than panic.
		if _, err := vi.ipv6Conn.WriteTo(data, dst); err != nil {
			return fmt.Errorf("ipv6 writeto: %w", err)
		}
		return nil
	}
	if err := vi.ipv6Send(data, cm, dst); err != nil {
		return fmt.Errorf("ipv6 writeto: %w", err)
	}

	return nil
}

// maxAdvertIntCentiseconds9039 is the largest value the VRRPv3 Max Advert Int
// field can carry: it is 12 bits of centiseconds, masked with 0x0FFF by
// packet.go. Spelled once here so the clamp and the mask cannot drift apart.
const maxAdvertIntCentiseconds9039 = 0x0FFF
