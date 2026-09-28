package vrrp

import (
	"encoding/binary"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
	"golang.org/x/sys/unix"
)

// isTimeoutError returns true if the error is a network timeout.
func isTimeoutError(err error) bool {
	if ne, ok := err.(net.Error); ok {
		return ne.Timeout()
	}
	return false
}

// acceptArrivalIfindex decides whether a raw-socket VRRP advert that arrived on
// interface arrivalIfindex should be processed by an instance bound to
// expectedIfindex.
//
// On the fallback raw-IP receiver path (afPacketFD < 0), VLAN sub-interfaces
// skip SO_BINDTODEVICE (maybeBindToDevice is a no-op on VLAN, see manager.go),
// so every per-instance raw socket on a shared parent binds to the wildcard
// address with NO device isolation. The kernel then delivers a proto-112 frame
// to ALL such sockets. Without an arrival-interface check, two VLAN
// sub-interfaces (e.g. reth0.50 / reth0.80) running instances with the SAME
// VRID would cross-process each other's adverts — state corruption, false
// BACKUP transitions, split-brain flapping (#2886).
//
// The receiver enables the per-packet interface control message and passes the
// reported arrival ifindex here. A mismatch is rejected. arrivalIfindex == 0
// means the platform did not report an arrival interface for this packet; we
// fail OPEN in that case so we never regress real delivery on a kernel/socket
// combination that omits the control message — the VRID/TTL/self-IP gates still
// apply. expectedIfindex <= 0 (an instance with no resolved interface index, as
// in some unit-test constructions) also fails open.
// arrivalIfindexDetector records the case where the platform does not report
// an arrival interface for a VRRP advert (#7171), keeping the DECISION that it
// happened separate from the once-guarded emission of the warning.
//
// The fail-open in acceptArrivalIfindex is deliberate and stays: it exists so a
// kernel/socket combination that omits the interface control message does not
// lose real advert delivery. What was missing is any way to know it is in
// effect. On such a platform EVERY advert takes that branch, so the #2886
// per-interface isolation is silently inactive for the life of the process --
// exactly the configuration #2886 was filed for, two VLAN sub-interfaces of one
// parent running instances with the same VRID, where the symptom is state
// corruption and BACKUP flapping with nothing pointing at the disabled guard.
//
// The split matters twice over. A bare sync.Once cannot be tested -- whether it
// fires depends on which test ran first in the package binary rather than on
// the input -- so a guard against silence would itself have been unverifiable.
// And the count is the operator-relevant signal: this condition is not a
// one-off, it is every packet, and a Once reports one occurrence and a million
// identically.
type arrivalIfindexDetector struct {
	occurrences atomic.Uint64
	warn        sync.Once
}

// observe records one arrival-interface decision and reports whether the
// platform failed to report an interface for a real instance. The log fires
// once per process -- RETH instances advertise every 30ms and CLAUDE.md forbids
// an unguarded log on a per-packet path -- while the count advances every time.
func (d *arrivalIfindexDetector) observe(arrivalIfindex, expectedIfindex int) bool {
	// Only the platform-side case is reportable. expectedIfindex <= 0 is an
	// instance with no resolved index, which is a test construction rather
	// than something an operator can act on.
	if arrivalIfindex > 0 || expectedIfindex <= 0 {
		return false
	}
	d.occurrences.Add(1)
	d.warn.Do(func() {
		slog.Warn("vrrp: kernel did not report an arrival interface for a "+
			"VRRP advert; per-interface advert isolation (#2886) is inactive "+
			"on this platform, so instances sharing a VRID across VLAN "+
			"sub-interfaces of one parent may cross-process adverts",
			"expected_ifindex", expectedIfindex)
	})
	return true
}

// count returns how many unreported-arrival adverts have been observed, across
// all occurrences rather than only the first.
func (d *arrivalIfindexDetector) count() uint64 { return d.occurrences.Load() }

var unreportedArrivalIfindex arrivalIfindexDetector

func acceptArrivalIfindex(arrivalIfindex, expectedIfindex int) bool {
	if arrivalIfindex <= 0 || expectedIfindex <= 0 {
		unreportedArrivalIfindex.observe(arrivalIfindex, expectedIfindex)
		return true
	}
	return arrivalIfindex == expectedIfindex
}

// expectedIfindex returns the kernel ifindex this instance is bound to, or 0 if
// no interface is resolved (test constructions may leave iface nil).
func (vi *vrrpInstance) expectedIfindex() int {
	if vi.iface == nil {
		return 0
	}
	return vi.iface.Index
}

// receiver reads VRRP packets from the per-instance raw socket.
func (vi *vrrpInstance) receiver() {
	buf := make([]byte, 1500)
	vi.socketMu.RLock()
	rawConn, conn := vi.rawConn, vi.conn
	vi.socketMu.RUnlock()
	if rawConn == nil || conn == nil {
		return
	}

	// Capture the per-packet arrival interface so cross-VLAN frames delivered
	// to this wildcard-bound socket can be rejected (#2886). On VLAN
	// sub-interfaces the socket is NOT bound to a device, so the kernel fans a
	// proto-112 frame out to every instance's socket on the shared parent.
	if err := rawConn.SetControlMessage(ipv4.FlagInterface, true); err != nil {
		slog.Debug("vrrp: set control message failed", "key", vi.key(), "err", err)
	}

	for {
		select {
		case <-vi.stopCh:
			return
		default:
		}

		// Set a read deadline so ReadFrom doesn't block forever.
		// ipv4.RawConn.ReadFrom uses RawRead which can get stuck in a
		// blocking recvmsg syscall; the deadline ensures we periodically
		// check stopCh even if the socket is unexpectedly in blocking mode.
		conn.SetReadDeadline(time.Now().Add(1 * time.Second))
		hdr, payload, cm, err := rawConn.ReadFrom(buf)
		if err != nil {
			select {
			case <-vi.stopCh:
				return
			default:
				// Ignore timeout errors — they're expected from our deadline.
				if !isTimeoutError(err) {
					slog.Debug("vrrp: read error", "key", vi.key(), "err", err)
				}
				continue
			}
		}

		// Reject adverts that arrived on a different interface (#2886). On the
		// VLAN fallback path the socket is wildcard-bound, so the kernel
		// delivers a same-VRID advert from a sibling VLAN here too.
		arrivalIf := 0
		if cm != nil {
			arrivalIf = cm.IfIndex
		}
		if !acceptArrivalIfindex(arrivalIf, vi.expectedIfindex()) {
			continue
		}

		// Verify TTL == 255 (RFC 5798 §5.1.1.3).
		if hdr.TTL != 255 {
			continue
		}

		// Filter self-sent packets (RFC 5798 §6.4.2/6.4.3).
		// #7334: the SET, not the one selected send source. A self-advert sent
		// from address A bypassed this once the selection moved to B.
		if vi.isLocalAddr(hdr.Src) {
			continue
		}

		if len(payload) < vrrpHeaderLen {
			continue
		}

		// Only accept packets matching our VRID.
		if payload[1] != uint8(vi.cfg.GroupID) {
			continue
		}

		srcIP := hdr.Src
		dstIP := hdr.Dst

		pkt, err := ParseVRRPPacket(payload, false, srcIP, dstIP)
		if err != nil {
			slog.Debug("vrrp: parse error", "key", vi.key(), "err", err)
			continue
		}

		vi.enqueuePacket(pkt, false)
	}
}

// receiverIPv6 reads VRRPv3 packets from the IPv6 raw socket (ip6:112).
// Used as fallback when AF_PACKET is unavailable. The kernel strips the
// IPv6 header for raw sockets, so ReadFrom returns the VRRP payload directly.
// Source address comes from the addr parameter of ReadFrom.
func (vi *vrrpInstance) receiverIPv6() {
	buf := make([]byte, 1500)
	vi.socketMu.RLock()
	conn, recv := vi.ipv6Conn, vi.ipv6Recv
	vi.socketMu.RUnlock()
	if conn == nil && recv == nil {
		return
	}

	// Resolve the read seam. Production builds a wrapper over the raw conn that
	// returns the per-packet control message (the arrival interface). The IPv6
	// raw socket is wildcard-bound (`::`) and NOT bound to a device on a VLAN
	// sub-interface (no SO_BINDTODEVICE — manager.go), so the kernel fans a
	// proto-112 frame out to every instance's socket on the shared parent;
	// without an arrival-interface check, sibling VLANs with the same VRID
	// cross-process (#2886). Tests override ipv6Recv to inject a chosen ifindex.
	if recv == nil {
		pc := ipv6.NewPacketConn(conn)
		// FlagInterface → arrival ifindex (#2886 cross-VLAN filter).
		// FlagHopLimit → IPV6_RECVHOPLIMIT so the received hop limit is
		// carried in the control message; the kernel strips the IPv6 header
		// on a raw ip6:112 socket, so this is the only way to enforce the
		// RFC 5798 §5.1.2.3 GTSM hop-limit==255 check on this fallback path
		// (#4549 F8).
		if err := pc.SetControlMessage(ipv6.FlagInterface|ipv6.FlagHopLimit, true); err != nil {
			slog.Debug("vrrp: set ipv6 control message failed", "key", vi.key(), "err", err)
		}
		recv = func(b []byte) (int, int, int, net.Addr, error) {
			conn.SetReadDeadline(time.Now().Add(1 * time.Second))
			n, cm, src, err := pc.ReadFrom(b)
			ifindex := 0
			hopLimit := 0
			if cm != nil {
				ifindex = cm.IfIndex
				hopLimit = cm.HopLimit
			}
			return n, ifindex, hopLimit, src, err
		}
	}

	for {
		select {
		case <-vi.stopCh:
			return
		default:
		}

		n, arrivalIf, hopLimit, addr, err := recv(buf)
		if err != nil {
			select {
			case <-vi.stopCh:
				return
			default:
				if !isTimeoutError(err) {
					slog.Debug("vrrp: ipv6 read error", "key", vi.key(), "err", err)
				}
				continue
			}
		}

		if n < vrrpHeaderLen {
			continue
		}

		// Verify hop limit == 255 (RFC 5798 §5.1.2.3, GTSM). The AF_PACKET and
		// IPv4-raw paths already enforce this; the raw IPv6 fallback strips the
		// header, so the value arrives via the IPV6_RECVHOPLIMIT control message
		// (#4549 F8). Reject anything that was routed (hop limit decremented).
		if hopLimit != 255 {
			slog.Debug("vrrp: ipv6 advert rejected on hop limit",
				"key", vi.key(), "hopLimit", hopLimit)
			continue
		}

		// Reject adverts that arrived on a different interface (#2886).
		if !acceptArrivalIfindex(arrivalIf, vi.expectedIfindex()) {
			continue
		}

		// Only accept packets matching our VRID.
		if buf[1] != uint8(vi.cfg.GroupID) {
			continue
		}

		// Extract source IP from the addr returned by ReadFrom.
		var srcIP net.IP
		if ipAddr, ok := addr.(*net.IPAddr); ok {
			srcIP = ipAddr.IP
		}

		// Filter self-sent packets.
		// #7334: the SET, not the one selected link-local.
		if srcIP != nil && vi.isLocalAddr(srcIP) {
			continue
		}

		// IPv6 VRRP multicast destination (ff02::12).
		dstIP := net.ParseIP("ff02::12")

		pkt, err := ParseVRRPPacket(buf[:n], true, srcIP, dstIP)
		if err != nil {
			slog.Debug("vrrp: ipv6 parse error", "key", vi.key(), "err", err)
			continue
		}

		vi.enqueuePacket(pkt, true)
	}
}

// receiverAfPacket reads VRRP packets via AF_PACKET on VLAN sub-interfaces.
// Uses SOCK_RAW + ETH_P_ALL (same as tcpdump) — receives full Ethernet frames.
// Handles IPv4, IPv6, and 802.1Q-tagged variants. Detects VLAN tags and
// adjusts header skip: 14 bytes untagged, 18 bytes single-tagged.
func (vi *vrrpInstance) receiverAfPacket() {
	buf := make([]byte, 1500)
	for {
		select {
		case <-vi.stopCh:
			return
		default:
		}

		n, from, err := afPacketRecvfrom(vi.afPacketFD, buf, 0)
		if err != nil {
			select {
			case <-vi.stopCh:
				return
			default:
				// EAGAIN/EWOULDBLOCK from SO_RCVTIMEO — expected.
				if err != unix.EAGAIN && err != unix.EWOULDBLOCK {
					slog.Debug("vrrp: af_packet read error", "key", vi.key(), "err", err)
				}
				continue
			}
		}

		// Drop our OWN transmissions (#6560). See afPacketFrameIsOutgoing for
		// why this is not redundant with PACKET_IGNORE_OUTGOING, and why the
		// address-snapshot comparison further down cannot cover it.
		if afPacketFrameIsOutgoing(from) {
			continue
		}

		// Need at least 14 bytes to read the ethertype.
		if n < 14 {
			continue
		}

		// Detect 802.1Q VLAN tag and resolve real ethertype.
		ethHeaderLen := 14
		ethertype := binary.BigEndian.Uint16(buf[12:14])
		if ethertype == 0x8100 || ethertype == 0x88a8 {
			ethHeaderLen = 18 // 14 + 4-byte VLAN tag
			if n < 18 {
				continue
			}
			ethertype = binary.BigEndian.Uint16(buf[16:18])
		}

		isIPv6 := ethertype == 0x86DD

		if isIPv6 {
			vi.parseAfPacketIPv6(buf, n, ethHeaderLen)
		} else if ethertype == 0x0800 {
			vi.parseAfPacketIPv4(buf, n, ethHeaderLen)
		}
	}
}

// parseAfPacketIPv4 parses an IPv4 VRRP packet from a raw Ethernet frame.
func (vi *vrrpInstance) parseAfPacketIPv4(buf []byte, n, ethHeaderLen int) {
	// Minimum: eth header + 20-byte IPv4 + 8-byte VRRP.
	if n < ethHeaderLen+20+vrrpHeaderLen {
		return
	}

	ip := buf[ethHeaderLen:]
	ipLen := n - ethHeaderLen

	ihl := int(ip[0]&0x0F) * 4
	if ihl < 20 || ipLen < ihl+vrrpHeaderLen {
		return
	}

	// Verify TTL == 255 (RFC 5798 §5.1.1.3).
	if ip[8] != 255 {
		return
	}

	srcIP := make(net.IP, 4)
	copy(srcIP, ip[12:16])

	// Filter self-sent packets.
	// #7334: see isLocalAddr — the address SET, failing open when unresolved.
	if vi.isLocalAddr(srcIP) {
		return
	}

	payload := ip[ihl:ipLen]
	if payload[1] != uint8(vi.cfg.GroupID) {
		return
	}

	dstIP := make(net.IP, 4)
	copy(dstIP, ip[16:20])

	pkt, err := ParseVRRPPacket(payload, false, srcIP, dstIP)
	if err != nil {
		slog.Debug("vrrp: parse error", "key", vi.key(), "err", err)
		return
	}

	vi.enqueuePacket(pkt, false)
}

// parseAfPacketIPv6 parses an IPv6 VRRP packet from a raw Ethernet frame.
// IPv6 base header: 40 bytes fixed, next-header at offset 6, hop limit at
// offset 7, source at 8-24, destination at 24-40. The VRRP payload may be
// preceded by one or more IPv6 extension headers (#2155); walkIPv6ExtHeaders
// finds the real payload offset.
func (vi *vrrpInstance) parseAfPacketIPv6(buf []byte, n, ethHeaderLen int) {
	const ipv6HeaderLen = 40

	// Minimum: eth header + 40-byte IPv6 + 8-byte VRRP.
	if n < ethHeaderLen+ipv6HeaderLen+vrrpHeaderLen {
		return
	}

	ip6 := buf[ethHeaderLen:]
	ip6Len := n - ethHeaderLen

	// Verify hop limit == 255 (RFC 5798 §5.1.2.3).
	if ip6[7] != 255 {
		return
	}

	srcIP := make(net.IP, 16)
	copy(srcIP, ip6[8:24])

	// Filter self-sent packets.
	// #7334: see isLocalAddr.
	if vi.isLocalAddr(srcIP) {
		return
	}

	// Walk any IPv6 extension-header chain to the proto-112 VRRP payload.
	// A bare advert (base Next-Header == 112) yields off == ipv6HeaderLen.
	off, ok := walkIPv6ExtHeaders(ip6, ip6Len)
	if !ok {
		return
	}

	payload := ip6[off:ip6Len]
	if len(payload) < vrrpHeaderLen {
		return
	}
	if payload[1] != uint8(vi.cfg.GroupID) {
		return
	}

	dstIP := make(net.IP, 16)
	copy(dstIP, ip6[24:40])

	pkt, err := ParseVRRPPacket(payload, true, srcIP, dstIP)
	if err != nil {
		slog.Debug("vrrp: ipv6 parse error", "key", vi.key(), "err", err)
		return
	}

	vi.enqueuePacket(pkt, true)
}

// enqueuePacket is the single admission point shared by all raw and
// AF_PACKET receivers. Family-tagged generic instances accept only their own
// election domain; empty-family RETH instances intentionally accept both.
// Keeping this check at the leaf closes cross-family bleed for every current
// transport and for future receiver refactors that use this helper.
func (vi *vrrpInstance) enqueuePacket(pkt *VRRPPacket, isIPv6 bool) {
	if (vi.cfg.Family == "inet" && isIPv6) || (vi.cfg.Family == "inet6" && !isIPv6) {
		return
	}
	select {
	case vi.rxCh <- pkt:
		vi.rxReceived.Add(1)
	default:
		vi.warnRXDrop()
	}
}

// walkIPv6ExtHeaders walks the IPv6 extension-header chain in ip6 (an IPv6
// packet starting at its base header, ip6Len bytes long) and returns the
// offset of the first proto-112 (VRRP) header. The bool is false if the
// chain does not terminate at VRRP, is truncated, contains a Fragment
// header, or exceeds the iteration cap — all of which mean "not a parseable
// VRRP advert; drop". A bare advert (base Next-Header == 112) returns
// (40, true).
//
// Length-unit conventions and the deliberately small admit set:
//   - Hop-by-Hop (0), Routing (43), Destination Options (60): the header is
//     8 + HdrExtLen*8 bytes, i.e. (HdrExtLen+1)*8. These are the only chained
//     headers a conformant VRRP advert can carry, so they are walked.
//   - Fragment (44): VRRP adverts are never legitimately fragmented and the
//     receiver does no reassembly, so a Fragment header is a hard drop. The
//     cBPF prefilter (manager.go) does not admit base Next-Header 44 either,
//     so this hard drop is defense-in-depth for the path the kernel can't
//     prefilter (a Fragment header buried mid-chain).
//   - Authentication Header (51) and every other Next-Header: not a VRRP
//     carrier (VRRP authenticates itself, it is never IPsec-AH-wrapped), so
//     it is dropped. The cBPF likewise does not admit base Next-Header 51, so
//     an AH-first advert is kernel-dropped before this walk ever runs.
//
// The walk is bounded to maxIPv6ExtHeaders iterations and bounds-checks every
// access against ip6Len, so a malicious or truncated chain can neither loop
// nor read out of bounds.
func walkIPv6ExtHeaders(ip6 []byte, ip6Len int) (int, bool) {
	const (
		ipv6HeaderLen     = 40
		maxIPv6ExtHeaders = 8
		nhVRRP            = 112
		nhHopByHop        = 0
		nhRouting         = 43
		nhFragment        = 44
		nhDestOpts        = 60
	)

	if ip6Len < ipv6HeaderLen {
		return 0, false
	}

	nh := int(ip6[6]) // base Next-Header
	off := ipv6HeaderLen

	for i := 0; i < maxIPv6ExtHeaders; i++ {
		if nh == nhVRRP {
			return off, true
		}

		// Need at least the 2-byte (NextHeader, length) preamble of the
		// next extension header to make progress.
		if off+2 > ip6Len {
			return 0, false
		}

		var hdrLen int
		switch nh {
		case nhHopByHop, nhRouting, nhDestOpts:
			hdrLen = (int(ip6[off+1]) + 1) * 8
		case nhFragment:
			// Fragmented VRRP is non-conformant — drop.
			return 0, false
		default:
			// AH (51) or any other terminal protocol — not VRRP.
			return 0, false
		}

		next := int(ip6[off]) // NextHeader of this ext-header
		off += hdrLen
		if hdrLen <= 0 || off > ip6Len {
			return 0, false
		}
		nh = next
	}

	// Chain exceeded the iteration cap without reaching VRRP — drop.
	return 0, false
}

// warnRXDrop increments the drop counter and logs a rate-limited warning.
//
// warnRXDrop may run concurrently from both receiver() and receiverIPv6() on
// the AF_PACKET-fallback path (#2225), so lastDropWarn is an atomic.Int64 of
// Unix nanos and the read-modify-write is done with CompareAndSwap. The CAS
// ensures the once-per-interval dampener holds even under contention: only the
// goroutine that successfully swaps the stale timestamp emits the warning, so a
// burst of concurrent drops produces a single log line per interval rather than
// one per racing goroutine.
func (vi *vrrpInstance) warnRXDrop() {
	drops := vi.rxDrops.Add(1)
	now := time.Now().UnixNano()
	last := vi.lastDropWarn.Load()
	// Clamp negative elapsed: lastDropWarn is wall-clock UnixNano (not a
	// monotonic time.Time), so a backward wall-clock step makes now-last
	// negative — without the >= 0 guard that would read as "< 10s" and
	// suppress drop warnings until the clock re-advances. Mirrors
	// garpDampened's elapsed>=0 clamp (#1792).
	if elapsed := now - last; elapsed >= 0 && elapsed < int64(10*time.Second) {
		return
	}
	if !vi.lastDropWarn.CompareAndSwap(last, now) {
		// Another goroutine just emitted the warning for this interval.
		return
	}
	slog.Warn("vrrp: rx channel full, dropping advertisements",
		"key", vi.key(), "total_drops", drops)
}

// afPacketRecvfrom is the recvfrom(2) entry point used by receiverAfPacket.
// Package var for the same reason as afPacketSocket in manager.go: it lets a
// test drive the receive LOOP — including the #6560 self-frame drop, which lives
// in the loop and not in the parsers — deterministically and without CAP_NET_RAW.
var afPacketRecvfrom = unix.Recvfrom

// afPacketFrameIsOutgoing reports whether a frame the AF_PACKET capture socket
// delivered is one this host TRANSMITTED, using the sll_pkttype the kernel
// reports in the frame's sockaddr_ll (#6560).
//
// WHY THIS EXISTS AT ALL. The capture socket is an ETH_P_ALL tap — that is what
// tcpdump uses and why tcpdump shows egress traffic. dev_queue_xmit_nit clones
// every outbound frame to each ptype_all tap with skb->pkt_type =
// PACKET_OUTGOING, and packet_rcv drops only PACKET_LOOPBACK. Adverts leave on
// the raw AF_INET/AF_INET6 sockets, but they egress the very netdev this socket
// is bound to, so a MASTER's own advertisement arrives in its own receive queue.
// The cBPF filter cannot stop it: every instruction matches ethertype or IP
// protocol, there is no SKF_AD_PKTTYPE ancillary load, and a self-advert
// satisfies the filter exactly.
//
// WHY THE EXISTING SELF-CHECK IS NOT ENOUGH. Self-filtering rested solely on
// comparing the frame's source against getLocalIP()/getLocalIPv6(), and those
// are DELIBERATELY nilable: reresolveLocalAddrs stores nil when the interface
// has no non-VIP address of the family. Every one of those four comparisons is
// written `lip != nil && src.Equal(lip)`, so a nil snapshot means ACCEPT. During
// the #2528 RETH-MAC flush window — programRethMAC does link DOWN, set MAC, link
// UP, and DOWN flushes every kernel address — the snapshot is nil for 30ms-1s.
// A self-advert already committed to the tap then reaches handleMasterRx, where
// it necessarily carries our own priority, so resolveEqualPriorityMaster runs;
// that function re-reads the same nilable snapshot and, on nil, logs "local
// source unresolved — stepping down" and calls becomeBackup. The comment there
// justifies the step-down by assuming the advert came from a PEER. In this case
// the "actively advertising equal-priority peer" is this node itself.
//
// WHY IT IS NOT REDUNDANT WITH PACKET_IGNORE_OUTGOING. That socket option is
// Linux >= 4.20; on an older kernel openAfPacketReceiver logs and continues, and
// this check is what still holds. Keeping both is the belt-and-braces pair: the
// option avoids the copy, this avoids acting on it.
//
// A sockaddr that is missing or not a link-layer one is treated as NOT outgoing.
// Failing open here is correct: a frame we cannot classify must still be able to
// be a peer's advert, and dropping it would be a self-inflicted master-down.
func afPacketFrameIsOutgoing(from unix.Sockaddr) bool {
	sll, ok := from.(*unix.SockaddrLinklayer)
	if !ok || sll == nil {
		return false
	}
	return sll.Pkttype == unix.PACKET_OUTGOING
}
