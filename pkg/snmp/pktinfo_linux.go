//go:build linux

package snmp

import (
	"fmt"
	"net"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

// ipPktInfoRecv is IP_RECVPKTINFO on Linux (not exported by x/sys/unix).
const ipPktInfoRecv = 8

// snmpListenSocketControl arms a newly-created dual-stack UDP listener for
// per-datagram ingress capture (#16781). Unlike snmpVRFSocketControl it never
// pins the socket with SO_BINDTODEVICE: the listener stays in the default
// (main-table) context so both management-VRF and in-band datagrams are
// delivered (the kernel requires udp_l3mdev_accept=1 for the VRF leg, which
// the daemon enables at bring-up). It enables IP_PKTINFO (IPv4) and
// IPV6_RECVPKTINFO (IPv6) so ReadMsgUDP returns the ingress ifindex and the
// local destination address of every request, and SO_REUSEPORT so the second
// listener (vrf-mgmt-bound, see Agent.Bind) can share :161 without stealing
// the main-table socket's traffic — the kernel demultiplexes by L3 domain.
//
// SO_REUSEPORT is load-bearing for coexistence, not a convenience: two
// wildcard :161 binds without it fail EADDRINUSE.
func snmpListenSocketControl() func(string, string, syscall.RawConn) error {
	return func(network, _ string, raw syscall.RawConn) error {
		var socketErr error
		if err := raw.Control(func(fd uintptr) {
			if err := unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEPORT, 1); err != nil {
				socketErr = fmt.Errorf("snmp: set SO_REUSEPORT on listener: %w", err)
				return
			}
			// ListenPacket("udp", ":161") creates an IPv6 dual-stack
			// socket when IPv6 is available and an IPv4 socket when it is
			// not. Only the family's own pktinfo option exists on each:
			// IP_PKTINFO/IP_RECVPKTINFO on the v4 socket, IPV6_RECVPKTINFO
			// on the v6 socket (which also yields IP_PKTINFO cmsgs for
			// v4-mapped datagrams). Setting the other family's option
			// fails ENOPROTOOPT, so arm exactly one by socket family.
			if network == "udp4" {
				if err := unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, ipPktInfoRecv, 1); err != nil {
					socketErr = fmt.Errorf("snmp: enable IP_PKTINFO on listener: %w", err)
					return
				}
			} else {
				if err := unix.SetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_RECVPKTINFO, 1); err != nil {
					socketErr = fmt.Errorf("snmp: enable IPV6_RECVPKTINFO on listener: %w", err)
					return
				}
			}
		}); err != nil {
			return fmt.Errorf("snmp: configure listener socket: %w", err)
		}
		if socketErr != nil {
			return socketErr
		}
		return nil
	}
}

// snmpVRFPktinfoSocketControl is the control for the vrf-mgmt-bound second
// listener (#16781). It keeps the #11427 SO_BINDTODEVICE pin (management
// replies and traps must leave via vrf-mgmt) and adds the same
// SO_REUSEPORT + PKTINFO arming as the main listener so the two wildcard
// :161 sockets coexist and Serve can route each reply on the socket that
// received its request.
func snmpVRFPktinfoSocketControl(device string) func(string, string, syscall.RawConn) error {
	base := snmpVRFSocketControl(device)
	listen := snmpListenSocketControl()
	return func(network, address string, raw syscall.RawConn) error {
		if base != nil {
			if err := base(network, address, raw); err != nil {
				return err
			}
		}
		return listen(network, address, raw)
	}
}

// pktinfo is the per-datagram ingress identity captured from the ancillary
// data of one received request: the interface the datagram arrived on and
// the local address it was addressed to. Serve echoes the destination in
// every reply's control message so the response is sourced from the exact
// address the manager polled (#16781); the ifindex is echoed as reply
// egress unless the request ingressed a userspace reinjection TUN
// (see oob, #17832).
type pktinfo struct {
	ifindex int
	dst     net.IP // local (destination) address of the request; nil if unknown
}

// parsePktinfo extracts the IP_PKTINFO / IPV6_PKTINFO ancillary datum from
// oob (the control-message bytes returned by ReadMsgUDP). It returns the
// zero pktinfo when no pktinfo cmsg is present.
func parsePktinfo(oob []byte) pktinfo {
	if len(oob) == 0 {
		return pktinfo{}
	}
	msgs, err := unix.ParseSocketControlMessage(oob)
	if err != nil {
		return pktinfo{}
	}
	for i := range msgs {
		m := &msgs[i]
		switch {
		case m.Header.Level == unix.SOL_IP && m.Header.Type == unix.IP_PKTINFO:
			if len(m.Data) < unix.SizeofInet4Pktinfo {
				continue
			}
			info := (*unix.Inet4Pktinfo)(unsafe.Pointer(&m.Data[0]))
			// Addr is the local destination address of the datagram.
			dst := net.IP(info.Addr[:])
			return pktinfo{ifindex: int(info.Ifindex), dst: dst}
		case m.Header.Level == unix.SOL_IPV6 && m.Header.Type == unix.IPV6_PKTINFO:
			if len(m.Data) < unix.SizeofInet6Pktinfo {
				continue
			}
			info := (*unix.Inet6Pktinfo)(unsafe.Pointer(&m.Data[0]))
			dst := make(net.IP, net.IPv6len)
			copy(dst, info.Addr[:])
			return pktinfo{ifindex: int(info.Ifindex), dst: dst}
		}
	}
	return pktinfo{}
}

// The userspace dataplane's host-inbound reinjection TUNs: the AF_XDP slow
// path writes LocalDelivery traffic into xpf-usp0 and adjudicated transit
// into xpf-usp1 (userspace-dp/src/slowpath.rs). From the kernel's side they
// are write-only taps — nothing reads the far end for replies — so a reply
// whose egress is pinned to one of these ifindexes can never reach its
// manager (#17832).
const (
	reinjectTUNUSP0 = "xpf-usp0"
	reinjectTUNUSP1 = "xpf-usp1"
)

// isUserspaceReinjectTUN reports whether ifindex currently belongs to one of
// the userspace reinjection TUNs above. A vanished device reports false (the
// reply then leaves egress unpinned rather than pinned to a dead index).
func isUserspaceReinjectTUN(ifindex int) bool {
	if ifindex == 0 {
		return false
	}
	iface, err := net.InterfaceByIndex(ifindex)
	if err != nil {
		return false
	}
	return iface.Name == reinjectTUNUSP0 || iface.Name == reinjectTUNUSP1
}

// oob returns the reply control message for one request:
//
//   - The reply SOURCE is always pinned to the request's local destination
//     (Spec_dst / Addr), so the response leaves from the exact address the
//     manager polled — the fxp0 address for management polls, the trust/reth
//     address for in-band polls (#16781).
//
//   - pinEgress controls whether the received ifindex is echoed as the
//     reply's egress interface. serveOne passes false only when the request
//     ingressed one of the userspace reinjection TUNs
//     (isUserspaceReinjectTUN): echoing that ifindex pinned the reply onto
//     the write-only TUN, so the manager never received an answer, and with
//     ifindex 0 the kernel routes the reply normally (#17832). Every other
//     ingress keeps the pin: the explicit oif is what makes a VRF-domain
//     route lookup reach the VRF's routing table — with ifindex 0 the lookup
//     misses it and sendmsg fails ENETUNREACH, verified live for both the
//     vrf-mgmt-bound socket and a VRF-domain datagram served by the
//     main-table listener under udp_l3mdev_accept (#16781 cell, #17832
//     regression run).
//
// It returns nil when no local destination was captured, leaving
// source/oif selection to the socket (bound device or routing table).
func (p pktinfo) oob(pinEgress bool) []byte {
	if p.dst == nil {
		return nil
	}
	if ip4 := p.dst.To4(); ip4 != nil {
		var info unix.Inet4Pktinfo
		if pinEgress {
			info.Ifindex = int32(p.ifindex)
		}
		copy(info.Spec_dst[:], ip4)
		copy(info.Addr[:], ip4)
		return unix.PktInfo4(&info)
	}
	var info unix.Inet6Pktinfo
	if pinEgress {
		info.Ifindex = uint32(p.ifindex)
	}
	copy(info.Addr[:], p.dst.To16())
	return unix.PktInfo6(&info)
}
