package cluster

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"

	"github.com/psaab/xpf/pkg/linuxsock"
	"golang.org/x/sys/unix"
)

// #8621: an ARP responder for proxy-ARP pool addresses.
//
// WHY THIS EXISTS AT ALL. The daemon's `reconcileProxyARP` installs NTF_PROXY
// neighbour entries plus the per-interface `proxy_arp` sysctl, and for the
// topology this product ships BOTH ARE STRUCTURALLY INERT. `arp_process` in
// net/ipv4/arp.c reaches the proxy branch only through three arms, and every
// one of them turns on the relationship between the route to the target and the
// device the request arrived on:
//
//	arp_fwd_proxy(in_dev, dev, rt)                     // returns 0 on its FIRST
//	                                                   // line when rt->dst.dev == dev
//	arp_fwd_pvlan(in_dev, dev, rt, sip, tip)           // needs proxy_arp_pvlan
//	(rt->dst.dev != dev && pneigh_lookup(...))         // the NTF_PROXY arm
//
// A source-NAT pool address sits inside the connected subnet of the very
// interface it egresses on — that is what `docs/ha-cluster-userspace.conf`
// configures and what #8280 chose deliberately, because #6751 forbids the pool
// overlapping an interface-mode SNAT egress address. For such a target
// `rt->dst.dev == dev`, so the NTF_PROXY arm is skipped by its own guard and
// `arp_fwd_proxy` bails before it ever reads the sysctl. The kernel accepts the
// configuration and then declines to use it.
//
// MEASURED, on the loss userspace cluster: a probe for the pool address left
// the requester's neighbour entry INCOMPLETE while the interface's own address
// answered 2/2 REACHABLE from the same host in the same second. Setting only
// `proxy_arp_pvlan=1` made the pool address answer, and reverting it made it
// stop — the mechanism operating a lever in both directions.
//
// WHY NOT proxy_arp_pvlan. It works, and it is refused: `arp_fwd_pvlan`
// consults NO proxy entry list, so the box would answer for every address it
// has a route for on that segment. On a connected subnet that is every host in
// it, invisibly to `ip neigh show proxy`. It is also incompatible with the RG
// ownership design — the STANDBY would answer too, which is exactly the
// misdelivery #8297 and #8405 exist to prevent.
//
// WHY HERE rather than in the dataplane. ARP never reaches the AF_XDP
// dataplane: the shim returns `pass_non_ip_l2_direct()` (a plain XDP_PASS) for
// every non-IP ethertype except nested-VLAN TPIDs (#9888 drops those) ABOVE
// the ingress-interface guard, and two comments exist to defend that
// placement. Answering there would mean stopping that pass on every interface
// to fix a per-pool problem. The daemon, by contrast,
// already opens AF_PACKET/SOCK_RAW/ETH_P_ARP and builds ARP frames for exactly
// these addresses (SendGratuitousARPBurstGated, used by
// announceProxyARPPoolAddresses) — this adds the receive half to machinery that
// is already aimed at the right address set.
//
// IPv4 ONLY, AND THAT IS DELIBERATE — NOT AN OVERSIGHT. IPv6 proxy NDP does
// not have this defect: `ndisc_recv_ns` gates on
// `forwarding && (proxy_ndp) && pndisc_is_router(target, dev) >= 0`, and
// `pndisc_is_router` is a bare `pneigh_lookup` with NO route lookup and hence
// nothing corresponding to `rt->dst.dev != dev`. The kernel answers v6 proxy
// NDP for a same-subnet target correctly, and `reconcileProxyARP` already
// installs the v6 entries and sets `proxy_ndp`. Adding a v6 responder here
// would DUPLICATE a working kernel path, and two responders for one family can
// disagree while only one of them is gated by RG ownership. If you are reading
// this because v6 looks missing: it is absent on purpose.

const (
	arpFrameLen     = 42 // 14 ethernet + 28 ARP
	arpHTypeEther   = 1
	arpPTypeIPv4    = 0x0800
	arpHLenEther    = 6
	arpPLenIPv4     = 4
	arpOpcodeReq    = 1
	arpOpcodeReply  = 2
	arpEthHdrLen    = 14
	arpOpcodeOffset = 20
)

// ErrNotAnARPRequest is returned by ParseARPRequest for any frame that is not a
// well-formed Ethernet/IPv4 ARP REQUEST.
var ErrNotAnARPRequest = errors.New("not an ethernet/ipv4 arp request")

// ARPRequest is the subset of an ARP request a responder needs.
type ARPRequest struct {
	SenderMAC net.HardwareAddr
	SenderIP  net.IP
	TargetIP  net.IP
}

// ParseARPRequest validates and decodes an Ethernet/IPv4 ARP REQUEST.
//
// It validates the fixed header BEFORE reading any address, for the reason
// #2369 records on the dataplane's own ARP parser: the sender hardware and
// protocol addresses sit at offsets that are only correct when
// htype==1 / ptype==0x0800 / hlen==6 / plen==4. A frame declaring different
// types or lengths would otherwise have attacker-chosen bytes read as a MAC and
// an IP. Fail closed — anything unexpected is simply not an ARP request.
func ParseARPRequest(frame []byte) (*ARPRequest, error) {
	if len(frame) < arpFrameLen {
		return nil, ErrNotAnARPRequest
	}
	if binary.BigEndian.Uint16(frame[12:14]) != unix.ETH_P_ARP {
		return nil, ErrNotAnARPRequest
	}
	if binary.BigEndian.Uint16(frame[14:16]) != arpHTypeEther ||
		binary.BigEndian.Uint16(frame[16:18]) != arpPTypeIPv4 ||
		frame[18] != arpHLenEther ||
		frame[19] != arpPLenIPv4 {
		return nil, ErrNotAnARPRequest
	}
	if binary.BigEndian.Uint16(frame[arpOpcodeOffset:arpOpcodeOffset+2]) != arpOpcodeReq {
		return nil, ErrNotAnARPRequest
	}
	req := &ARPRequest{
		SenderMAC: net.HardwareAddr(append([]byte(nil), frame[22:28]...)),
		SenderIP:  net.IP(append([]byte(nil), frame[28:32]...)),
		TargetIP:  net.IP(append([]byte(nil), frame[38:42]...)),
	}
	return req, nil
}

// BuildARPReply builds a UNICAST ARP reply claiming targetIP for ourMAC,
// addressed back to the requester.
//
// Unicast, not broadcast: a reply is an answer to one asker. Broadcasting it
// would program the mapping into every neighbour on the segment, which is what
// the gratuitous announce path is for and is deliberately a separate decision
// with its own RG gate (#8405). Answering broadly here would re-introduce the
// #8297 misdelivery shape from the other direction.
func BuildARPReply(ourMAC net.HardwareAddr, targetIP net.IP, req *ARPRequest) ([]byte, error) {
	ip4 := targetIP.To4()
	if ip4 == nil {
		return nil, fmt.Errorf("not an IPv4 address: %s", targetIP)
	}
	if len(ourMAC) != arpHLenEther {
		return nil, fmt.Errorf("bad hardware address length %d", len(ourMAC))
	}
	if req == nil || len(req.SenderMAC) != arpHLenEther || req.SenderIP.To4() == nil {
		return nil, errors.New("incomplete arp request")
	}
	pkt := make([]byte, arpFrameLen)
	copy(pkt[0:6], req.SenderMAC) // dst: the asker
	copy(pkt[6:12], ourMAC)       // src: us
	binary.BigEndian.PutUint16(pkt[12:14], unix.ETH_P_ARP)

	binary.BigEndian.PutUint16(pkt[14:16], arpHTypeEther)
	binary.BigEndian.PutUint16(pkt[16:18], arpPTypeIPv4)
	pkt[18] = arpHLenEther
	pkt[19] = arpPLenIPv4
	binary.BigEndian.PutUint16(pkt[20:22], arpOpcodeReply)

	copy(pkt[22:28], ourMAC) // sender hardware = us
	copy(pkt[28:32], ip4)    // sender protocol = the address we answer for
	copy(pkt[32:38], req.SenderMAC)
	copy(pkt[38:42], req.SenderIP.To4())
	return pkt, nil
}

// ARPAnswerPolicy decides whether this node answers for targetIP on ifName.
// It is consulted PER REQUEST rather than at responder start, because RG
// ownership changes while the responder runs and a stale answer draws traffic
// to the wrong node.
type ARPAnswerPolicy func(ifName string, targetIP net.IP) bool

// OpenARPSocket opens an AF_PACKET/SOCK_RAW socket bound to one interface,
// receiving only ARP. Split out so the responder loop is testable against a
// pipe rather than a raw socket.
func OpenARPSocket(ifName string) (fd int, ifIndex int, mac net.HardwareAddr, err error) {
	ifi, err := net.InterfaceByName(ifName)
	if err != nil {
		return -1, 0, nil, fmt.Errorf("interface %s: %w", ifName, err)
	}
	fd, err = linuxsock.Socket(unix.AF_PACKET, unix.SOCK_RAW, int(htons(unix.ETH_P_ARP)))
	if err != nil {
		return -1, 0, nil, fmt.Errorf("raw socket: %w", err)
	}
	// Bind to THIS interface. Without it the socket receives ARP from every
	// interface and the responder would answer on the wrong segment for an
	// address that is only proxied on one.
	if err := unix.Bind(fd, &unix.SockaddrLinklayer{
		Protocol: htons(unix.ETH_P_ARP),
		Ifindex:  ifi.Index,
	}); err != nil {
		unix.Close(fd)
		return -1, 0, nil, fmt.Errorf("bind %s: %w", ifName, err)
	}
	return fd, ifi.Index, ifi.HardwareAddr, nil
}

// ARPReplyVerdict is why a request was or was not answered. It is a named
// verdict rather than a bare bool so each refusal is bindable by a test: a
// responder that answers nothing and a responder that answers everything both
// "work" against a bool, and the difference between them is the whole defect
// this guards.
type ARPReplyVerdict int

const (
	// ARPReplyAnswer: we proxy this address on this interface and own it.
	ARPReplyAnswer ARPReplyVerdict = iota
	// ARPReplyOwnFrame: the sender is us. Our own gratuitous announces come
	// back on this socket, and answering them would be a self-sustaining loop.
	ARPReplyOwnFrame
	// ARPReplyGratuitous: sender IP == target IP. That is an announcement or a
	// self-probe, not a question. `arp_fwd_pvlan` skips these for the same
	// reason ("Don't reply on self probes").
	ARPReplyGratuitous
	// ARPReplyNotOurs: the policy declined — either this address is not a
	// proxy-ARP address on this interface, or this node does not own the
	// redundancy group that does. The second case is the load-bearing one: the
	// RETH virtual MAC is PER NODE, so a standby that answered would answer
	// with its own MAC and draw traffic to itself, which is precisely the
	// misdelivery #8405 measured.
	ARPReplyNotOurs
)

// DecideARPReply is the whole answer/refuse decision, extracted from the
// receive loop so it can be driven directly.
//
// ourMAC is compared against the sender to drop our own frames. policy is
// consulted LAST, so a test that stubs it to "always yes" still cannot make the
// structural refusals disappear.
func DecideARPReply(req *ARPRequest, ourMAC net.HardwareAddr, ifName string, policy ARPAnswerPolicy) ARPReplyVerdict {
	if req == nil {
		return ARPReplyNotOurs
	}
	if len(ourMAC) == arpHLenEther && req.SenderMAC.String() == net.HardwareAddr(ourMAC).String() {
		return ARPReplyOwnFrame
	}
	if req.SenderIP.Equal(req.TargetIP) {
		return ARPReplyGratuitous
	}
	if policy == nil || !policy(ifName, req.TargetIP) {
		return ARPReplyNotOurs
	}
	return ARPReplyAnswer
}

// HandleARPFrame parses one frame and returns the reply to send, or nil when
// the frame must be ignored.
//
// The parsed request is returned alongside so the caller can address the reply
// without parsing the frame a SECOND time — the sender MAC is needed for the
// link-layer destination, and re-deriving it would mean two parses of
// attacker-supplied bytes per answered frame where one will do. The verdict is
// returned so a caller can count refusals by reason without re-deriving them.
func HandleARPFrame(frame []byte, ourMAC net.HardwareAddr, ifName string, policy ARPAnswerPolicy) ([]byte, *ARPRequest, ARPReplyVerdict) {
	req, err := ParseARPRequest(frame)
	if err != nil {
		return nil, nil, ARPReplyNotOurs
	}
	verdict := DecideARPReply(req, ourMAC, ifName, policy)
	if verdict != ARPReplyAnswer {
		return nil, req, verdict
	}
	reply, err := BuildARPReply(ourMAC, req.TargetIP, req)
	if err != nil {
		return nil, req, ARPReplyNotOurs
	}
	return reply, req, ARPReplyAnswer
}
