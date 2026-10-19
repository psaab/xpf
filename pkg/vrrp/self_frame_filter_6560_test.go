package vrrp

import (
	"encoding/binary"
	"net"
	"testing"

	"golang.org/x/sys/unix"
)

// TestAfPacketFrameIsOutgoing_6560 pins the classification the receive loop
// gates on. Before #6560 the sockaddr from Recvfrom was discarded (`n, _, err
// :=`), so sll_pkttype was structurally unavailable and a self-transmitted
// advert was indistinguishable from a peer's.
func TestAfPacketFrameIsOutgoing_6560(t *testing.T) {
	if !afPacketFrameIsOutgoing(&unix.SockaddrLinklayer{Pkttype: unix.PACKET_OUTGOING}) {
		t.Fatal("a PACKET_OUTGOING frame is our own transmission and must be dropped")
	}
	// Every delivery type a PEER's advert can arrive as must be kept. Getting
	// this wrong is not a missed optimisation — dropping a peer advert is a
	// self-inflicted master-down.
	for name, pt := range map[string]uint8{
		"multicast": unix.PACKET_MULTICAST,
		"host":      unix.PACKET_HOST,
		"broadcast": unix.PACKET_BROADCAST,
		"otherhost": unix.PACKET_OTHERHOST,
	} {
		if afPacketFrameIsOutgoing(&unix.SockaddrLinklayer{Pkttype: pt}) {
			t.Fatalf("a PACKET_%s frame is a peer's advert and must be kept", name)
		}
	}
	// An unclassifiable sockaddr FAILS OPEN: a frame we cannot classify must
	// still be able to be a peer's advert.
	if afPacketFrameIsOutgoing(nil) {
		t.Fatal("a nil sockaddr must fail open (kept), not be dropped as self")
	}
	if afPacketFrameIsOutgoing(&unix.SockaddrInet4{}) {
		t.Fatal("a non-link-layer sockaddr must fail open (kept), not be dropped as self")
	}
	// A typed-nil *SockaddrLinklayer must not panic on the Pkttype deref.
	var typedNil *unix.SockaddrLinklayer
	if afPacketFrameIsOutgoing(typedNil) {
		t.Fatal("a typed-nil link-layer sockaddr must fail open (kept)")
	}
}

// TestAfPacketReceiverIgnoresOutgoing_6560 is the WIRING gate for the socket
// option: openAfPacketReceiver must actually ask the kernel to stop delivering
// our own transmissions. It intercepts the setsockopt(2) entry point so the
// exact (level, option, value) at the call site is asserted deterministically,
// without CAP_NET_RAW.
//
// Deleting the afPacketSetsockoptInt call from openAfPacketReceiver makes this
// go red; the pure classification test above would not catch that.
func TestAfPacketReceiverIgnoresOutgoing_6560(t *testing.T) {
	type call struct{ level, opt, value int }
	var calls []call

	origSock := afPacketSocket
	origOpt := afPacketSetsockoptInt
	defer func() {
		afPacketSocket = origSock
		afPacketSetsockoptInt = origOpt
	}()

	// Hand back a real but harmless fd so the function proceeds past socket()
	// into the setsockopt call. Bind then fails (a link-layer address on an
	// AF_UNIX socket), which is fine — the option is set BEFORE bind on purpose,
	// because an ETH_P_ALL socket is already capturing at creation and setting
	// it after bind would leave a window for our own frames to queue.
	fd, err := unix.Socket(unix.AF_UNIX, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Skipf("cannot open a stand-in fd: %v", err)
	}
	defer unix.Close(fd)

	afPacketSocket = func(_, _, _ int) (int, error) { return fd, nil }
	afPacketSetsockoptInt = func(_, level, opt, value int) error {
		calls = append(calls, call{level, opt, value})
		return unix.ENOPROTOOPT // an old kernel — must be tolerated, not fatal
	}

	// Bind will fail; that is expected and irrelevant to what is asserted.
	_, _ = openAfPacketReceiver(1)

	var found bool
	for _, c := range calls {
		if c.level == unix.SOL_PACKET && c.opt == unix.PACKET_IGNORE_OUTGOING {
			found = true
			if c.value != 1 {
				t.Fatalf("PACKET_IGNORE_OUTGOING set to %d, want 1", c.value)
			}
		}
	}
	if !found {
		t.Fatalf("openAfPacketReceiver never set PACKET_IGNORE_OUTGOING; setsockopt calls: %+v", calls)
	}
}

// buildSelfAdvertFrame6560 builds a complete, VALID Ethernet + IPv4 + VRRPv3
// advertisement frame from srcIP, exactly as this node would transmit one. It
// must be genuinely parseable: a frame the parser would reject for any other
// reason would make the test below pass for the wrong reason.
func buildSelfAdvertFrame6560(t *testing.T, srcIP net.IP, vrid, prio uint8) []byte {
	t.Helper()
	dstIP := net.IPv4(224, 0, 0, 18).To4()
	pkt := &VRRPPacket{
		VRID:         vrid,
		Priority:     prio,
		MaxAdvertInt: 3,
		IPAddresses:  []net.IP{srcIP.To4()},
	}
	payload, err := pkt.Marshal(false, srcIP.To4(), dstIP)
	if err != nil {
		t.Fatalf("marshal advert: %v", err)
	}

	frame := make([]byte, 14+20+len(payload))
	binary.BigEndian.PutUint16(frame[12:14], 0x0800) // ethertype IPv4

	ip := frame[14:]
	ip[0] = 0x45                                                 // v4, IHL 5
	binary.BigEndian.PutUint16(ip[2:4], uint16(20+len(payload))) // total length
	ip[8] = 255                                                  // TTL, RFC 5798 §5.1.1.3
	ip[9] = 112                                                  // proto VRRP
	copy(ip[12:16], srcIP.To4())
	copy(ip[16:20], dstIP)
	copy(ip[20:], payload)
	return frame
}

// TestReceiverAfPacketDropsSelfFrameWithNilSnapshot_6560 is the fail-on-revert
// gate for the LOOP, and it reproduces the issue's exact scenario.
//
// The local-IP snapshot is left NIL — the state reresolveLocalAddrs stores
// during the #2528 RETH-MAC flush window, when programRethMAC's link DOWN has
// flushed every kernel address. All four existing self-checks are written
// `lip != nil && src.Equal(lip)`, so a nil snapshot means ACCEPT: without the
// sll_pkttype drop this node's OWN advert reaches rxCh, and from there
// handleMasterRx -> resolveEqualPriorityMaster, which on a nil snapshot logs
// "local source unresolved — stepping down" and calls becomeBackup. A MASTER
// demotes itself.
//
// Deleting `if afPacketFrameIsOutgoing(from) { continue }` from receiverAfPacket
// makes this go red. Neither the pure classification test nor the setsockopt
// wiring test above would catch that deletion.
func TestReceiverAfPacketDropsSelfFrameWithNilSnapshot_6560(t *testing.T) {
	const vrid = 42
	self := net.IPv4(10, 0, 61, 1)
	peer := net.IPv4(10, 0, 61, 2)

	vi := &vrrpInstance{
		afPacketFD: 3, // never touched: the recvfrom seam is stubbed
		rxCh:       make(chan *VRRPPacket, 8),
		stopCh:     make(chan struct{}),
	}
	vi.cfg.GroupID = vrid
	vi.cfg.Family = "inet"
	// The flush window: no local address of the family is resolvable.
	vi.setLocalIP(nil)
	if vi.getLocalIP() != nil {
		t.Fatal("setup: the local-IP snapshot must be nil to reproduce the flush window")
	}

	// Same VRID and the same priority the instance would advertise, so the
	// frame lands on resolveEqualPriorityMaster's equal-priority branch — the
	// path that steps a MASTER down.
	selfFrame := buildSelfAdvertFrame6560(t, self, vrid, 100)
	peerFrame := buildSelfAdvertFrame6560(t, peer, vrid, 100)

	type delivery struct {
		frame   []byte
		pkttype uint8
	}
	queue := []delivery{
		{selfFrame, unix.PACKET_OUTGOING},  // our own transmission, tapped on TX
		{peerFrame, unix.PACKET_MULTICAST}, // a real peer advert
	}

	orig := afPacketRecvmsg
	defer func() { afPacketRecvmsg = orig }()
	idx := 0
	afPacketRecvmsg = func(_ int, p, _ []byte, _ int) (int, int, int, unix.Sockaddr, error) {
		if idx >= len(queue) {
			close(vi.stopCh)
			return 0, 0, 0, nil, unix.EAGAIN
		}
		d := queue[idx]
		idx++
		n := copy(p, d.frame)
		return n, 0, 0, &unix.SockaddrLinklayer{Pkttype: d.pkttype}, nil
	}

	done := make(chan struct{})
	go func() { vi.receiverAfPacket(); close(done) }()
	<-done

	var got []string
	for {
		select {
		case pkt := <-vi.rxCh:
			got = append(got, pkt.SrcIP.String())
			continue
		default:
		}
		break
	}

	// The peer advert MUST have arrived — otherwise the assertion below is
	// vacuous (a loop that dropped everything would also "drop the self frame").
	if len(got) != 1 || got[0] != peer.String() {
		t.Fatalf("received %v; want exactly the peer advert %s — the self-sent "+
			"PACKET_OUTGOING frame must be dropped and the peer's kept",
			got, peer.String())
	}
}
