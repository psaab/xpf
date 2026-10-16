package dhcprelay

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/insomniacslk/dhcp/dhcpv4"
	"github.com/insomniacslk/dhcp/iana"
)

// fakeL2 records sendReply calls and can be forced to fail to exercise the
// broadcast fallback. It implements l2Replier.
type fakeL2 struct {
	mu         sync.Mutex
	calls      []fakeL2Call
	failWith   error
	closeCount int
}

type fakeL2Call struct {
	dstMAC       net.HardwareAddr
	srcIP, dstIP net.IP
	payload      []byte
}

func (f *fakeL2) sendReply(dstMAC net.HardwareAddr, srcIP, dstIP net.IP, payload []byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	cp := append([]byte(nil), payload...)
	f.calls = append(f.calls, fakeL2Call{
		dstMAC:  append(net.HardwareAddr(nil), dstMAC...),
		srcIP:   append(net.IP(nil), srcIP...),
		dstIP:   append(net.IP(nil), dstIP...),
		payload: cp,
	})
	return f.failWith
}

func (f *fakeL2) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.closeCount++
	return nil
}

func (f *fakeL2) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.calls)
}

// newReply builds a BOOTREPLY OFFER with the given flags/yiaddr/ciaddr/chaddr.
func newReply(t *testing.T, broadcast bool, yiaddr, ciaddr net.IP, chaddr net.HardwareAddr) *dhcpv4.DHCPv4 {
	t.Helper()
	pkt, err := dhcpv4.New()
	if err != nil {
		t.Fatalf("dhcpv4.New: %v", err)
	}
	pkt.OpCode = dhcpv4.OpcodeBootReply
	pkt.HWType = iana.HWTypeEthernet
	pkt.ClientHWAddr = chaddr
	pkt.UpdateOption(dhcpv4.OptMessageType(dhcpv4.MessageTypeOffer))
	if broadcast {
		pkt.SetBroadcast()
	}
	if yiaddr != nil {
		pkt.YourIPAddr = yiaddr
	} else {
		pkt.YourIPAddr = net.IPv4zero
	}
	if ciaddr != nil {
		pkt.ClientIPAddr = ciaddr
	} else {
		pkt.ClientIPAddr = net.IPv4zero
	}
	return pkt
}

var (
	testGiaddr = net.IPv4(10, 0, 0, 254)
	testYiaddr = net.IPv4(10, 0, 0, 50)
	testCiaddr = net.IPv4(10, 0, 0, 60)
	testChaddr = net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x99}
	// testServerIP matches the default source IP fakeConn.ReadFrom reports for
	// pending datagrams (10.0.0.1), so the #4163 source-validation check admits
	// the existing reply-path tests. Drive a drop by pointing fakeConn.srcAddr
	// at a different IP.
	testServerIP = net.IPv4(10, 0, 0, 1)
)

// testServerSet returns the configured-server allow-set passed into
// handleServerResponses. With no args it is the single default server
// (testServerIP) that matches fakeConn's default reply source.
func testServerSet(ips ...net.IP) []*net.UDPAddr {
	if len(ips) == 0 {
		ips = []net.IP{testServerIP}
	}
	set := make([]*net.UDPAddr, 0, len(ips))
	for _, ip := range ips {
		set = append(set, &net.UDPAddr{IP: ip, Port: relayPort})
	}
	return set
}

// armedRelay builds an interfaceRelay whose #6562 outstanding-request table is
// already armed for each given reply — i.e. it models the normal flow, where
// the client-facing loop forwarded a request upstream and the server echoed
// that request's xid and chaddr back (RFC 2131 §4.3.1 Table 3).
//
// Every handleServerResponses test that expects a reply to be DELIVERED must
// arm the relay: an unbound reply is now dropped by design. Tests that expect a
// DROP use a bare interfaceRelay (unarmedRelay) instead.
func armedRelay(name string, replies ...*dhcpv4.DHCPv4) *interfaceRelay {
	ir := unarmedRelay(name)
	for _, r := range replies {
		insertPending(ir.pending, r)
		if r != nil {
			ir.pendingRequestCiaddr = r.ClientIPAddr.To4()
		}
	}
	return ir
}

// unarmedRelay builds an interfaceRelay with a live-but-EMPTY pending table:
// no outstanding requests, so every reply fails the #6562 binding. It is a real
// table rather than a nil one so these tests exercise the ordinary miss path,
// not the nil-receiver fail-closed guard.
func unarmedRelay(name string) *interfaceRelay {
	return &interfaceRelay{
		ifaceName: name,
		pending:   newPendingTable(defaultTestPendingCap(), pendingTTL, time.Now),
	}
}

// TestDeliverReply_Matrix is the §7.1 decision-matrix oracle: every row of the
// reply-destination table maps to exactly one delivery path and one counter.
func TestDeliverReply_Matrix(t *testing.T) {
	type want struct {
		l2Calls     int          // raw-L2 unicast sends
		clientWrite *net.UDPAddr // expected UDP WriteTo dst, nil if none
		counter     func(*interfaceRelay) uint64
		counterName string
	}
	cases := []struct {
		name            string
		alwaysBroadcast bool
		l2Fails         bool
		nilL2           bool
		pkt             func(*testing.T) *dhcpv4.DHCPv4
		want            want
	}{
		{
			name: "flag1_broadcast",
			pkt:  func(t *testing.T) *dhcpv4.DHCPv4 { return newReply(t, true, testYiaddr, nil, testChaddr) },
			want: want{
				clientWrite: &net.UDPAddr{IP: net.IPv4bcast, Port: clientPort},
				counter:     func(ir *interfaceRelay) uint64 { return ir.repliesBroadcastFlag1.Load() },
				counterName: "repliesBroadcastFlag1",
			},
		},
		{
			name: "flag0_real_yiaddr_L2",
			pkt:  func(t *testing.T) *dhcpv4.DHCPv4 { return newReply(t, false, testYiaddr, nil, testChaddr) },
			want: want{
				l2Calls:     1,
				counter:     func(ir *interfaceRelay) uint64 { return ir.repliesL2Unicast.Load() },
				counterName: "repliesL2Unicast",
			},
		},
		{
			name:    "flag0_real_yiaddr_L2_fail_fallback",
			l2Fails: true,
			pkt:     func(t *testing.T) *dhcpv4.DHCPv4 { return newReply(t, false, testYiaddr, nil, testChaddr) },
			want: want{
				l2Calls:     1,
				clientWrite: &net.UDPAddr{IP: net.IPv4bcast, Port: clientPort},
				counter:     func(ir *interfaceRelay) uint64 { return ir.repliesBroadcastL2Fallback.Load() },
				counterName: "repliesBroadcastL2Fallback",
			},
		},
		{
			name:  "flag0_real_yiaddr_nil_l2_fallback",
			nilL2: true,
			pkt:   func(t *testing.T) *dhcpv4.DHCPv4 { return newReply(t, false, testYiaddr, nil, testChaddr) },
			want: want{
				clientWrite: &net.UDPAddr{IP: net.IPv4bcast, Port: clientPort},
				counter:     func(ir *interfaceRelay) uint64 { return ir.repliesBroadcastL2Fallback.Load() },
				counterName: "repliesBroadcastL2Fallback",
			},
		},
		{
			name: "flag0_no_yiaddr_ciaddr_unicast",
			pkt:  func(t *testing.T) *dhcpv4.DHCPv4 { return newReply(t, false, nil, testCiaddr, testChaddr) },
			want: want{
				clientWrite: &net.UDPAddr{IP: testCiaddr, Port: clientPort},
				counter:     func(ir *interfaceRelay) uint64 { return ir.repliesUnicastCiaddr.Load() },
				counterName: "repliesUnicastCiaddr",
			},
		},
		{
			name: "flag0_no_yiaddr_no_ciaddr_broadcast",
			pkt:  func(t *testing.T) *dhcpv4.DHCPv4 { return newReply(t, false, nil, nil, testChaddr) },
			want: want{
				clientWrite: &net.UDPAddr{IP: net.IPv4bcast, Port: clientPort},
				counter:     func(ir *interfaceRelay) uint64 { return ir.repliesBroadcastNoTarget.Load() },
				counterName: "repliesBroadcastNoTarget",
			},
		},
		{
			name:            "overrides_always_broadcast_wins",
			alwaysBroadcast: true,
			pkt:             func(t *testing.T) *dhcpv4.DHCPv4 { return newReply(t, false, testYiaddr, nil, testChaddr) },
			want: want{
				clientWrite: &net.UDPAddr{IP: net.IPv4bcast, Port: clientPort},
				counter:     func(ir *interfaceRelay) uint64 { return ir.repliesBroadcastForced.Load() },
				counterName: "repliesBroadcastForced",
			},
		},
		{
			name:            "overrides_beats_flag0_yiaddr_no_L2",
			alwaysBroadcast: true,
			pkt:             func(t *testing.T) *dhcpv4.DHCPv4 { return newReply(t, false, testYiaddr, nil, testChaddr) },
			want: want{
				l2Calls:     0, // override must NOT touch the L2 path
				clientWrite: &net.UDPAddr{IP: net.IPv4bcast, Port: clientPort},
				counter:     func(ir *interfaceRelay) uint64 { return ir.repliesBroadcastForced.Load() },
				counterName: "repliesBroadcastForced",
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ir := &interfaceRelay{ifaceName: "ge-0-0-0", alwaysBroadcast: tc.alwaysBroadcast}
			client := newFakeConn()
			defer client.Close()
			var l2 l2Replier
			fl2 := &fakeL2{}
			if tc.l2Fails {
				fl2.failWith = errors.New("forced l2 failure")
			}
			if !tc.nilL2 {
				l2 = fl2
			}
			pkt := tc.pkt(t)
			ir.pendingRequestCiaddr = pkt.ClientIPAddr.To4()
			payload := pkt.ToBytes()

			ok := deliverReply(ir, client, l2, testGiaddr, pkt, payload)
			if !ok {
				t.Fatalf("deliverReply returned false (delivery failed)")
			}
			if got := fl2.callCount(); got != tc.want.l2Calls {
				t.Errorf("L2 sendReply calls = %d, want %d", got, tc.want.l2Calls)
			}

			client.mu.Lock()
			writes := append([]fakeWrite(nil), client.writes...)
			client.mu.Unlock()
			if tc.want.clientWrite == nil {
				if len(writes) != 0 {
					t.Errorf("expected NO client UDP write, got %d", len(writes))
				}
			} else {
				if len(writes) != 1 {
					t.Fatalf("expected 1 client UDP write, got %d", len(writes))
				}
				got := writes[0].addr.(*net.UDPAddr)
				if !got.IP.Equal(tc.want.clientWrite.IP) || got.Port != tc.want.clientWrite.Port {
					t.Errorf("client write dst = %v, want %v", got, tc.want.clientWrite)
				}
			}

			if got := tc.want.counter(ir); got != 1 {
				t.Errorf("counter %s = %d, want 1", tc.want.counterName, got)
			}

			// On the L2-success path, verify the L2 frame is addressed to
			// chaddr + yiaddr with the SAVED giaddr source.
			if tc.want.l2Calls == 1 && !tc.l2Fails {
				fl2.mu.Lock()
				c := fl2.calls[0]
				fl2.mu.Unlock()
				if !equalBytes(c.dstMAC, testChaddr) {
					t.Errorf("L2 dstMAC = %x, want chaddr %x", c.dstMAC, testChaddr)
				}
				if !c.srcIP.Equal(testGiaddr) {
					t.Errorf("L2 srcIP = %v, want saved giaddr %v", c.srcIP, testGiaddr)
				}
				if !c.dstIP.Equal(testYiaddr) {
					t.Errorf("L2 dstIP = %v, want yiaddr %v", c.dstIP, testYiaddr)
				}
			}
		})
	}
}

// TestL2Eligible enforces the htype/chaddr guards: only 6-byte Ethernet
// addresses are L2-eligible; everything else falls back to broadcast.
func TestL2Eligible(t *testing.T) {
	mk := func(ht iana.HWType, chaddr net.HardwareAddr) *dhcpv4.DHCPv4 {
		return &dhcpv4.DHCPv4{HWType: ht, ClientHWAddr: chaddr}
	}
	mac6 := net.HardwareAddr{1, 2, 3, 4, 5, 6}
	mac8 := net.HardwareAddr{1, 2, 3, 4, 5, 6, 7, 8}

	if !l2Eligible(mk(iana.HWTypeEthernet, mac6)) {
		t.Errorf("6-byte Ethernet must be L2-eligible")
	}
	if l2Eligible(mk(iana.HWTypeEthernet, mac8)) {
		t.Errorf("8-byte chaddr must NOT be L2-eligible")
	}
	if l2Eligible(mk(iana.HWTypeIEEE802, mac6)) {
		t.Errorf("non-Ethernet htype must NOT be L2-eligible")
	}
	if l2Eligible(mk(iana.HWTypeEthernet, net.HardwareAddr{1, 2, 3})) {
		t.Errorf("3-byte chaddr must NOT be L2-eligible")
	}
}

// TestDeliverReply_NonEthernet_FallsBackToBroadcast proves a non-Ethernet htype
// with a real yiaddr does NOT take the L2 path (the frame would be malformed)
// and broadcasts instead, counting it as an L2 fallback.
func TestDeliverReply_NonEthernet_FallsBackToBroadcast(t *testing.T) {
	ir := &interfaceRelay{ifaceName: "ge-0-0-0"}
	client := newFakeConn()
	defer client.Close()
	fl2 := &fakeL2{}

	pkt := newReply(t, false, testYiaddr, nil, net.HardwareAddr{1, 2, 3, 4, 5, 6})
	pkt.HWType = iana.HWTypeIEEE802 // not Ethernet

	if !deliverReply(ir, client, fl2, testGiaddr, pkt, pkt.ToBytes()) {
		t.Fatal("deliverReply returned false")
	}
	if fl2.callCount() != 0 {
		t.Errorf("non-Ethernet must NOT call L2 sendReply, got %d", fl2.callCount())
	}
	if ir.repliesBroadcastL2Fallback.Load() != 1 {
		t.Errorf("expected L2-fallback counter, got %d", ir.repliesBroadcastL2Fallback.Load())
	}
	client.mu.Lock()
	n := len(client.writes)
	dst := net.IP(nil)
	if n == 1 {
		dst = client.writes[0].addr.(*net.UDPAddr).IP
	}
	client.mu.Unlock()
	if n != 1 || !dst.Equal(net.IPv4bcast) {
		t.Errorf("expected 1 broadcast write, got %d to %v", n, dst)
	}
}

// TestDeliverReply_ExactlyOneSend_NoDoubleDeliver proves a single relay
// instance never double-delivers a reply: for every matrix row, the total
// number of sends (L2 + UDP) is EXACTLY one. This is the per-node invariant
// behind the #2076 §7.6 HA analysis — cross-node duplication (Backup also
// relaying) is handled by client xid+chaddr dedupe, but a single node must
// NOT itself emit both an L2 frame AND a broadcast for the same reply (which
// WOULD be a new duplicate-delivery defect introduced by this change).
func TestDeliverReply_ExactlyOneSend_NoDoubleDeliver(t *testing.T) {
	type row struct {
		name            string
		alwaysBroadcast bool
		l2Fails         bool
		pkt             func(*testing.T) *dhcpv4.DHCPv4
	}
	rows := []row{
		{"flag1", false, false, func(t *testing.T) *dhcpv4.DHCPv4 { return newReply(t, true, testYiaddr, nil, testChaddr) }},
		{"flag0_L2_ok", false, false, func(t *testing.T) *dhcpv4.DHCPv4 { return newReply(t, false, testYiaddr, nil, testChaddr) }},
		{"flag0_L2_fail", false, true, func(t *testing.T) *dhcpv4.DHCPv4 { return newReply(t, false, testYiaddr, nil, testChaddr) }},
		{"ciaddr", false, false, func(t *testing.T) *dhcpv4.DHCPv4 { return newReply(t, false, nil, testCiaddr, testChaddr) }},
		{"no_target", false, false, func(t *testing.T) *dhcpv4.DHCPv4 { return newReply(t, false, nil, nil, testChaddr) }},
		{"override", true, false, func(t *testing.T) *dhcpv4.DHCPv4 { return newReply(t, false, testYiaddr, nil, testChaddr) }},
	}
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			ir := &interfaceRelay{ifaceName: "ge-0-0-0", alwaysBroadcast: r.alwaysBroadcast}
			client := newFakeConn()
			defer client.Close()
			fl2 := &fakeL2{}
			if r.l2Fails {
				fl2.failWith = errors.New("forced")
			}
			pkt := r.pkt(t)
			ir.pendingRequestCiaddr = pkt.ClientIPAddr.To4()
			if !deliverReply(ir, client, fl2, testGiaddr, pkt, pkt.ToBytes()) {
				t.Fatal("deliverReply returned false")
			}
			client.mu.Lock()
			udpSends := len(client.writes)
			client.mu.Unlock()
			total := udpSends + fl2.callCount()
			// On L2 failure, the L2 attempt counts as one call but the frame
			// did NOT go on the wire — the broadcast fallback is the single
			// delivered send. So the DELIVERED count is exactly one UDP send.
			if r.l2Fails {
				if udpSends != 1 {
					t.Errorf("%s: expected exactly 1 delivered (broadcast) send, got udp=%d l2=%d",
						r.name, udpSends, fl2.callCount())
				}
				return
			}
			if total != 1 {
				t.Errorf("%s: expected exactly 1 send, got udp=%d + l2=%d = %d",
					r.name, udpSends, fl2.callCount(), total)
			}
		})
	}
}

// newNak builds a BOOTREPLY DHCPNAK. Per RFC 2131 a NAK carries no binding,
// so yiaddr/ciaddr are zero; broadcast controls whether the client set the
// flag. A stale ciaddr is accepted to exercise the force-broadcast guard.
func newNak(t *testing.T, broadcast bool, ciaddr net.IP, chaddr net.HardwareAddr) *dhcpv4.DHCPv4 {
	t.Helper()
	pkt, err := dhcpv4.New()
	if err != nil {
		t.Fatalf("dhcpv4.New: %v", err)
	}
	pkt.OpCode = dhcpv4.OpcodeBootReply
	pkt.HWType = iana.HWTypeEthernet
	pkt.ClientHWAddr = chaddr
	pkt.UpdateOption(dhcpv4.OptMessageType(dhcpv4.MessageTypeNak))
	if broadcast {
		pkt.SetBroadcast()
	}
	pkt.YourIPAddr = net.IPv4zero
	if ciaddr != nil {
		pkt.ClientIPAddr = ciaddr
	} else {
		pkt.ClientIPAddr = net.IPv4zero
	}
	return pkt
}

// TestDeliverReply_Nak_AlwaysBroadcast proves a DHCPNAK is force-broadcast to
// the client (RFC 2131 §4.3.2) regardless of the broadcast flag, never
// unicast — even when the server erroneously echoes a stale ciaddr that would
// otherwise drive the matrix to a UDP unicast. It must also never take the
// raw-L2 path (yiaddr is zero, so there is no address to unicast to).
func TestDeliverReply_Nak_AlwaysBroadcast(t *testing.T) {
	cases := []struct {
		name      string
		broadcast bool
		ciaddr    net.IP
	}{
		{"flag_clear_no_ciaddr", false, nil},
		{"flag_set_no_ciaddr", true, nil},
		// Defense-in-depth: a NAK MUST NOT be unicast even if the server
		// (incorrectly) leaves a stale ciaddr in the reply.
		{"flag_clear_stale_ciaddr", false, testCiaddr},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ir := &interfaceRelay{ifaceName: "ge-0-0-0"}
			client := newFakeConn()
			defer client.Close()
			fl2 := &fakeL2{}

			pkt := newNak(t, tc.broadcast, tc.ciaddr, testChaddr)
			if !deliverReply(ir, client, fl2, testGiaddr, pkt, pkt.ToBytes()) {
				t.Fatal("deliverReply returned false (NAK not delivered)")
			}

			if fl2.callCount() != 0 {
				t.Errorf("NAK must NOT use raw-L2 unicast, got %d calls", fl2.callCount())
			}
			if ir.repliesBroadcastNak.Load() != 1 {
				t.Errorf("repliesBroadcastNak = %d, want 1", ir.repliesBroadcastNak.Load())
			}
			if ir.repliesUnicastCiaddr.Load() != 0 {
				t.Errorf("NAK must NOT unicast to ciaddr, got %d", ir.repliesUnicastCiaddr.Load())
			}

			client.mu.Lock()
			writes := append([]fakeWrite(nil), client.writes...)
			client.mu.Unlock()
			if len(writes) != 1 {
				t.Fatalf("expected 1 client UDP write, got %d", len(writes))
			}
			got := writes[0].addr.(*net.UDPAddr)
			if !got.IP.Equal(net.IPv4bcast) || got.Port != clientPort {
				t.Errorf("NAK dst = %v, want broadcast %v:%d", got, net.IPv4bcast, clientPort)
			}
		})
	}
}

// TestHandleServerResponses_NakForwarded is the fail-on-revert gate for #2606:
// a DHCPNAK server reply MUST be forwarded to the client (broadcast), not
// silently dropped. Removing dhcpv4.MessageTypeNak from the accepted set in
// handleServerResponses makes this test red (the NAK is never written to the
// client conn).
func TestHandleServerResponses_NakForwarded(t *testing.T) {
	nak := newNak(t, false, nil, testChaddr)
	nak.GatewayIPAddr = testGiaddr // server echoes giaddr; relay must zero it
	serverConn := newFakeConn()
	serverConn.mu.Lock()
	serverConn.pending = [][]byte{nak.ToBytes()}
	serverConn.mu.Unlock()
	clientConn := newFakeConn()
	defer clientConn.Close()
	fl2 := &fakeL2{}
	ir := armedRelay("ge-0-0-0", nak)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		handleServerResponses(ctx, serverConn, clientConn, ir, fl2, testGiaddr, testServerSet())
		close(done)
	}()

	// Wait for the client-direction write (the NAK must reach the client).
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		clientConn.mu.Lock()
		n := len(clientConn.writes)
		clientConn.mu.Unlock()
		if n > 0 {
			break
		}
		time.Sleep(time.Millisecond)
	}

	clientConn.mu.Lock()
	writes := append([]fakeWrite(nil), clientConn.writes...)
	clientConn.mu.Unlock()
	if len(writes) != 1 {
		t.Fatalf("DHCPNAK not forwarded to client: got %d writes, want 1", len(writes))
	}
	dst := writes[0].addr.(*net.UDPAddr)
	if !dst.IP.Equal(net.IPv4bcast) || dst.Port != clientPort {
		t.Errorf("NAK forwarded to %v, want broadcast %v:%d", dst, net.IPv4bcast, clientPort)
	}
	if fl2.callCount() != 0 {
		t.Errorf("NAK must not use raw-L2, got %d calls", fl2.callCount())
	}
	if ir.repliesForwarded.Load() != 1 {
		t.Errorf("repliesForwarded = %d, want 1", ir.repliesForwarded.Load())
	}

	cancel()
	serverConn.Close()
	<-done
}

// newForceRenew builds a BOOTREPLY DHCPFORCERENEW (RFC 3203, type 9). The
// server forces a client that ALREADY holds a lease back into RENEWING, so the
// message carries the client's current address in ciaddr and no yiaddr.
func newForceRenew(t *testing.T, ciaddr net.IP, chaddr net.HardwareAddr) *dhcpv4.DHCPv4 {
	t.Helper()
	pkt, err := dhcpv4.New()
	if err != nil {
		t.Fatalf("dhcpv4.New: %v", err)
	}
	pkt.OpCode = dhcpv4.OpcodeBootReply
	pkt.HWType = iana.HWTypeEthernet
	pkt.ClientHWAddr = chaddr
	pkt.UpdateOption(dhcpv4.OptMessageType(messageTypeForceRenew))
	pkt.YourIPAddr = net.IPv4zero
	pkt.ClientIPAddr = ciaddr
	return pkt
}

// TestHandleServerResponses_ForceRenewRefused is the #6562 fail-on-revert gate
// for the SECOND defect: a DHCPFORCERENEW MUST NOT be forwarded to the client,
// even when it arrives from a CONFIGURED server (so the #4163 source check
// passes) and is otherwise perfectly well formed.
//
// This deliberately REVERSES #2645, which forwarded FORCERENEW on the reasoning
// that RFC 3118 authentication is end-to-end and therefore not the relay's
// concern. RFC 3203 §6 makes that authentication a MUST precisely because
// "FORCERENEW can be used to snoop and spoof traffic", and a relay holds none
// of the key material RFC 3118 §5.2/§5.3 places between the client and the
// server — so it cannot verify one and refuses instead.
//
// Restoring messageTypeForceRenew to the forwarded set in handleServerResponses
// makes this RED: the reply reaches the client conn and
// repliesDroppedForceRenew stays 0.
func TestHandleServerResponses_ForceRenewRefused(t *testing.T) {
	fr := newForceRenew(t, testCiaddr, testChaddr)
	fr.GatewayIPAddr = testGiaddr
	serverConn := newFakeConn()
	serverConn.mu.Lock()
	serverConn.pending = [][]byte{fr.ToBytes()}
	serverConn.mu.Unlock()
	clientConn := newFakeConn()
	defer clientConn.Close()
	fl2 := &fakeL2{}
	// ARMED for this very transaction: the refusal must be driven by the
	// message TYPE, not by a missing outstanding-request binding. Without this
	// the test would pass for the wrong reason (the #6562 binding would drop it
	// anyway) and would not pin the FORCERENEW rule at all.
	ir := armedRelay("ge-0-0-0", fr)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		handleServerResponses(ctx, serverConn, clientConn, ir, fl2, testGiaddr, testServerSet())
		close(done)
	}()

	// The datagram is consumed but never forwarded, so poll the refusal counter
	// rather than a client write.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if ir.repliesDroppedForceRenew.Load() > 0 {
			break
		}
		time.Sleep(time.Millisecond)
	}

	if got := ir.repliesDroppedForceRenew.Load(); got != 1 {
		t.Errorf("repliesDroppedForceRenew = %d, want 1 (FORCERENEW must be refused+counted)", got)
	}
	clientConn.mu.Lock()
	nWrites := len(clientConn.writes)
	clientConn.mu.Unlock()
	if nWrites != 0 {
		t.Errorf("FORCERENEW reached the client: got %d client writes, want 0", nWrites)
	}
	if ir.repliesForwarded.Load() != 0 {
		t.Errorf("repliesForwarded = %d, want 0", ir.repliesForwarded.Load())
	}
	if ir.repliesUnicastCiaddr.Load() != 0 {
		t.Errorf("repliesUnicastCiaddr = %d, want 0 (must not reach deliverReply)", ir.repliesUnicastCiaddr.Load())
	}
	if fl2.callCount() != 0 {
		t.Errorf("FORCERENEW used raw-L2: got %d calls, want 0", fl2.callCount())
	}
	// The refusal is its OWN counter, not a side effect of the other gates —
	// an operator must be able to tell "FORCERENEW refused" from "rogue source"
	// and from "no outstanding request".
	if got := ir.repliesDroppedUnknownServer.Load(); got != 0 {
		t.Errorf("repliesDroppedUnknownServer = %d, want 0 (source WAS configured)", got)
	}
	if got := ir.repliesDroppedNoRequest.Load(); got != 0 {
		t.Errorf("repliesDroppedNoRequest = %d, want 0 (relay WAS armed for this xid)", got)
	}

	cancel()
	serverConn.Close()
	<-done
}

// TestHandleServerResponses_L2SourceIsSavedGiaddr proves the end-to-end path:
// handleServerResponses zeroes pkt.GatewayIPAddr before sending, yet the L2
// frame's source IP is the SAVED giaddr passed by runRelay (#2076 §7.2 / SMR-F4)
// — never the zeroed packet field.
func TestHandleServerResponses_L2SourceIsSavedGiaddr(t *testing.T) {
	// Build a flag-clear OFFER from a server and feed it through a server conn.
	offer := newReply(t, false, testYiaddr, nil, testChaddr)
	offer.GatewayIPAddr = testGiaddr // server echoes giaddr; we must zero it
	serverConn := newFakeConn()
	serverConn.mu.Lock()
	serverConn.pending = [][]byte{offer.ToBytes()}
	serverConn.mu.Unlock()
	clientConn := newFakeConn()
	defer clientConn.Close()
	fl2 := &fakeL2{}
	ir := armedRelay("ge-0-0-0", offer)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		handleServerResponses(ctx, serverConn, clientConn, ir, fl2, testGiaddr, testServerSet())
		close(done)
	}()

	// Wait for the L2 send.
	deadline := time.Now().Add(2 * time.Second)
	for fl2.callCount() == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if fl2.callCount() == 0 {
		t.Fatal("no L2 send observed")
	}
	fl2.mu.Lock()
	c := fl2.calls[0]
	fl2.mu.Unlock()
	if !c.srcIP.Equal(testGiaddr) {
		t.Errorf("L2 srcIP = %v, want saved giaddr %v", c.srcIP, testGiaddr)
	}

	cancel()
	serverConn.Close()
	<-done
}

// waitClientWrite polls until the client conn has ≥1 write or the deadline, then
// returns a snapshot of its writes.
func waitClientWrite(clientConn *fakeConn) []fakeWrite {
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		clientConn.mu.Lock()
		n := len(clientConn.writes)
		clientConn.mu.Unlock()
		if n > 0 {
			break
		}
		time.Sleep(time.Millisecond)
	}
	clientConn.mu.Lock()
	defer clientConn.mu.Unlock()
	return append([]fakeWrite(nil), clientConn.writes...)
}

// TestHandleServerResponses_ConfiguredSourceForwarded is the #4163 positive
// gate: a reply whose source IP IS a configured server is forwarded to the
// client and the drop counter stays zero. It pins the srcAddr explicitly (a
// configured member other than the default) so the accept path is not an
// accident of fakeConn's default source.
func TestHandleServerResponses_ConfiguredSourceForwarded(t *testing.T) {
	srv := net.IPv4(192, 0, 2, 10)
	offer := newReply(t, true, testYiaddr, nil, testChaddr) // broadcast flag → client write
	serverConn := newFakeConn()
	serverConn.mu.Lock()
	serverConn.pending = [][]byte{offer.ToBytes()}
	serverConn.srcAddr = &net.UDPAddr{IP: srv, Port: relayPort}
	serverConn.mu.Unlock()
	clientConn := newFakeConn()
	defer clientConn.Close()
	fl2 := &fakeL2{}
	ir := armedRelay("ge-0-0-0", offer)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		handleServerResponses(ctx, serverConn, clientConn, ir, fl2, testGiaddr, testServerSet(srv))
		close(done)
	}()

	writes := waitClientWrite(clientConn)
	if len(writes) != 1 {
		t.Fatalf("reply from configured server not forwarded: got %d writes, want 1", len(writes))
	}
	if ir.repliesForwarded.Load() != 1 {
		t.Errorf("repliesForwarded = %d, want 1", ir.repliesForwarded.Load())
	}
	if got := ir.repliesDroppedUnknownServer.Load(); got != 0 {
		t.Errorf("repliesDroppedUnknownServer = %d, want 0 (legit reply must not count as a drop)", got)
	}

	cancel()
	serverConn.Close()
	<-done
}

// TestHandleServerResponses_UnconfiguredSourceDropped is the #4163 fail-on-revert
// gate: a syntactically valid OFFER whose SOURCE IP is not a configured server
// MUST be dropped before it reaches the client (rogue-reply injection), and the
// repliesDroppedUnknownServer counter MUST increment. Reverting the source
// check makes this RED — the forged OFFER is forwarded (a client write appears)
// and the counter stays 0.
func TestHandleServerResponses_UnconfiguredSourceDropped(t *testing.T) {
	rogue := net.IPv4(192, 0, 2, 66) // NOT in the configured set
	offer := newReply(t, true, testYiaddr, nil, testChaddr)
	offer.GatewayIPAddr = testGiaddr
	serverConn := newFakeConn()
	serverConn.mu.Lock()
	serverConn.pending = [][]byte{offer.ToBytes()}
	serverConn.srcAddr = &net.UDPAddr{IP: rogue, Port: relayPort}
	serverConn.mu.Unlock()
	clientConn := newFakeConn()
	defer clientConn.Close()
	fl2 := &fakeL2{}
	ir := unarmedRelay("ge-0-0-0")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		// Configured server set is 10.0.0.1 only; the reply comes from 192.0.2.66.
		handleServerResponses(ctx, serverConn, clientConn, ir, fl2, testGiaddr, testServerSet())
		close(done)
	}()

	// Wait for the drop to register (bounded); the datagram is consumed but
	// never forwarded, so poll the counter rather than a client write.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if ir.repliesDroppedUnknownServer.Load() > 0 {
			break
		}
		time.Sleep(time.Millisecond)
	}

	if got := ir.repliesDroppedUnknownServer.Load(); got != 1 {
		t.Errorf("repliesDroppedUnknownServer = %d, want 1 (rogue reply must be dropped+counted)", got)
	}
	clientConn.mu.Lock()
	nWrites := len(clientConn.writes)
	clientConn.mu.Unlock()
	if nWrites != 0 {
		t.Errorf("rogue reply reached the client: got %d client writes, want 0", nWrites)
	}
	if ir.repliesForwarded.Load() != 0 {
		t.Errorf("repliesForwarded = %d, want 0 (rogue reply must not be forwarded)", ir.repliesForwarded.Load())
	}
	if fl2.callCount() != 0 {
		t.Errorf("rogue reply used raw-L2: got %d calls, want 0", fl2.callCount())
	}

	cancel()
	serverConn.Close()
	<-done
}

// TestHandleServerResponses_MultiServerGroupAnyMemberForwarded proves the check
// is set-membership, not first-only: with a two-server group, a reply from the
// SECOND configured member is forwarded (not just the first). Reverting to a
// single-server or "==first" check would drop the legitimate reply.
func TestHandleServerResponses_MultiServerGroupAnyMemberForwarded(t *testing.T) {
	srvA := net.IPv4(10, 0, 0, 1)
	srvB := net.IPv4(10, 0, 0, 2)
	offer := newReply(t, true, testYiaddr, nil, testChaddr)
	serverConn := newFakeConn()
	serverConn.mu.Lock()
	serverConn.pending = [][]byte{offer.ToBytes()}
	serverConn.srcAddr = &net.UDPAddr{IP: srvB, Port: relayPort} // second member
	serverConn.mu.Unlock()
	clientConn := newFakeConn()
	defer clientConn.Close()
	fl2 := &fakeL2{}
	ir := armedRelay("ge-0-0-0", offer)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		handleServerResponses(ctx, serverConn, clientConn, ir, fl2, testGiaddr, testServerSet(srvA, srvB))
		close(done)
	}()

	writes := waitClientWrite(clientConn)
	if len(writes) != 1 {
		t.Fatalf("reply from 2nd configured server not forwarded: got %d writes, want 1", len(writes))
	}
	if got := ir.repliesDroppedUnknownServer.Load(); got != 0 {
		t.Errorf("repliesDroppedUnknownServer = %d, want 0", got)
	}

	cancel()
	serverConn.Close()
	<-done
}

// TestHandleServerResponses_ConfiguredSourceWrongOpCodeDropped confirms the
// #4163 source check is added ALONGSIDE the existing OpCode gate, not in place
// of it: a datagram from a CONFIGURED server that is a BOOTREQUEST (wrong
// OpCode for the reply path) is still dropped — and because the source WAS
// valid, it is NOT counted as an unknown-server drop.
func TestHandleServerResponses_ConfiguredSourceWrongOpCodeDropped(t *testing.T) {
	offer := newReply(t, true, testYiaddr, nil, testChaddr)
	offer.OpCode = dhcpv4.OpcodeBootRequest // wrong direction for the reply path
	serverConn := newFakeConn()
	serverConn.mu.Lock()
	serverConn.pending = [][]byte{offer.ToBytes()}
	// default srcAddr (10.0.0.1) is a configured server
	serverConn.mu.Unlock()
	clientConn := newFakeConn()
	defer clientConn.Close()
	fl2 := &fakeL2{}
	ir := unarmedRelay("ge-0-0-0")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		handleServerResponses(ctx, serverConn, clientConn, ir, fl2, testGiaddr, testServerSet())
		close(done)
	}()

	// Let the datagram be consumed (two reads: the pending datagram, then block).
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if serverConn.readCalls.Load() >= 2 {
			break
		}
		time.Sleep(time.Millisecond)
	}

	clientConn.mu.Lock()
	nWrites := len(clientConn.writes)
	clientConn.mu.Unlock()
	if nWrites != 0 {
		t.Errorf("BOOTREQUEST on the reply path was forwarded: got %d client writes, want 0", nWrites)
	}
	if got := ir.repliesDroppedUnknownServer.Load(); got != 0 {
		t.Errorf("repliesDroppedUnknownServer = %d, want 0 (source WAS configured; OpCode gate dropped it)", got)
	}
	if ir.repliesForwarded.Load() != 0 {
		t.Errorf("repliesForwarded = %d, want 0", ir.repliesForwarded.Load())
	}

	cancel()
	serverConn.Close()
	<-done
}
