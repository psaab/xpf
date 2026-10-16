package dhcprelay

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/insomniacslk/dhcp/dhcpv4"
)

// TestDeliverReply_BadCiaddrDropped14188 is the #14188 fail-on-revert gate:
// a flag-clear, yiaddr==0 reply whose ciaddr is loopback, multicast,
// broadcast, link-local, or differs from the pending request ciaddr must be
// DROPPED (no WriteTo at all, counted), never unicast and never broadcast.
// Reverting the validation makes every bad row WriteTo (RED, proven on base).
func TestDeliverReply_BadCiaddrDropped14188(t *testing.T) {
	reqCiaddr := net.IPv4(10, 0, 0, 60)
	bad := []struct {
		name   string
		ciaddr net.IP
	}{
		{"loopback", net.IPv4(127, 0, 0, 1)},
		{"multicast", net.IPv4(224, 0, 0, 1)},
		{"broadcast", net.IPv4(255, 255, 255, 255)},
		{"link_local", net.IPv4(169, 254, 10, 1)},
		{"off_lan_global", net.IPv4(192, 0, 2, 9)},
		{"on_lan_wrong_client", net.IPv4(10, 0, 0, 99)},
	}
	for _, tc := range bad {
		t.Run(tc.name, func(t *testing.T) {
			ir := &interfaceRelay{ifaceName: "ge-0-0-0", pendingRequestCiaddr: reqCiaddr}
			client := newFakeConn()
			defer client.Close()
			pkt := newReply(t, false, nil, tc.ciaddr, testChaddr)
			if deliverReply(ir, client, &fakeL2{}, testGiaddr, pkt, pkt.ToBytes()) {
				t.Errorf("deliverReply returned true for bad ciaddr %v, want drop", tc.ciaddr)
			}
			client.mu.Lock()
			writes := len(client.writes)
			client.mu.Unlock()
			if writes != 0 {
				t.Errorf("bad ciaddr %v: %d WriteTo, want 0 (dropped, not broadcast/unicast)", tc.ciaddr, writes)
			}
			if got := ir.repliesDroppedBadCiaddr.Load(); got != 1 {
				t.Errorf("repliesDroppedBadCiaddr = %d, want 1", got)
			}
			if got := ir.repliesUnicastCiaddr.Load(); got != 0 {
				t.Errorf("repliesUnicastCiaddr = %d, want 0", got)
			}
		})
	}
	// No recorded request ciaddr: any real reply ciaddr is unbound -> drop.
	ir := &interfaceRelay{ifaceName: "ge-0-0-0"}
	client := newFakeConn()
	defer client.Close()
	pkt := newReply(t, false, nil, reqCiaddr, testChaddr)
	if deliverReply(ir, client, &fakeL2{}, testGiaddr, pkt, pkt.ToBytes()) {
		t.Error("deliverReply with no recorded request ciaddr returned true, want drop")
	}
	if got := ir.repliesDroppedBadCiaddr.Load(); got != 1 {
		t.Errorf("no-request-ciaddr: repliesDroppedBadCiaddr = %d, want 1", got)
	}
}

// TestDeliverReply_GoodCiaddrStillUnicasts14188 pins the legitimate row:
// request ciaddr == reply ciaddr (global-unicast incl. RFC1918) still unicasts.
func TestDeliverReply_GoodCiaddrStillUnicasts14188(t *testing.T) {
	ir := &interfaceRelay{ifaceName: "ge-0-0-0", pendingRequestCiaddr: testCiaddr}
	client := newFakeConn()
	defer client.Close()
	pkt := newReply(t, false, nil, testCiaddr, testChaddr)
	if !deliverReply(ir, client, &fakeL2{}, testGiaddr, pkt, pkt.ToBytes()) {
		t.Fatal("deliverReply returned false for matching ciaddr")
	}
	client.mu.Lock()
	defer client.mu.Unlock()
	if len(client.writes) != 1 {
		t.Fatalf("writes = %d, want 1", len(client.writes))
	}
	dst := client.writes[0].addr.(*net.UDPAddr)
	if !dst.IP.Equal(testCiaddr) || dst.Port != clientPort {
		t.Errorf("dst = %v, want %v:%d", dst, testCiaddr, clientPort)
	}
	if got := ir.repliesUnicastCiaddr.Load(); got != 1 {
		t.Errorf("repliesUnicastCiaddr = %d, want 1", got)
	}
	if got := ir.repliesDroppedBadCiaddr.Load(); got != 0 {
		t.Errorf("repliesDroppedBadCiaddr = %d, want 0", got)
	}
}

// TestPendingRecordsRequestCiaddr14188 proves insertPending records the
// request ciaddr, matchesPending returns it, expiry clears it, and
// snapshot/adopt migrates it.
func TestPendingRecordsRequestCiaddr14188(t *testing.T) {
	now := time.Unix(1700000000, 0)
	tbl := newPendingTable(16, pendingTTL, func() time.Time { return now })
	req := newRequest(t, dhcpv4.MessageTypeInform, testChaddr, testCiaddr)
	insertPending(tbl, req)
	ciaddr, ok := matchesPending(tbl, pendingKeyFor(req))
	if !ok {
		t.Fatal("matchesPending missed inserted request")
	}
	if !ciaddr.Equal(testCiaddr) {
		t.Fatalf("recorded ciaddr = %v, want %v", ciaddr, testCiaddr)
	}
	// DISCOVER (ciaddr zero) records no usable ciaddr.
	tbl2 := newPendingTable(16, pendingTTL, func() time.Time { return now })
	disc := newRequest(t, dhcpv4.MessageTypeDiscover, testChaddr, nil)
	insertPending(tbl2, disc)
	ci2, ok2 := matchesPending(tbl2, pendingKeyFor(disc))
	if !ok2 {
		t.Fatal("matchesPending missed DISCOVER")
	}
	if ciaddrMatchesRequest(ci2, testCiaddr) {
		t.Errorf("zero request ciaddr must not admit reply ciaddr %v", testCiaddr)
	}
	// Expiry: past TTL, no match.
	now = now.Add(pendingTTL + time.Second)
	if _, ok := matchesPending(tbl, pendingKeyFor(req)); ok {
		t.Error("expired binding still matched")
	}
	// Snapshot/adopt preserves ciaddr.
	now2 := time.Unix(1700000000, 0)
	src := newPendingTable(16, pendingTTL, func() time.Time { return now2 })
	insertPending(src, req)
	dst := newPendingTable(16, pendingTTL, func() time.Time { return now2 })
	dst.adopt(src.snapshot())
	ci3, ok3 := matchesPending(dst, pendingKeyFor(req))
	if !ok3 || !ci3.Equal(testCiaddr) {
		t.Errorf("adopted ciaddr = %v ok=%v, want %v", ci3, ok3, testCiaddr)
	}
}

// TestHandleServerResponses_BadCiaddrDropped14188 drives the full reply loop:
// a configured-server ACK matching xid+chaddr but with a spoofed ciaddr is
// dropped before the client conn; a matching-ciaddr ACK is delivered.
func TestHandleServerResponses_BadCiaddrDropped14188(t *testing.T) {
	run := func(t *testing.T, replyCiaddr net.IP) (*fakeConn, *interfaceRelay) {
		t.Helper()
		req := newRequest(t, dhcpv4.MessageTypeInform, testChaddr, testCiaddr)
		reply := serverReply(t, req, dhcpv4.MessageTypeAck, nil, replyCiaddr, false)
		ir := armedRelay("ge-0-0-0", req)
		insertPending(ir.pending, req)
		ir.pendingRequestCiaddr = testCiaddr
		serverConn := newFakeConn()
		serverConn.mu.Lock()
		serverConn.pending = [][]byte{reply.ToBytes()}
		serverConn.mu.Unlock()
		clientConn := newFakeConn()
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan struct{})
		go func() {
			handleServerResponses(ctx, serverConn, clientConn, ir, &fakeL2{}, testGiaddr, testServerSet())
			close(done)
		}()
		deadline := time.Now().Add(2 * time.Second)
		for time.Now().Before(deadline) {
			clientConn.mu.Lock()
			n := len(clientConn.writes)
			clientConn.mu.Unlock()
			if n > 0 || ir.repliesDroppedBadCiaddr.Load() > 0 {
				break
			}
			time.Sleep(time.Millisecond)
		}
		cancel()
		serverConn.Close()
		<-done
		return clientConn, ir
	}
	// Bad ciaddr: no client write.
	clientBad, irBad := run(t, net.IPv4(127, 0, 0, 1))
	clientBad.mu.Lock()
	badWrites := len(clientBad.writes)
	clientBad.mu.Unlock()
	if badWrites != 0 {
		t.Errorf("bad-ciaddr ACK delivered %d writes, want 0", badWrites)
	}
	if got := irBad.repliesDroppedBadCiaddr.Load(); got != 1 {
		t.Errorf("bad-ciaddr repliesDroppedBadCiaddr = %d, want 1", got)
	}
	// Good ciaddr: one unicast write.
	clientGood, irGood := run(t, testCiaddr)
	clientGood.mu.Lock()
	goodWrites := len(clientGood.writes)
	var dst *net.UDPAddr
	if goodWrites == 1 {
		dst = clientGood.writes[0].addr.(*net.UDPAddr)
	}
	clientGood.mu.Unlock()
	if goodWrites != 1 || dst == nil || !dst.IP.Equal(testCiaddr) {
		t.Errorf("good-ciaddr writes=%d dst=%v, want 1 to %v", goodWrites, dst, testCiaddr)
	}
	if got := irGood.repliesUnicastCiaddr.Load(); got != 1 {
		t.Errorf("good-ciaddr repliesUnicastCiaddr = %d, want 1", got)
	}
}
