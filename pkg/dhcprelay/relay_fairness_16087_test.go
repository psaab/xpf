package dhcprelay

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/insomniacslk/dhcp/dhcpv4"
	"github.com/insomniacslk/dhcp/dhcpv6"
)

// #16087 — bounded per-sender fairness within the aggregate token bucket.
// Pre-fix the relay limiter was one aggregate bucket per interface, so a
// sustained flood at >= rate from a single sender starved legitimate
// DISCOVERs for the flood's duration (A10-17 fairness leg; the eviction
// leg was refuted — pending capacity is rate-derived, pending.go).
//
// Decisive check (from the issue): 1-MAC flood at the rate cap while a
// second MAC attempts DORA -> second MAC must complete DORA post-fix.
// Pre-fix it starves. These tests drive that shape with frozen clocks.
//
// HONEST LIMIT pinned here too: the sender key is attacker-chosen, so
// this only stops a naive single-identity flooder (and the common
// accidental looping client). TestFairLimiter_RotationCannotEvictKnown
// pins that identity rotation cannot evict an established sender, and
// the README documents that multi-identity floods need switch controls.

func discoverWire(t *testing.T, mac byte) []byte {
	t.Helper()
	pkt, err := dhcpv4.New()
	if err != nil {
		t.Fatalf("dhcpv4.New: %v", err)
	}
	pkt.OpCode = dhcpv4.OpcodeBootRequest
	pkt.ClientHWAddr = net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, mac}
	pkt.UpdateOption(dhcpv4.OptMessageType(dhcpv4.MessageTypeDiscover))
	return pkt.ToBytes()
}

// TestFairLimiter_SecondSenderGetsShare is the unit decisive check: with
// the clock frozen, sender A floods far past the aggregate burst; sender B
// must still be admitted up to B's own fairness burst. Pre-fix (aggregate
// only) B would be admitted 0 times once A drained the bucket.
func TestFairLimiter_SecondSenderGetsShare(t *testing.T) {
	frozen := time.Unix(1_700_000_000, 0)
	clock := func() time.Time { return frozen }
	// Aggregate 100 pps (burst 200) as in production defaults.
	agg := newTokenBucket(100, relayBurstFor(100), clock)
	fair := newFairLimiter[fairSenderKeyV4](100, clock)

	keyA := fairSenderKeyV4{hlen: 6, chaddr: [16]byte{0x02, 0, 0, 0, 0, 0xA0}}
	keyB := fairSenderKeyV4{hlen: 6, chaddr: [16]byte{0x02, 0, 0, 0, 0, 0xB0}}

	admittedA := 0
	for range 500 {
		if !agg.allow() {
			continue
		}
		if fair.allowSender(keyA) {
			admittedA++
		} else {
			agg.refund() // production: fairness denial refunds the aggregate
		}
	}
	if admittedA != fairBurstFloor {
		t.Fatalf("flooder admitted %d, want per-sender burst %d", admittedA, fairBurstFloor)
	}
	admittedB := 0
	for range 50 {
		if !agg.allow() {
			continue
		}
		if fair.allowSender(keyB) {
			admittedB++
		} else {
			agg.refund()
		}
	}
	if admittedB != fairBurstFloor {
		t.Fatalf("second sender admitted %d, want its own burst %d — "+
			"single-sender flood still starves other clients", admittedB, fairBurstFloor)
	}
}

// TestFairLimiter_RefillSharesEqually pins the sustained leg: after one
// second the flooder and the legitimate sender each regain only their
// per-sender share, not the whole aggregate refill.
func TestFairLimiter_RefillSharesEqually(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	clock := func() time.Time { return now }
	agg := newTokenBucket(25600, relayBurstFor(25600), clock)
	fair := newFairLimiter[fairSenderKeyV4](25600, clock) // per-sender 100 pps

	keyA := fairSenderKeyV4{hlen: 6, chaddr: [16]byte{0x02, 0, 0, 0, 0, 0xA1}}
	keyB := fairSenderKeyV4{hlen: 6, chaddr: [16]byte{0x02, 0, 0, 0, 0, 0xB1}}
	drain := func(k fairSenderKeyV4) int {
		n := 0
		for range 10000 {
			if agg.allow() && fair.allowSender(k) {
				n++
			}
		}
		return n
	}
	// Drain both bursts, then 1s refill must give each exactly 100 more.
	drain(keyA)
	drain(keyB)
	now = now.Add(time.Second)
	if got := drain(keyA); got != 100 {
		t.Fatalf("flooder after 1s refill admitted %d, want per-sender 100", got)
	}
	if got := drain(keyB); got != 100 {
		t.Fatalf("second sender after 1s refill admitted %d, want per-sender 100", got)
	}
}

// TestFairLimiter_TableBoundedAndRotationCannotEvictKnown pins the memory
// bound and the rotation resistance: filling the table with rotating
// identities must neither grow it past maxFairSenders nor evict a known
// sender that keeps transmitting.
func TestFairLimiter_TableBoundedAndRotationCannotEvictKnown(t *testing.T) {
	frozen := time.Unix(1_700_000_000, 0)
	clock := func() time.Time { return frozen }
	fair := newFairLimiter[fairSenderKeyV4](100, clock)

	known := fairSenderKeyV4{hlen: 6, chaddr: [16]byte{0x02, 0, 0, 0, 0, 0x01}}
	if !fair.allowSender(known) {
		t.Fatal("first packet from known sender must be admitted")
	}
	// Rotate through far more identities than the table holds.
	for i := range 3 * maxFairSenders {
		k := fairSenderKeyV4{hlen: 6}
		k.chaddr[0] = 0x02
		k.chaddr[4] = byte(i >> 8)
		k.chaddr[5] = byte(i)
		if k == known {
			continue
		}
		fair.allowSender(k) // result irrelevant; bound is what matters
	}
	if got := len(fair.table); got > maxFairSenders {
		t.Fatalf("fairness table holds %d senders, want <= %d (memory bound)", got, maxFairSenders)
	}
	if _, ok := fair.table[known]; !ok {
		t.Fatal("identity rotation evicted an established sender — rotation must only deny newcomers")
	}
	// A brand-new identity is denied while every slot is held by a
	// non-idle sender (frozen clock: nothing has been idle 30s).
	newcomer := fairSenderKeyV4{hlen: 6, chaddr: [16]byte{0x02, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}}
	if len(fair.table) >= maxFairSenders && fair.allowSender(newcomer) {
		t.Fatal("new identity admitted into a full, non-idle fairness table — rotation can starve newcomers without bound")
	}
}

// TestFairLimiter_IdleEvictionAdmitsNewcomer pins that the bound is not a
// permanent lock-out: once incumbents have been idle for fairIdleEvict, a
// new sender takes the longest-idle slot.
func TestFairLimiter_IdleEvictionAdmitsNewcomer(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	clock := func() time.Time { return now }
	fair := newFairLimiter[fairSenderKeyV4](100, clock)
	for i := range maxFairSenders {
		k := fairSenderKeyV4{hlen: 6}
		k.chaddr[0] = 0x02
		k.chaddr[4] = byte(i >> 8)
		k.chaddr[5] = byte(i)
		fair.allowSender(k)
	}
	if len(fair.table) != maxFairSenders {
		t.Fatalf("table = %d, want full %d", len(fair.table), maxFairSenders)
	}
	now = now.Add(fairIdleEvict + time.Second)
	newcomer := fairSenderKeyV4{hlen: 6, chaddr: [16]byte{0x02, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE}}
	if !fair.allowSender(newcomer) {
		t.Fatal("new sender denied after incumbents went idle — fairness table never recycles")
	}
	if got := len(fair.table); got != maxFairSenders {
		t.Fatalf("table = %d after idle eviction, want %d", got, maxFairSenders)
	}
}

// TestRunRelay_Fairness_SecondMACCompletesDORA is the issue's decisive
// end-to-end check through the live relay: MAC-A floods DISCOVERs at the
// frozen instant while MAC-B runs a full DORA. Post-fix B's DISCOVER and
// REQUEST are both relayed and the server's OFFER/ACK are delivered back.
// Pre-fix (aggregate only, or fairness removed) B's messages compete for
// the tokens A already consumed and the exchange does not complete.
func TestRunRelay_Fairness_SecondMACCompletesDORA(t *testing.T) {
	const rate = 5 // aggregate burst 10

	macB := net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0xB0}

	// Flood first: 25 copies of A's DISCOVER (same shape as the #5670
	// test). They occupy the head of the client queue, so B's packets are
	// processed only after the flood has had every chance to drain both
	// buckets.
	flood := discoverWire(t, 0xA0)
	pending := make([][]byte, 0, 27)
	for range 25 {
		pending = append(pending, append([]byte(nil), flood...))
	}
	discoverB := newRequest(t, dhcpv4.MessageTypeDiscover, macB, nil)
	pending = append(pending, discoverB.ToBytes())
	requestB := newRequest(t, dhcpv4.MessageTypeRequest, macB, nil)
	requestB.TransactionID = discoverB.TransactionID
	pending = append(pending, requestB.ToBytes())

	client := newFakeConn()
	client.pending = pending
	server := newFakeConn()
	// Replies must come from the configured server (192.0.2.1) to pass the
	// #4163 source check, as in newBindingHarness.
	server.srcAddr = &net.UDPAddr{IP: net.IPv4(192, 0, 2, 1), Port: relayPort}
	factory, _ := recordingFactory(client, server)
	m := testManager(factory)
	frozen := time.Unix(1_700_000_000, 0)
	m.now = func() time.Time { return frozen }
	m.Apply(context.Background(), relayConfigWithRate(rate))
	defer m.Stop()

	// Wait until all 27 datagrams are consumed.
	if !waitFor(func() bool { return client.readCalls.Load() >= 28 }) {
		t.Fatalf("relay did not consume the flood + DORA requests (readCalls=%d)", client.readCalls.Load())
	}

	// Upstream: exactly A's fairness burst + B's DISCOVER + B's REQUEST.
	wantUp := fairBurstFloor + 2
	if got := server.writeCount(); got != wantUp {
		t.Fatalf("relayed upstream %d datagrams, want %d (A burst %d + B DISCOVER/REQUEST) — "+
			"second MAC starved by the single-MAC flood", got, wantUp, fairBurstFloor)
	}
	// The last two upstream datagrams must be B's, in order.
	server.mu.Lock()
	writes := append([]fakeWrite(nil), server.writes...)
	server.mu.Unlock()
	for i, wantType := range []dhcpv4.MessageType{dhcpv4.MessageTypeDiscover, dhcpv4.MessageTypeRequest} {
		got, err := dhcpv4.FromBytes(writes[wantUp-2+i].data)
		if err != nil {
			t.Fatalf("upstream B datagram %d does not parse: %v", i, err)
		}
		if !equalBytes(got.ClientHWAddr, macB) || got.MessageType() != wantType {
			t.Fatalf("upstream datagram %d = %s from %v, want %s from B %v",
				i, got.MessageType(), got.ClientHWAddr, wantType, macB)
		}
	}

	// Downstream: answer B's DISCOVER with an OFFER and B's REQUEST with
	// an ACK (broadcast, so delivery is a client-conn write). Both must
	// be delivered — that is DORA completing for the second MAC.
	yiaddr := net.IPv4(10, 0, 0, 77)
	offer := serverReply(t, discoverB, dhcpv4.MessageTypeOffer, yiaddr, nil, true)
	server.push(offer.ToBytes())
	if !waitFor(func() bool { return client.writeCount() >= 1 }) {
		t.Fatal("OFFER for second MAC was not delivered — DORA did not complete")
	}
	ack := serverReply(t, requestB, dhcpv4.MessageTypeAck, yiaddr, nil, true)
	server.push(ack.ToBytes())
	if !waitFor(func() bool { return client.writeCount() >= 2 }) {
		t.Fatal("ACK for second MAC was not delivered — DORA did not complete")
	}
	client.mu.Lock()
	delivered := append([]fakeWrite(nil), client.writes...)
	client.mu.Unlock()
	for i, wantType := range []dhcpv4.MessageType{dhcpv4.MessageTypeOffer, dhcpv4.MessageTypeAck} {
		got, err := dhcpv4.FromBytes(delivered[i].data)
		if err != nil {
			t.Fatalf("delivered datagram %d does not parse: %v", i, err)
		}
		if got.MessageType() != wantType || !equalBytes(got.ClientHWAddr, macB) {
			t.Fatalf("delivered datagram %d = %s for %v, want %s for B %v",
				i, got.MessageType(), got.ClientHWAddr, wantType, macB)
		}
	}
}

// TestDHCPV6Fairness_SecondClientGetsShare mirrors the decisive check on
// the DHCPv6 client loop: one DUID floods Solicits while a second DUID's
// Solicit must still be relayed. Rate 256 gives an aggregate burst of 512
// (never binding for 40 packets), so only the fairness layer can drop
// the flooder — removing it makes the flooder count 32 and fails loudly.
func TestDHCPV6Fairness_SecondClientGetsShare(t *testing.T) {
	client := newFakeDHCPV6Conn()
	server := newFakeConn()
	client.srcAddr = &net.UDPAddr{IP: net.ParseIP("fe80::2"), Port: dhcpv6ClientPort}
	now := time.Unix(123, 0)
	m := newDHCPV6Manager()
	m.now = func() time.Time { return now }
	relay := &dhcpV6Relay{
		ifaceName:     "ge-0/0/0.0",
		kernelName:    "ge-0/0/0.0",
		maxPacketRate: 256,
		pending:       newPendingTableOf[pending6Key, pending6Entry](4096, pendingTTL, m.now),
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		m.runDHCPV6ClientLoop(ctx, relay, client, server, net.ParseIP("2001:db8:1::1"),
			[]*net.UDPAddr{{IP: net.ParseIP("2001:db8::5"), Port: dhcpv6RelayPort}}, nil)
		close(done)
	}()

	solicit := func(b byte) []byte {
		msg, err := dhcpv6.NewMessage()
		if err != nil {
			t.Fatalf("NewMessage: %v", err)
		}
		msg.MessageType = dhcpv6.MessageTypeSolicit
		msg.AddOption(dhcpv6.OptClientID(&dhcpv6.DUIDUUID{UUID: [16]byte{b}}))
		msg.AddOption(&dhcpv6.OptIANA{IaId: [4]byte{1, 2, 3, 4}})
		return msg.ToBytes()
	}
	const floodN = 32
	for range floodN {
		client.push(solicit(0xA0))
	}
	client.push(solicit(0xB0))

	wantWrites := fairBurstFloor + 1
	total := floodN + 1
	if !waitFor(func() bool {
		return server.writeCount()+int(relay.requestsDroppedRateLimit.Load()) >= total
	}) {
		t.Fatalf("v6 loop processed %d of %d datagrams (writes=%d drops=%d)",
			server.writeCount()+int(relay.requestsDroppedRateLimit.Load()), total,
			server.writeCount(), relay.requestsDroppedRateLimit.Load())
	}
	if got := server.writeCount(); got != wantWrites {
		t.Fatalf("v6 relayed %d datagrams, want %d (flooder burst %d + second client 1) — "+
			"second DHCPv6 client starved", got, wantWrites, fairBurstFloor)
	}
	if got := relay.requestsDroppedRateLimit.Load(); got != uint64(total-wantWrites) {
		t.Fatalf("v6 rate-limit drops=%d, want %d", got, total-wantWrites)
	}
	cancel()
	_ = client.Close()
	_ = server.Close()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("v6 client loop did not stop")
	}
}
