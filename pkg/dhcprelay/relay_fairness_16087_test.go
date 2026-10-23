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

// admit drives one packet through the composed production gate
// (fairness, then aggregate, with the low-rate handoff) — exactly what
// the read loops call.
func admit[K comparable](fair *fairLimiter[K], agg *tokenBucket, key K) bool {
	return fair.admitWithAggregate(key, agg)
}

// TestFairLimiter_Rate1TwoSenderRotation is the fold-2 deterministic
// rate-1 check: aggregate 1 pps (burst 2), frozen apart from explicit
// 100ms steps. Sender A floods continuously; sender B arrives behind
// it. First-come-first-served would give every refill to whichever
// packet happens to be read first; the rotation instead queues B
// behind A once, hands B the banked credit, and B progresses within a
// bounded number of steps while A's total stays within burst +
// rate*elapsed + the single handoff credit.
func TestFairLimiter_Rate1TwoSenderRotation(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	clock := func() time.Time { return now }
	agg := newTokenBucket(1, relayBurstFor(1), clock) // burst 2
	fair := newFairLimiter[fairSenderKeyV4](1, clock)
	keyA := fairSenderKeyV4{hlen: 6, chaddr: [16]byte{0x02, 0, 0, 0, 0, 0xA9}}
	keyB := fairSenderKeyV4{hlen: 6, chaddr: [16]byte{0x02, 0, 0, 0, 0, 0xB9}}

	// A consumes the burst (2 packets).
	if !admit(fair, agg, keyA) || !admit(fair, agg, keyA) {
		t.Fatal("A's initial burst at rate 1 must be admitted")
	}
	// Now interleave: each 100ms step, A floods 3 packets then B tries
	// once. The rotation schedule this pins: the burst (2) is consumed
	// by A; the first banked refill (~step 9) is granted to the head
	// waiter (A, which queued first); B, queued second, is granted the
	// second banked refill (~step 19-20). B therefore progresses within
	// two aggregate intervals (<= 30 steps of margin) — bounded, and
	// crucially not subject to B winning a refill race, because grants
	// come from the banked pool in queue order.
	bAt := -1
	aCount := 2
	for step := 0; step < 30 && bAt < 0; step++ {
		now = now.Add(100 * time.Millisecond)
		for range 3 {
			if admit(fair, agg, keyA) {
				aCount++
			}
		}
		if admit(fair, agg, keyB) {
			bAt = step
		}
	}
	if bAt < 0 {
		t.Fatalf("B never progressed behind A's rate-1 flood (A admitted %d)", aCount)
	}
	// A's total stays within burst + refills granted to it (<= 2 by
	// the time B is granted) + the initial 2: no minted tokens.
	if aCount > 5 {
		t.Fatalf("A admitted %d by step %d — rotation minted aggregate tokens", aCount, bAt)
	}
}

// TestFairSenderKeyV6FromWire pins the wire DUID peek against the parsed
// key for the standard DUID forms (verified to agree byte-for-byte with
// copyPending6DUID's typed encoding), plus the malformed arms: no
// Client ID, truncated TLV, and an over-long option must all report
// not-ok so the caller lumps them into the unknown sender.
func TestFairSenderKeyV6FromWire(t *testing.T) {
	duids := []dhcpv6.DUID{
		&dhcpv6.DUIDUUID{UUID: [16]byte{0x10, 0x21, 0x32}},
		&dhcpv6.DUIDLL{LinkLayerAddr: net.HardwareAddr{0x02, 0, 0, 0, 0, 9}},
		&dhcpv6.DUIDEN{EnterpriseNumber: 42, EnterpriseIdentifier: []byte{1, 2, 3}},
	}
	for i, d := range duids {
		m := newDHCPV6BindingMessage(t, dhcpv6.TransactionID{byte(i)})
		m.Options.Del(dhcpv6.OptionClientID)
		m.AddOption(dhcpv6.OptClientID(d))
		wire := m.ToBytes()
		got, ok := fairSenderKeyV6FromWire(wire)
		if !ok {
			t.Fatalf("duid %d: wire peek rejected a valid message", i)
		}
		want, wok := fairSenderKeyForV6(m)
		if !wok || got != want {
			t.Fatalf("duid %d: wire key %+v, want parsed %+v (ok=%v)", i, got, want, wok)
		}
	}
	// No Client ID at all.
	bare, err := dhcpv6.NewMessage()
	if err != nil {
		t.Fatalf("NewMessage: %v", err)
	}
	if _, ok := fairSenderKeyV6FromWire(bare.ToBytes()); ok {
		t.Error("wire peek accepted a message with no Client ID")
	}
	// Truncated TLV: Client-ID header claims 100 bytes, datagram ends.
	trunc := []byte{1, 0, 0, 0, 0, 1, 0, 100, 0xAA}
	if _, ok := fairSenderKeyV6FromWire(trunc); ok {
		t.Error("wire peek accepted a truncated Client-ID option")
	}
	// Too short for any option.
	if _, ok := fairSenderKeyV6FromWire([]byte{1, 0}); ok {
		t.Error("wire peek accepted a 2-byte datagram")
	}
}

// TestFairLimiter_SecondSenderGetsShare is the unit decisive check: with
// the clock frozen, sender A floods far past the aggregate burst; sender B
// must still be admitted up to B's own fairness burst. Because fairness
// gates first, A's excess costs no aggregate tokens, so B's share of the
// aggregate is still there. Pre-fix (aggregate only) B would be admitted
// 0 times once A drained the bucket.
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
		if admit(fair, agg, keyA) {
			admittedA++
		}
	}
	if admittedA != fairBurstFloor {
		t.Fatalf("flooder admitted %d, want per-sender burst %d", admittedA, fairBurstFloor)
	}
	admittedB := 0
	for range 50 {
		if admit(fair, agg, keyB) {
			admittedB++
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
			if admit(fair, agg, k) {
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

// TestFairLimiter_TinyRateFloorCompletesDORA pins the fold's rate floor:
// at an aggregate of 1 pps a bare 1/256 sustained share would strand a
// DORA after its first exchange (~256s per later packet). The floor
// (sustained >= 1 pps, burst >= aggregate burst) lets one sender finish
// a whole DORA inside the burst and keep trickling at 1 pps.
func TestFairLimiter_TinyRateFloorCompletesDORA(t *testing.T) {
	frozen := time.Unix(1_700_000_000, 0)
	clock := func() time.Time { return frozen }
	agg := newTokenBucket(1, relayBurstFor(1), clock) // burst 2
	fair := newFairLimiter[fairSenderKeyV4](1, clock)
	if got := fair.perSenderRate(); got != fairRateFloor {
		t.Fatalf("per-sender rate at aggregate 1 = %d, want floor %d", got, fairRateFloor)
	}
	if got, want := fair.perSenderBurst(), relayBurstFor(1); got < want {
		t.Fatalf("per-sender burst at aggregate 1 = %d, want >= aggregate burst %d", got, want)
	}
	key := fairSenderKeyV4{hlen: 6, chaddr: [16]byte{0x02, 0, 0, 0, 0, 0x77}}
	// DISCOVER + REQUEST must both clear at the frozen instant (the
	// aggregate burst is 2, so only a fairness burst >= 2 allows both).
	if !admit(fair, agg, key) || !admit(fair, agg, key) {
		t.Fatal("DORA at aggregate 1 pps did not clear the fairness+aggregate bursts")
	}
}

// TestFairSenderKeyFromWire pins the RFC 951 header peek against the
// parsed key for a real wire packet, plus the truncated/odd-hlen arms.
func TestFairSenderKeyFromWire(t *testing.T) {
	wire := discoverWire(t, 0x5A)
	pkt, err := dhcpv4.FromBytes(wire)
	if err != nil {
		t.Fatalf("FromBytes: %v", err)
	}
	got, ok := fairSenderKeyFromWire(wire)
	if !ok {
		t.Fatal("wire peek rejected a valid DISCOVER")
	}
	if want := fairSenderKeyForV4(pkt); got != want {
		t.Fatalf("wire key = %+v, want parsed key %+v", got, want)
	}
	if _, ok := fairSenderKeyFromWire(wire[:20]); ok {
		t.Fatal("wire peek accepted a truncated datagram")
	}
	bad := append([]byte(nil), wire...)
	bad[v4HlenOff] = 0
	if _, ok := fairSenderKeyFromWire(bad); ok {
		t.Fatal("wire peek accepted hlen 0")
	}
	bad[v4HlenOff] = 17
	if _, ok := fairSenderKeyFromWire(bad); ok {
		t.Fatal("wire peek accepted hlen 17")
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

	// Upstream: the aggregate burst (10) is the hard cap on parsed work;
	// fairness decides WHO fills it — A's 8, then B's DISCOVER + REQUEST.
	wantUp := relayBurstFor(rate)
	if got := server.writeCount(); got != wantUp {
		t.Fatalf("relayed upstream %d datagrams, want %d (A fairness burst %d + B DISCOVER/REQUEST) — "+
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
