package userspace

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
	"unsafe"

	"github.com/psaab/xpf/pkg/dataplane"
	"github.com/psaab/xpf/pkg/logging"
)

// buildSessionOpenV4Payload builds a binary SessionOpen payload for an IPv4 session.
func buildSessionOpenV4Payload(
	proto uint8,
	srcPort, dstPort uint16,
	srcIP, dstIP [4]byte,
	natSrcIP, natDstIP [4]byte,
	natSrcPort, natDstPort uint16,
	ownerRG int16,
	egressIfindex, txIfindex int16,
	tunnelEndpoint, txVLAN uint16,
	flags uint8,
	ingressZone, egressZone, disposition uint8,
	neighborMAC, srcMAC [6]byte,
	nextHop [4]byte,
) []byte {
	// 24 fixed + 4*4 IPs + 6+6 MACs + 4 NextHop = 56 bytes
	buf := make([]byte, 56)
	buf[0] = 4 // AddrFamily
	buf[1] = proto
	binary.LittleEndian.PutUint16(buf[2:4], srcPort)
	binary.LittleEndian.PutUint16(buf[4:6], dstPort)
	binary.LittleEndian.PutUint16(buf[6:8], natSrcPort)
	binary.LittleEndian.PutUint16(buf[8:10], natDstPort)
	binary.LittleEndian.PutUint16(buf[10:12], uint16(ownerRG))
	binary.LittleEndian.PutUint16(buf[12:14], uint16(egressIfindex))
	binary.LittleEndian.PutUint16(buf[14:16], uint16(txIfindex))
	binary.LittleEndian.PutUint16(buf[16:18], tunnelEndpoint)
	binary.LittleEndian.PutUint16(buf[18:20], txVLAN)
	buf[20] = flags
	buf[21] = ingressZone
	buf[22] = egressZone
	buf[23] = disposition
	copy(buf[24:28], srcIP[:])
	copy(buf[28:32], dstIP[:])
	copy(buf[32:36], natSrcIP[:])
	copy(buf[36:40], natDstIP[:])
	copy(buf[40:46], neighborMAC[:])
	copy(buf[46:52], srcMAC[:])
	copy(buf[52:56], nextHop[:])
	return buf
}

// buildSessionCloseV4Payload builds a binary SessionClose payload for IPv4.
// #919/#922: includes the trailing ingress/egress zone-id u8 bytes.
func buildSessionCloseV4Payload(
	proto uint8,
	srcPort, dstPort uint16,
	srcIP, dstIP [4]byte,
	ownerRG int16,
	flags uint8,
	ingressZoneID, egressZoneID uint8,
) []byte {
	// 6 + 4+4 + 2 + 1 + 2 = 19 bytes
	buf := make([]byte, 19)
	buf[0] = 4 // AddrFamily
	buf[1] = proto
	binary.LittleEndian.PutUint16(buf[2:4], srcPort)
	binary.LittleEndian.PutUint16(buf[4:6], dstPort)
	copy(buf[6:10], srcIP[:])
	copy(buf[10:14], dstIP[:])
	binary.LittleEndian.PutUint16(buf[14:16], uint16(ownerRG))
	buf[16] = flags
	buf[17] = ingressZoneID
	buf[18] = egressZoneID
	return buf
}

func buildDataplaneEventV4Payload(
	proto uint8,
	srcPort, dstPort uint16,
	srcIP, dstIP [4]byte,
	natSrcIP [4]byte,
	natSrcPort uint16,
	ingressZone, egressZone uint16,
	reason uint16,
	policyID uint32,
	timestampNS uint64,
) []byte {
	_ = reason // RT_FLOW policy-deny records carry policy identity, not the userspace-only reason field.
	buf := make([]byte, int(unsafe.Sizeof(dataplane.Event{})))
	binary.LittleEndian.PutUint64(buf[0:8], timestampNS)
	copy(buf[8:12], srcIP[:])
	copy(buf[24:28], dstIP[:])
	binary.BigEndian.PutUint16(buf[40:42], srcPort)
	binary.BigEndian.PutUint16(buf[42:44], dstPort)
	binary.LittleEndian.PutUint32(buf[44:48], policyID)
	binary.LittleEndian.PutUint16(buf[48:50], ingressZone)
	binary.LittleEndian.PutUint16(buf[50:52], egressZone)
	buf[52] = dataplane.EventTypePolicyDeny
	buf[53] = proto
	buf[54] = dataplane.ActionDeny
	buf[55] = dataplane.AFInet
	copy(buf[72:76], natSrcIP[:])
	binary.BigEndian.PutUint16(buf[104:106], natSrcPort)
	return buf
}

func writeFrame(w io.Writer, typ uint8, seq uint64, payload []byte) error {
	var hdr [EventFrameHeaderSize]byte
	binary.LittleEndian.PutUint32(hdr[0:4], uint32(len(payload)))
	hdr[4] = typ
	binary.LittleEndian.PutUint64(hdr[8:16], seq)
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	if len(payload) > 0 {
		if _, err := w.Write(payload); err != nil {
			return err
		}
	}
	return nil
}

func readFrame(r io.Reader) (typ uint8, seq uint64, payload []byte, err error) {
	var hdr [EventFrameHeaderSize]byte
	if _, err = io.ReadFull(r, hdr[:]); err != nil {
		return
	}
	length := binary.LittleEndian.Uint32(hdr[0:4])
	typ = hdr[4]
	seq = binary.LittleEndian.Uint64(hdr[8:16])
	if length > 0 {
		payload = make([]byte, length)
		_, err = io.ReadFull(r, payload)
	}
	return
}

func TestDecodeSessionEventV4(t *testing.T) {
	payload := buildSessionOpenV4Payload(
		6,          // TCP
		12345, 443, // ports
		[4]byte{10, 0, 1, 102}, [4]byte{172, 16, 80, 200}, // src, dst
		[4]byte{172, 16, 80, 8}, [4]byte{0, 0, 0, 0}, // nat src, nat dst
		40000, 0, // nat ports
		1,      // ownerRG
		12, 11, // egress/tx ifindex
		0, 80, // tunnel, vlan
		SessionEventFlagFabricRedirect, // flags
		1, 2, 0,                        // ingress/egress zone, disposition
		[6]byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}, // neighbor MAC
		[6]byte{0x02, 0xbf, 0x72, 0x00, 0x50, 0x08}, // src MAC
		[4]byte{172, 16, 80, 1},                     // next hop
	)

	d, ok := decodeSessionEvent(payload)
	if !ok {
		t.Fatal("decodeSessionEvent returned false")
	}
	if d.AddrFamily != dataplane.AFInet {
		t.Fatalf("AddrFamily = %d, want %d (AFInet)", d.AddrFamily, dataplane.AFInet)
	}
	// #919/#922: zone IDs decoded from payload[21]/[22].
	if d.IngressZoneID != 1 {
		t.Fatalf("IngressZoneID = %d, want 1", d.IngressZoneID)
	}
	if d.EgressZoneID != 2 {
		t.Fatalf("EgressZoneID = %d, want 2", d.EgressZoneID)
	}
	if d.Protocol != 6 {
		t.Fatalf("Protocol = %d, want 6", d.Protocol)
	}
	if d.SrcPort != 12345 {
		t.Fatalf("SrcPort = %d, want 12345", d.SrcPort)
	}
	if d.DstPort != 443 {
		t.Fatalf("DstPort = %d, want 443", d.DstPort)
	}
	if d.NATSrcPort != 40000 {
		t.Fatalf("NATSrcPort = %d, want 40000", d.NATSrcPort)
	}
	if d.OwnerRGID != 1 {
		t.Fatalf("OwnerRGID = %d, want 1", d.OwnerRGID)
	}
	if d.SrcIP != "10.0.1.102" {
		t.Fatalf("SrcIP = %q, want 10.0.1.102", d.SrcIP)
	}
	if d.DstIP != "172.16.80.200" {
		t.Fatalf("DstIP = %q, want 172.16.80.200", d.DstIP)
	}
	if d.NATSrcIP != "172.16.80.8" {
		t.Fatalf("NATSrcIP = %q, want 172.16.80.8", d.NATSrcIP)
	}
	if d.NATDstIP != "" {
		t.Fatalf("NATDstIP = %q, want empty (zero)", d.NATDstIP)
	}
	if !d.FabricRedirect {
		t.Fatal("FabricRedirect should be true")
	}
	if d.FabricIngress {
		t.Fatal("FabricIngress should be false")
	}
	if d.EgressIfindex != 12 {
		t.Fatalf("EgressIfindex = %d, want 12", d.EgressIfindex)
	}
	if d.TXIfindex != 11 {
		t.Fatalf("TXIfindex = %d, want 11", d.TXIfindex)
	}
	if d.TXVLANID != 80 {
		t.Fatalf("TXVLANID = %d, want 80", d.TXVLANID)
	}
	if d.NeighborMAC != "aa:bb:cc:dd:ee:ff" {
		t.Fatalf("NeighborMAC = %q, want aa:bb:cc:dd:ee:ff", d.NeighborMAC)
	}
	if d.SrcMAC != "02:bf:72:00:50:08" {
		t.Fatalf("SrcMAC = %q, want 02:bf:72:00:50:08", d.SrcMAC)
	}
	if d.NextHop != "172.16.80.1" {
		t.Fatalf("NextHop = %q, want 172.16.80.1", d.NextHop)
	}
}

func TestDecodeSessionEventV4LocalDelivery(t *testing.T) {
	payload := buildSessionOpenV4Payload(
		17, 53, 53,
		[4]byte{10, 0, 1, 1}, [4]byte{10, 0, 1, 10},
		[4]byte{}, [4]byte{},
		0, 0, 0, 0, 0, 0, 0,
		0,
		1, 2, 1, // disposition=1 → local_delivery
		[6]byte{}, [6]byte{}, [4]byte{},
	)
	d, ok := decodeSessionEvent(payload)
	if !ok {
		t.Fatal("decodeSessionEvent returned false")
	}
	if d.Disposition != "local_delivery" {
		t.Fatalf("Disposition = %q, want local_delivery", d.Disposition)
	}
}

func TestDecodeSessionCloseEventV4(t *testing.T) {
	payload := buildSessionCloseV4Payload(
		6,          // TCP
		12345, 443, // ports
		[4]byte{10, 0, 1, 102}, [4]byte{172, 16, 80, 200},
		1,                              // ownerRG
		SessionEventFlagFabricRedirect, // flags
		3, 4,                           // ingress/egress zone IDs
	)

	d, ok := decodeSessionCloseEvent(payload)
	if !ok {
		t.Fatal("decodeSessionCloseEvent returned false")
	}
	if d.IngressZoneID != 3 || d.EgressZoneID != 4 {
		t.Fatalf("ZoneIDs = (%d,%d), want (3,4)", d.IngressZoneID, d.EgressZoneID)
	}
	if d.AddrFamily != dataplane.AFInet {
		t.Fatalf("AddrFamily = %d, want %d (AFInet)", d.AddrFamily, dataplane.AFInet)
	}
	if d.Protocol != 6 {
		t.Fatalf("Protocol = %d, want 6", d.Protocol)
	}
	if d.SrcPort != 12345 || d.DstPort != 443 {
		t.Fatalf("ports = %d/%d, want 12345/443", d.SrcPort, d.DstPort)
	}
	if d.SrcIP != "10.0.1.102" {
		t.Fatalf("SrcIP = %q, want 10.0.1.102", d.SrcIP)
	}
	if d.DstIP != "172.16.80.200" {
		t.Fatalf("DstIP = %q, want 172.16.80.200", d.DstIP)
	}
	if d.OwnerRGID != 1 {
		t.Fatalf("OwnerRGID = %d, want 1", d.OwnerRGID)
	}
	if !d.FabricRedirect {
		t.Fatal("FabricRedirect should be true")
	}
}

func TestDecodeSessionEventRejectsTruncated(t *testing.T) {
	// Too short for v4 (need 56 bytes minimum).
	_, ok := decodeSessionEvent([]byte{4, 6, 0, 0})
	if ok {
		t.Fatal("should reject truncated v4 payload")
	}
	// Invalid address family.
	_, ok = decodeSessionEvent([]byte{99, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0})
	if ok {
		t.Fatal("should reject unknown address family")
	}
}

func TestDecodeDataplaneEventPolicyDenyRTFlow(t *testing.T) {
	payload := buildDataplaneEventV4Payload(
		6,
		12345, 443,
		[4]byte{10, 0, 1, 102}, [4]byte{172, 16, 80, 200},
		[4]byte{172, 16, 80, 8},
		40000,
		1, 2,
		7,
		99,
		1700000000000000000,
	)
	if !dataplaneEventPayloadMatchesFrame(EventTypePolicyDeny, payload) {
		t.Fatal("RT_FLOW payload did not match policy-deny event-stream frame type")
	}
	rec, ok := decodeDataplaneEventPayload(payload)
	if !ok {
		t.Fatal("decodeDataplaneEventPayload returned false")
	}
	if rec.Type != "POLICY_DENY" || rec.Action != "deny" {
		t.Fatalf("event = %s/%s, want POLICY_DENY/deny", rec.Type, rec.Action)
	}
	if rec.Protocol != "TCP" {
		t.Fatalf("Protocol = %q, want TCP", rec.Protocol)
	}
	if rec.SrcAddr != "10.0.1.102:12345" {
		t.Fatalf("SrcAddr = %q, want 10.0.1.102:12345", rec.SrcAddr)
	}
	if rec.DstAddr != "172.16.80.200:443" {
		t.Fatalf("DstAddr = %q, want 172.16.80.200:443", rec.DstAddr)
	}
	if rec.NATSrcAddr != "172.16.80.8:40000" {
		t.Fatalf("NATSrcAddr = %q, want 172.16.80.8:40000", rec.NATSrcAddr)
	}
	if rec.PolicyID != 99 || rec.InZone != 1 || rec.OutZone != 2 {
		t.Fatalf("identity = policy %d zones %d->%d, want policy 99 zones 1->2", rec.PolicyID, rec.InZone, rec.OutZone)
	}
	if rec.ScreenCheck != "" {
		t.Fatalf("ScreenCheck/reason = %q, want empty for policy-deny RT_FLOW", rec.ScreenCheck)
	}
}

func TestFrameRoundTrip(t *testing.T) {
	payload := buildSessionOpenV4Payload(
		6, 1234, 80,
		[4]byte{10, 0, 1, 1}, [4]byte{10, 0, 2, 1},
		[4]byte{}, [4]byte{},
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		[6]byte{}, [6]byte{}, [4]byte{},
	)

	r, w := io.Pipe()
	go func() {
		_ = writeFrame(w, EventTypeSessionOpen, 42, payload)
		w.Close()
	}()

	typ, seq, got, err := readFrame(r)
	if err != nil {
		t.Fatalf("readFrame: %v", err)
	}
	if typ != EventTypeSessionOpen {
		t.Fatalf("type = %d, want %d", typ, EventTypeSessionOpen)
	}
	if seq != 42 {
		t.Fatalf("seq = %d, want 42", seq)
	}
	if len(got) != len(payload) {
		t.Fatalf("payload len = %d, want %d", len(got), len(payload))
	}
}

func TestEventStreamAcceptAndRead(t *testing.T) {
	dir := t.TempDir()
	sockPath := filepath.Join(dir, "test-events.sock")

	es := NewEventStream(sockPath)
	var received atomic.Int32
	var lastSeq atomic.Uint64
	es.SetOnEvent(func(eventType uint8, seq uint64, delta SessionDeltaInfo) {
		received.Add(1)
		lastSeq.Store(seq)
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	es.Start(ctx)
	defer es.Close()

	// Wait for listener.
	time.Sleep(50 * time.Millisecond)

	// Connect as the "helper".
	conn, err := net.Dial("unix", sockPath)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	// Wait for connection to be accepted.
	deadline := time.Now().Add(2 * time.Second)
	for !es.IsConnected() {
		if time.Now().After(deadline) {
			t.Fatal("event stream did not become connected")
		}
		time.Sleep(10 * time.Millisecond)
	}

	// Send 3 SessionOpen events.
	payload := buildSessionOpenV4Payload(
		6, 1000, 80,
		[4]byte{10, 0, 1, 1}, [4]byte{10, 0, 2, 1},
		[4]byte{}, [4]byte{},
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		[6]byte{}, [6]byte{}, [4]byte{},
	)
	for i := uint64(1); i <= 3; i++ {
		if err := writeFrame(conn, EventTypeSessionOpen, i, payload); err != nil {
			t.Fatalf("write frame %d: %v", i, err)
		}
	}

	// Wait for events to be processed.
	deadline = time.Now().Add(2 * time.Second)
	for received.Load() < 3 {
		if time.Now().After(deadline) {
			t.Fatalf("received only %d events, want 3", received.Load())
		}
		time.Sleep(10 * time.Millisecond)
	}

	if lastSeq.Load() != 3 {
		t.Fatalf("lastSeq = %d, want 3", lastSeq.Load())
	}
}

func TestEventStreamDataplaneEventAckAndCallback(t *testing.T) {
	dir := t.TempDir()
	sockPath := filepath.Join(dir, "test-events.sock")

	es := NewEventStream(sockPath)
	type dataplaneEventResult struct {
		seq uint64
		rec logging.EventRecord
	}
	got := make(chan dataplaneEventResult, 1)
	es.SetOnDataplaneEvent(func(seq uint64, rec logging.EventRecord) {
		got <- dataplaneEventResult{seq: seq, rec: rec}
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	es.Start(ctx)
	defer es.Close()

	waitCtx, waitCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer waitCancel()
	var conn net.Conn
	for conn == nil {
		var err error
		conn, err = net.Dial("unix", sockPath)
		if err == nil {
			break
		}
		select {
		case <-waitCtx.Done():
			t.Fatalf("dial: %v", err)
		case <-time.After(10 * time.Millisecond):
		}
	}
	defer conn.Close()

	connectCtx, connectCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer connectCancel()
	for !es.IsConnected() {
		select {
		case <-connectCtx.Done():
			t.Fatal("event stream did not become connected")
		case <-time.After(10 * time.Millisecond):
		}
	}

	payload := buildDataplaneEventV4Payload(
		6, 1111, 443,
		[4]byte{10, 0, 1, 5}, [4]byte{172, 16, 80, 200},
		[4]byte{172, 16, 80, 8},
		40000,
		1, 2,
		0, 77,
		0,
	)
	if err := writeFrame(conn, EventTypePolicyDeny, 7, payload); err != nil {
		t.Fatalf("write dataplane event: %v", err)
	}

	select {
	case result := <-got:
		if result.seq != 7 {
			t.Fatalf("seq = %d, want 7", result.seq)
		}
		if result.rec.Type != "POLICY_DENY" || result.rec.PolicyID != 77 {
			t.Fatalf("rec = %+v, want policy deny policy 77", result.rec)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("dataplane event callback not called")
	}

	_ = conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	typ, seq, _, err := readFrame(conn)
	if err != nil {
		t.Fatalf("read ack: %v", err)
	}
	if typ != EventTypeAck || seq != 7 {
		t.Fatalf("ack = type %d seq %d, want type %d seq 7", typ, seq, EventTypeAck)
	}
	if got := es.PolicyDenyEvents.Load(); got != 1 {
		t.Fatalf("PolicyDenyEvents = %d, want 1", got)
	}
}

func TestEventStreamDataplaneEventRawCallbackPreferred(t *testing.T) {
	dir := t.TempDir()
	sockPath := filepath.Join(dir, "test-events.sock")

	es := NewEventStream(sockPath)
	rawGot := make(chan []byte, 1)
	decodedGot := make(chan struct{}, 1)
	es.SetOnRawDataplaneEvent(func(seq uint64, payload []byte) {
		if seq != 11 {
			t.Fatalf("seq = %d, want 11", seq)
		}
		rawGot <- append([]byte(nil), payload...)
	})
	es.SetOnDataplaneEvent(func(uint64, logging.EventRecord) {
		decodedGot <- struct{}{}
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	es.Start(ctx)
	defer es.Close()

	waitCtx, waitCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer waitCancel()
	var conn net.Conn
	for conn == nil {
		var err error
		conn, err = net.Dial("unix", sockPath)
		if err == nil {
			break
		}
		select {
		case <-waitCtx.Done():
			t.Fatalf("dial: %v", err)
		case <-time.After(10 * time.Millisecond):
		}
	}
	defer conn.Close()

	connectCtx, connectCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer connectCancel()
	for !es.IsConnected() {
		select {
		case <-connectCtx.Done():
			t.Fatal("event stream did not become connected")
		case <-time.After(10 * time.Millisecond):
		}
	}

	payload := buildDataplaneEventV4Payload(
		6, 1111, 443,
		[4]byte{10, 0, 1, 5}, [4]byte{172, 16, 80, 200},
		[4]byte{172, 16, 80, 8},
		40000,
		1, 2,
		0, 77,
		0,
	)
	if err := writeFrame(conn, EventTypePolicyDeny, 11, payload); err != nil {
		t.Fatalf("write dataplane event: %v", err)
	}

	select {
	case got := <-rawGot:
		if !bytes.Equal(got, payload) {
			t.Fatalf("raw payload changed: got %d bytes, want %d", len(got), len(payload))
		}
	case <-time.After(2 * time.Second):
		t.Fatal("raw dataplane event callback not called")
	}
	select {
	case <-decodedGot:
		t.Fatal("decoded callback should not fire when raw callback is installed")
	default:
	}
}

func TestEventStreamDataplaneEventBeforeCallbackWaitsForCallbackBeforeAck(t *testing.T) {
	dir := t.TempDir()
	sockPath := filepath.Join(dir, "test-events.sock")

	es := NewEventStream(sockPath)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	es.Start(ctx)
	defer es.Close()

	time.Sleep(50 * time.Millisecond)

	conn, err := net.Dial("unix", sockPath)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	deadline := time.Now().Add(2 * time.Second)
	for !es.IsConnected() {
		if time.Now().After(deadline) {
			t.Fatal("event stream did not become connected")
		}
		time.Sleep(10 * time.Millisecond)
	}

	payload := buildDataplaneEventV4Payload(
		6, 1111, 443,
		[4]byte{10, 0, 1, 5}, [4]byte{172, 16, 80, 200},
		[4]byte{172, 16, 80, 8},
		40000,
		1, 2,
		0, 77,
		0,
	)
	if err := writeFrame(conn, EventTypePolicyDeny, 21, payload); err != nil {
		t.Fatalf("write first dataplane event: %v", err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(150 * time.Millisecond))
	if typ, seq, _, err := readFrame(conn); err == nil {
		t.Fatalf("event before callback was acked type=%d seq=%d; want no ack until callback applies it", typ, seq)
	} else if ne, ok := err.(net.Error); !ok || !ne.Timeout() {
		t.Fatalf("read first ack error = %v, want timeout", err)
	}

	got := make(chan uint64, 1)
	es.SetOnDataplaneEvent(func(seq uint64, _ logging.EventRecord) {
		got <- seq
	})

	select {
	case gotSeq := <-got:
		if gotSeq != 21 {
			t.Fatalf("callback seq = %d, want 21", gotSeq)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("callback not invoked after late registration")
	}
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	typ, seq, _, err := readFrame(conn)
	if err != nil {
		t.Fatalf("read ack after callback: %v", err)
	}
	if typ != EventTypeAck || seq != 21 {
		t.Fatalf("ack after callback = type %d seq %d, want type %d seq 21", typ, seq, EventTypeAck)
	}
}

func TestEventStreamMalformedDataplaneEventDropsAndAcks(t *testing.T) {
	dir := t.TempDir()
	sockPath := filepath.Join(dir, "test-events.sock")

	es := NewEventStream(sockPath)
	var callbackCalled atomic.Bool
	es.SetOnDataplaneEvent(func(uint64, logging.EventRecord) {
		callbackCalled.Store(true)
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	es.Start(ctx)
	defer es.Close()

	time.Sleep(50 * time.Millisecond)

	conn, err := net.Dial("unix", sockPath)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	deadline := time.Now().Add(2 * time.Second)
	for !es.IsConnected() {
		if time.Now().After(deadline) {
			t.Fatal("event stream did not become connected")
		}
		time.Sleep(10 * time.Millisecond)
	}

	if err := writeFrame(conn, EventTypeScreenDrop, 9, []byte{4, 6}); err != nil {
		t.Fatalf("write malformed dataplane event: %v", err)
	}

	_ = conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	typ, seq, _, err := readFrame(conn)
	if err != nil {
		t.Fatalf("read ack: %v", err)
	}
	if typ != EventTypeAck || seq != 9 {
		t.Fatalf("ack = type %d seq %d, want type %d seq 9", typ, seq, EventTypeAck)
	}
	if got := es.ScreenDropDrops.Load(); got != 1 {
		t.Fatalf("ScreenDropDrops = %d, want 1", got)
	}
	if got := es.DecodeErrors.Load(); got != 1 {
		t.Fatalf("DecodeErrors = %d, want 1", got)
	}
	if callbackCalled.Load() {
		t.Fatal("malformed dataplane event must not call callback")
	}
}

func TestEventStreamUnknownFrameDropsAndAcks(t *testing.T) {
	dir := t.TempDir()
	sockPath := filepath.Join(dir, "test-events.sock")

	es := NewEventStream(sockPath)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	es.Start(ctx)
	defer es.Close()

	time.Sleep(50 * time.Millisecond)

	conn, err := net.Dial("unix", sockPath)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	deadline := time.Now().Add(2 * time.Second)
	for !es.IsConnected() {
		if time.Now().After(deadline) {
			t.Fatal("event stream did not become connected")
		}
		time.Sleep(10 * time.Millisecond)
	}

	if err := writeFrame(conn, 250, 11, nil); err != nil {
		t.Fatalf("write unknown frame: %v", err)
	}

	_ = conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	typ, seq, _, err := readFrame(conn)
	if err != nil {
		t.Fatalf("read ack: %v", err)
	}
	if typ != EventTypeAck || seq != 11 {
		t.Fatalf("ack = type %d seq %d, want type %d seq 11", typ, seq, EventTypeAck)
	}
	if got := es.UnknownFrameDrops.Load(); got != 1 {
		t.Fatalf("UnknownFrameDrops = %d, want 1", got)
	}
}

func TestEventStreamAcksSent(t *testing.T) {
	dir := t.TempDir()
	sockPath := filepath.Join(dir, "test-events.sock")

	es := NewEventStream(sockPath)
	es.SetOnEvent(func(uint8, uint64, SessionDeltaInfo) {})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	es.Start(ctx)
	defer es.Close()

	time.Sleep(50 * time.Millisecond)

	conn, err := net.Dial("unix", sockPath)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	deadline := time.Now().Add(2 * time.Second)
	for !es.IsConnected() {
		if time.Now().After(deadline) {
			t.Fatal("not connected")
		}
		time.Sleep(10 * time.Millisecond)
	}

	// Send a SessionOpen event.
	payload := buildSessionOpenV4Payload(
		6, 1000, 80,
		[4]byte{10, 0, 1, 1}, [4]byte{10, 0, 2, 1},
		[4]byte{}, [4]byte{},
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		[6]byte{}, [6]byte{}, [4]byte{},
	)
	if err := writeFrame(conn, EventTypeSessionOpen, 1, payload); err != nil {
		t.Fatalf("write: %v", err)
	}

	// Read the Ack frame from the daemon side (within 200ms).
	_ = conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	typ, seq, _, err := readFrame(conn)
	if err != nil {
		t.Fatalf("read ack: %v", err)
	}
	if typ != EventTypeAck {
		t.Fatalf("type = %d, want %d (Ack)", typ, EventTypeAck)
	}
	if seq != 1 {
		t.Fatalf("ack seq = %d, want 1", seq)
	}
}

func TestEventStreamFullResyncCallback(t *testing.T) {
	dir := t.TempDir()
	sockPath := filepath.Join(dir, "test-events.sock")

	es := NewEventStream(sockPath)
	var resyncCalled atomic.Bool
	es.SetOnFullResync(func() { resyncCalled.Store(true) })

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	es.Start(ctx)
	defer es.Close()

	time.Sleep(50 * time.Millisecond)

	conn, err := net.Dial("unix", sockPath)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	deadline := time.Now().Add(2 * time.Second)
	for !es.IsConnected() {
		if time.Now().After(deadline) {
			t.Fatal("not connected")
		}
		time.Sleep(10 * time.Millisecond)
	}

	// Send FullResync frame.
	if err := writeFrame(conn, EventTypeFullResync, 0, nil); err != nil {
		t.Fatalf("write: %v", err)
	}

	deadline = time.Now().Add(2 * time.Second)
	for !resyncCalled.Load() {
		if time.Now().After(deadline) {
			t.Fatal("onFullResync not called")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestEventStreamDrainRequestComplete(t *testing.T) {
	dir := t.TempDir()
	sockPath := filepath.Join(dir, "test-events.sock")

	es := NewEventStream(sockPath)
	var applied atomic.Int32
	es.SetOnEvent(func(uint8, uint64, SessionDeltaInfo) {
		applied.Add(1)
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	es.Start(ctx)
	defer es.Close()

	time.Sleep(50 * time.Millisecond)

	conn, err := net.Dial("unix", sockPath)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	deadline := time.Now().Add(2 * time.Second)
	for !es.IsConnected() {
		if time.Now().After(deadline) {
			t.Fatal("not connected")
		}
		time.Sleep(10 * time.Millisecond)
	}

	// Send some events so lastAppliedSeq is non-zero before draining.
	payload := buildSessionOpenV4Payload(
		6, 1000, 80,
		[4]byte{10, 0, 1, 1}, [4]byte{10, 0, 2, 1},
		[4]byte{}, [4]byte{},
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		[6]byte{}, [6]byte{}, [4]byte{},
	)
	for i := uint64(1); i <= 5; i++ {
		if err := writeFrame(conn, EventTypeSessionOpen, i, payload); err != nil {
			t.Fatalf("write event %d: %v", i, err)
		}
	}

	// Wait for all events to be applied.
	deadline = time.Now().Add(2 * time.Second)
	for applied.Load() < 5 {
		if time.Now().After(deadline) {
			t.Fatalf("applied = %d, want 5", applied.Load())
		}
		time.Sleep(10 * time.Millisecond)
	}

	// In background, the daemon sends DrainRequest. We respond with DrainComplete.
	done := make(chan uint64, 1)
	go func() {
		drainCtx, drainCancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer drainCancel()
		seq, err := es.SendDrainRequest(drainCtx)
		if err != nil {
			t.Errorf("SendDrainRequest: %v", err)
			return
		}
		done <- seq
	}()

	// Read the DrainRequest from the "helper" side.
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	var drainTargetSeq uint64
	for {
		typ, seq, _, err := readFrame(conn)
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		if typ == EventTypeDrainRequest {
			drainTargetSeq = seq
			break
		}
	}

	// Issue #267: DrainRequest must carry the real lastAppliedSeq, not zero.
	if drainTargetSeq == 0 {
		t.Fatal("DrainRequest target seq = 0, want non-zero (lastAppliedSeq)")
	}
	if drainTargetSeq != 5 {
		t.Fatalf("DrainRequest target seq = %d, want 5", drainTargetSeq)
	}

	// Respond with DrainComplete.
	if err := writeFrame(conn, EventTypeDrainComplete, 99, nil); err != nil {
		t.Fatalf("write DrainComplete: %v", err)
	}

	select {
	case seq := <-done:
		if seq != 99 {
			t.Fatalf("drain complete seq = %d, want 99", seq)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("SendDrainRequest did not complete")
	}
}

func TestEventStreamDisconnectReconnect(t *testing.T) {
	dir := t.TempDir()
	sockPath := filepath.Join(dir, "test-events.sock")

	es := NewEventStream(sockPath)
	var received atomic.Int32
	es.SetOnEvent(func(uint8, uint64, SessionDeltaInfo) {
		received.Add(1)
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	es.Start(ctx)
	defer es.Close()

	time.Sleep(50 * time.Millisecond)

	// First connection.
	conn1, err := net.Dial("unix", sockPath)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}

	dl := time.Now().Add(2 * time.Second)
	for !es.IsConnected() {
		if time.Now().After(dl) {
			t.Fatal("not connected")
		}
		time.Sleep(10 * time.Millisecond)
	}

	// Send one event.
	payload := buildSessionOpenV4Payload(
		6, 1000, 80,
		[4]byte{10, 0, 1, 1}, [4]byte{10, 0, 2, 1},
		[4]byte{}, [4]byte{},
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		[6]byte{}, [6]byte{}, [4]byte{},
	)
	_ = writeFrame(conn1, EventTypeSessionOpen, 1, payload)
	time.Sleep(50 * time.Millisecond)
	if received.Load() != 1 {
		t.Fatalf("received = %d, want 1", received.Load())
	}

	// Disconnect.
	conn1.Close()

	dl = time.Now().Add(2 * time.Second)
	for es.IsConnected() {
		if time.Now().After(dl) {
			t.Fatal("still connected after close")
		}
		time.Sleep(10 * time.Millisecond)
	}

	// Reconnect.
	conn2, err := net.Dial("unix", sockPath)
	if err != nil {
		t.Fatalf("reconnect dial: %v", err)
	}
	defer conn2.Close()

	dl = time.Now().Add(2 * time.Second)
	for !es.IsConnected() {
		if time.Now().After(dl) {
			t.Fatal("not reconnected")
		}
		time.Sleep(10 * time.Millisecond)
	}

	// Send event on second connection.
	_ = writeFrame(conn2, EventTypeSessionOpen, 2, payload)
	dl = time.Now().Add(2 * time.Second)
	for received.Load() < 2 {
		if time.Now().After(dl) {
			t.Fatalf("received = %d after reconnect, want 2", received.Load())
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestEventStreamPauseResume(t *testing.T) {
	dir := t.TempDir()
	sockPath := filepath.Join(dir, "test-events.sock")

	es := NewEventStream(sockPath)
	es.SetOnEvent(func(uint8, uint64, SessionDeltaInfo) {})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	es.Start(ctx)
	defer es.Close()

	time.Sleep(50 * time.Millisecond)

	conn, err := net.Dial("unix", sockPath)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	dl := time.Now().Add(2 * time.Second)
	for !es.IsConnected() {
		if time.Now().After(dl) {
			t.Fatal("not connected")
		}
		time.Sleep(10 * time.Millisecond)
	}

	// Send Pause.
	if err := es.SendPause(); err != nil {
		t.Fatalf("SendPause: %v", err)
	}

	// Read Pause frame on helper side.
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	for {
		typ, _, _, err := readFrame(conn)
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		if typ == EventTypePause {
			break
		}
	}

	// Send Resume.
	if err := es.SendResume(); err != nil {
		t.Fatalf("SendResume: %v", err)
	}

	for {
		typ, _, _, err := readFrame(conn)
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		if typ == EventTypeResume {
			break
		}
	}
}

func TestEventStreamSequenceGapDetection(t *testing.T) {
	dir := t.TempDir()
	sockPath := filepath.Join(dir, "test-events.sock")

	es := NewEventStream(sockPath)
	es.SetOnEvent(func(uint8, uint64, SessionDeltaInfo) {})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	es.Start(ctx)
	defer es.Close()

	time.Sleep(50 * time.Millisecond)

	conn, err := net.Dial("unix", sockPath)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	dl := time.Now().Add(2 * time.Second)
	for !es.IsConnected() {
		if time.Now().After(dl) {
			t.Fatal("not connected")
		}
		time.Sleep(10 * time.Millisecond)
	}

	payload := buildSessionOpenV4Payload(
		6, 1000, 80,
		[4]byte{10, 0, 1, 1}, [4]byte{10, 0, 2, 1},
		[4]byte{}, [4]byte{},
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		[6]byte{}, [6]byte{}, [4]byte{},
	)

	// Send seq 1, then skip to seq 5 (gap of 3).
	_ = writeFrame(conn, EventTypeSessionOpen, 1, payload)
	_ = writeFrame(conn, EventTypeSessionOpen, 5, payload)

	time.Sleep(100 * time.Millisecond)
	if gaps := es.SeqGaps.Load(); gaps != 1 {
		t.Fatalf("SeqGaps = %d, want 1", gaps)
	}
}

func TestEventSocketPathRemoved(t *testing.T) {
	dir := t.TempDir()
	sockPath := filepath.Join(dir, "test-events.sock")

	es := NewEventStream(sockPath)
	ctx, cancel := context.WithCancel(context.Background())
	es.Start(ctx)

	// Verify socket file exists.
	if _, err := os.Stat(sockPath); err != nil {
		t.Fatalf("socket not created: %v", err)
	}

	cancel()
	es.Close()

	// Verify socket file removed.
	if _, err := os.Stat(sockPath); !os.IsNotExist(err) {
		t.Fatal("socket file not cleaned up")
	}
}
