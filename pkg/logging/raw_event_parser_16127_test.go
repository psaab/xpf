package logging

import (
	"encoding/binary"
	"net"
	"testing"
)

// goldenFrame16127 builds a wire frame of the given length carrying a
// distinctive value in every fixed slot, so a parser offset/endianness
// slip flips a golden assertion. Frames shorter than rawEventWireSize
// keep the same prefix (the legacy/short cells).
func goldenFrame16127(length int, family uint8) []byte {
	data := make([]byte, length)
	put := func(off int, b []byte) {
		if off+len(b) <= len(data) {
			copy(data[off:], b)
		}
	}
	u16 := func(v uint16) []byte { b := make([]byte, 2); binary.LittleEndian.PutUint16(b, v); return b }
	u32 := func(v uint32) []byte { b := make([]byte, 4); binary.LittleEndian.PutUint32(b, v); return b }
	u64 := func(v uint64) []byte { b := make([]byte, 8); binary.LittleEndian.PutUint64(b, v); return b }
	be16 := func(v uint16) []byte { b := make([]byte, 2); binary.BigEndian.PutUint16(b, v); return b }

	put(0, u64(1_700_000_300_000_000_000))
	if family == addrFamilyInet6 {
		put(8, net.ParseIP("2001:db8::102").To16())
		put(24, net.ParseIP("2001:db8:1::200").To16())
		put(72, net.ParseIP("2001:db8:2::7").To16())
		put(88, net.ParseIP("2001:db8:3::8").To16())
	} else {
		put(8, net.ParseIP("10.0.1.102").To4())
		put(24, net.ParseIP("172.16.80.200").To4())
		put(72, net.ParseIP("203.0.113.7").To4())
		put(88, net.ParseIP("198.51.100.9").To4())
	}
	put(40, be16(12345))
	put(42, be16(443))
	put(44, u32(4242)) // policy id (non-close) / created nanos (close)
	put(48, u16(3))
	put(50, u16(4))
	if len(data) > 55 {
		data[52] = eventTypeSessionOpen
		data[53] = 6
		data[54] = actionPermit
		data[55] = family
	}
	put(56, u64(111)) // rule id slot / session packets
	put(64, u64(222)) // term/owner slot / session bytes
	put(104, be16(5001))
	put(106, be16(5002))
	put(108, u32(1_700_000_000)) // created secs
	put(112, u64(333))           // rev packets
	put(120, u64(444))           // rev bytes
	put(128, u32(17))            // ingress ifindex
	put(132, u16(0))             // app id
	if len(data) > rawEventLogSyslogOffset {
		data[rawEventLogSyslogOffset] = 1 // per-policy log gate: logged
	}
	put(rawEventPolicyCloseOffset, u32(99)) // admitting policy on close
	// Extended CoS block [144:152] and stable session id [152:160].
	if len(data) > rawEventTOSOffset {
		data[rawEventTOSOffset] = 0xB8
	}
	if len(data) > rawEventTCPBitOffset {
		data[rawEventTCPBitOffset] = 0x13
	}
	put(rawEventEgressOffset, u32(37))
	put(rawEventSessionIDOffset, u64(0x1122334455667788))
	return data
}

func decodeLive16127(t *testing.T, frame []byte) (EventRecord, bool) {
	t.Helper()
	buffer := NewEventBuffer(4)
	reader := NewEventReader(nil, buffer)
	var got EventRecord
	seen := false
	reader.AddCallback(func(rec EventRecord, _ []byte) { got, seen = rec, true })
	if !reader.ProcessRawEvent(frame) {
		return EventRecord{}, false
	}
	if !seen {
		// Accepted frames always run callbacks (they precede the #2508
		// syslog gate), so no callback means the frame was dropped —
		// e.g. an unknown address family rejected by parseRawEvent.
		return EventRecord{}, false
	}
	if recs := buffer.Latest(4); len(recs) != 1 {
		t.Fatalf("buffer holds %d records, want 1", len(recs))
	}
	return got, true
}

// TestRawEventParserGolden16127 pins the shared parser (#16127) across the
// short / legacy-144 / extended / IPv6 golden cells on BOTH entry points:
// DecodeRawEventRecord and the live ProcessRawEvent->logEvent path must
// agree field-for-field on the record fields both populate.
func TestRawEventParserGolden16127(t *testing.T) {
	for _, n := range []int{0, 55, 111, rawEventWireSize - 1} {
		frame := goldenFrame16127(n, addrFamilyInet)
		if _, ok := DecodeRawEventRecord(frame); ok {
			t.Fatalf("len %d: DecodeRawEventRecord accepted a short frame", n)
		}
		buffer := NewEventBuffer(4)
		reader := NewEventReader(nil, buffer)
		if reader.ProcessRawEvent(frame) {
			t.Fatalf("len %d: ProcessRawEvent accepted a short frame", n)
		}
		if got := len(buffer.Latest(4)); got != 0 {
			t.Fatalf("len %d: buffer holds %d records, want 0", n, got)
		}
	}

	// Legacy 144-byte IPv4 SESSION_OPEN golden.
	frame := goldenFrame16127(rawEventWireSize, addrFamilyInet)
	rec, ok := DecodeRawEventRecord(frame)
	if !ok {
		t.Fatal("DecodeRawEventRecord rejected legacy 144-byte frame")
	}
	if rec.SrcAddr != "10.0.1.102:12345" || rec.DstAddr != "172.16.80.200:443" {
		t.Fatalf("tuple = %q -> %q", rec.SrcAddr, rec.DstAddr)
	}
	if rec.NATSrcAddr != "203.0.113.7:5001" || rec.NATDstAddr != "198.51.100.9:5002" {
		t.Fatalf("NAT = %q -> %q", rec.NATSrcAddr, rec.NATDstAddr)
	}
	if rec.PolicyID != 4242 || rec.InZone != 3 || rec.OutZone != 4 || rec.ProtocolNum != 6 {
		t.Fatalf("header = policy %d zones %d/%d proto %d", rec.PolicyID, rec.InZone, rec.OutZone, rec.ProtocolNum)
	}
	if rec.RuleID != 111 || rec.TermID != 0 {
		// [56:64] LE u64 111 -> RuleID low u32 111, TermID [60:64] 0.
		t.Fatalf("RuleID/TermID = %d/%d", rec.RuleID, rec.TermID)
	}
	if rec.Created != 1_700_000_000 || rec.IngressIfindex != 17 {
		t.Fatalf("Created/Ifindex = %d/%d", rec.Created, rec.IngressIfindex)
	}
	if rec.RevSessionPkts != 333 || rec.RevSessionBytes != 444 {
		t.Fatalf("rev counters = %d/%d (non-close records carry them in the decode path)", rec.RevSessionPkts, rec.RevSessionBytes)
	}
	if rec.SessionID != 0 || rec.TOS != 0 || rec.EgressIfindex != 0 {
		t.Fatalf("legacy frame must leave extended slots zero, got sid %#x tos %#x egress %d", rec.SessionID, rec.TOS, rec.EgressIfindex)
	}

	live, ok := decodeLive16127(t, frame)
	if !ok {
		t.Fatal("live path rejected legacy 144-byte frame")
	}
	assertSharedFields16127(t, live, rec)

	// Extended 160-byte IPv6 SESSION_CLOSE golden.
	closeFrame := goldenFrame16127(rawEventSessionIDSize, addrFamilyInet6)
	closeFrame[52] = eventTypeSessionClose
	crec, ok := DecodeRawEventRecord(closeFrame)
	if !ok {
		t.Fatal("DecodeRawEventRecord rejected extended IPv6 close frame")
	}
	if crec.SrcAddr != "[2001:db8::102]:12345" || crec.DstAddr != "[2001:db8:1::200]:443" {
		t.Fatalf("v6 tuple = %q -> %q", crec.SrcAddr, crec.DstAddr)
	}
	if crec.NATSrcAddr != "[2001:db8:2::7]:5001" || crec.NATDstAddr != "[2001:db8:3::8]:5002" {
		t.Fatalf("v6 NAT = %q -> %q", crec.NATSrcAddr, crec.NATDstAddr)
	}
	if crec.CreatedNanos != 4242 || crec.PolicyID != 99 {
		t.Fatalf("close CreatedNanos/PolicyID = %d/%d, want 4242/99", crec.CreatedNanos, crec.PolicyID)
	}
	if crec.SessionPkts != 111 || crec.SessionBytes != 222 {
		t.Fatalf("close counters = %d/%d", crec.SessionPkts, crec.SessionBytes)
	}
	if crec.TOS != 0xB8 || crec.TCPControlBits != 0x13 || crec.EgressIfindex != 37 {
		t.Fatalf("CoS block = %#x/%#x/%d", crec.TOS, crec.TCPControlBits, crec.EgressIfindex)
	}
	if crec.SessionID != 0x1122334455667788 {
		t.Fatalf("SessionID = %#x", crec.SessionID)
	}
	clive, ok := decodeLive16127(t, closeFrame)
	if !ok {
		t.Fatal("live path rejected extended IPv6 close frame")
	}
	assertSharedFields16127(t, clive, crec)
	if clive.ElapsedTime != 300 {
		t.Fatalf("live ElapsedTime = %d, want 300 (close ts 1700000300 - created 1700000000)", clive.ElapsedTime)
	}
}

// assertSharedFields16127 compares the fields both paths populate from the
// shared parser. Live-only enrichments (zone/iface/app/policy names,
// EventSeq, ElapsedTime) and the decode-only zeroing of non-close session
// counters are intentionally excluded.
func assertSharedFields16127(t *testing.T, live, decoded EventRecord) {
	t.Helper()
	if live.Type != decoded.Type || live.SrcAddr != decoded.SrcAddr || live.DstAddr != decoded.DstAddr ||
		live.Protocol != decoded.Protocol || live.ProtocolNum != decoded.ProtocolNum ||
		live.Action != decoded.Action || live.PolicyID != decoded.PolicyID ||
		live.RuleID != decoded.RuleID || live.TermID != decoded.TermID ||
		live.OwnerRGID != decoded.OwnerRGID || live.Reason != decoded.Reason ||
		live.InZone != decoded.InZone || live.OutZone != decoded.OutZone ||
		live.ScreenCheck != decoded.ScreenCheck ||
		live.NATSrcAddr != decoded.NATSrcAddr || live.NATDstAddr != decoded.NATDstAddr ||
		live.Created != decoded.Created || live.CreatedNanos != decoded.CreatedNanos ||
		live.RevSessionPkts != decoded.RevSessionPkts || live.RevSessionBytes != decoded.RevSessionBytes ||
		live.IngressIfindex != decoded.IngressIfindex || live.CloseReason != decoded.CloseReason ||
		live.TOS != decoded.TOS || live.TCPControlBits != decoded.TCPControlBits ||
		live.EgressIfindex != decoded.EgressIfindex {
		t.Fatalf("live and decoded records diverge:\nlive:    %+v\ndecoded: %+v", live, decoded)
	}
	if !live.Time.Equal(decoded.Time) {
		t.Fatalf("live Time %v != decoded Time %v", live.Time, decoded.Time)
	}
	// Session counters: the live path populates them only on SESSION_CLOSE
	// (same frames the decoder keeps them on); compare unconditionally and
	// let the close golden above exercise the nonzero cell.
	if live.SessionPkts != decoded.SessionPkts || live.SessionBytes != decoded.SessionBytes {
		t.Fatalf("session counters live %d/%d != decoded %d/%d",
			live.SessionPkts, live.SessionBytes, decoded.SessionPkts, decoded.SessionBytes)
	}
	// SessionID: the decoder surfaces the wire id; the live path falls back
	// to its per-event ordinal when... it also decodes the wire id on
	// extended session frames, so extended frames must match exactly.
	if decoded.SessionID != 0 && live.SessionID != decoded.SessionID {
		t.Fatalf("SessionID live %#x != decoded %#x", live.SessionID, decoded.SessionID)
	}
}

// TestRawEventFamilyPolicy16127 pins the explicit #16127 unknown-family
// policy: REJECT on both paths. Only AF_INET (2) and AF_INET6 (10) decode;
// every other family byte is dropped by the live path and rejected by
// DecodeRawEventRecord. Reverting parseRawEvent to the former live-only
// "non-v6 means v4" fallback makes the live cells RED.
func TestRawEventFamilyPolicy16127(t *testing.T) {
	for _, family := range []uint8{0, 1, 3, 9, 11, 255} {
		frame := goldenFrame16127(rawEventWireSize, addrFamilyInet)
		frame[55] = family
		if _, ok := DecodeRawEventRecord(frame); ok {
			t.Fatalf("family %d: DecodeRawEventRecord accepted unknown family", family)
		}
		if _, ok := decodeLive16127(t, frame); ok {
			t.Fatalf("family %d: live path accepted unknown family (must drop, not render as IPv4)", family)
		}
	}
	for _, family := range []uint8{addrFamilyInet, addrFamilyInet6} {
		frame := goldenFrame16127(rawEventWireSize, family)
		if _, ok := DecodeRawEventRecord(frame); !ok {
			t.Fatalf("family %d: DecodeRawEventRecord rejected known family", family)
		}
		if _, ok := decodeLive16127(t, frame); !ok {
			t.Fatalf("family %d: live path rejected known family", family)
		}
	}
}

// TestParseRawEventZeroAlloc16127 pins the #16127 zero-extra-allocation
// budget: the shared parser itself must not allocate. (The address-string
// formatting above the parser allocates exactly as the pre-unification
// paths did; this guards the parse step added by the unification.)
func TestParseRawEventZeroAlloc16127(t *testing.T) {
	frame := goldenFrame16127(rawEventWireSize, addrFamilyInet)
	var evt rawEvent
	if got := testing.AllocsPerRun(100, func() {
		evt = rawEvent{}
		if !parseRawEvent(frame, &evt) {
			t.Fatal("parseRawEvent rejected golden frame")
		}
	}); got != 0 {
		t.Fatalf("parseRawEvent allocated %v times per run, want 0", got)
	}
	if evt.PolicyID != 4242 || evt.AddrFamily != addrFamilyInet {
		t.Fatalf("parse sanity: policy %d family %d", evt.PolicyID, evt.AddrFamily)
	}
}
