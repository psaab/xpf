package logging

import (
	"encoding/binary"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unsafe"

	"github.com/psaab/xpf/pkg/dataplane"
)

func TestFormatBinaryRecord_Basic(t *testing.T) {
	evt := &rawEvent{
		EventType:   eventTypeSessionOpen,
		Protocol:    6, // TCP
		Action:      actionPermit,
		AddrFamily:  addrFamilyInet,
		SrcPort:     12345,
		DstPort:     443,
		PolicyID:    42,
		IngressZone: 1,
		EgressZone:  2,
	}
	copy(evt.SrcIP[:4], net.ParseIP("10.0.1.5").To4())
	copy(evt.DstIP[:4], net.ParseIP("10.0.2.10").To4())

	rec := &EventRecord{
		Time:        time.Date(2026, 1, 15, 10, 30, 0, 0, time.UTC),
		InZoneName:  "trust",
		OutZoneName: "untrust",
		// #4914: the binary record now encodes rec.PolicyID (the authoritative
		// post-processing policy id) rather than evt.PolicyID. In the live
		// pipeline logEvent mirrors evt.PolicyID into rec.PolicyID for every
		// non-close event, so set it here to match evt.PolicyID above.
		PolicyID:   42,
		PolicyName: "allow-web",
		AppName:    "junos-https",
		SessionID:  100,
	}

	buf := formatBinaryRecord(evt, rec, SyslogInfo, 0)

	// Verify magic
	if buf[0] != binaryLogMagicHi || buf[1] != binaryLogMagicLo {
		t.Errorf("magic = 0x%02x%02x, want 0xBF52", buf[0], buf[1])
	}

	// Verify version
	if buf[2] != binaryLogVersion {
		t.Errorf("version = %d, want %d", buf[2], binaryLogVersion)
	}

	// Verify total length
	totalLen := binary.BigEndian.Uint16(buf[3:5])
	if int(totalLen) != len(buf) {
		t.Errorf("record length = %d, buf len = %d", totalLen, len(buf))
	}

	// Verify event fields
	if buf[5] != eventTypeSessionOpen {
		t.Errorf("event type = %d, want %d", buf[5], eventTypeSessionOpen)
	}
	if buf[6] != 6 {
		t.Errorf("protocol = %d, want 6", buf[6])
	}
	// #7531: this fixture is a SESSION_OPEN, and a lifecycle event's binary
	// action byte is the "not applicable" sentinel, not a forwarding decision.
	//
	// The assertion used to be `want actionPermit`, pinning a value NO PRODUCER
	// EMITS. Every write to the wire action byte was enumerated: the two
	// lifecycle encoders (`encode_session_close_rt_flow` /
	// `encode_session_create_rt_flow`) both write a literal 0 and say at the
	// write site that it is intentional, and the generic
	// `encode_dataplane_event` — the only site that writes `event.action`
	// verbatim — carries a `debug_assert!(false)` for SessionClose/SessionCreate
	// stating that no payload is ever constructed for them. So the old
	// expectation described a record that cannot occur, while the record that
	// DOES occur (action byte 0) rendered as `deny` to every binary consumer.
	if buf[7] != actionNotApplicable {
		t.Errorf("action = %d, want %d (actionNotApplicable — a SESSION_OPEN "+
			"carries no forwarding decision)", buf[7], actionNotApplicable)
	}
	if buf[8] != addrFamilyInet {
		t.Errorf("addr family = %d, want %d", buf[8], addrFamilyInet)
	}
	if buf[9] != uint8(SyslogInfo) {
		t.Errorf("severity = %d, want %d", buf[9], SyslogInfo)
	}

	// Verify source IP (first 4 bytes should match)
	srcIP := net.IP(buf[18:22])
	if !srcIP.Equal(net.ParseIP("10.0.1.5").To4()) {
		t.Errorf("src IP = %s, want 10.0.1.5", srcIP)
	}

	// Verify ports
	srcPort := binary.BigEndian.Uint16(buf[50:52])
	dstPort := binary.BigEndian.Uint16(buf[52:54])
	if srcPort != 12345 {
		t.Errorf("src port = %d, want 12345", srcPort)
	}
	if dstPort != 443 {
		t.Errorf("dst port = %d, want 443", dstPort)
	}

	// Verify policy ID
	policyID := binary.LittleEndian.Uint32(buf[54:58])
	if policyID != 42 {
		t.Errorf("policy ID = %d, want 42", policyID)
	}

	// Verify zone IDs
	inZone := binary.LittleEndian.Uint16(buf[58:60])
	outZone := binary.LittleEndian.Uint16(buf[60:62])
	if inZone != 1 {
		t.Errorf("ingress zone = %d, want 1", inZone)
	}
	if outZone != 2 {
		t.Errorf("egress zone = %d, want 2", outZone)
	}

	// Verify session ID
	sessID := binary.LittleEndian.Uint64(buf[134:142])
	if sessID != 100 {
		t.Errorf("session ID = %d, want 100", sessID)
	}

	// Verify variable-length strings
	off := binaryLogHeaderSize
	inZoneName, off := readLenStr(buf, off)
	if inZoneName != "trust" {
		t.Errorf("in zone name = %q, want %q", inZoneName, "trust")
	}
	outZoneName, off := readLenStr(buf, off)
	if outZoneName != "untrust" {
		t.Errorf("out zone name = %q, want %q", outZoneName, "untrust")
	}
	policyName, off := readLenStr(buf, off)
	if policyName != "allow-web" {
		t.Errorf("policy name = %q, want %q", policyName, "allow-web")
	}
	appName, off := readLenStr(buf, off)
	if appName != "junos-https" {
		t.Errorf("app name = %q, want %q", appName, "junos-https")
	}
	ifName, _ := readLenStr(buf, off)
	if ifName != "" {
		t.Errorf("iface name = %q, want %q", ifName, "")
	}
}

func TestRawEventWireContractSize(t *testing.T) {
	// #3056: grew 136 -> 144 to carry the admitting policy ID on a SESSION_CLOSE
	// frame in the trailing [136:140] slot (#2853 occupies [44:48] on a close).
	if rawEventWireSize != 144 {
		t.Fatalf("rawEventWireSize = %d, want 144", rawEventWireSize)
	}
	if rawEventStructSize != rawEventWireSize {
		t.Fatalf("rawEventStructSize = %d, want wire size %d",
			rawEventStructSize, rawEventWireSize)
	}
}

func TestRawEventContractMatchesDataplaneEvent(t *testing.T) {
	if rawEventWireSize != int(unsafe.Sizeof(dataplane.Event{})) {
		t.Fatalf("rawEventWireSize = %d, dataplane.Event size = %d",
			rawEventWireSize, unsafe.Sizeof(dataplane.Event{}))
	}
	if eventTypeSessionOpen != dataplane.EventTypeSessionOpen {
		t.Fatalf("eventTypeSessionOpen = %d, want %d",
			eventTypeSessionOpen, dataplane.EventTypeSessionOpen)
	}
	if eventTypeSessionClose != dataplane.EventTypeSessionClose {
		t.Fatalf("eventTypeSessionClose = %d, want %d",
			eventTypeSessionClose, dataplane.EventTypeSessionClose)
	}
	if eventTypePolicyDeny != dataplane.EventTypePolicyDeny {
		t.Fatalf("eventTypePolicyDeny = %d, want %d",
			eventTypePolicyDeny, dataplane.EventTypePolicyDeny)
	}
	if eventTypeScreenDrop != dataplane.EventTypeScreenDrop {
		t.Fatalf("eventTypeScreenDrop = %d, want %d",
			eventTypeScreenDrop, dataplane.EventTypeScreenDrop)
	}
	if eventTypeFilterLog != dataplane.EventTypeFilterLog {
		t.Fatalf("eventTypeFilterLog = %d, want %d",
			eventTypeFilterLog, dataplane.EventTypeFilterLog)
	}
	if actionDeny != dataplane.ActionDeny ||
		actionPermit != dataplane.ActionPermit ||
		actionReject != dataplane.ActionReject {
		t.Fatalf("action constants drifted: logging=(%d,%d,%d) dataplane=(%d,%d,%d)",
			actionDeny, actionPermit, actionReject,
			dataplane.ActionDeny, dataplane.ActionPermit, dataplane.ActionReject)
	}
	if addrFamilyInet != dataplane.AFInet || addrFamilyInet6 != dataplane.AFInet6 {
		t.Fatalf("address family constants drifted: logging=(%d,%d) dataplane=(%d,%d)",
			addrFamilyInet, addrFamilyInet6, dataplane.AFInet, dataplane.AFInet6)
	}
	if closeReasonNone != dataplane.CloseReasonNone ||
		closeReasonTimeout != dataplane.CloseReasonTimeout ||
		closeReasonTCPFIN != dataplane.CloseReasonTCPFIN ||
		closeReasonTCPRST != dataplane.CloseReasonTCPRST ||
		closeReasonAgeOut != dataplane.CloseReasonAgeOut ||
		closeReasonPolicy != dataplane.CloseReasonPolicy ||
		closeReasonClear != dataplane.CloseReasonClear ||
		closeReasonPolicyDelete != dataplane.CloseReasonPolicyDelete {
		t.Fatalf("close reason constants drifted")
	}
	if len(screenFlagNames) != len(dataplane.ScreenFlagNames) {
		t.Fatalf("screen flag count = %d, want %d",
			len(screenFlagNames), len(dataplane.ScreenFlagNames))
	}
	for flag, name := range dataplane.ScreenFlagNames {
		if screenFlagNames[flag] != name {
			t.Fatalf("screen flag %d = %q, want %q",
				flag, screenFlagNames[flag], name)
		}
	}
}

func TestRawEventContractMatchesBPFHeader(t *testing.T) {
	fields := eventStructFieldsFromXPFCommon(t)
	want := []string{
		"__u64 timestamp",
		"__u8 src_ip[16]",
		"__u8 dst_ip[16]",
		"__be16 src_port",
		"__be16 dst_port",
		"__u32 policy_id",
		"__u16 ingress_zone",
		"__u16 egress_zone",
		"__u8 event_type",
		"__u8 protocol",
		"__u8 action",
		"__u8 addr_family",
		"__u64 session_packets",
		"__u64 session_bytes",
		"__u8 nat_src_ip[16]",
		"__u8 nat_dst_ip[16]",
		"__be16 nat_src_port",
		"__be16 nat_dst_port",
		"__u32 created",
		"__u64 rev_packets",
		"__u64 rev_bytes",
		"__u32 ingress_ifindex",
		"__u16 app_id",
		"__u8 close_reason",
		"__u8 pad_event",
	}
	if len(fields) != len(want) {
		t.Fatalf("struct event field count = %d, want %d\nfields: %v",
			len(fields), len(want), fields)
	}
	for i := range want {
		if fields[i] != want[i] {
			t.Fatalf("struct event field %d = %q, want %q\nfields: %v",
				i, fields[i], want[i], fields)
		}
	}
}

func TestRawEventFieldOffsetsMatchWireFormat(t *testing.T) {
	var evt rawEvent
	tests := []struct {
		name string
		got  uintptr
		want uintptr
	}{
		{name: "Timestamp", got: unsafe.Offsetof(evt.Timestamp), want: 0},
		{name: "SrcIP", got: unsafe.Offsetof(evt.SrcIP), want: 8},
		{name: "DstIP", got: unsafe.Offsetof(evt.DstIP), want: 24},
		{name: "SrcPort", got: unsafe.Offsetof(evt.SrcPort), want: 40},
		{name: "DstPort", got: unsafe.Offsetof(evt.DstPort), want: 42},
		{name: "PolicyID", got: unsafe.Offsetof(evt.PolicyID), want: 44},
		{name: "IngressZone", got: unsafe.Offsetof(evt.IngressZone), want: 48},
		{name: "EgressZone", got: unsafe.Offsetof(evt.EgressZone), want: 50},
		{name: "EventType", got: unsafe.Offsetof(evt.EventType), want: 52},
		{name: "Protocol", got: unsafe.Offsetof(evt.Protocol), want: 53},
		{name: "Action", got: unsafe.Offsetof(evt.Action), want: 54},
		{name: "AddrFamily", got: unsafe.Offsetof(evt.AddrFamily), want: 55},
		{name: "SessionPackets", got: unsafe.Offsetof(evt.SessionPackets), want: 56},
		{name: "SessionBytes", got: unsafe.Offsetof(evt.SessionBytes), want: 64},
		{name: "NATSrcIP", got: unsafe.Offsetof(evt.NATSrcIP), want: 72},
		{name: "NATDstIP", got: unsafe.Offsetof(evt.NATDstIP), want: 88},
		{name: "NATSrcPort", got: unsafe.Offsetof(evt.NATSrcPort), want: 104},
		{name: "NATDstPort", got: unsafe.Offsetof(evt.NATDstPort), want: 106},
		{name: "Created", got: unsafe.Offsetof(evt.Created), want: 108},
		{name: "RevPackets", got: unsafe.Offsetof(evt.RevPackets), want: 112},
		{name: "RevBytes", got: unsafe.Offsetof(evt.RevBytes), want: 120},
		{name: "IngressIfindex", got: unsafe.Offsetof(evt.IngressIfindex), want: 128},
		{name: "AppID", got: unsafe.Offsetof(evt.AppID), want: 132},
		{name: "CloseReason", got: unsafe.Offsetof(evt.CloseReason), want: 134},
		{name: "LogSyslog", got: unsafe.Offsetof(evt.LogSyslog), want: 135},
	}
	for _, tt := range tests {
		if tt.got != tt.want {
			t.Fatalf("%s offset = %d, want %d", tt.name, tt.got, tt.want)
		}
	}
}

func eventStructFieldsFromXPFCommon(t *testing.T) []string {
	t.Helper()
	path := filepath.Join("..", "..", "bpf", "headers", "xpf_common.h")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	text := string(data)
	start := strings.Index(text, "struct event {")
	if start < 0 {
		t.Fatalf("%s missing struct event", path)
	}
	bodyStart := start + len("struct event {")
	end := strings.Index(text[bodyStart:], "\n};")
	if end < 0 {
		t.Fatalf("%s struct event missing terminator", path)
	}
	body := text[bodyStart : bodyStart+end]
	var fields []string
	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "/*") || strings.HasPrefix(line, "*") {
			continue
		}
		if idx := strings.Index(line, "/*"); idx >= 0 {
			line = strings.TrimSpace(line[:idx])
		}
		line = strings.TrimSuffix(line, ";")
		line = strings.Join(strings.Fields(line), " ")
		if line != "" {
			fields = append(fields, line)
		}
	}
	return fields
}

func minimallyValidRawEventData() []byte {
	data := make([]byte, rawEventWireSize)
	data[40] = 0x30 // src port 12345
	data[41] = 0x39
	data[42] = 0x01 // dst port 443
	data[43] = 0xbb
	data[52] = eventTypeSessionOpen
	data[53] = 6
	data[54] = actionPermit
	data[55] = addrFamilyInet
	copy(data[8:12], net.ParseIP("10.0.1.1").To4())
	copy(data[24:28], net.ParseIP("10.0.2.1").To4())
	// #2508: mark the SESSION_OPEN as per-policy logged so it reaches the
	// human-facing log buffer (a SESSION_OPEN/CLOSE with the gate clear is
	// intentionally suppressed; tests that assert buffering must opt in).
	data[rawEventLogSyslogOffset] = 1
	return data
}

func TestDecodeRawEventRecordRejectsShortRecord(t *testing.T) {
	tests := []struct {
		name string
		data []byte
		want bool
	}{
		{name: "nil", data: nil, want: false},
		{name: "empty", data: []byte{}, want: false},
		{name: "short", data: make([]byte, rawEventWireSize-1), want: false},
		{name: "exact", data: minimallyValidRawEventData(), want: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, ok := DecodeRawEventRecord(tt.data)
			if ok != tt.want {
				t.Fatalf("DecodeRawEventRecord(%s) ok = %v, want %v", tt.name, ok, tt.want)
			}
		})
	}
}

// TestDecodeRawEventCarriesCreatedStamp is the #2465 cross-language layout
// check for the SESSION_CLOSE frame: the Rust encoder
// (event_stream/codec.rs::encode_session_close_rt_flow) writes the absolute
// session-creation Unix SECONDS at offset 108 as a LITTLE-endian u32 and the
// close instant at offset 0 as a LITTLE-endian u64. This test builds a frame
// at those exact offsets/endianness and asserts DecodeRawEventRecord surfaces
// them into EventRecord.Created (and the close timestamp into rec.Time). A
// one-sided field — Rust writes offset 108 but Go reads a different offset or
// endianness — would corrupt the StartTime; this pins the contract.
func TestDecodeRawEventCarriesCreatedStamp(t *testing.T) {
	const (
		createdSecs = uint32(1_700_000_000)
		closeNS     = uint64(1_700_000_300_000_000_000) // 300s later, in ns
	)
	data := make([]byte, rawEventWireSize)
	// offset 0: timestamp_ns (LE u64) — the close instant (record EndTime).
	binary.LittleEndian.PutUint64(data[0:8], closeNS)
	data[40], data[41] = 0x30, 0x39 // src port 12345 (BE)
	data[42], data[43] = 0x01, 0xbb // dst port 443 (BE)
	data[52] = eventTypeSessionClose
	data[53] = 6 // TCP
	data[55] = addrFamilyInet
	copy(data[8:12], net.ParseIP("10.0.1.102").To4())
	copy(data[24:28], net.ParseIP("172.16.80.200").To4())
	// offset 108: created (LE u32) Unix seconds — the #2465 field.
	binary.LittleEndian.PutUint32(data[108:112], createdSecs)

	rec, ok := DecodeRawEventRecord(data)
	if !ok {
		t.Fatal("DecodeRawEventRecord rejected a valid SESSION_CLOSE frame")
	}
	if rec.Type != "SESSION_CLOSE" {
		t.Fatalf("Type = %q, want SESSION_CLOSE", rec.Type)
	}
	if rec.Created != createdSecs {
		t.Fatalf("rec.Created = %d, want %d (offset 108 LE u32)", rec.Created, createdSecs)
	}
	if !rec.Time.Equal(time.Unix(0, int64(closeNS))) {
		t.Fatalf("rec.Time = %v, want %v (offset 0 LE u64)", rec.Time, time.Unix(0, int64(closeNS)))
	}
}

// TestDecodeRawEventCarriesIngressIfindex13556 pins #13556: the wire
// [128:132] ingress ifindex (#2615) decoded into rawEvent.IngressIfindex
// must survive DecodeRawEventRecord into EventRecord.IngressIfindex.
// The production consumers (daemon flowExportCallback /
// ipfixExportCallback via the userspace eventstream raw path) copy
// rec.IngressIfindex into SessionCloseData.InIf, which the exporters
// encode as NetFlow v9 IN_SNMP / IPFIX ingressInterface (IE 10).
// Dropping the field makes every decoded close export InIf=0.
func TestDecodeRawEventCarriesIngressIfindex13556(t *testing.T) {
	const ingressIfindex = uint32(0x0A0B0C0D)
	data := make([]byte, rawEventWireSize)
	binary.LittleEndian.PutUint64(data[0:8], uint64(1_700_000_300_000_000_000))
	data[40], data[41] = 0x30, 0x39
	data[42], data[43] = 0x01, 0xbb
	data[52] = eventTypeSessionClose
	data[53] = 6
	data[55] = addrFamilyInet
	copy(data[8:12], net.ParseIP("10.0.1.102").To4())
	copy(data[24:28], net.ParseIP("172.16.80.200").To4())
	binary.LittleEndian.PutUint32(data[128:132], ingressIfindex)

	rec, ok := DecodeRawEventRecord(data)
	if !ok {
		t.Fatal("DecodeRawEventRecord rejected a valid SESSION_CLOSE frame")
	}
	if rec.IngressIfindex != ingressIfindex {
		t.Fatalf("rec.IngressIfindex = 0x%08x, want 0x%08x ([128:132] LE u32 dropped by DecodeRawEventRecord)",
			rec.IngressIfindex, ingressIfindex)
	}
}

// TestDecodeRawEventCarriesCreatedSubNanos is the #2853 cross-language layout
// check: the Rust encoder writes the creation instant's sub-second NANOSECOND
// remainder into the SESSION_CLOSE-unused policy_id slot at offset 44 (LE u32).
// DecodeRawEventRecord must surface it into EventRecord.CreatedNanos AND clear
// PolicyID (so the close record's policy id/name stays the "no policy" value,
// not the nanosecond bits). Reverting the decoder to read [44:48] as PolicyID
// (the pre-#2853 behavior) makes CreatedNanos 0 and PolicyID nonzero — both
// assertions catch that.
func TestDecodeRawEventCarriesCreatedSubNanos(t *testing.T) {
	const (
		createdSecs  = uint32(1_700_000_000)
		createdNanos = uint32(123_456_789) // 123.456789 ms into the second
		closeNS      = uint64(1_700_000_300_000_000_000)
	)
	data := make([]byte, rawEventWireSize)
	binary.LittleEndian.PutUint64(data[0:8], closeNS)
	data[40], data[41] = 0x30, 0x39
	data[42], data[43] = 0x01, 0xbb
	data[52] = eventTypeSessionClose
	data[53] = 6
	data[55] = addrFamilyInet
	copy(data[8:12], net.ParseIP("10.0.1.102").To4())
	copy(data[24:28], net.ParseIP("172.16.80.200").To4())
	binary.LittleEndian.PutUint32(data[108:112], createdSecs)
	// offset 44: created sub-second nanos (LE u32) — the #2853 repurposed slot.
	binary.LittleEndian.PutUint32(data[44:48], createdNanos)

	rec, ok := DecodeRawEventRecord(data)
	if !ok {
		t.Fatal("DecodeRawEventRecord rejected a valid SESSION_CLOSE frame")
	}
	if rec.CreatedNanos != createdNanos {
		t.Fatalf("rec.CreatedNanos = %d, want %d (offset 44 LE u32)", rec.CreatedNanos, createdNanos)
	}
	if rec.PolicyID != 0 {
		t.Fatalf("rec.PolicyID = %d, want 0 (the [44:48] slot is repurposed on a close; the #3056 policy slot at [136:140] is unset here)", rec.PolicyID)
	}
}

// TestDecodeRawEventCloseCarriesAdmittingPolicyID is the #3056 cross-language
// layout check: because #2853 took the [44:48] policy_id slot on a close for the
// created-subsec-nanos, the Rust encoder writes the admitting policy ID into the
// trailing [136:140] slot (LE u32) on a SESSION_CLOSE. DecodeRawEventRecord (and
// the live logEvent path) must read [136:140] back into EventRecord.PolicyID so
// the RT_FLOW_SESSION_CLOSE record and the NetFlow/IPFIX close exporters name the
// admitting policy instead of policy 0. The [44:48] created-subsec-nanos must NOT
// be clobbered. Reverting the decoder to leave the close PolicyID 0 (the
// pre-#3056 behavior) makes this assertion fail.
func TestDecodeRawEventCloseCarriesAdmittingPolicyID(t *testing.T) {
	const (
		policyID     = uint32(42)
		createdNanos = uint32(123_456_789)
		closeNS      = uint64(1_700_000_300_000_000_000)
	)
	data := make([]byte, rawEventWireSize)
	binary.LittleEndian.PutUint64(data[0:8], closeNS)
	data[40], data[41] = 0x30, 0x39
	data[42], data[43] = 0x01, 0xbb
	data[52] = eventTypeSessionClose
	data[53] = 6
	data[55] = addrFamilyInet
	copy(data[8:12], net.ParseIP("10.0.1.102").To4())
	copy(data[24:28], net.ParseIP("172.16.80.200").To4())
	// offset 44: #2853 created-subsec-nanos (must survive).
	binary.LittleEndian.PutUint32(data[44:48], createdNanos)
	// offset 136: #3056 admitting policy ID (LE u32) — the close-only slot.
	binary.LittleEndian.PutUint32(data[rawEventPolicyCloseOffset:rawEventPolicyCloseOffset+4], policyID)

	rec, ok := DecodeRawEventRecord(data)
	if !ok {
		t.Fatal("DecodeRawEventRecord rejected a valid SESSION_CLOSE frame")
	}
	if rec.PolicyID != policyID {
		t.Fatalf("rec.PolicyID = %d, want %d (offset 136 LE u32 on a close)", rec.PolicyID, policyID)
	}
	if rec.CreatedNanos != createdNanos {
		t.Fatalf("rec.CreatedNanos = %d, want %d ([44:48] must not be clobbered by the policy read)",
			rec.CreatedNanos, createdNanos)
	}
}

// TestDecodeRawEventCloseCarriesCosBlock is the #2749 Go-side round-trip pin:
// an EXTENDED (152-byte) SESSION_CLOSE frame — the shape the Rust
// encode_session_close_rt_flow now emits — must decode its [144:152]
// class-of-service / interface-attribution block into EventRecord.TOS /
// TCPControlBits / EgressIfindex with the real values, not zero. Reverting the
// ringbuf reads (or the Rust encoder writes) flips this RED.
func TestDecodeRawEventCloseCarriesCosBlock(t *testing.T) {
	const (
		tos      = uint8(0xB8) // DSCP EF (46) << 2
		tcpBits  = uint8(0x13) // SYN|FIN|ACK
		egressIf = uint32(0xFEEDFACE)
	)
	data := make([]byte, rawEventExtSize)
	data[52] = eventTypeSessionClose
	data[53] = 6
	data[55] = addrFamilyInet
	copy(data[8:12], net.ParseIP("10.0.1.102").To4())
	copy(data[24:28], net.ParseIP("172.16.80.200").To4())
	data[rawEventTOSOffset] = tos
	data[rawEventTCPBitOffset] = tcpBits
	binary.LittleEndian.PutUint32(data[rawEventEgressOffset:rawEventEgressOffset+4], egressIf)

	rec, ok := DecodeRawEventRecord(data)
	if !ok {
		t.Fatal("DecodeRawEventRecord rejected a valid extended SESSION_CLOSE frame")
	}
	if rec.TOS != tos {
		t.Fatalf("rec.TOS = 0x%02x, want 0x%02x ([144] read reverted)", rec.TOS, tos)
	}
	if rec.TCPControlBits != tcpBits {
		t.Fatalf("rec.TCPControlBits = 0x%02x, want 0x%02x ([145] read reverted)", rec.TCPControlBits, tcpBits)
	}
	if rec.EgressIfindex != egressIf {
		t.Fatalf("rec.EgressIfindex = 0x%08x, want 0x%08x ([148:152] read reverted)", rec.EgressIfindex, egressIf)
	}

	// Additive/back-compat: a legacy 144-byte close frame must still decode
	// (minimum acceptance is rawEventWireSize, not the extended size) and leave
	// the CoS block at the 0 "unknown" default.
	legacy := data[:rawEventWireSize]
	lrec, ok := DecodeRawEventRecord(legacy)
	if !ok {
		t.Fatal("DecodeRawEventRecord rejected a legacy 144-byte SESSION_CLOSE frame")
	}
	if lrec.TOS != 0 || lrec.TCPControlBits != 0 || lrec.EgressIfindex != 0 {
		t.Fatalf("legacy 144-byte frame must leave CoS block zero, got {0x%02x 0x%02x 0x%08x}",
			lrec.TOS, lrec.TCPControlBits, lrec.EgressIfindex)
	}
}

// TestDecodeRawEventPolicyDenyKeepsPolicyID guards the #2853 negative: a
// non-SESSION_CLOSE frame must still read [44:48] as the real PolicyID (the
// repurpose is close-only). A POLICY_DENY carrying a policy id must surface it.
func TestDecodeRawEventPolicyDenyKeepsPolicyID(t *testing.T) {
	const policyID = uint32(4242)
	data := make([]byte, rawEventWireSize)
	data[40], data[41] = 0x30, 0x39
	data[42], data[43] = 0x01, 0xbb
	data[52] = eventTypePolicyDeny
	data[53] = 6
	data[54] = actionDeny
	data[55] = addrFamilyInet
	copy(data[8:12], net.ParseIP("192.0.2.10").To4())
	copy(data[24:28], net.ParseIP("198.51.100.20").To4())
	binary.LittleEndian.PutUint32(data[44:48], policyID)

	rec, ok := DecodeRawEventRecord(data)
	if !ok {
		t.Fatal("DecodeRawEventRecord rejected a valid POLICY_DENY frame")
	}
	if rec.PolicyID != policyID {
		t.Fatalf("rec.PolicyID = %d, want %d (non-close frames keep the real policy id)", rec.PolicyID, policyID)
	}
	if rec.CreatedNanos != 0 {
		t.Fatalf("rec.CreatedNanos = %d, want 0 (only SESSION_CLOSE repurposes [44:48])", rec.CreatedNanos)
	}
}

// TestDecodeRawEventPolicyDenyUsesDecisionTimestamp pins the #2470 contract on
// the Go side: an RT_FLOW deny/screen/filter-log event carries the dataplane
// DECISION instant at offset 0 (LE u64, absolute Unix ns). When it is nonzero
// the decoder must report THAT instant in rec.Time, not the daemon receive
// time (time.Now()), so a backlogged / reconnect-delayed delivery cannot skew
// the logged event time to consumption time. The Rust emitters previously
// wrote 0 here (the bug), which falls through to receive time below.
func TestDecodeRawEventPolicyDenyUsesDecisionTimestamp(t *testing.T) {
	const decisionNS = uint64(1_700_000_123_000_000_000)
	data := make([]byte, rawEventWireSize)
	binary.LittleEndian.PutUint64(data[0:8], decisionNS) // offset 0: timestamp_ns
	data[40], data[41] = 0x30, 0x39                      // src port 12345 (BE)
	data[42], data[43] = 0x01, 0xbb                      // dst port 443 (BE)
	data[52] = eventTypePolicyDeny
	data[53] = 6 // TCP
	data[54] = actionDeny
	data[55] = addrFamilyInet
	copy(data[8:12], net.ParseIP("192.0.2.10").To4())
	copy(data[24:28], net.ParseIP("198.51.100.20").To4())

	rec, ok := DecodeRawEventRecord(data)
	if !ok {
		t.Fatal("DecodeRawEventRecord rejected a valid POLICY_DENY frame")
	}
	if !rec.Time.Equal(time.Unix(0, int64(decisionNS))) {
		t.Fatalf("rec.Time = %v, want decision time %v (offset 0 LE u64); the "+
			"decoder must prefer the on-wire decision timestamp over receive time",
			rec.Time, time.Unix(0, int64(decisionNS)))
	}
}

// TestDecodeRawEventZeroTimestampFallsBackToReceiveTime pins the OTHER half of
// the #2470 contract: a frame with timestamp_ns == 0 (an old/unstamped emitter
// or a clock-read failure on the helper) still falls back to receive time
// (time.Now()), so the event is never logged at the Unix epoch.
func TestDecodeRawEventZeroTimestampFallsBackToReceiveTime(t *testing.T) {
	data := make([]byte, rawEventWireSize)
	// offset 0 left as 0 — no decision timestamp.
	data[40], data[41] = 0x30, 0x39
	data[42], data[43] = 0x01, 0xbb
	data[52] = eventTypePolicyDeny
	data[53] = 6
	data[54] = actionDeny
	data[55] = addrFamilyInet
	copy(data[8:12], net.ParseIP("192.0.2.10").To4())
	copy(data[24:28], net.ParseIP("198.51.100.20").To4())

	before := time.Now()
	rec, ok := DecodeRawEventRecord(data)
	after := time.Now()
	if !ok {
		t.Fatal("DecodeRawEventRecord rejected a valid POLICY_DENY frame")
	}
	if rec.Time.Before(before) || rec.Time.After(after) {
		t.Fatalf("rec.Time = %v, want receive time in [%v, %v] for a zero "+
			"on-wire timestamp", rec.Time, before, after)
	}
}

func TestProcessRawEventRejectsShortRecord(t *testing.T) {
	tests := []struct {
		name      string
		data      []byte
		wantOK    bool
		wantCount int
	}{
		{name: "nil", data: nil, wantOK: false, wantCount: 0},
		{name: "empty", data: []byte{}, wantOK: false, wantCount: 0},
		{name: "short", data: make([]byte, rawEventWireSize-1), wantOK: false, wantCount: 0},
		{name: "exact", data: minimallyValidRawEventData(), wantOK: true, wantCount: 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			buffer := NewEventBuffer(4)
			reader := NewEventReader(nil, buffer)
			if ok := reader.ProcessRawEvent(tt.data); ok != tt.wantOK {
				t.Fatalf("ProcessRawEvent(%s) ok = %v, want %v", tt.name, ok, tt.wantOK)
			}
			if got := len(buffer.Latest(4)); got != tt.wantCount {
				t.Fatalf("buffer count = %d, want %d", got, tt.wantCount)
			}
		})
	}
}

func TestFormatBinaryRecord_SessionClose(t *testing.T) {
	evt := &rawEvent{
		EventType:   eventTypeSessionClose,
		Protocol:    6,
		Action:      actionPermit,
		AddrFamily:  addrFamilyInet,
		SrcPort:     54321,
		DstPort:     80,
		PolicyID:    10,
		IngressZone: 3,
		EgressZone:  4,
	}
	copy(evt.SrcIP[:4], net.ParseIP("192.168.1.100").To4())
	copy(evt.DstIP[:4], net.ParseIP("10.0.2.50").To4())

	rec := &EventRecord{
		Time:            time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC),
		SessionPkts:     1000,
		SessionBytes:    500000,
		RevSessionPkts:  800,
		RevSessionBytes: 400000,
		ElapsedTime:     120,
		SessionID:       42,
		InZoneName:      "lan",
		OutZoneName:     "wan",
		PolicyName:      "default-permit",
		AppName:         "junos-http",
		IngressIface:    "trust0",
	}

	buf := formatBinaryRecord(evt, rec, SyslogInfo, closeReasonTCPFIN)

	// Verify session stats
	pkts := binary.LittleEndian.Uint64(buf[98:106])
	bytes := binary.LittleEndian.Uint64(buf[106:114])
	if pkts != 1000 {
		t.Errorf("session pkts = %d, want 1000", pkts)
	}
	if bytes != 500000 {
		t.Errorf("session bytes = %d, want 500000", bytes)
	}

	revPkts := binary.LittleEndian.Uint64(buf[114:122])
	revBytes := binary.LittleEndian.Uint64(buf[122:130])
	if revPkts != 800 {
		t.Errorf("rev session pkts = %d, want 800", revPkts)
	}
	if revBytes != 400000 {
		t.Errorf("rev session bytes = %d, want 400000", revBytes)
	}

	elapsed := binary.LittleEndian.Uint32(buf[130:134])
	if elapsed != 120 {
		t.Errorf("elapsed = %d, want 120", elapsed)
	}

	// Verify close reason
	if buf[142] != closeReasonTCPFIN {
		t.Errorf("close reason = %d, want %d", buf[142], closeReasonTCPFIN)
	}

	// Verify ingress iface in variable section
	off := binaryLogHeaderSize
	_, off = readLenStr(buf, off) // inZone
	_, off = readLenStr(buf, off) // outZone
	_, off = readLenStr(buf, off) // policyName
	_, off = readLenStr(buf, off) // appName
	ifName, _ := readLenStr(buf, off)
	if ifName != "trust0" {
		t.Errorf("iface = %q, want %q", ifName, "trust0")
	}
}

func TestFormatBinaryRecord_IPv6(t *testing.T) {
	evt := &rawEvent{
		EventType:   eventTypeSessionOpen,
		Protocol:    6,
		Action:      actionPermit,
		AddrFamily:  addrFamilyInet6,
		SrcPort:     8080,
		DstPort:     443,
		IngressZone: 1,
		EgressZone:  2,
	}
	srcV6 := net.ParseIP("2001:db8::1")
	dstV6 := net.ParseIP("2001:db8::2")
	copy(evt.SrcIP[:], srcV6.To16())
	copy(evt.DstIP[:], dstV6.To16())

	rec := &EventRecord{
		Time:        time.Now(),
		InZoneName:  "trust",
		OutZoneName: "untrust",
		SessionID:   7,
	}

	buf := formatBinaryRecord(evt, rec, SyslogInfo, 0)

	// Verify IPv6 addresses
	if buf[8] != addrFamilyInet6 {
		t.Errorf("addr family = %d, want %d", buf[8], addrFamilyInet6)
	}
	gotSrc := net.IP(buf[18:34])
	if !gotSrc.Equal(srcV6) {
		t.Errorf("src IPv6 = %s, want %s", gotSrc, srcV6)
	}
	gotDst := net.IP(buf[34:50])
	if !gotDst.Equal(dstV6) {
		t.Errorf("dst IPv6 = %s, want %s", gotDst, dstV6)
	}
}

func TestFormatBinaryRecord_EmptyStrings(t *testing.T) {
	evt := &rawEvent{
		EventType: eventTypePolicyDeny,
		Protocol:  17,
		Action:    actionDeny,
	}
	rec := &EventRecord{
		Time:      time.Now(),
		SessionID: 1,
	}

	buf := formatBinaryRecord(evt, rec, SyslogWarning, 0)

	// All 5 variable strings should be zero-length
	off := binaryLogHeaderSize
	for i := 0; i < 5; i++ {
		if buf[off] != 0 {
			t.Errorf("string %d length = %d, want 0", i, buf[off])
		}
		off++
	}
	// Total record should be header + 5 zero-length bytes
	if len(buf) != binaryLogHeaderSize+5 {
		t.Errorf("buf len = %d, want %d", len(buf), binaryLogHeaderSize+5)
	}
}

func TestFormatBinaryRecord_SelfFraming(t *testing.T) {
	// Verify the record length field matches actual data — needed for TCP stream parsing
	evt := &rawEvent{
		EventType:   eventTypeSessionOpen,
		Protocol:    6,
		IngressZone: 1,
	}
	rec := &EventRecord{
		Time:         time.Now(),
		InZoneName:   "very-long-zone-name-for-testing",
		OutZoneName:  "another-zone",
		PolicyName:   "my-policy",
		AppName:      "custom-app",
		IngressIface: "ge-0/0/0",
		SessionID:    99,
	}

	buf := formatBinaryRecord(evt, rec, SyslogInfo, 0)

	// Read total length from header
	totalLen := binary.BigEndian.Uint16(buf[3:5])
	if int(totalLen) != len(buf) {
		t.Errorf("header length %d != buf length %d", totalLen, len(buf))
	}

	// Simulate TCP stream: concatenate 3 records and parse them back
	stream := make([]byte, 0, len(buf)*3)
	for i := 0; i < 3; i++ {
		stream = append(stream, buf...)
	}

	// Parse records from stream
	off := 0
	count := 0
	for off < len(stream) {
		if off+5 > len(stream) {
			t.Fatal("truncated header in stream")
		}
		magic := uint16(stream[off])<<8 | uint16(stream[off+1])
		if magic != 0xBF52 {
			t.Fatalf("bad magic at offset %d: 0x%04x", off, magic)
		}
		recLen := int(binary.BigEndian.Uint16(stream[off+3 : off+5]))
		if off+recLen > len(stream) {
			t.Fatalf("truncated record at offset %d: need %d, have %d", off, recLen, len(stream)-off)
		}
		off += recLen
		count++
	}
	if count != 3 {
		t.Errorf("parsed %d records from stream, want 3", count)
	}
}

func TestSyslogSendBinary_UDP(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()

	addr := pc.LocalAddr().(*net.UDPAddr)
	client, err := NewSyslogClient("127.0.0.1", addr.Port)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	// Create a minimal binary record
	evt := &rawEvent{
		EventType: eventTypeSessionOpen,
		Protocol:  6,
	}
	rec := &EventRecord{
		Time:       time.Now(),
		InZoneName: "test",
		SessionID:  1,
	}
	binData := formatBinaryRecord(evt, rec, SyslogInfo, 0)

	if err := client.SendBinary(binData); err != nil {
		t.Fatal(err)
	}

	// Read the UDP packet
	rxBuf := make([]byte, 4096)
	pc.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, _, err := pc.ReadFrom(rxBuf)
	if err != nil {
		t.Fatal(err)
	}

	// Should be exact binary data (no syslog header)
	if n != len(binData) {
		t.Errorf("received %d bytes, sent %d", n, len(binData))
	}
	if rxBuf[0] != binaryLogMagicHi || rxBuf[1] != binaryLogMagicLo {
		t.Errorf("magic mismatch in received data: 0x%02x%02x", rxBuf[0], rxBuf[1])
	}
}

func TestSyslogSendBinary_TCP(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	addr := ln.Addr().(*net.TCPAddr)

	// Accept and read in background
	dataCh := make(chan []byte, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		buf := make([]byte, 4096)
		n, _ := conn.Read(buf)
		dataCh <- buf[:n]
	}()

	client, err := NewSyslogClientTransport("127.0.0.1", addr.Port, "", "tcp", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	evt := &rawEvent{
		EventType: eventTypeSessionOpen,
		Protocol:  17,
	}
	rec := &EventRecord{
		Time:       time.Now(),
		InZoneName: "trust",
		SessionID:  5,
	}
	binData := formatBinaryRecord(evt, rec, SyslogInfo, 0)

	if err := client.SendBinary(binData); err != nil {
		t.Fatal(err)
	}

	select {
	case data := <-dataCh:
		// Binary records are sent raw (self-framing via length at [3:5])
		if len(data) != len(binData) {
			t.Errorf("received %d bytes, sent %d", len(data), len(binData))
		}
		if data[0] != binaryLogMagicHi || data[1] != binaryLogMagicLo {
			t.Errorf("magic mismatch: 0x%02x%02x", data[0], data[1])
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for TCP data")
	}
}

func TestLocalLogWriterSendBinary(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.binlog")

	lw, err := NewLocalLogWriter(LocalLogConfig{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	defer lw.Close()

	evt := &rawEvent{
		EventType:   eventTypeSessionClose,
		Protocol:    6,
		Action:      actionPermit,
		IngressZone: 1,
		EgressZone:  2,
	}
	rec := &EventRecord{
		Time:         time.Now(),
		SessionPkts:  50,
		SessionBytes: 25000,
		InZoneName:   "trust",
		OutZoneName:  "untrust",
		PolicyName:   "web-access",
		SessionID:    10,
	}

	binData := formatBinaryRecord(evt, rec, SyslogInfo, closeReasonTimeout)

	if err := lw.SendBinary(binData); err != nil {
		t.Fatal(err)
	}
	lw.Close()

	// Read back and verify
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(content) != len(binData) {
		t.Errorf("file size = %d, want %d", len(content), len(binData))
	}
	if content[0] != binaryLogMagicHi || content[1] != binaryLogMagicLo {
		t.Errorf("magic in file: 0x%02x%02x", content[0], content[1])
	}

	// Verify we can parse the record length from file
	recLen := binary.BigEndian.Uint16(content[3:5])
	if int(recLen) != len(content) {
		t.Errorf("record length in file = %d, file size = %d", recLen, len(content))
	}
}

func TestLocalLogWriterSendBinary_Rotation(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.binlog")

	lw, err := NewLocalLogWriter(LocalLogConfig{
		Path:     path,
		MaxSize:  500, // tiny size to trigger rotation
		MaxFiles: 2,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer lw.Close()

	evt := &rawEvent{EventType: eventTypeSessionOpen}
	rec := &EventRecord{Time: time.Now(), SessionID: 1}
	binData := formatBinaryRecord(evt, rec, SyslogInfo, 0)

	// Write enough records to trigger rotation
	for i := 0; i < 10; i++ {
		if err := lw.SendBinary(binData); err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
	}

	// Verify rotated file exists
	if _, err := os.Stat(path + ".1"); err != nil {
		t.Error("expected rotated file .1 to exist")
	}
}

func TestTruncStr(t *testing.T) {
	if got := truncStr("hello", 255); got != "hello" {
		t.Errorf("short string: got %q", got)
	}
	long := make([]byte, 300)
	for i := range long {
		long[i] = 'a'
	}
	if got := truncStr(string(long), 255); len(got) != 255 {
		t.Errorf("long string: got len %d, want 255", len(got))
	}
}

// readLenStr reads a length-prefixed string from buf at offset.
func readLenStr(buf []byte, off int) (string, int) {
	if off >= len(buf) {
		return "", off
	}
	n := int(buf[off])
	off++
	if off+n > len(buf) {
		return "", off
	}
	s := string(buf[off : off+n])
	return s, off + n
}
