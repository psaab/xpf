package flowexport

import (
	"encoding/binary"
	"net"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/logging"
)

// #2465: flowStartTime uses the real session-creation timestamp (rec.Created,
// absolute Unix seconds) when it is present.
func TestFlowStartTimeUsesRealCreated(t *testing.T) {
	end := time.Unix(1_700_000_300, 0) // close time
	created := uint32(1_700_000_000)   // 300s earlier

	rec := logging.EventRecord{
		Time:        end,
		Created:     created,
		SessionPkts: 9,
		Protocol:    "TCP",
	}

	start, missingCreated := flowStartTime(rec)
	if missingCreated {
		t.Fatal("a real created timestamp must not be reported missing")
	}
	if !start.Equal(time.Unix(int64(created), 0)) {
		t.Fatalf("StartTime = %v, want %v (the real created stamp)", start, time.Unix(int64(created), 0))
	}
}

// #11699: without a creation stamp, packet counts cannot establish flow age.
// Export the close time (zero duration) and report the missing stamp.
func TestFlowStartTimeWithoutCreationStampUsesEndTime(t *testing.T) {
	end := time.Unix(1_700_000_300, 0)
	rec := logging.EventRecord{
		Time:        end,
		Created:     0,
		SessionPkts: ^uint64(0),
		Protocol:    "TCP",
	}
	start, missingCreated := flowStartTime(rec)
	if !missingCreated {
		t.Fatal("a zero created timestamp must be reported missing")
	}
	if !start.Equal(end) {
		t.Fatalf("StartTime = %v, want close time %v for a zero-duration record", start, end)
	}
}

// #2465: a created stamp at or after the close time (clock skew) clamps to the
// EndTime so the flow never reports a negative duration.
func TestFlowStartTimeClampsFutureCreated(t *testing.T) {
	end := time.Unix(1_700_000_000, 0)
	rec := logging.EventRecord{
		Time:    end,
		Created: 1_700_000_500, // 500s AFTER the close — impossible, clamp
	}
	start, missingCreated := flowStartTime(rec)
	if missingCreated {
		t.Fatal("a non-zero created timestamp must not be reported missing")
	}
	if !start.Equal(end) {
		t.Fatalf("StartTime = %v, want clamp to EndTime %v", start, end)
	}
}

// #2465 fail-on-revert (NetFlow v9): a close with a real creation stamp keeps
// its measured StartTime and does not bump the EstimatedDurations counter.
func TestNetFlowExportSessionCloseUsesRealCreated(t *testing.T) {
	e, err := NewExporter(&ExportConfig{})
	if err != nil {
		t.Fatalf("NewExporter: %v", err)
	}
	end := time.Unix(1_700_000_600, 0)
	created := uint32(1_700_000_000)
	rec := logging.EventRecord{
		Time:        end,
		Type:        "SESSION_CLOSE",
		Created:     created,
		SessionPkts: 4,
		Protocol:    "TCP",
	}
	evt := SessionCloseData{
		SrcIP:    net.ParseIP("10.0.1.102"),
		DstIP:    net.ParseIP("172.16.80.200"),
		SrcPort:  12345,
		DstPort:  443,
		Protocol: 6,
	}
	e.ExportSessionClose(rec, evt)

	v4, _ := e.batch.drain()
	if len(v4) != 1 {
		t.Fatalf("expected 1 batched flow, got %d", len(v4))
	}
	if !v4[0].StartTime.Equal(time.Unix(int64(created), 0)) {
		t.Fatalf("StartTime = %v, want real created %v", v4[0].StartTime, time.Unix(int64(created), 0))
	}
	if !v4[0].EndTime.Equal(end) {
		t.Fatalf("EndTime = %v, want %v", v4[0].EndTime, end)
	}
	if got := e.EstimatedDurations(); got != 0 {
		t.Fatalf("EstimatedDurations = %d, want 0 (a real created ts was used)", got)
	}
}

// #11699 (NetFlow v9): synthesized closes without Created are emitted with
// StartTime=EndTime, while retaining the missing-timestamp counter.
func TestNetFlowExportSessionCloseFallbackBumpsCounter(t *testing.T) {
	e, err := NewExporter(&ExportConfig{})
	if err != nil {
		t.Fatalf("NewExporter: %v", err)
	}
	end := time.Unix(1_700_000_600, 0)
	rec := logging.EventRecord{
		Time:        end,
		Type:        "SESSION_CLOSE",
		Created:     0,
		SessionPkts: 4,
		Protocol:    "TCP",
	}
	evt := SessionCloseData{SrcIP: net.ParseIP("10.0.1.102"), DstIP: net.ParseIP("172.16.80.200"), Protocol: 6}
	e.ExportSessionClose(rec, evt)

	v4, _ := e.batch.drain()
	if len(v4) != 1 {
		t.Fatalf("expected 1 batched flow, got %d", len(v4))
	}
	if !v4[0].StartTime.Equal(end) {
		t.Fatalf("StartTime = %v, want close time %v for zero duration", v4[0].StartTime, end)
	}
	if !v4[0].EndTime.Equal(end) {
		t.Fatalf("EndTime = %v, want %v", v4[0].EndTime, end)
	}
	if got := e.EstimatedDurations(); got != 1 {
		t.Fatalf("EstimatedDurations = %d, want 1 (missing Created)", got)
	}
}

// #2465 fail-on-revert (IPFIX): same contract as the NetFlow v9 test.
func TestIPFIXExportSessionCloseUsesRealCreated(t *testing.T) {
	e, err := NewIPFIXExporter(&ExportConfig{})
	if err != nil {
		t.Fatalf("NewIPFIXExporter: %v", err)
	}
	end := time.Unix(1_700_000_600, 0)
	created := uint32(1_700_000_100)
	rec := logging.EventRecord{
		Time:        end,
		Type:        "SESSION_CLOSE",
		Created:     created,
		SessionPkts: 4,
		Protocol:    "TCP",
	}
	evt := SessionCloseData{SrcIP: net.ParseIP("10.0.1.102"), DstIP: net.ParseIP("172.16.80.200"), Protocol: 6}
	e.ExportSessionClose(rec, evt)

	v4, _ := e.batch.drain()
	if len(v4) != 1 {
		t.Fatalf("expected 1 batched flow, got %d", len(v4))
	}
	if !v4[0].StartTime.Equal(time.Unix(int64(created), 0)) {
		t.Fatalf("StartTime = %v, want real created %v", v4[0].StartTime, time.Unix(int64(created), 0))
	}
	if got := e.EstimatedDurations(); got != 0 {
		t.Fatalf("EstimatedDurations = %d, want 0", got)
	}
}

// #2853 fail-on-revert: two flows created within the SAME integer second but at
// distinct sub-second offsets must keep distinct StartTimes (millisecond
// resolution) in the flow record. Before #2853 the dataplane stamped only the
// truncated second, so both flows collapsed onto the same StartTime; this test
// goes RED if flowStartTime is reverted to time.Unix(int64(rec.Created), 0)
// (i.e. drops rec.CreatedNanos).
func TestFlowStartTimeKeepsSubSecondResolution(t *testing.T) {
	end := time.Unix(1_700_000_300, 0)
	sec := uint32(1_700_000_000)

	// Two short flows opened ~600ms apart inside the same wall-clock second.
	recEarly := logging.EventRecord{
		Time: end, Type: "SESSION_CLOSE", Protocol: "UDP",
		Created: sec, CreatedNanos: 100_000_000, // .100s
	}
	recLate := logging.EventRecord{
		Time: end, Type: "SESSION_CLOSE", Protocol: "UDP",
		Created: sec, CreatedNanos: 700_000_000, // .700s
	}

	startEarly, missingEarly := flowStartTime(recEarly)
	startLate, missingLate := flowStartTime(recLate)
	if missingEarly || missingLate {
		t.Fatal("a real created timestamp must not be reported missing")
	}
	if startEarly.Equal(startLate) {
		t.Fatalf("same-second flows must have DISTINCT sub-second StartTimes; both = %v (sub-second truncated?)", startEarly)
	}
	// Exact instants — proves the nanos are combined, not discarded.
	if want := time.Unix(int64(sec), 100_000_000); !startEarly.Equal(want) {
		t.Fatalf("early StartTime = %v, want %v", startEarly, want)
	}
	if want := time.Unix(int64(sec), 700_000_000); !startLate.Equal(want) {
		t.Fatalf("late StartTime = %v, want %v", startLate, want)
	}
	// Millisecond delta survives — this is what IPFIX flowStartMilliseconds /
	// NetFlow uptimeMs render from StartTime.
	if d := startLate.Sub(startEarly); d != 600*time.Millisecond {
		t.Fatalf("sub-second delta = %v, want 600ms", d)
	}
}

// #2853 fail-on-revert (IPFIX end-to-end): two SESSION_CLOSE events in the same
// second but at distinct sub-second offsets must produce flow records whose
// exported flowStartMilliseconds differ. Reverting the dataplane stamp or
// flowStartTime to whole-second resolution makes both UnixMilli() collapse to
// sec*1000 and this assertion fails.
func TestIPFIXExportSessionCloseSubSecondStart(t *testing.T) {
	e, err := NewIPFIXExporter(&ExportConfig{})
	if err != nil {
		t.Fatalf("NewIPFIXExporter: %v", err)
	}
	end := time.Unix(1_700_000_600, 0)
	sec := uint32(1_700_000_100)
	evt := SessionCloseData{SrcIP: net.ParseIP("10.0.1.102"), DstIP: net.ParseIP("172.16.80.200"), Protocol: 6}

	e.ExportSessionClose(logging.EventRecord{
		Time: end, Type: "SESSION_CLOSE", Created: sec, CreatedNanos: 250_000_000, Protocol: "TCP",
	}, evt)
	e.ExportSessionClose(logging.EventRecord{
		Time: end, Type: "SESSION_CLOSE", Created: sec, CreatedNanos: 850_000_000, Protocol: "TCP",
	}, evt)

	v4, _ := e.batch.drain()
	if len(v4) != 2 {
		t.Fatalf("expected 2 batched flows, got %d", len(v4))
	}
	got := map[int64]bool{
		v4[0].StartTime.UnixMilli(): true,
		v4[1].StartTime.UnixMilli(): true,
	}
	if len(got) != 2 {
		t.Fatalf("same-second flows produced identical flowStartMilliseconds (sub-second truncated?): %v", got)
	}
	wantA := int64(sec)*1000 + 250
	wantB := int64(sec)*1000 + 850
	if !got[wantA] || !got[wantB] {
		t.Fatalf("flowStartMilliseconds = %v, want {%d, %d}", got, wantA, wantB)
	}
}

// #11699 (IPFIX): synthesized closes without Created are emitted with
// StartTime=EndTime, while retaining the missing-timestamp counter.
func TestIPFIXExportSessionCloseFallbackBumpsCounter(t *testing.T) {
	e, err := NewIPFIXExporter(&ExportConfig{})
	if err != nil {
		t.Fatalf("NewIPFIXExporter: %v", err)
	}
	end := time.Unix(1_700_000_600, 0)
	rec := logging.EventRecord{Time: end, Type: "SESSION_CLOSE", Created: 0, SessionPkts: 4, Protocol: "TCP"}
	evt := SessionCloseData{SrcIP: net.ParseIP("10.0.1.102"), DstIP: net.ParseIP("172.16.80.200"), Protocol: 6}
	e.ExportSessionClose(rec, evt)

	v4, _ := e.batch.drain()
	if len(v4) != 1 {
		t.Fatalf("expected 1 batched flow, got %d", len(v4))
	}
	if !v4[0].StartTime.Equal(end) || !v4[0].EndTime.Equal(end) {
		t.Fatalf("flow times = (%v, %v), want zero duration at %v", v4[0].StartTime, v4[0].EndTime, end)
	}
	if got := e.EstimatedDurations(); got != 1 {
		t.Fatalf("EstimatedDurations = %d, want 1 (missing Created)", got)
	}
}

// #11699: synthesized closes with no Created stamp must encode a zero-duration
// wire record for both address families and exporters, without changing counters.
func TestSynthesizedCloseWireTimestampsPreserveCounters(t *testing.T) {
	const packets uint64 = 0x0102030405060708
	const octets uint64 = 0x8877665544332211
	end := time.Unix(1_700_000_600, 123_000_000)
	boot := end.Add(-time.Hour)

	// These offsets are from the encoded record after its 4-byte set header.
	// IPFIX's 8-byte timestamps place EndTime four bytes after the v9 offset.
	families := []struct {
		name                       string
		isIPv6                     bool
		src, dst                   string
		packetsOffset, bytesOffset int
		startOffset, endOffset     int
	}{
		{
			name: "IPv4", src: "10.0.1.102", dst: "172.16.80.200",
			packetsOffset: 13, bytesOffset: 21, startOffset: 29, endOffset: 33,
		},
		{
			name: "IPv6", isIPv6: true, src: "2001:db8::1", dst: "2001:db8::2",
			packetsOffset: 37, bytesOffset: 45, startOffset: 53, endOffset: 57,
		},
	}
	for _, family := range families {
		family := family
		for _, ipfix := range []bool{false, true} {
			ipfix := ipfix
			format := "NetFlow v9"
			timeWidth := 4
			if ipfix {
				format = "IPFIX"
				timeWidth = 8
			}
			t.Run(format+"/"+family.name, func(t *testing.T) {
				rec := logging.EventRecord{
					Time:         end,
					Type:         "SESSION_CLOSE",
					SessionPkts:  packets,
					SessionBytes: octets,
					Protocol:     "TCP",
					ProtocolNum:  6,
				}
				evt := SessionCloseData{
					SrcIP:    net.ParseIP(family.src),
					DstIP:    net.ParseIP(family.dst),
					Protocol: 6,
					IsIPv6:   family.isIPv6,
				}

				var records []FlowRecord
				var wireSet []byte
				var estimatedDurations uint64
				if ipfix {
					e, err := NewIPFIXExporter(&ExportConfig{})
					if err != nil {
						t.Fatalf("NewIPFIXExporter: %v", err)
					}
					e.ExportSessionClose(rec, evt)
					v4, v6 := e.batch.drain()
					records = v4
					if family.isIPv6 {
						records = v6
					}
					wireSet = encodeIPFIXDataSetDir(records, false)
					estimatedDurations = e.EstimatedDurations()
				} else {
					e, err := NewExporter(&ExportConfig{})
					if err != nil {
						t.Fatalf("NewExporter: %v", err)
					}
					e.ExportSessionClose(rec, evt)
					v4, v6 := e.batch.drain()
					records = v4
					if family.isIPv6 {
						records = v6
					}
					wireSet = encodeDataFlowSet(records, boot, V9TemplateOptions{})
					estimatedDurations = e.EstimatedDurations()
				}
				if len(records) != 1 {
					t.Fatalf("expected 1 batched flow, got %d", len(records))
				}
				if estimatedDurations != 1 {
					t.Fatalf("EstimatedDurations = %d, want 1", estimatedDurations)
				}
				wireRecord := wireSet[4:]
				if got := binary.BigEndian.Uint64(wireRecord[family.packetsOffset : family.packetsOffset+8]); got != packets {
					t.Fatalf("wire packet counter = %#x, want %#x", got, packets)
				}
				if got := binary.BigEndian.Uint64(wireRecord[family.bytesOffset : family.bytesOffset+8]); got != octets {
					t.Fatalf("wire byte counter = %#x, want %#x", got, octets)
				}
				endOffset := family.endOffset
				// IPFIX time fields are 8-byte Unix milliseconds; v9 uses 4-byte uptime.
				if timeWidth == 8 {
					endOffset += 4
				}
				var start, finish uint64
				if timeWidth == 4 {
					start = uint64(binary.BigEndian.Uint32(wireRecord[family.startOffset : family.startOffset+4]))
					finish = uint64(binary.BigEndian.Uint32(wireRecord[endOffset : endOffset+4]))
				} else {
					start = binary.BigEndian.Uint64(wireRecord[family.startOffset : family.startOffset+8])
					finish = binary.BigEndian.Uint64(wireRecord[endOffset : endOffset+8])
				}
				if start != finish {
					t.Fatalf("wire start/end times = (%d, %d), want equal fields for a missing creation stamp", start, finish)
				}
			})
		}
	}
}
