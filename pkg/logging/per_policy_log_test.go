package logging

import (
	"net"
	"testing"
)

// #2508: the userspace-dp SESSION_CREATE / SESSION_CLOSE raw frames carry a
// per-policy "should-log-to-syslog" gate in the final payload byte (offset
// 135). When the gate is clear the human-facing log consumers (security-log
// buffer, slog, syslog clients, local writers) must NOT emit a per-policy
// RT_FLOW record — but the registered callbacks (the global NetFlow/IPFIX
// session-close exporter, #2460) must STILL run for every close.
//
// These are fail-on-revert tests: if the gate parse, the early return, or the
// callback ordering is reverted, one of the assertions below fails.

func rawSessionFrame(eventType uint8, logGate byte) []byte {
	data := make([]byte, rawEventWireSize)
	data[40] = 0x30 // src port 12345
	data[41] = 0x39
	data[42] = 0x01 // dst port 443
	data[43] = 0xbb
	data[52] = eventType
	data[53] = 6 // TCP
	data[55] = addrFamilyInet
	copy(data[8:12], net.ParseIP("10.0.1.1").To4())
	copy(data[24:28], net.ParseIP("10.0.2.1").To4())
	data[rawEventLogSyslogOffset] = logGate
	return data
}

// newGatedReader wires an EventReader with a buffer (the human-facing
// security-log proxy, gated by the per-policy bit) and a callback recorder
// (the flowexport proxy, which must always run).
func newGatedReader(t *testing.T) (*EventReader, *EventBuffer, *int) {
	t.Helper()
	buffer := NewEventBuffer(16)
	reader := NewEventReader(nil, buffer)
	callbackCount := new(int)
	reader.AddCallback(func(rec EventRecord, raw []byte) {
		*callbackCount++
	})
	return reader, buffer, callbackCount
}

func TestPerPolicyLogGate_CloseSuppressedWhenFlagUnset(t *testing.T) {
	reader, buffer, cbCount := newGatedReader(t)

	if ok := reader.ProcessRawEvent(rawSessionFrame(eventTypeSessionClose, 0)); !ok {
		t.Fatalf("ProcessRawEvent returned false")
	}

	// Human-facing log (buffer) MUST be suppressed: no `then log session-close`.
	if got := len(buffer.Latest(16)); got != 0 {
		t.Fatalf("close with gate=0: buffer count = %d, want 0 (per-policy SYSLOG record must be suppressed)", got)
	}
	// flowexport callback MUST still fire on every close (#2460 no regression).
	if *cbCount != 1 {
		t.Fatalf("close with gate=0: callback count = %d, want 1 (flowexport must observe every close)", *cbCount)
	}
}

func TestPerPolicyLogGate_CloseLoggedWhenFlagSet(t *testing.T) {
	reader, buffer, cbCount := newGatedReader(t)

	if ok := reader.ProcessRawEvent(rawSessionFrame(eventTypeSessionClose, 1)); !ok {
		t.Fatalf("ProcessRawEvent returned false")
	}

	if got := len(buffer.Latest(16)); got != 1 {
		t.Fatalf("close with gate=1: buffer count = %d, want 1 (per-policy SYSLOG record must be emitted)", got)
	}
	if *cbCount != 1 {
		t.Fatalf("close with gate=1: callback count = %d, want 1", *cbCount)
	}
	rec := buffer.Latest(16)[0]
	if rec.Type != "SESSION_CLOSE" {
		t.Fatalf("close record Type = %q, want SESSION_CLOSE", rec.Type)
	}
}

func TestPerPolicyLogGate_OpenSuppressedWhenFlagUnset(t *testing.T) {
	// Since #15946 the helper emits a SESSION_CREATE for every fresh
	// admission, including flowexport-only opens with the gate clear;
	// those must never reach the human-facing log path.
	reader, buffer, cbCount := newGatedReader(t)

	if ok := reader.ProcessRawEvent(rawSessionFrame(eventTypeSessionOpen, 0)); !ok {
		t.Fatalf("ProcessRawEvent returned false")
	}

	if got := len(buffer.Latest(16)); got != 0 {
		t.Fatalf("open with gate=0: buffer count = %d, want 0 (per-policy SYSLOG record must be suppressed)", got)
	}
	// Flowexport consumes opens (#15946 tracker/sampling) via the
	// type-agnostic callback fan-out, so it still fires; the
	// human-facing suppression is the behavior under test.
	if *cbCount != 1 {
		t.Fatalf("open with gate=0: callback count = %d, want 1", *cbCount)
	}
}

// nopEventSource is a non-nil EventSource that never yields events. It exists
// solely to construct an EventReader whose `source != nil`, exercising the
// source-based (kernel/ring-buffer) reader path.
type nopEventSource struct{}

func (nopEventSource) ReadEvent() ([]byte, error) { return nil, nil }
func (nopEventSource) Close() error               { return nil }

// TestPerPolicyLogGate_SourceReaderNotGated is the #2508 over-suppression
// fail-on-revert guard. The per-policy SYSLOG gate must apply ONLY to the
// userspace-dp event-stream path (er.source == nil), the only producer that
// sets the per-policy log bit. A source-based EventReader (er.source != nil,
// created at pkg/daemon/daemon_run.go) feeds SESSION events whose gate byte is
// 0 by default; those events MUST still be logged. Removing the
// `er.source == nil` guard from the gate makes these events wrongly suppressed
// and this test fails.
func TestPerPolicyLogGate_SourceReaderNotGated(t *testing.T) {
	for _, et := range []struct {
		name string
		typ  uint8
	}{
		{"SESSION_CLOSE", eventTypeSessionClose},
		{"SESSION_OPEN", eventTypeSessionOpen},
	} {
		t.Run(et.name, func(t *testing.T) {
			buffer := NewEventBuffer(16)
			// source != nil: the gate must not fire for this reader.
			reader := NewEventReader(nopEventSource{}, buffer)

			// gate byte 0 (a source-based event never sets the per-policy bit).
			if ok := reader.ProcessRawEvent(rawSessionFrame(et.typ, 0)); !ok {
				t.Fatalf("ProcessRawEvent returned false")
			}
			if got := len(buffer.Latest(16)); got != 1 {
				t.Fatalf("source-based %s with gate=0: buffer count = %d, want 1 "+
					"(source readers must never be gated by the per-policy bit)", et.name, got)
			}
		})
	}
}

func TestPerPolicyLogGate_OpenLoggedWhenFlagSet(t *testing.T) {
	reader, buffer, _ := newGatedReader(t)

	if ok := reader.ProcessRawEvent(rawSessionFrame(eventTypeSessionOpen, 1)); !ok {
		t.Fatalf("ProcessRawEvent returned false")
	}

	recs := buffer.Latest(16)
	if len(recs) != 1 {
		t.Fatalf("open with gate=1: buffer count = %d, want 1 (RT_FLOW_SESSION_CREATE must be emitted)", len(recs))
	}
	if recs[0].Type != "SESSION_OPEN" {
		t.Fatalf("open record Type = %q, want SESSION_OPEN (renders as RT_FLOW_SESSION_CREATE)", recs[0].Type)
	}
}

// TestPerPolicyLogGate_Matrix is the consolidated init/close-flag matrix
// requested in #2508: no-flags -> no create/close record; init-only -> create
// only; close-only -> close only; both -> both. Each policy emits independent
// create and close frames (the dataplane gates each frame on its own flag), so
// the matrix is expressed as the union of the per-frame gate decisions.
func TestPerPolicyLogGate_Matrix(t *testing.T) {
	cases := []struct {
		name      string
		initFlag  byte
		closeFlag byte
		wantOpen  bool
		wantClose bool
	}{
		{"no-flags", 0, 0, false, false},
		{"init-only", 1, 0, true, false},
		{"close-only", 0, 1, false, true},
		{"both", 1, 1, true, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			reader, buffer, _ := newGatedReader(t)

			// Since #15946 the helper always emits the create frame on a
			// fresh admission (gate byte = init flag) and always emits
			// the close frame (gate byte = close flag); the Go side gates
			// the human-facing record on each frame's own flag, so feed
			// both frames unconditionally.
			if ok := reader.ProcessRawEvent(rawSessionFrame(eventTypeSessionOpen, tc.initFlag)); !ok {
				t.Fatalf("ProcessRawEvent(open) returned false")
			}
			if ok := reader.ProcessRawEvent(rawSessionFrame(eventTypeSessionClose, tc.closeFlag)); !ok {
				t.Fatalf("ProcessRawEvent(close) returned false")
			}

			var sawOpen, sawClose bool
			for _, rec := range buffer.Latest(16) {
				switch rec.Type {
				case "SESSION_OPEN":
					sawOpen = true
				case "SESSION_CLOSE":
					sawClose = true
				}
			}
			if sawOpen != tc.wantOpen {
				t.Errorf("%s: SESSION_CREATE logged = %v, want %v", tc.name, sawOpen, tc.wantOpen)
			}
			if sawClose != tc.wantClose {
				t.Errorf("%s: SESSION_CLOSE logged = %v, want %v", tc.name, sawClose, tc.wantClose)
			}
		})
	}
}
