package logging

import (
	"encoding/binary"
	"net"
	"strings"
	"testing"
)

// #4914: residual of #4796. On a SESSION_CLOSE, logEvent zeroes evt.PolicyID
// (#2853 repurposes the [44:48] slot for the created-subsec-nanos) and only
// rec.PolicyID carries the admitting policy from the trailing [136:140] slot
// (#3056); the wire action byte is intentionally 0 for a close. Two sinks still
// misrepresented that close:
//
//   - the binary log record encoded evt.PolicyID (0) and evt.Action (0 ->
//     "deny"), so every binary session-close record read policy_id=0 +
//     action=deny;
//   - the generic slog "firewall event" close line still emitted
//     action=actionName(0) = "deny".
//
// This fixture drives one live extended-close frame through ProcessRawEvent and
// asserts parity across the buffer, callback, slog, standard, structured, and
// binary sinks: the admitting policy id shows everywhere and no sink reports a
// normal close as a deny.
//
// RED on revert of any of the three production changes:
//   - generic slog close branch re-adding `"action", actionStr` -> the slog
//     line contains action=deny (assertion below fails);
//   - formatBinaryRecord encoding evt.PolicyID -> binary policy_id = 0 (fails);
//   - formatBinaryRecord encoding evt.Action for a close -> binary action byte
//     = 0/actionDeny instead of actionNotApplicable (fails).
func TestSessionCloseParity_PolicyIDAndActionAcrossSinks(t *testing.T) {
	const (
		admittingPolicy = uint32(7777)
		policyName      = "allow-web"
		ingressZone     = uint16(1)
		egressZone      = uint16(2)
	)

	// Build a full extended (rawEventExtSize) SESSION_CLOSE frame.
	data := make([]byte, rawEventExtSize)
	binary.LittleEndian.PutUint64(data[0:8], 1_700_000_000_000_000_000) // decision ts (ns)
	copy(data[8:12], net.ParseIP("10.0.1.5").To4())
	copy(data[24:28], net.ParseIP("10.0.2.7").To4())
	binary.BigEndian.PutUint16(data[40:42], 12345) // src port
	binary.BigEndian.PutUint16(data[42:44], 443)   // dst port
	binary.LittleEndian.PutUint16(data[48:50], ingressZone)
	binary.LittleEndian.PutUint16(data[50:52], egressZone)
	data[52] = eventTypeSessionClose
	data[53] = 6          // TCP
	data[54] = actionDeny // wire action byte is intentionally 0 on a close
	data[55] = addrFamilyInet
	data[134] = closeReasonTCPFIN     // close reason code
	data[rawEventLogSyslogOffset] = 1 // #2508 per-policy gate: DO log this close
	binary.LittleEndian.PutUint32(data[rawEventPolicyCloseOffset:rawEventPolicyCloseOffset+4], admittingPolicy)

	buf := captureInfoLogs(t)

	reader := NewEventReader(nil, NewEventBuffer(16))
	reader.SetPolicyNames(map[uint32]string{admittingPolicy: policyName})
	reader.SetZoneNames(map[uint32]string{uint32(ingressZone): "trust", uint32(egressZone): "untrust"})

	var cbRec EventRecord
	var cbCalls int
	reader.AddCallback(func(rec EventRecord, _ []byte) {
		cbRec = rec
		cbCalls++
	})

	if ok := reader.ProcessRawEvent(data); !ok {
		t.Fatalf("ProcessRawEvent returned false")
	}

	// --- callback sink ---
	if cbCalls != 1 {
		t.Fatalf("callback fired %d times, want 1", cbCalls)
	}
	if cbRec.Type != "SESSION_CLOSE" {
		t.Fatalf("callback rec.Type = %q, want SESSION_CLOSE", cbRec.Type)
	}
	if cbRec.PolicyID != admittingPolicy {
		t.Fatalf("callback rec.PolicyID = %d, want %d (admitting policy from [136:140])",
			cbRec.PolicyID, admittingPolicy)
	}
	if cbRec.PolicyName != policyName {
		t.Fatalf("callback rec.PolicyName = %q, want %q", cbRec.PolicyName, policyName)
	}
	if cbRec.CloseReason != "TCP FIN" {
		t.Fatalf("callback rec.CloseReason = %q, want %q", cbRec.CloseReason, "TCP FIN")
	}

	// --- buffer sink ---
	buffered := reader.buffer.Latest(1)
	if len(buffered) != 1 {
		t.Fatalf("buffer holds %d records, want 1", len(buffered))
	}
	if buffered[0].PolicyID != admittingPolicy {
		t.Fatalf("buffer rec.PolicyID = %d, want %d", buffered[0].PolicyID, admittingPolicy)
	}

	// --- slog sink (generic "firewall event" close line) ---
	out := buf.String()
	if !strings.Contains(out, "firewall event") {
		t.Fatalf("expected a \"firewall event\" slog line, got: %s", out)
	}
	if !strings.Contains(out, "policy_id=7777") {
		t.Fatalf("slog close line missing policy_id=7777: %s", out)
	}
	if strings.Contains(out, "action=") {
		t.Fatalf("slog close line still emits an action field (a close is not a "+
			"forwarding decision; the wire byte 0 renders \"deny\" and drives "+
			"false drop alerts, #4914): %s", out)
	}
	if !strings.Contains(out, `reason="TCP FIN"`) {
		t.Fatalf("slog close line missing reason=\"TCP FIN\": %s", out)
	}

	// --- standard text sink ---
	std := formatSyslogMsg(cbRec)
	if !strings.Contains(std, "policy=7777") {
		t.Fatalf("standard close line missing policy=7777: %s", std)
	}
	if strings.Contains(std, "action=") {
		t.Fatalf("standard close line unexpectedly carries action=: %s", std)
	}

	// --- structured text sink ---
	structured := formatStructuredMsg(cbRec, 6)
	if !strings.Contains(structured, `policy-name="allow-web"`) {
		t.Fatalf("structured close line missing policy-name=\"allow-web\": %s", structured)
	}
	if !strings.Contains(structured, `reason="TCP FIN"`) {
		t.Fatalf("structured close line missing reason=\"TCP FIN\": %s", structured)
	}

	// --- binary sink ---
	// Model logEvent's evt for a close: evt.PolicyID was zeroed and the wire
	// action byte is 0. The record must nonetheless encode the admitting policy
	// (from rec.PolicyID) and flag the action "not applicable".
	evt := &rawEvent{
		EventType:  eventTypeSessionClose,
		Protocol:   6,
		Action:     actionDeny, // 0, as on the wire
		AddrFamily: addrFamilyInet,
		PolicyID:   0, // zeroed by logEvent on a close
	}
	copy(evt.SrcIP[:4], net.ParseIP("10.0.1.5").To4())
	copy(evt.DstIP[:4], net.ParseIP("10.0.2.7").To4())
	binRec := formatBinaryRecord(evt, &cbRec, SyslogInfo, closeReasonTCPFIN)

	binPolicy := binary.LittleEndian.Uint32(binRec[54:58])
	if binPolicy != admittingPolicy {
		t.Fatalf("binary record policy_id = %d, want %d (must encode rec.PolicyID, "+
			"not the zeroed evt.PolicyID, #4914)", binPolicy, admittingPolicy)
	}
	if binRec[7] != actionNotApplicable {
		t.Fatalf("binary record action byte = %d, want %d (a close carries no "+
			"forwarding decision; encoding the wire 0 reads as actionDeny, #4914)",
			binRec[7], actionNotApplicable)
	}
	if binRec[142] != closeReasonTCPFIN {
		t.Fatalf("binary record close reason = %d, want %d", binRec[142], closeReasonTCPFIN)
	}
}
