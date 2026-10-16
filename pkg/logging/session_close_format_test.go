package logging

import (
	"strings"
	"testing"
)

// sessionCloseRecord builds an EventRecord that mirrors what decodeUserspaceEvent
// produces for a SESSION_CLOSE frame: the wire action byte is 0 (a close carries
// no permit/deny/reject decision), which actionName maps to "deny".
func sessionCloseRecord() EventRecord {
	return EventRecord{
		Type:            "SESSION_CLOSE",
		SrcAddr:         "10.0.1.5:51000",
		DstAddr:         "10.0.2.7:443",
		Protocol:        "TCP",
		Action:          actionName(0), // wire action 0 -> "deny" before #2513
		PolicyID:        7,
		InZone:          1,
		OutZone:         2,
		InZoneName:      "trust",
		OutZoneName:     "untrust",
		SessionPkts:     12,
		SessionBytes:    3456,
		RevSessionPkts:  10,
		RevSessionBytes: 2048,
		ElapsedTime:     42,
		CloseReason:     "TCP FIN",
		SessionID:       99,
		PolicyName:      "allow-web",
		AppName:         "junos-https",
		IngressIface:    "ge-0-0-0",
	}
}

// TestStandardSessionCloseOmitsAction is the #2513 golden test for the plain
// RT_FLOW SESSION_CLOSE line. A session close is not a forwarding decision, so
// the standard formatter must NOT render the wire action byte (which is 0 and
// decodes to "deny"). Reverting the formatter change reintroduces "action=deny"
// here and turns this test red (fail-on-revert).
func TestStandardSessionCloseOmitsAction(t *testing.T) {
	rec := sessionCloseRecord()

	// Guard: confirm the input record really does carry the misleading value,
	// so this test would actually catch a regression in the formatter.
	if rec.Action != "deny" {
		t.Fatalf("precondition: wire action 0 should map to %q, got %q",
			"deny", rec.Action)
	}

	got := formatSyslogMsg(rec)

	const want = "RT_FLOW SESSION_CLOSE src=10.0.1.5:51000 dst=10.0.2.7:443 " +
		"proto=TCP policy=7 zone=trust->untrust pkts=12 bytes=3456"
	if got != want {
		t.Errorf("standard SESSION_CLOSE line mismatch:\n got: %s\nwant: %s", got, want)
	}

	if strings.Contains(got, "action=") {
		t.Errorf("standard SESSION_CLOSE line must omit action= (close is not a "+
			"deny decision, #2513); got: %s", got)
	}
	if strings.Contains(got, "deny") {
		t.Errorf("standard SESSION_CLOSE line must not contain \"deny\" (#2513); got: %s", got)
	}
}

// TestStructuredSessionCloseUnchanged pins the structured RT_FLOW_SESSION_CLOSE
// line: it already omits action and carries a close reason instead. This guards
// against the #2513 fix accidentally altering the structured output.
func TestStructuredSessionCloseUnchanged(t *testing.T) {
	rec := sessionCloseRecord()

	got := formatStructuredMsg(rec, 6) // protocol-id 6 = TCP

	if strings.Contains(got, "action=") {
		t.Errorf("structured SESSION_CLOSE line must not contain action=; got: %s", got)
	}
	if !strings.Contains(got, "RT_FLOW_SESSION_CLOSE") {
		t.Errorf("structured line missing RT_FLOW_SESSION_CLOSE tag; got: %s", got)
	}
	if !strings.Contains(got, `reason="TCP FIN"`) {
		t.Errorf("structured SESSION_CLOSE line must carry the close reason; got: %s", got)
	}
	// Spot-check the rest of the contract is intact (tuple, zones, counters).
	for _, want := range []string{
		`source-address="10.0.1.5" source-port="51000"`,
		`destination-address="10.0.2.7" destination-port="443"`,
		`protocol-id="6"`,
		`policy-name="allow-web"`,
		`source-zone-name="trust" destination-zone-name="untrust"`,
		`packets-from-client="12" bytes-from-client="3456"`,
		`packets-from-server="10" bytes-from-server="2048"`,
		`elapsed-time="42"`,
		`application="junos-https"`,
	} {
		if !strings.Contains(got, want) {
			t.Errorf("structured SESSION_CLOSE line missing %q; got: %s", want, got)
		}
	}
}

// TestStandardNonCloseStillRendersAction confirms the #2513 change is keyed on
// event type == SESSION_CLOSE, not on action == 0 globally: a POLICY_DENY (the
// genuine deny path) still renders action=deny in the standard formatter.
func TestStandardNonCloseStillRendersAction(t *testing.T) {
	rec := EventRecord{
		Type:        "POLICY_DENY",
		SrcAddr:     "10.0.1.5:51000",
		DstAddr:     "10.0.2.7:443",
		Protocol:    "TCP",
		Action:      actionName(actionDeny),
		PolicyID:    7,
		InZoneName:  "trust",
		OutZoneName: "untrust",
	}
	got := formatSyslogMsg(rec)
	if !strings.Contains(got, "action=deny") {
		t.Errorf("POLICY_DENY standard line must still render action=deny; got: %s", got)
	}
}

func TestControlPlaneCloseReasonsRender(t *testing.T) {
	for _, tc := range []struct {
		code uint8
		want string
	}{
		{closeReasonClear, "clear"},
		{closeReasonPolicyDelete, "policy delete"},
	} {
		if got := closeReasonName(tc.code); got != tc.want {
			t.Errorf("closeReasonName(%d) = %q, want %q", tc.code, got, tc.want)
		}
	}
}
