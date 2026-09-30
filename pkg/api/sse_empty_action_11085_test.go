package api

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/logging"
)

// #11085: lifecycle/close records with no action must omit the token
// (they printed a bare `action= `); records WITH an action keep it.
func TestEmptyActionOmitted11085(t *testing.T) {
	open := logging.EventRecord{Type: "SESSION_OPEN", SrcAddr: "10.0.1.5:51000", DstAddr: "10.0.2.7:443", Protocol: "TCP", PolicyID: 7, InZone: 1, OutZone: 2}
	if got := formatLogMessage(open); strings.Contains(got, "action=") {
		t.Errorf("SESSION_OPEN without action must omit the token, got %q", got)
	}
	close := logging.EventRecord{Type: "SESSION_CLOSE", SrcAddr: "a", DstAddr: "b", Protocol: "TCP", PolicyID: 7, InZone: 1, OutZone: 2, SessionPkts: 1, SessionBytes: 2}
	if got := formatLogMessage(close); strings.Contains(got, "action=") {
		t.Errorf("SESSION_CLOSE without action must omit the token, got %q", got)
	}
	deny := logging.EventRecord{Type: "POLICY_DENY", Action: "deny"}
	if got := formatLogMessage(deny); !strings.Contains(got, "action=deny") {
		t.Errorf("record with action must keep the token, got %q", got)
	}
}
