package userspace

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestControlResponseRejectsPartialStatus10868(t *testing.T) {
	for _, raw := range []string{
		`{"ok":true,"status":{"pid":4242}}`,
		`{"ok":true,"status":{"started_at":"2026-09-26T00:00:00Z","control_socket":"/run/xpf.sock"}}`,
		`{"ok":true,"status":{"pid":null,"started_at":"2026-09-26T00:00:00Z","control_socket":"/run/xpf.sock"}}`,
	} {
		var response ControlResponse
		err := json.Unmarshal([]byte(raw), &response)
		if err == nil || !strings.Contains(err.Error(), "partial") {
			t.Errorf("unmarshal partial helper status %s: err = %v, want partial-status rejection", raw, err)
		}
	}
}

func TestRequiredStatusReplyDistinguishesAbsentStatusFromZeroPID10868(t *testing.T) {
	if err := validateRequiredStatusReply("status", nil); err == nil {
		t.Fatal("status reply was accepted without a status object")
	}
	var zeroPIDResponse ControlResponse
	if err := json.Unmarshal([]byte(`{"ok":true,"status":{"pid":0,"started_at":"2026-09-26T00:00:00Z","control_socket":"/run/xpf.sock"}}`), &zeroPIDResponse); err != nil {
		t.Fatalf("explicit PID zero was treated as absence: %v", err)
	}
	if err := validateRequiredStatusReply("status", zeroPIDResponse.Status); err != nil {
		t.Fatalf("explicit zero PID remains a decoded value for compatibility: %v", err)
	}
	if err := validateRequiredStatusReply("export_owner_rg_sessions", nil); err != nil {
		t.Fatalf("status is optional for a non-status response: %v", err)
	}
}

func TestProbeStatusDowngradesAbsentWireStatus10868(t *testing.T) {
	sock := fakeHelperSocket(t, nil, true)
	status, err := ProbeStatus(sock, time.Second)
	if err != nil {
		t.Fatalf("probe absent status response: %v", err)
	}
	if status != nil {
		t.Fatalf("status = %+v, want nil not-ready result for an absent wire status", status)
	}
}

func TestStatusRequestRejectsAbsentWireStatus10868(t *testing.T) {
	sock := fakeHelperSocket(t, nil, true)
	m := &Manager{}
	m.cfg.ControlSocket = sock

	var status ProcessStatus
	err := m.requestLocked(ControlRequest{Type: "status"}, &status)
	if err == nil || !strings.Contains(err.Error(), "omitted required status") {
		t.Fatalf("status response without a status object: err = %v, want rejection", err)
	}
}

func TestAbsentSessionSchemaStatusRemainsUnknown10868(t *testing.T) {
	const base = `"pid":4242,"started_at":"2026-09-26T00:00:00Z","control_socket":"/run/xpf.sock"`
	for _, tc := range []struct {
		name string
		raw  string
	}{
		{name: "absent", raw: `{"ok":true,"status":{` + base + `}}`},
		{name: "explicit zero", raw: `{"ok":true,"status":{` + base + `,"session_delta_schema_fingerprint":0}}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var response ControlResponse
			if err := json.Unmarshal([]byte(tc.raw), &response); err != nil {
				t.Fatalf("unmarshal status response: %v", err)
			}
			if response.Status == nil {
				t.Fatal("status response omitted its status object")
			}
			if response.Status.SessionDeltaSchemaFingerprint != 0 {
				t.Fatalf("fingerprint = %d, want 0 for an unadvertised schema", response.Status.SessionDeltaSchemaFingerprint)
			}
			if verdict, _ := CompareSessionDeltaSchema(response.Status.SessionDeltaSchemaFingerprint, 0x1234); verdict != SessionDeltaSchemaUnknown {
				t.Fatalf("absent/zero fingerprint verdict = %v, want unknown-and-deferred", verdict)
			}
		})
	}
}
