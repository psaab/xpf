package userspace

import (
	"encoding/json"
	"testing"
)

// #18148: the helper emits ingress_zone_id as a u32 JSON number
// (userspace-dp protocol/control.rs + protocol/binding.rs, widened by
// #16557). config.StableZoneID("lan") is 262430026 — a real hash-derived
// zone that the live loss rig carried. With the Go fields at uint16,
// json.Unmarshal of any status/delta payload carrying that id failed
// ("cannot unmarshal number 262430026 into Go struct field"), so every
// JSON status poll failed and the #9651 supervisor killed the helper
// every ~32s on both loss nodes, starving the fabric.
//
// These cells unmarshal the exact live value through all three widened
// structs. Reverting any of them to uint16 makes the matching cell fail
// at decode (compile still passes — that is the point of a runtime cell).
const zoneID18148 = 262430026 // config.StableZoneID("lan"), frozen fold

func TestSessionDeltaInfoJSONZoneID18148(t *testing.T) {
	payload := []byte(`{"event":"open","src_ip":"10.0.0.1","dst_ip":"10.0.0.2",` +
		`"ingress_zone_id":262430026,"egress_zone_id":382805497}`)
	var d SessionDeltaInfo
	if err := json.Unmarshal(payload, &d); err != nil {
		t.Fatalf("SessionDeltaInfo with ingress_zone_id 262430026 must decode, got: %v", err)
	}
	if d.IngressZoneID != zoneID18148 {
		t.Fatalf("IngressZoneID = %d, want %d", d.IngressZoneID, zoneID18148)
	}
	if d.EgressZoneID != 382805497 { // config.StableZoneID("wan")
		t.Fatalf("EgressZoneID = %d, want 382805497", d.EgressZoneID)
	}
	// Round-trip: a re-marshal must carry the full value, not the low bits.
	out, err := json.Marshal(d)
	if err != nil {
		t.Fatal(err)
	}
	var back SessionDeltaInfo
	if err := json.Unmarshal(out, &back); err != nil || back.IngressZoneID != zoneID18148 {
		t.Fatalf("round-trip = %d err=%v, want %d", back.IngressZoneID, err, zoneID18148)
	}
}

func TestSessionSyncRequestJSONZoneID18148(t *testing.T) {
	payload := []byte(`{"ingress_zone_id":262430026,"egress_zone_id":382805497}`)
	var r SessionSyncRequest
	if err := json.Unmarshal(payload, &r); err != nil {
		t.Fatalf("SessionSyncRequest with ingress_zone_id 262430026 must decode, got: %v", err)
	}
	if r.IngressZoneID != zoneID18148 || r.EgressZoneID != 382805497 {
		t.Fatalf("zones = %d/%d, want %d/382805497", r.IngressZoneID, r.EgressZoneID, zoneID18148)
	}
}

func TestSessionPolicyMatchJSONZoneID18148(t *testing.T) {
	payload := []byte(`{"ingress_zone_id":262430026,"egress_zone_id":382805497}`)
	var m SessionPolicyMatch
	if err := json.Unmarshal(payload, &m); err != nil {
		t.Fatalf("SessionPolicyMatch with ingress_zone_id 262430026 must decode, got: %v", err)
	}
	if m.IngressZoneID != zoneID18148 || m.EgressZoneID != 382805497 {
		t.Fatalf("zones = %d/%d, want %d/382805497", m.IngressZoneID, m.EgressZoneID, zoneID18148)
	}
}

// The status-poll shape that actually killed the helper: a full
// ControlResponse whose recent deltas carry the wide id. This is the
// #9651 supervisor's poll, so this cell is the loss-blocker regression.
func TestControlResponseJSONZoneID18148(t *testing.T) {
	payload := []byte(`{"ok":true,"session_deltas":[{"event":"open",` +
		`"ingress_zone_id":262430026,"egress_zone_id":382805497}]}`)
	var resp ControlResponse
	if err := json.Unmarshal(payload, &resp); err != nil {
		t.Fatalf("ControlResponse with ingress_zone_id 262430026 must decode, got: %v", err)
	}
	if len(resp.SessionDeltas) != 1 || resp.SessionDeltas[0].IngressZoneID != zoneID18148 {
		t.Fatalf("deltas = %+v, want one delta with IngressZoneID %d", resp.SessionDeltas, zoneID18148)
	}
}
