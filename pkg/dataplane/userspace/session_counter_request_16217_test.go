package userspace

// #16217: SessionValue counters must reach the SessionSyncRequest
// wire (JSON keys fwd_packets/rev_packets) for both families, or the
// peer helper stamps (0,0) at import.

import (
	"encoding/json"
	"testing"

	"github.com/psaab/xpf/pkg/dataplane"
)

func TestSyncRequestCarriesPacketCounters16217(t *testing.T) {
	m := New()
	v4 := &dataplane.SessionValue{IngressZone: 1, EgressZone: 2, FwdPackets: 4242, RevPackets: 3131}
	req := m.buildSessionSyncRequestV4("upsert", dataplane.SessionKey{Protocol: 6}, v4)
	if req.FwdPackets != 4242 || req.RevPackets != 3131 {
		t.Fatalf("#16217: v4 request carries fwd=%d rev=%d, want 4242/3131", req.FwdPackets, req.RevPackets)
	}
	wire, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal v4 request: %v", err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(wire, &decoded); err != nil {
		t.Fatalf("unmarshal v4 request: %v", err)
	}
	if decoded["fwd_packets"] != float64(4242) || decoded["rev_packets"] != float64(3131) {
		t.Fatalf("#16217: v4 wire keys fwd=%v rev=%v, want 4242/3131", decoded["fwd_packets"], decoded["rev_packets"])
	}
	v6 := &dataplane.SessionValueV6{IngressZone: 1, EgressZone: 2, FwdPackets: 777, RevPackets: 888}
	req6 := m.buildSessionSyncRequestV6("upsert", dataplane.SessionKeyV6{Protocol: 6}, v6)
	if req6.FwdPackets != 777 || req6.RevPackets != 888 {
		t.Fatalf("#16217: v6 request carries fwd=%d rev=%d, want 777/888", req6.FwdPackets, req6.RevPackets)
	}
}
