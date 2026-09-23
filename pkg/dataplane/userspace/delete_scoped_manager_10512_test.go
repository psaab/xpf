package userspace

import (
	"testing"

	"github.com/psaab/xpf/pkg/dataplane"
)

// The scoped manager path issues mirror_delete_scoped with the expected
// originator identity (not the local mirror's id), the wire domain as
// scope (not a local probe), peer-marked, deriving reverse on the peer
// (ForwardOnly false).
func TestDeletePeerSyncedSessionScopedIssuesConditionalVerb10512(t *testing.T) {
	m, sessionSock := newBatchTestManager10512(t)
	fake := startScriptedBatchSocket10512(t, sessionSock, []ControlResponse{{OK: true}})
	key := dataplane.SessionKey{
		SrcIP: [4]byte{10, 0, 0, 1}, DstIP: [4]byte{10, 0, 0, 2},
		Protocol: 6, SrcPort: 1234, DstPort: 80,
	}
	refused, err := m.DeletePeerSyncedSessionScoped(key, 100007, 0xF10512)
	if err != nil {
		t.Fatalf("scoped delete failed: %v", err)
	}
	if refused {
		t.Fatal("OK response must not read as refused")
	}
	if got := fake.requestCount(); got != 1 {
		t.Fatalf("request count = %d, want 1", got)
	}
	req := fake.seen[0].SessionSync
	if req == nil {
		t.Fatal("request carries no session-sync payload")
	}
	if req.Operation != "mirror_delete_scoped" {
		t.Errorf("operation = %q, want mirror_delete_scoped", req.Operation)
	}
	if req.RTFlowSessionID != 0xF10512 {
		t.Errorf("session_id = %#x, want the expected originator id 0xF10512", req.RTFlowSessionID)
	}
	if req.RoutingDomain != 100007 {
		t.Errorf("routing_domain = %d, want the wire domain 100007", req.RoutingDomain)
	}
	if !req.PeerDelete || req.ForwardOnly {
		t.Errorf("PeerDelete=%v ForwardOnly=%v, want true/false", req.PeerDelete, req.ForwardOnly)
	}
}

// V6 twin: verb + identity + domain + marks.
func TestDeletePeerSyncedSessionScopedV6IssuesConditionalVerb10512(t *testing.T) {
	m, sessionSock := newBatchTestManager10512(t)
	fake := startScriptedBatchSocket10512(t, sessionSock, []ControlResponse{{OK: true}})
	key := dataplane.SessionKeyV6{Protocol: 6, SrcPort: 1234, DstPort: 80}
	key.SrcIP[15] = 1
	key.DstIP[15] = 2
	refused, err := m.DeletePeerSyncedSessionScopedV6(key, 200007, 0xC10512)
	if err != nil {
		t.Fatalf("scoped v6 delete failed: %v", err)
	}
	if refused {
		t.Fatal("OK response must not read as refused")
	}
	if got := fake.requestCount(); got != 1 {
		t.Fatalf("request count = %d, want 1", got)
	}
	req := fake.seen[0].SessionSync
	if req == nil {
		t.Fatal("request carries no session-sync payload")
	}
	if req.Operation != "mirror_delete_scoped" {
		t.Errorf("operation = %q, want mirror_delete_scoped", req.Operation)
	}
	if req.RTFlowSessionID != 0xC10512 {
		t.Errorf("session_id = %#x, want 0xC10512", req.RTFlowSessionID)
	}
	if req.RoutingDomain != 200007 {
		t.Errorf("routing_domain = %d, want 200007", req.RoutingDomain)
	}
	if !req.PeerDelete || req.ForwardOnly {
		t.Errorf("PeerDelete=%v ForwardOnly=%v, want true/false", req.PeerDelete, req.ForwardOnly)
	}
}

// Domain 0 rides STATED as the default-instance marker (1), never absent
// (0 would decode WIRE_ABSENT and probe another tenant's row).
func TestDeletePeerSyncedSessionScopedStatesDefaultDomain10512(t *testing.T) {
	m, sessionSock := newBatchTestManager10512(t)
	fake := startScriptedBatchSocket10512(t, sessionSock, []ControlResponse{{OK: true}})
	key := dataplane.SessionKey{
		SrcIP: [4]byte{10, 0, 0, 1}, DstIP: [4]byte{10, 0, 0, 2},
		Protocol: 6, SrcPort: 1234, DstPort: 80,
	}
	if _, err := m.DeletePeerSyncedSessionScoped(key, 0, 0xF10512); err != nil {
		t.Fatalf("scoped delete failed: %v", err)
	}
	req := fake.seen[0].SessionSync
	if req == nil {
		t.Fatal("request carries no session-sync payload")
	}
	if req.RoutingDomain != 1 {
		t.Errorf("routing_domain = %d, want stated-default marker 1", req.RoutingDomain)
	}
}
