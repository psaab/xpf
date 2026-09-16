package userspace

// #9752 round 4 item 4, chain link G3: the cluster link's installed (key,
// val) golden → the REAL helper-request builder → request JSON golden for
// the Rust import link. The builder input is the installed row (as the
// helper mirror write receives it), never a hand literal.

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/dataplane"
)

func TestInstalledValBuildsTheImportRequest9752(t *testing.T) {
	raw, err := os.ReadFile("testdata/installed_val_9752.json")
	if err != nil {
		t.Fatalf("read installed golden: %v", err)
	}
	var pair struct {
		Key dataplane.SessionKey
		Val dataplane.SessionValue
	}
	if err := json.Unmarshal(raw, &pair); err != nil {
		t.Fatalf("unmarshal installed golden: %v", err)
	}
	if pair.Val.InstallTableDomain != 525590 || pair.Val.InstallTableCheck != 3318534811 {
		t.Fatalf("installed golden lost the stamp: (%d,%d)",
			pair.Val.InstallTableDomain, pair.Val.InstallTableCheck)
	}
	m := New()
	req := m.buildSessionSyncRequestV4("upsert", pair.Key, &pair.Val)
	wire, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}
	s := string(wire)
	// The chain's load-bearing content survives the builder.
	for _, want := range []string{
		`"operation":"upsert"`,
		`"install_table_domain":525590`,
		`"install_table_check":3318534811`,
		`"session_id":77`,
	} {
		if !strings.Contains(s, want) {
			t.Errorf("request lost %s: %s", want, s)
		}
	}
	// Round 5 item 2: the mirror-sourced resend lost RTFlowSessionID, but
	// the builder falls back to the mirror-preserved SessionID, so the
	// incarnation still rides the request (this also closes #10103).
	// The unresolved session omits every other omitempty-absent key.
	for _, absent := range []string{
		"neighbor_mac", "src_mac", "nat_src_ip", "nat_dst_ip",
		"policy_id", "peer_delete", "forward_only",
	} {
		if strings.Contains(s, absent) {
			t.Errorf("request carries %s for an unresolved upsert (must be absent): %s", absent, s)
		}
	}
	const path = "testdata/synced_request_9752.json"
	if os.Getenv("XPF_WRITE_SYNCED_REQUEST_9752") != "" {
		if err := os.WriteFile(path, append(wire, '\n'), 0644); err != nil {
			t.Fatalf("write golden: %v", err)
		}
	}
	golden, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read the shared request golden: %v", err)
	}
	if string(golden) != s+"\n" {
		t.Fatalf("request drifted vs the shared golden:\n got %s\nwant %s", s, golden)
	}
}

// TestBuilderFallsBackToSessionIDWhenRTFlowIsAbsent9752 pins round 5 item 2:
// a mirror-sourced value (RTFlow dropped, SessionID preserved) still names
// its incarnation on the helper request. Without this, a reused tuple's new
// incarnation arrives id-less and the helper retains the old PBR table.
func TestBuilderFallsBackToSessionIDWhenRTFlowIsAbsent9752(t *testing.T) {
	m := New()
	k := key9146()
	// Mirror shape: SessionID preserved, RTFlow dropped.
	val := &dataplane.SessionValue{SessionID: 78, RTFlowSessionID: 0}
	req := m.buildSessionSyncRequestV4("upsert", k, val)
	if req.RTFlowSessionID != 78 {
		t.Fatalf("RTFlow-absent upsert carries session_id=%d, want the preserved SessionID 78", req.RTFlowSessionID)
	}
	// RTFlow present wins (authoritative stable id).
	val2 := &dataplane.SessionValue{SessionID: 78, RTFlowSessionID: 77}
	if req2 := m.buildSessionSyncRequestV4("upsert", k, val2); req2.RTFlowSessionID != 77 {
		t.Fatalf("RTFlow-present upsert carries session_id=%d, want 77", req2.RTFlowSessionID)
	}
	// Double-zero omits (genuinely unknown — the helper's unknown rule).
	val3 := &dataplane.SessionValue{}
	req3 := m.buildSessionSyncRequestV4("upsert", k, val3)
	if req3.RTFlowSessionID != 0 {
		t.Fatalf("identity-less upsert carries session_id=%d, want omitted", req3.RTFlowSessionID)
	}
	wire, err := json.Marshal(req3)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(wire), `"session_id"`) {
		t.Errorf("identity-less upsert emits session_id on the wire: %s", wire)
	}
}
