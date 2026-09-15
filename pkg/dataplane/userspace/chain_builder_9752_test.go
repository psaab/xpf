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
	} {
		if !strings.Contains(s, want) {
			t.Errorf("request lost %s: %s", want, s)
		}
	}
	// Production loss, pinned (see the cluster link): the mirror-sourced
	// resend carries no RTFlowSessionID, so the request omits session_id
	// and the helper import must treat it as unknown (pre-existing #5212
	// sweep gap — filed separately, not papered over here).
	// Likewise the unresolved session omits every other omitempty-absent key.
	for _, absent := range []string{
		`"session_id"`, "neighbor_mac", "src_mac", "nat_src_ip", "nat_dst_ip",
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
