package userspace

// #9752 round 3 item 5 (connector): the upsert envelope the Rust import test
// consumes is the shape this builder emits — not a hand-picked subset. An
// unresolved, unattributed, non-tunnel session emits every always-sent key
// (`generation`, `session_id`, `tunnel_discriminator`, the stamp) and omits
// exactly the omitempty-absent ones (MACs, NAT, policy, marks). If the
// builder's shape drifts, this cell — not a distant Rust failure — says so.

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/dataplane"
)

func TestUpsertEnvelopeShapeMatchesTheImportTest9752(t *testing.T) {
	m := New()
	k := key9146()
	val := &dataplane.SessionValue{
		// Post-convert shape: the daemon adopts the stable id into both
		// fields (`adoptedOrLocalSyncedSessionID`).
		SessionID:          77,
		RTFlowSessionID:    77,
		Generation:         10,
		InstallTableDomain: 525590,
		InstallTableCheck:  3318534811,
	}
	req := m.buildSessionSyncRequestV4("upsert", k, val)
	wire, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	s := string(wire)
	for _, want := range []string{
		`"operation":"upsert"`,
		`"addr_family":2`,
		`"session_id":77`,
		`"generation":10`,
		`"tunnel_discriminator":0`,
		`"install_table_domain":525590`,
		`"install_table_check":3318534811`,
	} {
		if !strings.Contains(s, want) {
			t.Errorf("upsert envelope lacks %s: %s", want, s)
		}
	}
	for _, absent := range []string{
		"neighbor_mac", "src_mac", "nat_src_ip", "nat_dst_ip",
		"policy_id", "peer_delete", "forward_only",
	} {
		if strings.Contains(s, absent) {
			t.Errorf("unresolved upsert envelope carries %s (must be omitempty-absent): %s", absent, s)
		}
	}
}
