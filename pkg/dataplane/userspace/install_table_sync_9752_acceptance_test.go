package userspace

// #9752 ACCEPTANCE, helper-side Go hops: the installing-table identity the
// helper states on its session frame must survive decode, and must be
// forwarded on the sync request the standby's helper imports.
//
// Shaped like close_state_sync_9412_acceptance_test.go: every value moves
// through JSON, so a struct without the field silently drops the key and the
// assertion then reads it back absent.

import (
	"encoding/binary"
	"encoding/json"
	"testing"

	"github.com/psaab/xpf/pkg/dataplane"
)

// jsonField9752 marshals v and returns one top-level key, or nil when absent.
func jsonField9752(t *testing.T, v any, key string) any {
	t.Helper()
	js, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(js, &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	return m[key]
}

// TestDecodeSessionEventCarriesTheInstallTable9752 covers the binary frame
// the helper sends for an open and for a close-state update, which share one
// layout. v6 frame: the #9412 close class is [160], so the #9752 domain is
// [161:165] and the check [165:169].
func TestDecodeSessionEventCarriesTheInstallTable9752(t *testing.T) {
	payload := make([]byte, 169)
	payload[0] = 6 // AddrFamily = v6
	payload[1] = 6 // Protocol = TCP
	payload[160] = 0
	binary.LittleEndian.PutUint32(payload[161:165], 525590)
	binary.LittleEndian.PutUint32(payload[165:169], 3318534811)

	d, ok := decodeSessionEvent(payload)
	if !ok {
		t.Fatal("FIXTURE: decodeSessionEvent returned false")
	}
	if got := jsonField9752(t, d, "install_table_domain"); got != float64(525590) {
		t.Fatalf("#9752 ACCEPTANCE: the helper's frame stated domain 525590 "+
			"and the decoded delta carries install_table_domain=%v. The table "+
			"is lost at the first Go hop, so the peer can never learn it.", got)
	}
	if got := jsonField9752(t, d, "install_table_check"); got != float64(3318534811) {
		t.Fatalf("#9752 ACCEPTANCE: the helper's frame stated check 3318534811 "+
			"and the decoded delta carries install_table_check=%v.", got)
	}

	// A frame from before the fields stops after the close class (or the
	// routing domain) and must decode as (0,0), the default table.
	for _, legacy := range [][]byte{payload[:161], payload[:160]} {
		dl, ok := decodeSessionEvent(legacy)
		if !ok {
			t.Fatal("decodeSessionEvent returned false for a legacy frame")
		}
		if got := jsonField9752(t, dl, "install_table_domain"); got != nil && got != float64(0) {
			t.Fatalf("legacy frame decoded install_table_domain=%v, want absent or 0", got)
		}
		if got := jsonField9752(t, dl, "install_table_check"); got != nil && got != float64(0) {
			t.Fatalf("legacy frame decoded install_table_check=%v, want absent or 0", got)
		}
	}
}

// TestSessionSyncRequestCarriesTheInstallTable9752 covers the last Go hop:
// the value the cluster wire delivered must be forwarded on the request the
// standby's helper imports.
func TestSessionSyncRequestCarriesTheInstallTable9752(t *testing.T) {
	m := &Manager{bpfShim: dataplane.New()}

	var v4 dataplane.SessionValue
	if err := json.Unmarshal([]byte(`{"IngressZone":1,"EgressZone":2,"InstallTableDomain":525590,"InstallTableCheck":3318534811}`), &v4); err != nil {
		t.Fatalf("FIXTURE: %v", err)
	}
	req := m.buildSessionSyncRequestV4("upsert", dataplane.SessionKey{Protocol: 6}, &v4)
	if got := jsonField9752(t, req, "install_table_domain"); got != float64(525590) {
		t.Fatalf("#9752 ACCEPTANCE: the synced v4 value said domain 525590 and the sync "+
			"request carries install_table_domain=%v. The standby helper imports the "+
			"session stamp-less and re-resolves it in inet.0.", got)
	}
	if got := jsonField9752(t, req, "install_table_check"); got != float64(3318534811) {
		t.Fatalf("#9752 ACCEPTANCE: the synced v4 value said check 3318534811 and the sync "+
			"request carries install_table_check=%v.", got)
	}

	var v6 dataplane.SessionValueV6
	if err := json.Unmarshal([]byte(`{"IngressZone":1,"EgressZone":2,"InstallTableDomain":525590,"InstallTableCheck":3318534811}`), &v6); err != nil {
		t.Fatalf("FIXTURE: %v", err)
	}
	reqV6 := m.buildSessionSyncRequestV6("upsert", dataplane.SessionKeyV6{Protocol: 6}, &v6)
	if got := jsonField9752(t, reqV6, "install_table_domain"); got != float64(525590) {
		t.Fatalf("#9752 ACCEPTANCE: the synced v6 value said domain 525590 and the sync "+
			"request carries install_table_domain=%v.", got)
	}

	// CONTROL: a default-table value must not invent an identity.
	plain := m.buildSessionSyncRequestV4("upsert", dataplane.SessionKey{Protocol: 6},
		&dataplane.SessionValue{IngressZone: 1, EgressZone: 2})
	if got := jsonField9752(t, plain, "install_table_domain"); got != nil && got != float64(0) {
		t.Fatalf("a default-table value produced install_table_domain=%v", got)
	}
}
