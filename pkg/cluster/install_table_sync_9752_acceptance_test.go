package cluster

// #9752 ACCEPTANCE, cluster wire: the installing-table identity on a synced
// session value must cross the node-to-node session-sync wire, and a record
// from a peer that predates the fields must still decode, as (0,0).
//
// Shaped like close_state_sync_9412_acceptance_test.go: values move through
// JSON onto dataplane.SessionValue{,V6}, so a struct without the fields drops
// them silently and the assertion reads them back absent.

import (
	"encoding/json"
	"testing"

	"github.com/psaab/xpf/pkg/dataplane"
)

func installTableOf9752(t *testing.T, v any) (any, any) {
	t.Helper()
	js, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(js, &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	return m["InstallTableDomain"], m["InstallTableCheck"]
}

func TestTheInstallTableCrossesTheClusterWire9752(t *testing.T) {
	var val dataplane.SessionValue
	if err := json.Unmarshal([]byte(`{"IngressZone":1,"EgressZone":2,"RoutingDomain":100007,"TCPCloseClass":3,"InstallTableDomain":525590,"InstallTableCheck":3318534811}`), &val); err != nil {
		t.Fatalf("FIXTURE: %v", err)
	}
	payload := encodeSessionV4Payload(rtflowKeyV4(41001), val)
	_, got, ok := decodeSessionV4Payload(payload)
	if !ok {
		t.Fatal("FIXTURE: v4 decode failed")
	}
	if dom, chk := installTableOf9752(t, got); dom != float64(525590) || chk != float64(3318534811) {
		t.Fatalf("#9752 ACCEPTANCE: the primary's v4 value said (525590,3318534811) and "+
			"the peer decoded (%v,%v). The table does not cross the cluster wire, "+
			"so the standby imports stamp-less and re-resolves in inet.0.", dom, chk)
	}
	// The fields before it must be untouched.
	if got.RoutingDomain != 100007 {
		t.Fatalf("RoutingDomain corrupted: %d", got.RoutingDomain)
	}
	if got.TCPCloseClass != 3 {
		t.Fatalf("TCPCloseClass corrupted: %d", got.TCPCloseClass)
	}
	// A peer from before the fields stops eight bytes earlier.
	_, legacy, ok := decodeSessionV4Payload(payload[:len(payload)-8])
	if !ok {
		t.Fatal("legacy (truncated) v4 decode failed")
	}
	if dom, chk := installTableOf9752(t, legacy); (dom != nil && dom != float64(0)) || (chk != nil && chk != float64(0)) {
		t.Fatalf("legacy v4 record decoded install_table=(%v,%v), want absent or (0,0)", dom, chk)
	}
	if legacy.RoutingDomain != 100007 || legacy.TCPCloseClass != 3 {
		t.Fatalf("legacy v4 record lost a prefix field: domain=%d class=%d", legacy.RoutingDomain, legacy.TCPCloseClass)
	}

	var val6 dataplane.SessionValueV6
	if err := json.Unmarshal([]byte(`{"IngressZone":1,"EgressZone":2,"InstallTableDomain":525590,"InstallTableCheck":3318534811}`), &val6); err != nil {
		t.Fatalf("FIXTURE: %v", err)
	}
	key6 := dataplane.SessionKeyV6{SrcPort: 41001, DstPort: 5201, Protocol: 6}
	_, got6, ok := decodeSessionV6Payload(encodeSessionV6Payload(key6, val6))
	if !ok {
		t.Fatal("FIXTURE: v6 decode failed")
	}
	if dom, chk := installTableOf9752(t, got6); dom != float64(525590) || chk != float64(3318534811) {
		t.Fatalf("#9752 ACCEPTANCE: the primary's v6 value said (525590,3318534811) and "+
			"the peer decoded (%v,%v).", dom, chk)
	}
}

// TestOldSenderResendKeepsTheRecordedStamp9752 composes the receive path end
// to end: a stamped install lands, then an old sender's resend (same key,
// higher generation, stamp absent => (0,0)) arrives as REAL wire bytes. The
// generation guard must let it through (it outranks) while the keep-rule
// preserves the recorded stamp.
func TestOldSenderResendKeepsTheRecordedStamp9752(t *testing.T) {
	fwd := rtflowKeyV4(41001)
	ss, dp := oldSenderResendSync9752(t)
	stamped := dataplane.SessionValue{SessionID: 77, Generation: 10,
		InstallTableDomain: 525590, InstallTableCheck: 3318534811}
	ss.installClusterSyncedV4(fwd, stamped)
	if got, _ := dp.GetSessionV4(fwd); got.InstallTableDomain != 525590 {
		t.Fatal("FIXTURE: stamped install did not land")
	}
	// Old sender's resend, as wire bytes: same incarnation, higher
	// generation, no install-table tail.
	resend := dataplane.SessionValue{SessionID: 77, Generation: 11}
	wire := encodeSessionV4Payload(fwd, resend)
	payload := wire[syncHeaderSize:]
	truncated := payload[:len(payload)-8] // strip the (0,0) tail: pre-9752 shape
	key, val, ok := decodeSessionV4Payload(truncated)
	if !ok {
		t.Fatal("FIXTURE: truncated resend did not decode")
	}
	ss.installClusterSyncedV4(key, val)
	got, err := dp.GetSessionV4(fwd)
	if err != nil {
		t.Fatalf("resend removed the row: %v", err)
	}
	if got.InstallTableDomain != 525590 || got.InstallTableCheck != 3318534811 {
		t.Fatalf("#9752: an old sender's stamp-less resend overwrote (%d,%d); mixed "+
			"clusters would silently wrong-table the fixed node",
			got.InstallTableDomain, got.InstallTableCheck)
	}
}

func oldSenderResendSync9752(t *testing.T) (*SessionSync, *mockSweepDP) {
	t.Helper()
	dp := &mockSweepDP{
		v4sessions:     map[dataplane.SessionKey]dataplane.SessionValue{},
		sessionCounter: 1,
	}
	ss := NewSessionSync(":0", "10.0.0.2:4785", dp)
	return ss, dp
}
