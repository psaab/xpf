package cluster

// #9412 ACCEPTANCE, cluster wire: the close class on a synced session value
// must cross the node-to-node session-sync wire, and a record from a peer that
// predates the field must still decode, as "not carried".
//
// Written BEFORE the fix, and shaped to COMPILE at base. The class moves through
// JSON onto dataplane.SessionValue{,V6}, which has no such field at base, so the
// assertion reads it back absent: a behavioural red, not a missing symbol.

import (
	"encoding/json"
	"testing"

	"github.com/psaab/xpf/pkg/dataplane"
)

func closeClassOf9412(t *testing.T, v any) any {
	t.Helper()
	js, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(js, &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	return m["TCPCloseClass"]
}

func TestTheCloseClassCrossesTheClusterWire9412(t *testing.T) {
	var val dataplane.SessionValue
	if err := json.Unmarshal([]byte(`{"IngressZone":1,"EgressZone":2,"RoutingDomain":100007,"TCPCloseClass":3}`), &val); err != nil {
		t.Fatalf("FIXTURE: %v", err)
	}
	payload := encodeSessionV4Payload(rtflowKeyV4(41001), val)
	_, got, ok := decodeSessionV4Payload(payload)
	if !ok {
		t.Fatal("FIXTURE: v4 decode failed")
	}
	if c := closeClassOf9412(t, got); c != float64(3) {
		t.Fatalf("#9412 ACCEPTANCE: the primary's v4 value said RST (close class 3) and "+
			"the peer decoded TCPCloseClass=%v. The close state does not cross the "+
			"cluster wire, so the standby cannot learn it.", c)
	}
	// The field before it must be untouched.
	if got.RoutingDomain != 100007 {
		t.Fatalf("RoutingDomain corrupted: %d", got.RoutingDomain)
	}
	// A peer from before the field stops one byte earlier.
	_, legacy, ok := decodeSessionV4Payload(payload[:len(payload)-1])
	if !ok {
		t.Fatal("legacy (truncated) v4 decode failed")
	}
	if c := closeClassOf9412(t, legacy); c != float64(0) {
		t.Fatalf("legacy v4 record decoded TCPCloseClass=%v, want 0", c)
	}
	if legacy.RoutingDomain != 100007 {
		t.Fatalf("legacy v4 record lost its RoutingDomain: %d", legacy.RoutingDomain)
	}

	var val6 dataplane.SessionValueV6
	if err := json.Unmarshal([]byte(`{"IngressZone":1,"EgressZone":2,"TCPCloseClass":2}`), &val6); err != nil {
		t.Fatalf("FIXTURE: %v", err)
	}
	key6 := dataplane.SessionKeyV6{SrcPort: 41001, DstPort: 5201, Protocol: 6}
	_, got6, ok := decodeSessionV6Payload(encodeSessionV6Payload(key6, val6))
	if !ok {
		t.Fatal("FIXTURE: v6 decode failed")
	}
	if c := closeClassOf9412(t, got6); c != float64(2) {
		t.Fatalf("#9412 ACCEPTANCE: the primary's v6 value said TIME_WAIT and the peer "+
			"decoded TCPCloseClass=%v", c)
	}
}
