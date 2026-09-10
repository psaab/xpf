package userspace

// #9412 ACCEPTANCE, helper-side Go hops: the close class the helper states on
// its session frame must survive decode, and must be forwarded on the sync
// request the standby's helper imports.
//
// Written BEFORE the fix, and shaped to COMPILE at base, so "red at base" is a
// behavioural failure and not a missing symbol. Every class value moves through
// JSON: a struct without the field silently drops the key, and the assertion
// then reads it back absent.

import (
	"encoding/json"
	"testing"

	"github.com/psaab/xpf/pkg/dataplane"
)

// jsonField9412 marshals v and returns one top-level key, or nil when absent.
func jsonField9412(t *testing.T, v any, key string) any {
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

// TestDecodeSessionEventCarriesTheCloseClass9412 covers the binary frame the
// helper sends for an open and for a close-state update, which share one
// layout. v6 frame: the #7239 routing domain is [156:160], so the #9412 close
// class is the next byte, [160].
func TestDecodeSessionEventCarriesTheCloseClass9412(t *testing.T) {
	payload := make([]byte, 161)
	payload[0] = 6 // AddrFamily = v6
	payload[1] = 6 // Protocol = TCP
	payload[160] = 1

	d, ok := decodeSessionEvent(payload)
	if !ok {
		t.Fatal("FIXTURE: decodeSessionEvent returned false")
	}
	if got := jsonField9412(t, d, "tcp_close_class"); got != float64(1) {
		t.Fatalf("#9412 ACCEPTANCE: the helper's frame stated close class 1 (CLOSING) "+
			"at [160] and the decoded delta carries tcp_close_class=%v. The close "+
			"state is lost at the first Go hop, so the peer can never learn it.", got)
	}

	// A frame from before the field stops after the routing domain and must
	// decode as "not carried".
	legacy := payload[:160]
	dl, ok := decodeSessionEvent(legacy)
	if !ok {
		t.Fatal("decodeSessionEvent returned false for a legacy frame")
	}
	if got := jsonField9412(t, dl, "tcp_close_class"); got != nil && got != float64(0) {
		t.Fatalf("legacy frame decoded tcp_close_class=%v, want absent or 0", got)
	}
}

// TestSessionSyncRequestCarriesTheCloseClass9412 covers the last Go hop: the
// value the cluster wire delivered must be forwarded on the request the
// standby's helper imports.
func TestSessionSyncRequestCarriesTheCloseClass9412(t *testing.T) {
	m := &Manager{bpfShim: dataplane.New()}

	var v4 dataplane.SessionValue
	if err := json.Unmarshal([]byte(`{"IngressZone":1,"EgressZone":2,"TCPCloseClass":1}`), &v4); err != nil {
		t.Fatalf("FIXTURE: %v", err)
	}
	req := m.buildSessionSyncRequestV4("upsert", dataplane.SessionKey{Protocol: 6}, &v4)
	if got := jsonField9412(t, req, "tcp_close_class"); got != float64(1) {
		t.Fatalf("#9412 ACCEPTANCE: the synced v4 value said CLOSING and the sync "+
			"request carries tcp_close_class=%v. The standby helper imports the "+
			"session as not-closing.", got)
	}

	var v6 dataplane.SessionValueV6
	if err := json.Unmarshal([]byte(`{"IngressZone":1,"EgressZone":2,"TCPCloseClass":2}`), &v6); err != nil {
		t.Fatalf("FIXTURE: %v", err)
	}
	reqV6 := m.buildSessionSyncRequestV6("upsert", dataplane.SessionKeyV6{Protocol: 6}, &v6)
	if got := jsonField9412(t, reqV6, "tcp_close_class"); got != float64(2) {
		t.Fatalf("#9412 ACCEPTANCE: the synced v6 value said TIME_WAIT and the sync "+
			"request carries tcp_close_class=%v", got)
	}

	// CONTROL: a value that is not closing must not invent a class.
	plain := m.buildSessionSyncRequestV4("upsert", dataplane.SessionKey{Protocol: 6},
		&dataplane.SessionValue{IngressZone: 1, EgressZone: 2})
	if got := jsonField9412(t, plain, "tcp_close_class"); got != nil && got != float64(0) {
		t.Fatalf("a not-closing value produced tcp_close_class=%v", got)
	}
}
