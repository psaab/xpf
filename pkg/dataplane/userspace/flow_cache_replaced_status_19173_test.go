package userspace

import (
	"encoding/json"
	"testing"
)

// #19173: the helper's replaced-row flow-cache refusal counter decodes from
// its wire key, defaults to zero for an older helper that omits it, and
// re-encodes under the same key. A renamed tag on either side would decode
// silently as zero, which reads as "no replacements", so the key is pinned
// here and in the Rust round trip
// (`process_status_flow_cache_replaced_evictions_roundtrip_19173`).
func TestFlowCacheReplacedEvictionsStatusWire19173(t *testing.T) {
	const payload = `{"flow_cache_replaced_evictions":19173}`
	var status ProcessStatus
	if err := json.Unmarshal([]byte(payload), &status); err != nil {
		t.Fatalf("decode flow-cache replaced status: %v", err)
	}
	if status.FlowCacheReplacedEvictions != 19173 {
		t.Fatalf("FlowCacheReplacedEvictions = %d, want 19173", status.FlowCacheReplacedEvictions)
	}
	encoded, err := json.Marshal(ProcessStatus{FlowCacheReplacedEvictions: 7})
	if err != nil {
		t.Fatalf("encode flow-cache replaced status: %v", err)
	}
	var keys map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &keys); err != nil {
		t.Fatalf("re-decode encoded status: %v", err)
	}
	if got := string(keys["flow_cache_replaced_evictions"]); got != "7" {
		t.Fatalf("encoded flow_cache_replaced_evictions = %q, want 7", got)
	}
	var older ProcessStatus
	if err := json.Unmarshal([]byte(`{}`), &older); err != nil {
		t.Fatalf("decode older status without the counter: %v", err)
	}
	if older.FlowCacheReplacedEvictions != 0 {
		t.Fatalf("absent flow-cache replaced counter did not default to zero: %+v", older)
	}
}
