package userspace

import (
	"encoding/json"
	"testing"
)

// #19153: the helper's materialize-divergence drop counter decodes from its
// wire key, defaults to zero for an older helper that omits it, and re-encodes
// under the same key (the round trip a gate reading the status relies on).
func TestMaterializeDivergenceStatusWire19153(t *testing.T) {
	const payload = `{"materialize_divergence_drops":19153}`
	var status ProcessStatus
	if err := json.Unmarshal([]byte(payload), &status); err != nil {
		t.Fatalf("decode materialize-divergence status: %v", err)
	}
	if status.MaterializeDivergenceDrops != 19153 {
		t.Fatalf("MaterializeDivergenceDrops = %d, want 19153", status.MaterializeDivergenceDrops)
	}
	encoded, err := json.Marshal(ProcessStatus{MaterializeDivergenceDrops: 7})
	if err != nil {
		t.Fatalf("encode materialize-divergence status: %v", err)
	}
	var keys map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &keys); err != nil {
		t.Fatalf("re-decode encoded status: %v", err)
	}
	if got := string(keys["materialize_divergence_drops"]); got != "7" {
		t.Fatalf("encoded materialize_divergence_drops = %q, want 7", got)
	}
	var older ProcessStatus
	if err := json.Unmarshal([]byte(`{}`), &older); err != nil {
		t.Fatalf("decode older status without the counter: %v", err)
	}
	if older.MaterializeDivergenceDrops != 0 {
		t.Fatalf("absent materialize-divergence counter did not default to zero: %+v", older)
	}
}
