package userspace

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// #11503: the populated Rust ProcessStatus specimen pins both direction keys
// and sentinel values through the Go wire decoder.
func TestUnzonedPolicyDenialsAgreeWithRustWireFixture11503(t *testing.T) {
	fixture := filepath.Join("..", "..", "..", "userspace-dp", "tests", "fixtures", "protocol_wire_v1.json")
	raw, err := os.ReadFile(fixture)
	if err != nil {
		t.Fatalf("read Rust protocol fixture %s: %v", fixture, err)
	}
	var specimens map[string]json.RawMessage
	if err := json.Unmarshal(raw, &specimens); err != nil {
		t.Fatalf("decode Rust protocol fixture: %v", err)
	}
	specimen, ok := specimens["process_status_unzoned_policy_denials"]
	if !ok {
		t.Fatalf("Rust protocol fixture has no populated unzoned-denial ProcessStatus specimen")
	}
	var status ProcessStatus
	if err := json.Unmarshal(specimen, &status); err != nil {
		t.Fatalf("decode Rust unzoned-denial ProcessStatus specimen: %v", err)
	}
	if status.UnzonedIngressDeniedTotal != 107 || status.UnzonedEgressDeniedTotal != 211 {
		t.Fatalf("decoded unzoned counters = ingress %d, egress %d; want distinct Rust sentinels 107 and 211",
			status.UnzonedIngressDeniedTotal, status.UnzonedEgressDeniedTotal)
	}
	wantRows := map[string]PolicyRuleCounterStatus{
		"unzoned-ingress-denied": {Packets: 107},
		"unzoned-egress-denied":  {Packets: 211},
	}
	assertRows := func(rows []PolicyRuleCounterStatus) {
		t.Helper()
		if len(rows) != len(wantRows) {
			t.Fatalf("decoded policy counter rows = %d; want %d", len(rows), len(wantRows))
		}
		for id, want := range wantRows {
			matches := 0
			for _, row := range rows {
				if row.RuleID != id {
					continue
				}
				matches++
				if row.Packets != want.Packets || row.Bytes != want.Bytes {
					t.Errorf("policy counter %q = packets %d bytes %d; want packets %d bytes %d",
						id, row.Packets, row.Bytes, want.Packets, want.Bytes)
				}
			}
			if matches != 1 {
				t.Errorf("policy counter %q has %d rows; want exactly one", id, matches)
			}
		}
	}
	assertRows(status.PolicyRuleCounters)

	// Re-encoding through the Go wire type must preserve the reserved policy
	// rows as well as the two scalar status counters.

	encoded, err := json.Marshal(status)
	if err != nil {
		t.Fatalf("re-encode ProcessStatus: %v", err)
	}
	var roundTrip ProcessStatus
	if err := json.Unmarshal(encoded, &roundTrip); err != nil {
		t.Fatalf("decode ProcessStatus round-trip: %v", err)
	}
	if roundTrip.UnzonedIngressDeniedTotal != 107 || roundTrip.UnzonedEgressDeniedTotal != 211 {
		t.Fatalf("round-trip unzoned counters = ingress %d, egress %d; want 107 and 211",
			roundTrip.UnzonedIngressDeniedTotal, roundTrip.UnzonedEgressDeniedTotal)
	}
	assertRows(roundTrip.PolicyRuleCounters)
}
