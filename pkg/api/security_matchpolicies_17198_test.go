package api

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestMatchPoliciesRESTUnsupportedTuple17198 pins divergence 2 of #17198:
// REST lacked the typed unsupported_tuple_family bit (#5720 wired gRPC/CLI
// only), so a REST client had to string-match `action`. The shared
// VerdictFrom now projects it; the JSON also stays pinned for a normal match.
//
// FAIL-ON-REVERT: dropping UnsupportedTupleFamily from verdictToREST /
// VerdictFrom makes the tuple case lose the typed field.
func TestMatchPoliciesRESTUnsupportedTuple17198(t *testing.T) {
	s := &Server{store: hostInboundAPIStore(t)}
	code, body := matchStatus(t, s, "from_zone=trust&to_zone=untrust&src_ip=192.0.2.1&dst_ip=2001:db8::1")
	if code != 200 {
		t.Fatalf("status=%d body=%s", code, body)
	}
	var env struct {
		Data MatchPoliciesResult `json:"data"`
	}
	if err := json.Unmarshal([]byte(body), &env); err != nil {
		t.Fatal(err)
	}
	if !env.Data.UnsupportedTupleFamily {
		t.Fatalf("unsupported_tuple_family missing: %s", body)
	}
	if !strings.Contains(body, `"unsupported_tuple_family":true`) {
		t.Fatalf("raw JSON missing typed bit: %s", body)
	}
	// Positive control: ordinary query has no typed bit and still matches.
	code, body = matchStatus(t, s, "from_zone=trust&to_zone=untrust")
	if code != 200 || strings.Contains(body, "unsupported_tuple_family") {
		t.Fatalf("control status=%d body=%s", code, body)
	}
}
