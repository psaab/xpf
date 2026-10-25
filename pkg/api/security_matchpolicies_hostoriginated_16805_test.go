package api

import (
	"encoding/json"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/psaab/xpf/pkg/policymatch"
)

// TestMatchPoliciesRESTHostOriginated16805 pins #16805 on the REST surface: a
// `from_zone=junos-host` query must render the host-originated "not evaluated
// by security policy" verdict with the typed host_originated flag, NOT the
// unknown-ingress-zone unconditional deny. The `from_zone=nosuch` and
// `to_zone=junos-host` controls are unchanged.
//
// FAIL-ON-REVERT: removing the policymatch host-originated arm makes the
// junos-host row return unzoned_ingress with UnzonedIngressActionString.
func TestMatchPoliciesRESTHostOriginated16805(t *testing.T) {
	s := &Server{store: hostInboundAPIStore(t)}

	type resp struct {
		Success bool `json:"success"`
		Data    struct {
			Matched              bool   `json:"matched"`
			Action               string `json:"action"`
			HostOriginated       bool   `json:"host_originated"`
			HostInboundUnmatched bool   `json:"host_inbound_unmatched"`
			UnzonedIngress       bool   `json:"unzoned_ingress"`
			UnzonedEgress        bool   `json:"unzoned_egress"`
			DefaultUsed          bool   `json:"default_used"`
		} `json:"data"`
	}
	call := func(q url.Values) resp {
		t.Helper()
		rr := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "/api/v1/security/match?"+q.Encode(), nil)
		s.matchPoliciesHandler(rr, req)
		if rr.Code != 200 {
			t.Fatalf("status = %d, want 200; body: %s", rr.Code, rr.Body.String())
		}
		var out resp
		if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil {
			t.Fatalf("unmarshal: %v; body: %s", err, rr.Body.String())
		}
		if !out.Success {
			t.Fatalf("success = false; body: %s", rr.Body.String())
		}
		return out
	}

	ho := call(url.Values{"from_zone": {"junos-host"}, "to_zone": {"untrust"}})
	if !ho.Data.HostOriginated || ho.Data.UnzonedIngress || ho.Data.UnzonedEgress || ho.Data.Matched || ho.Data.DefaultUsed || ho.Data.HostInboundUnmatched {
		t.Fatalf("from_zone=junos-host must be host_originated only, got %+v", ho.Data)
	}
	if ho.Data.Action != policymatch.HostOriginatedActionString {
		t.Fatalf("action = %q, want HostOriginatedActionString %q", ho.Data.Action, policymatch.HostOriginatedActionString)
	}

	// Control: genuinely unknown from-zone unchanged.
	nosuch := call(url.Values{"from_zone": {"nosuch"}, "to_zone": {"untrust"}})
	if nosuch.Data.HostOriginated || !nosuch.Data.UnzonedIngress || nosuch.Data.Action != policymatch.UnzonedIngressActionString {
		t.Fatalf("from_zone=nosuch control changed, got %+v", nosuch.Data)
	}

	// Control: host-bound to-zone unchanged.
	hi := call(url.Values{"from_zone": {"trust"}, "to_zone": {"junos-host"}})
	if hi.Data.HostOriginated || !hi.Data.HostInboundUnmatched || hi.Data.Action != policymatch.HostInboundActionString {
		t.Fatalf("to_zone=junos-host control changed, got %+v", hi.Data)
	}
}
