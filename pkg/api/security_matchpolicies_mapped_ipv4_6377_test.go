package api

import (
	"encoding/json"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"testing"

	"github.com/psaab/xpf/pkg/configstore"
	"github.com/psaab/xpf/pkg/policymatch"
)

// mappedTupleAPIStore builds a trust->untrust `permit any` over default-deny so
// a tuple that reaches address matching is PERMITTED. The #6377 gate, if it
// fires first, short-circuits to the "unsupported tuple" verdict before this
// permit is ever consulted — so a permit vs. unsupported answer cleanly
// discriminates whether the mapped-IPv6 source was folded to v4.
func mappedTupleAPIStore(t *testing.T) *configstore.Store {
	t.Helper()
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure() error = %v", err)
	}
	if err := store.LoadOverride(`
security {
    zones {
        security-zone trust;
        security-zone untrust;
    }
    policies {
        default-policy deny-all;
        from-zone trust to-zone untrust {
            policy permit-all {
                match { source-address any; destination-address any; application any; }
                then { permit; }
            }
        }
    }
}
`); err != nil {
		t.Fatalf("LoadOverride() error = %v", err)
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit() error = %v", err)
	}
	return store
}

type mappedMatchResponse struct {
	Success bool `json:"success"`
	Data    struct {
		Matched                   bool   `json:"matched"`
		PolicyName                string `json:"policy_name"`
		Action                    string `json:"action"`
		DefaultUsed               bool   `json:"default_used"`
		V4MappedCompatIngressDrop bool   `json:"v4_mapped_compat_ingress_drop"`
	} `json:"data"`
}

func mappedMatch(t *testing.T, s *Server, q url.Values) mappedMatchResponse {
	t.Helper()
	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/v1/security/match?"+q.Encode(), nil)
	s.matchPoliciesHandler(rr, req)
	if rr.Code != 200 {
		t.Fatalf("status = %d, want 200; body: %s", rr.Code, rr.Body.String())
	}
	var resp mappedMatchResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v; body: %s", err, rr.Body.String())
	}
	if !resp.Success {
		t.Fatalf("success = false; body: %s", rr.Body.String())
	}
	return resp
}

// mappedV4RuleAPIStore builds a trust->untrust `permit` whose source-address is
// a V4-only book (192.0.2.0/24) over default-deny, and NO V6 rule. A mapped
// source ::ffff:192.0.2.1 folds (To4) to 192.0.2.1 which is inside that subnet,
// so a v4-classified evaluation would fabricate a PERMIT.
func mappedV4RuleAPIStore(t *testing.T) *configstore.Store {
	t.Helper()
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure() error = %v", err)
	}
	if err := store.LoadOverride(`
security {
    address-book {
        global {
            address v4src 192.0.2.0/24;
        }
    }
    zones {
        security-zone trust;
        security-zone untrust;
    }
    policies {
        default-policy deny-all;
        from-zone trust to-zone untrust {
            policy permit-v4 {
                match { source-address v4src; destination-address any; application any; }
                then { permit; }
            }
        }
    }
}
`); err != nil {
		t.Fatalf("LoadOverride() error = %v", err)
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit() error = %v", err)
	}
	return store
}

// TestMatchPoliciesRESTMappedIPv6SourceNotEvaluatedAsV4_6377 is the REST
// EVALUATION-correctness fail-on-revert (Codex): on the live handler, a mapped
// IPv6 source must be evaluated as V6 by the policy matcher, NOT folded to v4
// and matched against a V4-only permit rule. Otherwise the REST simulator
// fabricates a PERMIT the runtime never produces (the colon-strict Rust matcher
// sees V6 → no V6 rule → default-deny). dst_ip is omitted (match-any) to isolate
// the source-family classification.
//
// RED on revert: restore `isV4 := ip.To4() != nil` in matchAddr. The mapped
// source folds to v4, matches permit-v4, and the REST response reports permit —
// the deny assertions below fail.
func TestMatchPoliciesRESTMappedIPv6SourceNotEvaluatedAsV4_6377(t *testing.T) {
	s := &Server{store: mappedV4RuleAPIStore(t)}

	// Mapped-IPv6 source: must NOT be folded to v4 and matched against the
	// V4-only permit rule. #16803 supersedes the fall-through half of the
	// #6377 expectation: since #10686 the runtime drops the mapped tuple
	// at ingress before policy, so REST now reports the ingress-drop
	// verdict (typed flag + SSOT action string), not default-deny. The
	// fail-open half is unchanged — never a fabricated permit.
	mapped := mappedMatch(t, s, url.Values{
		"from_zone": {"trust"}, "to_zone": {"untrust"},
		"src_ip": {"::ffff:192.0.2.1"},
	})
	if mapped.Data.Matched || mapped.Data.PolicyName != "" {
		t.Fatalf("mapped-IPv6 source must NOT match the V4-only permit rule on REST (fabricated permit); got %+v", mapped.Data)
	}
	if !mapped.Data.V4MappedCompatIngressDrop || mapped.Data.Action != policymatch.V4MappedCompatIngressDropActionString || mapped.Data.DefaultUsed {
		t.Fatalf("mapped-IPv6 source must report the #10686 ingress drop on REST (#16803); got %+v", mapped.Data)
	}

	// Control: a genuine dotted-quad V4 source in-subnet MUST still permit via
	// permit-v4 on REST — the family threading did not break real v4 matching.
	v4 := mappedMatch(t, s, url.Values{
		"from_zone": {"trust"}, "to_zone": {"untrust"},
		"src_ip": {"192.0.2.5"},
	})
	if !v4.Data.Matched || v4.Data.Action != "permit" || v4.Data.PolicyName != "permit-v4" {
		t.Fatalf("genuine v4 source must permit via permit-v4 on REST; got %+v", v4.Data)
	}
}

// TestMatchPoliciesRESTMappedIPv6SourceNotGated6377 is the REST fail-on-revert
// artifact for #6377 — the one #6377 surface (the live GET /api/v1/security/match
// handler, matchPoliciesHandler) that had no binding test, which is exactly why
// the 5th caller slipped through. An IPv4-mapped IPv6 source (::ffff:192.0.2.1)
// against a genuine IPv6 destination is a same-family V6/V6 tuple to the
// colon-strict runtime matcher, so the #5720 unsupported-tuple gate must NOT
// fire and the query must fall through to the permit-all policy.
//
// The handler threads the colon-strict text family via config.NATAddrFamily on
// the RAW src_ip/dst_ip query strings (before net.ParseIP folds them), so the
// mapped source is classified v6.
//
// RED on revert: drop the SrcFamily/DstFamily fields at the Query in
// security.go (or revert queryTupleFamily to To4()-only). net.ParseIP folds the
// mapped literal to a v4-looking address, the (v4,v6) gate fires, and the REST
// response reports the unsupported-tuple verdict instead of the permit — the
// permit assertion below fails cleanly.
func TestMatchPoliciesRESTMappedIPv6SourceNotGated6377(t *testing.T) {
	s := &Server{store: mappedTupleAPIStore(t)}

	// Mapped-IPv6 source against a genuine IPv6 destination: same-family
	// V6/V6 for the #5720 gate (not unsupported), but #16803: since #10686
	// the runtime drops the mapped tuple at ingress before policy, so REST
	// reports the ingress-drop verdict instead of the permit-all policy.
	mapped := mappedMatch(t, s, url.Values{
		"from_zone": {"trust"}, "to_zone": {"untrust"},
		"src_ip": {"::ffff:192.0.2.1"}, "dst_ip": {"2001:db8::1"},
	})
	if mapped.Data.Action == policymatch.UnsupportedTupleFamilyActionString {
		t.Fatalf("mapped-IPv6 source must NOT be gated unsupported on REST (same-family V6/V6); got %+v", mapped.Data)
	}
	if mapped.Data.Matched || mapped.Data.PolicyName != "" {
		t.Fatalf("mapped-IPv6 tuple must not report a matched policy (#16803 ingress drop); got %+v", mapped.Data)
	}
	if !mapped.Data.V4MappedCompatIngressDrop || mapped.Data.Action != policymatch.V4MappedCompatIngressDropActionString {
		t.Fatalf("mapped-IPv6 tuple must report the #10686 ingress drop on REST; got %+v", mapped.Data)
	}

	// Control: a GENUINE dotted-quad IPv4 source against an IPv6 destination is
	// the true (V4 src, V6 dst) tuple NAT46 cannot produce — the gate MUST still
	// fire on REST, so threading the family did not weaken the real gate.
	genuine := mappedMatch(t, s, url.Values{
		"from_zone": {"trust"}, "to_zone": {"untrust"},
		"src_ip": {"10.0.0.1"}, "dst_ip": {"2001:db8::1"},
	})
	if genuine.Data.Action != policymatch.UnsupportedTupleFamilyActionString {
		t.Fatalf("genuine v4 src / v6 dst MUST still be gated unsupported on REST; got %+v", genuine.Data)
	}
	if genuine.Data.Matched {
		t.Fatalf("an unsupported tuple must not report a matched policy; got %+v", genuine.Data)
	}
}
